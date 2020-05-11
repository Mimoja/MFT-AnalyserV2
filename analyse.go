package MFT_AnalyserV2

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	MFTCommon "github.com/Mimoja/MFT-Common"
	"github.com/Mimoja/intelfit"
	"github.com/hillu/go-yara"
	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/mimoja/intelfsp"
	"github.com/mimoja/intelmc"
	spdutil "github.com/mimoja/spdlib"
	zcrypto "github.com/zmap/zcrypto/x509"
	"io/ioutil"
	"log"
	"os"
	"path"
)

var yaraRules *yara.Rules

func SetupYara() {
	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatal("Could not create yara compiler")
	}

	rules := os.Args[1]

	log.Printf("Checking for Yara files in %s", rules)
	files, err := ioutil.ReadDir(rules)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		log.Printf("Adding file: %s", f.Name())
		file, err := os.Open(path.Join(rules, f.Name()))
		defer file.Close()
		if err != nil {
			log.Fatalf("Could not load rule: %v", err)
		}

		err = c.AddFile(file, "test")
		if err != nil {
			log.Fatalf("Could not add rule: %v", err)
		}
	}

	if err != nil {
		log.Fatalf("Failed to get rules: %v", err)
	}

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %v", err)
	}
	yaraRules = r
}

type Result struct {
	ID              MFTCommon.IDEntry        `json:",omitempty"`
	FirmwareOffset  int64                    `json:",omitempty"`
	AMD             *MFTCommon.AMDFirmware   `json:"AMD"`
	INTEL           *MFTCommon.IntelFirmware `json:"INTEL""`
	Certificates    []map[string]interface{} `json:"Certificates"`
	Copyrights      []string                 `json:"Copyrights"`
	Vendors         []string                 `json:"Vendors"`
	SPDs            []spdutil.ParsedSPD      `json:"SPDs"`
	IntelMicrocodes []intelmc.Microcode
}

func Analyse(bs []byte) (Result, error) {
	result := Result{}
	is_amd := false
	is_intel := false

	result.AMD = &MFTCommon.AMDFirmware{}
	result.INTEL = &MFTCommon.IntelFirmware{}
	result.ID = MFTCommon.GenerateID(bs)

	matches, err := yaraRules.ScanMem(bs, 0, 1000, nil)
	if err != nil {
		log.Fatal("could not scan with yara %v\n", err)
		return result, err
	}

	if len(matches) == 0 {
		log.Println("Could not find any matches!")
	}

	for _, match := range matches {
		for _, m := range match.Strings {
			name := m.Name[1:]
			match_bytes := bs[m.Offset:]
			switch match.Rule {
			case "AGESA":
				agesa := MFTCommon.AMDAGESA{
					Header: string(m.Data),
					Raw:    fmt.Sprintf("%q\n", bs[m.Offset:m.Offset+100]),
					Offset: uint32(m.Offset),
				}
				log.Printf("Matched : %v", agesa.Header)
				result.AMD.AGESA = append(result.AMD.AGESA, agesa)
				is_amd = true
			case "COPYRIGHT":
				result.Copyrights = append(result.Copyrights, string(m.Data))
			case "CRYPTO_DER":
				size := binary.BigEndian.Uint16(match_bytes[2:]) + 4

				if int(size) > len(match_bytes) {
					log.Printf("Could not read DER: Out of bounds")
					continue
				}
				switch name {
				case "CERT":
					certs, err := zcrypto.ParseCertificates(match_bytes[:size])

					if err != nil {
						log.Printf("Could not parse DER certificate format: %v", err)
						continue
					}

					for _, cert := range certs {
						b, err := cert.MarshalJSON()
						if err != nil {
							log.Printf("Could not marchal cert to json: %v", err)
							continue
						}
						out := map[string]interface{}{}
						json.Unmarshal(b, &out)

						id := MFTCommon.GenerateID(cert.Raw)
						out["ID"] = id
						result.Certificates = append(result.Certificates, out)
					}
				case "KEY_RSA_PUB":
					_, err := x509.ParsePKCS1PublicKey(match_bytes[:size])
					if err != nil {
						log.Fatalf("Could not parse PKCS1 trying PKIX: %v\n", err)
						_, err2 := x509.ParsePKIXPublicKey(match_bytes[:size])
						if err2 != nil {
							log.Printf("Could not parse public key\nPKIX: %v\nPKCS1: %v", err, err2)
							break
						}
						log.Printf("Found Public Key at 0x%08X", m.Offset)
						break
					}
				case "KEY_PUB":
					_, err := x509.ParsePKIXPublicKey(match_bytes[:size])
					if err != nil {
						log.Fatalf("Could not parse PKIX trying PKCS1: %v\n", err)
						_, err2 := x509.ParsePKCS1PublicKey(match_bytes[:size])
						if err2 != nil {
							log.Printf("Could not parse public key\nPKIX: %v\nPKCS1: %v", err, err2)
							break
						}
						log.Printf("Found RSA Public Key at 0x%08X", m.Offset)
						break
					}
				default:
					log.Printf("Unhandled RULE: %s : %s at 0x%X", match.Rule, name, m.Offset)
				}
			case "VENDOR":
				result.Vendors = append(result.Vendors, string(m.Data))
				break
			case "SPD_FILE":
				spd4 := spdutil.ParseSPD4(match_bytes)
				result.SPDs = append(result.SPDs, spd4)
				break
			case "FSP":
				fsp, err := intelfsp.Parse(match_bytes)
				if err != nil {
					break
				}

				result.INTEL.FSP = append(result.INTEL.FSP, MFTCommon.IntelFSP{
					IntelFSP: *fsp,
				})
				is_intel = true
				break
			case "MICROCODE":
				if name == "INTEL" {
					mc, err := intelmc.ParseMicrocode(match_bytes)
					if err != nil {
						log.Printf("Error parsing microcode: %v", err)
					}
					if mc != nil {
						unique := true
						for _, ele := range result.IntelMicrocodes {
							if bytes.Equal(ele.Raw, mc.Raw) {
								unique = false
							}
						}
						if unique {
							result.IntelMicrocodes = append(result.IntelMicrocodes, *mc)
						}
					}
				} else if name == "AMD" {
					//TODO AMD MC
					is_amd = true
				}
			default:
				log.Printf("Unhandled RULE: %s : %s at 0x%X", match.Rule, name, m.Offset)
			}
		}
	}

	/**
	 * Non yara based analyser
	 */
	// Intel
	fit, err := intelfit.ParseFIT(bs)
	if err == nil {
		result.INTEL.FIT = fit
		is_intel = true
	}

	if(result.INTEL.FIT != nil) {
		for _, fit := range result.INTEL.FIT.Entries {
			if fit.Type == intelfit.MICROCODE_UPDATE {
				mc, err := intelmc.ParseMicrocode(bs[fit.Address & ^result.INTEL.FIT.Mask:])
				if err != nil {
					log.Printf("Error parsing microcode: %v", err)
				}
				if mc != nil {
					unique := true
					for _, ele := range result.IntelMicrocodes {
						if bytes.Equal(ele.Raw, mc.Raw) {
							unique = false
						}
					}
					if unique {
						result.IntelMicrocodes = append(result.IntelMicrocodes, *mc)
					}
				}
			}
		}
	}
	/*
		ifd, err := intelifd.ParseIFD(bs);
		if err == nil {
			log.Printf("Found a valid IFD: %v", ifd)
		}
	*/

	//EFI
	//TODO point to bios part
	_, err = uefi.Parse(bs)
	if err != nil {
		if err.Error() == "no firmware volumes in BIOS Region" {
			log.Println("Not EFI found")
		} else {
			log.Printf("Could not parse UEFI")
		}
	}

	if !is_amd {
		result.AMD = nil
	}
	if !is_intel {
		result.INTEL = nil
	}

	return result, nil
}
