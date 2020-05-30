//go:generate go run github.com/UnnoTed/fileb0x embedding_rules.yaml
package MFT_AnalyserV2

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/Mimoja/MFT-AnalyserV2/yara_rules"
	MFTCommon "github.com/Mimoja/MFT-Common"
	"github.com/Mimoja/intelfit"
	"github.com/hillu/go-yara"
	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/mimoja/amdfw"
	"github.com/mimoja/intelfsp"
	"github.com/mimoja/intelmc"
	spdutil "github.com/mimoja/spdlib"
	zcrypto "github.com/zmap/zcrypto/x509"
	"log"
)

var yaraRules *yara.Rules

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

func SetupYara() {
	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatal("Could not create yara compiler")
	}

	files, err := yara_rules.WalkDirs("", false)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		log.Printf("Loading ruleset: %s", f)
		file, err := yara_rules.ReadFile(f)

		err = c.AddString(string(file), "test")
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
	AMDAGESA        []MFTCommon.AMDAGESA     `json:",omitempty"`
	AMDFirmware     *amdfw.Image             `json:",omitempty"`
	INTEL           *MFTCommon.IntelFirmware `json:"INTEL""`
	Certificates    []map[string]interface{} `json:"Certificates"`
	Copyrights      []string                 `json:"Copyrights"`
	Vendors         []string                 `json:"Vendors"`
	SPDs            []spdutil.ParsedSPD      `json:"SPDs"`
	IntelMicrocodes []intelmc.Microcode
}

func Analyse(bs []byte) (Result, error) {
	result := Result{}
	is_intel := false

	result.INTEL = &MFTCommon.IntelFirmware{}
	result.ID = MFTCommon.GenerateID(bs)

	matches, err := yaraRules.ScanMem(bs, 0, 1000)
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
				result.AMDAGESA = append(result.AMDAGESA, agesa)
			case "AMDEntryTable":
				result.AMDFirmware, err = AnalyseAMDFW(bs)
				if err != nil {
					log.Printf("Errors during AMD Firmware Parsing: %v", err)
				}
			case "COPYRIGHT":
				result.Copyrights = AppendIfMissing(result.Copyrights, string(m.Data))
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
				result.Vendors = AppendIfMissing(result.Vendors, string(m.Data))
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
					log.Printf("AMD microcode parsing is not implemented")
					//TODO AMD MC
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

	if result.INTEL.FIT != nil {
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

	if !is_intel {
		result.INTEL = nil
	}

	return result, nil
}


func AnalyseAMDFW(firmwareBytes []byte) (*amdfw.Image, error) {
	image := amdfw.Image{}

	fetOffset, err := amdfw.FindFirmwareEntryTable(firmwareBytes)
	if err != nil {
		return nil, err
	}

	log.Printf("Found PSP Magic 0x55AA55AA at 0x%08X", fetOffset)

	fet, err := amdfw.ParseFirmwareEntryTable(firmwareBytes, fetOffset)
	if err != nil {
		log.Printf("Could not read AMDFirmwareEntryTable: ", err)
		return nil, err
	}

	image.FET = fet
	mapping, err := amdfw.GetFlashMapping(firmwareBytes, fet)
	if err != nil {
		log.Printf("Could not determin FlashMapping: ", err)
		return &image, err
	}
	image.FlashMapping = &mapping

	roms, errs := amdfw.ParseRoms(firmwareBytes, fet, mapping)
	if len(errs) != 0 {
		err = fmt.Errorf("Errors parsing images %v", errs)
	} else {
		err = nil
	}

	image.Roms = roms
	return &image, err
}
