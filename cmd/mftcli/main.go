package main

import (
	"encoding/base64"
	"fmt"
	"github.com/Mimoja/MFT-AnalyserV2"
	"github.com/jedib0t/go-pretty/table"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

func main() {
	MFT_AnalyserV2.SetupYara()

	if len(os.Args) < 2 {
		log.Printf("Please provide the flashimage to be analysed")
		os.Exit(1)
	}

	bs, err := ioutil.ReadFile(os.Args[1])

	if err != nil {
		log.Fatalf("Could not open input file: %v", err)
	}

	analyse, err := MFT_AnalyserV2.Analyse(bs)
	if err != nil {
		log.Fatalf("Could not parse image: %v", err)
	}
	handleResult(analyse)

}

/**
type Result struct {
	ID                       MFTCommon.IDEntry        `json:",omitempty"`
	FirmwareOffset           int64          `json:",omitempty"`
	AMD                      *MFTCommon.AMDFirmware   `json:"AMD"`
	INTEL                    *MFTCommon.IntelFirmware `json:"INTEL""`

}
*/

func handleResult(r MFT_AnalyserV2.Result) {
	// ID Metadata
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"#", "Algorithm", "Hash"})
	tw.AppendRow(table.Row{0, "SSDEEP", r.ID.SSDEEP})
	tw.AppendRow(table.Row{1, "SHA3_512", r.ID.SHA3_512})
	tw.AppendRow(table.Row{2, "SHA512", r.ID.SHA512})
	tw.AppendRow(table.Row{3, "SHA256", r.ID.SHA256})
	tw.AppendRow(table.Row{4, "SHA1", r.ID.SHA1})
	tw.AppendRow(table.Row{5, "Whirlpool", r.ID.Whirlpool})
	tw.AppendRow(table.Row{6, "MD5", r.ID.MD5})
	println(tw.Render())

	if len(r.Copyrights) > 0 {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"#", "Copyright String"})
		for i, c := range r.Copyrights {
			tw.AppendRow(table.Row{i, c})

		}
		println(tw.Render())
	}

	tw = table.NewWriter()
	tw.AppendHeader(table.Row{"#", "Vendor String"})
	for i, c := range r.Vendors {
		tw.AppendRow(table.Row{i, c})

	}
	println(tw.Render())

	for i, c := range r.SPDs {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"SPD", strconv.Itoa(i)})
		tw.AppendRow(table.Row{"BytesTotal", c.BytesTotal})
		tw.AppendRow(table.Row{"BytesUsed", c.BytesUsed})
		tw.AppendRow(table.Row{"Revision", c.Revision})
		tw.AppendRow(table.Row{"RamType", c.RamType})
		tw.AppendRow(table.Row{"Vendor", c.Vendor})
		tw.AppendRow(table.Row{"ModulePartNumber", c.ModulePartNumber})

		println(tw.Render())
	}

	if len(r.AMDAGESA) > 0 || r.AMDFirmware != nil {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"AMD"})
		println(tw.Render())
	}

	if len(r.AMDAGESA) > 0 {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"#", "AGESA"})
		for i, agesa := range r.AMDAGESA {
			tw.AppendRow(table.Row{strconv.Itoa(i), agesa.Header})
		}
		println(tw.Render())
	}

	if r.AMDFirmware != nil {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"AMD embedded Firmware", "MASK:", fmt.Sprintf("0x%X", *r.AMDFirmware.FlashMapping)})
		println(tw.Render())

		if r.AMDFirmware.FET != nil {
			fet := r.AMDFirmware.FET

			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"FET", fmt.Sprintf("0x%X", fet.Location)})
			tw.AppendRow(table.Row{"Signature", fmt.Sprintf("0x%X", fet.Signature)})
			tw.AppendRow(table.Row{"ImcRomBase", fmt.Sprintf("0x%X", *fet.ImcRomBase)})
			tw.AppendRow(table.Row{"GecRomBase", fmt.Sprintf("0x%X", *fet.GecRomBase)})
			tw.AppendRow(table.Row{"XHCRomBase", fmt.Sprintf("0x%X", *fet.XHCRomBase)})
			tw.AppendRow(table.Row{"PSPDirBase", fmt.Sprintf("0x%X", *fet.PSPDirBase)})
			tw.AppendRow(table.Row{"NewPSPDirBase", fmt.Sprintf("0x%X", *fet.NewPSPDirBase)})
			tw.AppendRow(table.Row{"BHDDirBase", fmt.Sprintf("0x%X", *fet.BHDDirBase)})
			tw.AppendRow(table.Row{"NewBHDDirBase", fmt.Sprintf("0x%X", *fet.NewBHDDirBase)})
			println(tw.Render())

			for i, rom := range r.AMDFirmware.Roms {
				tw = table.NewWriter()
				tw.AppendHeader(table.Row{"ROM", "Entry", strconv.Itoa(i)})
				tw.AppendRow(table.Row{"Type", rom.Type})
				for y, dir := range rom.Directories {
					tw.AppendRow(table.Row{"Directory", strconv.Itoa(y)})
					tw.AppendRow(table.Row{"", "Location", fmt.Sprintf("0x%X", dir.Location)})
					tw.AppendRow(table.Row{"", "Header", "Cookie", string(dir.Header.Cookie[:])})
					tw.AppendRow(table.Row{"", "", "Checksum", fmt.Sprintf("0x%X", dir.Header.Checksum)})
					tw.AppendRow(table.Row{"", "", "TotalEntries", fmt.Sprintf("0x%X", dir.Header.TotalEntries)})

					for z, entry := range dir.Entries {
						tw.AppendRow(table.Row{"", "Entry", strconv.Itoa(z)})

						if entry.TypeInfo.Name != "" {
							tw.AppendRow(table.Row{"", "", "Type", fmt.Sprintf("%s (0x%x)", entry.TypeInfo.Name, entry.DirectoryEntry.Type)})
						} else {
							tw.AppendRow(table.Row{"", "", "Type", fmt.Sprintf("0x%x", entry.DirectoryEntry.Type)})
						}
						tw.AppendRow(table.Row{"", "", "Size", fmt.Sprintf("0x%x", entry.DirectoryEntry.Size)})
						tw.AppendRow(table.Row{"", "", "Location", fmt.Sprintf("0x%x", entry.DirectoryEntry.Location)})

						hex_signature := fmt.Sprintf("0x%X", entry.Signature)
						if len(hex_signature) > 30 {
							hex_signature = hex_signature[:30] + "..."
						}
						if hex_signature != "" {
							tw.AppendRow(table.Row{"", "", "Signature", hex_signature})
						}

						if entry.Version != "" {
							tw.AppendRow(table.Row{"", "", "Version", entry.Version})
						}

						if entry.Header != nil {
							tw.AppendRow(table.Row{"", "", "Header", "Unknown @ 0x00", fmt.Sprintf("0x%X", entry.Header.Unknown00)})
							tw.AppendRow(table.Row{"", "", "", "ID", fmt.Sprintf("0x%X", entry.Header.ID)})
							tw.AppendRow(table.Row{"", "", "", "SizeSigned", fmt.Sprintf("0x%X", entry.Header.SizeSigned)})
							tw.AppendRow(table.Row{"", "", "", "IsEncrypted", fmt.Sprintf("0x%X", entry.Header.IsEncrypted)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x1C", fmt.Sprintf("0x%X", entry.Header.Unknown1C)})
							tw.AppendRow(table.Row{"", "", "", "EncFingerprint", fmt.Sprintf("0x%X", entry.Header.EncFingerprint)})
							tw.AppendRow(table.Row{"", "", "", "IsSigned", fmt.Sprintf("0x%X", entry.Header.IsSigned)})
							tw.AppendRow(table.Row{"", "", "", "SigFingerprint", fmt.Sprintf("0x%X", entry.Header.SigFingerprint)})
							tw.AppendRow(table.Row{"", "", "", "IsCompressed", fmt.Sprintf("0x%X", entry.Header.IsCompressed)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x4C", fmt.Sprintf("0x%X", entry.Header.Unknown4C)})
							tw.AppendRow(table.Row{"", "", "", "FullSize", fmt.Sprintf("0x%X", entry.Header.FullSize)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x54", fmt.Sprintf("0x%X", entry.Header.Unknown54)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x58", fmt.Sprintf("0x%X", entry.Header.Unknown58)})
							tw.AppendRow(table.Row{"", "", "", "Version", fmt.Sprintf("0x%X", entry.Header.Version)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x64", fmt.Sprintf("0x%X", entry.Header.Unknown64)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x68", fmt.Sprintf("0x%X", entry.Header.Unknown68)})
							tw.AppendRow(table.Row{"", "", "", "SizePacked", fmt.Sprintf("0x%X", entry.Header.SizePacked)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x70", fmt.Sprintf("0x%X", entry.Header.Unknown70)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x80", fmt.Sprintf("0x%X", entry.Header.Unknown80)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x90", fmt.Sprintf("0x%X", entry.Header.Unknown90)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x94", fmt.Sprintf("0x%X", entry.Header.Unknown94)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x98", fmt.Sprintf("0x%X", entry.Header.Unknown98)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0x9C", fmt.Sprintf("0x%X", entry.Header.Unknown9C)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0xA0", fmt.Sprintf("0x%X", entry.Header.UnknownA0)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0xA4", fmt.Sprintf("0x%X", entry.Header.UnknownA4)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0xA8", fmt.Sprintf("0x%X", entry.Header.UnknownA8)})
							tw.AppendRow(table.Row{"", "", "", "Unknown @ 0xB0", fmt.Sprintf("0x%X", entry.Header.UnknownB0)[:30] + "..."})
						}
					}
				}
				println(tw.Render())

			}
		}
	}

	if r.INTEL != nil {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"Intel"})
		println(tw.Render())

		if len(r.INTEL.FSP) > 0 {
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"#", "FSP"})
			for i, fsp := range r.INTEL.FSP {
				tw.AppendRow(table.Row{strconv.Itoa(i), fsp.Summary()})
			}
			println(tw.Render())
		}

		if r.INTEL.FIT != nil {
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"FIT"})
			tw.AppendRow(table.Row{"Offset", r.INTEL.FIT.Offset})
			println(tw.Render())

			fit := r.INTEL.FIT.Header
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"FIT", "Header"})
			tw.AppendRow(table.Row{"", "Address", fmt.Sprintf("0x%X", fit.Address & ^r.INTEL.FIT.Mask)})
			tw.AppendRow(table.Row{"", "Size", fmt.Sprintf("0x%X", fit.Size)})
			tw.AppendRow(table.Row{"", "Version", fmt.Sprintf("0x%X", fit.Version)})
			tw.AppendRow(table.Row{"", "Type", fit.Type})
			tw.AppendRow(table.Row{"", "TypeString", fit.TypeString})
			tw.AppendRow(table.Row{"", "ChecksumAvailable", fit.ChecksumAvailable})
			tw.AppendRow(table.Row{"", "Checksum", fit.Checksum})
			println(tw.Render())

			for i, fit := range r.INTEL.FIT.Entries {
				tw = table.NewWriter()
				tw.AppendHeader(table.Row{"FIT", "Entry", strconv.Itoa(i)})
				tw.AppendRow(table.Row{"", "Address", fmt.Sprintf("0x%X", fit.Address & ^r.INTEL.FIT.Mask)})
				tw.AppendRow(table.Row{"", "Size", fmt.Sprintf("0x%X", fit.Size)})
				tw.AppendRow(table.Row{"", "Version", fmt.Sprintf("0x%X", fit.Version)})
				tw.AppendRow(table.Row{"", "Type", fit.Type})
				tw.AppendRow(table.Row{"", "TypeString", fit.TypeString})
				tw.AppendRow(table.Row{"", "ChecksumAvailable", fit.ChecksumAvailable})
				tw.AppendRow(table.Row{"", "Checksum", fit.Checksum})
				println(tw.Render())
			}
		}

		if len(r.INTEL.FSP) > 0 {
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"#", "FSP"})
			for i, fsp := range r.INTEL.FSP {
				tw.AppendRow(table.Row{strconv.Itoa(i), fsp.Summary()})
			}
			println(tw.Render())
		}
		if r.INTEL.IFD != nil {
			log.Fatalf("Plotting INTEL IFD is not implemented. Please hit @Mimoja with something!")
		}
	}

	if len(r.IntelMicrocodes) > 0 {
		tw = table.NewWriter()
		for i, mc := range r.IntelMicrocodes {
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"Intel Microcode", "", strconv.Itoa(i)})
			tw.AppendRow(table.Row{"Header", "HeaderVersion", fmt.Sprintf("0x%x", mc.Header.HeaderVersion)})
			tw.AppendRow(table.Row{"", "UpdateRevision", fmt.Sprintf("0x%x", mc.Header.UpdateRevision)})
			tw.AppendRow(table.Row{"", "ProcessorSignature", fmt.Sprintf("0x%x", mc.Header.ProcessorSignature)})
			tw.AppendRow(table.Row{"", "Date", fmt.Sprintf("%x/%x/%x", mc.Header.Year, mc.Header.Month, mc.Header.Day)})
			tw.AppendRow(table.Row{"", "Checksum", fmt.Sprintf("0x%x", mc.Header.Checksum)})
			tw.AppendRow(table.Row{"", "LoaderRevision", fmt.Sprintf("0x%x", mc.Header.LoaderRevision)})
			tw.AppendRow(table.Row{"", "Platforms", mc.Platforms})
			tw.AppendRow(table.Row{"", "DataSize", fmt.Sprintf("0x%x", mc.Header.DataSize)})
			tw.AppendRow(table.Row{"", "TotalSize", fmt.Sprintf("0x%x", mc.Header.TotalSize)})

			if mc.HeaderExtra != nil {

				tw.AppendRow(table.Row{"Header Extra", "Module Type", fmt.Sprintf("0x%x", mc.HeaderExtra.ModuleType)})
				tw.AppendRow(table.Row{"", "Module SubType", fmt.Sprintf("0x%x", mc.HeaderExtra.ModuleSubType)})
				tw.AppendRow(table.Row{"", "Module Size", fmt.Sprintf("0x%x", mc.HeaderExtra.ModuleSize)})
				tw.AppendRow(table.Row{"", "Flags", fmt.Sprintf("0x%x", mc.HeaderExtra.Flags)})
				tw.AppendRow(table.Row{"", "Flags: RSA Signed", mc.HeaderExtra.Flags & 1})
				tw.AppendRow(table.Row{"", "RSAKeySize", mc.HeaderExtra.RSAKeySize * 1024})
				tw.AppendRow(table.Row{"", "UpdateRevision", mc.HeaderExtra.UpdateRevision})
				tw.AppendRow(table.Row{"", "VCN", mc.HeaderExtra.VCN})
				tw.AppendRow(table.Row{"", "MultiPurpose1", fmt.Sprintf("0x%x", mc.HeaderExtra.MultiPurpose1)})
				tw.AppendRow(table.Row{"", "Date", fmt.Sprintf("%x/%x/%x", mc.HeaderExtra.Year, mc.HeaderExtra.Month, mc.HeaderExtra.Day)})
				tw.AppendRow(table.Row{"", "UpdateSize", mc.HeaderExtra.UpdateSize})
				tw.AppendRow(table.Row{"", "ProcessorSignatureCount", mc.HeaderExtra.ProcessorSignatureCount})
				tw.AppendRow(table.Row{"", "ProcessorSignature0", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature0)})
				tw.AppendRow(table.Row{"", "ProcessorSignature1", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature1)})
				tw.AppendRow(table.Row{"", "ProcessorSignature2", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature2)})
				tw.AppendRow(table.Row{"", "ProcessorSignature3", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature3)})
				tw.AppendRow(table.Row{"", "ProcessorSignature4", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature4)})
				tw.AppendRow(table.Row{"", "ProcessorSignature5", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature5)})
				tw.AppendRow(table.Row{"", "ProcessorSignature6", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature6)})
				tw.AppendRow(table.Row{"", "ProcessorSignature7", fmt.Sprintf("0x%x", mc.HeaderExtra.ProcessorSignature7)})
				tw.AppendRow(table.Row{"", "MultiPurpose2", fmt.Sprintf("0x%x", mc.HeaderExtra.MultiPurpose2)})
				tw.AppendRow(table.Row{"", "SVN", mc.HeaderExtra.SVN})
			}

			if mc.HeaderExtended != nil {
				tw.AppendRow(table.Row{"Header Extended", "Extended Signature Count", fmt.Sprintf("0x%x", mc.HeaderExtended.ExtendedSignatureCount)})
				tw.AppendRow(table.Row{"", "Extended Signature Checksum", fmt.Sprintf("0x%x", mc.HeaderExtended.ExtendedChecksum)})
			}

			tw.AppendRow(table.Row{"CalculatedChecksum", mc.CalculatedChecksum})
			tw.AppendRow(table.Row{"Signature", "RSA Exponent", fmt.Sprintf("0x%x", mc.Encryption.RSAExponent)})
			tw.AppendRow(table.Row{"", "RSA PublicKey", base64.StdEncoding.EncodeToString(mc.Encryption.RSAPublicKey)[:50] + "..."})
			tw.AppendRow(table.Row{"", "RSA Signature", base64.StdEncoding.EncodeToString(mc.Encryption.RSASignature)[:50] + "..."})

			println(tw.Render())
		}
	}

}
