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

	if len(r.Copyrights)  > 0 {
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

	if r.AMD != nil {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"AMD"})
		println(tw.Render())

		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"#", "AGESA"})
		for i, agesa := range r.AMD.AGESA {
			tw.AppendRow(table.Row{strconv.Itoa(i), agesa.Header})
		}
		println(tw.Render())

		if r.AMD.Firmware != nil {
			log.Fatalf("Plotting AMD firmware is not implemented. Please hit @Mimoja with something!")
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
