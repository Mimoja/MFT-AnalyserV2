package main

import (
	"github.com/Mimoja/MFT-AnalyserV2"
	"github.com/jedib0t/go-pretty/table"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

func main() {
	MFT_AnalyserV2.SetupYara()

	bs, err := ioutil.ReadFile(os.Args[2])

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
	println(tw.Render());

	tw = table.NewWriter()
	tw.AppendHeader(table.Row{"#", "Copyright String"})
	for i, c := range r.Copyrights {
		tw.AppendRow(table.Row{i, c})

	}
	println(tw.Render());

	tw = table.NewWriter()
	tw.AppendHeader(table.Row{"#", "Vendor String"})
	for i, c := range r.Vendors {
		tw.AppendRow(table.Row{i, c})

	}
	println(tw.Render());

	for i, c := range r.SPDs {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"SPD", strconv.Itoa(i)})
		tw.AppendRow(table.Row{"BytesTotal", c.BytesTotal})
		tw.AppendRow(table.Row{"BytesUsed", c.BytesUsed})
		tw.AppendRow(table.Row{"Revision", c.Revision})
		tw.AppendRow(table.Row{"RamType", c.RamType})
		tw.AppendRow(table.Row{"Vendor", c.Vendor})
		tw.AppendRow(table.Row{"ModulePartNumber", c.ModulePartNumber})

		println(tw.Render());
	}

	if r.AMD != nil {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"AMD"})
		println(tw.Render());

		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"#", "AGESA"})
		for i, agesa := range r.AMD.AGESA	{
			tw.AppendRow(table.Row{strconv.Itoa(i), agesa.Header})
		}
		println(tw.Render());

		if r.AMD.Firmware != nil {
			log.Fatalf("Plotting AMD firmware is not implemented. Please hit @Mimoja with something!")
		}
	}

	if r.INTEL != nil {
		tw = table.NewWriter()
		tw.AppendHeader(table.Row{"Intel"})
		println(tw.Render());

		if len(r.INTEL.FSP) > 0 {
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"#", "FSP"})
			for i, fsp := range r.INTEL.FSP {
				tw.AppendRow(table.Row{strconv.Itoa(i), fsp.Summary()})
			}
			println(tw.Render());
		}

		if r.INTEL.FIT  != nil{
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"", "FIT"})
			tw.AppendRow(table.Row{"",  "Offset", r.INTEL.FIT.Offset})
			println(tw.Render());

			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"Header", "FIT"})
			println(tw.Render());
			fit := r.INTEL.FIT.Header
			tw.AppendRow(table.Row{"", "Address", fit.Address})
			tw.AppendRow(table.Row{"", "Size", fit.Size})
			tw.AppendRow(table.Row{"", "Version", fit.Version})
			tw.AppendRow(table.Row{"", "Type", fit.Type})
			tw.AppendRow(table.Row{"", "TypeString", fit.TypeString})
			tw.AppendRow(table.Row{"", "ChecksumAvailable", fit.ChecksumAvailable})
			tw.AppendRow(table.Row{"", "Checksum", fit.Checksum})
			println(tw.Render());

			for i, fit := range r.INTEL.FIT.Entries {
				tw = table.NewWriter()
				tw.AppendHeader(table.Row{"Entry " + strconv.Itoa(i), "FIT"})
				tw.AppendRow(table.Row{"", "Address", fit.Address})
				tw.AppendRow(table.Row{"", "Size", fit.Size})
				tw.AppendRow(table.Row{"", "Version", fit.Version})
				tw.AppendRow(table.Row{"", "Type", fit.Type})
				tw.AppendRow(table.Row{"", "TypeString", fit.TypeString})
				tw.AppendRow(table.Row{"", "ChecksumAvailable", fit.ChecksumAvailable})
				tw.AppendRow(table.Row{"", "Checksum", fit.Checksum})
				println(tw.Render());
			}
		}

		if len(r.INTEL.FSP) > 0 {
			tw = table.NewWriter()
			tw.AppendHeader(table.Row{"#", "FSP"})
			for i, fsp := range r.INTEL.FSP {
				tw.AppendRow(table.Row{strconv.Itoa(i), fsp.Summary()})
			}
			println(tw.Render());
		}
		if r.INTEL.IFD  != nil {
			log.Fatalf("Plotting INTEL IFD is not implemented. Please hit @Mimoja with something!")
		}
	}


}
