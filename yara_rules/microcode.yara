

//# Intel - HeaderRev 01, LoaderRev 01, ProcesFlags xx00*3 (Intel 64 and IA-32 Architectures Software Developer's Manual Vol 3A, Ch 9.11.1)
//pat_icpu = re.compile(br'\x01\x00{3}.{4}[\x00-\x99](([\x19\x20][\x01-\x31][\x01-\x12])|(\x18\x07\x00)).{8}\x01\x00{3}.\x00{3}', re.DOTALL)

//# AMD - Year 20xx, Month 1-13, LoaderID 00-04, DataSize 00|10|20, InitFlag 00-01, NorthBridgeVEN_ID 0000|1022, SouthBridgeVEN_ID 0000|1022, BiosApiREV_ID 00-01, Reserved 00|AA
//pat_acpu = re.compile(br'\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x04]\x80[\x00\x20\x10][\x00\x01].{4}((\x00{2})|(\x22\x10)).{2}((\x00{2})|(\x22\x10)).{6}[\x00\x01](\x00{3}|\xAA{3})', re.DOTALL)

//# VIA - Signature RRAS, Loader Revision 01
//pat_vcpu = re.compile(br'\x52\x52\x41\x53.{16}\x01\x00{3}', re.DOTALL)

//# Freescale - Signature QEF, Header Revision 01
//pat_fcpu = re.compile(br'\x51\x45\x46\x01.{62}[\x00-\x01]', re.DOTALL)


rule MICROCODE {
    strings:
        $INTEL     = /\x01\x00{3}.{4}[\x00-\x99](([\x19\x20][\x01-\x31][\x01-\x12])|(\x18\x07\x00)).{8}\x01\x00{3}.\x00{3}/
        $AMD       = /\x20[\x01-\x31][\x01-\x13].{4}[\x00-\x04]\x80[\x00\x20\x10][\x00\x01].{4}((\x00{2})|(\x22\x10)).{2}((\x00{2})|(\x22\x10)).{6}[\x00\x01](\x00{3}|\xAA{3})/

    condition:
        any of them
}
