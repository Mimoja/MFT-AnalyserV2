rule Certificates {
    strings:
        $ARK_AND_ASK = {01 00 00 00 ?? ?? ?? ??                 ?? ??      ?? ?? ?? ??      ?? ??
                       ?? ?? ?? ?? ?? ?? ?? ??                 ?? ??      ?? ?? ?? ??      ?? ??
                       ?? ?? ?? ?? (00 00 00 00| 13 00 00 00)  00 00      00 00 00 00      00 00
                       00 00 00 00 00 00 00 00                 00 (08|10) 00 00 00 (08|10) 00 00
                       01 00 01 00 }
    condition:
        any of them
}

rule AGESA {
    strings:
        $AMDGESA = {41 4d 44 21 47 45 53 41 ?? ?? ?? ??}
        $AGESA = /AGESA![0-9a-zA-Z]{0,10}\x00{0,1}[0-9a-zA-Z .\-]*/
        $AAGESA = /!!AGESA[0-9a-zA-Z .\-]*/
        $AMD_PI = /\$AMD[A-Z][0-9a-zA-Z]*[PIVpiv][0-9a-zA-Z.\-]*/
    condition:
        any of them
}

rule amdHeader {
    strings:
        $AMDHeader = {aa 55 aa 55}
    condition:
        $AMDHeader at 0x20000
        or $AMDHeader at 0x820000
        or $AMDHeader at 0xC20000
        or $AMDHeader at 0xE20000
        or $AMDHeader at 0xF20000
        or uint32(0) == 0x55AA55AA
}
