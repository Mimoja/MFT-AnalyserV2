
rule FSP {
    strings:
        $FSP_HEADER = "FSPH"
    condition:
        any of them
}

rule intel_bootguard {
    strings:
        $acbp = "__ACBP__" // BootPolicyManifest
        $keym = "__KEYM__" // Key
        $ibbs = "__IBBS__" // BootBlock
        $pmsg = "__PMSG__" // BootPolicySignature

    condition:
        any of them
}
