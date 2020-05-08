rule COMPANY {
    strings:
        $phoenix = "Phoenix Technologies"
        $award = "Award Software"
        $ami = "American Megatrends"
    condition:
        any of them
}

rule COPYRIGHT {
    strings:
        $copyright = /copyright [a-z0-9\;\_\.\-\(\)( ]*/ nocase
    condition:
        any of them
}

rule VENDOR {
    strings:
        $intel = "Intel(R)" nocase
        $AMD = "AMD"
    condition:
        any of them
}