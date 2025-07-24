/*
    YARA Rule: CodZeeX_Infostealers_Detection_0265
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-07-24
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_0265 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #265"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-07-24"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00265" ascii wide
        $s2 = "cmd.exe /c echo beacon_0265" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 09 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
