/*
    YARA Rule: CodZeeX_Infostealers_Detection_1825
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-10-29
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_1825 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #1825"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-10-29"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01825" ascii wide
        $s2 = "cmd.exe /c echo beacon_1825" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 21 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
