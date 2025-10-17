/*
    YARA Rule: CodZeeX_Infostealers_Detection_1639
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-10-17
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_1639 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #1639"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-10-17"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01639" ascii wide
        $s2 = "cmd.exe /c echo beacon_1639" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 67 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
