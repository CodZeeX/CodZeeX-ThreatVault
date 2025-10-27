/*
    YARA Rule: CodZeeX_Infostealers_Detection_1801
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-10-27
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_1801 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #1801"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-10-27"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01801" ascii wide
        $s2 = "cmd.exe /c echo beacon_1801" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 09 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
