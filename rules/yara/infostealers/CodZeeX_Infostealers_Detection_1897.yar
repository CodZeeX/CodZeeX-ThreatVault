/*
    YARA Rule: CodZeeX_Infostealers_Detection_1897
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-11-02
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_1897 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #1897"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-11-02"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01897" ascii wide
        $s2 = "cmd.exe /c echo beacon_1897" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 69 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
