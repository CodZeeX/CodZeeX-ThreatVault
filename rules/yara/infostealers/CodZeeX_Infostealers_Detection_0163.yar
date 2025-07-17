/*
    YARA Rule: CodZeeX_Infostealers_Detection_0163
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-07-17
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_0163 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #163"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-07-17"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00163" ascii wide
        $s2 = "cmd.exe /c echo beacon_0163" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B A3 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
