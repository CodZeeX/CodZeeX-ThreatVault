/*
    YARA Rule: CodZeeX_Webshells_Detection_2240
    Category: webshells
    Author: RobsHs (CodZeeX)
    Date: 2025-11-20
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Webshells_Detection_2240 {
    meta:
        description = "Detects behavioral and byte patterns for webshells family variant #2240"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-11-20"
    strings:
        $s1 = "CodZeeX_ThreatSignature_02240" ascii wide
        $s2 = "cmd.exe /c echo beacon_2240" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B C0 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
