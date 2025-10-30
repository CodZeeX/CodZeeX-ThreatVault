/*
    YARA Rule: CodZeeX_Webshells_Detection_1850
    Category: webshells
    Author: RobsHs (CodZeeX)
    Date: 2025-10-30
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Webshells_Detection_1850 {
    meta:
        description = "Detects behavioral and byte patterns for webshells family variant #1850"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-10-30"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01850" ascii wide
        $s2 = "cmd.exe /c echo beacon_1850" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 3A }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
