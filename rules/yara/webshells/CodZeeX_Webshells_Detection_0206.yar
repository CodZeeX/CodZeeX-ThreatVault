/*
    YARA Rule: CodZeeX_Webshells_Detection_0206
    Category: webshells
    Author: RobsHs (CodZeeX)
    Date: 2025-07-21
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Webshells_Detection_0206 {
    meta:
        description = "Detects behavioral and byte patterns for webshells family variant #206"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-07-21"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00206" ascii wide
        $s2 = "cmd.exe /c echo beacon_0206" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B CE }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
