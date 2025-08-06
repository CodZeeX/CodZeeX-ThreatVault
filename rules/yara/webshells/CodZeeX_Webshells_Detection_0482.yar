/*
    YARA Rule: CodZeeX_Webshells_Detection_0482
    Category: webshells
    Author: RobsHs (CodZeeX)
    Date: 2025-08-06
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Webshells_Detection_0482 {
    meta:
        description = "Detects behavioral and byte patterns for webshells family variant #482"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-08-06"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00482" ascii wide
        $s2 = "cmd.exe /c echo beacon_0482" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B E2 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
