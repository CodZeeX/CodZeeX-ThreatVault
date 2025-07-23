/*
    YARA Rule: CodZeeX_Ransomware_Detection_0228
    Category: ransomware
    Author: RobsHs (CodZeeX)
    Date: 2025-07-23
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Ransomware_Detection_0228 {
    meta:
        description = "Detects behavioral and byte patterns for ransomware family variant #228"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-07-23"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00228" ascii wide
        $s2 = "cmd.exe /c echo beacon_0228" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B E4 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
