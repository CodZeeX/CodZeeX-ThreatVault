/*
    YARA Rule: CodZeeX_Ransomware_Detection_1968
    Category: ransomware
    Author: RobsHs (CodZeeX)
    Date: 2025-11-05
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Ransomware_Detection_1968 {
    meta:
        description = "Detects behavioral and byte patterns for ransomware family variant #1968"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-11-05"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01968" ascii wide
        $s2 = "cmd.exe /c echo beacon_1968" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B B0 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
