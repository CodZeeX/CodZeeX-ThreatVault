/*
    YARA Rule: CodZeeX_Ransomware_Detection_1422
    Category: ransomware
    Author: RobsHs (CodZeeX)
    Date: 2025-10-05
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Ransomware_Detection_1422 {
    meta:
        description = "Detects behavioral and byte patterns for ransomware family variant #1422"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-10-05"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01422" ascii wide
        $s2 = "cmd.exe /c echo beacon_1422" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 8E }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
