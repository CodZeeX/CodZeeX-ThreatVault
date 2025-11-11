/*
    YARA Rule: CodZeeX_Ransomware_Detection_2064
    Category: ransomware
    Author: RobsHs (CodZeeX)
    Date: 2025-11-11
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Ransomware_Detection_2064 {
    meta:
        description = "Detects behavioral and byte patterns for ransomware family variant #2064"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-11-11"
    strings:
        $s1 = "CodZeeX_ThreatSignature_02064" ascii wide
        $s2 = "cmd.exe /c echo beacon_2064" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 10 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
