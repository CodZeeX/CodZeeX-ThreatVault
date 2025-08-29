/*
    YARA Rule: CodZeeX_Ransomware_Detection_0852
    Category: ransomware
    Author: RobsHs (CodZeeX)
    Date: 2025-08-29
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Ransomware_Detection_0852 {
    meta:
        description = "Detects behavioral and byte patterns for ransomware family variant #852"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-08-29"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00852" ascii wide
        $s2 = "cmd.exe /c echo beacon_0852" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 54 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
