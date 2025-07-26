/*
    YARA Rule: CodZeeX_Apt_Detection_0297
    Category: apt
    Author: RobsHs (CodZeeX)
    Date: 2025-07-26
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Apt_Detection_0297 {
    meta:
        description = "Detects behavioral and byte patterns for apt family variant #297"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-07-26"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00297" ascii wide
        $s2 = "cmd.exe /c echo beacon_0297" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 29 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
