/*
    YARA Rule: CodZeeX_Infostealers_Detection_0643
    Category: infostealers
    Author: RobsHs (CodZeeX)
    Date: 2025-08-16
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Infostealers_Detection_0643 {
    meta:
        description = "Detects behavioral and byte patterns for infostealers family variant #643"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-08-16"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00643" ascii wide
        $s2 = "cmd.exe /c echo beacon_0643" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 83 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
