/*
    YARA Rule: CodZeeX_Packers_Detection_1006
    Category: packers
    Author: RobsHs (CodZeeX)
    Date: 2025-09-08
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Packers_Detection_1006 {
    meta:
        description = "Detects behavioral and byte patterns for packers family variant #1006"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-09-08"
    strings:
        $s1 = "CodZeeX_ThreatSignature_01006" ascii wide
        $s2 = "cmd.exe /c echo beacon_1006" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B EE }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
