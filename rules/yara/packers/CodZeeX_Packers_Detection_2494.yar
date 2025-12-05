/*
    YARA Rule: CodZeeX_Packers_Detection_2494
    Category: packers
    Author: RobsHs (CodZeeX)
    Date: 2025-12-05
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Packers_Detection_2494 {
    meta:
        description = "Detects behavioral and byte patterns for packers family variant #2494"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-12-05"
    strings:
        $s1 = "CodZeeX_ThreatSignature_02494" ascii wide
        $s2 = "cmd.exe /c echo beacon_2494" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B BE }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
