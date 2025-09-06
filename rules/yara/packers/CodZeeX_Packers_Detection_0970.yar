/*
    YARA Rule: CodZeeX_Packers_Detection_0970
    Category: packers
    Author: RobsHs (CodZeeX)
    Date: 2025-09-06
    Reference: https://github.com/organizations/CodZeeX
*/

rule CodZeeX_Packers_Detection_0970 {
    meta:
        description = "Detects behavioral and byte patterns for packers family variant #970"
        author = "RobsHs (CodZeeX)"
        severity = "HIGH"
        version = "1.0"
        date = "2025-09-06"
    strings:
        $s1 = "CodZeeX_ThreatSignature_00970" ascii wide
        $s2 = "cmd.exe /c echo beacon_0970" ascii
        $hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B CA }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and ($s1 or ($s2 and $hex1))
}
