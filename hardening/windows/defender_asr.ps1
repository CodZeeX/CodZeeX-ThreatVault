<#
.SYNOPSIS
    CodZeeX Windows Defender Attack Surface Reduction (ASR) Enforcement Script
    Author: RobsHs (CodZeeX)
#>

$ASRRules = @{
    "Block executable content from email client and webmail" = "be9b3072-0bb5-4350-a596-388592c606ec"
    "Block all Office applications from creating child processes" = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
    "Block Office applications from creating executable content" = "3b5764c1-6307-4553-a10b-b082121a649f"
    "Block Office applications from injecting code into other processes" = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
    "Block JavaScript or VBScript from launching downloaded executable content" = "d3e037e1-3eb8-44c8-a917-57927947596d"
    "Block execution of potentially obfuscated scripts" = "5beb249e-0e6e-4403-b12e-10064728a74f"
    "Block Win32 API calls from Office macros" = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
    "Block credential stealing from Windows Local Security Authority (lsass.exe)" = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
}

Write-Host "Enforcing CodZeeX ASR Rules..." -ForegroundColor Cyan
foreach ($ruleName in $ASRRules.Keys) {
    $ruleId = $ASRRules[$ruleName]
    Write-Host "Configuring ASR: $ruleName ($ruleId)"
    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled
}
Write-Host "ASR Baseline successfully enforced." -ForegroundColor Green
