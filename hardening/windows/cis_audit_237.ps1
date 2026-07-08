# CIS Windows Benchmark Audit Script #237
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #237..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
