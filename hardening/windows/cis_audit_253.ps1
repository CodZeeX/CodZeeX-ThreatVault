# CIS Windows Benchmark Audit Script #253
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #253..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
