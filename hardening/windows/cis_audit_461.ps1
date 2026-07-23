# CIS Windows Benchmark Audit Script #461
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #461..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
