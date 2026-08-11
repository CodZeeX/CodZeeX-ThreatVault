# CIS Windows Benchmark Audit Script #781
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #781..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
