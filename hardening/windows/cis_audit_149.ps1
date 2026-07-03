# CIS Windows Benchmark Audit Script #149
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #149..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
