# CIS Windows Benchmark Audit Script #121
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #121..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
