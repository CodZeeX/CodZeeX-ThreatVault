# CIS Windows Benchmark Audit Script #517
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #517..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
