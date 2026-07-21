# CIS Windows Benchmark Audit Script #421
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #421..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
