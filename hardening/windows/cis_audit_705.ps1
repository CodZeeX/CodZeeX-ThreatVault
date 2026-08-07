# CIS Windows Benchmark Audit Script #705
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #705..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
