# CIS Windows Benchmark Audit Script #341
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #341..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
