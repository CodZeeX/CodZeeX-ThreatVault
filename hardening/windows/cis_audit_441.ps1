# CIS Windows Benchmark Audit Script #441
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #441..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
