# CIS Windows Benchmark Audit Script #261
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #261..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
