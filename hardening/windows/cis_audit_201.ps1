# CIS Windows Benchmark Audit Script #201
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #201..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
