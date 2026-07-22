# CIS Windows Benchmark Audit Script #433
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #433..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
