# CIS Windows Benchmark Audit Script #429
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #429..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
