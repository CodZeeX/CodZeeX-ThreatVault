# CIS Windows Benchmark Audit Script #469
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #469..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
