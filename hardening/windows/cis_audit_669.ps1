# CIS Windows Benchmark Audit Script #669
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #669..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
