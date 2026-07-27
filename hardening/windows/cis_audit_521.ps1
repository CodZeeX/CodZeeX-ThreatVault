# CIS Windows Benchmark Audit Script #521
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #521..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
