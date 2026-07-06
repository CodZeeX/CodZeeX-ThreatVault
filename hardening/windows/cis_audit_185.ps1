# CIS Windows Benchmark Audit Script #185
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #185..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
