# CIS Windows Benchmark Audit Script #701
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #701..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
