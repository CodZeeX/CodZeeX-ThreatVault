# CIS Windows Benchmark Audit Script #633
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #633..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
