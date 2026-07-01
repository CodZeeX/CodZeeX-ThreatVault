# CIS Windows Benchmark Audit Script #109
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #109..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
