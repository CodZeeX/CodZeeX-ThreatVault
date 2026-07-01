# CIS Windows Benchmark Audit Script #113
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #113..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
