# CIS Windows Benchmark Audit Script #373
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #373..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
