# CIS Windows Benchmark Audit Script #293
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #293..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
