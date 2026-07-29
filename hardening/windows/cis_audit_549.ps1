# CIS Windows Benchmark Audit Script #549
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #549..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
