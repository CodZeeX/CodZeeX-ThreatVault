# CIS Windows Benchmark Audit Script #661
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #661..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
