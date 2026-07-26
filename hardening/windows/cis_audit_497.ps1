# CIS Windows Benchmark Audit Script #497
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #497..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
