# CIS Windows Benchmark Audit Script #533
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #533..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
