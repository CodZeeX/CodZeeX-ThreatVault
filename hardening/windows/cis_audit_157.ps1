# CIS Windows Benchmark Audit Script #157
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #157..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
