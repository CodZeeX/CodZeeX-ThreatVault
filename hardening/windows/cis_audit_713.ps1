# CIS Windows Benchmark Audit Script #713
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #713..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
