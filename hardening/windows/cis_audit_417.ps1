# CIS Windows Benchmark Audit Script #417
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #417..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
