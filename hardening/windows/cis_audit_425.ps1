# CIS Windows Benchmark Audit Script #425
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #425..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
