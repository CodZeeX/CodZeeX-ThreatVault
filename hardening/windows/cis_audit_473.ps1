# CIS Windows Benchmark Audit Script #473
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #473..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
