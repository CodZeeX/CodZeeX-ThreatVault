# CIS Windows Benchmark Audit Script #329
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #329..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
