# CIS Windows Benchmark Audit Script #377
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #377..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
