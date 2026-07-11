# CIS Windows Benchmark Audit Script #273
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #273..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
