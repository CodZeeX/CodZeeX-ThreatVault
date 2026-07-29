# CIS Windows Benchmark Audit Script #541
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #541..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
