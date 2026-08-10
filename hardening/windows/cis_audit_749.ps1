# CIS Windows Benchmark Audit Script #749
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #749..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
