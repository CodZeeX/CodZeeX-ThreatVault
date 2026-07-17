# CIS Windows Benchmark Audit Script #357
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #357..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
