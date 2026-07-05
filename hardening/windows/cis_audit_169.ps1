# CIS Windows Benchmark Audit Script #169
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #169..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
