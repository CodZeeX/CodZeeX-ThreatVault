# CIS Windows Benchmark Audit Script #193
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #193..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
