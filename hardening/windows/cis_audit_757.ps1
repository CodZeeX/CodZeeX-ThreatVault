# CIS Windows Benchmark Audit Script #757
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #757..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
