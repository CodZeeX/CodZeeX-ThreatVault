# CIS Windows Benchmark Audit Script #613
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #613..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
