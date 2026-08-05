# CIS Windows Benchmark Audit Script #657
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #657..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
