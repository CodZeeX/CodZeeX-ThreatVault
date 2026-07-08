# CIS Windows Benchmark Audit Script #233
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #233..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
