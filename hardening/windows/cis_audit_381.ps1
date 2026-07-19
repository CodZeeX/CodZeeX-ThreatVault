# CIS Windows Benchmark Audit Script #381
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #381..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
