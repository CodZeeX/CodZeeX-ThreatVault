# CIS Windows Benchmark Audit Script #569
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #569..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
