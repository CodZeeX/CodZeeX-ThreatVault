# CIS Windows Benchmark Audit Script #277
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #277..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
