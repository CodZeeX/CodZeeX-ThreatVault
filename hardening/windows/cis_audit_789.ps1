# CIS Windows Benchmark Audit Script #789
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #789..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
