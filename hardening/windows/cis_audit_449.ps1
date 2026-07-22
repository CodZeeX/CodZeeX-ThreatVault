# CIS Windows Benchmark Audit Script #449
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #449..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
