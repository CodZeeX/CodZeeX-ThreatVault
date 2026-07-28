# CIS Windows Benchmark Audit Script #537
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #537..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
