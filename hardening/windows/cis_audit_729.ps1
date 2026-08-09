# CIS Windows Benchmark Audit Script #729
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #729..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
