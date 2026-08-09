# CIS Windows Benchmark Audit Script #725
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #725..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
