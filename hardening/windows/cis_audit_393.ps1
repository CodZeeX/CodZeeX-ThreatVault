# CIS Windows Benchmark Audit Script #393
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #393..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
