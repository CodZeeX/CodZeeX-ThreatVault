# CIS Windows Benchmark Audit Script #225
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #225..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
