# CIS Windows Benchmark Audit Script #101
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #101..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
