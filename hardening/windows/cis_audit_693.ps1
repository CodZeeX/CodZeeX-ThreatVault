# CIS Windows Benchmark Audit Script #693
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #693..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
