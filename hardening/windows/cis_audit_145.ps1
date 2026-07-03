# CIS Windows Benchmark Audit Script #145
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #145..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
