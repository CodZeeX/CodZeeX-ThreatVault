# CIS Windows Benchmark Audit Script #465
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #465..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
