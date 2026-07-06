# CIS Windows Benchmark Audit Script #197
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #197..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
