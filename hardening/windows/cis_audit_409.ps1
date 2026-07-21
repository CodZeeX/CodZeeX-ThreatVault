# CIS Windows Benchmark Audit Script #409
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #409..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
