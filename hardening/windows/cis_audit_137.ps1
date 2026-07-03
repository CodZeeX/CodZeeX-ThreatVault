# CIS Windows Benchmark Audit Script #137
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #137..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
