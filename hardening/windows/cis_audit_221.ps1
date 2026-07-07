# CIS Windows Benchmark Audit Script #221
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #221..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
