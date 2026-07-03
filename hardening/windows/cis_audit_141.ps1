# CIS Windows Benchmark Audit Script #141
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #141..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
