# CIS Windows Benchmark Audit Script #309
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #309..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
