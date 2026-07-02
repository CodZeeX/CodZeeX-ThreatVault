# CIS Windows Benchmark Audit Script #129
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #129..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
