# CIS Windows Benchmark Audit Script #405
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #405..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
