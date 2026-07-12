# CIS Windows Benchmark Audit Script #285
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #285..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
