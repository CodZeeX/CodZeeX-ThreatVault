# CIS Windows Benchmark Audit Script #637
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #637..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
