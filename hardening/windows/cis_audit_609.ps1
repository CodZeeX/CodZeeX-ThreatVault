# CIS Windows Benchmark Audit Script #609
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #609..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
