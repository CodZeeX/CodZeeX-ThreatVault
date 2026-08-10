# CIS Windows Benchmark Audit Script #741
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #741..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
