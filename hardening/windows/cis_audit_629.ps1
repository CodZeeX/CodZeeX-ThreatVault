# CIS Windows Benchmark Audit Script #629
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #629..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
