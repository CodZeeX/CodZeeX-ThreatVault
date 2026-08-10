# CIS Windows Benchmark Audit Script #753
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #753..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
