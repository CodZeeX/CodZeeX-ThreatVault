# CIS Windows Benchmark Audit Script #389
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #389..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
