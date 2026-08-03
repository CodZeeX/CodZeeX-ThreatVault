# CIS Windows Benchmark Audit Script #621
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #621..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
