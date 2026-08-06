# CIS Windows Benchmark Audit Script #689
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #689..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
