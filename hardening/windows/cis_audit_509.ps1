# CIS Windows Benchmark Audit Script #509
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #509..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
