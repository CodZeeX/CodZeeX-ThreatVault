# CIS Windows Benchmark Audit Script #709
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #709..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
