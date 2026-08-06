# CIS Windows Benchmark Audit Script #673
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #673..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
