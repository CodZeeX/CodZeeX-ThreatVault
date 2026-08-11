# CIS Windows Benchmark Audit Script #765
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #765..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
