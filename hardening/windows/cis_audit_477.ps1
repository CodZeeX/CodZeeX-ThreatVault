# CIS Windows Benchmark Audit Script #477
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #477..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
