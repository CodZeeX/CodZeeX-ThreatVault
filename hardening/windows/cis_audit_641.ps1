# CIS Windows Benchmark Audit Script #641
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #641..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
