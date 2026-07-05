# CIS Windows Benchmark Audit Script #173
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #173..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
