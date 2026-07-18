# CIS Windows Benchmark Audit Script #369
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #369..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
