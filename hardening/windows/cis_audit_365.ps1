# CIS Windows Benchmark Audit Script #365
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #365..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
