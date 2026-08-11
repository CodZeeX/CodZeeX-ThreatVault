# CIS Windows Benchmark Audit Script #777
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #777..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
