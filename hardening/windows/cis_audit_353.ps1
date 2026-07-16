# CIS Windows Benchmark Audit Script #353
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #353..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
