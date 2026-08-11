# CIS Windows Benchmark Audit Script #773
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #773..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
