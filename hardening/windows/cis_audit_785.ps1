# CIS Windows Benchmark Audit Script #785
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #785..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
