# CIS Windows Benchmark Audit Script #501
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #501..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
