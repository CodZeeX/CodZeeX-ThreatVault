# CIS Windows Benchmark Audit Script #737
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #737..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
