# CIS Windows Benchmark Audit Script #585
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #585..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
