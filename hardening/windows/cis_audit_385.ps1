# CIS Windows Benchmark Audit Script #385
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #385..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
