# CIS Windows Benchmark Audit Script #561
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #561..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
