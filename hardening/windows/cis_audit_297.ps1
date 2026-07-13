# CIS Windows Benchmark Audit Script #297
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #297..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
