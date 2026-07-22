# CIS Windows Benchmark Audit Script #437
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #437..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
