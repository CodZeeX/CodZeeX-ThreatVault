# CIS Windows Benchmark Audit Script #249
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #249..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
