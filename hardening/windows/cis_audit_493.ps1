# CIS Windows Benchmark Audit Script #493
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #493..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
