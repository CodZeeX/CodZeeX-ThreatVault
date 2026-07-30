# CIS Windows Benchmark Audit Script #581
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #581..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
