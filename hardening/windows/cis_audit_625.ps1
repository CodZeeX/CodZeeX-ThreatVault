# CIS Windows Benchmark Audit Script #625
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #625..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
