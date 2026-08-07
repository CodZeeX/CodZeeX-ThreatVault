# CIS Windows Benchmark Audit Script #697
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #697..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
