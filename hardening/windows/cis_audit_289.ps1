# CIS Windows Benchmark Audit Script #289
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #289..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
