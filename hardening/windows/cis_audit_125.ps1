# CIS Windows Benchmark Audit Script #125
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #125..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
