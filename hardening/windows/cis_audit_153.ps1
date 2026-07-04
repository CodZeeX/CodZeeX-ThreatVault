# CIS Windows Benchmark Audit Script #153
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #153..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
