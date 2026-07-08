# CIS Windows Benchmark Audit Script #241
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #241..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
