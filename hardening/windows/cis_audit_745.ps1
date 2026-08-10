# CIS Windows Benchmark Audit Script #745
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #745..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
