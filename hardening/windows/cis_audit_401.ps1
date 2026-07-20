# CIS Windows Benchmark Audit Script #401
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #401..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
