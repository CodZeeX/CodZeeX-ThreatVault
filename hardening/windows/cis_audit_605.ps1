# CIS Windows Benchmark Audit Script #605
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #605..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
