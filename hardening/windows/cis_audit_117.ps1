# CIS Windows Benchmark Audit Script #117
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #117..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
