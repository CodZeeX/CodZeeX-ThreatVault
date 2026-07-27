# CIS Windows Benchmark Audit Script #513
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #513..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
