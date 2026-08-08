# CIS Windows Benchmark Audit Script #717
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #717..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
