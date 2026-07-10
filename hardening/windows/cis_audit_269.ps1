# CIS Windows Benchmark Audit Script #269
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #269..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
