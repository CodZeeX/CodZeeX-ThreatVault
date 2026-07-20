# CIS Windows Benchmark Audit Script #397
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #397..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
