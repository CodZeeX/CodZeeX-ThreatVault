# CIS Windows Benchmark Audit Script #213
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #213..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
