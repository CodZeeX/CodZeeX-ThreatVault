# CIS Windows Benchmark Audit Script #361
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #361..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
