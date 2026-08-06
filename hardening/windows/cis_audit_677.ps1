# CIS Windows Benchmark Audit Script #677
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #677..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
