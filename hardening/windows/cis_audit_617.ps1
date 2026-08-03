# CIS Windows Benchmark Audit Script #617
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #617..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
