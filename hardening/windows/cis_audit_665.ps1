# CIS Windows Benchmark Audit Script #665
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #665..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
