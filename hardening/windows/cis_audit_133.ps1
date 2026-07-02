# CIS Windows Benchmark Audit Script #133
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #133..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
