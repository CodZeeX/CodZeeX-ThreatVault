# CIS Windows Benchmark Audit Script #653
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #653..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
