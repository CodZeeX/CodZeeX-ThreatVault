# CIS Windows Benchmark Audit Script #565
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #565..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
