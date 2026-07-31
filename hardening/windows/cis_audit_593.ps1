# CIS Windows Benchmark Audit Script #593
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #593..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
