# CIS Windows Benchmark Audit Script #681
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #681..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
