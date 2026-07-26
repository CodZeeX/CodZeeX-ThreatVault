# CIS Windows Benchmark Audit Script #489
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #489..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
