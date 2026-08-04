# CIS Windows Benchmark Audit Script #645
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #645..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
