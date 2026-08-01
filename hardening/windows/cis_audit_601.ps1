# CIS Windows Benchmark Audit Script #601
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #601..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
