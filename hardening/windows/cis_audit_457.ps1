# CIS Windows Benchmark Audit Script #457
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #457..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
