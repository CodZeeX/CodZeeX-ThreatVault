# CIS Windows Benchmark Audit Script #573
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #573..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
