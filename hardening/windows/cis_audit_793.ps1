# CIS Windows Benchmark Audit Script #793
# Author: RobsHs (CodZeeX)
Write-Host "Verifying Windows Security Policy #793..." -ForegroundColor Cyan
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
