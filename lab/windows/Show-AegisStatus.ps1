$ErrorActionPreference = 'Stop'
Clear-Host
Write-Host 'PROJECT AEGIS / WINDOWS ATOMIC LAB' -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | Format-Table -AutoSize
Get-Service Sysmon64, winlogbeat | Select-Object Name, Status | Format-Table -AutoSize
$aegisInstall = Get-Content C:\AegisLab\atomic-install.json -Raw | ConvertFrom-Json
Import-Module $aegisInstall.module -Force
Get-Command Invoke-AtomicTest | Select-Object Name, Source | Format-Table -AutoSize
$aegisVerification = '\\host.lan\Data\results\verification.json'
if (Test-Path -LiteralPath $aegisVerification) {
    $aegisVerified = Get-Content -LiteralPath $aegisVerification -Raw | ConvertFrom-Json
    Write-Host "Guest installation: $($aegisVerified.guest_install)"
    Write-Host "Atomic T1057 tasklist: $($aegisVerified.atomic_execution)"
    Write-Host "Elasticsearch ingestion: $($aegisVerified.ingestion)"
    Write-Host "Aegis detection: $($aegisVerified.detection)"
    Write-Host "Run: $($aegisVerified.run_id)"
    Write-Host "Sysmon record: $($aegisVerified.source_events[0].record_id)"
}
