#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$aegisMachine = Get-CimInstance Win32_ComputerSystem
if ($aegisMachine.Model -notmatch 'QEMU|Standard PC' -and $aegisMachine.Manufacturer -notmatch 'QEMU') { throw 'Windows lab guest required.' }
$aegisRoot = 'C:\AegisLab'
$aegisInstall = Get-Content "$aegisRoot\atomic-install.json" -Raw | ConvertFrom-Json
$aegisSettings = Get-Content C:\OEM\settings.json -Raw | ConvertFrom-Json
Copy-Item (Join-Path $PSScriptRoot 'atomic_catalog.json') "$aegisRoot\atomic_catalog.json" -Force
Copy-Item (Join-Path $PSScriptRoot 'Run-AegisAtomicBatch.ps1') "$aegisRoot\Run-AegisAtomicBatch.ps1" -Force
$aegisCases = Get-Content "$aegisRoot\atomic_catalog.json" -Raw | ConvertFrom-Json
foreach ($aegisTechnique in ($aegisCases.technique | Select-Object -Unique)) {
    $aegisFolder = Join-Path $aegisInstall.atomics $aegisTechnique
    New-Item -ItemType Directory -Path $aegisFolder -Force | Out-Null
    $aegisUrl = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/$($aegisSettings.atomics_ref)/atomics/$aegisTechnique/$aegisTechnique.yaml"
    Invoke-WebRequest -UseBasicParsing -Uri $aegisUrl -OutFile (Join-Path $aegisFolder "$aegisTechnique.yaml")
}
$aegisAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\AegisLab\Run-AegisAtomicBatch.ps1'
$aegisTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5)
$aegisTaskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -StartWhenAvailable
Register-ScheduledTask -TaskName 'Aegis Atomic Lab Cycle' -Action $aegisAction -Trigger $aegisTrigger -Settings $aegisTaskSettings -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'Aegis Atomic Lab Cycle'
Get-ScheduledTask -TaskName 'Aegis Atomic Lab Cycle' | Select-Object TaskName, State
Write-Host "Aegis Atomic cycle registered: $($aegisCases.Count) catalogued tests every five minutes; overlapping runs ignored."
