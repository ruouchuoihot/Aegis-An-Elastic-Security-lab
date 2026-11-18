#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$aegisPackMachine = Get-CimInstance Win32_ComputerSystem
if ($aegisPackMachine.Model -notmatch 'QEMU|Standard PC' -and $aegisPackMachine.Manufacturer -notmatch 'QEMU') { throw 'QEMU lab guest required.' }
Disable-ScheduledTask -TaskName 'Aegis Atomic Lab Cycle' | Out-Null
$aegisPackDeadline = (Get-Date).AddSeconds(60)
while ((Get-ScheduledTask -TaskName 'Aegis Atomic Lab Cycle').State -eq 'Running') {
    if ((Get-Date) -gt $aegisPackDeadline) { throw 'Wait for the active batch before installing the pack.' }
    Start-Sleep -Milliseconds 500
}
$aegisPackRoot = 'C:\AegisLab'
& "$aegisPackRoot\Sysmon\Sysmon64.exe" -c (Join-Path $PSScriptRoot 'sysmon.xml')
if ($LASTEXITCODE -ne 0) { throw 'Sysmon configuration update failed.' }
& auditpol.exe /set '/subcategory:Other Object Access Events' /success:enable
if ($LASTEXITCODE -ne 0) { throw 'Cannot enable scheduled-task audit events.' }
$aegisPackBeat = Get-ChildItem -LiteralPath $aegisPackRoot -Directory -Filter 'winlogbeat-*' | Select-Object -First 1
if (-not $aegisPackBeat) { throw 'Winlogbeat installation not found.' }
$aegisPackConfig = Join-Path $aegisPackBeat.FullName 'winlogbeat.yml'
$aegisPackConfigText = Get-Content -LiteralPath $aegisPackConfig -Raw
$aegisPackConfigText = $aegisPackConfigText -replace 'event_id: 4688[^\r\n]*', 'event_id: 4688,4698,4699,4702'
$aegisPackConfigText | Set-Content -LiteralPath $aegisPackConfig -Encoding UTF8
& (Join-Path $aegisPackBeat.FullName 'winlogbeat.exe') test config -c $aegisPackConfig --path.home $aegisPackBeat.FullName
if ($LASTEXITCODE -ne 0) { throw 'Collector configuration validation failed.' }
Restart-Service winlogbeat
New-Item -ItemType Directory -Path "$aegisPackRoot\scenario-work" -Force | Out-Null
Set-Content -LiteralPath "$aegisPackRoot\scenario-work\seed.txt" -Value 'Aegis file decoding sample; no executable payload.' -Encoding ASCII
New-Item -ItemType Directory -Path 'C:\Windows\Temp\AegisScenario' -Force | Out-Null
Set-Content -LiteralPath 'C:\Windows\Temp\AegisScenario\marker.cmd' -Value '@exit /b 0' -Encoding ASCII
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Install-AegisSchedule.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Scheduler update failed.' }
Write-Host 'AEGIS_DETECTION_PACK_READY: Registry and task auditing enabled; expanded Atomic schedule started.'
