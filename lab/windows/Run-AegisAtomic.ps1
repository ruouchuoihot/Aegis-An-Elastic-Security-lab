#Requires -RunAsAdministrator
param([switch]$CheckPrerequisites)
$ErrorActionPreference = 'Stop'
$aegisLabRoot = 'C:\AegisLab'
if (-not (Test-Path -LiteralPath "$aegisLabRoot\atomic-install.json")) { throw 'Aegis guest provisioning has not completed.' }
$install = Get-Content "$aegisLabRoot\atomic-install.json" -Raw | ConvertFrom-Json
Import-Module $install.module -Force
$guid = 'c5806a4f-62b8-4900-980b-c7ec004e9908' # T1057: tasklist, discovery only.
$started = [DateTime]::UtcNow
$run = [guid]::NewGuid().ToString()
$log = "$aegisLabRoot\atomic-$run.log"
Start-Transcript -Path $log
try {
    if ($CheckPrerequisites) {
        Invoke-AtomicTest T1057 -TestGuids $guid -PathToAtomicsFolder $install.atomics -CheckPrereqs
    } else {
        Invoke-AtomicTest T1057 -TestGuids $guid -PathToAtomicsFolder $install.atomics
    }
    $observed = @()
    if (-not $CheckPrerequisites) {
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            Start-Sleep -Seconds 2
            $observed = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$started.ToLocalTime()} -ErrorAction SilentlyContinue | Where-Object {
                [xml]$xml = $_.ToXml()
                @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' -and $_.'#text' -match '\\tasklist\.exe$' }).Count -gt 0
            })
            if ($observed.Count -gt 0) { break }
        }
    }
    $record = @{run_id=$run; technique='T1057'; test_guid=$guid; computer=$env:COMPUTERNAME; start=$started.ToString('o'); end=[DateTime]::UtcNow.ToString('o'); status=$(if ($observed.Count -gt 0) {'tasklist_observed'} else {'invoked'}); sysmon_record_ids=@($observed | ForEach-Object {$_.RecordId}); check_only=[bool]$CheckPrerequisites; note='Local event observation is separate from ingestion/detection. Review the transcript and event parentage for attribution.'}
    $record | ConvertTo-Json | Set-Content "$aegisLabRoot\atomic-$run.json"
    Write-EventLog -LogName Application -Source AegisLab -EventId 101 -EntryType Information -Message ($record | ConvertTo-Json -Compress)
} finally { Stop-Transcript }
try {
    Copy-Item -LiteralPath $log -Destination '\\host.lan\Data\results' -Force
    Copy-Item -LiteralPath "$aegisLabRoot\atomic-$run.json" -Destination '\\host.lan\Data\results' -Force
} catch { Write-Warning 'Run records remain in C:\AegisLab.' }
