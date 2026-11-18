#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$aegisRoot = 'C:\AegisLab'
if (-not (Test-Path "$aegisRoot\atomic-install.json")) { throw 'Guest provisioning is incomplete.' }
$aegisMachine = Get-CimInstance Win32_ComputerSystem
if ($aegisMachine.Model -notmatch 'QEMU|Standard PC' -and $aegisMachine.Manufacturer -notmatch 'QEMU') { throw 'This runner is restricted to the QEMU lab guest.' }
$aegisInstall = Get-Content "$aegisRoot\atomic-install.json" -Raw | ConvertFrom-Json
$aegisCases = Get-Content "$aegisRoot\atomic_catalog.json" -Raw | ConvertFrom-Json
Import-Module $aegisInstall.module -Force
$aegisBatch = [guid]::NewGuid().ToString()
$aegisOutcomes = @()
$aegisTranscript = "$aegisRoot\batch-$aegisBatch.log"
Start-Transcript -Path $aegisTranscript
try {
    foreach ($aegisCase in $aegisCases) {
        $aegisStart = [DateTime]::UtcNow
        $aegisRun = [guid]::NewGuid().ToString()
        $aegisStatus = 'invoked'
        $aegisFailure = $null
        $aegisInputs = @{}
        if ($aegisCase.input_args) { foreach ($aegisProperty in $aegisCase.input_args.PSObject.Properties) { $aegisInputs[$aegisProperty.Name] = $aegisProperty.Value } }
        $aegisExecute = $false
        $aegisOldTemp = $env:TEMP
        $aegisWork = Join-Path "$aegisRoot\scenario-work" $aegisCase.id
        New-Item -ItemType Directory -Path $aegisWork -Force | Out-Null
        $env:TEMP = $aegisWork
        try {
            if ($aegisCase.id -like 'task-*' -and (Get-ScheduledTask -TaskName 'spawn' -ErrorAction SilentlyContinue)) { throw 'Reserved task name spawn already exists; skipped to preserve it.' }
            if ($aegisCase.id -eq 'registry-run-key' -and (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Atomic Red Team' -ErrorAction SilentlyContinue)) { throw 'Reserved Run value already exists; skipped to preserve it.' }
            $aegisExecute = $true
            Invoke-AtomicTest $aegisCase.technique -TestGuids $aegisCase.guid -PathToAtomicsFolder $aegisInstall.atomics -InputArgs $aegisInputs
        } catch { $aegisStatus = 'runner_failed'; $aegisFailure = $_.Exception.Message }
        Start-Sleep -Seconds 2
        $aegisEvents = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$aegisStart.ToLocalTime()} -ErrorAction SilentlyContinue | Where-Object {
            [xml]$aegisXml = $_.ToXml()
            $aegisImage = ($aegisXml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
            $aegisCase.processes -contains [IO.Path]::GetFileName($aegisImage)
        })
        if ($aegisCase.cleanup -and $aegisExecute) {
            try { Invoke-AtomicTest $aegisCase.technique -TestGuids $aegisCase.guid -PathToAtomicsFolder $aegisInstall.atomics -InputArgs $aegisInputs -Cleanup }
            catch { $aegisFailure = 'Cleanup failed: ' + $_.Exception.Message; $aegisStatus = 'cleanup_failed' }
        }
        $env:TEMP = $aegisOldTemp
        if ($aegisEvents.Count -gt 0 -and $aegisStatus -notin @('runner_failed','cleanup_failed')) { $aegisStatus = 'process_observed' }
        $aegisRecord = @{run_id=$aegisRun;batch_id=$aegisBatch;case_id=$aegisCase.id;technique=$aegisCase.technique;test_guid=$aegisCase.guid;test_name=$aegisCase.name;computer=$env:COMPUTERNAME;start=$aegisStart.ToString('o');end=[DateTime]::UtcNow.ToString('o');status=$aegisStatus;sysmon_record_ids=@($aegisEvents | ForEach-Object {$_.RecordId});check_only=$false;failure=$aegisFailure;note='Process observation is distinct from command success, ingestion and detection.'}
        $aegisRecord | ConvertTo-Json -Depth 5 | Set-Content "$aegisRoot\atomic-$aegisRun.json"
        Write-EventLog -LogName Application -Source AegisLab -EventId 101 -EntryType Information -Message ($aegisRecord | ConvertTo-Json -Depth 5 -Compress)
        $aegisOutcomes += $aegisRecord
        try { Copy-Item -LiteralPath "$aegisRoot\atomic-$aegisRun.json" -Destination '\\host.lan\Data\results' -Force } catch { Write-Warning 'Run record remains in guest.' }
        Start-Sleep -Seconds 2
    }
} finally {
    Stop-Transcript
    $aegisTask = Get-ScheduledTask -TaskName 'Aegis Atomic Lab Cycle' -ErrorAction SilentlyContinue
    $aegisTaskInfo = Get-ScheduledTaskInfo -TaskName 'Aegis Atomic Lab Cycle' -ErrorAction SilentlyContinue
    $aegisSchedule = @{task_name='Aegis Atomic Lab Cycle';interval_minutes=5;state=$(if($aegisTask){$aegisTask.State.ToString()}else{'NotRegistered'});batch_id=$aegisBatch;updated_at=[DateTime]::UtcNow.ToString('o');last_batch_cases=$aegisOutcomes.Count;last_batch_observed=@($aegisOutcomes | Where-Object {$_.status -eq 'process_observed'}).Count;last_task_result=$aegisTaskInfo.LastTaskResult;next_run=$(if($aegisTaskInfo){$aegisTaskInfo.NextRunTime.ToUniversalTime().ToString('o')}else{$null})}
    $aegisSchedule | ConvertTo-Json | Set-Content "$aegisRoot\atomic-schedule.json"
    try {
        Copy-Item -LiteralPath "$aegisRoot\atomic-schedule.json" -Destination '\\host.lan\Data\results' -Force
        Copy-Item -LiteralPath $aegisTranscript -Destination '\\host.lan\Data\results' -Force
    } catch { Write-Warning 'Batch transcript and schedule remain in guest.' }
}
