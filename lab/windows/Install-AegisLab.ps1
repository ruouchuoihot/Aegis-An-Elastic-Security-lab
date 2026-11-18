#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$aegisLabRoot = 'C:\AegisLab'
New-Item -ItemType Directory -Force -Path $aegisLabRoot | Out-Null
& icacls.exe $aegisLabRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict permissions on guest lab configuration' }
Start-Transcript -Path "$aegisLabRoot\bootstrap.log" -Append
try {
    $aegisSettings = Get-Content -LiteralPath C:\OEM\settings.json -Raw | ConvertFrom-Json
    # Guard against accidental execution on the analyst's workstation.
    $machine = Get-CimInstance Win32_ComputerSystem
    if ($machine.Model -notmatch 'QEMU|Standard PC' -and $machine.Manufacturer -notmatch 'QEMU') {
        throw 'This bootstrap is intended only for the disposable QEMU Windows lab.'
    }
    if (-not [System.Diagnostics.EventLog]::SourceExists('AegisLab')) {
        New-EventLog -LogName Application -Source AegisLab
    }
    Copy-Item -LiteralPath C:\OEM\ca.crt -Destination "$aegisLabRoot\ca.crt" -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-AegisAtomic.ps1') -Destination "$aegisLabRoot\Run-AegisAtomic.ps1" -Force
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsText = Get-Content -LiteralPath $hostsFile | Where-Object { $_ -notmatch '# aegis-es$' }
    @($hostsText; "$($aegisSettings.es_ip) es01 # aegis-es") | Set-Content -LiteralPath $hostsFile -Encoding ASCII

    Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$aegisLabRoot\Sysmon.zip"
    Expand-Archive -LiteralPath "$aegisLabRoot\Sysmon.zip" -DestinationPath "$aegisLabRoot\Sysmon" -Force
    $signature = Get-AuthenticodeSignature "$aegisLabRoot\Sysmon\Sysmon64.exe"
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'Invalid Sysmon publisher signature' }
    if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
        & "$aegisLabRoot\Sysmon\Sysmon64.exe" -accepteula -i C:\OEM\sysmon.xml
        if ($LASTEXITCODE -ne 0) { throw 'Sysmon installation failed' }
    }

    # Keep native process auditing as a second source alongside Sysmon.
    & auditpol.exe /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enable Process Creation auditing' }
    & auditpol.exe /set '/subcategory:Other Object Access Events' /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enable scheduled-task auditing' }
    New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null

    $version = $aegisSettings.stack_version
    $zipName = "winlogbeat-$version-windows-x86_64.zip"
    $url = "https://artifacts.elastic.co/downloads/beats/winlogbeat/$zipName"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile "$aegisLabRoot\$zipName"
    Invoke-WebRequest -UseBasicParsing -Uri "$url.sha512" -OutFile "$aegisLabRoot\$zipName.sha512"
    $checksum = (Get-Content -LiteralPath "$aegisLabRoot\$zipName.sha512" -Raw).Trim().Split(' ')[0]
    if ((Get-FileHash -LiteralPath "$aegisLabRoot\$zipName" -Algorithm SHA512).Hash -ne $checksum) { throw 'Winlogbeat SHA512 mismatch' }
    if (Get-Service winlogbeat -ErrorAction SilentlyContinue) { Stop-Service winlogbeat -Force }
    Expand-Archive -LiteralPath "$aegisLabRoot\$zipName" -DestinationPath $aegisLabRoot -Force
    $beat = "$aegisLabRoot\winlogbeat-$version-windows-x86_64"
    Copy-Item -LiteralPath C:\OEM\winlogbeat.yml -Destination "$beat\winlogbeat.yml" -Force
    & "$beat\winlogbeat.exe" test config -c "$beat\winlogbeat.yml" --path.home $beat
    if ($LASTEXITCODE -ne 0) { throw 'Winlogbeat config validation failed' }
    & "$beat\winlogbeat.exe" test output -c "$beat\winlogbeat.yml" --path.home $beat
    if ($LASTEXITCODE -ne 0) { throw 'Cannot reach Elasticsearch with TLS/API key' }
    if (-not (Get-Service winlogbeat -ErrorAction SilentlyContinue)) {
        & "$beat\install-service-winlogbeat.ps1"
    }
    Start-Service winlogbeat

    # Install only the framework and a small curated YAML catalog, no attack payloads.
    $aegisAtomicRoot = "$aegisLabRoot\AtomicRedTeam"
    New-Item -ItemType Directory -Path $aegisAtomicRoot -Force | Out-Null
    $ref = $aegisSettings.invoke_atomic_ref
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/redcanaryco/invoke-atomicredteam/archive/$ref.zip" -OutFile "$aegisAtomicRoot\framework.zip"
    Expand-Archive -LiteralPath "$aegisAtomicRoot\framework.zip" -DestinationPath $aegisAtomicRoot -Force
    $aegisAtomicModule = "$aegisAtomicRoot\invoke-atomicredteam-$ref\Invoke-AtomicRedTeam.psd1"
    # NuGet/PSGallery dependencies are installed in this guest only.
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
    Install-Module powershell-yaml -RequiredVersion $aegisSettings.yaml_version -Scope AllUsers -Force -AllowClobber -Repository PSGallery -Confirm:$false
    New-Item -ItemType Directory -Path "$aegisAtomicRoot\atomics\T1057" -Force | Out-Null
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/$($aegisSettings.atomics_ref)/atomics/T1057/T1057.yaml" -OutFile "$aegisAtomicRoot\atomics\T1057\T1057.yaml"
    Import-Module $aegisAtomicModule -Force
    Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null
    @{ module = $aegisAtomicModule; atomics = "$aegisAtomicRoot\atomics"; installed_at = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content "$aegisLabRoot\atomic-install.json"

    $result = @{ status = 'installed'; computer = $env:COMPUTERNAME; time = [DateTime]::UtcNow.ToString('o'); sysmon = (Get-Service Sysmon64).Status.ToString(); collector = (Get-Service winlogbeat).Status.ToString() }
    $result | ConvertTo-Json | Set-Content "$aegisLabRoot\bootstrap-result.json"
    Write-EventLog -LogName Application -Source AegisLab -EventId 100 -EntryType Information -Message ($result | ConvertTo-Json -Compress)
    Write-Host 'AEGIS_LAB_READY: Atomic Red Team, Sysmon and Winlogbeat installed.'
    if ($aegisSettings.run_smoke -eq $true) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$aegisLabRoot\Run-AegisAtomic.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'Atomic runner process failed; inspect the guest transcript' }
    }
} catch {
    @{ status = 'failed'; error = $_.Exception.Message; time = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content "$aegisLabRoot\bootstrap-result.json"
    Write-Error $_
} finally {
    Stop-Transcript
    # Only the dedicated exchange directory is shared, never the project or host root.
    try {
        $dest = '\\host.lan\Data\results'
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -LiteralPath "$aegisLabRoot\bootstrap-result.json" -Destination $dest -Force
        Copy-Item -LiteralPath "$aegisLabRoot\bootstrap.log" -Destination $dest -Force
    } catch { Write-Warning 'Results remain in C:\AegisLab; shared-folder copy unavailable.' }
}
