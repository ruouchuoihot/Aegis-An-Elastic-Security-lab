#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$aegisDestination = '\\host.lan\Data\results'
New-Item -ItemType Directory -Path $aegisDestination -Force | Out-Null
Get-CimInstance Win32_Service -Filter "Name='winlogbeat' OR Name='Sysmon64'" |
    Select-Object Name, State, ExitCode, PathName |
    ConvertTo-Json | Set-Content (Join-Path $aegisDestination 'services.json')
foreach ($aegisLogFolder in @('C:\AegisLab\collector-logs', 'C:\ProgramData\winlogbeat\Logs')) {
    if (Test-Path -LiteralPath $aegisLogFolder) {
        Get-ChildItem -LiteralPath $aegisLogFolder -File | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $aegisDestination -Force
        }
    }
}
Write-Host 'Aegis diagnostics exported to the dedicated exchange directory.'
