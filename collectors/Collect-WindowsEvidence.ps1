#requires -version 5.1
<#
  Recopilador de solo lectura para Windows PowerShell 5.1.
  No instala software, no cambia políticas ni extrae contraseñas.
  Ejecutar desde PowerShell como administrador para ampliar acceso a logs.
  Uso: powershell.exe -NoProfile -File .\Collect-WindowsEvidence.ps1 -Destination C:\Temp\DFIR
#>
param([string]$Destination = "$env:USERPROFILE\Desktop\DFIR")
$ErrorActionPreference = 'Continue'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
$hostName = $env:COMPUTERNAME
$root = Join-Path $Destination "${hostName}_$stamp"
$evtxDir = Join-Path $root 'events'
New-Item -ItemType Directory -Force -Path $evtxDir | Out-Null
$errors = New-Object System.Collections.Generic.List[string]

$logs = @(
    'Security', 'System', 'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Sysmon/Operational'
)
foreach ($log in $logs) {
    $filename = ($log -replace '[\\/]', '_') + '.evtx'
    $target = Join-Path $evtxDir $filename
    try {
        & wevtutil.exe epl $log $target /ow:true 2>$null
        if ($LASTEXITCODE -ne 0) { $errors.Add("No se pudo exportar $log (código $LASTEXITCODE)") }
    } catch { $errors.Add("Error al exportar ${log}: $($_.Exception.Message)") }
}

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$auto = $null
$hasDefaultPassword = $false
try {
    $key = Get-ItemProperty -Path $winlogon -ErrorAction Stop
    $auto = $key.AutoAdminLogon
    # Solo registramos existencia; NUNCA valor de una posible contraseña.
    $hasDefaultPassword = $null -ne $key.PSObject.Properties['DefaultPassword']
} catch { $errors.Add('No se pudo revisar AutoAdminLogon') }

$fw = @()
try {
    $fw = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled)
} catch { $errors.Add('No se pudo consultar perfiles del Firewall') }

$def = @{}
try {
    $pref = Get-MpPreference -ErrorAction Stop
    $def.ExclusionPath = @($pref.ExclusionPath | Where-Object { $_ })
    $def.ExclusionProcess = @($pref.ExclusionProcess | Where-Object { $_ })
    $def.ExclusionExtension = @($pref.ExclusionExtension | Where-Object { $_ })
} catch { $errors.Add('No se pudieron leer exclusiones de Defender') }
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $def.RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
    $def.AntivirusEnabled = $status.AntivirusEnabled
    $def.AMRunningMode = $status.AMRunningMode
    $def.IsTamperProtected = $status.IsTamperProtected
} catch { $errors.Add('No se pudo consultar estado de Defender') }

$data = @{
    security_snapshot = @{
        Hostname = $hostName
        CollectedUTC = (Get-Date).ToUniversalTime().ToString('o')
        AutoAdminLogon = $auto
        HasDefaultPasswordProperty = $hasDefaultPassword
        Firewall = $fw
        Defender = $def
    }
}
$data | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path (Join-Path $root 'security_snapshot.json')
$errors | Set-Content -Encoding UTF8 -Path (Join-Path $root 'collection_warnings.txt')
Get-ChildItem -Path $root -File -Recurse | Get-FileHash -Algorithm SHA256 |
    Select-Object Path, Hash | ConvertTo-Json -Depth 4 |
    Set-Content -Encoding UTF8 -Path (Join-Path $root 'sha256_files.json')

$archive = "$root.zip"
Compress-Archive -Path (Join-Path $root '*') -DestinationPath $archive -Force
Write-Host "[OK] Evidencias: $archive"
Write-Host "[OK] SHA256 ZIP: $((Get-FileHash -Algorithm SHA256 -Path $archive).Hash)"
Write-Host 'Conservar ZIP original y transferir por canal seguro. No compartir públicamente.'
