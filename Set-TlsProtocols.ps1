<#
.SYNOPSIS
    Toggle SCHANNEL protocol versions securely with backup/restore and reporting.

.DESCRIPTION
    Enables/disables SSL 2.0/3.0, TLS 1.0/1.1/1.2 for Server/Client registry keys under:
    HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols

.PARAMETER Secure
    Applies a secure baseline: Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1; Enable TLS 1.2.

.PARAMETER Enable
    One or more protocol names to enable (e.g. "TLS 1.2").

.PARAMETER Disable
    One or more protocol names to disable (e.g. "TLS 1.0","TLS 1.1").

.PARAMETER Scope
    Target 'Server', 'Client', or 'Both' (default: Both).

.PARAMETER Backup
    Save current SCHANNEL protocol settings to a JSON file before changes.

.PARAMETER BackupPath
    Where to write/read backups. Defaults to "$env:ProgramData\TlsToggle".

.PARAMETER Restore
    Restore settings from a previous backup (provide -From).

.PARAMETER From
    Backup file path to restore from.

.PARAMETER EnableDotNetStrongCrypto
    Sets .NET 4.x Strong Crypto and SystemDefaultTlsVersions for machine-wide defaults.

.PARAMETER ReportOnly
    Just print the current protocol states and exit (no changes).

.EXAMPLE
    # Secure baseline with safety:
    .\Toggle-TlsProtocols.ps1 -Secure -Backup -WhatIf

.EXAMPLE
    # Actually apply:
    .\Toggle-TlsProtocols.ps1 -Secure -Backup

.EXAMPLE
    # Disable TLS 1.0/1.1 and enable TLS 1.2 only on Server side:
    .\Toggle-TlsProtocols.ps1 -Disable "TLS 1.0","TLS 1.1" -Enable "TLS 1.2" -Scope Server -Backup

.EXAMPLE
    # Restore from a backup:
    .\Toggle-TlsProtocols.ps1 -Restore -From "C:\ProgramData\TlsToggle\backup-2024-09-09T140101.json"
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [switch]$Secure,
    [ValidateSet("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2")]
    [string[]]$Enable,
    [ValidateSet("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2")]
    [string[]]$Disable,
    [ValidateSet("Server","Client","Both")]
    [string]$Scope = "Both",
    [switch]$Backup,
    [string]$BackupPath = "$env:ProgramData\TlsToggle",
    [switch]$Restore,
    [string]$From,
    [switch]$EnableDotNetStrongCrypto,
    [switch]$ReportOnly
)

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw "Access denied. Please run PowerShell as Administrator."
}

$ProtocolNames = @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2")
$Root = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

function Get-ProtoKeyPaths([string]$name,[string]$scope){
    $paths = @()
    if ($scope -eq "Server" -or $scope -eq "Both") { $paths += Join-Path "$Root\$name" "Server" }
    if ($scope -eq "Client" -or $scope -eq "Both") { $paths += Join-Path "$Root\$name" "Client" }
    return $paths
}

function Ensure-Key([string]$path){
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}

function Get-ProtocolState([string]$name,[string]$scope){
    $paths = Get-ProtoKeyPaths -name $name -scope $scope
    $result = @()
    foreach($p in $paths){
        $enabled = (Get-ItemProperty -Path $p -Name Enabled -ErrorAction SilentlyContinue).Enabled
        $disabledByDefault = (Get-ItemProperty -Path $p -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
        $result += [pscustomobject]@{
            Protocol = $name
            Path = $p
            Enabled = if ($null -eq $enabled) { $null } else { [int]$enabled }
            DisabledByDefault = if ($null -eq $disabledByDefault){ $null } else { [int]$disabledByDefault }
            Effective = switch -Wildcard ($enabled,$disabledByDefault) {
                { $_[0] -eq 1 -and $_[1] -eq 0 } { "Enabled" ; break }
                { $_[0] -eq 0 -and $_[1] -eq 1 } { "Disabled" ; break }
                default { "Undefined" }
            }
        }
    }
    return $result
}

function Set-Protocol([string]$name,[bool]$enable,[string]$scope){
    $paths = Get-ProtoKeyPaths -name $name -scope $scope
    foreach($p in $paths){
        Ensure-Key $p
        $target = if($enable){"enable"}else{"disable"}
        if ($PSCmdlet.ShouldProcess("$name @ $p", "Set to $target")) {
            try {
                # Enabled:1 + DisabledByDefault:0  => protocol enabled
                # Enabled:0 + DisabledByDefault:1  => protocol disabled
                $en = [int]($enable)
                $dbd = [int](-not $enable)
                New-ItemProperty -Path $p -Name 'Enabled' -Value $en -PropertyType DWord -Force | Out-Null
                New-ItemProperty -Path $p -Name 'DisabledByDefault' -Value $dbd -PropertyType DWord -Force | Out-Null
            } catch {
                Write-Error "Failed to set $name at $p : $($_.Exception.Message)"
            }
        }
    }
}

function Save-Backup([string]$destDir){
    if (-not (Test-Path $destDir)){ New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    $stamp = (Get-Date).ToString("yyyy-MM-ddTHHmmss")
    $file  = Join-Path $destDir "backup-$stamp.json"
    $snap = @()
    foreach($n in $ProtocolNames){
        $snap += Get-ProtocolState -name $n -scope "Both"
    }
    $snap | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
    Write-Host "Backup saved to: $file"
    return $file
}

function Restore-FromFile([string]$file){
    if (-not (Test-Path $file)) { throw "Backup file not found: $file" }
    $data = Get-Content -Path $file -Raw | ConvertFrom-Json
    foreach($row in $data){
        $name = $row.Protocol
        $path = $row.Path
        $enable = $row.Enabled -eq 1 -and $row.DisabledByDefault -eq 0
        if ($PSCmdlet.ShouldProcess("$name @ $path","Restore to $((if($enable){"Enabled"}else{"Disabled/Undefined"}))")){
            Ensure-Key $path
            if ($row.Enabled -ne $null){ New-ItemProperty -Path $path -Name 'Enabled' -Value ([int]$row.Enabled) -PropertyType DWord -Force | Out-Null }
            if ($row.DisabledByDefault -ne $null){ New-ItemProperty -Path $path -Name 'DisabledByDefault' -Value ([int]$row.DisabledByDefault) -PropertyType DWord -Force | Out-Null }
        }
    }
}

function Write-Report([string]$title){
    Write-Host "`n==== $title ====" -ForegroundColor Cyan
    $table = foreach($n in $ProtocolNames){ Get-ProtocolState -name $n -scope "Both" }
    $table | Sort-Object Protocol,Path | Format-Table Protocol, Path, Enabled, DisabledByDefault, Effective -AutoSize
}

function Set-DotNetStrongCrypto {
    # Enables strong crypto & default TLS versions for .NET 4.x + WinHTTP defaults
    $base = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    $baseWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    $ieBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    $winHttp = Join-Path $ieBase "WinHttp"

    foreach($b in @($base,$baseWow)){
        if ($PSCmdlet.ShouldProcess($b,"Enable SchUseStrongCrypto=1; SystemDefaultTlsVersions=1")){
            New-Item -Path $b -Force | Out-Null
            New-ItemProperty -Path $b -Name "SchUseStrongCrypto" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $b -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType DWord -Force | Out-Null
        }
    }

    if ($PSCmdlet.ShouldProcess($ieBase,"Set DefaultSecureProtocols (TLS 1.2)")){
        # 0x00000800 = TLS1.2 for WinHTTP/WinINET default secure protocols
        New-Item -Path $ieBase -Force | Out-Null
        New-ItemProperty -Path $ieBase -Name "DefaultSecureProtocols" -Value 0x00000800 -PropertyType DWord -Force | Out-Null
        New-Item -Path $winHttp -Force | Out-Null
        New-ItemProperty -Path $winHttp -Name "DefaultSecureProtocols" -Value 0x00000800 -PropertyType DWord -Force | Out-Null
    }

    Write-Host "Enabled .NET strong crypto and default secure protocols for legacy clients."
}

# ---------------- Main flow ----------------

Write-Report "Current SCHANNEL Protocol State"

if ($ReportOnly) { return }

if ($Restore){
    if (-not $From){ throw "Use -From <backup.json> with -Restore." }
    Restore-FromFile -file $From
    Write-Report "State After Restore"
    Write-Host "`nReboot required for changes to take effect."
    return
}

if ($Backup){
    $backupFile = Save-Backup -destDir $BackupPath
}

# Resolve target actions
$toEnable = @()
$toDisable = @()

if ($Secure){
    $toDisable += "SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1"
    $toEnable  += "TLS 1.2"
}

if ($Enable){  $toEnable  += $Enable }
if ($Disable){ $toDisable += $Disable }

# Deduplicate / sanity
$toEnable  = $toEnable  | Where-Object { $_ } | Select-Object -Unique
$toDisable = $toDisable | Where-Object { $_ } | Select-Object -Unique
$clash = Compare-Object -ReferenceObject $toEnable -DifferenceObject $toDisable -IncludeEqual -ExcludeDifferent | ForEach-Object {$_.InputObject}
if ($clash){
    throw "Same protocol specified in -Enable and -Disable: $($clash -join ', ')"
}

# Apply changes
foreach($n in $toEnable){
    if ($ProtocolNames -notcontains $n){ Write-Warning "Unknown protocol '$n' (skipped)"; continue }
    Set-Protocol -name $n -enable:$true -scope $Scope
}

foreach($n in $toDisable){
    if ($ProtocolNames -notcontains $n){ Write-Warning "Unknown protocol '$n' (skipped)"; continue }
    Set-Protocol -name $n -enable:$false -scope $Scope
}

if ($EnableDotNetStrongCrypto){
    Set-DotNetStrongCrypto
}

Write-Report "State After Changes"
Write-Host "`nReboot required for SCHANNEL protocol changes to take effect."
