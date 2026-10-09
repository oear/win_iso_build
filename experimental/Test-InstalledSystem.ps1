#requires -Version 5.1
<#
Collect evidence after installing an experimental ISO in a disposable VM.
Run from a normal, non-elevated PowerShell window. This script does not repair
permissions, change the registry, start an update scan, or read proxy configs.
Exit 0 means evidence was collected, NOT that the experimental ISO passed.
#>
[CmdletBinding()]
param(
    [string]$ExpectedBuild = '',
    [string]$OutputPath = (Join-Path (Get-Location).Path ('ltsc-acceptance-{0}-{1}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N').Substring(0, 8))),
    [ValidateRange(1, 30)][int]$EventDays = 7
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this collector on the installed Windows system, not the build host.' }
if ($ExpectedBuild -and $ExpectedBuild -notmatch '^\d+\.\d+$') { throw 'ExpectedBuild must be a build.revision string, for example 26340.9616. This parameter is an expectation, not source verification.' }
$outputFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([IO.File]::Exists($outputFullPath)) { throw 'OutputPath already exists. Choose a new file so earlier evidence is preserved.' }
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($outputFullPath))) { throw 'The output directory must already exist.' }

$checks = New-Object 'System.Collections.Generic.List[object]'
function Add-Check {
    param([string]$Id, [string]$Status, $Evidence, [string]$Note)
    $checks.Add([pscustomobject][ordered]@{ Id = $Id; Status = $Status; Evidence = $Evidence; Note = $Note })
}
function Get-ErrorSummary {
    param($Record)
    # Do not serialize arbitrary exception messages, event messages, or configs.
    [pscustomobject]@{ ExceptionType = $Record.Exception.GetType().FullName; HResult = $Record.Exception.HResult }
}
function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        try { return $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
        finally { $key.Close() }
    }
    return $null
}
function Get-AclEvidence {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    [pscustomobject][ordered]@{
        Path = $Path
        Owner = $acl.Owner
        InheritanceDisabled = $acl.AreAccessRulesProtected
        Entries = @($acl.Access | ForEach-Object {
            [pscustomobject]@{
                Identity = $_.IdentityReference.Value
                Rights = $_.FileSystemRights.ToString()
                Type = $_.AccessControlType.ToString()
                Inherited = $_.IsInherited
                Inheritance = $_.InheritanceFlags.ToString()
                Propagation = $_.PropagationFlags.ToString()
            }
        })
    }
}
function Test-UserDirectory {
    param([string]$Label, [string]$Path, [bool]$Elevated)
    if ($Elevated) {
        Add-Check ('Write.' + $Label) 'NotRun' @{ Path = $Path } 'Elevated access could hide the reported ACL bug. Rerun from a normal PowerShell window.'
        return
    }
    if (-not $Path -or -not [IO.Directory]::Exists($Path)) {
        Add-Check ('Write.' + $Label) 'Failed' @{ Path = $Path } 'The user directory was not resolved or does not exist; no directory was created.'
        return
    }
    $probe = Join-Path $Path ('.ltsc-acceptance-' + [Guid]::NewGuid().ToString('N'))
    $first = Join-Path $probe 'probe.txt'
    $renamed = Join-Path $probe 'renamed.txt'
    $created = $false
    $stage = 'CreateDirectory'
    $failure = $null
    $cleanupFailure = $null
    try {
        if ([IO.Directory]::Exists($probe) -or [IO.File]::Exists($probe)) { throw 'Probe path collision.' }
        [void][IO.Directory]::CreateDirectory($probe)
        $created = $true
        $stage = 'CreateFile'
        $content = 'LTSC acceptance probe ' + [Guid]::NewGuid().ToString('N')
        $bytes = [Text.Encoding]::UTF8.GetBytes($content)
        $stream = [IO.File]::Open($first, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        $stage = 'ReadFile'
        if ([IO.File]::ReadAllText($first, [Text.Encoding]::UTF8) -cne $content) { throw 'Probe readback mismatch.' }
        $stage = 'RenameFile'
        [IO.File]::Move($first, $renamed)
        $stage = 'DeleteFile'
        [IO.File]::Delete($renamed)
    }
    catch { $failure = Get-ErrorSummary $_ }
    finally {
        if ($created) {
            try {
                # Delete only names created by this probe; never recursively delete
                # unexpected content that another program might have placed here.
                if ([IO.File]::Exists($first)) { [IO.File]::Delete($first) }
                if ([IO.File]::Exists($renamed)) { [IO.File]::Delete($renamed) }
                [IO.Directory]::Delete($probe, $false)
            }
            catch { $cleanupFailure = Get-ErrorSummary $_ }
        }
    }
    $evidence = [ordered]@{ Path = $Path; ProbePath = $probe; LastStage = $stage; Error = $failure; CleanupError = $cleanupFailure }
    if ($failure -or $cleanupFailure) {
        Add-Check ('Write.' + $Label) 'Failed' $evidence 'Normal-user create/read/rename/delete or cleanup failed. Preserve evidence before any repair.'
    }
    else {
        Add-Check ('Write.' + $Label) 'Passed' $evidence 'This small normal-user file probe passed. Explorer menu behavior and long-term ACL correctness still need manual acceptance.'
    }
}
function Get-ShellNewEvidence {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Path = $Path; Exists = $false; ValueNames = @(); CreationMechanismPresent = $false } }
    $key = Get-Item -LiteralPath $Path
    try {
        $names = @($key.GetValueNames() | Where-Object { $_ -in @('NullFile', 'FileName', 'Command', 'Data', 'ItemName') })
        [pscustomobject]@{ Path = $Path; Exists = $true; ValueNames = $names; CreationMechanismPresent = (@($names | Where-Object { $_ -in @('NullFile', 'FileName', 'Command', 'Data') }).Count -gt 0) }
    }
    finally { $key.Close() }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Check 'ExecutionContext' $(if ($elevated) { 'Failed' } else { 'Passed' }) @{ User = $identity.Name; SID = $sid; Elevated = $elevated } 'Writability probes are valid only under the affected normal user, without elevation.'

try {
    $cv = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [string](Get-RegistryValue $cv 'CurrentBuildNumber')
    $revision = Get-RegistryValue $cv 'UBR'
    $actualBuild = if ($build -and $null -ne $revision) { '{0}.{1}' -f $build, $revision } else { 'Unknown' }
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $edition = [string](Get-RegistryValue $cv 'EditionID')
    $installLanguage = [string](Get-RegistryValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language' 'InstallLanguage')
    $system = [ordered]@{
        ActualBuild = $actualBuild; ExpectedBuild = $ExpectedBuild
        EditionID = $edition; CompositionEditionID = Get-RegistryValue $cv 'CompositionEditionID'
        DisplayVersion = Get-RegistryValue $cv 'DisplayVersion'; BuildLabEx = Get-RegistryValue $cv 'BuildLabEx'
        Architecture = $architecture; Is64BitOS = [Environment]::Is64BitOperatingSystem
        InstallLanguage = $installLanguage; CurrentUICulture = (Get-UICulture).Name
        SystemLocale = (Get-WinSystemLocale).Name
    }
    $targetStatus = 'Observed'
    if ($ExpectedBuild) { $targetStatus = if ($actualBuild -eq $ExpectedBuild) { 'Passed' } else { 'Failed' } }
    Add-Check 'BuildIdentity' $targetStatus $system 'Build identity matching is not proof of Microsoft LTSC support, package applicability, or authenticity.'
    Add-Check 'TargetEditionArchitectureLanguage' $(if ($edition -eq 'EnterpriseS' -and $architecture -eq 'AMD64' -and $installLanguage -eq '0804') { 'Passed' } else { 'Failed' }) @{ EditionID = $edition; Architecture = $architecture; InstallLanguage = $installLanguage } 'Expected target: EnterpriseS, x64/AMD64, Simplified Chinese installation language 0804. Check any intentional evaluation or redirected-language difference separately.'
}
catch { Add-Check 'BuildIdentity' 'Failed' (Get-ErrorSummary $_) 'Could not collect the installed system identity.' }

$directories = [ordered]@{
    Profile = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
    Desktop = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::DesktopDirectory)
    Documents = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
}
try {
    $mappedProfile = Get-RegistryValue ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid) 'ProfileImagePath'
    Add-Check 'ProfileIdentity' 'Observed' @{ SID = $sid; EnvironmentProfile = $env:USERPROFILE; KnownFolderProfile = $directories.Profile; RegisteredProfile = $mappedProfile } 'Compare SID and paths with the newly installed account; identical account names do not prove identical SIDs.'
}
catch { Add-Check 'ProfileIdentity' 'NotRun' (Get-ErrorSummary $_) 'Profile mapping could not be read.' }
foreach ($entry in $directories.GetEnumerator()) {
    try {
        if (-not $entry.Value) { throw 'Known folder could not be resolved.' }
        Add-Check ('ACL.' + $entry.Key) 'Observed' (Get-AclEvidence $entry.Value) 'ACL evidence is read-only. The script does not change ownership, inheritance, or permissions.'
    }
    catch { Add-Check ('ACL.' + $entry.Key) 'NotRun' (Get-ErrorSummary $_) 'ACL could not be collected; do not infer that permissions are correct.' }
    Test-UserDirectory $entry.Key $entry.Value $elevated
}

try {
    $rawProgId = [string](Get-RegistryValue 'Registry::HKEY_CLASSES_ROOT\.txt' '')
    $rawUserChoice = [string](Get-RegistryValue 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice' 'ProgId')
    # Store only conventional ProgID syntax; never serialize ShellNew command/data.
    $progId = if ($rawProgId -match '^[A-Za-z0-9_.\\-]{1,160}$') { $rawProgId } else { '' }
    $userChoice = if ($rawUserChoice -match '^[A-Za-z0-9_.\\-]{1,160}$') { $rawUserChoice } else { '' }
    $shellPaths = @(
        'Registry::HKEY_CLASSES_ROOT\.txt\ShellNew',
        'Registry::HKEY_CURRENT_USER\Software\Classes\.txt\ShellNew',
        'Registry::HKEY_LOCAL_MACHINE\Software\Classes\.txt\ShellNew'
    )
    if ($progId) { $shellPaths += ('Registry::HKEY_CLASSES_ROOT\.txt\' + $progId + '\ShellNew') }
    $shellNew = @($shellPaths | ForEach-Object { Get-ShellNewEvidence $_ })
    Add-Check 'TextShellNewRegistry' 'Observed' @{ DefaultProgId = $progId; UserChoiceProgId = $userChoice; ProgIdSyntaxRecognized = [bool]$progId; ShellNew = $shellNew } 'Registry presence does not prove the actual Explorer New menu works. No registry values were written; raw Command/Data/Hash values are omitted.'
}
catch { Add-Check 'TextShellNewRegistry' 'NotRun' (Get-ErrorSummary $_) 'Could not read the effective text-file association.' }

try {
    $serviceNames = @('wuauserv', 'BITS', 'UsoSvc', 'WaaSMedicSvc', 'DoSvc')
    $services = @($serviceNames | ForEach-Object {
        $name = $_
        $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name)
        if ($null -eq $service) { [pscustomobject]@{ Name = $name; Exists = $false; State = $null; StartMode = $null } }
        else { [pscustomobject]@{ Name = $name; Exists = $true; State = $service.State; StartMode = $service.StartMode } }
    })
    Add-Check 'WindowsUpdateServices' 'Observed' $services 'Stopped trigger-start services can be normal. Service presence/state is not proof of Windows Update compatibility. No service was started or modified.'
}
catch { Add-Check 'WindowsUpdateServices' 'NotRun' (Get-ErrorSummary $_) 'Could not inspect update service state.' }
try {
    $wuPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPath = $wuPath + '\AU'
    $policy = [ordered]@{}
    foreach ($name in @('DisableWindowsUpdateAccess', 'DoNotConnectToWindowsUpdateInternetLocations', 'SetDisableUXWUAccess', 'TargetReleaseVersion', 'ManagePreviewBuilds', 'ManagePreviewBuildsPolicyValue', 'BranchReadinessLevel', 'DeferFeatureUpdatesPeriodInDays')) {
        $value = Get-RegistryValue $wuPath $name
        $policy[$name] = if ($null -ne $value -and [string]$value -match '^\d{1,10}$') { [string]$value } else { $null }
    }
    foreach ($name in @('NoAutoUpdate', 'AUOptions', 'UseWUServer', 'NoAutoRebootWithLoggedOnUsers')) {
        $value = Get-RegistryValue $auPath $name
        $policy['AU.' + $name] = if ($null -ne $value -and [string]$value -match '^\d{1,10}$') { [string]$value } else { $null }
    }
    $wuKey = if (Test-Path -LiteralPath $wuPath) { Get-Item -LiteralPath $wuPath } else { $null }
    try { $policy['ManagedServerValuePresent'] = if ($wuKey) { @($wuKey.GetValueNames() | Where-Object { $_ -in @('WUServer', 'WUStatusServer') }).Count -gt 0 } else { $false } }
    finally { if ($wuKey) { $wuKey.Close() } }
    Add-Check 'WindowsUpdatePolicies' 'Observed' $policy 'Only selected numeric policies and managed-server presence are recorded. Internal URLs are omitted. No policy was changed.'
}
catch { Add-Check 'WindowsUpdatePolicies' 'NotRun' (Get-ErrorSummary $_) 'Could not inspect update policies.' }
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; StartTime = (Get-Date).AddDays(-$EventDays) } -MaxEvents 30 | ForEach-Object {
        [pscustomobject]@{ TimeUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); Id = $_.Id; Level = $_.Level; Provider = $_.ProviderName; RecordId = $_.RecordId }
    })
    Add-Check 'WindowsUpdateEvents' 'Observed' $events 'Recent event metadata only; messages are omitted. The collector did not initiate a scan, download, install, or upgrade.'
}
catch {
    if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { Add-Check 'WindowsUpdateEvents' 'Observed' @() 'No recent matching events. An empty log is not proof that updates work.' }
    else { Add-Check 'WindowsUpdateEvents' 'NotRun' (Get-ErrorSummary $_) 'Event log could not be read; manual update acceptance remains required.' }
}

try {
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($command in @(Get-Command 'sing-box.exe' -CommandType Application -ErrorAction SilentlyContinue)) { $candidates.Add($command.Source) }
    foreach ($path in @(
        (Join-Path $env:ProgramFiles 'sing-box\sing-box.exe'),
        (Join-Path $env:LOCALAPPDATA 'sing-box\sing-box.exe'),
        (Join-Path $env:USERPROFILE 'scoop\apps\sing-box\current\sing-box.exe'),
        (Join-Path $env:ProgramData 'chocolatey\bin\sing-box.exe')
    )) { if ([IO.File]::Exists($path)) { $candidates.Add($path) } }
    $binaries = @($candidates | Select-Object -Unique | ForEach-Object {
        $file = Get-Item -LiteralPath $_
        # File metadata only. Do not execute an unverified discovered binary or read
        # its configuration; many Go binaries have no Windows version resource.
        $version = $file.VersionInfo.FileVersion
        if (-not $version -or $version -notmatch '^[0-9A-Za-z.+ _-]{1,64}$') { $version = $null }
        [pscustomobject]@{ Path = $file.FullName; FileVersion = $version; SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
    })
    $running = @(Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name = $_.ProcessName; Id = $_.Id } })
    Add-Check 'SingBoxLocalPresence' 'Observed' @{ Binaries = $binaries; RunningProcesses = $running; SearchScope = 'PATH and common local installation locations; no recursive scan' } 'Presence/hash/file metadata do not prove the runtime version or Reality compatibility. Verify a trusted binary privately with sing-box version; no config, command line, credentials, or remote endpoints were collected.'
}
catch { Add-Check 'SingBoxLocalPresence' 'NotRun' (Get-ErrorSummary $_) 'Local binary metadata could not be collected.' }

$manual = @(
    [pscustomobject]@{ Id = 'ExplorerNewMenu'; Status = 'NotRun'; Requirement = 'Under the same normal user, test Profile/Desktop/Documents: New Folder and Text Document, edit/save/rename/delete, no elevation prompt. Restart Explorer or sign out/in and repeat.' },
    [pscustomobject]@{ Id = 'WindowsUpdate'; Status = 'NotRun'; Requirement = 'In a disposable VM, snapshot first; manually scan, inspect offered updates, install only the intended applicable update, reboot, verify build/edition/ACL/menu and errors. Preserve before/after evidence.' },
    [pscustomobject]@{ Id = 'RealitySingBox'; Status = 'NotRun'; Requirement = 'Use a private authorized endpoint and validated client. Test Reality handshake, TCP, UDP if supported by the chosen outbound, DNS, TUN, IPv4/IPv6, reconnect, and reboot. Unsupported or untested cases cannot pass.' },
    [pscustomobject]@{ Id = 'BuildIntegrityAndLicensing'; Status = 'NotRun'; Requirement = 'Review ISO/package/script hashes, pinned revisions, DISM package states/logs and provenance; retain security defaults and a valid license. Do not publish keys or private network configs.' }
)
$automaticFailures = @($checks | Where-Object { $_.Status -eq 'Failed' }).Count
$unavailable = @($checks | Where-Object { $_.Status -eq 'NotRun' }).Count
$scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
$report = [ordered]@{
    SchemaVersion = 1
    CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    CollectorSHA256 = $scriptHash
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    OverallStatus = $(if ($automaticFailures -gt 0) { 'Failed' } else { 'ManualRequired' })
    AcceptanceConfirmed = $false
    AutomaticFailures = $automaticFailures
    UnavailableChecks = $unavailable
    Scope = 'Read-only evidence plus own small temporary user-directory probes. No update scans, registry writes, ACL repairs, elevation, activation changes, or proxy config reads.'
    Checks = @($checks.ToArray())
    ManualAcceptance = $manual
}
$json = $report | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($outputFullPath, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host ('Evidence saved: ' + $outputFullPath)
Write-Host ('OverallStatus: {0}; automatic failures: {1}; unavailable checks: {2}' -f $report.OverallStatus, $automaticFailures, $unavailable)
Write-Host 'Manual acceptance is still required. Exit 0 does not mean the ISO passed.'
if ($automaticFailures -gt 0) { exit 1 }
exit 0
