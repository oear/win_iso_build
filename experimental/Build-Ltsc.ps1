#requires -Version 5.1
<##
Offline trial only. The default prints the plan; -Apply services a fresh work copy.
Use an x64 Windows 11 24H2+ host and Microsoft ADK oscdimg. Never runs Start.cmd.
##>
[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifest.json'),
    [string]$BaseIso,
    [string]$PackageDirectory,
    [string]$WorkDirectory,
    [string]$OscdimgPath,
    [string]$Python = 'python',
    [switch]$Apply,
    [switch]$AllowPendingFirstBoot,
    [ValidateSet('auto', 'sequential')][string]$CheckpointMode = 'auto',
    [switch]$AcceptUnverifiedMirrorProvenance
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

& $Python (Join-Path $PSScriptRoot 'prepare.py') validate --manifest $ManifestPath
if ($LASTEXITCODE -ne 0) { throw 'Manifest validation failed.' }
$manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $Apply) {
    Write-Output ('Target: {0}, {1}, {2}, {3}; manifest status: {4}' -f
        $manifest.target.build, $manifest.target.edition, $manifest.target.language,
        $manifest.target.architecture, $manifest.status)
    Write-Output 'Plan only. -Apply additionally requires complete dependency review and locked package bytes.'
    return
}
& $Python (Join-Path $PSScriptRoot 'prepare.py') validate --manifest $ManifestPath --require-build-ready
if ($LASTEXITCODE -ne 0) { throw 'Offline trial is blocked by the manifest review gate.' }
if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Use a native x64 Windows host.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Offline DISM mounting requires an elevated host PowerShell session.'
}
$hostBuild = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
if ($hostBuild -lt 26100) { throw 'Use Windows 11 24H2+ DISM for checkpoint MSU servicing.' }
if (-not $manifest.base_iso.official_hash_verified -and -not $AcceptUnverifiedMirrorProvenance) {
    throw 'Mirror SHA256 has not been independently verified against Microsoft. Review provenance before using -AcceptUnverifiedMirrorProvenance.'
}
foreach ($value in @($BaseIso, $PackageDirectory, $WorkDirectory, $OscdimgPath)) {
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'BaseIso, PackageDirectory, WorkDirectory and OscdimgPath are required.' }
}
$BaseIso = (Resolve-Path -LiteralPath $BaseIso).ProviderPath
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).ProviderPath
$OscdimgPath = (Resolve-Path -LiteralPath $OscdimgPath).ProviderPath
$WorkDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDirectory)
if (Test-Path -LiteralPath $WorkDirectory) { throw 'WorkDirectory must be a new directory; existing work is never overwritten.' }
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($WorkDirectory))
if ($drive.DriveFormat -ne 'NTFS' -or $drive.AvailableFreeSpace -lt 40GB) {
    throw 'The new working directory needs a local NTFS volume with at least 40 GiB free after acquiring inputs.'
}
if ((Get-FileHash -LiteralPath $BaseIso -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.base_iso.sha256 -or
    (Get-Item -LiteralPath $BaseIso).Length -ne $manifest.base_iso.size) { throw 'Base ISO integrity mismatch.' }
$toolSignature = Get-AuthenticodeSignature -LiteralPath $OscdimgPath
if ($toolSignature.Status -ne 'Valid' -or $toolSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
    throw 'oscdimg must have a valid Microsoft Authenticode signature (Microsoft ADK).'
}
$disk = Get-DiskImage -ImagePath $BaseIso
if ($disk.Attached) { throw 'Base ISO is already mounted. Detach it explicitly before this trial.' }
$lockedNames = @($manifest.packages | ForEach-Object { $_.filename })
$localNames = @(Get-ChildItem -LiteralPath $PackageDirectory -File -Recurse | Where-Object { $_.Extension -in '.cab', '.msu' } | ForEach-Object { $_.Name })
if (@(Compare-Object $lockedNames $localNames).Count -ne 0) { throw 'Package directory must contain exactly the locked packages, with no duplicate or unreviewed CAB/MSU.' }
foreach ($package in $manifest.packages) {
    $file = Join-Path $PackageDirectory $package.filename
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw ('Missing package: ' + $package.filename) }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $package.sha256 -or
        (Get-Item -LiteralPath $file).Length -ne $package.size) { throw ('Package integrity mismatch: ' + $package.filename) }
}
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null
$logs = Join-Path $WorkDirectory 'logs'
$media = Join-Path $WorkDirectory 'media'
$mount = Join-Path $WorkDirectory 'mount'
$staging = Join-Path $WorkDirectory 'servicing-inputs'
$scratch = Join-Path $WorkDirectory 'scratch'
foreach ($dir in @($logs, $media, $mount, $staging, $scratch)) { New-Item -ItemType Directory -Path $dir | Out-Null }
Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $logs 'manifest.json')
$report = [ordered]@{
    unofficial = $true; target = $manifest.target; started_utc = [DateTime]::UtcNow.ToString('o')
    host_build = $hostBuild; media_scope = $manifest.media_scope
    status = 'running'; runtime_acceptance = 'pending'; packages = @(); errors = @()
    commands = @(); firstboot_required = $false; free_bytes_at_start = $drive.AvailableFreeSpace
    checkpoint_mode = $CheckpointMode
    base_sha256 = $manifest.base_iso.sha256
    microsoft_iso_provenance_verified = $manifest.base_iso.official_hash_verified
    oscdimg_sha256 = (Get-FileHash -LiteralPath $OscdimgPath -Algorithm SHA256).Hash.ToLowerInvariant()
    builder_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    manifest_sha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
$isoMounted = $false
$wimMounted = $false
$nativeSequence = 0
$dism = Join-Path $env:WINDIR 'System32\dism.exe'
$report.dism_sha256 = (Get-FileHash -LiteralPath $dism -Algorithm SHA256).Hash.ToLowerInvariant()
$report.dism_file_version = (Get-Item -LiteralPath $dism).VersionInfo.FileVersion
$report.powershell_version = $PSVersionTable.PSVersion.ToString()
$report.dism_module_version = (Get-Module -ListAvailable DISM | Select-Object -First 1).Version.ToString()

function Invoke-Dism([string[]]$Arguments) {
    $script:nativeSequence++
    $label = 'dism-{0:000}' -f $script:nativeSequence
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $result = & $script:dism /English @Arguments ("/ScratchDir:$script:scratch") ('/LogPath:' + (Join-Path $script:logs ($label + '.log'))) 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    $result | Out-File -LiteralPath (Join-Path $script:logs ($label + '.txt')) -Encoding UTF8
    $script:report.commands += [ordered]@{ label = $label; arguments = $Arguments; exit_code = $code }
    if ($code -notin 0, 3010) { throw ('DISM failed ({0}); inspect {1}' -f $code, $label) }
    return ($result -join "`n")
}

function Read-ImageVersion([string]$ImagePath) {
    $hive = 'LTSCTrial_' + [Guid]::NewGuid().ToString('N')
    & reg.exe load ('HKLM\' + $hive) (Join-Path $ImagePath 'Windows\System32\config\SOFTWARE') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot load offline SOFTWARE hive for read-only verification.' }
    try {
        $values = Get-ItemProperty -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\' + $hive + '\Microsoft\Windows NT\CurrentVersion')
        return [ordered]@{ edition = [string]$values.EditionID; build = [string]$values.CurrentBuildNumber; ubr = [int]$values.UBR; build_lab = [string]$values.BuildLabEx }
    } finally {
        $values = $null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        & reg.exe unload ('HKLM\' + $hive) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw ('Offline hive still loaded: HKLM\' + $hive) }
    }
}

try {
    $cumulativeGroup = Join-Path $staging 'cumulative'
    $enablementGroup = Join-Path $staging 'enablement'
    $checkpointGroup = Join-Path $staging 'checkpoint'
    foreach ($dir in @($cumulativeGroup, $enablementGroup, $checkpointGroup)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    foreach ($p in $manifest.packages) {
        $group = $cumulativeGroup
        if ($p.role -eq 'enablement') { $group = $enablementGroup }
        if ($p.role -eq 'checkpoint' -and $CheckpointMode -eq 'sequential') { $group = $checkpointGroup }
        $snapshot = Join-Path $group $p.filename
        Copy-Item -LiteralPath (Join-Path $PackageDirectory $p.filename) -Destination $snapshot
        if ((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash.ToLowerInvariant() -ne $p.sha256 -or
            (Get-Item -LiteralPath $snapshot).Length -ne $p.size) { throw ('Staged package changed: ' + $p.id) }
    }
    foreach ($p in $manifest.packages | Where-Object { $_.role -eq 'enablement' }) {
        & (Join-Path $PSScriptRoot 'Inspect-EnablementPackage.ps1') -PackagePath (Join-Path $enablementGroup $p.filename) -ExpectedSha256 $p.sha256 -OutputDirectory (Join-Path $logs ('trust-' + $p.id))
    }
    $isoDisk = Mount-DiskImage -ImagePath $BaseIso -PassThru
    $isoMounted = $true
    $volume = $isoDisk | Get-Volume
    if (-not $volume.DriveLetter) { throw 'Mounted base ISO has no drive letter.' }
    $root = $volume.DriveLetter + ':\'
    Copy-Item -Path (Join-Path $root '*') -Destination $media -Recurse -Force
    Get-ChildItem -LiteralPath $media -Recurse -File -Force | ForEach-Object { $_.IsReadOnly = $false }
    $retainedMedia = @()
    foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse -Force) {
        $relative = $file.FullName.Substring($root.Length)
        $copy = Join-Path $media $relative
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not (Test-Path -LiteralPath $copy -PathType Leaf) -or (Get-Item -LiteralPath $copy).Length -ne $file.Length -or
            (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) { throw ('Base media copy mismatch: ' + $relative) }
        if ($relative -notin 'sources\install.wim', 'sources\install.esd') {
            $retainedMedia += [ordered]@{ path = $relative; size = $file.Length; sha256 = $hash }
        }
    }
    $report.retained_media = $retainedMedia
    $sourceImages = @(Get-ChildItem -LiteralPath (Join-Path $root 'sources') -File | Where-Object { $_.Name -in 'install.wim', 'install.esd' })
    if ($sourceImages.Count -ne 1) { throw 'Base media must contain exactly one install.wim or install.esd.' }
    $source = $sourceImages[0].FullName
    $baseImages = @(Get-WindowsImage -ImagePath $source | ForEach-Object { Get-WindowsImage -ImagePath $source -Index $_.ImageIndex })
    $report.base_image_candidates = @($baseImages | Select-Object ImageIndex, ImageName, EditionId, Architecture, Version, Languages,
        @{ Name = 'VersionRuntimeType'; Expression = { $_.Version.GetType().FullName } })
    $choices = @($baseImages | Where-Object { $_.EditionId -eq 'EnterpriseS' -and [int]$_.Architecture -eq 9 -and
        ([version]([string]$_.Version)).Build -eq 26100 -and (@($_.Languages) -contains 'zh-CN') })
    if ($choices.Count -ne 1) { throw 'Expected exactly one EnterpriseS x64 zh-CN 26100 base index (no edition conversion).' }
    $report.source_index = $choices[0].ImageIndex
    $report.source_image_metadata = $choices[0] | Select-Object ImageIndex, ImageName, EditionId, Architecture, Version, Languages
    # The immutable source remains mounted. Remove only the redundant work copy
    # of the original install image before exporting the single trial index.
    foreach ($name in 'install.wim', 'install.esd') {
        $old = Join-Path $media ('sources\' + $name)
        if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old }
    }
    $wim = Join-Path $WorkDirectory 'install-trial.wim'
    Export-WindowsImage -SourceImagePath $source -SourceIndex $choices[0].ImageIndex -DestinationImagePath $wim -CompressionType Max -CheckIntegrity | Out-Null
    Mount-WindowsImage -ImagePath $wim -Index 1 -Path $mount -CheckIntegrity | Out-Null
    $wimMounted = $true
    $report.base_image = Read-ImageVersion $mount
    if ($report.base_image.edition -ne 'EnterpriseS' -or $report.base_image.build -ne '26100') { throw 'Base hive is not the expected LTSC.' }
    # Give native 24H2+ DISM the latest cumulative MSU. It discovers the locked
    # checkpoint siblings in this isolated folder in their required order.
    $latest = $manifest.packages | Where-Object { $_.role -eq 'cumulative' }
    if ($CheckpointMode -eq 'sequential') {
        foreach ($p in $manifest.packages | Where-Object { $_.role -eq 'checkpoint' }) {
            Write-Host ('Native isolated checkpoint: ' + $p.id)
            Invoke-Dism @("/Image:$mount", '/Add-Package', ('/PackagePath:' + (Join-Path $checkpointGroup $p.filename)), '/NoRestart') | Out-Null
            $inventory = @(Get-WindowsPackage -Path $mount)
            $installed = @($inventory | Where-Object { $_.PackageName -eq $p.package_identity -and [string]$_.PackageState -in 'Installed', 'InstallPending' })
            if (-not $installed.Count) { throw ('Isolated checkpoint did not stage: ' + $p.id) }
            $report.checkpoint_image = Read-ImageVersion $mount
            $report.checkpoint_inventory = @($inventory | Select-Object PackageName, PackageState)
            Dismount-WindowsImage -Path $mount -Save -CheckIntegrity | Out-Null
            $wimMounted = $false
            Mount-WindowsImage -ImagePath $wim -Index 1 -Path $mount -CheckIntegrity | Out-Null
            $wimMounted = $true
        }
    }
    Write-Host ('Native latest cumulative update: ' + $latest.id)
    Invoke-Dism @("/Image:$mount", '/Add-Package', ('/PackagePath:' + (Join-Path $cumulativeGroup $latest.filename)), '/NoRestart') | Out-Null
    foreach ($p in $manifest.packages | Where-Object { $_.role -in 'checkpoint', 'cumulative' }) {
        $inventory = @(Get-WindowsPackage -Path $mount)
        $allowedStates = @('Installed', 'InstallPending')
        if ($p.role -eq 'checkpoint') { $allowedStates += 'Superseded' }
        $installed = @($inventory | Where-Object { $_.PackageName -eq $p.package_identity -and [string]$_.PackageState -in $allowedStates })
        if ($installed.Count -eq 0) { throw ('Native checkpoint/CU staging did not produce the locked identity: ' + $p.id) }
        $report.packages += [ordered]@{ id = $p.id; sha256 = $p.sha256; identities = @($installed.PackageName); states = @($installed | ForEach-Object { [string]$_.PackageState }) }
    }
    foreach ($p in $manifest.packages | Where-Object { $_.role -eq 'enablement' }) {
        $group = $cumulativeGroup
        if ($p.role -eq 'enablement') { $group = $enablementGroup }
        $path = Join-Path $group $p.filename
        if ([IO.Path]::GetExtension($path) -eq '.cab') {
            $info = Invoke-Dism @("/Image:$mount", '/Get-PackageInfo', "/PackagePath:$path")
            if ($info -notmatch '(?m)^\s*Applicable\s*:\s*Yes\s*$') { throw ('CAB not applicable: ' + $p.id) }
            if ($info -notmatch [regex]::Escape($p.package_identity)) { throw ('Unexpected CAB identity: ' + $p.id) }
        }
        # Native CBS/DISM applies its own package verification policy. No IgnoreCheck,
        # expanded child-MUM installation, cleanup, ResetBase, or host servicing.
        Invoke-Dism @("/Image:$mount", '/Add-Package', "/PackagePath:$path", '/NoRestart') | Out-Null
        $inventory = @(Get-WindowsPackage -Path $mount)
        $installed = @($inventory | Where-Object { $_.PackageName -eq $p.package_identity -and [string]$_.PackageState -in 'Installed', 'InstallPending' })
        if ($installed.Count -eq 0) { throw ('DISM did not stage the expected package: ' + $p.id) }
        $report.packages += [ordered]@{ id = $p.id; sha256 = $p.sha256; identities = @($installed.PackageName); states = @($installed | ForEach-Object { [string]$_.PackageState }) }
    }
    $report.actual_image = Read-ImageVersion $mount
    $actual = $report.actual_image.build + '.' + $report.actual_image.ubr
    $report.offline_observed_version = $actual
    $report.kernel_file_version = (Get-Item -LiteralPath (Join-Path $mount 'Windows\System32\ntoskrnl.exe')).VersionInfo.FileVersion
    if ($actual -ne $manifest.target.build -or $report.actual_image.edition -ne 'EnterpriseS') {
        $pending = @($report.packages | Where-Object { 'InstallPending' -in $_.states }).Count -gt 0
        if (-not $AllowPendingFirstBoot -or -not $pending -or $report.actual_image.edition -ne 'EnterpriseS' -or
            $report.actual_image.build -notin '26100', '26340') {
            throw ('Actual offline image is {0}/{1}; target is {2}/EnterpriseS. No accepted ISO emitted.' -f $actual, $report.actual_image.edition, $manifest.target.build)
        }
        $report.firstboot_required = $true
    }
    Invoke-Dism @("/Image:$mount", '/Cleanup-Image', '/ScanHealth') | Out-Null
    $health = Repair-WindowsImage -Path $mount -CheckHealth
    if ([string]$health.ImageHealthState -ne 'Healthy') { throw 'Offline component store is not Healthy.' }
    $report.inventory = @(Get-WindowsPackage -Path $mount | Select-Object PackageName, PackageState)
    $cbsLog = Join-Path $mount 'Windows\Logs\CBS\CBS.log'
    if (Test-Path -LiteralPath $cbsLog) { Copy-Item -LiteralPath $cbsLog -Destination (Join-Path $logs 'offline-CBS.log') }
    Dismount-WindowsImage -Path $mount -Save -CheckIntegrity | Out-Null
    $wimMounted = $false
    foreach ($name in 'install.wim', 'install.esd') {
        $old = Join-Path $media ('sources\' + $name)
        if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old }
    }
    Move-Item -LiteralPath $wim -Destination (Join-Path $media 'sources\install.wim')
    $outputIso = Join-Path $WorkDirectory ('UNOFFICIAL-EXPERIMENTAL-LTSC-' + $manifest.target.build + '-zh-CN-x64.iso')
    if ($report.firstboot_required) {
        $outputIso = Join-Path $WorkDirectory ('UNOFFICIAL-CANDIDATE-requested-' + $manifest.target.build + '-offline-' + $actual + '-zh-CN-x64.iso')
    }
    $pendingIso = Join-Path $WorkDirectory 'unverified-output.pending.iso'
    $bios = Join-Path $media 'boot\etfsboot.com'
    $uefi = Join-Path $media 'efi\microsoft\boot\efisys.bin'
    if (-not (Test-Path -LiteralPath $bios) -or -not (Test-Path -LiteralPath $uefi)) { throw 'Base boot image is missing.' }
    foreach ($file in $retainedMedia) {
        $path = Join-Path $media $file.path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw ('Retained media changed unexpectedly: ' + $file.path) }
    }
    & $OscdimgPath -m -o -u2 -udfver102 -lLTSC_EXPERIMENTAL ('-bootdata:2#p0,e,b' + $bios + '#pEF,e,b' + $uefi) $media $pendingIso 2>&1 |
        Out-File -LiteralPath (Join-Path $logs 'oscdimg.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pendingIso)) { throw 'oscdimg failed.' }
    $report.iso_sha256 = (Get-FileHash -LiteralPath $pendingIso -Algorithm SHA256).Hash.ToLowerInvariant()
    Move-Item -LiteralPath $pendingIso -Destination $outputIso
    $report.status = 'offline-image-verified-runtime-pending'
    if ($report.firstboot_required) { $report.status = 'native-packages-staged-firstboot-pending' }
    $report.iso_filename = [IO.Path]::GetFileName($outputIso)
    Write-Output $outputIso
} catch {
    $nativeFailure = $_
    $report.status = 'failed-no-accepted-iso'
    $report.errors += $nativeFailure.Exception.Message
    if ($wimMounted) {
        try {
            $cbsLog = Join-Path $mount 'Windows\Logs\CBS\CBS.log'
            if (Test-Path -LiteralPath $cbsLog) { Copy-Item -LiteralPath $cbsLog -Destination (Join-Path $logs 'failed-offline-CBS.log') }
            $report.failed_inventory = @(Get-WindowsPackage -Path $mount | Select-Object PackageName, PackageState)
            $report.failed_image = Read-ImageVersion $mount
            $compression = @()
            foreach ($path in @((Join-Path $env:WINDIR 'System32\msdelta.dll'), (Join-Path $env:WINDIR 'System32\UpdateCompression.dll'),
                (Join-Path $mount 'Windows\System32\msdelta.dll'), (Join-Path $mount 'Windows\System32\UpdateCompression.dll'))) {
                if (Test-Path -LiteralPath $path) {
                    $compression += [ordered]@{ path = $path; version = (Get-Item -LiteralPath $path).VersionInfo.FileVersion;
                        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
                }
            }
            $report.compression_libraries_on_failure = $compression
        } catch { $report.errors += ('Failure diagnostic collection incomplete: ' + $_.Exception.Message) }
    }
    throw $nativeFailure
} finally {
    $cleanupFailed = $false
    if ($wimMounted) {
        try { Dismount-WindowsImage -Path $mount -Discard | Out-Null }
        catch { $cleanupFailed = $true; $report.errors += ('Discard mount failed; inspect manually: ' + $_.Exception.Message) }
    }
    if ($isoMounted) {
        try { Dismount-DiskImage -ImagePath $BaseIso | Out-Null }
        catch { $cleanupFailed = $true; $report.errors += ('ISO detach failed: ' + $_.Exception.Message) }
    }
    $report.finished_utc = [DateTime]::UtcNow.ToString('o')
    $report.free_bytes_at_end = $drive.AvailableFreeSpace
    if ($cleanupFailed) { $report.status = 'cleanup-incomplete' }
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $logs 'build-report.json') -Encoding UTF8
    if ($cleanupFailed) { throw 'Mount cleanup incomplete. Inspect build-report.json and the host mounts before continuing.' }
}
