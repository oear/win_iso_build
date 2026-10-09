#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BaseIso,
    [Parameter(Mandatory = $true)][string]$FoundationEsd,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$SevenZipPath = 'C:\Program Files\7-Zip\7z.exe',
    [string]$SignToolPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Save-Report {
    [IO.File]::WriteAllText((Join-Path $script:out 'probe-report.json'),
        ($script:report | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
}
function Run-ReadTool([string]$Tool, [string[]]$Arguments, [string]$Label) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $lines = @(& $Tool @Arguments 2>&1); $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $saved }
    $text = ($lines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $script:out ($Label + '.txt')), $text,
        (New-Object Text.UTF8Encoding($false)))
    $script:report.commands += [ordered]@{ label = $Label; tool = $Tool; arguments = $Arguments; exit_code = $code }
    return [pscustomobject]@{ text = $text; exit_code = $code }
}
function Query-Image([string]$Label) {
    $edition = Run-ReadTool $script:dism @('/English', "/Image:$script:mount", '/Get-CurrentEdition', "/ScratchDir:$script:scratch", "/LogPath:$script:out\$Label-edition.log") ($Label + '-edition')
    $packages = Run-ReadTool $script:dism @('/English', "/Image:$script:mount", '/Get-Packages', '/Format:Table', "/ScratchDir:$script:scratch", "/LogPath:$script:out\$Label-packages.log") ($Label + '-packages')
    if ($edition.exit_code -ne 0 -or $packages.exit_code -ne 0) { throw 'Read-only image inventory query failed.' }
    $match = [regex]::Match($edition.text, '(?m)^\s*Current Edition\s*:\s*(\S+)\s*$')
    $rows = @($packages.text -split '\r?\n' | Where-Object { $_ -match '^\s*[^|]*~[^|]*\|' } |
        ForEach-Object { (($_ -split '\|' | ForEach-Object { $_.Trim() }) -join '|') } | Sort-Object)
    if (-not $match.Success -or $rows.Count -eq 0) { throw 'Cannot establish the original image edition/package inventory.' }
    return [pscustomobject]@{ edition = $match.Groups[1].Value; package_rows = $rows }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {
    throw 'Use native 64-bit Windows PowerShell on Windows.'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Read-only WIM mounting requires an elevated session.' }
$BaseIso = (Resolve-Path -LiteralPath $BaseIso).ProviderPath
$FoundationEsd = (Resolve-Path -LiteralPath $FoundationEsd).ProviderPath
$SevenZipPath = (Resolve-Path -LiteralPath $SevenZipPath).ProviderPath
if ((Get-Item -LiteralPath $BaseIso).Length -ne 5287520256 -or
    (Get-FileHash -LiteralPath $BaseIso -Algorithm SHA256).Hash -ine '2cb21649590c8cf770cd93556596dff4fd800f24d267a9be9d9ce0ee9e03f5ac') { throw 'Original LTSC base ISO lock mismatch.' }
if ((Get-Item -LiteralPath $FoundationEsd).Length -ne 25588 -or
    (Get-FileHash -LiteralPath $FoundationEsd -Algorithm SHA256).Hash -ine '03f8de2ae1bf94efcad630281219870ef2a21eee986e4123e81e3d5dc2e00321') { throw 'Foundation .6 ESD lock mismatch.' }
if ((Get-DiskImage -ImagePath $BaseIso).Attached) { throw 'Base ISO is already mounted; probe will not borrow or detach it.' }
$out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new.' }
$null = New-Item -ItemType Directory -Path $out
$mount = Join-Path $out 'readonly-mount'
$expanded = Join-Path $out 'expanded'
$scratch = Join-Path $out 'scratch'
foreach ($dir in @($mount, $expanded, $scratch)) { $null = New-Item -ItemType Directory -Path $dir }
$dism = Join-Path $env:WINDIR 'System32\dism.exe'
$report = [ordered]@{
    status = 'running'; started_utc = [DateTime]::UtcNow.ToString('o')
    target_migration_eligibility = $false; foundation_installed = $false
    full_dependency_closure_verified = $false; full_catalog_membership_verified = $false
    manifest_catalog_membership_verified = $false; mum_catalog_membership_verified = $false
    source_kind = 'canonical CBS-style folder extracted from locked UUP ESD; no ESD installation'
    foundation_sha256 = '03f8de2ae1bf94efcad630281219870ef2a21eee986e4123e81e3d5dc2e00321'
    seven_zip_sha256 = (Get-FileHash -LiteralPath $SevenZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    commands = @(); catalogs = @(); identities = @(); errors = @()
    limitations = @('Foundation/Common metadata does not prove Required/Features/language or EnterpriseS dependency compatibility.',
        'DCM/PA30 component manifests remain compressed; this probe verifies MUM members only.',
        'Applicable Yes is a package query result, not permission or proof of a successful rebase.')
}
$isoMounted = $false
$wimMounted = $false

try {
    $foundationSnapshot = Join-Path $out 'Foundation-26100.6.esd'
    Copy-Item -LiteralPath $FoundationEsd -Destination $foundationSnapshot
    if ((Get-Item -LiteralPath $foundationSnapshot).Length -ne 25588 -or
        (Get-FileHash -LiteralPath $foundationSnapshot -Algorithm SHA256).Hash -ine $report.foundation_sha256) { throw 'Foundation snapshot integrity changed.' }
    $foundationMum = 'Microsoft-Windows-Foundation-Package~31bf3856ad364e35~amd64~~10.0.26100.6.mum'
    $commonMum = 'Microsoft-Windows-Common-Foundation-Package~31bf3856ad364e35~amd64~~10.0.26100.6.mum'
    $names = @('update.mum', 'update.cat', $foundationMum, $commonMum,
        ($foundationMum -replace '\.mum$', '.cat'), ($commonMum -replace '\.mum$', '.cat'),
        'amd64_microsoft-windows-foundation_31bf3856ad364e35_10.0.26100.6_none_dd5a619eda592fb9.manifest',
        'amd64_microsoft-windows-m..foundation-security_31bf3856ad364e35_10.0.26100.6_none_a1f80a97dbdeac93.manifest',
        'amd64_microsoft-windows-p..ucturenonexecutable_31bf3856ad364e35_10.0.26100.6_none_62007e3b3278b862.manifest', '$filehashes$.dat')
    # e flattens the ESD's sole image; explicit names exclude synthetic WIM XML.
    $extraction = Run-ReadTool $SevenZipPath (@('e', $foundationSnapshot, "-o$expanded", '-y', '-r') + $names) 'extract-foundation'
    if ($extraction.exit_code -ne 0) { throw '7-Zip ESD extraction failed.' }
    $files = @(Get-ChildItem -LiteralPath $expanded -File -Force)
    if ($files.Count -ne 10 -or @(Compare-Object $names @($files.Name)).Count -ne 0 -or
        @(Get-ChildItem -LiteralPath $expanded -Directory -Force).Count -ne 0) { throw 'Foundation extraction is not the expected flat ten-file layout.' }
    $report.expanded_files = @($files | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; size = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    foreach ($file in $files | Where-Object { $_.Extension -eq '.mum' }) {
        $settings = New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
        $reader = [Xml.XmlReader]::Create($file.FullName, $settings)
        try { $xml = New-Object Xml.XmlDocument; $xml.XmlResolver = $null; $xml.Load($reader) }
        finally { $reader.Dispose() }
        $identity = $xml.SelectSingleNode('/*[local-name()="assembly"]/*[local-name()="assemblyIdentity"]')
        if ($null -eq $identity -or $identity.GetAttribute('version') -cne '10.0.26100.6' -or
            $identity.GetAttribute('processorArchitecture') -cne 'amd64') { throw 'Unexpected Foundation MUM identity.' }
        $report.identities += [ordered]@{ file = $file.Name; name = $identity.GetAttribute('name'); version = $identity.GetAttribute('version') }
    }
    foreach ($file in $files | Where-Object { $_.Extension -eq '.cat' }) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        $publisher = $null -ne $signature.SignerCertificate -and $signature.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)'
        $report.catalogs += [ordered]@{ file = $file.Name; status = $signature.Status.ToString(); microsoft_publisher = $publisher;
            signer = $(if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }) }
        if ($signature.Status -ne 'Valid' -or -not $publisher) { throw ('Foundation catalog trust failed: ' + $file.Name) }
    }
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
        $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        if (Test-Path -LiteralPath $sdk) {
            $candidates = @(Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
            if ($candidates.Count -gt 0) { $SignToolPath = $candidates[0] }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
        $SignToolPath = (Resolve-Path -LiteralPath $SignToolPath).ProviderPath
        $sig = Get-AuthenticodeSignature -LiteralPath $SignToolPath
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') { throw 'SDK SignTool trust failed.' }
        $report.signtool = [ordered]@{ path = $SignToolPath; version = (Get-Item -LiteralPath $SignToolPath).VersionInfo.FileVersion;
            sha256 = (Get-FileHash -LiteralPath $SignToolPath -Algorithm SHA256).Hash.ToLowerInvariant() }
        foreach ($name in @('update.mum', $foundationMum, $commonMum)) {
            $catalog = $name -replace '\.mum$', '.cat'
            $verified = Run-ReadTool $SignToolPath @('verify', '/pa', '/v', '/hash', 'SHA256', '/c', (Join-Path $expanded $catalog), (Join-Path $expanded $name)) ('member-' + $name)
            if ($verified.exit_code -ne 0) { throw ('MUM catalog member verification failed: ' + $name) }
        }
        $report.mum_catalog_membership_verified = $true
    } else { $report.signtool = 'not available; MUM member validation not completed' }
    $disk = Mount-DiskImage -ImagePath $BaseIso -PassThru
    $isoMounted = $true
    $volumes = @($disk | Get-Volume | Where-Object { $_.DriveLetter })
    if ($volumes.Count -ne 1) { throw 'Expected exactly one base ISO volume.' }
    $source = Join-Path ($volumes[0].DriveLetter + ':\') 'sources\install.wim'
    $choices = @(Get-WindowsImage -ImagePath $source | ForEach-Object { Get-WindowsImage -ImagePath $source -Index $_.ImageIndex } |
        Where-Object { $_.EditionId -eq 'EnterpriseS' -and [int]$_.Architecture -eq 9 -and
            ([version]([string]$_.Version)).Build -eq 26100 -and (@($_.Languages) -contains 'zh-CN') })
    if ($choices.Count -ne 1) { throw 'Original ISO does not have one matching EnterpriseS index.' }
    $report.source_image = $choices[0] | Select-Object ImageIndex, EditionId, Architecture, Version, Languages
    Mount-WindowsImage -ImagePath $source -Index $choices[0].ImageIndex -Path $mount -ReadOnly -CheckIntegrity | Out-Null
    $wimMounted = $true
    $before = Query-Image 'before'
    if ($before.edition -cne 'EnterpriseS') { throw 'Read-only mounted image is not EnterpriseS.' }
    $report.before = $before
    $query = Run-ReadTool $dism @('/English', "/Image:$mount", '/Get-PackageInfo', "/PackagePath:$expanded", "/ScratchDir:$scratch", "/LogPath:$out\foundation-packageinfo.log") 'foundation-packageinfo'
    $id = [regex]::Match($query.text, '(?m)^\s*Package Identity\s*:\s*(\S+)\s*$')
    $applicable = [regex]::Match($query.text, '(?m)^\s*Applicable\s*:\s*(\S+)\s*$')
    $report.package_query = [ordered]@{ exit_code = $query.exit_code;
        identity = $(if ($id.Success) { $id.Groups[1].Value } else { $null });
        applicable = $(if ($applicable.Success) { $applicable.Groups[1].Value } else { $null }) }
    if ($query.exit_code -eq 0 -and (-not $id.Success -or
        $id.Groups[1].Value -cne 'Microsoft-Windows-Foundation-Package~31bf3856ad364e35~amd64~~10.0.26100.6')) {
        throw 'The folder query did not return the locked Foundation package identity.'
    }
    $after = Query-Image 'after'
    $report.after = $after
    $unchanged = $before.edition -ceq $after.edition -and @(Compare-Object $before.package_rows $after.package_rows).Count -eq 0
    $report.image_inventory_unchanged = $unchanged
    if (-not $unchanged) { throw 'Edition or package inventory changed during the read-only probe.' }
    $report.status = $(if ($query.exit_code -eq 0) { 'readonly-query-complete-migration-unverified' } else { 'readonly-query-rejected-migration-unverified' })
} catch {
    $report.status = 'probe-failed-migration-unverified'
    $report.errors += $_.Exception.Message
    throw
} finally {
    $cleanupFailed = $false
    if (-not $wimMounted) {
        try { $wimMounted = @(Get-WindowsImage -Mounted | Where-Object { $_.Path -ieq $mount }).Count -gt 0 }
        catch { $report.errors += ('Own partial mount detection failed: ' + $_.Exception.Message) }
    }
    if ($wimMounted) {
        try { Dismount-WindowsImage -Path $mount -Discard | Out-Null }
        catch { $cleanupFailed = $true; $report.errors += ('Own WIM unmount failed: ' + $_.Exception.Message) }
    }
    if ($isoMounted) {
        try { Dismount-DiskImage -ImagePath $BaseIso | Out-Null }
        catch { $cleanupFailed = $true; $report.errors += ('Own ISO detach failed: ' + $_.Exception.Message) }
    }
    if ($cleanupFailed) { $report.status = 'cleanup-incomplete-migration-unverified' }
    $report.finished_utc = [DateTime]::UtcNow.ToString('o')
    Save-Report
    if ($cleanupFailed) { throw 'Probe could not clean up its own mounts.' }
}
Write-Output (Join-Path $out 'probe-report.json')
