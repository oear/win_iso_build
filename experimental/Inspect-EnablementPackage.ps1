#Requires -Version 5.1
<#
.SYNOPSIS
Inspects a hash-pinned enablement CAB without installing any package.
.DESCRIPTION
Expands the CAB with the Windows expand.exe tool, parses MUM metadata with DTDs
disabled, and verifies each extracted catalog's Authenticode signature and
Microsoft publisher. A valid catalog signature does not establish that each
extracted payload belongs to that catalog or that LTSC servicing will accept it.
The CAB wrapper itself need not have an Authenticode signature.
.EXAMPLE
.\Inspect-EnablementPackage.ps1 -PackagePath C:\Inputs\Windows11.0-KB5122776-x64.cab
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath,

    [string]$OutputDirectory,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSha256 = 'fcf1101ccc6de263c894768160e0f02695526924a0a7665933c5e9843f64e737'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Utf8File {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText(
        $Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Read-SafeXml {
    param([string]$Path)
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16777216
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    try {
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        return ,$document
    }
    finally {
        $reader.Dispose()
    }
}

function Get-XmlAttributes {
    param([System.Xml.XmlElement]$Element)
    $attributes = [ordered]@{}
    foreach ($attribute in $Element.Attributes) {
        $attributes[$attribute.Name] = $attribute.Value
    }
    return [pscustomobject]$attributes
}

function Get-AssemblyIdentity {
    param([System.Xml.XmlElement]$Element)
    if ($null -eq $Element -or [string]::IsNullOrWhiteSpace($Element.GetAttribute('name'))) {
        throw 'A MUM assemblyIdentity is missing or has no name.'
    }
    return [pscustomobject][ordered]@{
        name = $Element.GetAttribute('name')
        version = $Element.GetAttribute('version')
        processor_architecture = $Element.GetAttribute('processorArchitecture')
        language = $Element.GetAttribute('language')
        public_key_token = $Element.GetAttribute('publicKeyToken')
        build_type = $Element.GetAttribute('buildType')
        version_scope = $Element.GetAttribute('versionScope')
    }
}

function Get-CertificateSummary {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if ($null -eq $Certificate) { return $null }
    return [pscustomobject][ordered]@{
        subject = $Certificate.Subject
        issuer = $Certificate.Issuer
        thumbprint = $Certificate.Thumbprint
        not_before_utc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        not_after_utc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Invoke-ExpandChecked {
    param([string]$ToolPath, [string[]]$Arguments, [string]$LogPath)
    # Native stderr in Windows PowerShell is an ErrorRecord. Capture it while
    # checking the native exit code, so a diagnostic line cannot hide the code.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& $ToolPath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    Write-Utf8File -Path $LogPath -Content (($lines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
    if ($exitCode -ne 0) {
        throw "expand.exe failed with exit code $exitCode. See $LogPath."
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Inspection requires Windows and its built-in expand.exe; no package was installed.'
}

$source = Get-Item -LiteralPath $PackagePath
if ($source.PSIsContainer -or $source.Extension -ine '.cab') {
    throw 'PackagePath must refer to a CAB file.'
}
if ($source.Length -gt 67108864) {
    throw 'This metadata inspector accepts small CAB files up to 64 MiB.'
}

$expectedHash = $ExpectedSha256.ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -cne $expectedHash) {
    throw "SHA-256 mismatch: expected $expectedHash; received $actualHash. Nothing was expanded."
}

$expandPath = Join-Path $env:WINDIR 'System32\expand.exe'
if (Test-Path -LiteralPath (Join-Path $env:WINDIR 'Sysnative\expand.exe') -PathType Leaf) {
    $expandPath = Join-Path $env:WINDIR 'Sysnative\expand.exe'
}
if (-not (Test-Path -LiteralPath $expandPath -PathType Leaf)) {
    throw 'The built-in Windows expand.exe could not be found.'
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $uniqueName = 'enablement-inspection-{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), ([Guid]::NewGuid().ToString('N'))
    $OutputDirectory = Join-Path (Get-Location).ProviderPath $uniqueName
}
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) {
    throw "OutputDirectory already exists; refusing to overwrite it: $outputPath"
}
# Do not use -Force: even an empty existing directory must not be reused.
$null = New-Item -ItemType Directory -Path $outputPath
$inputPath = Join-Path $outputPath 'input'
$expandedPath = Join-Path $outputPath 'expanded'
$null = New-Item -ItemType Directory -Path $inputPath
$null = New-Item -ItemType Directory -Path $expandedPath
$reportPath = Join-Path $outputPath 'inspection.json'

try {
    # Expand a separately rehashed snapshot, not a source that can change
    # between the initial hash validation and the external tool invocation.
    $snapshotPath = Join-Path $inputPath 'package.cab'
    Copy-Item -LiteralPath $source.FullName -Destination $snapshotPath
    $snapshotHash = (Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($snapshotHash -cne $expectedHash) {
        throw 'The CAB changed while copying; inspection was stopped before expansion.'
    }
    Invoke-ExpandChecked -ToolPath $expandPath -Arguments @('-F:*', $snapshotPath, $expandedPath) -LogPath (Join-Path $outputPath 'expand.log')

    $updateMumPath = Join-Path $expandedPath 'update.mum'
    if (-not (Test-Path -LiteralPath $updateMumPath -PathType Leaf)) {
        throw 'The CAB does not contain a top-level update.mum.'
    }
    $updateXml = Read-SafeXml -Path $updateMumPath
    $updateIdentity = Get-AssemblyIdentity -Element ($updateXml.SelectSingleNode('/*[local-name()="assembly"]/*[local-name()="assemblyIdentity"]'))
    $updatePackage = $updateXml.SelectSingleNode('/*[local-name()="assembly"]/*[local-name()="package"]')
    if ($null -eq $updatePackage) { throw 'update.mum has no package element.' }

    $parents = @()
    $parentEditionIdentities = @()
    foreach ($parent in $updatePackage.SelectNodes('./*[local-name()="parent"]')) {
        $identities = @()
        foreach ($identityNode in $parent.SelectNodes('./*[local-name()="assemblyIdentity"]')) {
            $identity = Get-AssemblyIdentity -Element $identityNode
            $identities += $identity
            if ($identity.name -match 'Edition$') { $parentEditionIdentities += $identity }
        }
        $parents += [pscustomobject][ordered]@{
            attributes = Get-XmlAttributes -Element $parent
            assembly_identities = @($identities)
        }
    }

    $childMums = @()
    $mumFiles = @(Get-ChildItem -LiteralPath $expandedPath -Recurse -File -Filter '*.mum' | Sort-Object FullName)
    foreach ($mumFile in $mumFiles) {
        if ($mumFile.FullName -ieq $updateMumPath) { continue }
        $childXml = Read-SafeXml -Path $mumFile.FullName
        $childIdentity = Get-AssemblyIdentity -Element ($childXml.SelectSingleNode('/*[local-name()="assembly"]/*[local-name()="assemblyIdentity"]'))
        $referencedIdentities = @()
        foreach ($identityNode in $childXml.SelectNodes('/*[local-name()="assembly"]/*[local-name()="package"]//*[local-name()="assemblyIdentity"]')) {
            $referencedIdentities += Get-AssemblyIdentity -Element $identityNode
        }
        $childMums += [pscustomobject][ordered]@{
            file = $mumFile.FullName.Substring($expandedPath.Length + 1)
            sha256 = (Get-FileHash -LiteralPath $mumFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            assembly_identity = $childIdentity
            referenced_assembly_identities = @($referencedIdentities)
        }
    }

    $catalogFiles = @(Get-ChildItem -LiteralPath $expandedPath -Recurse -File -Filter '*.cat' | Sort-Object FullName)
    if ($catalogFiles.Count -eq 0) { throw 'No catalog (.cat) files were found.' }
    $catalogs = @()
    foreach ($catalogFile in $catalogFiles) {
        $signature = Get-AuthenticodeSignature -LiteralPath $catalogFile.FullName
        $microsoftPublisher = $false
        if ($null -ne $signature.SignerCertificate) {
            # Match the certificate's organization attribute, not an arbitrary
            # occurrence of the word Microsoft in a CN or other attribute.
            $microsoftPublisher = $signature.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)'
        }
        $catalogs += [pscustomobject][ordered]@{
            file = $catalogFile.FullName.Substring($expandedPath.Length + 1)
            sha256 = (Get-FileHash -LiteralPath $catalogFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            signature_status = $signature.Status.ToString()
            signature_status_message = $signature.StatusMessage
            microsoft_publisher = [bool]$microsoftPublisher
            signer_certificate = Get-CertificateSummary -Certificate $signature.SignerCertificate
            timestamp_certificate = Get-CertificateSummary -Certificate $signature.TimeStamperCertificate
        }
    }
    $invalidCatalogs = @($catalogs | Where-Object { $_.signature_status -cne 'Valid' -or -not $_.microsoft_publisher })
    $catalogsPassed = $invalidCatalogs.Count -eq 0

    $report = [pscustomobject][ordered]@{
        schema_version = 1
        inspection_status = $(if ($catalogsPassed) { 'metadata-inspected' } else { 'catalog-verification-failed' })
        inspected_at_utc = [DateTime]::UtcNow.ToString('o')
        package = [pscustomobject][ordered]@{
            source_path = $source.FullName
            size_bytes = $source.Length
            expected_sha256 = $expectedHash
            snapshot_sha256 = $snapshotHash
            sha256_matches = $true
        }
        expand_tool = $expandPath
        update_mum = [pscustomobject][ordered]@{
            assembly_identity = $updateIdentity
            assembly_attributes = Get-XmlAttributes -Element $updateXml.DocumentElement
            package_attributes = Get-XmlAttributes -Element $updatePackage
            parent_groups = @($parents)
            parent_edition_identities = @($parentEditionIdentities)
            parent_declares_enterprise_s = (@($parentEditionIdentities | Where-Object { $_.name -ceq 'Microsoft-Windows-EnterpriseSEdition' }).Count -gt 0)
            sha256 = (Get-FileHash -LiteralPath $updateMumPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        child_mums = @($childMums)
        catalogs = @($catalogs)
        verification_scope = [pscustomobject][ordered]@{
            all_catalog_signatures_valid_and_microsoft = $catalogsPassed
            payload_catalog_membership_verified = $false
            actual_ltsc_applicability_verified = $false
            package_installed = $false
            limitations = @(
                'Valid CAT signatures verify those catalog signatures only; payload membership has not been checked.',
                'Edition parent declarations are metadata; actual LTSC applicability and prerequisites require DISM/CBS on the intended image.',
                'The CAB wrapper is not required to be Authenticode-signed and was not treated as a signed executable.',
                'No package installation, registry edits, ACL changes, activation changes, or downloaded payload execution was performed.'
            )
        }
    }
    Write-Utf8File -Path $reportPath -Content ($report | ConvertTo-Json -Depth 16)
    if (-not $catalogsPassed) {
        throw "One or more catalogs are not Valid Microsoft signatures. See $reportPath."
    }
    Write-Output $reportPath
}
catch {
    $failure = [pscustomobject][ordered]@{
        schema_version = 1
        inspection_status = 'failed'
        failed_at_utc = [DateTime]::UtcNow.ToString('o')
        error = $_.Exception.Message
        package_installed = $false
        evidence_directory = $outputPath
    }
    Write-Utf8File -Path (Join-Path $outputPath 'failure.json') -Content ($failure | ConvertTo-Json -Depth 4)
    throw
}
