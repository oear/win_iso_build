#Requires -Version 5.1
<#
.SYNOPSIS
Acquires the locked Microsoft x64 oscdimg tool without installing the ADK.
.DESCRIPTION
Downloads one fixed HTTPS CAB, verifies its size and SHA-256, expands only the
locked x64 member, then checks the executable's size, hash, version and valid
Microsoft Authenticode signature. Returns its full path only after verification.
Does not execute oscdimg, install an MSI, or modify registry/certificate stores.
#>
[CmdletBinding()]
param([string]$OutputDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-ToolReport {
    param([string]$Path, $Report)
    [IO.File]::WriteAllText($Path, ($Report | ConvertTo-Json -Depth 10),
        (New-Object System.Text.UTF8Encoding($false)))
}

function Get-CertificateEvidence {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if ($null -eq $Certificate) { return $null }
    return [pscustomobject][ordered]@{
        subject = $Certificate.Subject
        issuer = $Certificate.Issuer
        thumbprint = $Certificate.Thumbprint
        not_before_utc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        not_after_utc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Get-LockedDownload {
    param([string]$Uri, [string]$Destination, [long]$ExpectedSize)
    $savedProtocol = [Net.ServicePointManager]::SecurityProtocol
    $response = $null
    $inputStream = $null
    $outputStream = $null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $request = [Net.HttpWebRequest]::CreateHttp($Uri)
        $request.Method = 'GET'
        $request.AllowAutoRedirect = $false
        $request.Timeout = 60000
        $request.ReadWriteTimeout = 60000
        $request.UseDefaultCredentials = $false
        $request.UserAgent = 'LTSC-Experimental-Tool-Acquisition/1.0'
        $response = $request.GetResponse()
        if ($response.StatusCode -ne [Net.HttpStatusCode]::OK -or $response.ResponseUri.AbsoluteUri -cne $Uri) {
            throw 'The fixed Microsoft URL did not return HTTP 200 without a redirect.'
        }
        if ($response.ContentLength -ge 0 -and $response.ContentLength -ne $ExpectedSize) {
            throw 'Microsoft CAB response length differs from the lock.'
        }
        $inputStream = $response.GetResponseStream()
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        [long]$total = 0
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $ExpectedSize) { throw 'Microsoft CAB download exceeded the locked size.' }
            $outputStream.Write($buffer, 0, $read)
        }
        if ($total -ne $ExpectedSize) { throw 'Microsoft CAB download ended before the locked size.' }
    }
    finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $response) { $response.Close() }
        [Net.ServicePointManager]::SecurityProtocol = $savedProtocol
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Tool acquisition requires Windows for native expansion and Authenticode verification.'
}
$lockPath = Join-Path $PSScriptRoot 'evidence\oscdimg-source-lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json
$fixedUrl = 'https://download.microsoft.com/download/8e0c0f5a-abb5-4358-a51b-168eb40b1590/adk/Installers/bbf55224a0290f00676ddc410f004498.cab'
$fixedCabHash = '4f6351fe31ff58aa5ef81e407ef74071b149f0b42e200b4c036398c1068d687b'
$fixedMember = 'fild40c79d789d460e48dc1cbd485d6fc2e'
$fixedExeHash = 'd2709f8099ddd202bc41bcb399ecd5638503c6466f416d1a321769af83a70c3a'
if ($lock.schema_version -ne 1 -or $lock.tool -cne 'oscdimg' -or $lock.architecture -cne 'x64' -or
    $lock.adk_version -cne '10.1.26100.9457' -or $lock.file_version -cne '2.56' -or
    $lock.cab.url -cne $fixedUrl -or $lock.cab.size -ne 77696 -or $lock.cab.sha256 -cne $fixedCabHash -or
    $lock.executable.cab_member -cne $fixedMember -or $lock.executable.output_filename -cne 'oscdimg.exe' -or
    $lock.executable.size -ne 154024 -or $lock.executable.sha256 -cne $fixedExeHash) {
    throw 'The source lock does not match the reviewed Microsoft x64 tool acquisition route.'
}
$expandPath = Join-Path $env:WINDIR 'System32\expand.exe'
if (Test-Path -LiteralPath (Join-Path $env:WINDIR 'Sysnative\expand.exe') -PathType Leaf) {
    $expandPath = Join-Path $env:WINDIR 'Sysnative\expand.exe'
}
if (-not (Test-Path -LiteralPath $expandPath -PathType Leaf)) { throw 'Windows expand.exe is missing.' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $uniqueName = 'oscdimg-{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), ([Guid]::NewGuid().ToString('N'))
    $OutputDirectory = Join-Path (Get-Location).ProviderPath $uniqueName
}
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) { throw "OutputDirectory already exists: $outputPath" }
$null = New-Item -ItemType Directory -Path $outputPath
$expandedPath = Join-Path $outputPath 'extracted'
$null = New-Item -ItemType Directory -Path $expandedPath
$reportPath = Join-Path $outputPath 'tool-report.json'
$report = [ordered]@{
    schema_version = 1
    status = 'running'
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    tool = $lock.tool
    architecture = $lock.architecture
    adk_version = $lock.adk_version
    source_reference = $lock.official_reference
    source_lock_sha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    downloaded_url = $fixedUrl
    executable_executed = $false
    installer_executed = $false
}

try {
    Copy-Item -LiteralPath $lockPath -Destination (Join-Path $outputPath 'source-lock.json')
    $cabPath = Join-Path $outputPath 'oscdimg-source.cab'
    Get-LockedDownload -Uri $fixedUrl -Destination $cabPath -ExpectedSize $lock.cab.size
    $cabInfo = Get-Item -LiteralPath $cabPath
    $cabHash = (Get-FileHash -LiteralPath $cabPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($cabInfo.Length -ne $lock.cab.size -or $cabHash -cne $fixedCabHash) { throw 'Downloaded CAB integrity mismatch.' }
    $report.cab = [ordered]@{ size = $cabInfo.Length; sha256 = $cabHash; verified = $true }

    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $expandOutput = @(& $expandPath ("-F:$fixedMember") $cabPath $expandedPath 2>&1)
        $expandCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $savedPreference }
    [IO.File]::WriteAllText((Join-Path $outputPath 'expand.log'),
        (($expandOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false)))
    $report.expand = [ordered]@{ tool = $expandPath; member = $fixedMember; exit_code = $expandCode }
    if ($expandCode -ne 0) { throw "expand.exe failed with exit code $expandCode." }
    $extractedFiles = @(Get-ChildItem -LiteralPath $expandedPath -Recurse -File -Force)
    $memberPath = Join-Path $expandedPath $fixedMember
    if ($extractedFiles.Count -ne 1 -or -not (Test-Path -LiteralPath $memberPath -PathType Leaf)) {
        throw 'Expansion did not produce exactly the locked x64 member.'
    }
    $exePath = Join-Path $outputPath 'oscdimg.exe'
    Move-Item -LiteralPath $memberPath -Destination $exePath
    $exeInfo = Get-Item -LiteralPath $exePath
    $exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($exeInfo.Length -ne $lock.executable.size -or $exeHash -cne $fixedExeHash) {
        throw 'Extracted x64 executable integrity mismatch.'
    }
    if ($exeInfo.VersionInfo.FileVersion -cne $lock.file_version -or $exeInfo.VersionInfo.ProductVersion -cne $lock.file_version) {
        throw 'Extracted executable version differs from the lock.'
    }
    $report.executable = [ordered]@{
        full_name = $exeInfo.FullName
        size = $exeInfo.Length
        sha256 = $exeHash
        file_version = $exeInfo.VersionInfo.FileVersion
        product_version = $exeInfo.VersionInfo.ProductVersion
        verified = $true
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $exePath
    $microsoftPublisher = $false
    if ($null -ne $signature.SignerCertificate) {
        $microsoftPublisher = $signature.SignerCertificate.Subject -match '(^|,\s*)O=Microsoft Corporation(,|$)'
    }
    $report.authenticode = [ordered]@{
        status = $signature.Status.ToString()
        status_message = $signature.StatusMessage
        microsoft_publisher = [bool]$microsoftPublisher
        signer_certificate = Get-CertificateEvidence -Certificate $signature.SignerCertificate
        timestamp_certificate = Get-CertificateEvidence -Certificate $signature.TimeStamperCertificate
    }
    if ($signature.Status -ne 'Valid' -or -not $microsoftPublisher) {
        throw 'The x64 executable must have a Valid Microsoft Authenticode signature before use.'
    }
    $report.status = 'verified-tool-ready'
    $report.finished_at_utc = [DateTime]::UtcNow.ToString('o')
    Write-ToolReport -Path $reportPath -Report $report
    Write-Output $exeInfo.FullName
}
catch {
    $report.status = 'failed-no-trusted-tool'
    $report.error = $_.Exception.Message
    $report.finished_at_utc = [DateTime]::UtcNow.ToString('o')
    Write-ToolReport -Path $reportPath -Report $report
    throw
}
