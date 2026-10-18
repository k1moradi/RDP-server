# SPDX-License-Identifier: GPL-3.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Verify', 'Start', 'Status', 'Stop', 'Uninstall')]
    [string]$Action,

    [string]$ArchivePath = '',

    [string]$InstallRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BlockedExitCode = 3
$script:MaximumMemberBytes = 268435456
$script:LifecycleRelativePath = 'platform/windows/rdp-server-test.ps1'
$script:ExecutableRelativePath = 'bin/rdp-server.exe'

function Get-LocalAppDataRoot {
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return [System.IO.Path]::GetFullPath($env:LOCALAPPDATA)
    }
    return [System.IO.Path]::GetFullPath(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
}

function Test-PathBelow {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullParent = [System.IO.Path]::GetFullPath($Parent).TrimEnd([char[]]@('\', '/'))
    $prefix = $fullParent + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'reparse points are not accepted'
    }
}

function Resolve-InstallRoot {
    $localAppData = Get-LocalAppDataRoot
    $candidate = $InstallRoot
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = Join-Path $localAppData 'RDP-server\server-test'
    }
    $fullCandidate = [System.IO.Path]::GetFullPath($candidate)
    if (-not (Test-PathBelow -Path $fullCandidate -Parent $localAppData)) {
        throw 'install root must remain below LocalApplicationData'
    }

    $cursor = $fullCandidate
    while (Test-PathBelow -Path $cursor -Parent $localAppData) {
        Assert-NoReparsePoint -Path $cursor
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }
        $cursor = $parent.FullName
    }
    Assert-NoReparsePoint -Path $localAppData
    return $fullCandidate
}

function Assert-SafeRelativePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.StartsWith('/') -or
        $RelativePath.EndsWith('/') -or
        $RelativePath.Contains('\') -or
        $RelativePath.Contains(':')) {
        throw 'unsafe archive member path'
    }
    foreach ($part in $RelativePath.Split('/')) {
        if ([string]::IsNullOrEmpty($part) -or $part -eq '.' -or $part -eq '..') {
            throw 'unsafe archive member path'
        }
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Read-ZipEntryBytes {
    param([Parameter(Mandatory = $true)]$Entry)

    if ($Entry.Length -gt $script:MaximumMemberBytes) {
        throw 'archive member exceeds the bounded size limit'
    }
    $source = $Entry.Open()
    $buffer = New-Object System.IO.MemoryStream
    try {
        $source.CopyTo($buffer)
        return $buffer.ToArray()
    }
    finally {
        $source.Dispose()
        $buffer.Dispose()
    }
}

function Assert-NoSensitiveMarkers {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
    # Compose sentinels at runtime so this verifier can itself be packaged
    # without containing the forbidden credential markers it rejects.
    $privateKeyPrefix = '-----BEGIN '
    foreach ($marker in @(
        ($privateKeyPrefix + 'PRIVATE KEY-----'),
        ($privateKeyPrefix + 'ENCRYPTED PRIVATE KEY-----'),
        ($privateKeyPrefix + 'RSA PRIVATE KEY-----'),
        ('github_' + 'pat_'))) {
        if ($text.Contains($marker)) {
            throw 'credential-bearing payload rejected'
        }
    }
    if ($text -match 'AKIA[0-9A-Z]{16}' -or $text -match 'gh[pousr]_[A-Za-z0-9]{20,}') {
        throw 'credential-bearing payload rejected'
    }
}

function Parse-ChecksumText {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $result = @{}
    $text = [System.Text.Encoding]::UTF8.GetString($Bytes).Replace("`r`n", "`n")
    foreach ($line in $text.Split("`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') {
            throw 'invalid internal checksum manifest'
        }
        $relativePath = $Matches[2]
        Assert-SafeRelativePath -RelativePath $relativePath
        if ($result.ContainsKey($relativePath)) {
            throw 'duplicate internal checksum entry'
        }
        $result[$relativePath] = $Matches[1]
    }
    if ($result.Count -eq 0) {
        throw 'empty internal checksum manifest'
    }
    return $result
}

function Assert-OuterChecksum {
    param([Parameter(Mandatory = $true)][string]$ResolvedArchivePath)

    $checksumPath = $ResolvedArchivePath + '.sha256'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'adjacent archive checksum is missing'
    }
    Assert-NoReparsePoint -Path $checksumPath
    $line = (Get-Content -LiteralPath $checksumPath -Raw -Encoding UTF8).TrimEnd([char[]]@("`r", "`n"))
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') {
        throw 'adjacent archive checksum is malformed'
    }
    if ($Matches[2] -ne [System.IO.Path]::GetFileName($ResolvedArchivePath)) {
        throw 'adjacent archive checksum names a different file'
    }
    $actual = (Get-FileHash -LiteralPath $ResolvedArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Matches[1]) {
        throw 'archive SHA-256 mismatch'
    }
}

function Read-VerifiedArchive {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'archive path is required'
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw 'archive is missing'
    }
    Assert-NoReparsePoint -Path $resolved
    Assert-OuterChecksum -ResolvedArchivePath $resolved

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($resolved)
    try {
        $entries = @{}
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            Assert-SafeRelativePath -RelativePath $name
            if ([string]::IsNullOrEmpty($entry.Name)) {
                throw 'directory entries are not accepted'
            }
            $key = $name.ToLowerInvariant()
            if ($entries.ContainsKey($key)) {
                throw 'duplicate archive member'
            }
            $entries[$key] = $entry
        }

        $manifestEntries = @($archive.Entries | Where-Object {
            $_.FullName.EndsWith('/metadata/SERVER-TEST-MANIFEST.json', [StringComparison]::Ordinal)
        })
        if ($manifestEntries.Count -ne 1) {
            throw 'SERVER-TEST manifest missing or duplicated'
        }
        $manifestEntry = $manifestEntries[0]
        $artifactName = $manifestEntry.FullName.Split('/')[0]
        if ([System.IO.Path]::GetFileName($resolved) -ne ($artifactName + '.zip')) {
            throw 'archive filename does not match manifest root'
        }

        $manifestBytes = Read-ZipEntryBytes -Entry $manifestEntry
        Assert-NoSensitiveMarkers -Bytes $manifestBytes
        $manifest = [System.Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
        if ($manifest.artifact_family -ne 'SERVER-TEST' -or
            $manifest.artifact_name -ne $artifactName -or
            $manifest.classification -ne 'startup-disabled-preview' -or
            $manifest.production_ready -ne $false -or
            $manifest.startup_enabled -ne $false -or
            $manifest.platform -ne 'windows' -or
            $manifest.architecture -ne 'x86_64' -or
            $manifest.executable -ne $script:ExecutableRelativePath -or
            $manifest.exact_git_sha -notmatch '^[0-9a-f]{40}$') {
            throw 'unsupported Windows SERVER-TEST manifest identity'
        }
        if ($manifest.install.owner -ne 'R6' -or
            $manifest.install.service_registration -ne $false -or
            $manifest.install.autostart -ne $false -or
            $manifest.install.firewall_rules -ne $false -or
            $manifest.install.lifecycle_script -ne $script:LifecycleRelativePath) {
            throw 'unsafe Windows install contract'
        }

        $checksumName = ($artifactName + '/metadata/SHA256SUMS.txt').ToLowerInvariant()
        if (-not $entries.ContainsKey($checksumName)) {
            throw 'internal SHA256SUMS is missing'
        }
        $checksums = Parse-ChecksumText -Bytes (Read-ZipEntryBytes -Entry $entries[$checksumName])

        $payloadProperties = @($manifest.files.PSObject.Properties)
        if ($checksums.Count -ne ($payloadProperties.Count + 1)) {
            throw 'internal checksum path set mismatch'
        }
        $expectedArchiveEntries = @{}
        foreach ($property in $payloadProperties) {
            $relative = $property.Name
            Assert-SafeRelativePath -RelativePath $relative
            $entryName = ($artifactName + '/' + $relative).ToLowerInvariant()
            if (-not $entries.ContainsKey($entryName)) {
                throw 'manifested payload member is missing'
            }
            $bytes = Read-ZipEntryBytes -Entry $entries[$entryName]
            Assert-NoSensitiveMarkers -Bytes $bytes
            $digest = Get-Sha256Hex -Bytes $bytes
            if ([int64]$property.Value.bytes -ne $bytes.LongLength -or
                [string]$property.Value.sha256 -ne $digest -or
                -not $checksums.ContainsKey($relative) -or
                $checksums[$relative] -ne $digest) {
                throw 'manifested payload digest mismatch'
            }
            $expectedArchiveEntries[$entryName] = $true
        }

        $manifestRelative = 'metadata/SERVER-TEST-MANIFEST.json'
        if (-not $checksums.ContainsKey($manifestRelative) -or
            $checksums[$manifestRelative] -ne (Get-Sha256Hex -Bytes $manifestBytes)) {
            throw 'manifest checksum mismatch'
        }
        $expectedArchiveEntries[($artifactName + '/' + $manifestRelative).ToLowerInvariant()] = $true
        $expectedArchiveEntries[$checksumName] = $true
        if ($expectedArchiveEntries.Count -ne $entries.Count) {
            throw 'archive contains unmanifested content'
        }
        foreach ($key in $entries.Keys) {
            if (-not $expectedArchiveEntries.ContainsKey($key)) {
                throw 'archive contains unmanifested content'
            }
        }

        if (-not $manifest.files.PSObject.Properties[$script:LifecycleRelativePath]) {
            throw 'Windows lifecycle script is missing from bundle payload'
        }
        $runtimeNames = @($manifest.runtime_dependencies)
        $runtimeSeen = @{}
        foreach ($runtimeNameObject in $runtimeNames) {
            $runtimeName = [string]$runtimeNameObject
            if ($runtimeName -notmatch '^[A-Za-z0-9_.+\-]+\.dll$') {
                throw 'invalid Windows runtime dependency name'
            }
            $runtimeKey = $runtimeName.ToLowerInvariant()
            if ($runtimeSeen.ContainsKey($runtimeKey)) {
                throw 'duplicate Windows runtime dependency name'
            }
            $runtimeSeen[$runtimeKey] = $true
            $relative = 'bin/' + $runtimeName
            if (-not $manifest.files.PSObject.Properties[$relative]) {
                throw 'required Windows runtime DLL is not bundled'
            }
        }

        return [PSCustomObject]@{
            ArchivePath = $resolved
            ArtifactName = $artifactName
            Manifest = $manifest
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Read-InstalledManifest {
    param([Parameter(Mandatory = $true)][string]$Root)

    $manifestPath = Join-Path $Root 'metadata\SERVER-TEST-MANIFEST.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'installed manifest is missing'
    }
    Assert-NoReparsePoint -Path $manifestPath
    return (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Assert-InstalledTree {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        $ExpectedManifest = $null
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw 'Windows SERVER-TEST is not installed'
    }
    Assert-NoReparsePoint -Path $Root
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'installed tree contains a reparse point'
        }
    }

    $manifest = Read-InstalledManifest -Root $Root
    if ($manifest.artifact_family -ne 'SERVER-TEST' -or
        $manifest.platform -ne 'windows' -or
        $manifest.startup_enabled -ne $false -or
        $manifest.install.owner -ne 'R6' -or
        $manifest.install.service_registration -ne $false -or
        $manifest.install.autostart -ne $false -or
        $manifest.install.firewall_rules -ne $false) {
        throw 'installed Windows SERVER-TEST identity is invalid'
    }
    if ($null -ne $ExpectedManifest -and
        ($manifest.artifact_name -ne $ExpectedManifest.artifact_name -or
         $manifest.exact_git_sha -ne $ExpectedManifest.exact_git_sha)) {
        throw 'installed bundle differs from requested archive'
    }

    $checksumPath = Join-Path $Root 'metadata\SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'installed checksum manifest is missing'
    }
    $checksums = Parse-ChecksumText -Bytes ([System.IO.File]::ReadAllBytes($checksumPath))
    $payloadProperties = @($manifest.files.PSObject.Properties)
    if ($checksums.Count -ne ($payloadProperties.Count + 1)) {
        throw 'installed checksum path set mismatch'
    }
    $expectedRelative = @{}
    foreach ($property in $payloadProperties) {
        $relative = $property.Name
        Assert-SafeRelativePath -RelativePath $relative
        $path = Join-Path $Root ($relative.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'installed payload member is missing'
        }
        Assert-NoReparsePoint -Path $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        Assert-NoSensitiveMarkers -Bytes $bytes
        $digest = Get-Sha256Hex -Bytes $bytes
        if ([int64]$property.Value.bytes -ne $bytes.LongLength -or
            [string]$property.Value.sha256 -ne $digest -or
            -not $checksums.ContainsKey($relative) -or
            $checksums[$relative] -ne $digest) {
            throw 'installed payload digest mismatch'
        }
        $expectedRelative[$relative.ToLowerInvariant()] = $true
    }

    $manifestRelative = 'metadata/SERVER-TEST-MANIFEST.json'
    $manifestBytes = [System.IO.File]::ReadAllBytes((Join-Path $Root 'metadata\SERVER-TEST-MANIFEST.json'))
    if (-not $checksums.ContainsKey($manifestRelative) -or
        $checksums[$manifestRelative] -ne (Get-Sha256Hex -Bytes $manifestBytes)) {
        throw 'installed manifest checksum mismatch'
    }
    $expectedRelative[$manifestRelative.ToLowerInvariant()] = $true
    $expectedRelative['metadata/sha256sums.txt'] = $true

    $actualRelative = @{}
    foreach ($file in Get-ChildItem -LiteralPath $Root -Force -Recurse -File) {
        $relative = $file.FullName.Substring($Root.TrimEnd('\').Length + 1).Replace('\', '/')
        $actualRelative[$relative.ToLowerInvariant()] = $true
    }
    if ($actualRelative.Count -ne $expectedRelative.Count) {
        throw 'installed tree contains missing or unexpected files'
    }
    foreach ($relative in $actualRelative.Keys) {
        if (-not $expectedRelative.ContainsKey($relative)) {
            throw 'installed tree contains missing or unexpected files'
        }
    }
    return $manifest
}

function Install-Bundle {
    $root = Resolve-InstallRoot
    $descriptor = Read-VerifiedArchive -Path $ArchivePath

    if (Test-Path -LiteralPath $root) {
        [void](Assert-InstalledTree -Root $root -ExpectedManifest $descriptor.Manifest)
        Write-Output 'RDP-server Windows TEST BUNDLE already installed and verified; startup remains BLOCKED.'
        return
    }

    $parent = [System.IO.Directory]::GetParent($root).FullName
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Assert-NoReparsePoint -Path $parent
    $staging = $root + '.installing-' + [Guid]::NewGuid().ToString('N')
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($descriptor.ArchivePath)
        try {
            $prefix = $descriptor.ArtifactName + '/'
            foreach ($entry in $archive.Entries) {
                if (-not $entry.FullName.StartsWith($prefix, [StringComparison]::Ordinal)) {
                    throw 'archive member is outside artifact root'
                }
                $relative = $entry.FullName.Substring($prefix.Length)
                Assert-SafeRelativePath -RelativePath $relative
                $target = Join-Path $staging ($relative.Replace('/', '\'))
                if (-not (Test-PathBelow -Path $target -Parent $staging)) {
                    throw 'archive extraction escaped staging root'
                }
                $targetParent = [System.IO.Directory]::GetParent($target).FullName
                if (-not (Test-Path -LiteralPath $targetParent)) {
                    New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
                }
                [System.IO.File]::WriteAllBytes($target, (Read-ZipEntryBytes -Entry $entry))
            }
        }
        finally {
            $archive.Dispose()
        }
        [void](Assert-InstalledTree -Root $staging -ExpectedManifest $descriptor.Manifest)
        Move-Item -LiteralPath $staging -Destination $root
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
    Write-Output 'RDP-server Windows TEST BUNDLE installed for the current user; startup remains BLOCKED.'
}

function Verify-Bundle {
    $root = Resolve-InstallRoot
    $descriptor = $null
    if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
        $descriptor = Read-VerifiedArchive -Path $ArchivePath
    }
    if (Test-Path -LiteralPath $root) {
        $expected = $null
        if ($null -ne $descriptor) {
            $expected = $descriptor.Manifest
        }
        [void](Assert-InstalledTree -Root $root -ExpectedManifest $expected)
        Write-Output 'RDP-server Windows TEST BUNDLE installation verified; startup remains BLOCKED.'
        return
    }
    if ($null -ne $descriptor) {
        Write-Output 'RDP-server Windows TEST BUNDLE archive verified; no installation is present.'
        return
    }
    throw 'nothing is available to verify'
}

function Show-Status {
    $root = Resolve-InstallRoot
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Output 'RDP-server Windows TEST BUNDLE is not installed; startup status is BLOCKED.'
        return
    }
    $manifest = Assert-InstalledTree -Root $root
    Write-Output ("RDP-server Windows TEST BUNDLE {0} ({1}) is installed; startup status is BLOCKED." -f $manifest.version, $manifest.exact_git_sha)
}

function Start-Bundle {
    $root = Resolve-InstallRoot
    [void](Assert-InstalledTree -Root $root)
    [Console]::Error.WriteLine('RDP-server Windows native server start is BLOCKED: genuine Windows R2 SSPI/CredSSP SID-bound admission and serialized R10 interactive-session ownership are unavailable. No listener was started.')
    return $script:BlockedExitCode
}

function Stop-Bundle {
    $root = Resolve-InstallRoot
    if (Test-Path -LiteralPath $root) {
        [void](Assert-InstalledTree -Root $root)
    }
    Write-Output 'RDP-server Windows TEST BUNDLE manages no background process or service; nothing was stopped.'
}

function Uninstall-Bundle {
    $root = Resolve-InstallRoot
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Output 'RDP-server Windows TEST BUNDLE is already uninstalled.'
        return
    }
    [void](Assert-InstalledTree -Root $root)
    Remove-Item -LiteralPath $root -Recurse -Force
    Write-Output 'RDP-server Windows TEST BUNDLE uninstalled from the current user profile.'
}

$exitCode = 0
try {
    switch ($Action) {
        'Install' { Install-Bundle }
        'Verify' { Verify-Bundle }
        'Start' { $exitCode = Start-Bundle }
        'Status' { Show-Status }
        'Stop' { Stop-Bundle }
        'Uninstall' { Uninstall-Bundle }
    }
}
catch {
    [Console]::Error.WriteLine('RDP-server Windows TEST BUNDLE operation failed closed; no sensitive values were logged and no startup was authorized.')
    $exitCode = 1
}
exit $exitCode
