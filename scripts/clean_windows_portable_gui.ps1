# SPDX-License-Identifier: GPL-3.0-or-later
# Runs ONLY on a truly clean, interactive, non-admin Windows VM. Never install
# MSYS2/Qt/LLVM/SDK or add toolchain directories to the launched child PATH.
param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][string]$ExactGitSha,
    [Parameter(Mandatory=$true)][string]$Receipt
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExactGitSha -cnotmatch '^[0-9a-f]{40}$') { throw 'Bad exact source SHA' }
$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$archiveName = Split-Path -Leaf $archivePath
$outerDigest = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if (!(Test-Path -LiteralPath "$archivePath.sha256" -PathType Leaf) -or
    (Get-Content -LiteralPath "$archivePath.sha256" -Raw).Trim() -cne "$outerDigest  $archiveName") {
    throw 'ZIP outer digest/sidecar mismatch'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Runner must be a non-administrator Windows desktop user'
}
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($sessionId -eq 0 -or
    @((Get-Process explorer -ErrorAction Stop) | Where-Object SessionId -eq $sessionId).Count -eq 0) {
    throw 'Runner must use an interactive Explorer session, not Session 0'
}
if ($env:PATH -match '(?i)(msys|mingw|clang|llvm|qt[56]|cmake|openssl|vcpkg|windows kits|sdk)') {
    throw 'Runner is provisioned with development/toolchain PATH entries'
}
foreach ($directory in @('C:\msys64', 'C:\Qt', 'C:\Program Files\LLVM')) {
    if (Test-Path -LiteralPath $directory) { throw 'Runner contains forbidden toolchain installation' }
}

$osArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$processArchitecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
if ($osArchitecture -cne 'X64') {
    throw 'Clean Windows evidence must come from an x86-64 OS'
}
$evidenceOrigin = if ($env:GITHUB_ACTIONS -ceq 'true') {
    'self-hosted-clean-runner'
} else {
    'manual-owner-native'
}
$acceptanceLabel = if ($evidenceOrigin -ceq 'manual-owner-native') {
    'MANUAL CLEAN PASS'
} else {
    'SELF-HOSTED CLEAN PASS'
}

# The exact producer archive is structurally bounded and inspected before
# extraction. No ZIP rewriting, dependency deployment, or copying DLLs.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
$names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$exactNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
try {
    if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 4096) {
        throw 'Invalid archive entry count'
    }
    [long]$total = 0
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName
        $parts = $name.Split('/')
        $unsafeWindowsComponent = @(
            $parts | Where-Object {
                $_.EndsWith(' ') -or $_.EndsWith('.')
            }).Count -ne 0
        if (!$name -or $name.StartsWith('/') -or $name.Contains('\') -or
            $name.Contains(':') -or ($name.IndexOf([char]0) -ge 0) -or
            $parts.Contains('') -or $parts.Contains('.') -or
            $parts.Contains('..') -or $name.EndsWith('/') -or
            $unsafeWindowsComponent -or !$names.Add($name) -or
            !$exactNames.Add($name)) {
            throw 'Unsafe or duplicate ZIP entry'
        }
        $total += $entry.Length
        if ($entry.Length -gt 536870912 -or $total -gt 1073741824 -or
            ($entry.Length -gt 0 -and $entry.CompressedLength -eq 0) -or
            $entry.Length -gt 200 * [Math]::Max(1, $entry.CompressedLength)) {
            throw 'Unsafe ZIP size/compression'
        }
        if ($name -match '(?i)\.(msi|msix|bat|cmd|ps1)$' -or
            ($name -match '(?i)\.exe$' -and $name -cne 'RDP-server-GUI.exe')) {
            throw 'Unexpected installer/helper in portable GUI ZIP'
        }
        if ((($entry.ExternalAttributes -shr 16) -band 61440) -eq 40960) {
            throw 'Symlink in Windows ZIP'
        }
    }
}
finally { $zip.Dispose() }

$workspace = (Resolve-Path -LiteralPath '.').Path
$root = Join-Path $workspace 'build\Consumer Windows Ω path with spaces'
if (Test-Path -LiteralPath $root) { throw 'Extraction path must start absent' }
New-Item -ItemType Directory -Path $root -Force | Out-Null
Expand-Archive -LiteralPath $archivePath -DestinationPath $root
$manifestPath = Join-Path $root 'metadata\PORTABLE-GUI-MANIFEST.json'
if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Manifest absent' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.exact_git_sha -cne $ExactGitSha -or
    $manifest.artifact_family -cne 'PORTABLE-GUI' -or
    $manifest.platform -cne 'windows' -or
    $manifest.architecture -cne 'x86_64' -or
    $manifest.startup_enabled -ne $false -or
    $manifest.native_host_ready -ne $false) {
    throw 'Manifest source/target/hosting policy mismatch'
}
foreach ($required in @('LICENSE','NOTICE','THIRD_PARTY.md',
                        'metadata\SHA256SUMS.txt','metadata\DEPENDENCIES.txt',
                        'metadata\PLATFORM-MINIMUMS.json','qt.conf',
                        'Qt6Core.dll','Qt6Gui.dll','Qt6Widgets.dll',
                        'plugins\platforms\qwindows.dll','RDP-server-GUI.exe')) {
    if (!(Test-Path -LiteralPath (Join-Path $root $required) -PathType Leaf)) {
        throw "Required portable GUI file missing: $required"
    }
}
# The source-verified ZIP must still independently match its internal
# manifest and license/notice/checksum payload on this separate machine.
$hashes = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$checksumNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$checksumPath = Join-Path $root 'metadata\SHA256SUMS.txt'
foreach ($line in (Get-Content -LiteralPath $checksumPath)) {
    $checksumMatch = [regex]::Match(
        $line, '^([0-9a-f]{64})  ([^\x00\\:\r\n]+)$')
    if (!$checksumMatch.Success) { throw 'Malformed ZIP checksum line' }
    $checksumName = $checksumMatch.Groups[2].Value
    $checksumParts = $checksumName.Split('/')
    $unsafeChecksumComponent = @(
        $checksumParts | Where-Object {
            $_.EndsWith(' ') -or $_.EndsWith('.')
        }).Count -ne 0
    if (!$checksumName -or $checksumName.StartsWith('/') -or
        $checksumName.EndsWith('/') -or $checksumName.Contains('\') -or
        $checksumName.Contains(':') -or
        ($checksumName.IndexOf([char]0) -ge 0) -or
        $checksumParts.Contains('') -or
        $checksumParts.Contains('.') -or
        $checksumParts.Contains('..') -or $unsafeChecksumComponent) {
        throw 'Unsafe ZIP checksum path'
    }
    if (!$exactNames.Contains($checksumName)) {
        throw 'Checksum refers to missing or differently-cased archive path'
    }
    if ($checksumName -ceq 'metadata/SHA256SUMS.txt') {
        throw 'Checksum list must not hash itself'
    }
    if (!$checksumNames.Add($checksumName)) {
        throw 'Duplicate internal checksum entry'
    }
    $hashes.Add($checksumName, $checksumMatch.Groups[1].Value)
}
if ($hashes.Count -ne $exactNames.Count - 1 -or
    !$hashes.ContainsKey('metadata/PORTABLE-GUI-MANIFEST.json')) {
    throw 'Incomplete ZIP checksum inventory'
}
foreach ($archiveEntryName in $exactNames) {
    if ($archiveEntryName -cne 'metadata/SHA256SUMS.txt' -and
        !$hashes.ContainsKey($archiveEntryName)) {
        throw 'Incomplete ZIP checksum inventory'
    }
}
foreach ($name in $hashes.Keys) {
    $path = Join-Path $root ($name.Replace('/', '\'))
    if (!(Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $hashes[$name]) {
        throw 'ZIP payload hash mismatch'
    }
}
$manifestFiles = @($manifest.files.PSObject.Properties)
if ($manifestFiles.Count -ne $hashes.Count - 1) {
    throw 'Manifest file count mismatch'
}
foreach ($file in $manifestFiles) {
    if (!$hashes.ContainsKey($file.Name) -or
        $hashes[$file.Name] -cne [string]$file.Value) {
        throw 'Manifest hashes disagree with internal checksum list'
    }
}
$minimums = Get-Content -LiteralPath (Join-Path $root 'metadata\PLATFORM-MINIMUMS.json') -Raw | ConvertFrom-Json
if ($minimums.privilege -cne 'standard-user' -or
    $minimums.installation -cne 'none-required') {
    throw 'GUI requires administrator or installation'
}

# Native, read-only snapshots reject installation/service/TermService/firewall
# mutations. Never modify service, registry, firewall or Windows RDP settings.
function Get-WindowsSafetyState {
    $rules = Get-NetFirewallRule -ErrorAction Stop | Sort-Object Name |
        Select-Object Name, Enabled, Direction, Action, Profile | ConvertTo-Json -Compress -Depth 4
    $profiles = Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        ConvertTo-Json -Compress -Depth 4
    $services = Get-CimInstance Win32_Service -ErrorAction Stop | Sort-Object Name |
        Select-Object Name, State, StartMode, PathName | ConvertTo-Json -Compress -Depth 4
    $term = Get-CimInstance Win32_Service -Filter "Name='TermService'" -ErrorAction Stop
    $policy = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
    $port = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
    return (@($rules, $profiles, $services, $term.State, $term.StartMode,
              $policy.fDenyTSConnections, $port.PortNumber) | Out-String)
}
$before = Get-WindowsSafetyState
# A failed socket inventory is not evidence of an unused/listener-free port.
$null = @(Get-NetTCPConnection -ErrorAction Stop)
$null = @(Get-NetUDPEndpoint -ErrorAction Stop)

$originalPath = $env:PATH
$namesToRestore = @('QT_PLUGIN_PATH','QT_QPA_PLATFORM_PLUGIN_PATH','QT_QPA_PLATFORM',
                    'QML2_IMPORT_PATH','QML_IMPORT_PATH','MSYSTEM','MSYS2_PATH_TYPE',
                    'CMAKE_PREFIX_PATH','OPENSSL_ROOT_DIR','LD_LIBRARY_PATH','PYTHONPATH')
$oldEnvironment = @{}
foreach ($name in $namesToRestore) {
    $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
}
$windows = [Environment]::GetFolderPath('Windows')
if (!$windows) { throw 'Windows root unavailable' }
$isolatedChildPath = "$windows\System32;$windows;$windows\System32\Wbem"
$env:PATH = $isolatedChildPath
foreach ($name in $namesToRestore) {
    [Environment]::SetEnvironmentVariable($name,$null,'Process')
}
$env:QT_QPA_PLATFORM = 'windows'
if ($env:PATH -cne $isolatedChildPath) {
    throw 'GUI child PATH was not isolated to Windows system directories'
}
foreach ($name in $namesToRestore) {
    if ($name -ne 'QT_QPA_PLATFORM' -and
        [Environment]::GetEnvironmentVariable($name,'Process')) {
        throw "GUI inherited developer environment override: $name"
    }
}
if ($env:QT_QPA_PLATFORM -cne 'windows') {
    throw 'Qt platform selection was not pinned to the native Windows plugin'
}
try {
    # This real GUI smoke runs hidden tests, first window, ordinary close,
    # relaunch and second close, plus per-process TCP/UDP socket assertions.
    & (Join-Path $workspace 'scripts\smoke_windows_portable_gui.ps1') -Root $root
    if (!$?) { throw 'Clean Windows GUI launch/close/relaunch failed' }
    $process = Start-Process -FilePath (Join-Path $root 'RDP-server-GUI.exe') -ArgumentList '--offline-unsupported-password-test' -WorkingDirectory $root -PassThru
    try {
        if (!$process.WaitForExit(15000) -or $process.ExitCode -ne 0) {
            throw 'Packaged independent-password denial test failed'
        }
    }
    finally {
        if (!$process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
finally {
    $env:PATH = $originalPath
    foreach ($name in $namesToRestore) {
        [Environment]::SetEnvironmentVariable($name,$oldEnvironment[$name],'Process')
    }
}
if ((Get-WindowsSafetyState) -cne $before) {
    throw 'GUI changed firewall/TermService/RDP policy/service registration'
}
$receiptParent = Split-Path -Parent $Receipt
if ($receiptParent) {
    New-Item -ItemType Directory -Path $receiptParent -Force | Out-Null
}
[ordered]@{
    schema = 'rdp-server-clean-windows-receipt-v1'
    status = 'PASS'
    gate = 'clean-windows-portable-gui'
    evidence_origin = $evidenceOrigin
    acceptance_label = $acceptanceLabel
    exact_git_sha = $ExactGitSha
    archive = $archiveName
    archive_sha256 = $outerDigest
    machine = [Environment]::MachineName
    windows_version = [Environment]::OSVersion.VersionString
    os_architecture = $osArchitecture
    process_architecture = $processArchitecture
    session_id = $sessionId
    non_admin_interactive = $true
    explorer_session = $true
    clean_path = [ordered]@{
        initial_development_entries_absent = $true
        forbidden_toolchain_directories_absent = $true
        child_windows_system_only = $true
        developer_environment_cleared = $true
    }
    checks = [ordered]@{
        archive_outer_sidecar_match = $true
        archive_internal_hashes_match = $true
        manifest_and_notices_present = $true
        windows_platform_plugin_present = $true
        launch_close_relaunch = $true
        offline_hidden_self_tests = $true
        unicode_space_extraction = $true
        no_process_tcp_udp_before_start = $true
        firewall_rules_profiles_unchanged = $true
        services_unchanged = $true
        termservice_unchanged = $true
        rdp_policy_port_unchanged = $true
        no_install_or_elevation = $true
    }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Receipt -Encoding UTF8
$receiptPath = (Resolve-Path -LiteralPath $Receipt).Path
$receiptName = Split-Path -Leaf $receiptPath
$receiptDigest = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath ($receiptPath + '.sha256') -Value "$receiptDigest  $receiptName" -Encoding ascii
Write-Host "R9 CLEAN evidence classification: $acceptanceLabel"
Write-Host "R9 CLEAN receipt SHA-256: $receiptDigest"
Write-Host 'R9 clean Windows portable GUI acceptance PASS'
