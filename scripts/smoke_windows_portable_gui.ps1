# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [string]$Root,
    [switch]$SnapshotContractTest
)

$ErrorActionPreference = "Stop"

function Get-FirewallState {
    $state = @(& netsh.exe advfirewall show allprofiles state)
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot read Windows firewall profile state"
    }
    return ($state -join "`n").Trim()
}

function Get-OfflineSystemState {
    # Observe only: this smoke must never configure TermService, RDP-Tcp,
    # firewall rules, services or the Windows RDP listener.
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService'" -ErrorAction Stop
    if ($null -eq $service) {
        throw "Cannot read TermService configuration"
    }

    $rdpPort = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop
    $rdpDisabled = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop

    $firewallRules = @(& netsh.exe advfirewall firewall show rule name=all)
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot read Windows firewall rules"
    }
    return [ordered]@{
        FirewallProfiles = Get-FirewallState
        FirewallRules = ($firewallRules -join "`n").Trim()
        TermService = (@($service.State, $service.StartMode, $service.PathName, $service.StartName) -join "`n")
        RdpPort = [string]$rdpPort
        RdpPolicy = [string]$rdpDisabled
    }
}

function Assert-UnchangedSystemState(
    [System.Collections.IDictionary]$Before,
    [System.Collections.IDictionary]$After
) {
    foreach ($property in @('FirewallProfiles', 'FirewallRules', 'TermService', 'RdpPort', 'RdpPolicy')) {
        if ($Before[$property] -cne $After[$property]) {
            throw "Windows $property changed during offline GUI smoke"
        }
    }
}

if ($SnapshotContractTest) {
    # Pure synthetic negative paths; this mode never reads native state,
    # launches the GUI or modifies the user's firewall/service configuration.
    $baseline = [ordered]@{
        FirewallProfiles = 'unchanged'
        FirewallRules = 'unchanged'
        TermService = 'unchanged'
        RdpPort = 'unchanged'
        RdpPolicy = 'unchanged'
    }
    Assert-UnchangedSystemState $baseline $baseline
    foreach ($property in @($baseline.Keys)) {
        $changed = [ordered]@{}
        foreach ($key in $baseline.Keys) {
            $changed[$key] = $baseline[$key]
        }
        $changed[$property] = 'changed'
        $rejected = $false
        try {
            Assert-UnchangedSystemState $baseline $changed
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw "System-state mutation escaped offline denial: $property"
        }
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Root)) {
    throw "Extracted Windows GUI root is required"
}
$Root = (Resolve-Path -LiteralPath $Root).Path
$Exe = Join-Path $Root "RDP-server-GUI.exe"
$Plugin = Join-Path $Root "plugins\platforms\qwindows.dll"
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf) -or -not (Test-Path -LiteralPath $Plugin -PathType Leaf)) {
    throw "Extracted Windows GUI entrypoint/plugin missing"
}

function Invoke-OfflineMode([string]$Argument) {
    $process = Start-Process -FilePath $Exe -ArgumentList $Argument -WorkingDirectory $Root -PassThru
    try {
        if (-not $process.WaitForExit(15000)) {
            throw "Offline GUI mode timed out: $Argument"
        }
        if ($process.ExitCode -ne 0) {
            throw "Offline GUI mode failed: $Argument exit=$($process.ExitCode)"
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-NoProcessSockets([int]$ProcessId) {
    $tcp = @(Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue)
    $udp = @(Get-NetUDPEndpoint -OwningProcess $ProcessId -ErrorAction SilentlyContinue)
    if ($tcp.Count -ne 0 -or $udp.Count -ne 0) {
        throw "GUI opened a TCP/UDP socket during offline first-screen smoke"
    }
}

function Invoke-FirstScreenSmoke {
    $process = Start-Process -FilePath $Exe -WorkingDirectory $Root -PassThru
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 200
            $process.Refresh()
            if ($process.HasExited) {
                throw "GUI exited before first window became visible"
            }
        } while ($process.MainWindowHandle -eq 0 -and [DateTime]::UtcNow -lt $deadline)

        if ($process.MainWindowHandle -eq 0) {
            throw "GUI did not expose a first-screen window handle"
        }
        Assert-NoProcessSockets -ProcessId $process.Id

        if (-not $process.CloseMainWindow()) {
            throw "GUI first-screen window refused ordinary close"
        }
        if (-not $process.WaitForExit(5000)) {
            throw "GUI did not exit after ordinary window close"
        }
        if ($process.ExitCode -ne 0) {
            throw "GUI ordinary close returned nonzero exit"
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

$systemStateBefore = Get-OfflineSystemState
Invoke-OfflineMode "--offline-self-test"
Invoke-OfflineMode "--offline-start-denial-test"
Invoke-FirstScreenSmoke
Invoke-FirstScreenSmoke
$systemStateAfter = Get-OfflineSystemState
Assert-UnchangedSystemState $systemStateBefore $systemStateAfter

Write-Host "Windows extracted GUI offline first-screen/no-socket/rerun and native system-state smoke: PASS"
