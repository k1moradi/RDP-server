# SPDX-License-Identifier: GPL-3.0-or-later
param(
    [Parameter(Mandatory = $true)]
    [string]$Root
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path -LiteralPath $Root).Path
$Exe = Join-Path $Root "RDP-server-GUI.exe"
$Plugin = Join-Path $Root "plugins\platforms\qwindows.dll"
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf) -or -not (Test-Path -LiteralPath $Plugin -PathType Leaf)) {
    throw "Extracted Windows GUI entrypoint/plugin missing"
}

function Get-FirewallState {
    return ((& netsh.exe advfirewall show allprofiles state) | Out-String).Trim()
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

$firewallBefore = Get-FirewallState
Invoke-OfflineMode "--offline-self-test"
Invoke-OfflineMode "--offline-start-denial-test"
Invoke-FirstScreenSmoke
Invoke-FirstScreenSmoke
$firewallAfter = Get-FirewallState

if ($firewallBefore -ne $firewallAfter) {
    throw "Windows firewall profile state changed during offline GUI smoke"
}

Write-Host "Windows extracted GUI offline first-screen/no-socket/rerun smoke: PASS"
