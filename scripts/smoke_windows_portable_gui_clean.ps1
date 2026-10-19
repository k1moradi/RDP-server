# SPDX-License-Identifier: GPL-3.0-or-later
# Unprivileged, process-local clean-PATH wrapper for the real portable GUI smoke.
param([string]$Root, [switch]$EnvironmentSelfTest)

$ErrorActionPreference = "Stop"
$windowsDirectory = [Environment]::GetFolderPath("Windows")
$systemDirectory = Join-Path $windowsDirectory "System32"
if ([string]::IsNullOrWhiteSpace($windowsDirectory) -or
    -not (Test-Path -LiteralPath $systemDirectory -PathType Container)) {
    throw "Windows system DLL directory unavailable"
}
$isolatedPath = $systemDirectory + [IO.Path]::PathSeparator + $windowsDirectory
$environmentNames = @(
    "PATH", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH",
    "QT_QPA_PLATFORM", "QT_QPA_FONTDIR", "QML_IMPORT_PATH",
    "QML2_IMPORT_PATH", "MSYSTEM", "MINGW_PREFIX"
)
$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
try {
    if ($EnvironmentSelfTest) {
        $env:PATH = "C:\msys64\clang64\bin;C:\Qt\developer\bin;" + $env:PATH
        $env:QT_PLUGIN_PATH = "C:\Qt\developer\plugins"
        $env:QT_QPA_PLATFORM_PLUGIN_PATH = "C:\Qt\developer\platforms"
    }
    [Environment]::SetEnvironmentVariable("PATH", $isolatedPath, "Process")
    foreach ($name in $environmentNames) {
        if ($name -ne "PATH") {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
    }
    if ([Environment]::GetEnvironmentVariable("PATH", "Process") -cne $isolatedPath) {
        throw "GUI child PATH was not isolated"
    }
    foreach ($name in $environmentNames) {
        if ($name -ne "PATH" -and [Environment]::GetEnvironmentVariable($name, "Process")) {
            throw "GUI inherited developer environment override: $name"
        }
    }
    if (-not $EnvironmentSelfTest) {
        if ([string]::IsNullOrWhiteSpace($Root)) { throw "extracted GUI root is required" }
        # Reuse real first-screen, normal-close, two-launch and no-socket tests.
        & (Join-Path $PSScriptRoot "smoke_windows_portable_gui.ps1") -Root $Root
        if (-not $?) { throw "isolated GUI smoke failed" }
    }
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], "Process")
    }
}
