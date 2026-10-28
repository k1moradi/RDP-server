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


function Add-ValidatedFirewallRule(
    [System.Collections.Generic.List[string]]$Lines,
    [System.Collections.Generic.List[string]]$Records
) {
    if ($Lines.Count -eq 0) {
        return
    }
    $record = ($Lines -join "`n").Trim()
    # Keep every advertised field, not merely Enabled/Direction/Action: a
    # rule-property change must remain visible even when netsh reorders rules.
    foreach ($requiredField in @('Enabled', 'Direction', 'Profiles', 'Action')) {
        if ($record -cnotmatch "(?m)^\s*$requiredField\s*:\s*\S") {
            throw "Incomplete Windows firewall rule enumeration: $requiredField"
        }
    }
    $Records.Add($record)
}

function Get-FirewallRuleSnapshot([string[]]$Enumeration) {
    # netsh does not guarantee rule enumeration order. Preserve exact fields,
    # duplicate rule records and identity; normalize only inter-rule order.
    $records = [System.Collections.Generic.List[string]]::new()
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($rawLine in $Enumeration) {
        $line = $rawLine.TrimEnd()
        if ($line -cmatch '^\s*Rule Name:\s*\S') {
            Add-ValidatedFirewallRule $lines $records
            $lines.Clear()
            $lines.Add($line)
        }
        elseif ($lines.Count -eq 0) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                throw "Unexpected Windows firewall rule enumeration header"
            }
        }
        else {
            $lines.Add($line)
        }
    }
    Add-ValidatedFirewallRule $lines $records
    if ($records.Count -eq 0) {
        throw "Empty Windows firewall rule enumeration"
    }

    $orderedRecords = $records.ToArray()
    $sortedRecords = [string[]]$orderedRecords.Clone()
    [Array]::Sort($sortedRecords, [StringComparer]::Ordinal)
    return [ordered]@{
        Canonical = [string]::Join([char]31, $sortedRecords)
        SortedRecords = $sortedRecords
        OrderedRecords = $orderedRecords
        Raw = ($Enumeration -join "`n").Trim()
    }
}

function Write-FirewallRuleDifferences(
    [System.Collections.IDictionary]$Before,
    [System.Collections.IDictionary]$After
) {
    $changes = @(Compare-Object -ReferenceObject $Before['FirewallRuleRecords'] -DifferenceObject $After['FirewallRuleRecords'] -CaseSensitive)
    Write-Host "Firewall rule record difference count: $($changes.Count); before=$(@($Before['FirewallRuleRecords']).Count) after=$(@($After['FirewallRuleRecords']).Count)"
    foreach ($change in ($changes | Select-Object -First 16)) {
        # Fail-only evidence: report actual removed/added complete rule records.
        Write-Host ("Firewall rule {0}: {1}" -f $change.SideIndicator, $change.InputObject)
    }
    if ($changes.Count -gt 16) {
        Write-Host "Firewall rule differences truncated after 16 records"
    }
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
    $ruleSnapshot = Get-FirewallRuleSnapshot -Enumeration $firewallRules
    return [ordered]@{
        FirewallProfiles = Get-FirewallState
        FirewallRules = $ruleSnapshot.Canonical
        FirewallRuleRecords = $ruleSnapshot.SortedRecords
        FirewallRuleOrder = $ruleSnapshot.OrderedRecords
        FirewallRuleRaw = $ruleSnapshot.Raw
        TermService = (@($service.State, $service.StartMode, $service.PathName, $service.StartName) -join "`n")
        RdpPort = [string]$rdpPort
        RdpPolicy = [string]$rdpDisabled
    }
}

function Assert-UnchangedSystemState(
    [System.Collections.IDictionary]$Before,
    [System.Collections.IDictionary]$After,
    [string]$Phase = 'offline GUI smoke'
) {
    foreach ($property in @('FirewallProfiles', 'FirewallRules', 'TermService', 'RdpPort', 'RdpPolicy')) {
        if ($Before[$property] -cne $After[$property]) {
            if ($property -eq 'FirewallRules' -and $Before.Contains('FirewallRuleRecords') -and $After.Contains('FirewallRuleRecords')) {
                Write-FirewallRuleDifferences $Before $After
            }
            throw "Windows $property changed during $Phase"
        }
    }
    if ($Before.Contains('FirewallRuleRaw') -and $After.Contains('FirewallRuleRaw') -and
        $Before['FirewallRuleRaw'] -cne $After['FirewallRuleRaw']) {
        # A changed raw rendering is observable, never an exemption for a
        # changed rule. The complete sorted record multiset already matched.
        $oldOrder = @($Before['FirewallRuleOrder'])
        $newOrder = @($After['FirewallRuleOrder'])
        $firstChangedIndex = 0
        while ($firstChangedIndex -lt $oldOrder.Count -and
               $firstChangedIndex -lt $newOrder.Count -and
               $oldOrder[$firstChangedIndex] -ceq $newOrder[$firstChangedIndex]) {
            ++$firstChangedIndex
        }
        $oldFirst = if ($firstChangedIndex -lt $oldOrder.Count) { ($oldOrder[$firstChangedIndex] -split "\n")[0] } else { '<end>' }
        $newFirst = if ($firstChangedIndex -lt $newOrder.Count) { ($newOrder[$firstChangedIndex] -split "\n")[0] } else { '<end>' }
        Write-Host "Windows FirewallRules raw netsh ordering/format drift during $Phase; canonical rule identities and every displayed property unchanged (before=$($oldOrder.Count), after=$($newOrder.Count), first-different-index=$firstChangedIndex, before-rule=$oldFirst, after-rule=$newFirst)"
    }
}

if ($SnapshotContractTest) {
    # Pure synthetic negative paths; no native reads, GUI or system mutation.
    $firstRule = @(
        'Rule Name: Example inbound',
        '----------------------------------------------------------------------',
        'Enabled: Yes',
        'Direction: In',
        'Profiles: Domain,Private',
        'LocalIP: Any',
        'RemoteIP: Any',
        'Protocol: TCP',
        'LocalPort: 3389',
        'Action: Allow'
    )
    $secondRule = @(
        'Rule Name: Example outbound',
        '----------------------------------------------------------------------',
        'Enabled: Yes',
        'Direction: Out',
        'Profiles: Any',
        'LocalIP: Any',
        'RemoteIP: Any',
        'Protocol: UDP',
        'LocalPort: Any',
        'Action: Block'
    )
    $firstSnapshot = Get-FirewallRuleSnapshot -Enumeration ($firstRule + @('') + $secondRule)
    $reorderedSnapshot = Get-FirewallRuleSnapshot -Enumeration ($secondRule + @('') + $firstRule)
    $baseline = [ordered]@{
        FirewallProfiles = 'unchanged'
        FirewallRules = $firstSnapshot.Canonical
        FirewallRuleRecords = $firstSnapshot.SortedRecords
        FirewallRuleOrder = $firstSnapshot.OrderedRecords
        FirewallRuleRaw = $firstSnapshot.Raw
        TermService = 'unchanged'
        RdpPort = 'unchanged'
        RdpPolicy = 'unchanged'
    }
    $reordered = [ordered]@{}
    foreach ($key in $baseline.Keys) { $reordered[$key] = $baseline[$key] }
    $reordered['FirewallRules'] = $reorderedSnapshot.Canonical
    $reordered['FirewallRuleRecords'] = $reorderedSnapshot.SortedRecords
    $reordered['FirewallRuleOrder'] = $reorderedSnapshot.OrderedRecords
    $reordered['FirewallRuleRaw'] = $reorderedSnapshot.Raw
    Assert-UnchangedSystemState $baseline $baseline
    Assert-UnchangedSystemState $baseline $reordered 'synthetic ordering control'

    foreach ($property in @('FirewallProfiles', 'FirewallRules', 'TermService', 'RdpPort', 'RdpPolicy')) {
        $changed = [ordered]@{}
        foreach ($key in $baseline.Keys) { $changed[$key] = $baseline[$key] }
        $changed[$property] = 'changed'
        try {
            Assert-UnchangedSystemState $baseline $changed 'synthetic mutation'
            throw "System-state mutation escaped offline denial: $property"
        }
        catch {
            if ($_.Exception.Message -cne "Windows $property changed during synthetic mutation") { throw }
        }
    }
    foreach ($mutation in @(
        @('Enabled: Yes', 'Enabled: No'),
        @('Direction: In', 'Direction: Out'),
        @('Profiles: Domain,Private', 'Profiles: Public'),
        @('RemoteIP: Any', 'RemoteIP: 192.0.2.1'),
        @('Protocol: TCP', 'Protocol: UDP'),
        @('LocalPort: 3389', 'LocalPort: 3390'),
        @('Action: Allow', 'Action: Block'),
        @('Rule Name: Example inbound', 'Rule Name: Renamed inbound')
    )) {
        $changedRule = ($firstRule -join "`n").Replace($mutation[0], $mutation[1]) -split "`n"
        $changedSnapshot = Get-FirewallRuleSnapshot -Enumeration ($changedRule + @('') + $secondRule)
        $changed = [ordered]@{}
        foreach ($key in $baseline.Keys) { $changed[$key] = $baseline[$key] }
        $changed['FirewallRules'] = $changedSnapshot.Canonical
        $changed['FirewallRuleRecords'] = $changedSnapshot.SortedRecords
        $changed['FirewallRuleOrder'] = $changedSnapshot.OrderedRecords
        $changed['FirewallRuleRaw'] = $changedSnapshot.Raw
        try {
            Assert-UnchangedSystemState $baseline $changed 'synthetic mutation'
            throw "Firewall rule mutation escaped offline denial: $($mutation[0])"
        }
        catch {
            if ($_.Exception.Message -cne 'Windows FirewallRules changed during synthetic mutation') { throw }
        }
    }
    $removedSnapshot = Get-FirewallRuleSnapshot -Enumeration $firstRule
    $addedSnapshot = Get-FirewallRuleSnapshot -Enumeration ($firstRule + @('') + $firstRule + @('') + $secondRule)
    if ($removedSnapshot.Canonical -ceq $firstSnapshot.Canonical -or
        $addedSnapshot.Canonical -ceq $firstSnapshot.Canonical) {
        throw 'Firewall rule addition/removal escaped offline denial'
    }

    $malformedCases = [System.Collections.Generic.List[string[]]]::new()
    $malformedCases.Add([string[]]@('Unexpected enumeration header'))
    $malformedCases.Add([string[]]@('Rule Name: Example inbound', 'Enabled: Yes', 'Action: Allow'))
    foreach ($malformed in $malformedCases) {
        $rejected = $false
        try {
            $null = Get-FirewallRuleSnapshot -Enumeration $malformed
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw 'Malformed firewall enumeration escaped offline denial'
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
    # Enumerate first and then filter. A failed Windows networking query must
    # not be mistaken for an empty per-process socket list in portable smoke.
    $tcp = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $ProcessId })
    $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $ProcessId })
    if ($tcp.Count -ne 0 -or $udp.Count -ne 0) {
        throw "GUI opened a TCP/UDP socket during offline first-screen smoke"
    }
}

function Invoke-FirstScreenSmoke {
    # Canonical consumer startup is the extracted desktop application with no
    # arguments. Hidden argument modes above are diagnostics only.
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

$initialSystemState = Get-OfflineSystemState
$systemStateBefore = Get-OfflineSystemState
Assert-UnchangedSystemState $initialSystemState $systemStateBefore 'idle control before GUI'
Invoke-OfflineMode "--offline-self-test"
$nextState = Get-OfflineSystemState
Assert-UnchangedSystemState $systemStateBefore $nextState 'offline self-test'
Invoke-OfflineMode "--offline-start-denial-test"
$nextState = Get-OfflineSystemState
Assert-UnchangedSystemState $systemStateBefore $nextState 'offline Start denial'
Invoke-FirstScreenSmoke
$nextState = Get-OfflineSystemState
Assert-UnchangedSystemState $systemStateBefore $nextState 'first GUI window'
Invoke-FirstScreenSmoke
$systemStateAfter = Get-OfflineSystemState
Assert-UnchangedSystemState $systemStateBefore $systemStateAfter 'second GUI window'

Write-Host "Windows canonical no-argument extracted GUI first-screen/no-socket/rerun and native system-state smoke: PASS"
