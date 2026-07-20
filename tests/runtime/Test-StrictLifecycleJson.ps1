[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail
    )

    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function Write-StrictFixtureText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    [System.IO.File]::WriteAllText(
        $Path,
        $Text,
        [System.Text.UTF8Encoding]::new($false))
}

function ConvertTo-StrictFixtureJson {
    param([Parameter(Mandatory)]$Value)

    $Value | ConvertTo-Json -Depth 8 -Compress
}

function Test-RejectedBeforeLifecycleActions {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)]
        [ValidateSet('ServerProcessRecord', 'ServerControlState',
            'ServerControlRequest', 'ClientStartupReceipt')]
        [string]$Contract
    )

    $fixturePath = Join-Path $script:fixtureRoot (
        [Guid]::NewGuid().ToString('N') + '.json')
    Write-StrictFixtureText -Path $fixturePath -Text $Json
    $actions = [ordered]@{
        Child = 0
        Control = 0
        Stdin = 0
        Pid = 0
        Cleanup = 0
    }
    $message = ''
    try {
        Read-PSOBBStrictLifecycleJson `
            -Path $fixturePath -Root $script:fixtureRoot -Contract $Contract | Out-Null
        # This is the first point at which any lifecycle consumer is allowed to
        # act. A malformed fixture must never reach it.
        foreach ($key in @($actions.Keys)) {
            $actions[$key]++
        }
    } catch {
        $message = $_.Exception.Message
    }
    $actionCount = [int](($actions.Values | Measure-Object -Sum).Sum)
    Add-Result -Name $Name -Passed (
        -not [string]::IsNullOrWhiteSpace($message) -and $actionCount -eq 0) `
        -Detail "actions=$actionCount; $message"
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-strict-lifecycle-json-' + [Guid]::NewGuid().ToString('N'))
try {
    [System.IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null

    $processRecord = [ordered]@{
        schemaVersion = 3
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        pid = 101
        executablePath = 'C:\fixture\newserv-windows.exe'
        executableSha256 = 'a' * 64
        startTimeUtc = 'Sun, 19 Jul 2026 12:00:00 GMT'
        startTimeFileTimeUtc = 133000000000000001L
        hostPid = 102
        hostStartTimeUtc = 'Sun, 19 Jul 2026 11:59:59 GMT'
        hostStartTimeFileTimeUtc = 133000000000000000L
        hostExecutablePath = 'C:\fixture\pwsh.exe'
        startupRequestId = 'b' * 32
        controlToken = 'A' * 43
        controlProtocol = 'protected-filesystem-exit-v2'
        buildContractSha256 = $null
        clientBindingSha256 = $null
        stateBindingSha256 = $null
        stdoutLog = 'C:\fixture\stdout.log'
        stderrLog = 'C:\fixture\stderr.log'
    }
    $startingState = [ordered]@{
        schemaVersion = 3
        state = 'starting'
        installationId = '12345678-1234-1234-1234-123456789abc'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        executablePath = 'C:\fixture\newserv-windows.exe'
        executableSha256 = 'a' * 64
        buildContractSha256 = $null
        clientBindingSha256 = $null
        stateBindingSha256 = $null
        startupRequestId = 'b' * 32
        controlToken = 'A' * 43
        requestedAtUtc = '2026-07-19T12:00:00.0000000Z'
    }
    $readyState = [ordered]@{
        schemaVersion = 3
        state = 'child-started'
        installationId = '12345678-1234-1234-1234-123456789abc'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        pid = 101
        startTimeFileTimeUtc = 133000000000000001L
        hostPid = 102
        hostStartTimeFileTimeUtc = 133000000000000000L
        startupRequestId = 'b' * 32
        startTimeUtc = '2026-07-19T12:00:00.0000000Z'
        updatedAtUtc = '2026-07-19T12:00:01.0000000Z'
    }
    $stoppingState = [ordered]@{
        schemaVersion = 3
        state = 'shell-exit-requested'
        installationId = '12345678-1234-1234-1234-123456789abc'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        pid = 101
        startTimeFileTimeUtc = 133000000000000001L
        hostPid = 102
        hostStartTimeFileTimeUtc = 133000000000000000L
        updatedAtUtc = '2026-07-19T12:00:02.0000000Z'
    }
    $terminalState = [ordered]@{
        schemaVersion = 3
        state = 'stopped'
        installationId = '12345678-1234-1234-1234-123456789abc'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        pid = 101
        startTimeFileTimeUtc = 133000000000000001L
        exitCode = 0
        gracefulShellExitRequested = $true
        updatedAtUtc = '2026-07-19T12:00:03.0000000Z'
    }
    $failedState = [ordered]@{
        schemaVersion = 3
        state = 'failed'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = $null
        message = 'fixture failure'
        updatedAtUtc = '2026-07-19T12:00:04.0000000Z'
    }
    $exitRequest = [ordered]@{
        schemaVersion = 3
        action = 'exit'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        startupRequestId = 'b' * 32
        pid = 101
        startTimeUtc = 'Sun, 19 Jul 2026 12:00:00 GMT'
        startTimeFileTimeUtc = 133000000000000001L
        controlToken = 'A' * 43
        requestedAtUtc = '2026-07-19T12:00:05.0000000Z'
    }
    $cancelRequest = [ordered]@{
        schemaVersion = 3
        action = 'cancel-start'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        componentId = 'newserv-stable-release'
        controlIdentity = 'control-identity'
        hostPid = 102
        hostStartTimeFileTimeUtc = 133000000000000000L
        startupRequestId = 'b' * 32
        controlToken = 'A' * 43
        requestedAtUtc = '2026-07-19T12:00:06.0000000Z'
    }
    $clientReceipt = [ordered]@{
        schemaVersion = 3
        completedAtUtc = '2026-07-19T12:00:07.0000000Z'
        serverEnvironment = 'Stable'
        environmentId = 'stable'
        channel = 'Stable'
        profileId = $null
        materializedProfileSha256 = 'c' * 64
        configurationSha256 = $null
        processId = 103
        processStartTimeUtc = '2026-07-19T12:00:07.0000000Z'
        processStartTimeFileTimeUtc = 133000000000000002L
        executableSize = 4096L
        executableSha256 = 'd' * 64
        clientBindingSha256 = $null
        startupElapsedMilliseconds = 12.5
        foregroundPreserved = $true
        windowMode = 'ProfileDefault'
        window = [ordered]@{
            x = 0
            y = 0
            width = 640
            height = 480
            clientWidth = 640
            clientHeight = 480
        }
        nativeGraphicsPresetId = 'high-end'
        graphicCtrlSha256 = 'e' * 64
    }

    $validFixtures = @(
        [pscustomobject]@{ Name = 'process'; Contract = 'ServerProcessRecord'; Value = $processRecord },
        [pscustomobject]@{ Name = 'startup'; Contract = 'ServerControlState'; Value = $startingState },
        [pscustomobject]@{ Name = 'ready'; Contract = 'ServerControlState'; Value = $readyState },
        [pscustomobject]@{ Name = 'control'; Contract = 'ServerControlState'; Value = $stoppingState },
        [pscustomobject]@{ Name = 'terminal'; Contract = 'ServerControlState'; Value = $terminalState },
        [pscustomobject]@{ Name = 'failure'; Contract = 'ServerControlState'; Value = $failedState },
        [pscustomobject]@{ Name = 'exit request'; Contract = 'ServerControlRequest'; Value = $exitRequest },
        [pscustomobject]@{ Name = 'cancel request'; Contract = 'ServerControlRequest'; Value = $cancelRequest },
        [pscustomobject]@{ Name = 'client receipt'; Contract = 'ClientStartupReceipt'; Value = $clientReceipt })
    $validAccepted = $true
    $validDetail = [System.Collections.Generic.List[string]]::new()
    foreach ($fixture in $validFixtures) {
        $path = Join-Path $fixtureRoot ($fixture.Name.Replace(' ', '-') + '.json')
        Write-StrictFixtureText -Path $path -Text (
            ConvertTo-StrictFixtureJson -Value $fixture.Value)
        try {
            $parsed = Read-PSOBBStrictLifecycleJson `
                -Path $path -Root $fixtureRoot -Contract $fixture.Contract
            $validDetail.Add("$($fixture.Name)=$($parsed.schemaVersion)")
        } catch {
            $validAccepted = $false
            $validDetail.Add("$($fixture.Name)=$($_.Exception.Message)")
        }
    }
    Add-Result 'schema-3 lifecycle producer shapes pass the strict reader' `
        $validAccepted ($validDetail -join '; ')

    $startingJson = ConvertTo-StrictFixtureJson -Value $startingState
    Test-RejectedBeforeLifecycleActions `
        -Name 'startup state rejects a missing control token before every action' `
        -Contract ServerControlState `
        -Json ($startingJson -replace ',"controlToken":"[^"]+"', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'startup state rejects an extra action property before every action' `
        -Contract ServerControlState `
        -Json ($startingJson -replace '^{', '{"action":"exit",')
    Test-RejectedBeforeLifecycleActions `
        -Name 'startup state rejects a decoded duplicate identity before every action' `
        -Contract ServerControlState `
        -Json ($startingJson -replace '"controlIdentity":"control-identity",',
            '"controlIdentity":"control-identity","control\u0049dentity":"control-identity",')

    $processJson = ConvertTo-StrictFixtureJson -Value $processRecord
    Test-RejectedBeforeLifecycleActions `
        -Name 'process record rejects a missing PID before every action' `
        -Contract ServerProcessRecord `
        -Json ($processJson -replace ',"pid":101', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'process record rejects an extra action before every action' `
        -Contract ServerProcessRecord `
        -Json ($processJson -replace '^{', '{"action":"exit",')
    Test-RejectedBeforeLifecycleActions `
        -Name 'process record rejects an escaped duplicate PID before every action' `
        -Contract ServerProcessRecord `
        -Json ($processJson -replace '"pid":101,', '"pid":101,"p\u0069d":101,')

    $readyJson = ConvertTo-StrictFixtureJson -Value $readyState
    Test-RejectedBeforeLifecycleActions `
        -Name 'ready state rejects a missing exact child creation time before every action' `
        -Contract ServerControlState `
        -Json ($readyJson -replace ',"startTimeFileTimeUtc":133000000000000001', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'ready state rejects an extra cleanup property before every action' `
        -Contract ServerControlState `
        -Json ($readyJson -replace '^{', '{"cleanup":true,')
    Test-RejectedBeforeLifecycleActions `
        -Name 'ready state rejects a duplicate PID before every action' `
        -Contract ServerControlState `
        -Json ($readyJson -replace '"pid":101,', '"pid":101,"pid":101,')

    $stoppingJson = ConvertTo-StrictFixtureJson -Value $stoppingState
    Test-RejectedBeforeLifecycleActions `
        -Name 'control state rejects a missing identity before every action' `
        -Contract ServerControlState `
        -Json ($stoppingJson -replace ',"controlIdentity":"control-identity"', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'control state rejects an extra token before every action' `
        -Contract ServerControlState `
        -Json ($stoppingJson -replace '^{', '{"controlToken":"untrusted",')

    $exitJson = ConvertTo-StrictFixtureJson -Value $exitRequest
    Test-RejectedBeforeLifecycleActions `
        -Name 'exit request rejects a missing token before every action' `
        -Contract ServerControlRequest `
        -Json ($exitJson -replace ',"controlToken":"[^"]+"', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'exit request rejects an extra cleanup field before every action' `
        -Contract ServerControlRequest `
        -Json ($exitJson -replace '^{', '{"cleanup":true,')
    Test-RejectedBeforeLifecycleActions `
        -Name 'exit request rejects a duplicate action before every action' `
        -Contract ServerControlRequest `
        -Json ($exitJson -replace '"action":"exit",',
            '"action":"exit","action":"exit",')

    $cancelJson = ConvertTo-StrictFixtureJson -Value $cancelRequest
    Test-RejectedBeforeLifecycleActions `
        -Name 'cancel request rejects a missing identity before every action' `
        -Contract ServerControlRequest `
        -Json ($cancelJson -replace ',"controlIdentity":"control-identity"', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'cancel request rejects an extra child PID before every action' `
        -Contract ServerControlRequest `
        -Json ($cancelJson -replace '^{', '{"pid":101,')
    Test-RejectedBeforeLifecycleActions `
        -Name 'cancel request rejects an escaped duplicate action before every action' `
        -Contract ServerControlRequest `
        -Json ($cancelJson -replace '"action":"cancel-start",',
            '"action":"cancel-start","act\u0069on":"cancel-start",')

    $receiptJson = ConvertTo-StrictFixtureJson -Value $clientReceipt
    Test-RejectedBeforeLifecycleActions `
        -Name 'client receipt rejects a missing exact process creation time before every action' `
        -Contract ClientStartupReceipt `
        -Json ($receiptJson -replace
            ',"processStartTimeFileTimeUtc":133000000000000002', '')
    Test-RejectedBeforeLifecycleActions `
        -Name 'client receipt rejects a recursively decoded duplicate window property' `
        -Contract ClientStartupReceipt `
        -Json ($receiptJson -replace '"clientWidth":640,',
            '"clientWidth":640,"client\u0057idth":640,')

    Test-RejectedBeforeLifecycleActions `
        -Name 'schema downgrade is rejected before every lifecycle action' `
        -Contract ServerProcessRecord `
        -Json ($processJson -replace '"schemaVersion":3', '"schemaVersion":2')
    Test-RejectedBeforeLifecycleActions `
        -Name 'comments are rejected before every lifecycle action' `
        -Contract ServerProcessRecord `
        -Json ($processJson -replace '^{', "{/*comment*/")
    Test-RejectedBeforeLifecycleActions `
        -Name 'trailing commas are rejected before every lifecycle action' `
        -Contract ServerProcessRecord `
        -Json ($processJson -replace '}$', ',}')

    $invalidUtf8Path = Join-Path $fixtureRoot 'invalid-utf8.json'
    [System.IO.File]::WriteAllBytes($invalidUtf8Path, [byte[]]@(0x7B, 0xFF, 0x7D))
    $invalidUtf8Rejected = $false
    try {
        Read-PSOBBStrictLifecycleJson `
            -Path $invalidUtf8Path -Root $fixtureRoot -Contract ServerProcessRecord | Out-Null
    } catch {
        $invalidUtf8Rejected = $true
    }
    Add-Result 'invalid UTF-8 lifecycle bytes fail closed' $invalidUtf8Rejected `
        'the strict decoder rejected the same byte sequence before JSON conversion'

    $supervisorSource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'scripts\Invoke-NewservSupervisor.ps1')
    $stopSource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'scripts\Stop-PSOBB.ps1')
    $commonSource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
    $startupReadIndex = $supervisorSource.IndexOf(
        '-Contract ServerControlState', [System.StringComparison]::Ordinal)
    $childStartIndex = $supervisorSource.IndexOf(
        '[System.Diagnostics.Process]::Start($startInfo)',
        [System.StringComparison]::Ordinal)
    $requestReadIndex = $supervisorSource.IndexOf(
        '-Contract ServerControlRequest', [System.StringComparison]::Ordinal)
    $stdinIndex = $supervisorSource.IndexOf(
        ".StandardInput.WriteLine('exit')", [System.StringComparison]::Ordinal)
    Add-Result 'production lifecycle actions consume strict parsed objects first' (
        $startupReadIndex -ge 0 -and
        $childStartIndex -gt $startupReadIndex -and
        $requestReadIndex -gt $childStartIndex -and
        $stdinIndex -gt $requestReadIndex -and
        $supervisorSource -notmatch 'ConvertFrom-Json' -and
        $supervisorSource -match '\$startupAuthenticated\s*=\s*\$false' -and
        $supervisorSource -match '\$startupAuthenticated\s*=\s*\$true[\s\S]+\[System\.Diagnostics\.Process\]::Start' -and
        $supervisorSource -match 'if \(\$startupAuthenticated\) \{[\s\S]{0,900}Write-ProtectedJson' -and
        $stopSource -match 'Get-NewservProcess -Layout \$layout -PassThruIdentity' -and
        $commonSource -match 'Read-PSOBBStrictLifecycleJson[\s\S]{0,180}-Contract ServerProcessRecord') `
        'startup, process, ready/control, and request consumers have no selected ConvertFrom-Json path'
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) strict-lifecycle-JSON test(s) failed"
}

[pscustomobject]@{
    Suite = 'StrictLifecycleJson'
    Passed = $results.Count
    Failed = 0
}
