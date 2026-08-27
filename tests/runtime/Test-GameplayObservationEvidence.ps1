[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..'))
$verifierPath = Join-Path $repositoryRoot `
    'scripts\Get-PSOBBGameplayObservationEvidence.ps1'
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.Common.ps1')

$script:fixtureAuthority = [pscustomobject]@{
    ClientBindingSha256 = 'a' * 64
    ClientExecutableSize = 6971904L
    ClientExecutableSha256 =
        'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535'
    GameplayModulePath = 'plugins/PSOBB.Gameplay.asi'
    GameplayModuleSize = 240000L
    GameplayModuleSha256 = 'b' * 64
    GameplayConfigurationPath = 'plugins/PSOBB.Gameplay.ini'
    GameplayConfigurationSize = 38L
    GameplayConfigurationSha256 = 'c' * 64
}

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

function Set-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint32]$Value
    )

    for ($index = 0; $index -lt 4; $index++) {
        $Bytes[$Offset + $index] =
            [byte](($Value -shr ($index * 8)) -band 0xFF)
    }
}

function Set-UInt64LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint64]$Value
    )

    for ($index = 0; $index -lt 8; $index++) {
        $Bytes[$Offset + $index] =
            [byte](($Value -shr ($index * 8)) -band 0xFF)
    }
}

function Get-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset
    )

    [uint32](
        [uint64]$Bytes[$Offset] +
        ([uint64]$Bytes[$Offset + 1] * 0x100L) +
        ([uint64]$Bytes[$Offset + 2] * 0x10000L) +
        ([uint64]$Bytes[$Offset + 3] * 0x1000000L))
}

function Get-UInt64LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset
    )

    [uint64]$value = 0
    for ($index = 7; $index -ge 0; $index--) {
        $value = [uint64](($value -shl 8) -bor
            [uint64]$Bytes[$Offset + $index])
    }
    $value
}

function Set-ObservationEvent {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][uint64]$Sequence,
        [ValidateRange(1, 3)][uint32]$Kind = 3,
        [uint32]$Header = 0x43,
        [uint32]$ByteCount = 4
    )

    $offset = 256 + ($Index * 32)
    Set-UInt64LittleEndian $Bytes $offset $Sequence
    Set-UInt32LittleEndian $Bytes ($offset + 8) ([uint32](100 + $Index))
    Set-UInt32LittleEndian $Bytes ($offset + 12) $Kind
    Set-UInt32LittleEndian $Bytes ($offset + 16) 0
    Set-UInt32LittleEndian $Bytes ($offset + 24) $Header
    Set-UInt32LittleEndian $Bytes ($offset + 28) $ByteCount
}

function New-ObservationEvidenceBytes {
    param(
        [ValidateRange(0, 16384)][int]$EventCount = 3,
        [uint64]$FirstSequence = 100,
        [uint64]$RingDrops = 0,
        [uint64]$ProducerViolations = 0,
        [uint64]$EvidenceDrops = 0,
        [uint64]$TotalDrained = [uint64]::MaxValue,
        [uint32]$ProducerThreadId = 111,
        [uint32]$ConsumerThreadId = 222,
        [uint32]$ProcessId = 2147483000,
        [ValidateRange(1, 4)][uint32]$LifecycleState = 3,
        [uint32]$TerminalFailureCode = 0,
        [uint64]$CaptureStartFileTime = 133000000000000000,
        [uint64]$LastCommitFileTime = 133000003000000000,
        [uint64]$CompletionFileTime = 133000003000000000,
        [uint64]$HeartbeatCount = 300,
        [uint64]$ActiveStartTickMs = 100000,
        [uint64]$LastCommitTickMs = 400000,
        [uint64]$ProcessStartFileTime = 132999999000000000
    )

    $bytes = [byte[]]::new(524544)
    [System.Text.Encoding]::ASCII.GetBytes('PSOBBOBS').CopyTo($bytes, 0)
    Set-UInt32LittleEndian $bytes 8 256
    Set-UInt32LittleEndian $bytes 12 1
    Set-UInt32LittleEndian $bytes 16 0x01020304
    Set-UInt32LittleEndian $bytes 20 524544
    Set-UInt32LittleEndian $bytes 24 1
    Set-UInt32LittleEndian $bytes 28 32
    Set-UInt32LittleEndian $bytes 32 16384
    Set-UInt32LittleEndian $bytes 36 ([uint32]$EventCount)
    Set-UInt32LittleEndian $bytes 40 1
    Set-UInt32LittleEndian $bytes 44 32
    if ($TotalDrained -eq [uint64]::MaxValue) {
        $TotalDrained = [uint64]$EventCount + $EvidenceDrops
    }
    Set-UInt64LittleEndian $bytes 48 $TotalDrained
    Set-UInt64LittleEndian $bytes 56 $RingDrops
    Set-UInt64LittleEndian $bytes 64 $ProducerViolations
    Set-UInt64LittleEndian $bytes 72 $EvidenceDrops
    Set-UInt32LittleEndian $bytes 80 $(if ($EventCount -eq 0) {
            0
        } else {
            $ProducerThreadId
        })
    Set-UInt32LittleEndian $bytes 84 $ConsumerThreadId
    Set-UInt32LittleEndian $bytes 88 $ProcessId
    Set-UInt64LittleEndian $bytes 96 $ProcessStartFileTime
    if ($EventCount -gt 0) {
        Set-UInt64LittleEndian $bytes 104 $FirstSequence
        Set-UInt64LittleEndian $bytes 112 (
            $FirstSequence + [uint64]$EventCount - 1)
    }
    $clientSha = [Convert]::FromHexString(
        'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535')
    [System.Array]::Copy($clientSha, 0, $bytes, 120, $clientSha.Length)
    $moduleVersion = [System.Text.Encoding]::ASCII.GetBytes(
        '0.4.0-observation-evidence')
    [System.Array]::Copy(
        $moduleVersion, 0, $bytes, 152, $moduleVersion.Length)
    Set-UInt32LittleEndian $bytes 184 $LifecycleState
    Set-UInt32LittleEndian $bytes 188 $TerminalFailureCode
    Set-UInt64LittleEndian $bytes 192 $CaptureStartFileTime
    Set-UInt64LittleEndian $bytes 200 $LastCommitFileTime
    Set-UInt64LittleEndian $bytes 208 $CompletionFileTime
    Set-UInt64LittleEndian $bytes 216 $HeartbeatCount
    Set-UInt64LittleEndian $bytes 224 $ActiveStartTickMs
    Set-UInt64LittleEndian $bytes 232 $LastCommitTickMs

    for ($index = 0; $index -lt $EventCount; $index++) {
        $kind = if ($EventCount -eq 3) {
            [uint32]($index + 1)
        } else {
            [uint32]3
        }
        $header = if ($kind -eq 3) { [uint32]0x43 } else { [uint32]0 }
        $byteCount = if ($kind -eq 3) { [uint32]4 } else { [uint32]0 }
        Set-ObservationEvent -Bytes $bytes -Index $index `
            -Sequence ($FirstSequence + [uint64]$index) `
            -Kind $kind -Header $header -ByteCount $byteCount
    }
    $bytes
}

$script:runOrdinal = 0
function New-EvidenceFixture {
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [switch]$ProtectedFile,
        [switch]$UnprotectedRunDirectory,
        [string]$FileName = 'events-v1.partial'
    )

    $script:runOrdinal++
    $runId = '20260726T103200000Z-gameplay-{0:x12}' -f $script:runOrdinal
    $evidenceRoot = Join-Path $RuntimeRoot 'combat-canary\evidence'
    $categoryRoot = Join-Path $evidenceRoot 'gameplay-observation'
    $runRoot = Join-Path $categoryRoot $runId
    foreach ($directory in @($evidenceRoot, $categoryRoot)) {
        if (-not (Test-Path -LiteralPath $directory)) {
            [void][System.IO.Directory]::CreateDirectory($directory)
            Set-PSOBBProtectedAcl -Path $directory
        }
    }
    [void][System.IO.Directory]::CreateDirectory($runRoot)
    if (-not $UnprotectedRunDirectory) {
        Set-PSOBBProtectedAcl -Path $runRoot
    }
    $filePath = Join-Path $runRoot $FileName
    [System.IO.File]::WriteAllBytes($filePath, $Bytes)
    if ($ProtectedFile) {
        Set-PSOBBProtectedAcl -Path $filePath
    }
    $evidenceIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $filePath -Root $runRoot -Directory $false `
        -RoleLabel 'test Gameplay observation evidence'
    $manifest = [ordered]@{
        schemaVersion = 1
        createdAtUtc = '2026-07-26T10:32:00.0000000+00:00'
        environmentId = 'combat-canary'
        runId = $runId
        evidenceFileName = 'events-v1.partial'
        evidenceLength = 524544L
        evidenceVolumeSerialNumber = ('{0:x8}' -f
            [uint32]$evidenceIdentity.VolumeSerialNumber)
        evidenceFileId = ('{0:x16}' -f
            [uint64]$evidenceIdentity.FileId)
        clientBindingSha256 =
            [string]$script:fixtureAuthority.ClientBindingSha256
        clientExecutableSize =
            [long]$script:fixtureAuthority.ClientExecutableSize
        clientExecutableSha256 =
            [string]$script:fixtureAuthority.ClientExecutableSha256
        gameplayModulePath =
            [string]$script:fixtureAuthority.GameplayModulePath
        gameplayModuleSize =
            [long]$script:fixtureAuthority.GameplayModuleSize
        gameplayModuleSha256 =
            [string]$script:fixtureAuthority.GameplayModuleSha256
        gameplayConfigurationPath =
            [string]$script:fixtureAuthority.GameplayConfigurationPath
        gameplayConfigurationSize =
            [long]$script:fixtureAuthority.GameplayConfigurationSize
        gameplayConfigurationSha256 =
            [string]$script:fixtureAuthority.GameplayConfigurationSha256
        processId = [long](Get-UInt32LittleEndian $Bytes 88)
        processStartTimeFileTimeUtc =
            [long](Get-UInt64LittleEndian $Bytes 96)
        consumerThreadId = [long](Get-UInt32LittleEndian $Bytes 84)
    }
    $manifestPath = Join-Path $runRoot 'run-manifest-v1.json'
    $manifestText = $manifest | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText(
        $manifestPath, $manifestText,
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $manifestPath
    [pscustomobject]@{
        RunId = $runId
        RunRoot = $runRoot
        FilePath = $filePath
        ManifestPath = $manifestPath
    }
}

function Set-EvidenceFixtureManifestProperty {
    param(
        [Parameter(Mandatory)]$Fixture,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [switch]$Add
    )

    $manifest = Get-Content -Raw -LiteralPath $Fixture.ManifestPath |
        ConvertFrom-Json -DateKind String
    if ($Add) {
        $manifest | Add-Member -NotePropertyName $Name `
            -NotePropertyValue $Value
    } else {
        $property = $manifest.PSObject.Properties[$Name]
        if ($null -eq $property) {
            throw "The test manifest property '$Name' does not exist"
        }
        $property.Value = $Value
    }
    [System.IO.File]::WriteAllText(
        $Fixture.ManifestPath, ($manifest | ConvertTo-Json -Depth 4),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $Fixture.ManifestPath
}

function Invoke-EvidenceVerifier {
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$RunId
    )

    & $verifierPath -RunId $RunId -InternalTestRuntimeRoot $RuntimeRoot `
        -InternalTestAuthority $script:fixtureAuthority
}

function Test-EvidenceRejected {
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Pattern
    )

    $script:lastEvidenceRejection = ''
    try {
        Invoke-EvidenceVerifier -RuntimeRoot $RuntimeRoot -RunId $RunId |
            Out-Null
        $false
    } catch {
        $script:lastEvidenceRejection = $_.Exception.Message
        $_.Exception.Message -match $Pattern
    }
}

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $verifierPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
Add-Result -Name 'observation evidence verifier parses cleanly' `
    -Passed ($parseErrors.Count -eq 0) `
    -Detail "$($parseErrors.Count) parser error(s)"

$source = Get-Content -Raw -LiteralPath $verifierPath
Add-Result -Name 'verifier remains read-only and summary-only' `
    -Passed (
        $source -notmatch '\b(?:Remove|Rename|Move|Set|Write|New)-Item\b' -and
        $source -notmatch 'Set-PSOBBProtectedAcl' -and
        $source -match 'Invoke-PSOBBCombatCanaryBoundedFileSnapshot' -and
        $source -match 'Assert-PSOBBGlobalStoppedRuntime') `
    -Detail 'no evidence rename, seal, delete, write, or ACL mutation surface'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-gameplay-observation-' + [Guid]::NewGuid().ToString('N'))
try {
    [void][System.IO.Directory]::CreateDirectory($temporaryRoot)
    $layout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    Initialize-PSOBBRuntimeMarker -Layout $layout | Out-Null
    [void](Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
            -Operation 'Gameplay observation evidence fixture tests')

    $validFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes)
    $validResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $validFixture.RunId
    $expectedHash = (Get-FileHash -LiteralPath $validFixture.FilePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedManifestHash = (Get-FileHash `
            -LiteralPath $validFixture.ManifestPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedProperties = @(
        'Accepted', 'ActionStateEvents', 'ConsumerThreadId', 'EventCount',
        'EvidenceCapacityDroppedEventCount', 'FileLength', 'FileSha256',
        'FirstSequence', 'LastSequence', 'ModuleVersion', 'ProcessId',
        'ProcessStartFileTime', 'ProducerThreadId', 'ProcessStopped',
        'ProducerViolationCount', 'RingDroppedEventCount', 'RunId',
        'Send60Events', 'TickEvents', 'TotalDrainedEventCount', 'Valid',
        'LifecycleState', 'TerminalFailureCode', 'CaptureStartFileTime',
        'LastCommitFileTime', 'CompletionFileTime', 'HeartbeatCount',
        'ActiveStartTickMs', 'LastCommitTickMs',
        'ActiveDurationMilliseconds', 'CaptureDurationFileTimeTicks',
        'ManifestPath', 'ManifestSha256')
    Add-Result -Name 'valid fixed evidence is accepted with a closed summary' `
        -Passed (
            [bool]$validResult.Valid -and [bool]$validResult.Accepted -and
            [uint32]$validResult.EventCount -eq 3 -and
            [uint32]$validResult.TickEvents -eq 1 -and
            [uint32]$validResult.ActionStateEvents -eq 1 -and
            [uint32]$validResult.Send60Events -eq 1 -and
            [string]$validResult.FileSha256 -ceq $expectedHash -and
            [string]$validResult.ManifestPath -ceq
                [string]$validFixture.ManifestPath -and
            [string]$validResult.ManifestSha256 -ceq
                $expectedManifestHash -and
            [string]$validResult.ModuleVersion -ceq
                '0.4.0-observation-evidence' -and
            [uint32]$validResult.LifecycleState -eq 3 -and
            [uint64]$validResult.HeartbeatCount -eq 300 -and
            [uint64]$validResult.ActiveStartTickMs -eq 100000 -and
            [uint64]$validResult.LastCommitTickMs -eq 400000 -and
            [uint64]$validResult.ActiveDurationMilliseconds -eq 300000 -and
            [bool]$validResult.ProcessStopped -and
            @(Compare-Object -ReferenceObject ($expectedProperties | Sort-Object) `
                    -DifferenceObject @(
                        $validResult.PSObject.Properties.Name | Sort-Object)
                ).Count -eq 0) `
        -Detail 'three kinds plus evidence and protected-manifest SHA-256 summaries'

    $missingManifestFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot -Bytes (New-ObservationEvidenceBytes)
    [System.IO.File]::Delete($missingManifestFixture.ManifestPath)
    Add-Result -Name 'missing run manifest fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $missingManifestFixture.RunId `
            -Pattern 'run manifest path is invalid') `
        -Detail 'evidence is never accepted without its protected launch binding'

    $extraPropertyFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot -Bytes (New-ObservationEvidenceBytes)
    Set-EvidenceFixtureManifestProperty -Fixture $extraPropertyFixture `
        -Name 'unexpected' -Value 'rejected' -Add
    Add-Result -Name 'an extra manifest property fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $extraPropertyFixture.RunId `
            -Pattern 'exact property set') `
        -Detail 'the versioned manifest contract is closed to unknown properties'

    $manifestBindingCases = @(
        [pscustomobject]@{
            Name = 'wrong run ID'; Property = 'runId'
            Value = '20260726T103200000Z-gameplay-ffffffffffff'
            Pattern = 'manifest scope is invalid'
        },
        [pscustomobject]@{
            Name = 'wrong evidence file ID'; Property = 'evidenceFileId'
            Value = 'ffffffffffffffff'
            Pattern = 'manifest binding is invalid'
        },
        [pscustomobject]@{
            Name = 'wrong process ID'; Property = 'processId'
            Value = 2147482999L
            Pattern = 'manifest binding is invalid'
        },
        [pscustomobject]@{
            Name = 'wrong client binding'; Property = 'clientBindingSha256'
            Value = ('d' * 64)
            Pattern = 'manifest binding is invalid'
        },
        [pscustomobject]@{
            Name = 'wrong Gameplay module identity'
            Property = 'gameplayModuleSha256'; Value = ('d' * 64)
            Pattern = 'manifest binding is invalid'
        },
        [pscustomobject]@{
            Name = 'wrong Gameplay configuration identity'
            Property = 'gameplayConfigurationSha256'; Value = ('d' * 64)
            Pattern = 'manifest binding is invalid'
        }
    )
    foreach ($case in $manifestBindingCases) {
        $fixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
            -Bytes (New-ObservationEvidenceBytes)
        Set-EvidenceFixtureManifestProperty -Fixture $fixture `
            -Name $case.Property -Value $case.Value
        $rejected = Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $fixture.RunId -Pattern $case.Pattern
        Add-Result -Name "$($case.Name) in the manifest fails closed" `
            -Passed $rejected `
            -Detail "$($case.Pattern); $script:lastEvidenceRejection"
    }

    $unprotectedManifestFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot -Bytes (New-ObservationEvidenceBytes)
    $unprotectedManifestText = [System.IO.File]::ReadAllText(
        $unprotectedManifestFixture.ManifestPath)
    [System.IO.File]::Delete($unprotectedManifestFixture.ManifestPath)
    [System.IO.File]::WriteAllText(
        $unprotectedManifestFixture.ManifestPath,
        $unprotectedManifestText,
        [System.Text.UTF8Encoding]::new($false))
    Add-Result -Name 'an unprotected run manifest fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $unprotectedManifestFixture.RunId `
            -Pattern 'does not have its protected file ACL') `
        -Detail 'the manifest must have its own exact protected allowlist'

    $linkedManifestFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot -Bytes (New-ObservationEvidenceBytes)
    [void](New-Item -ItemType HardLink `
            -Path (Join-Path $linkedManifestFixture.RunRoot 'manifest-link.json') `
            -Target $linkedManifestFixture.ManifestPath)
    Add-Result -Name 'a multiply linked run manifest fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $linkedManifestFixture.RunId `
            -Pattern 'handle identity is not one contained ordinary path') `
        -Detail 'manifest authority is bound to one ordinary file identity'

    $caseManifestFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot -Bytes (New-ObservationEvidenceBytes)
    $manifestCaseStage = Join-Path $caseManifestFixture.RunRoot `
        '.manifest-case-stage.json'
    $manifestCasePath = Join-Path $caseManifestFixture.RunRoot `
        'Run-manifest-v1.json'
    [System.IO.File]::Move(
        $caseManifestFixture.ManifestPath, $manifestCaseStage)
    [System.IO.File]::Move($manifestCaseStage, $manifestCasePath)
    Add-Result -Name 'a case-variant run manifest name fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $caseManifestFixture.RunId `
            -Pattern 'run manifest path is invalid') `
        -Detail 'the manifest leaf name is case-exact'

    $shortCompletedFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 `
            -LastCommitTickMs 399999)
    $shortCompletedResult = Invoke-EvidenceVerifier `
        -RuntimeRoot $temporaryRoot -RunId $shortCompletedFixture.RunId
    Add-Result -Name 'wall-clock duration cannot replace monotonic duration' `
        -Passed (
            [bool]$shortCompletedResult.Valid -and
            -not [bool]$shortCompletedResult.Accepted -and
            [uint32]$shortCompletedResult.LifecycleState -eq 3 -and
            [uint64]$shortCompletedResult.CaptureDurationFileTimeTicks -eq
                3000000000 -and
            [uint64]$shortCompletedResult.ActiveDurationMilliseconds -eq
                299999) `
        -Detail 'a wall-clock jump cannot satisfy five minutes of active liveness'

    $emptyFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 0)
    $emptyResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $emptyFixture.RunId
    Add-Result -Name 'zero events are structurally valid but not accepted' `
        -Passed (
            [bool]$emptyResult.Valid -and -not [bool]$emptyResult.Accepted -and
            [uint32]$emptyResult.EventCount -eq 0 -and
            [uint64]$emptyResult.FirstSequence -eq 0 -and
            [uint64]$emptyResult.LastSequence -eq 0) `
        -Detail 'an empty observation run cannot satisfy live acceptance'

    [byte[]]$tailBytes = New-ObservationEvidenceBytes -EventCount 1
    Set-UInt32LittleEndian $tailBytes (256 + 32 + 12) 99
    $tailFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes $tailBytes
    $tailResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $tailFixture.RunId
    Add-Result -Name 'only the committed payload prefix is parsed' `
        -Passed (
            [bool]$tailResult.Valid -and [bool]$tailResult.Accepted -and
            [uint32]$tailResult.EventCount -eq 1) `
        -Detail 'stale bytes after the committed boundary are not evidence'

    $ringDropFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 -RingDrops 1)
    $ringDropResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $ringDropFixture.RunId
    Add-Result -Name 'ring drops remain valid evidence but reject acceptance' `
        -Passed (
            [bool]$ringDropResult.Valid -and
            -not [bool]$ringDropResult.Accepted -and
            [uint64]$ringDropResult.RingDroppedEventCount -eq 1) `
        -Detail 'acceptance requires a lossless observation ring'

    $violationFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes `
            -EventCount 1 -ProducerViolations 1)
    $violationResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $violationFixture.RunId
    Add-Result -Name 'producer violations reject acceptance' `
        -Passed (
            [bool]$violationResult.Valid -and
            -not [bool]$violationResult.Accepted -and
            [uint64]$violationResult.ProducerViolationCount -eq 1) `
        -Detail 'single-producer violations remain visible in the summary'

    $capacityFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 16384 `
            -EvidenceDrops 1 -TotalDrained 16385)
    $capacityResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $capacityFixture.RunId
    Add-Result -Name 'evidence-capacity drops reject acceptance' `
        -Passed (
            [bool]$capacityResult.Valid -and
            -not [bool]$capacityResult.Accepted -and
            [uint32]$capacityResult.EventCount -eq 16384 -and
            [uint64]$capacityResult.EvidenceCapacityDroppedEventCount -eq 1) `
        -Detail 'a structurally exact full evidence file may report bounded loss'

    $activeFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 `
            -LifecycleState 2 -CompletionFileTime 0)
    $activeResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $activeFixture.RunId
    Add-Result -Name 'active-at-exit evidence is never accepted' `
        -Passed (
            [bool]$activeResult.Valid -and
            -not [bool]$activeResult.Accepted -and
            [uint32]$activeResult.LifecycleState -eq 2 -and
            [uint64]$activeResult.ActiveDurationMilliseconds -eq 300000 -and
            [uint64]$activeResult.HeartbeatCount -eq 300) `
        -Detail 'only an explicit completed lifecycle can pass acceptance'

    $heartbeatFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 `
            -HeartbeatCount 299)
    $heartbeatResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $heartbeatFixture.RunId
    Add-Result -Name 'insufficient completed heartbeats reject acceptance' `
        -Passed (
            [bool]$heartbeatResult.Valid -and
            -not [bool]$heartbeatResult.Accepted -and
            [uint64]$heartbeatResult.ActiveDurationMilliseconds -eq
                300000 -and
            [uint64]$heartbeatResult.HeartbeatCount -eq 299) `
        -Detail 'acceptance requires at least 300 committed heartbeats'

    $readyFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 0 `
            -LifecycleState 1 -CompletionFileTime 0 -HeartbeatCount 0 `
            -LastCommitFileTime 133000000000000000 `
            -ActiveStartTickMs 0 -LastCommitTickMs 0)
    $readyResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $readyFixture.RunId
    Add-Result -Name 'ready lifecycle evidence is valid but not accepted' `
        -Passed (
            [bool]$readyResult.Valid -and
            -not [bool]$readyResult.Accepted -and
            [uint32]$readyResult.LifecycleState -eq 1) `
        -Detail 'launcher readiness alone is not a completed live checkpoint'

    $failedFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 `
            -LifecycleState 4 -TerminalFailureCode 7)
    $failedResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $failedFixture.RunId
    Add-Result -Name 'terminal failure evidence remains valid but not accepted' `
        -Passed (
            [bool]$failedResult.Valid -and
            -not [bool]$failedResult.Accepted -and
            [uint32]$failedResult.TerminalFailureCode -eq 7) `
        -Detail 'bounded failure metadata remains inspectable without promotion'

    $currentProcess = Get-Process -Id $PID
    $currentProcessStartFileTime =
        [uint64]$currentProcess.StartTime.ToFileTimeUtc()
    $liveProcessFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 `
            -ProcessId ([uint32]$PID) `
            -ProcessStartFileTime $currentProcessStartFileTime)
    $liveProcessResult = Invoke-EvidenceVerifier -RuntimeRoot $temporaryRoot `
        -RunId $liveProcessFixture.RunId
    Add-Result -Name 'a still-live exact process identity is not accepted' `
        -Passed (
            [bool]$liveProcessResult.Valid -and
            -not [bool]$liveProcessResult.Accepted -and
            -not [bool]$liveProcessResult.ProcessStopped) `
        -Detail 'post-run evidence acceptance requires the recorded process to be gone'

    $uninspectablePidFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes -EventCount 1 `
            -ProcessId 4000000000)
    $uninspectablePidResult = Invoke-EvidenceVerifier `
        -RuntimeRoot $temporaryRoot -RunId $uninspectablePidFixture.RunId
    Add-Result -Name 'an uninspectable process ID cannot be accepted as stopped' `
        -Passed (
            [bool]$uninspectablePidResult.Valid -and
            -not [bool]$uninspectablePidResult.Accepted -and
            -not [bool]$uninspectablePidResult.ProcessStopped) `
        -Detail 'stopped-process acceptance fails closed outside the inspectable PID range'

    $malformedCases = @(
        [pscustomobject]@{
            Name = 'wrong magic'
            Pattern = 'header contract'
            Type = 'Byte'; Offset = 0; Value = [uint64][byte][char]'X'
        },
        [pscustomobject]@{
            Name = 'wrong module identity'
            Pattern = 'module identity'
            Type = 'Byte'; Offset = 152; Value = [uint64][byte][char]'9'
        },
        [pscustomobject]@{
            Name = 'nonzero reserved-tail byte'
            Pattern = 'reserved bytes'
            Type = 'Byte'; Offset = 255; Value = [uint64]1
        },
        [pscustomobject]@{
            Name = 'wrong exact-client hash'
            Pattern = 'header contract'
            Type = 'Byte'; Offset = 120; Value = [uint64]0
        },
        [pscustomobject]@{
            Name = 'sequence gap'
            Pattern = 'sequence is not contiguous'
            Type = 'UInt64'; Offset = (256 + 32); Value = [uint64]500
        },
        [pscustomobject]@{
            Name = 'header sequence mismatch'
            Pattern = 'sequence bounds are invalid'
            Type = 'UInt64'; Offset = 112; Value = [uint64]999
        },
        [pscustomobject]@{
            Name = 'unsupported event kind'
            Pattern = 'unsupported event kind'
            Type = 'UInt32'; Offset = (256 + 12); Value = [uint64]4
        },
        [pscustomobject]@{
            Name = 'invalid send60 header'
            Pattern = 'invalid send60 event'
            Type = 'UInt32'; Offset = (256 + (2 * 32) + 24)
            Value = [uint64]0x42
        },
        [pscustomobject]@{
            Name = 'short send60 byte count'
            Pattern = 'invalid send60 event'
            Type = 'UInt32'; Offset = (256 + (2 * 32) + 28)
            Value = [uint64]3
        },
        [pscustomobject]@{
            Name = 'inconsistent counters'
            Pattern = 'counters are inconsistent'
            Type = 'UInt64'; Offset = 48; Value = [uint64]4
        },
        [pscustomobject]@{
            Name = 'zero producer with events'
            Pattern = 'identity or sequence bounds'
            Type = 'UInt32'; Offset = 80; Value = [uint64]0
        },
        [pscustomobject]@{
            Name = 'producer equals consumer'
            Pattern = 'identity or sequence bounds'
            Type = 'UInt32'; Offset = 80; Value = [uint64]222
        },
        [pscustomobject]@{
            Name = 'zero process identity'
            Pattern = 'process identity is incomplete'
            Type = 'UInt32'; Offset = 88; Value = [uint64]0
        },
        [pscustomobject]@{
            Name = 'unknown lifecycle state'
            Pattern = 'lifecycle timestamps are invalid'
            Type = 'UInt32'; Offset = 184; Value = [uint64]5
        },
        [pscustomobject]@{
            Name = 'invalid monotonic tick ordering'
            Pattern = 'lifecycle monotonic ticks are invalid'
            Type = 'UInt64'; Offset = 232; Value = [uint64]99999
        },
        [pscustomobject]@{
            Name = 'completed lifecycle with failure code'
            Pattern = 'completed observation evidence lifecycle is invalid'
            Type = 'UInt32'; Offset = 188; Value = [uint64]9
        },
        [pscustomobject]@{
            Name = 'completion before last commit'
            Pattern = 'completed observation evidence lifecycle is invalid'
            Type = 'UInt64'; Offset = 208; Value = [uint64]133000002999999999
        }
    )
    foreach ($case in $malformedCases) {
        [byte[]]$bytes = New-ObservationEvidenceBytes
        switch -CaseSensitive ([string]$case.Type) {
            'Byte' {
                $bytes[[int]$case.Offset] = [byte]$case.Value
            }
            'UInt32' {
                Set-UInt32LittleEndian $bytes ([int]$case.Offset) `
                    ([uint32]$case.Value)
            }
            'UInt64' {
                Set-UInt64LittleEndian $bytes ([int]$case.Offset) `
                    ([uint64]$case.Value)
            }
            default { throw 'Unknown evidence mutation type' }
        }
        $fixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
            -Bytes $bytes
        if ([string]$case.Name -ceq 'zero process identity') {
            Set-EvidenceFixtureManifestProperty -Fixture $fixture `
                -Name 'processId' -Value 2147483000L
        }
        $rejected = Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $fixture.RunId -Pattern $case.Pattern
        Add-Result -Name "malformed $($case.Name) fails closed" `
            -Passed $rejected `
            -Detail "$($case.Pattern); $script:lastEvidenceRejection"
    }

    [byte[]]$truncated = New-ObservationEvidenceBytes
    [Array]::Resize([ref]$truncated, 524543)
    $truncatedFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes $truncated
    Add-Result -Name 'truncated fixed file fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $truncatedFixture.RunId -Pattern 'invalid bounded size') `
        -Detail '524543 bytes is not the exact preallocated format size'

    $protectedFileFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes) -ProtectedFile
    Add-Result -Name 'a file with a directly protected DACL fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $protectedFileFixture.RunId -Pattern 'file ACL is invalid') `
        -Detail 'the native file must inherit only the verified run-directory allowlist'

    $unprotectedRunFixture = New-EvidenceFixture `
        -RuntimeRoot $temporaryRoot -Bytes (New-ObservationEvidenceBytes) `
        -UnprotectedRunDirectory
    Add-Result -Name 'an unprotected run directory fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $unprotectedRunFixture.RunId `
            -Pattern 'directory ACL is invalid') `
        -Detail 'category and run boundaries must retain exact protected ACLs'

    $wrongNameFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes) -FileName 'events-v1.bin'
    Add-Result -Name 'a lookalike filename is not evidence' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $wrongNameFixture.RunId -Pattern 'cannot find|does not exist') `
        -Detail 'only events-v1.partial at the exact derived path is read'

    $wrongCaseFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes) -FileName 'Events-v1.partial'
    Add-Result -Name 'a case-variant evidence filename fails closed' `
        -Passed (Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
            -RunId $wrongCaseFixture.RunId -Pattern 'file ACL is invalid') `
        -Detail 'the on-disk leaf name must match the native contract exactly'

    $linkedFixture = New-EvidenceFixture -RuntimeRoot $temporaryRoot `
        -Bytes (New-ObservationEvidenceBytes)
    $linkedPath = Join-Path $linkedFixture.RunRoot 'second-link.partial'
    [void](New-Item -ItemType HardLink -Path $linkedPath `
            -Target $linkedFixture.FilePath)
    $linkedRejected = Test-EvidenceRejected -RuntimeRoot $temporaryRoot `
        -RunId $linkedFixture.RunId `
        -Pattern 'handle identity is not one contained ordinary path'
    Add-Result -Name 'a multiply linked evidence file fails closed' `
        -Passed $linkedRejected `
        -Detail "native file identity requires a single link; $script:lastEvidenceRejection"

    $alternateRejected = $false
    try {
        & $verifierPath -RunId $validFixture.RunId `
            -RuntimeRoot $temporaryRoot | Out-Null
    } catch {
        $alternateRejected = $_.Exception.Message -match 'only the canonical'
    }
    Add-Result -Name 'the public runtime parameter rejects alternate roots' `
        -Passed $alternateRejected `
        -Detail 'only the hidden bounded temp fixture seam accepts a test root'

    $invalidRunRejected = $false
    try {
        & $verifierPath `
            -RunId '20260726T103200000Z-gameplay-ABCDEF123456' `
            -InternalTestRuntimeRoot $temporaryRoot | Out-Null
    } catch {
        $invalidRunRejected = $_.Exception.Message -match 'run ID is invalid'
    }
    Add-Result -Name 'run IDs require exact lowercase hexadecimal' `
        -Passed $invalidRunRejected `
        -Detail 'case-insensitive parameter binding cannot widen the path grammar'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $safeTemporaryRoot = Assert-PathWithinRoot `
            -Path $temporaryRoot -Root ([System.IO.Path]::GetTempPath())
        if ((Split-Path -Leaf $safeTemporaryRoot) -cnotmatch
            '^psobb-gameplay-observation-[a-f0-9]{32}$') {
            throw 'Refusing to remove an unexpected observation fixture root'
        }
        Remove-Item -LiteralPath $safeTemporaryRoot -Recurse -Force
    }
}

$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    $failureDetail = @($failed | ForEach-Object {
            "$($_.Name): $($_.Detail)"
        }) -join ' | '
    throw ("$($failed.Count) gameplay observation evidence test(s) " +
        "failed: $failureDetail")
}

[pscustomobject]@{
    Suite = 'GameplayObservationEvidence'
    Passed = $results.Count
    Failed = 0
}
