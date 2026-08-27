[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}$')]
    [string]$RunId,

    [string]$RuntimeRoot,

    [Parameter(DontShow = $true)]
    [string]$InternalTestRuntimeRoot,

    [Parameter(DontShow = $true)]
    [pscustomobject]$InternalTestAuthority
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

$script:RepositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..')).TrimEnd('\')
$script:CanonicalRuntimeRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $script:RepositoryRoot 'PSOBB-Runtime')).TrimEnd('\')
$script:EvidenceFileSize = 524544L
$script:EvidenceHeaderSize = 256
$script:EvidenceRecordSize = 32
$script:EvidenceCapacity = 16384
$script:ExactClientSha256 =
    'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535'
$script:ExactModuleVersion = '0.4.0-observation-evidence'
$script:MinimumActiveDurationMilliseconds = 300000UL
$script:MinimumHeartbeatCount = 300UL
$script:RuntimeRootWasProvided = $PSBoundParameters.ContainsKey('RuntimeRoot')
$script:InternalAuthorityWasProvided =
    $PSBoundParameters.ContainsKey('InternalTestAuthority')
$script:ManifestProperties = @(
    'schemaVersion', 'createdAtUtc', 'environmentId', 'runId',
    'evidenceFileName', 'evidenceLength',
    'evidenceVolumeSerialNumber', 'evidenceFileId',
    'clientBindingSha256', 'clientExecutableSize',
    'clientExecutableSha256', 'gameplayModulePath', 'gameplayModuleSize',
    'gameplayModuleSha256', 'gameplayConfigurationPath',
    'gameplayConfigurationSize', 'gameplayConfigurationSha256',
    'processId', 'processStartTimeFileTimeUtc', 'consumerThreadId')

function Read-PSOBBObservationUInt32LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)]
        [int]$Offset
    )

    if ($Offset -gt ($Bytes.Length - 4)) {
        throw 'The observation evidence contains a truncated 32-bit field'
    }
    [uint32](
        [uint64]$Bytes[$Offset] +
        ([uint64]$Bytes[$Offset + 1] * 0x100L) +
        ([uint64]$Bytes[$Offset + 2] * 0x10000L) +
        ([uint64]$Bytes[$Offset + 3] * 0x1000000L))
}

function Read-PSOBBObservationUInt64LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)]
        [int]$Offset
    )

    if ($Offset -gt ($Bytes.Length - 8)) {
        throw 'The observation evidence contains a truncated 64-bit field'
    }
    [uint64]$value = 0
    for ($index = 7; $index -ge 0; $index--) {
        $value = [uint64](($value -shl 8) -bor
            [uint64]$Bytes[$Offset + $index])
    }
    $value
}

function Test-PSOBBObservationZeroRange {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$Count
    )

    for ($index = 0; $index -lt $Count; $index++) {
        if ($Bytes[$Offset + $index] -ne 0) {
            return $false
        }
    }
    $true
}

function Test-PSOBBObservationEvidenceFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RunRoot
    )

    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    $exactLeaf = @(Get-ChildItem -Force -LiteralPath $RunRoot |
        Where-Object { $_.Name -ceq 'events-v1.partial' })
    if ($exactLeaf.Count -ne 1 -or $exactLeaf[0].PSIsContainer -or
        $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }
    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$allowed.Add(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    [void]$allowed.Add('S-1-5-32-544')
    [void]$allowed.Add('S-1-5-18')
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules(
            $true, $true,
            [System.Security.Principal.SecurityIdentifier]))
    if ($acl.AreAccessRulesProtected -or $rules.Count -ne $allowed.Count) {
        return $false
    }
    $found = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            -not $rule.IsInherited -or
            -not $allowed.Contains($rule.IdentityReference.Value) -or
            $rule.FileSystemRights -ne
                [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None) {
            return $false
        }
        [void]$found.Add($rule.IdentityReference.Value)
    }
    $found.SetEquals($allowed)
}

function Test-PSOBBObservationProcessIdentityStopped {
    param(
        [Parameter(Mandatory)][uint32]$ProcessId,
        [Parameter(Mandatory)][uint64]$ProcessStartFileTime
    )

    if ($ProcessId -gt [int]::MaxValue) {
        return $false
    }
    $process = Get-Process -Id ([int]$ProcessId) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $true
    }
    try {
        [uint64]$liveStart = [uint64]$process.StartTime.ToFileTimeUtc()
        $liveStart -ne $ProcessStartFileTime
    } catch {
        $false
    }
}

function Test-PSOBBObservationExactLeafName {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$DirectoryExpected
    )

    $matches = @(Get-ChildItem -Force -LiteralPath $Directory |
        Where-Object { $_.Name -ceq $Name })
    $matches.Count -eq 1 -and
        [bool]$matches[0].PSIsContainer -eq $DirectoryExpected
}

function ConvertFrom-PSOBBObservationManifestBytes {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$ExpectedRunId
    )

    $document = $null
    try {
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($Bytes)
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling =
            [System.Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 4
        $document = [System.Text.Json.JsonDocument]::Parse($text, $options)
        Test-PSOBBStrictJsonPropertyUniqueness `
            -Element $document.RootElement -Path '$' | Out-Null
        $value = ConvertFrom-PSOBBStrictDataJsonElement `
            -Element $document.RootElement `
            -Label 'Gameplay observation run manifest'
        [void](Assert-PSOBBStrictDataObjectProperties `
                -Value $value -Expected $script:ManifestProperties `
                -Label 'Gameplay observation run manifest')

        foreach ($property in @(
                'schemaVersion', 'evidenceLength', 'clientExecutableSize',
                'gameplayModuleSize', 'gameplayConfigurationSize',
                'processId', 'processStartTimeFileTimeUtc',
                'consumerThreadId')) {
            if ($value.$property -isnot [long]) {
                throw "The Gameplay observation run manifest $property type is invalid"
            }
        }
        foreach ($property in @(
                'createdAtUtc', 'environmentId', 'runId',
                'evidenceFileName', 'evidenceVolumeSerialNumber',
                'evidenceFileId', 'clientBindingSha256',
                'clientExecutableSha256', 'gameplayModulePath',
                'gameplayModuleSha256', 'gameplayConfigurationPath',
                'gameplayConfigurationSha256')) {
            if ($value.$property -isnot [string]) {
                throw "The Gameplay observation run manifest $property type is invalid"
            }
        }
        [DateTimeOffset]$createdAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                [string]$value.createdAtUtc, [ref]$createdAt) -or
            $createdAt.ToString('o') -cne [string]$value.createdAtUtc) {
            throw 'The Gameplay observation run manifest creation time is invalid'
        }
        if ([long]$value.schemaVersion -ne 1 -or
            [string]$value.environmentId -cne 'combat-canary' -or
            [string]$value.runId -cne $ExpectedRunId -or
            [string]$value.evidenceFileName -cne 'events-v1.partial' -or
            [long]$value.evidenceLength -ne $script:EvidenceFileSize) {
            throw 'The Gameplay observation run manifest scope is invalid'
        }
        if ([string]$value.evidenceVolumeSerialNumber -cnotmatch
                '^[a-f0-9]{8}$' -or
            [string]$value.evidenceFileId -cnotmatch '^[a-f0-9]{16}$') {
            throw 'The Gameplay observation run manifest evidence identity is invalid'
        }
        if ([string]$value.clientBindingSha256 -cnotmatch
                '^[a-f0-9]{64}$' -or
            [long]$value.clientExecutableSize -ne 6971904 -or
            [string]$value.clientExecutableSha256 -cne
                $script:ExactClientSha256) {
            throw 'The Gameplay observation run manifest client identity is invalid'
        }
        if ([string]$value.gameplayModulePath -cne
                'plugins/PSOBB.Gameplay.asi' -or
            [long]$value.gameplayModuleSize -lt 1 -or
            [long]$value.gameplayModuleSize -gt 4MB -or
            [string]$value.gameplayModuleSha256 -cnotmatch
                '^[a-f0-9]{64}$') {
            throw 'The Gameplay observation run manifest module identity is invalid'
        }
        if ([string]$value.gameplayConfigurationPath -cne
                'plugins/PSOBB.Gameplay.ini' -or
            [long]$value.gameplayConfigurationSize -lt 1 -or
            [long]$value.gameplayConfigurationSize -gt 4KB -or
            [string]$value.gameplayConfigurationSha256 -cnotmatch
                '^[a-f0-9]{64}$') {
            throw 'The Gameplay observation run manifest configuration identity is invalid'
        }
        if ([long]$value.processId -lt 1 -or
            [long]$value.processId -gt [uint32]::MaxValue -or
            [long]$value.processStartTimeFileTimeUtc -lt 1 -or
            [long]$value.consumerThreadId -lt 1 -or
            [long]$value.consumerThreadId -gt [uint32]::MaxValue) {
            throw 'The Gameplay observation run manifest process identity is invalid'
        }
        $value
    } catch {
        throw ('The Gameplay observation run manifest is not exact strict ' +
            "JSON: $($_.Exception.Message)")
    } finally {
        if ($document) { $document.Dispose() }
    }
}

function ConvertTo-PSOBBObservationManifestAuthority {
    param([Parameter(Mandatory)]$Value)

    $properties = @(
        'ClientBindingSha256', 'ClientExecutableSize',
        'ClientExecutableSha256', 'GameplayModulePath',
        'GameplayModuleSize', 'GameplayModuleSha256',
        'GameplayConfigurationPath', 'GameplayConfigurationSize',
        'GameplayConfigurationSha256')
    [void](Assert-PSOBBStrictDataObjectProperties `
            -Value $Value -Expected $properties `
            -Label 'Gameplay observation manifest authority')
    if ($Value.ClientBindingSha256 -isnot [string] -or
        [string]$Value.ClientBindingSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Value.ClientExecutableSize -isnot [long] -or
        [long]$Value.ClientExecutableSize -ne 6971904 -or
        $Value.ClientExecutableSha256 -isnot [string] -or
        [string]$Value.ClientExecutableSha256 -cne
            $script:ExactClientSha256 -or
        $Value.GameplayModulePath -isnot [string] -or
        [string]$Value.GameplayModulePath -cne
            'plugins/PSOBB.Gameplay.asi' -or
        $Value.GameplayModuleSize -isnot [long] -or
        [long]$Value.GameplayModuleSize -lt 1 -or
        [long]$Value.GameplayModuleSize -gt 4MB -or
        $Value.GameplayModuleSha256 -isnot [string] -or
        [string]$Value.GameplayModuleSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Value.GameplayConfigurationPath -isnot [string] -or
        [string]$Value.GameplayConfigurationPath -cne
            'plugins/PSOBB.Gameplay.ini' -or
        $Value.GameplayConfigurationSize -isnot [long] -or
        [long]$Value.GameplayConfigurationSize -lt 1 -or
        [long]$Value.GameplayConfigurationSize -gt 4KB -or
        $Value.GameplayConfigurationSha256 -isnot [string] -or
        [string]$Value.GameplayConfigurationSha256 -cnotmatch
            '^[a-f0-9]{64}$') {
        throw 'The Gameplay observation manifest authority is invalid'
    }
    [pscustomobject]@{
        ClientBindingSha256 = [string]$Value.ClientBindingSha256
        ClientExecutableSize = [long]$Value.ClientExecutableSize
        ClientExecutableSha256 = [string]$Value.ClientExecutableSha256
        GameplayModulePath = [string]$Value.GameplayModulePath
        GameplayModuleSize = [long]$Value.GameplayModuleSize
        GameplayModuleSha256 = [string]$Value.GameplayModuleSha256
        GameplayConfigurationPath =
            [string]$Value.GameplayConfigurationPath
        GameplayConfigurationSize =
            [long]$Value.GameplayConfigurationSize
        GameplayConfigurationSha256 =
            [string]$Value.GameplayConfigurationSha256
    }
}

function Get-PSOBBObservationManifestAuthority {
    param([Parameter(Mandatory)]$Layout)

    if (-not [string]::IsNullOrWhiteSpace($InternalTestRuntimeRoot)) {
        return ConvertTo-PSOBBObservationManifestAuthority `
            -Value $InternalTestAuthority
    }

    $contract = Get-PSOBBCombatCanaryClientLaunchContract -Layout $Layout
    if ([long]$contract.Binding.schemaVersion -ne 2 -or
        [string]$contract.Verification.ClientBindingSha256 -cnotmatch
            '^[a-f0-9]{64}$') {
        throw 'The installed Gameplay observation client contract is inactive'
    }
    $moduleEntries = @($contract.GameplayOverlayEntries | Where-Object {
            [string]$_.path -ceq 'plugins/PSOBB.Gameplay.asi'
        })
    $configurationEntries = @(
        $contract.GameplayOverlayEntries | Where-Object {
            [string]$_.path -ceq 'plugins/PSOBB.Gameplay.ini'
        })
    $approvedClient = Get-PSOBBCombatCanaryApprovedClientIdentity `
        -RepositoryRoot $script:RepositoryRoot
    if ($moduleEntries.Count -ne 1 -or
        $configurationEntries.Count -ne 1 -or
        [long]$contract.Binding.clientExecutableSize -ne
            [long]$approvedClient.Size -or
        [string]$contract.Binding.clientExecutableSha256 -cne
            [string]$approvedClient.Sha256) {
        throw 'The installed Gameplay observation authority is inconsistent'
    }
    ConvertTo-PSOBBObservationManifestAuthority -Value ([pscustomobject]@{
            ClientBindingSha256 =
                [string]$contract.Verification.ClientBindingSha256
            ClientExecutableSize = [long]$approvedClient.Size
            ClientExecutableSha256 = [string]$approvedClient.Sha256
            GameplayModulePath = [string]$moduleEntries[0].path
            GameplayModuleSize = [long]$moduleEntries[0].size
            GameplayModuleSha256 = [string]$moduleEntries[0].sha256
            GameplayConfigurationPath =
                [string]$configurationEntries[0].path
            GameplayConfigurationSize =
                [long]$configurationEntries[0].size
            GameplayConfigurationSha256 =
                [string]$configurationEntries[0].sha256
        })
}

function Assert-PSOBBObservationManifestBinding {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$Evidence
    )

    if ([string]$Manifest.evidenceVolumeSerialNumber -cne
            ('{0:x8}' -f [uint32]$Evidence.VolumeSerialNumber) -or
        [string]$Manifest.evidenceFileId -cne
            ('{0:x16}' -f [uint64]$Evidence.FileId) -or
        [long]$Manifest.evidenceLength -ne [long]$Evidence.Length -or
        [string]$Manifest.clientBindingSha256 -cne
            [string]$Authority.ClientBindingSha256 -or
        [long]$Manifest.clientExecutableSize -ne
            [long]$Authority.ClientExecutableSize -or
        [string]$Manifest.clientExecutableSha256 -cne
            [string]$Authority.ClientExecutableSha256 -or
        [string]$Manifest.gameplayModulePath -cne
            [string]$Authority.GameplayModulePath -or
        [long]$Manifest.gameplayModuleSize -ne
            [long]$Authority.GameplayModuleSize -or
        [string]$Manifest.gameplayModuleSha256 -cne
            [string]$Authority.GameplayModuleSha256 -or
        [string]$Manifest.gameplayConfigurationPath -cne
            [string]$Authority.GameplayConfigurationPath -or
        [long]$Manifest.gameplayConfigurationSize -ne
            [long]$Authority.GameplayConfigurationSize -or
        [string]$Manifest.gameplayConfigurationSha256 -cne
            [string]$Authority.GameplayConfigurationSha256 -or
        [uint64][long]$Manifest.processId -ne
            [uint32]$Evidence.Value.ProcessId -or
        [uint64][long]$Manifest.processStartTimeFileTimeUtc -ne
            [uint64]$Evidence.Value.ProcessStartFileTime -or
        [uint64][long]$Manifest.consumerThreadId -ne
            [uint32]$Evidence.Value.ConsumerThreadId) {
        throw 'The Gameplay observation run manifest binding is invalid'
    }
    $true
}

function ConvertFrom-PSOBBGameplayObservationEvidenceBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    if ($Bytes.Length -ne $script:EvidenceFileSize) {
        throw 'The observation evidence does not have its exact fixed size'
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 8)
    $structSize = Read-PSOBBObservationUInt32LittleEndian $Bytes 8
    $formatVersion = Read-PSOBBObservationUInt32LittleEndian $Bytes 12
    $byteOrderMarker = Read-PSOBBObservationUInt32LittleEndian $Bytes 16
    $maximumFileSize = Read-PSOBBObservationUInt32LittleEndian $Bytes 20
    $eventAbiVersion = Read-PSOBBObservationUInt32LittleEndian $Bytes 24
    $eventRecordSize = Read-PSOBBObservationUInt32LittleEndian $Bytes 28
    $eventCapacity = Read-PSOBBObservationUInt32LittleEndian $Bytes 32
    $committedEventCount =
        Read-PSOBBObservationUInt32LittleEndian $Bytes 36
    $clientIdentityVersion =
        Read-PSOBBObservationUInt32LittleEndian $Bytes 40
    $clientSha256ByteCount =
        Read-PSOBBObservationUInt32LittleEndian $Bytes 44
    $totalDrainedEventCount =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 48
    $ringDroppedEventCount =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 56
    $producerViolationCount =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 64
    $evidenceCapacityDroppedEventCount =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 72
    $producerThreadId = Read-PSOBBObservationUInt32LittleEndian $Bytes 80
    $consumerThreadId = Read-PSOBBObservationUInt32LittleEndian $Bytes 84
    $processId = Read-PSOBBObservationUInt32LittleEndian $Bytes 88
    $reserved0 = Read-PSOBBObservationUInt32LittleEndian $Bytes 92
    $processStartFileTime =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 96
    $headerFirstSequence =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 104
    $headerLastSequence =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 112
    $clientSha256 = ([Convert]::ToHexString(
            $Bytes[120..151])).ToLowerInvariant()
    $moduleVersionBytes = [byte[]]::new(32)
    $expectedModuleVersionBytes =
        [System.Text.Encoding]::ASCII.GetBytes($script:ExactModuleVersion)
    [System.Array]::Copy(
        $Bytes, 152, $moduleVersionBytes, 0, $moduleVersionBytes.Length)
    $moduleVersionTerminator = [Array]::IndexOf($moduleVersionBytes, [byte]0)
    $moduleVersion = if ($moduleVersionTerminator -ge 0) {
        [System.Text.Encoding]::ASCII.GetString(
            $moduleVersionBytes, 0, $moduleVersionTerminator)
    } else {
        ''
    }
    $lifecycleState = Read-PSOBBObservationUInt32LittleEndian $Bytes 184
    $terminalFailureCode =
        Read-PSOBBObservationUInt32LittleEndian $Bytes 188
    $captureStartFileTime =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 192
    $lastCommitFileTime =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 200
    $completionFileTime =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 208
    $heartbeatCount =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 216
    $activeStartTickMs =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 224
    $lastCommitTickMs =
        Read-PSOBBObservationUInt64LittleEndian $Bytes 232

    if ($magic -cne 'PSOBBOBS' -or
        $structSize -ne $script:EvidenceHeaderSize -or
        $formatVersion -ne 1 -or
        $byteOrderMarker -ne 0x01020304 -or
        $maximumFileSize -ne $script:EvidenceFileSize -or
        $eventAbiVersion -ne 1 -or
        $eventRecordSize -ne $script:EvidenceRecordSize -or
        $eventCapacity -ne $script:EvidenceCapacity -or
        $committedEventCount -gt $eventCapacity -or
        $clientIdentityVersion -ne 1 -or
        $clientSha256ByteCount -ne 32 -or
        $clientSha256 -cne $script:ExactClientSha256) {
        throw 'The observation evidence header contract is invalid'
    }
    if ($moduleVersionTerminator -ne $expectedModuleVersionBytes.Length -or
        $moduleVersion -cne $script:ExactModuleVersion -or
        -not (Test-PSOBBObservationZeroRange `
            $moduleVersionBytes ($moduleVersionTerminator + 1) `
            ($moduleVersionBytes.Length - $moduleVersionTerminator - 1))) {
        throw 'The observation evidence module identity is invalid'
    }
    if ($reserved0 -ne 0 -or
        -not (Test-PSOBBObservationZeroRange $Bytes 240 16)) {
        throw 'The observation evidence header reserved bytes are not zero'
    }
    if ($consumerThreadId -eq 0 -or $processId -eq 0 -or
        $processStartFileTime -eq 0) {
        throw 'The observation evidence process identity is incomplete'
    }
    if ($lifecycleState -lt 1 -or $lifecycleState -gt 4 -or
        $captureStartFileTime -eq 0 -or
        $lastCommitFileTime -lt $captureStartFileTime) {
        throw 'The observation evidence lifecycle timestamps are invalid'
    }
    if (($lifecycleState -eq 1 -and
            ($activeStartTickMs -ne 0 -or $lastCommitTickMs -ne 0)) -or
        ($lifecycleState -ne 1 -and
            ($activeStartTickMs -eq 0 -or
                $lastCommitTickMs -lt $activeStartTickMs))) {
        throw 'The observation evidence lifecycle monotonic ticks are invalid'
    }
    switch ($lifecycleState) {
        1 {
            if ($terminalFailureCode -ne 0 -or $completionFileTime -ne 0 -or
                $lastCommitFileTime -ne $captureStartFileTime -or
                $heartbeatCount -ne 0 -or $committedEventCount -ne 0 -or
                $totalDrainedEventCount -ne 0 -or
                $ringDroppedEventCount -ne 0 -or
                $producerViolationCount -ne 0 -or
                $evidenceCapacityDroppedEventCount -ne 0 -or
                $producerThreadId -ne 0) {
                throw 'The ready observation evidence lifecycle is invalid'
            }
        }
        2 {
            if ($terminalFailureCode -ne 0 -or $completionFileTime -ne 0 -or
                $heartbeatCount -eq 0) {
                throw 'The active observation evidence lifecycle is invalid'
            }
        }
        3 {
            if ($terminalFailureCode -ne 0 -or
                $completionFileTime -ne $lastCommitFileTime -or
                ($committedEventCount -ne 0 -and $heartbeatCount -eq 0)) {
                throw 'The completed observation evidence lifecycle is invalid'
            }
        }
        4 {
            if ($terminalFailureCode -eq 0 -or
                $completionFileTime -ne $lastCommitFileTime) {
                throw 'The failed observation evidence lifecycle is invalid'
            }
        }
    }
    if ($totalDrainedEventCount -lt $committedEventCount -or
        ($totalDrainedEventCount - $committedEventCount) -ne
            $evidenceCapacityDroppedEventCount -or
        ($committedEventCount -lt $eventCapacity -and
            $evidenceCapacityDroppedEventCount -ne 0)) {
        throw 'The observation evidence counters are inconsistent'
    }

    [uint64]$firstSequence = 0
    [uint64]$lastSequence = 0
    [int]$tickEvents = 0
    [int]$actionStateEvents = 0
    [int]$send60Events = 0
    for ($index = 0; $index -lt $committedEventCount; $index++) {
        $offset = $script:EvidenceHeaderSize +
            ($index * $script:EvidenceRecordSize)
        $sequence = Read-PSOBBObservationUInt64LittleEndian $Bytes $offset
        $kind = Read-PSOBBObservationUInt32LittleEndian $Bytes ($offset + 12)
        $subcommandHeader =
            Read-PSOBBObservationUInt32LittleEndian $Bytes ($offset + 24)
        $subcommandByteCount =
            Read-PSOBBObservationUInt32LittleEndian $Bytes ($offset + 28)

        if ($sequence -eq 0 -or
            ($index -gt 0 -and
                ($lastSequence -eq [uint64]::MaxValue -or
                    $sequence -ne ($lastSequence + 1)))) {
            throw 'The observation evidence event sequence is not contiguous'
        }
        if ($kind -lt 1 -or $kind -gt 3) {
            throw 'The observation evidence contains an unsupported event kind'
        }
        switch ($kind) {
            1 { $tickEvents++ }
            2 { $actionStateEvents++ }
            3 {
                $send60Events++
                $headerByte = [byte]($subcommandHeader -band 0xFF)
                if ($headerByte -lt 0x43 -or $headerByte -gt 0x48 -or
                    $subcommandByteCount -lt 4) {
                    throw 'The observation evidence contains an invalid send60 event'
                }
            }
        }
        if ($index -eq 0) {
            $firstSequence = $sequence
        }
        $lastSequence = $sequence
    }

    if ($committedEventCount -eq 0) {
        if ($headerFirstSequence -ne 0 -or $headerLastSequence -ne 0) {
            throw 'The empty observation evidence has nonzero sequence bounds'
        }
    } elseif ($producerThreadId -eq 0 -or
        $producerThreadId -eq $consumerThreadId -or
        $headerFirstSequence -ne $firstSequence -or
        $headerLastSequence -ne $lastSequence) {
        throw 'The observation evidence identity or sequence bounds are invalid'
    }

    $processStopped = Test-PSOBBObservationProcessIdentityStopped `
        -ProcessId $processId -ProcessStartFileTime $processStartFileTime
    $captureDurationFileTimeTicks =
        $lastCommitFileTime - $captureStartFileTime
    $activeDurationMilliseconds =
        $lastCommitTickMs - $activeStartTickMs
    $lifecycleAccepted = $lifecycleState -eq 3 -and
        $activeDurationMilliseconds -ge
            $script:MinimumActiveDurationMilliseconds -and
        $heartbeatCount -ge $script:MinimumHeartbeatCount
    $accepted = $processStopped -and $committedEventCount -gt 0 -and
        $terminalFailureCode -eq 0 -and $lifecycleAccepted -and
        $ringDroppedEventCount -eq 0 -and
        $producerViolationCount -eq 0 -and
        $evidenceCapacityDroppedEventCount -eq 0
    [pscustomobject]@{
        Valid = $true
        Accepted = [bool]$accepted
        EventCount = [uint32]$committedEventCount
        TickEvents = [uint32]$tickEvents
        ActionStateEvents = [uint32]$actionStateEvents
        Send60Events = [uint32]$send60Events
        FirstSequence = [uint64]$firstSequence
        LastSequence = [uint64]$lastSequence
        TotalDrainedEventCount = [uint64]$totalDrainedEventCount
        RingDroppedEventCount = [uint64]$ringDroppedEventCount
        ProducerViolationCount = [uint64]$producerViolationCount
        EvidenceCapacityDroppedEventCount =
            [uint64]$evidenceCapacityDroppedEventCount
        ProducerThreadId = [uint32]$producerThreadId
        ConsumerThreadId = [uint32]$consumerThreadId
        ProcessId = [uint32]$processId
        ProcessStartFileTime = [uint64]$processStartFileTime
        ModuleVersion = $moduleVersion
        LifecycleState = [uint32]$lifecycleState
        TerminalFailureCode = [uint32]$terminalFailureCode
        CaptureStartFileTime = [uint64]$captureStartFileTime
        LastCommitFileTime = [uint64]$lastCommitFileTime
        CompletionFileTime = [uint64]$completionFileTime
        HeartbeatCount = [uint64]$heartbeatCount
        ActiveStartTickMs = [uint64]$activeStartTickMs
        LastCommitTickMs = [uint64]$lastCommitTickMs
        ActiveDurationMilliseconds =
            [uint64]$activeDurationMilliseconds
        CaptureDurationFileTimeTicks =
            [uint64]$captureDurationFileTimeTicks
        ProcessStopped = [bool]$processStopped
    }
}

function Resolve-PSOBBObservationEvidenceRuntimeRoot {
    if (-not [string]::IsNullOrWhiteSpace($InternalTestRuntimeRoot)) {
        if ($script:RuntimeRootWasProvided) {
            throw 'A test runtime cannot be combined with RuntimeRoot'
        }
        if (-not $script:InternalAuthorityWasProvided -or
            $null -eq $InternalTestAuthority) {
            throw 'The internal observation fixture authority is missing'
        }
        $testRoot = [System.IO.Path]::GetFullPath(
            $InternalTestRuntimeRoot).TrimEnd('\')
        $temporaryRoot = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::GetTempPath()).TrimEnd('\')
        $temporaryPrefix = $temporaryRoot + '\'
        if (-not $testRoot.StartsWith(
                $temporaryPrefix,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $testRoot) -cnotmatch
                '^psobb-gameplay-observation-[a-f0-9]{32}$') {
            throw 'The internal observation fixture root is invalid'
        }
        return $testRoot
    }

    if ($script:InternalAuthorityWasProvided) {
        throw 'A test authority cannot be used with the canonical runtime'
    }

    $requestedRoot = if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
        $script:CanonicalRuntimeRoot
    } else {
        [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\')
    }
    if (-not $requestedRoot.Equals(
            $script:CanonicalRuntimeRoot,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The observation evidence verifier accepts only the canonical PSOBB runtime'
    }
    $requestedRoot
}

if ($RunId -cnotmatch
    '^[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}$') {
    throw 'The observation evidence run ID is invalid'
}

$effectiveRuntimeRoot = Resolve-PSOBBObservationEvidenceRuntimeRoot
$layout = Get-PSOBBLayout -RuntimeRoot $effectiveRuntimeRoot
[void](Assert-PSOBBRuntimeMarker -Layout $layout)
[void](Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
        -Operation 'Gameplay observation evidence verification')
$combatLayout = Get-PSOBBServerEnvironmentLayout `
    -Layout $layout -Environment CombatCanary
if ([string]$combatLayout.Environment -cne 'CombatCanary' -or
    [string]$combatLayout.EnvironmentId -cne 'combat-canary') {
    throw 'The observation evidence environment is invalid'
}
$evidenceRoot = Join-Path $combatLayout.EnvironmentRoot 'evidence'
$categoryRoot = Join-Path $evidenceRoot 'gameplay-observation'
$runRoot = Join-Path $categoryRoot $RunId
$expectedPath = Join-Path $runRoot 'events-v1.partial'
$manifestPath = Join-Path $runRoot 'run-manifest-v1.json'
$directoryContracts = @(
    [pscustomobject]@{ Path = $evidenceRoot; Name = 'evidence' },
    [pscustomobject]@{
        Path = $categoryRoot
        Name = 'gameplay-observation'
    },
    [pscustomobject]@{ Path = $runRoot; Name = $RunId })
foreach ($directoryContract in $directoryContracts) {
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $directoryContract.Path `
            -Root $combatLayout.EnvironmentRoot `
            -Kind Directory -Label 'Gameplay observation evidence directory')
    $directoryItem = Get-Item -Force -LiteralPath $directoryContract.Path
    if ($directoryItem.Name -cne $directoryContract.Name -or
        -not (Test-PSOBBProtectedAcl -Path $directoryContract.Path)) {
        throw 'The observation evidence directory ACL is invalid'
    }
}
if (-not (Test-PSOBBObservationExactLeafName `
        -Directory $runRoot -Name 'run-manifest-v1.json' `
        -DirectoryExpected $false)) {
    throw 'The Gameplay observation run manifest path is invalid'
}
$manifestSnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
    -LiteralPath $manifestPath -Root $runRoot -MaximumBytes 32KB `
    -RoleLabel 'Gameplay observation run manifest' `
    -RequireProtectedAcl `
    -Consumer {
        param([byte[]]$Bytes)
        ConvertFrom-PSOBBObservationManifestBytes `
            -Bytes $Bytes -ExpectedRunId $RunId
    }
$manifestAuthority = Get-PSOBBObservationManifestAuthority -Layout $layout

$snapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
    -LiteralPath $expectedPath -Root $evidenceRoot `
    -MaximumBytes $script:EvidenceFileSize `
    -ExpectedLength $script:EvidenceFileSize `
    -RoleLabel 'Gameplay observation evidence' `
    -Consumer {
        param([byte[]]$Bytes)
        if (-not (Test-PSOBBObservationEvidenceFileAcl `
                -Path $expectedPath -RunRoot $runRoot)) {
            throw 'The observation evidence file ACL is invalid'
        }
        ConvertFrom-PSOBBGameplayObservationEvidenceBytes -Bytes $Bytes
    }
[void](Assert-PSOBBObservationManifestBinding `
        -Manifest $manifestSnapshot.Value `
        -Authority $manifestAuthority -Evidence $snapshot)
[void](Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
        -Operation 'Gameplay observation evidence verification completion')

[pscustomobject]@{
    Valid = [bool]$snapshot.Value.Valid
    Accepted = [bool]$snapshot.Value.Accepted
    RunId = $RunId
    FileLength = [long]$snapshot.Length
    FileSha256 = [string]$snapshot.Sha256
    ManifestPath = [string]$manifestSnapshot.Path
    ManifestSha256 = [string]$manifestSnapshot.Sha256
    EventCount = [uint32]$snapshot.Value.EventCount
    TickEvents = [uint32]$snapshot.Value.TickEvents
    ActionStateEvents = [uint32]$snapshot.Value.ActionStateEvents
    Send60Events = [uint32]$snapshot.Value.Send60Events
    FirstSequence = [uint64]$snapshot.Value.FirstSequence
    LastSequence = [uint64]$snapshot.Value.LastSequence
    TotalDrainedEventCount =
        [uint64]$snapshot.Value.TotalDrainedEventCount
    RingDroppedEventCount =
        [uint64]$snapshot.Value.RingDroppedEventCount
    ProducerViolationCount =
        [uint64]$snapshot.Value.ProducerViolationCount
    EvidenceCapacityDroppedEventCount =
        [uint64]$snapshot.Value.EvidenceCapacityDroppedEventCount
    ProducerThreadId = [uint32]$snapshot.Value.ProducerThreadId
    ConsumerThreadId = [uint32]$snapshot.Value.ConsumerThreadId
    ProcessId = [uint32]$snapshot.Value.ProcessId
    ProcessStartFileTime = [uint64]$snapshot.Value.ProcessStartFileTime
    ModuleVersion = [string]$snapshot.Value.ModuleVersion
    LifecycleState = [uint32]$snapshot.Value.LifecycleState
    TerminalFailureCode = [uint32]$snapshot.Value.TerminalFailureCode
    CaptureStartFileTime = [uint64]$snapshot.Value.CaptureStartFileTime
    LastCommitFileTime = [uint64]$snapshot.Value.LastCommitFileTime
    CompletionFileTime = [uint64]$snapshot.Value.CompletionFileTime
    HeartbeatCount = [uint64]$snapshot.Value.HeartbeatCount
    ActiveStartTickMs = [uint64]$snapshot.Value.ActiveStartTickMs
    LastCommitTickMs = [uint64]$snapshot.Value.LastCommitTickMs
    ActiveDurationMilliseconds =
        [uint64]$snapshot.Value.ActiveDurationMilliseconds
    CaptureDurationFileTimeTicks =
        [uint64]$snapshot.Value.CaptureDurationFileTimeTicks
    ProcessStopped = [bool]$snapshot.Value.ProcessStopped
}
