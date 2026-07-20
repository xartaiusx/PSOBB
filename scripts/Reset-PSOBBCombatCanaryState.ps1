[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,

    [Parameter(Mandatory)]
    [string]$SnapshotPath,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedTwillsContractSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSigningPublicKeySpkiSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedBuildContractSha256,

    [Parameter(DontShow = $true)]
    [ValidateRange(0, 5)]
    [int]$InternalTestFailAfterSwap = 0,

    [Parameter(DontShow = $true)]
    [string]$InternalTestFaultToken,

    [Parameter(DontShow = $true)]
    [switch]$InternalTestLeaveCompensationIncomplete,

    [Parameter(DontShow = $true)]
    [switch]$InternalTestFailInstallMove,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestAfterPayloadSourceLease,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestBeforePayloadCopy,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestAfterPublishedMove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

function Assert-PSOBBCombatResetLayout {
    param([Parameter(Mandatory)]$Value)

    $required = @(
        'Environment', 'EnvironmentId', 'Root', 'EnvironmentRoot',
        'ServerBase', 'Server', 'Client', 'ControlDirectory', 'PidFile',
        'LegacyPidFile', 'HostPidFile', 'ControlState', 'ControlRequest',
        'InstallRecord', 'Backups', 'Logs', 'Snapshots', 'Builds',
        'RuntimeMarker', 'BaseClient', 'BaseClientManifest', 'Secrets')
    $missing = @($required | Where-Object {
            $Value.PSObject.Properties.Name -notcontains $_ -or
            [string]::IsNullOrWhiteSpace([string]$Value.$_)
        })
    if ($missing.Count -ne 0 -or
        [string]$Value.Environment -cne 'CombatCanary' -or
        [string]$Value.EnvironmentId -cne 'combat-canary') {
        throw 'The combat-canary server-environment layout contract is incomplete'
    }
    $Value
}

function Assert-PSOBBCombatResetStopped {
    $running = @(Get-Process -ErrorAction Stop | Where-Object {
            $_.ProcessName -like 'newserv*' -or
            $_.ProcessName -in @('Psobb', 'online', 'option')
        })
    if ($running.Count -gt 0) {
        $identities = @($running | Sort-Object ProcessName, Id | ForEach-Object {
                '{0} PID {1}' -f $_.ProcessName, $_.Id
            })
        throw ('Combat-canary reset requires every PSOBB/newserv process to be ' +
            "stopped. Running: $($identities -join ', ')")
    }
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { [int]$_.LocalPort -in @(11000, 12000, 12001) })
    } catch {
        throw ('Cannot verify that PSOBB listeners are stopped: ' +
            $_.Exception.Message)
    }
    if ($listeners.Count -gt 0) {
        $evidence = @($listeners | Sort-Object LocalPort, LocalAddress, OwningProcess |
            ForEach-Object {
                '{0}:{1} PID {2}' -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess
            })
        throw ('Combat-canary reset requires ports 11000, 12000, and 12001 to ' +
            "have no listeners. Listening: $($evidence -join ', ')")
    }
    $true
}

function Assert-PSOBBCombatResetInternalFaultGate {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Marker
    )

    $requested = $InternalTestFailAfterSwap -ne 0 -or
        $InternalTestFailInstallMove.IsPresent -or
        $null -ne $InternalTestAfterPayloadSourceLease -or
        $null -ne $InternalTestBeforePayloadCopy -or
        $null -ne $InternalTestAfterPublishedMove -or
        $InternalTestLeaveCompensationIncomplete.IsPresent -or
        -not [string]::IsNullOrWhiteSpace($InternalTestFaultToken)
    if (-not $requested) { return $true }
    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root)
    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $fixtureName = [System.IO.Path]::GetFileName($root.TrimEnd('\'))
    $fixtureMarkerPath = Join-Path $root '.combat-canary-state-test.json'
    $injectionCount = [int]($InternalTestFailAfterSwap -gt 0) +
        [int]($InternalTestFailInstallMove.IsPresent) +
        [int]($null -ne $InternalTestAfterPayloadSourceLease) +
        [int]($null -ne $InternalTestBeforePayloadCopy) +
        [int]($null -ne $InternalTestAfterPublishedMove)
    if ($injectionCount -ne 1 -or
        ($InternalTestLeaveCompensationIncomplete.IsPresent -and
            $InternalTestFailAfterSwap -le 0) -or
        -not $root.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fixtureName -cnotmatch '^psobb-combat-canary-state-test-[a-f0-9]{32}$' -or
        [string]$Marker.installationId -cne $InternalTestFaultToken -or
        -not (Test-Path -LiteralPath $fixtureMarkerPath -PathType Leaf)) {
        throw 'Internal combat-canary fault injection is restricted to an explicit temporary fixture'
    }
    $rootItem = Get-Item -Force -LiteralPath $root -ErrorAction Stop
    $fixtureMarkerItem = Get-Item -Force -LiteralPath $fixtureMarkerPath `
        -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $fixtureMarkerItem.PSIsContainer -or
        ($fixtureMarkerItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-PSOBBProtectedAcl -Path $fixtureMarkerPath)) {
        throw 'Internal combat-canary fault injection requires an ordinary protected fixture'
    }
    $fixtureMarkerJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $fixtureMarkerPath `
        -Root $root -MaximumBytes 4KB `
        -RoleLabel 'internal combat canary fault fixture marker'
    $fixtureMarker = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $fixtureMarkerJson `
        -RoleLabel 'internal combat canary fault fixture marker'
    Assert-PSOBBCombatResetExactProperties -Value $fixtureMarker `
        -Label 'Internal combat-canary fault fixture marker' `
        -Expected @('schemaVersion', 'purpose', 'installationId')
    if ([int]$fixtureMarker.schemaVersion -ne 1 -or
        [string]$fixtureMarker.purpose -cne 'combat-canary-state-transaction-test' -or
        [string]$fixtureMarker.installationId -cne [string]$Marker.installationId) {
        throw 'The internal combat-canary fault fixture marker is not bound to this runtime'
    }
    $true
}

function Assert-PSOBBCombatResetExactProperties {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if ($actual.Count -ne $expectedSorted.Count -or
        @(Compare-Object -ReferenceObject $expectedSorted `
            -DifferenceObject $actual).Count -ne 0) {
        throw "$Label does not have the exact combat-canary schema"
    }
}

function Move-PSOBBCombatResetNoClobber {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Label
    )

    try {
        $sourceItem = Get-Item -Force -LiteralPath $Source -ErrorAction Stop
        if (($sourceItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Unsafe transaction item'
        }
        if ($sourceItem.PSIsContainer) {
            [System.IO.Directory]::Move($Source, $Destination)
        } else {
            [System.IO.File]::Move($Source, $Destination, $false)
        }
    } catch {
        throw "No-clobber move failed for reset target '$Label'"
    }
}

function Get-PSOBBCombatResetSemanticResult {
    param(
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)][string]$BankPath,
        [Parameter(Mandatory)][string]$ContractPath,
        [Parameter(Mandatory)][string]$ContractHash
    )

    try {
        $characterOutput = @(& (Join-Path $PSScriptRoot 'Test-PSOBBCharacterBuild.ps1') `
                -Path $CharacterPath -BuildPath $ContractPath)
        $character = @($characterOutput | Where-Object {
                $_.PSObject.Properties.Name -contains 'Valid'
            })
        $bankOutput = @(& (Join-Path $PSScriptRoot 'Test-PSOBBTwillsBank.ps1') `
                -Path $BankPath -BuildPath $ContractPath `
                -ExpectedBuildSha256 $ContractHash)
        $bank = @($bankOutput | Where-Object {
                $_.PSObject.Properties.Name -contains 'Valid'
            })
    } catch {
        throw 'The staged combat-canary state failed independent Twills semantic verification'
    }
    if ($character.Count -ne 1 -or $bank.Count -ne 1 -or
        -not [bool]$character[0].Valid -or -not [bool]$bank[0].Valid -or
        [string]$character[0].BuildSha256 -cne $ContractHash -or
        [string]$bank[0].BuildSha256 -cne $ContractHash -or
        [int]$character[0].SlotIndex -ne 0 -or
        [int]$character[0].DisplayedLevel -ne 200 -or
        [string]$bank[0].Character -cne 'Twills' -or
        [string]$bank[0].Class -cne 'FOnewearl' -or
        [int]$bank[0].SlotIndex -ne 0) {
        throw 'The staged combat-canary state is not exact slot-0 Twills FOnewearl'
    }
    [pscustomobject]@{ Character = $character[0]; Bank = $bank[0] }
}

function Test-PSOBBCombatResetInstalledFiles {
    param(
        [Parameter(Mandatory)][string]$SystemRoot,
        [Parameter(Mandatory)]$StateEntries
    )

    $expected = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($StateEntries)) {
        $relative = ([string]$entry.path).Substring('state/system/'.Length)
        if (-not $expected.Add($relative)) {
            throw 'The reset manifest contains case-colliding state paths'
        }
        try {
            $installed = Assert-PathWithinRoot `
                -Path (Join-Path $SystemRoot ($relative.Replace('/', '\'))) `
                -Root $SystemRoot
            $item = Get-Item -Force -LiteralPath $installed -ErrorAction Stop
            if ($item.PSIsContainer -or
                ($item.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not (Test-PSOBBProtectedAcl -Path $installed) -or
                $item.Length -ne [int64]$entry.size -or
                (Get-LowerSha256 $installed) -cne [string]$entry.sha256) {
                throw 'Installed state mismatch'
            }
        } catch {
            throw "Installed readback failed for state role '$($entry.role)'"
        }
    }
    try {
        $actual = @(foreach ($directoryName in @('licenses', 'players', 'teams')) {
                $directory = Join-Path $SystemRoot $directoryName
                if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
                    throw 'Missing state directory'
                }
                Get-ChildItem -Force -LiteralPath $directory -Recurse -File `
                    -ErrorAction Stop | ForEach-Object {
                        [void](Assert-PathWithinRoot `
                                -Path $_.FullName -Root $SystemRoot)
                        [System.IO.Path]::GetRelativePath(
                            $SystemRoot, $_.FullName).Replace('\', '/')
                    }
            })
    } catch {
        throw 'Installed combat-canary state inventory is unreadable or unsafe'
    }
    if ($actual.Count -ne $expected.Count -or
        @($actual | Where-Object { -not $expected.Contains($_) }).Count -ne 0) {
        throw 'Installed combat-canary state has missing or extra files'
    }
    foreach ($directoryName in @('licenses', 'players', 'teams')) {
        $prefix = $directoryName + '/'
        $directoryFiles = @($StateEntries | ForEach-Object {
                ([string]$_.path).Substring('state/system/'.Length)
            } | Where-Object { $_.StartsWith(
                    $prefix, [System.StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { $_.Substring($prefix.Length) })
        $expectedDirectories = Get-PSOBBCombatCanaryExpectedDirectories `
            -FilePaths $directoryFiles
        [void](Assert-PSOBBCombatCanaryExactDirectoryInventory `
                -Root (Join-Path $SystemRoot $directoryName) `
                -ExpectedDirectories $expectedDirectories `
                -RoleLabel 'installed combat canary state' -RequireProtected)
    }
    $true
}

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if (-not (Get-Command Get-PSOBBServerEnvironmentLayout -ErrorAction SilentlyContinue)) {
    throw 'Get-PSOBBServerEnvironmentLayout is required for combat-canary reset'
}
$layout = Assert-PSOBBCombatResetLayout -Value (
    Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment CombatCanary)
$stableLayout = Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment Stable
[void](Assert-PSOBBServerEnvironmentIsolation -Layout $rootLayout)
if ([System.IO.Path]::GetFullPath($layout.Server).Equals(
        [System.IO.Path]::GetFullPath($stableLayout.Server),
        [System.StringComparison]::OrdinalIgnoreCase) -or
    -not [System.IO.Path]::GetFullPath($layout.Server).StartsWith(
        [System.IO.Path]::GetFullPath($layout.EnvironmentRoot).TrimEnd('\') + '\',
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The reset target is not exclusively inside the combat-canary environment'
}
[void](Assert-PSOBBCombatResetStopped)

$snapshotVerification = & (Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
    -RuntimeRoot $rootLayout.Root -Target Snapshot -SnapshotPath $SnapshotPath `
    -ExpectedTwillsContractSha256 $ExpectedTwillsContractSha256 `
    -ExpectedSigningPublicKeySpkiSha256 $ExpectedSigningPublicKeySpkiSha256
if ($null -eq $snapshotVerification -or -not [bool]$snapshotVerification.Valid) {
    throw 'The requested combat-canary snapshot did not pass sealed verification'
}
$snapshotRoot = [string]$snapshotVerification.SnapshotPath
$snapshotDirectoryName = (Get-Item -Force -LiteralPath $snapshotRoot).Name
$manifestPath = Join-Path $snapshotRoot 'manifest.json'
$manifestJson = Read-PSOBBCombatCanaryStrictJsonObject `
    -LiteralPath $manifestPath -Root $snapshotRoot -MaximumBytes 256KB `
    -ExpectedSha256 ([string]$snapshotVerification.ManifestSha256) `
    -RoleLabel 'reset snapshot manifest'
$manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
    -JsonObject $manifestJson -RoleLabel 'reset snapshot manifest'
$stateEntries = @($manifest.files | Where-Object {
        [string]$_.path -cmatch '^state/system/'
    })
if ($stateEntries.Count -ne [int]$snapshotVerification.StateFiles) {
    throw 'The verified snapshot state-file count changed before reset'
}
[void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
        -Entries $stateEntries -Scope State)
$contractPath = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'config\twills-fonewearl-build.json'
$contractHash = [string]$snapshotVerification.TwillsContractSha256
$systemRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Server 'system') -Root $layout.Server
if (-not (Test-Path -LiteralPath $layout.Server -PathType Container) -or
    -not (Test-Path -LiteralPath (Join-Path $systemRoot 'config.json') -PathType Leaf)) {
    throw 'Initialize the exact combat-canary server before restoring sealed state'
}

$marker = Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $rootLayout
[void](Assert-PSOBBCombatResetInternalFaultGate `
        -Layout $rootLayout -Marker $marker)
$mutexName = 'Local\PSOBB.Newserv.Start.' +
    ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
try {
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (-not $ownsMutex) {
        throw 'Another combat-canary state operation is in progress'
    }
    [void](Assert-PSOBBCombatResetStopped)
    $installationVerification = & (
        Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $rootLayout.Root -Target Installation `
        -ExpectedTwillsContractSha256 $ExpectedTwillsContractSha256 `
        -ExpectedSigningPublicKeySpkiSha256 $ExpectedSigningPublicKeySpkiSha256 `
        -ExpectedBuildContractSha256 $ExpectedBuildContractSha256
    if ($null -eq $installationVerification -or
        -not [bool]$installationVerification.Valid) {
        throw 'The combat-canary installation identity gate did not pass'
    }
    if (-not $PSCmdlet.ShouldProcess(
            $layout.Server,
            'Atomically reset only the combat-canary to the sealed Twills snapshot')) {
        return [pscustomobject]@{
            Restored = $false
            WhatIf = $true
            Environment = 'CombatCanary'
            SnapshotId = [string]$snapshotVerification.SnapshotId
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
        }
    }

    $transactionId = [Guid]::NewGuid().ToString('N')
    $stageRoot = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot ('.state-stage-' + $transactionId)) `
        -Root $layout.EnvironmentRoot
    $rollbackRoot = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot ('.state-rollback-' + $transactionId)) `
        -Root $layout.EnvironmentRoot
    $stateBindingPath = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot 'state-binding.json') `
        -Root $layout.EnvironmentRoot
    $completed = $false
    $processed = [System.Collections.Generic.List[object]]::new()
    $stageTransaction = $null
    $rollbackTransaction = $null
    try {
        $stageTransaction = New-PSOBBCombatCanaryTransactionTree `
            -Path $stageRoot -Root $layout.EnvironmentRoot `
            -TransactionId $transactionId -Purpose 'state-reset-stage'
        foreach ($directoryName in @('licenses', 'players', 'teams')) {
            New-Item -ItemType Directory `
                -Path (Join-Path $stageRoot ('system\' + $directoryName)) `
                -Force | Out-Null
        }
        if ($null -ne $InternalTestBeforePayloadCopy) {
            & $InternalTestBeforePayloadCopy
        }
        foreach ($entry in $stateEntries) {
            try {
                $source = Assert-PathWithinRoot `
                    -Path (Join-Path $snapshotRoot (
                        ([string]$entry.path).Replace('/', '\'))) `
                    -Root $snapshotRoot
                $destinationRelative = ([string]$entry.path).Substring('state/'.Length)
                $destination = Assert-PathWithinRoot `
                    -Path (Join-Path $stageRoot (
                        $destinationRelative.Replace('/', '\'))) `
                    -Root $stageRoot
                New-Item -ItemType Directory `
                    -Path (Split-Path -Parent $destination) -Force | Out-Null
                $rolePolicy = Get-PSOBBCombatCanaryPayloadRolePolicy `
                    -Role ([string]$entry.role)
                Copy-PSOBBCombatCanaryBoundedFileSnapshot `
                    -Source $source -SourceRoot $snapshotRoot `
                    -Destination $destination -DestinationRoot $stageRoot `
                    -MaximumBytes ([long]$rolePolicy.MaximumBytes) `
                    -ExpectedLength ([long]$entry.size) `
                    -ExpectedSha256 ([string]$entry.sha256) `
                    -RoleLabel ("reset $($entry.role) payload") `
                    -InternalTestAfterSourceLease `
                        $InternalTestAfterPayloadSourceLease | Out-Null
            } catch {
                throw "Staged reset copy failed for role '$($entry.role)'"
            }
        }
        $stageCharacter = @($stateEntries | Where-Object {
                [string]$_.role -ceq 'twills-character'
            })
        $stageBank = @($stateEntries | Where-Object {
                [string]$_.role -ceq 'twills-bank'
            })
        if ($stageCharacter.Count -ne 1 -or $stageBank.Count -ne 1) {
            throw 'The verified snapshot no longer identifies one Twills save pair'
        }
        $stageCharacterPath = Join-Path $stageRoot (
            ([string]$stageCharacter[0].path).Substring('state/'.Length).Replace('/', '\'))
        $stageBankPath = Join-Path $stageRoot (
            ([string]$stageBank[0].path).Substring('state/'.Length).Replace('/', '\'))
        [void](Get-PSOBBCombatResetSemanticResult `
                -CharacterPath $stageCharacterPath -BankPath $stageBankPath `
                -ContractPath $contractPath -ContractHash $contractHash)

        $binding = [ordered]@{
            schemaVersion = 1
            environment = 'CombatCanary'
            environmentId = 'combat-canary'
            restoredAtUtc = [DateTime]::UtcNow.ToString('o')
            snapshotDirectoryName = $snapshotDirectoryName
            snapshotId = [string]$snapshotVerification.SnapshotId
            snapshotManifestSha256 = [string]$snapshotVerification.ManifestSha256
            twillsContractSha256 = $contractHash
            signingPublicKeySpkiSha256 = [string]$snapshotVerification.SigningPublicKeySpkiSha256
            stateFiles = $stateEntries.Count
        }
        $stageBindingPath = Join-Path $stageRoot 'state-binding.json'
        [System.IO.File]::WriteAllText(
            $stageBindingPath,
            ($binding | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false))
        $stagedBindingHash = Get-LowerSha256 $stageBindingPath
        $installRecordJson = Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $layout.InstallRecord `
            -Root $layout.EnvironmentRoot -MaximumBytes 256KB `
            -RoleLabel 'combat canary installation record'
        $installRecord = ConvertTo-PSOBBCombatCanaryPowerShellObject `
            -JsonObject $installRecordJson `
            -RoleLabel 'combat canary installation record'
        Assert-PSOBBCombatResetExactProperties -Value $installRecord `
            -Label 'Combat-canary installation record' `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'initializedAtUtc', 'buildContractSha256',
                'serverReleaseManifestSha256', 'baseClientManifestSha256',
                'clientBindingSha256', 'snapshotDirectoryName', 'snapshotId',
                'snapshotManifestSha256', 'stateBindingSha256',
                'twillsContractSha256', 'signingPublicKeySpkiSha256',
                'configurationSha256')
        $installRecord.snapshotDirectoryName = $snapshotDirectoryName
        $installRecord.snapshotId = [string]$snapshotVerification.SnapshotId
        $installRecord.snapshotManifestSha256 =
            [string]$snapshotVerification.ManifestSha256
        $installRecord.stateBindingSha256 = $stagedBindingHash
        $installRecord.twillsContractSha256 = $contractHash
        $installRecord.signingPublicKeySpkiSha256 =
            [string]$snapshotVerification.SigningPublicKeySpkiSha256
        $stageInstallPath = Join-Path $stageRoot 'installation.json'
        [System.IO.File]::WriteAllText(
            $stageInstallPath,
            ($installRecord | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
        try {
            Set-PSOBBProtectedTreeAcl -Path $stageRoot `
                -Root $layout.EnvironmentRoot
        } catch {
            throw 'The staged combat-canary reset state could not be sealed'
        }
        [void](Assert-PSOBBCombatResetStopped)

        $rollbackTransaction = New-PSOBBCombatCanaryTransactionTree `
            -Path $rollbackRoot -Root $layout.EnvironmentRoot `
            -TransactionId ([Guid]::NewGuid().ToString('N')) `
            -Purpose 'state-reset-rollback'
        Set-PSOBBProtectedAcl -Path $rollbackRoot
        $items = @(
            [pscustomobject]@{
                Name = 'licenses'
                Current = Join-Path $systemRoot 'licenses'
                Staged = Join-Path $stageRoot 'system\licenses'
                Rollback = Join-Path $rollbackRoot 'licenses'
            },
            [pscustomobject]@{
                Name = 'players'
                Current = Join-Path $systemRoot 'players'
                Staged = Join-Path $stageRoot 'system\players'
                Rollback = Join-Path $rollbackRoot 'players'
            },
            [pscustomobject]@{
                Name = 'teams'
                Current = Join-Path $systemRoot 'teams'
                Staged = Join-Path $stageRoot 'system\teams'
                Rollback = Join-Path $rollbackRoot 'teams'
            },
            [pscustomobject]@{
                Name = 'state-binding'
                Current = $stateBindingPath
                Staged = $stageBindingPath
                Rollback = Join-Path $rollbackRoot 'state-binding.json'
            },
            [pscustomobject]@{
                Name = 'installation'
                Current = $layout.InstallRecord
                Staged = $stageInstallPath
                Rollback = Join-Path $rollbackRoot 'installation.json'
            })
        if ($InternalTestFailAfterSwap -gt $items.Count) {
            throw 'The requested internal reset swap boundary does not exist'
        }
        $swapCount = 0
        foreach ($item in $items) {
            $hadCurrent = Test-Path -LiteralPath $item.Current
            $stagedItem = Get-Item -Force -LiteralPath $item.Staged `
                -ErrorAction Stop
            $isDirectory = [bool]$stagedItem.PSIsContainer
            $newIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $item.Staged -Root $stageRoot -Directory $isDirectory `
                -RoleLabel ("staged reset target '$($item.Name)'")
            $record = [pscustomobject]@{
                Item = $item
                HadCurrent = $hadCurrent
                OldMoved = $false
                NewPublished = $false
                NeedsCompensation = $false
                Directory = $isDirectory
                NewVolumeSerialNumber = [uint32]$newIdentity.VolumeSerialNumber
                NewFileId = [uint64]$newIdentity.FileId
                OldVolumeSerialNumber = [uint32]0
                OldFileId = [uint64]0
            }
            $processed.Add($record)
            if ($hadCurrent) {
                $oldIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                    -Path $item.Current -Root $layout.EnvironmentRoot `
                    -Directory $isDirectory `
                    -RoleLabel ("current reset target '$($item.Name)'")
                $record.OldVolumeSerialNumber =
                    [uint32]$oldIdentity.VolumeSerialNumber
                $record.OldFileId = [uint64]$oldIdentity.FileId
                Move-PSOBBCombatResetNoClobber -Source $item.Current `
                    -Destination $item.Rollback -Label $item.Name
                $record.OldMoved = $true
                $record.NeedsCompensation = $true
                $rollbackIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                    -Path $item.Rollback -Root $rollbackRoot `
                    -Directory $isDirectory `
                    -RoleLabel ("rollback reset target '$($item.Name)'")
                if ([uint32]$rollbackIdentity.VolumeSerialNumber -ne
                        [uint32]$record.OldVolumeSerialNumber -or
                    [uint64]$rollbackIdentity.FileId -ne
                        [uint64]$record.OldFileId) {
                    throw "Reset target '$($item.Name)' changed identity during rollback move"
                }
            }
            if ($InternalTestFailInstallMove.IsPresent -and
                $item.Name -ceq 'installation') {
                throw 'Injected temporary-fixture installation move failure'
            }
            Move-PSOBBCombatResetNoClobber -Source $item.Staged `
                -Destination $item.Current -Label $item.Name
            $record.NewPublished = $true
            $record.NeedsCompensation = $true
            if ($null -ne $InternalTestAfterPublishedMove) {
                & $InternalTestAfterPublishedMove $item.Current $item.Name
            }
            $publishedIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $item.Current -Root $layout.EnvironmentRoot `
                -Directory $isDirectory `
                -RoleLabel ("published reset target '$($item.Name)'")
            if ([uint32]$publishedIdentity.VolumeSerialNumber -ne
                    [uint32]$record.NewVolumeSerialNumber -or
                [uint64]$publishedIdentity.FileId -ne
                    [uint64]$record.NewFileId) {
                throw "Reset target '$($item.Name)' changed identity after publication"
            }
            $swapCount++
            if ($InternalTestFailAfterSwap -eq $swapCount) {
                throw 'Injected temporary-fixture reset swap failure'
            }
        }

        [void](Test-PSOBBCombatResetInstalledFiles `
                -SystemRoot $systemRoot -StateEntries $stateEntries)
        $installedCharacterPath = Join-Path $systemRoot (
            ([string]$stageCharacter[0].path).Substring('state/system/'.Length).Replace('/', '\'))
        $installedBankPath = Join-Path $systemRoot (
            ([string]$stageBank[0].path).Substring('state/system/'.Length).Replace('/', '\'))
        [void](Get-PSOBBCombatResetSemanticResult `
                -CharacterPath $installedCharacterPath -BankPath $installedBankPath `
                -ContractPath $contractPath -ContractHash $contractHash)
        $installedBindingHash = Get-LowerSha256 $stateBindingPath
        $completeReadback = & (Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
            -RuntimeRoot $rootLayout.Root -Target Installed `
            -SnapshotPath $snapshotRoot `
            -ExpectedBuildContractSha256 $installationVerification.BuildContractSha256 `
            -ExpectedTwillsContractSha256 $contractHash `
            -ExpectedSigningPublicKeySpkiSha256 `
                $snapshotVerification.SigningPublicKeySpkiSha256
        if ($null -eq $completeReadback -or -not [bool]$completeReadback.Valid) {
            throw 'The reset combat-canary failed complete installed readback verification'
        }
        $completed = $true
        [pscustomobject]@{
            Restored = $true
            Environment = 'CombatCanary'
            SnapshotId = [string]$snapshotVerification.SnapshotId
            SnapshotDirectoryName = $snapshotDirectoryName
            SnapshotManifestSha256 = [string]$snapshotVerification.ManifestSha256
            StateBindingSha256 = $installedBindingHash
            TwillsContractSha256 = $contractHash
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
            DisplayedLevel = 200
            StateFiles = $stateEntries.Count
            Transaction = 'canary-only staged swap with reverse-order compensation'
        }
    } catch {
        $failure = $_
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        $compensationFaultInjected = $false
        for ($index = $processed.Count - 1; $index -ge 0; $index--) {
            $record = $processed[$index]
            if (-not [bool]$record.NeedsCompensation) { continue }
            if ($InternalTestLeaveCompensationIncomplete.IsPresent -and
                -not $compensationFaultInjected) {
                $rollbackErrors.Add($record.Item.Name)
                $compensationFaultInjected = $true
                continue
            }
            try {
                if ([bool]$record.NewPublished -and
                    (Test-Path -LiteralPath $record.Item.Current)) {
                    if ([bool]$record.Directory) {
                        Remove-PSOBBCombatCanaryOwnedTree `
                            -Path $record.Item.Current `
                            -Root $layout.EnvironmentRoot `
                            -ExpectedVolumeSerialNumber `
                                $record.NewVolumeSerialNumber `
                            -ExpectedFileId $record.NewFileId `
                            -RoleLabel ("reset compensation '$($record.Item.Name)'")
                    } else {
                        Remove-PSOBBCombatCanaryOwnedFile `
                            -Path $record.Item.Current `
                            -Root $layout.EnvironmentRoot `
                            -ExpectedVolumeSerialNumber `
                                $record.NewVolumeSerialNumber `
                            -ExpectedFileId $record.NewFileId `
                            -RoleLabel ("reset compensation '$($record.Item.Name)'")
                    }
                }
                if ([bool]$record.OldMoved -and
                    (Test-Path -LiteralPath $record.Item.Rollback)) {
                    Move-PSOBBCombatResetNoClobber `
                        -Source $record.Item.Rollback `
                        -Destination $record.Item.Current `
                        -Label $record.Item.Name
                    $restoredIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                        -Path $record.Item.Current `
                        -Root $layout.EnvironmentRoot `
                        -Directory $record.Directory `
                        -RoleLabel ("restored reset target '$($record.Item.Name)'")
                    if ([uint32]$restoredIdentity.VolumeSerialNumber -ne
                            [uint32]$record.OldVolumeSerialNumber -or
                        [uint64]$restoredIdentity.FileId -ne
                            [uint64]$record.OldFileId) {
                        throw "Reset target '$($record.Item.Name)' changed identity during compensation"
                    }
                }
                $record.NeedsCompensation = $false
            } catch {
                $rollbackErrors.Add($record.Item.Name)
            }
        }
        if ($rollbackErrors.Count -ne 0) {
            throw ('Combat-canary reset failed and compensation was incomplete for: ' +
                ($rollbackErrors -join ', ') + '. Original error: ' +
                $failure.Exception.Message)
        }
        throw $failure
    } finally {
        if (Test-Path -LiteralPath $stageRoot) {
            try {
                if ($null -eq $stageTransaction) {
                    throw 'The reset stage has no transaction identity'
                }
                Remove-PSOBBCombatCanaryTransactionTree `
                    -Transaction $stageTransaction `
                    -RoleLabel 'combat-canary reset staging cleanup'
            } catch {
                throw 'Combat-canary reset staging cleanup retained identity-mismatched evidence'
            }
        }
        $compensationComplete = @($processed | Where-Object {
                [bool]$_.NeedsCompensation
            }).Count -eq 0
        if (($completed -or $compensationComplete) -and
            (Test-Path -LiteralPath $rollbackRoot)) {
            try {
                if ($null -eq $rollbackTransaction) {
                    throw 'The reset rollback tree has no transaction identity'
                }
                Remove-PSOBBCombatCanaryTransactionTree `
                    -Transaction $rollbackTransaction `
                    -RoleLabel 'combat-canary reset rollback cleanup'
            } catch {
                throw 'Combat-canary reset rollback cleanup retained identity-mismatched evidence'
            }
        }
    }
} finally {
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
