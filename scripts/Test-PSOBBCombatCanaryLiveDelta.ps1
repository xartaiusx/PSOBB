[CmdletBinding()]
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

    [Parameter(Mandatory)]
    [ValidateRange(0, 3600)]
    [uint32]$MaximumPlayTimeDeltaSeconds
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.LiveDelta.ps1')

$script:RepositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..'))
$script:CanonicalRuntimeRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $script:RepositoryRoot 'PSOBB-Runtime')).TrimEnd('\')

function Invoke-PSOBBCombatCanaryIdentityVerifier {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Installation', 'Snapshot')]
        [string]$Target,
        [Parameter(Mandatory)][string]$VerifiedSnapshotPath
    )

    $parameters = @{
        RuntimeRoot = $script:CanonicalRuntimeRoot
        Target = $Target
    }
    if ($Target -ceq 'Snapshot') {
        $parameters.SnapshotPath = $VerifiedSnapshotPath
    }
    if (-not [string]::IsNullOrWhiteSpace(
            $ExpectedTwillsContractSha256)) {
        $parameters.ExpectedTwillsContractSha256 =
            $ExpectedTwillsContractSha256
    }
    if (-not [string]::IsNullOrWhiteSpace(
            $ExpectedSigningPublicKeySpkiSha256)) {
        $parameters.ExpectedSigningPublicKeySpkiSha256 =
            $ExpectedSigningPublicKeySpkiSha256
    }
    if (-not [string]::IsNullOrWhiteSpace(
            $ExpectedBuildContractSha256)) {
        $parameters.ExpectedBuildContractSha256 =
            $ExpectedBuildContractSha256
    }

    try {
        $output = @(& (Join-Path $PSScriptRoot `
                    'Test-PSOBBCombatCanary.ps1') @parameters)
        $results = @($output | Where-Object {
                $_ -is [pscustomobject] -and
                $_.PSObject.Properties.Name -contains 'Valid'
            })
        if ($results.Count -ne 1 -or -not [bool]$results[0].Valid -or
            [string]$results[0].Target -cne $Target) {
            throw 'Inexact verifier result'
        }
        $results[0]
    } catch {
        throw "The combat-canary $Target identity verification failed"
    }
}

function Get-PSOBBCombatCanaryLiveSemanticResult {
    param(
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)][string]$BankPath,
        [Parameter(Mandatory)][string]$ContractPath,
        [Parameter(Mandatory)][string]$ContractSha256,
        [Parameter(Mandatory)][string]$CharacterSha256,
        [Parameter(Mandatory)][string]$BankSha256,
        [Parameter(Mandatory)][int]$InventoryItems
    )

    try {
        $characterOutput = @(& (Join-Path $PSScriptRoot `
                    'Test-PSOBBCharacterBuild.ps1') `
                -Path $CharacterPath -BuildPath $ContractPath)
        $characterResults = @($characterOutput | Where-Object {
                $_ -is [pscustomobject] -and
                $_.PSObject.Properties.Name -contains 'Valid'
            })
        $bankOutput = @(& (Join-Path $PSScriptRoot `
                    'Test-PSOBBTwillsBank.ps1') `
                -Path $BankPath -BuildPath $ContractPath `
                -ExpectedBuildSha256 $ContractSha256)
        $bankResults = @($bankOutput | Where-Object {
                $_ -is [pscustomobject] -and
                $_.PSObject.Properties.Name -contains 'Valid'
            })
        if ($characterResults.Count -ne 1 -or $bankResults.Count -ne 1 -or
            -not [bool]$characterResults[0].Valid -or
            -not [bool]$bankResults[0].Valid -or
            [string]$characterResults[0].BuildSha256 -cne $ContractSha256 -or
            [string]$bankResults[0].BuildSha256 -cne $ContractSha256 -or
            [string]$characterResults[0].CharacterSha256 -cne
                $CharacterSha256 -or
            [string]$bankResults[0].Sha256 -cne $BankSha256 -or
            [int]$characterResults[0].SlotIndex -ne 0 -or
            [int]$characterResults[0].DisplayedLevel -ne 200 -or
            [int]$characterResults[0].InventoryItems -ne $InventoryItems -or
            [string]$bankResults[0].Character -cne 'Twills' -or
            [string]$bankResults[0].Class -cne 'FOnewearl' -or
            [int]$bankResults[0].SlotIndex -ne 0) {
            throw 'Inexact semantic result'
        }
        [pscustomobject]@{
            Character = $characterResults[0]
            Bank = $bankResults[0]
        }
    } catch {
        throw 'The live combat-canary state failed exact Twills semantic verification'
    }
}

function Invoke-PSOBBCombatCanaryStoppedRuntimeLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][scriptblock]$Operation
    )

    $clientOperationMutex = $null
    $lifecycleMutex = $null
    $ownsLifecycleMutex = $false
    try {
        $clientOperationMutex = Enter-PSOBBClientOperationLock `
            -Layout $Layout -TimeoutSeconds 0
        $marker = Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $Layout
        $mutexName = 'Local\PSOBB.Newserv.Start.' +
            ([string]$marker.installationId).Replace('-', '')
        $lifecycleMutex = [System.Threading.Mutex]::new($false, $mutexName)
        try {
            $ownsLifecycleMutex = $lifecycleMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsLifecycleMutex = $true
        }
        if (-not $ownsLifecycleMutex) {
            throw 'Another PSOBB lifecycle or state operation is in progress'
        }

        [void](Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
                -Operation 'Combat-canary live-state verification')
        & $Operation $Layout
    } finally {
        try {
            try {
                if ($ownsLifecycleMutex) {
                    $lifecycleMutex.ReleaseMutex()
                }
            } finally {
                if ($null -ne $lifecycleMutex) {
                    $lifecycleMutex.Dispose()
                }
            }
        } finally {
            if ($null -ne $clientOperationMutex) {
                Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
            }
        }
    }
}

$requestedRuntimeRoot = if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    $script:CanonicalRuntimeRoot
} else {
    [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\')
}
if (-not $requestedRuntimeRoot.Equals(
        $script:CanonicalRuntimeRoot,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The live-delta verifier accepts only the canonical PSOBB runtime'
}

$canonicalLayout = Get-PSOBBLayout -RuntimeRoot $script:CanonicalRuntimeRoot
Invoke-PSOBBCombatCanaryStoppedRuntimeLease -Layout $canonicalLayout `
    -Operation {
param($rootLayout)

[void](Assert-PSOBBServerEnvironmentIsolation -Layout $rootLayout)
$layout = Get-PSOBBServerEnvironmentLayout `
    -Layout $rootLayout -Environment CombatCanary

$installationResult = Invoke-PSOBBCombatCanaryIdentityVerifier `
    -Target Installation -VerifiedSnapshotPath $SnapshotPath
[void](Assert-PSOBBCombatCanaryExactProperties `
        -Value $installationResult `
        -RoleLabel 'combat canary installation verifier result' `
        -Expected @('Valid', 'Target', 'Environment', 'ServerArtifact',
            'ServerComponentId', 'BuildContractSha256',
            'ServerReleaseManifestSha256', 'BaseClientManifestSha256',
            'ClientBindingSha256', 'ConfigurationSha256',
            'TwillsContractSha256', 'SigningPublicKeySpkiSha256'))
if ([string]$installationResult.Environment -cne 'CombatCanary' -or
    [string]$installationResult.ServerArtifact -cne 'StableShadow') {
    throw 'The live-delta verifier requires the exact StableShadow installation'
}

try {
    $installationSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $layout.InstallRecord -Root $layout.EnvironmentRoot `
        -MaximumBytes 256KB -RoleLabel 'combat canary installation record' `
        -RequireProtectedAcl -PassThruSnapshot
    $installation = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $installationSnapshot.Value `
        -RoleLabel 'combat canary installation record'
    [void](Assert-PSOBBCombatCanaryExactProperties -Value $installation `
            -RoleLabel 'combat canary installation record' `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'initializedAtUtc', 'buildContractSha256',
                'serverReleaseManifestSha256', 'baseClientManifestSha256',
                'clientBindingSha256', 'snapshotDirectoryName', 'snapshotId',
                'snapshotManifestSha256', 'stateBindingSha256',
                'twillsContractSha256', 'signingPublicKeySpkiSha256',
                'configurationSha256'))
    if ([int]$installation.schemaVersion -ne 1 -or
        [string]$installation.environment -cne 'CombatCanary' -or
        [string]$installation.environmentId -cne 'combat-canary' -or
        [string]$installation.buildContractSha256 -cne
            [string]$installationResult.BuildContractSha256 -or
        [string]$installation.serverReleaseManifestSha256 -cne
            [string]$installationResult.ServerReleaseManifestSha256 -or
        [string]$installation.baseClientManifestSha256 -cne
            [string]$installationResult.BaseClientManifestSha256 -or
        [string]$installation.clientBindingSha256 -cne
            [string]$installationResult.ClientBindingSha256 -or
        [string]$installation.configurationSha256 -cne
            [string]$installationResult.ConfigurationSha256 -or
        [string]$installation.twillsContractSha256 -cne
            [string]$installationResult.TwillsContractSha256 -or
        [string]$installation.signingPublicKeySpkiSha256 -cne
            [string]$installationResult.SigningPublicKeySpkiSha256 -or
        [string]$installation.snapshotDirectoryName -cnotmatch
            '^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$' -or
        [string]$installation.snapshotId -cnotmatch
            '^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$' -or
        [string]$installation.snapshotManifestSha256 -cnotmatch
            '^[a-f0-9]{64}$' -or
        [string]$installation.stateBindingSha256 -cnotmatch
            '^[a-f0-9]{64}$') {
        throw 'Inexact installation binding'
    }
} catch {
    throw 'The combat-canary installation record is not an exact live-state binding'
}

try {
    $boundSnapshotPath = Assert-PathWithinRoot `
        -Path (Join-Path $layout.Snapshots `
            ([string]$installation.snapshotDirectoryName)) `
        -Root $layout.Snapshots
    $requestedSnapshotPath = Assert-PathWithinRoot `
        -Path $SnapshotPath -Root $layout.Snapshots
    if (-not $boundSnapshotPath.Equals(
            $requestedSnapshotPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Snapshot mismatch'
    }
} catch {
    throw 'The requested snapshot is not the exact installation-bound snapshot'
}

$snapshotResult = Invoke-PSOBBCombatCanaryIdentityVerifier `
    -Target Snapshot -VerifiedSnapshotPath $boundSnapshotPath
[void](Assert-PSOBBCombatCanaryExactProperties -Value $snapshotResult `
        -RoleLabel 'combat canary snapshot verifier result' `
        -Expected @('Valid', 'Target', 'SnapshotId', 'SnapshotPath',
            'ManifestSha256', 'SourceBackupId',
            'SourceBackupManifestSha256', 'TwillsContractSha256',
            'SigningPublicKeySpkiSha256', 'Character', 'Class', 'SlotIndex',
            'DisplayedLevel', 'StateFiles'))
if ([string]$snapshotResult.SnapshotId -cne
        [string]$installation.snapshotId -or
    [string]$snapshotResult.ManifestSha256 -cne
        [string]$installation.snapshotManifestSha256 -or
    [string]$snapshotResult.TwillsContractSha256 -cne
        [string]$installation.twillsContractSha256 -or
    [string]$snapshotResult.SigningPublicKeySpkiSha256 -cne
        [string]$installation.signingPublicKeySpkiSha256 -or
    [string]$snapshotResult.Character -cne 'Twills' -or
    [string]$snapshotResult.Class -cne 'FOnewearl' -or
    [int]$snapshotResult.SlotIndex -ne 0 -or
    [int]$snapshotResult.DisplayedLevel -ne 200) {
    throw 'The verified snapshot is not the exact Twills installation binding'
}

try {
    $stateBindingPath = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot 'state-binding.json') `
        -Root $layout.EnvironmentRoot
    $stateBindingSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $stateBindingPath -Root $layout.EnvironmentRoot `
        -MaximumBytes 256KB `
        -ExpectedSha256 ([string]$installation.stateBindingSha256) `
        -RoleLabel 'combat canary state binding' -RequireProtectedAcl `
        -PassThruSnapshot
    $stateBinding = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $stateBindingSnapshot.Value `
        -RoleLabel 'combat canary state binding'
    [void](Assert-PSOBBCombatCanaryExactProperties -Value $stateBinding `
            -RoleLabel 'combat canary state binding' `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'restoredAtUtc', 'snapshotDirectoryName', 'snapshotId',
                'snapshotManifestSha256', 'twillsContractSha256',
                'signingPublicKeySpkiSha256', 'stateFiles'))
    if ([int]$stateBinding.schemaVersion -ne 1 -or
        [string]$stateBinding.environment -cne 'CombatCanary' -or
        [string]$stateBinding.environmentId -cne 'combat-canary' -or
        [string]$stateBinding.snapshotDirectoryName -cne
            [string]$installation.snapshotDirectoryName -or
        [string]$stateBinding.snapshotId -cne
            [string]$installation.snapshotId -or
        [string]$stateBinding.snapshotManifestSha256 -cne
            [string]$installation.snapshotManifestSha256 -or
        [string]$stateBinding.twillsContractSha256 -cne
            [string]$installation.twillsContractSha256 -or
        [string]$stateBinding.signingPublicKeySpkiSha256 -cne
            [string]$installation.signingPublicKeySpkiSha256 -or
        [int]$stateBinding.stateFiles -ne [int]$snapshotResult.StateFiles) {
        throw 'Inexact state binding'
    }
} catch {
    throw 'The combat-canary state binding is not exact'
}

try {
    $manifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath (Join-Path $boundSnapshotPath 'manifest.json') `
        -Root $boundSnapshotPath -MaximumBytes 256KB `
        -ExpectedSha256 ([string]$snapshotResult.ManifestSha256) `
        -RoleLabel 'sealed snapshot manifest' -RequireProtectedAcl `
        -PassThruSnapshot
    $manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $manifestSnapshot.Value -RoleLabel 'sealed snapshot manifest'
    $stateEntries = @($manifest.files | Where-Object {
            [string]$_.path -cmatch '^state/system/'
        })
    [void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
            -Entries $stateEntries -Scope State)
    if ($stateEntries.Count -ne [int]$snapshotResult.StateFiles) {
        throw 'Inexact state payload count'
    }
} catch {
    throw 'The sealed snapshot state index is not exact'
}

$systemRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Server 'system') -Root $layout.Server
$expectedStatePaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $stateEntries) {
    $relative = ([string]$entry.path).Substring('state/system/'.Length)
    if (-not $expectedStatePaths.Add($relative)) {
        throw 'The sealed state index contains colliding installed paths'
    }
}

try {
    $actualStatePaths = @(foreach ($directoryName in @(
                'licenses', 'players', 'teams')) {
            $directory = Assert-PathWithinRoot `
                -Path (Join-Path $systemRoot $directoryName) -Root $systemRoot
            Get-ChildItem -Force -LiteralPath $directory -Recurse -File `
                -ErrorAction Stop | ForEach-Object {
                    $safePath = Assert-PathWithinRoot `
                        -Path $_.FullName -Root $systemRoot
                    [System.IO.Path]::GetRelativePath(
                        $systemRoot, $safePath).Replace('\', '/')
                }
        })
    if ($actualStatePaths.Count -ne $expectedStatePaths.Count -or
        @($actualStatePaths | Where-Object {
                -not $expectedStatePaths.Contains($_)
            }).Count -ne 0) {
        throw 'Inexact installed state inventory'
    }
    foreach ($directoryName in @('licenses', 'players', 'teams')) {
        $prefix = $directoryName + '/'
        $directoryFiles = @($stateEntries | ForEach-Object {
                ([string]$_.path).Substring('state/system/'.Length)
            } | Where-Object {
                $_.StartsWith(
                    $prefix,
                    [System.StringComparison]::OrdinalIgnoreCase)
            } | ForEach-Object { $_.Substring($prefix.Length) })
        $expectedDirectories = Get-PSOBBCombatCanaryExpectedDirectories `
            -FilePaths $directoryFiles
        [void](Assert-PSOBBCombatCanaryExactDirectoryInventory `
                -Root (Join-Path $systemRoot $directoryName) `
                -ExpectedDirectories $expectedDirectories `
                -RoleLabel 'installed combat canary state' -RequireProtected)
    }
} catch {
    throw 'The installed combat-canary state inventory is missing, extra, or unsafe'
}

$delta = $null
$referenceCharacterSha256 = $null
$candidateCharacterSha256 = $null
$installedCharacterPath = $null
$installedBankPath = $null
$installedBankSha256 = $null
$exactStateFiles = 0
foreach ($entry in $stateEntries) {
    $role = [string]$entry.role
    try {
        $relative = ([string]$entry.path).Substring('state/system/'.Length)
        $referencePath = Assert-PathWithinRoot `
            -Path (Join-Path $boundSnapshotPath `
                (([string]$entry.path).Replace('/', '\'))) `
            -Root $boundSnapshotPath
        $installedPath = Assert-PathWithinRoot `
            -Path (Join-Path $systemRoot ($relative.Replace('/', '\'))) `
            -Root $systemRoot
        $rolePolicy = Get-PSOBBCombatCanaryPayloadRolePolicy -Role $role

        if ($role -ceq 'twills-character') {
            if ([int64]$entry.size -ne 0x399C -or
                $null -ne $installedCharacterPath) {
                throw 'Inexact character role'
            }
            $installedCharacterPath = $installedPath
            $referenceCharacterSnapshot =
                Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
                    -LiteralPath $referencePath -Root $boundSnapshotPath `
                    -MaximumBytes ([long]$rolePolicy.MaximumBytes) `
                    -ExpectedLength 0x399C `
                    -ExpectedSha256 ([string]$entry.sha256) `
                    -RoleLabel 'sealed reference character' `
                    -RequireProtectedAcl `
                    -Consumer {
                        param([byte[]]$ReferenceBytes)
                        $candidateCharacterSnapshot =
                            Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
                                -LiteralPath $installedPath -Root $systemRoot `
                                -MaximumBytes ([long]$rolePolicy.MaximumBytes) `
                                -ExpectedLength 0x399C `
                                -RoleLabel 'installed live character' `
                                -RequireProtectedAcl `
                                -Consumer {
                                    param([byte[]]$CandidateBytes)
                                    Compare-PSOBBCombatCanaryCharacterLiveDelta `
                                        -ReferenceBytes $ReferenceBytes `
                                        -CandidateBytes $CandidateBytes `
                                        -MaximumPlayTimeDeltaSeconds `
                                            $MaximumPlayTimeDeltaSeconds
                                }
                        [pscustomobject]@{
                            Delta = $candidateCharacterSnapshot.Value
                            CandidateSha256 = $candidateCharacterSnapshot.Sha256
                        }
                    }
            $referenceCharacterSha256 = $referenceCharacterSnapshot.Sha256
            $candidateCharacterSha256 =
                $referenceCharacterSnapshot.Value.CandidateSha256
            $delta = $referenceCharacterSnapshot.Value.Delta
        } else {
            $installedSnapshot =
                Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
                    -LiteralPath $installedPath -Root $systemRoot `
                    -MaximumBytes ([long]$rolePolicy.MaximumBytes) `
                    -ExpectedLength ([int64]$entry.size) `
                    -ExpectedSha256 ([string]$entry.sha256) `
                    -RoleLabel 'installed exact state payload' `
                    -RequireProtectedAcl `
                    -Consumer { param([byte[]]$Bytes) $Bytes.Length -gt 0 }
            $exactStateFiles++
            if ($role -ceq 'twills-bank') {
                if ($null -ne $installedBankPath) {
                    throw 'Duplicate bank role'
                }
                $installedBankPath = $installedPath
                $installedBankSha256 = $installedSnapshot.Sha256
            }
        }
    } catch {
        throw "Live-state readback failed for role '$role'"
    }
}
if ($null -eq $delta -or
    [string]::IsNullOrWhiteSpace($referenceCharacterSha256) -or
    [string]::IsNullOrWhiteSpace($candidateCharacterSha256) -or
    [string]::IsNullOrWhiteSpace($installedCharacterPath) -or
    [string]::IsNullOrWhiteSpace($installedBankPath) -or
    [string]::IsNullOrWhiteSpace($installedBankSha256) -or
    $exactStateFiles -ne ($stateEntries.Count - 1)) {
    throw 'The installed combat-canary state role set is incomplete'
}

$contractPath = Join-Path $script:RepositoryRoot `
    'config\twills-fonewearl-build.json'
[void](Get-PSOBBCombatCanaryLiveSemanticResult `
        -CharacterPath $installedCharacterPath -BankPath $installedBankPath `
        -ContractPath $contractPath `
        -ContractSha256 ([string]$installation.twillsContractSha256) `
        -CharacterSha256 $candidateCharacterSha256 `
        -BankSha256 $installedBankSha256 `
        -InventoryItems ([int]$delta.InventoryItems))
[void](Assert-PSOBBGlobalStoppedRuntime -Layout $rootLayout `
        -Operation 'Combat-canary live-state verification completion')

[pscustomobject]@{
    Valid = $true
    Target = 'LiveDelta'
    Environment = 'CombatCanary'
    ServerArtifact = 'StableShadow'
    SnapshotId = [string]$snapshotResult.SnapshotId
    SnapshotManifestSha256 = [string]$snapshotResult.ManifestSha256
    StateBindingSha256 = [string]$stateBindingSnapshot.Sha256
    BuildContractSha256 = [string]$installationResult.BuildContractSha256
    TwillsContractSha256 = [string]$installationResult.TwillsContractSha256
    SigningPublicKeySpkiSha256 =
        [string]$installationResult.SigningPublicKeySpkiSha256
    Character = 'Twills'
    Class = 'FOnewearl'
    SlotIndex = 0
    DisplayedLevel = 200
    StateFiles = $stateEntries.Count
    ExactStateFiles = $exactStateFiles
    InventoryItems = [int]$delta.InventoryItems
    ChangedBytes = [int]$delta.ChangedBytes
    InventoryItemIdChangedBytes =
        [int]$delta.InventoryItemIdChangedBytes
    PlayTimeChangedBytes = [int]$delta.PlayTimeChangedBytes
    PlayTimeDeltaSeconds = [uint32]$delta.PlayTimeDeltaSeconds
    MaximumPlayTimeDeltaSeconds =
        [uint32]$delta.MaximumPlayTimeDeltaSeconds
    ReferenceCharacterSha256 = $referenceCharacterSha256
    CandidateCharacterSha256 = $candidateCharacterSha256
}
}
