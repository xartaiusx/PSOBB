[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,

    [string]$StableBackupPath,

    [ValidateRange(1, 1440)]
    [int]$MaximumBackupAgeMinutes = 15,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedTwillsContractSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSigningPublicKeySpkiSha256,

    [Parameter(DontShow = $true)]
    [switch]$InternalTestCreatePublishCollision,

    [Parameter(DontShow = $true)]
    [string]$InternalTestFaultToken,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestAfterPayloadSourceLease,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestBeforePayloadCopy,

    [Parameter(DontShow = $true)]
    [scriptblock]$InternalTestAfterPublishMove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

$script:RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:ContractFileName = 'twills-fonewearl-build.json'

function Assert-PSOBBCombatSnapshotLayout {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][ValidateSet('Stable', 'CombatCanary')]
        [string]$Environment
    )

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
    if ($missing.Count -ne 0 -or [string]$Value.Environment -cne $Environment) {
        throw "The $Environment server-environment layout contract is incomplete"
    }
    $Value
}

function Assert-PSOBBCombatSnapshotStopped {
    $running = @(Get-Process -ErrorAction Stop | Where-Object {
            $_.ProcessName -like 'newserv*' -or
            $_.ProcessName -in @('Psobb', 'online', 'option')
        })
    if ($running.Count -gt 0) {
        $identities = @($running | Sort-Object ProcessName, Id | ForEach-Object {
                '{0} PID {1}' -f $_.ProcessName, $_.Id
            })
        throw ('Combat-canary state mutation requires every PSOBB/newserv process ' +
            "to be stopped. Running: $($identities -join ', ')")
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
        throw ('Combat-canary state mutation requires ports 11000, 12000, and ' +
            "12001 to have no listeners. Listening: $($evidence -join ', ')")
    }
    $true
}

function Assert-PSOBBCombatSnapshotInternalFaultGate {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Marker
    )

    $requested = $InternalTestCreatePublishCollision.IsPresent -or
        $null -ne $InternalTestAfterPayloadSourceLease -or
        $null -ne $InternalTestBeforePayloadCopy -or
        $null -ne $InternalTestAfterPublishMove -or
        -not [string]::IsNullOrWhiteSpace($InternalTestFaultToken)
    if (-not $requested) { return $true }
    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root)
    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $fixtureName = [System.IO.Path]::GetFileName($root.TrimEnd('\'))
    $fixtureMarkerPath = Join-Path $root '.combat-canary-state-test.json'
    if ((-not $InternalTestCreatePublishCollision.IsPresent -and
            $null -eq $InternalTestAfterPayloadSourceLease -and
            $null -eq $InternalTestBeforePayloadCopy -and
            $null -eq $InternalTestAfterPublishMove) -or
        -not $root.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fixtureName -cnotmatch '^psobb-combat-canary-state-test-[a-f0-9]{32}$' -or
        [string]$Marker.installationId -cne $InternalTestFaultToken -or
        -not (Test-Path -LiteralPath $fixtureMarkerPath -PathType Leaf)) {
        throw 'Internal snapshot fault injection is restricted to an explicit temporary fixture'
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
        throw 'Internal snapshot fault injection requires an ordinary protected fixture'
    }
    $fixtureMarkerJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $fixtureMarkerPath `
        -Root $root -MaximumBytes 4KB `
        -RoleLabel 'internal snapshot fault fixture marker'
    $fixtureMarker = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $fixtureMarkerJson `
        -RoleLabel 'internal snapshot fault fixture marker'
    $properties = @($fixtureMarker.PSObject.Properties.Name | Sort-Object)
    if (($properties -join ',') -cne 'installationId,purpose,schemaVersion' -or
        [int]$fixtureMarker.schemaVersion -ne 1 -or
        [string]$fixtureMarker.purpose -cne
            'combat-canary-state-transaction-test' -or
        [string]$fixtureMarker.installationId -cne [string]$Marker.installationId) {
        throw 'The internal snapshot fault fixture marker is not bound to this runtime'
    }
    $true
}

function Assert-PSOBBCombatSnapshotProtectedTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    try {
        $safeRoot = Assert-PathWithinRoot -Path $Path -Root $Root
        $pending = [System.Collections.Generic.Queue[string]]::new()
        $pending.Enqueue($safeRoot)
        while ($pending.Count -gt 0) {
            $directory = Assert-PathWithinRoot -Path $pending.Dequeue() -Root $safeRoot
            $item = Get-Item -Force -LiteralPath $directory -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not (Test-PSOBBProtectedAcl -Path $directory)) {
                throw 'Unsafe protected tree'
            }
            foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory)) {
                $safeChild = Assert-PathWithinRoot -Path $child.FullName -Root $safeRoot
                if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    -not (Test-PSOBBProtectedAcl -Path $safeChild)) {
                    throw 'Unsafe protected tree item'
                }
                if ($child.PSIsContainer) { $pending.Enqueue($safeChild) }
            }
        }
        $safeRoot
    } catch {
        throw 'The source backup protected tree is unreadable or unsafe'
    }
}

function Get-PSOBBCombatSnapshotTrustFingerprint {
    param([string]$ExplicitFingerprint)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitFingerprint)) {
        return $ExplicitFingerprint.ToLowerInvariant()
    }
    $trustJson = Read-PSOBBCombatCanaryStrictJsonObject -LiteralPath (
        Join-Path $script:RepositoryRoot 'config\release-trust.json') `
        -Root $script:RepositoryRoot -MaximumBytes 256KB `
        -RoleLabel 'release trust policy'
    $trust = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $trustJson -RoleLabel 'release trust policy'
    $active = @($trust.keys | Where-Object {
            [string]$_.id -ceq [string]$trust.activeKeyId
        })
    if ([int]$trust.schemaVersion -ne 1 -or $active.Count -ne 1 -or
        [string]$active[0].spkiSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The release trust policy does not identify one local acceptance key'
    }
    [string]$active[0].spkiSha256
}

function Get-PSOBBCombatSnapshotKey {
    param(
        [Parameter(Mandatory)]$StableLayout,
        [Parameter(Mandatory)][string]$ExpectedFingerprint
    )

    $publicPath = Assert-PathWithinRoot `
        -Path (Join-Path $StableLayout.EnvironmentRoot 'release-public-key.pem') `
        -Root $StableLayout.Root
    $privatePath = Assert-PathWithinRoot `
        -Path (Join-Path $StableLayout.Secrets 'local-acceptance-signing-private.pem') `
        -Root $StableLayout.Root
    if (-not (Test-PSOBBProtectedAcl -Path $privatePath)) {
        throw 'The local acceptance signing material is missing or unprotected'
    }
    $publicSnapshot = Read-PSOBBCombatCanaryStrictUtf8Text `
        -LiteralPath $publicPath -Root $StableLayout.Root -MaximumBytes 16KB `
        -RoleLabel 'local acceptance public key' -PassThruSnapshot
    [void](Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
            -LiteralPath $privatePath -Root $StableLayout.Root -MaximumBytes 16KB `
            -RoleLabel 'local acceptance private key' `
            -Consumer { param([byte[]]$Bytes) $Bytes.Length -gt 0 })
    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportFromPem([string]$publicSnapshot.Value)
        $fingerprint = ([Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData(
                    $verifier.ExportSubjectPublicKeyInfo()))).ToLowerInvariant()
    } catch {
        throw 'The local acceptance public key is not valid ECDSA PEM'
    } finally {
        $verifier.Dispose()
    }
    if ($fingerprint -cne $ExpectedFingerprint) {
        throw 'The local acceptance public key does not match its explicit trust pin'
    }
    [pscustomobject]@{
        PublicPath = $publicPath
        PrivatePath = $privatePath
        PublicText = [string]$publicSnapshot.Value
        PublicLength = [int64]$publicSnapshot.Length
        PublicSha256 = [string]$publicSnapshot.Sha256
        Fingerprint = $fingerprint
    }
}

function Get-PSOBBCombatSnapshotRole {
    param([Parameter(Mandatory)][string]$BackupRelativePath)

    if ($BackupRelativePath -cmatch '^system/licenses/[^/\\:]+\.json$') {
        return 'license-state'
    }
    if ($BackupRelativePath -cmatch '^system/players/[^/\\:]+\.psochar$') {
        return 'twills-character'
    }
    if ($BackupRelativePath -cmatch '^system/players/[^/\\:]+\.psobank$') {
        return 'twills-bank'
    }
    if ($BackupRelativePath -cmatch '^system/players/[^/\\:]+\.psosys$') {
        return 'twills-system'
    }
    if ($BackupRelativePath -cmatch '^system/players/[^/\\:]+\.psocard$') {
        return 'twills-card'
    }
    if ($BackupRelativePath -cmatch '^system/teams/[^/\\:]+\.json$') {
        return 'team-state'
    }
    $null
}

function Assert-PSOBBCombatSnapshotAccountBinding {
    param(
        [Parameter(Mandatory)]$Roles,
        [Parameter(Mandatory)][string]$BackupRoot
    )

    $characterName = [System.IO.Path]::GetFileName(
        [string]$Roles['twills-character'][0].BackupRelativePath)
    if ($characterName -cnotmatch
        '^player_(?<account>[a-z][a-z0-9_-]{2,15})_0\.psochar$') {
        throw 'The stable backup character path is not an exact slot-0 BB account path'
    }
    $accountName = [string]$Matches.account
    $expectedNames = [ordered]@{
        'twills-bank' = "player_${accountName}_0.psobank"
        'twills-system' = "system_${accountName}.psosys"
        'twills-card' = "guild_cards_${accountName}.psocard"
    }
    foreach ($role in $expectedNames.Keys) {
        if ([System.IO.Path]::GetFileName(
                [string]$Roles[$role][0].BackupRelativePath) -cne
            [string]$expectedNames[$role]) {
            throw 'The stable backup protected state does not belong to one BB account'
        }
    }

    $licenseMatches = 0
    $licenseIdentities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($license in @($Roles['license-state'])) {
        try {
            $licenseText = Read-PSOBBCombatCanaryStrictUtf8Text `
                -LiteralPath ([string]$license.Source) `
                -Root $BackupRoot -MaximumBytes 256KB `
                -ExpectedLength ([int64]$license.Size) `
                -ExpectedSha256 ([string]$license.Sha256) `
                -RoleLabel 'stable backup protected license state'
            $state = Read-PSOBBCombatCanaryStrictJsonObject `
                -Text $licenseText -RoleLabel 'stable backup protected license state'
            $identities = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
                    -State $state -RawText $licenseText `
                    -ExpectedAccountName $accountName `
                    -RoleLabel 'stable backup protected license state')
        } catch {
            throw 'The stable backup contains invalid protected license JSON'
        }
        foreach ($identity in $identities) {
            if (-not [bool]$identity.IsSafeAccountName -or
                [string]$identity.IdentitySha256 -cnotmatch '^[a-f0-9]{64}$' -or
                -not $licenseIdentities.Add(
                    [string]$identity.IdentitySha256)) {
                throw 'The stable backup has duplicate or invalid BB license identities'
            }
            if ([bool]$identity.MatchesExpectedAccount) { $licenseMatches++ }
        }
    }
    if ($licenseMatches -ne 1) {
        throw 'The stable backup does not bind exactly one BB license to Twills state'
    }
    $true
}

function Get-PSOBBCombatSnapshotSemanticResult {
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
        throw 'The fresh stable backup failed independent Twills semantic verification'
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
        throw 'The fresh stable backup is not exact slot-0 Twills FOnewearl state'
    }
    [pscustomobject]@{ Character = $character[0]; Bank = $bank[0] }
}

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if (-not (Get-Command Get-PSOBBServerEnvironmentLayout -ErrorAction SilentlyContinue)) {
    throw 'Get-PSOBBServerEnvironmentLayout is required for combat-canary snapshots'
}
$stableLayout = Assert-PSOBBCombatSnapshotLayout -Value (
    Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment Stable) `
    -Environment Stable
$canaryLayout = Assert-PSOBBCombatSnapshotLayout -Value (
    Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment CombatCanary) `
    -Environment CombatCanary
[void](Assert-PSOBBServerEnvironmentIsolation -Layout $rootLayout)
[void](Assert-PSOBBCombatSnapshotStopped)
$marker = Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $rootLayout

$contractPath = Join-Path $script:RepositoryRoot ('config\' + $script:ContractFileName)
$expectedContractHash = if ([string]::IsNullOrWhiteSpace(
        $ExpectedTwillsContractSha256)) { '' } else {
    $ExpectedTwillsContractSha256.ToLowerInvariant()
}
$contractSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
    -LiteralPath $contractPath -Root $script:RepositoryRoot -MaximumBytes 128KB `
    -ExpectedSha256 $expectedContractHash -PassThruSnapshot `
    -RoleLabel 'tracked Twills contract'
$contractHash = [string]$contractSnapshot.Sha256
$contractJson = $contractSnapshot.Value
$contract = ConvertTo-PSOBBCombatCanaryPowerShellObject `
    -JsonObject $contractJson -RoleLabel 'tracked Twills contract'
if ([int]$contract.schemaVersion -ne 2 -or
    [string]$contract.character.name -cne 'Twills' -or
    [int]$contract.character.classId -ne 8 -or
    [string]$contract.character.className -cne 'FOnewearl' -or
    [int]$contract.character.slotIndex -ne 0) {
    throw 'The tracked contract is not exact slot-0 Twills FOnewearl'
}
$trustFingerprint = Get-PSOBBCombatSnapshotTrustFingerprint `
    -ExplicitFingerprint $ExpectedSigningPublicKeySpkiSha256
$signingKey = Get-PSOBBCombatSnapshotKey `
    -StableLayout $stableLayout -ExpectedFingerprint $trustFingerprint

if ([string]::IsNullOrWhiteSpace($StableBackupPath)) {
    if (-not $PSCmdlet.ShouldProcess(
            $stableLayout.Backups,
            'Create a fresh protected schema-3 stable backup for the combat-canary snapshot')) {
        return [pscustomobject]@{
            Created = $false
            WhatIf = $true
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
            TwillsContractSha256 = $contractHash
        }
    }
    $backupResult = & (Join-Path $PSScriptRoot 'Backup-PSOBB.ps1') `
        -RuntimeRoot $rootLayout.Root -BackupKind state -Retention 7
    if ($null -eq $backupResult) {
        throw 'A fresh stable schema-3 backup was not created'
    }
    $StableBackupPath = [string]$backupResult.BackupPath
}
$backupRoot = Assert-PathWithinRoot -Path $StableBackupPath -Root $stableLayout.Backups
[void](Assert-PSOBBCombatSnapshotProtectedTree `
        -Path $backupRoot -Root $stableLayout.Backups)
$backupManifestPath = Join-Path $backupRoot 'manifest.json'
$backupManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
    -LiteralPath $backupManifestPath -Root $backupRoot -MaximumBytes 16MB `
    -RoleLabel 'stable backup manifest' -PassThruSnapshot
$backupManifestJson = $backupManifestSnapshot.Value
$backupManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
    -JsonObject $backupManifestJson -RoleLabel 'stable backup manifest'
$backupManifestHash = [string]$backupManifestSnapshot.Sha256
try {
    $backupValidation = & (Join-Path $PSScriptRoot 'Restore-PSOBB.ps1') `
        -RuntimeRoot $rootLayout.Root -BackupPath $backupRoot -ValidateOnly
} catch {
    throw 'The selected stable backup failed independent schema-3 validation'
}
$validatedManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
    -LiteralPath $backupManifestPath -Root $backupRoot -MaximumBytes 16MB `
    -ExpectedLength ([int64]$backupManifestSnapshot.Length) `
    -ExpectedSha256 $backupManifestHash -PassThruSnapshot `
    -RoleLabel 'stable backup manifest after validation'
if ($null -eq $backupValidation -or
    [string]$backupValidation.ManifestSha256 -cne $backupManifestHash -or
    [string]$validatedManifestSnapshot.Sha256 -cne $backupManifestHash) {
    throw 'The selected stable backup manifest changed during validation'
}
$backupCreatedAt = [DateTimeOffset]::MinValue
$backupTimestampValid = $false
if ($backupManifest.createdAtUtc -is [DateTime]) {
    $backupCreatedAt = [DateTimeOffset]([DateTime]$backupManifest.createdAtUtc).ToUniversalTime()
    $backupTimestampValid = $true
} elseif ($backupManifest.createdAtUtc -is [DateTimeOffset]) {
    $backupCreatedAt = ([DateTimeOffset]$backupManifest.createdAtUtc).ToUniversalTime()
    $backupTimestampValid = $true
} else {
    $backupTimestampValid = [DateTimeOffset]::TryParse(
        [string]$backupManifest.createdAtUtc, [ref]$backupCreatedAt)
}
$backupAgeMinutes = if ($backupTimestampValid) {
    ([DateTimeOffset]::UtcNow - $backupCreatedAt.ToUniversalTime()).TotalMinutes
} else {
    [double]::PositiveInfinity
}
if ([int]$backupManifest.schemaVersion -ne 3 -or
    [string]$backupManifest.backupKind -cne 'state' -or
    [string]$backupManifest.clientPatchState.profile -cne 'baseline' -or
    -not $backupTimestampValid -or $backupAgeMinutes -lt -1 -or
    $backupAgeMinutes -gt $MaximumBackupAgeMinutes) {
    throw 'The selected stable backup failed the schema-3 baseline freshness gate'
}

$selectedFiles = [System.Collections.Generic.List[object]]::new()
$roles = @{}
$seenPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @($backupManifest.files)) {
    $relative = [string]$entry.path
    if ($relative -cmatch '^system/(licenses|players|teams)/') {
        $role = Get-PSOBBCombatSnapshotRole -BackupRelativePath $relative
        if ([string]::IsNullOrWhiteSpace($role) -or -not $seenPaths.Add($relative)) {
            throw 'The stable backup contains disallowed or case-colliding protected state'
        }
        try {
            $source = Assert-PathWithinRoot `
                -Path (Join-Path $backupRoot ($relative.Replace('/', '\'))) `
                -Root $backupRoot
        } catch {
            throw "The stable backup payload for role '$role' is unreadable or unsafe"
        }
        $selected = [pscustomobject]@{
            Source = $source
            BackupRelativePath = $relative
            SnapshotRelativePath = 'state/' + $relative
            Role = $role
            Size = [int64]$entry.size
            Sha256 = [string]$entry.sha256
        }
        $selectedFiles.Add($selected)
        if (-not $roles.ContainsKey($role)) {
            $roles[$role] = [System.Collections.Generic.List[object]]::new()
        }
        $roles[$role].Add($selected)
    }
}
foreach ($role in @('twills-character', 'twills-bank', 'twills-system',
        'twills-card', 'team-state')) {
    if (-not $roles.ContainsKey($role) -or $roles[$role].Count -ne 1) {
        throw "The stable backup does not contain exactly one required '$role' payload"
    }
}
if (-not $roles.ContainsKey('license-state') -or $roles['license-state'].Count -lt 1) {
    throw 'The stable backup does not contain its complete protected license state'
}
[void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
        -Entries $selectedFiles.ToArray() -Scope State `
        -RoleProperty Role -SizeProperty Size)
[void](Assert-PSOBBCombatSnapshotAccountBinding `
        -Roles $roles -BackupRoot $backupRoot)
$semantic = Get-PSOBBCombatSnapshotSemanticResult `
    -CharacterPath ([string]$roles['twills-character'][0].Source) `
    -BankPath ([string]$roles['twills-bank'][0].Source) `
    -ContractPath $contractPath -ContractHash $contractHash

$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 8)
$snapshotName = "twills-slot0-$stamp-$suffix"
$snapshotRoot = Assert-PathWithinRoot `
    -Path (Join-Path $canaryLayout.Snapshots $snapshotName) `
    -Root $canaryLayout.Snapshots
$partialRoot = Assert-PathWithinRoot `
    -Path ($snapshotRoot + '.partial-' + [Guid]::NewGuid().ToString('N')) `
    -Root $canaryLayout.Snapshots
if (-not $PSCmdlet.ShouldProcess(
        $canaryLayout.Snapshots,
        'Publish one signed protected slot-0 Twills combat-canary snapshot')) {
    return [pscustomobject]@{
        Created = $false
        WhatIf = $true
        Character = 'Twills'
        Class = 'FOnewearl'
        SlotIndex = 0
        TwillsContractSha256 = $contractHash
    }
}

[void](Assert-PSOBBCombatSnapshotInternalFaultGate `
        -Layout $rootLayout -Marker $marker)
$mutexName = 'Local\PSOBB.Newserv.Start.' +
    ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
$published = $false
$partialTransaction = $null
$partialMarkerPresent = $false
try {
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (-not $ownsMutex) {
        throw 'Another PSOBB lifecycle operation is in progress'
    }
    [void](Assert-PSOBBCombatSnapshotStopped)
    if (-not (Test-Path -LiteralPath $canaryLayout.Snapshots -PathType Container)) {
        New-Item -ItemType Directory -Path $canaryLayout.Snapshots -Force | Out-Null
    }
    Set-PSOBBProtectedAcl -Path $canaryLayout.Snapshots
    $partialTransaction = New-PSOBBCombatCanaryTransactionTree `
        -Path $partialRoot -Root $canaryLayout.Snapshots `
        -TransactionId ([Guid]::NewGuid().ToString('N')) `
        -Purpose 'snapshot-stage'
    $partialMarkerPresent = $true
    $manifestFiles = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $InternalTestBeforePayloadCopy) {
        & $InternalTestBeforePayloadCopy
    }
    foreach ($selected in $selectedFiles) {
        try {
            $destination = Assert-PathWithinRoot `
                -Path (Join-Path $partialRoot (
                    $selected.SnapshotRelativePath.Replace('/', '\'))) `
                -Root $partialRoot
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) `
                -Force | Out-Null
            $rolePolicy = Get-PSOBBCombatCanaryPayloadRolePolicy `
                -Role ([string]$selected.Role)
            Copy-PSOBBCombatCanaryBoundedFileSnapshot `
                -Source ([string]$selected.Source) -SourceRoot $backupRoot `
                -Destination $destination -DestinationRoot $partialRoot `
                -MaximumBytes ([long]$rolePolicy.MaximumBytes) `
                -ExpectedLength ([long]$selected.Size) `
                -ExpectedSha256 ([string]$selected.Sha256) `
                -RoleLabel ("snapshot $($selected.Role) payload") `
                -InternalTestAfterSourceLease `
                    $InternalTestAfterPayloadSourceLease | Out-Null
        } catch {
            throw "Snapshot copy failed for protected role '$($selected.Role)'"
        }
        $manifestFiles.Add([ordered]@{
                path = $selected.SnapshotRelativePath
                role = $selected.Role
                size = $selected.Size
                sha256 = $selected.Sha256
            })
    }
    $archivedContractPath = Assert-PathWithinRoot `
        -Path (Join-Path $partialRoot ('contract\' + $script:ContractFileName)) `
        -Root $partialRoot
    $archivedPublicKeyPath = Assert-PathWithinRoot `
        -Path (Join-Path $partialRoot 'trust\signing-public-key.pem') `
        -Root $partialRoot
    New-Item -ItemType Directory -Path (Split-Path -Parent $archivedContractPath),
        (Split-Path -Parent $archivedPublicKeyPath) -Force | Out-Null
    $contractPolicy = Get-PSOBBCombatCanaryPayloadRolePolicy `
        -Role 'twills-contract'
    Copy-PSOBBCombatCanaryBoundedFileSnapshot `
        -Source $contractPath -SourceRoot $script:RepositoryRoot `
        -Destination $archivedContractPath -DestinationRoot $partialRoot `
        -MaximumBytes ([long]$contractPolicy.MaximumBytes) `
        -ExpectedLength ([long]$contractSnapshot.Length) `
        -ExpectedSha256 $contractHash `
        -RoleLabel 'snapshot Twills contract' | Out-Null
    $archivedPublicKeyBytes = [System.Text.UTF8Encoding]::new(
        $false, $true).GetBytes([string]$signingKey.PublicText)
    try {
        Write-PSOBBCombatCanaryNoClobberBytes `
            -Destination $archivedPublicKeyPath -DestinationRoot $partialRoot `
            -Bytes $archivedPublicKeyBytes `
            -ExpectedSha256 ([string]$signingKey.PublicSha256) `
            -RoleLabel 'snapshot signing public key' | Out-Null
    } finally {
        [Array]::Clear(
            $archivedPublicKeyBytes, 0, $archivedPublicKeyBytes.Length)
    }
    $manifestFiles.Add([ordered]@{
            path = 'contract/' + $script:ContractFileName
            role = 'twills-contract'
            size = [int64]$contractSnapshot.Length
            sha256 = $contractHash
        })
    $manifestFiles.Add([ordered]@{
            path = 'trust/signing-public-key.pem'
            role = 'signing-public-key'
            size = [int64]$signingKey.PublicLength
            sha256 = [string]$signingKey.PublicSha256
        })
    [void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
            -Entries $manifestFiles.ToArray() -Scope Snapshot)
    $manifest = [ordered]@{
        '$schema' = 'https://psobb.local/schemas/combat-canary-snapshot.schema.json'
        schemaVersion = 1
        snapshotId = [Guid]::NewGuid().ToString('D')
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        sourceBackup = [ordered]@{
            backupId = [string]$backupManifest.backupId
            backupKind = 'state'
            createdAtUtc = [string]$backupManifest.createdAtUtc
            manifestSha256 = $backupManifestHash
            clientPatchProfile = 'baseline'
        }
        twillsContract = [ordered]@{
            path = 'contract/' + $script:ContractFileName
            size = [int64]$contractSnapshot.Length
            sha256 = $contractHash
            profileId = [string]$semantic.Character.ProfileId
        }
        character = [ordered]@{
            name = 'Twills'
            classId = 8
            className = 'FOnewearl'
            slotIndex = 0
        }
        semanticSummary = [ordered]@{
            displayedLevel = [int]$semantic.Character.DisplayedLevel
            profileId = [string]$semantic.Character.ProfileId
            activeLoadoutId = [string]$semantic.Character.ActiveLoadoutId
            characterSha256 = [string]$semantic.Character.CharacterSha256
            bankSha256 = [string]$semantic.Bank.Sha256
            inventoryItems = [int]$semantic.Character.InventoryItems
            embeddedBankItems = [int]$semantic.Character.BankItems
            authoritativeBankItems = [int]$semantic.Bank.Count
            exactOwnedItems = [int]$semantic.Character.ExactOwnedItems
            characterChecksPassed = [int]$semantic.Character.ChecksPassed
            bankUniqueItemIds = [int]$semantic.Bank.UniqueItemIds
        }
        files = @($manifestFiles | Sort-Object { $_.path })
        signing = [ordered]@{
            algorithm = 'ECDSA-P256-SHA256-P1363'
            publicKeyPath = 'trust/signing-public-key.pem'
            publicKeySpkiSha256 = $signingKey.Fingerprint
            signaturePath = 'manifest.sig'
        }
    }
    $manifestPath = Join-Path $partialRoot 'manifest.json'
    [System.IO.File]::WriteAllText(
        $manifestPath,
        ($manifest | ConvertTo-Json -Depth 12),
        [System.Text.UTF8Encoding]::new($false))
    $signatureResult = & (Join-Path $PSScriptRoot 'New-PSOBBManifestSignature.ps1') `
        -RuntimeRoot $rootLayout.Root -ManifestPath $manifestPath `
        -PrivateKeyPath $signingKey.PrivatePath `
        -PublicKeyPath $archivedPublicKeyPath
    $sealedSignaturePath = Join-Path $partialRoot 'manifest.sig'
    if (-not [System.IO.Path]::GetFullPath(
            [string]$signatureResult.SignaturePath).Equals(
            [System.IO.Path]::GetFullPath($sealedSignaturePath),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        try {
            [System.IO.File]::Move(
                [string]$signatureResult.SignaturePath,
                $sealedSignaturePath,
                $false)
        } catch {
            throw 'No-clobber snapshot signature publication failed'
        }
    }
    if (-not [bool]$signatureResult.Verified -or
        [string]$signatureResult.PublicKeySha256 -cne $signingKey.Fingerprint -or
        (Get-LowerSha256 $archivedPublicKeyPath) -cne
            [string]($manifestFiles | Where-Object {
                    $_.role -ceq 'signing-public-key'
                }).sha256) {
        throw 'The sealed snapshot signature did not verify against its trust pin'
    }
    Remove-PSOBBCombatCanaryTransactionMarker `
        -Transaction $partialTransaction
    $partialMarkerPresent = $false
    try {
        Set-PSOBBProtectedTreeAcl -Path $partialRoot `
            -Root $canaryLayout.Snapshots
    } catch {
        throw 'The staged protected snapshot tree could not be sealed'
    }
    [void](Assert-PSOBBCombatSnapshotStopped)
    if ($InternalTestCreatePublishCollision.IsPresent) {
        [void][System.IO.Directory]::CreateDirectory($snapshotRoot)
        [System.IO.File]::WriteAllText(
            (Join-Path $snapshotRoot '.unexpected-preserve'),
            'preserve', [System.Text.UTF8Encoding]::new($false))
    }
    try {
        [System.IO.Directory]::Move($partialRoot, $snapshotRoot)
    } catch {
        throw 'No-clobber snapshot publication failed'
    }
    $published = $true
    if ($null -ne $InternalTestAfterPublishMove) {
        & $InternalTestAfterPublishMove $snapshotRoot
    }
    $publishedIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $snapshotRoot -Root $canaryLayout.Snapshots -Directory $true `
        -RoleLabel 'published combat canary snapshot'
    if ([uint32]$publishedIdentity.VolumeSerialNumber -ne
            [uint32]$partialTransaction.VolumeSerialNumber -or
        [uint64]$publishedIdentity.FileId -ne
            [uint64]$partialTransaction.FileId) {
        throw 'The published snapshot tree identity changed after its no-clobber move'
    }
    $verification = & (Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $rootLayout.Root -Target Snapshot -SnapshotPath $snapshotRoot `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $signingKey.Fingerprint
    if (-not [bool]$verification.Valid) {
        throw 'Published combat-canary snapshot did not pass complete readback verification'
    }
    [pscustomobject]@{
        Created = $true
        SnapshotId = [string]$verification.SnapshotId
        SnapshotPath = $snapshotRoot
        ManifestSha256 = [string]$verification.ManifestSha256
        SourceBackupId = [string]$backupManifest.backupId
        SourceBackupManifestSha256 = $backupManifestHash
        TwillsContractSha256 = $contractHash
        SigningPublicKeySpkiSha256 = $signingKey.Fingerprint
        Character = 'Twills'
        Class = 'FOnewearl'
        SlotIndex = 0
        DisplayedLevel = 200
        StateFiles = [int]$verification.StateFiles
    }
} catch {
    if ($published -and (Test-Path -LiteralPath $snapshotRoot)) {
        try {
            Remove-PSOBBCombatCanaryOwnedTree `
                -Path $snapshotRoot -Root $canaryLayout.Snapshots `
                -ExpectedVolumeSerialNumber `
                    $partialTransaction.VolumeSerialNumber `
                -ExpectedFileId $partialTransaction.FileId `
                -RoleLabel 'published snapshot rollback'
        } catch {
            throw 'Published snapshot rollback retained an identity-mismatched tree as evidence'
        }
    }
    throw
} finally {
    if (Test-Path -LiteralPath $partialRoot) {
        try {
            if ($null -eq $partialTransaction) {
                throw 'The partial snapshot has no transaction identity'
            }
            if ($partialMarkerPresent) {
                Remove-PSOBBCombatCanaryTransactionTree `
                    -Transaction $partialTransaction `
                    -RoleLabel 'partial snapshot cleanup'
            } else {
                Remove-PSOBBCombatCanaryOwnedTree `
                    -Path $partialRoot -Root $canaryLayout.Snapshots `
                    -ExpectedVolumeSerialNumber `
                        $partialTransaction.VolumeSerialNumber `
                    -ExpectedFileId $partialTransaction.FileId `
                    -RoleLabel 'partial snapshot cleanup'
            }
        } catch {
            throw 'Partial snapshot cleanup retained identity-mismatched evidence'
        }
    }
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
