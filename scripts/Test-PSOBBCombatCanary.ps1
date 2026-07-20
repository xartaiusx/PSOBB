[CmdletBinding()]
param(
    [string]$RuntimeRoot,

    [string]$SnapshotPath,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedTwillsContractSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSigningPublicKeySpkiSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedBuildContractSha256,

    [ValidateSet('Snapshot', 'Installation', 'Installed', 'Both')]
    [string]$Target = 'Snapshot'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

$script:RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:ContractRelativePath = 'contract/twills-fonewearl-build.json'
$script:PublicKeyRelativePath = 'trust/signing-public-key.pem'
$script:ManifestRelativePath = 'manifest.json'
$script:SignatureRelativePath = 'manifest.sig'

function Assert-PSOBBCombatCanaryLayoutContract {
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
    if ($missing.Count -ne 0) {
        throw ('Get-PSOBBServerEnvironmentLayout is missing required combat-canary ' +
            "properties: $($missing -join ', ')")
    }
    if ([string]$Value.Environment -cne 'CombatCanary' -or
        [string]$Value.EnvironmentId -cne 'combat-canary') {
        throw 'The resolved server environment is not the combat-canary environment'
    }
    $Value
}

function Assert-PSOBBCombatCanaryVerifierExactProperties {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    if ($null -eq $Value) {
        throw "$Label is null"
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if ($actual.Count -ne $expectedSorted.Count -or
        @(Compare-Object -ReferenceObject $expectedSorted `
            -DifferenceObject $actual).Count -ne 0) {
        throw "$Label does not have the exact sealed schema"
    }
}

function Test-PSOBBCombatCanaryVerifierMutableServerExemptPath {
    param([Parameter(Mandatory)][string]$Path)

    $Path -cmatch (
        '^system/(?:config\.json|(?:licenses|players|teams)' +
        '(?:/(?!\.{1,2}(?:/|$))[^/\\:]+)*|' +
        'patch-(?:bb|pc)/\.metadata-cache\.json)$')
}

function Assert-PSOBBCombatCanaryMetadataCache {
    param(
        [Parameter(Mandatory)][string]$ServerRoot,
        [Parameter(Mandatory)]$Policy
    )

    $path = Assert-PathWithinRoot `
        -Path (Join-Path $ServerRoot (
            ([string]$Policy.path).Replace('/', '\'))) `
        -Root $ServerRoot
    if (-not (Test-Path -LiteralPath $path)) { return $true }
    $item = Get-Item -Force -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 1 -or
        $item.Length -gt [int64]$Policy.maximumBytes) {
        throw 'A generated newserv metadata cache is unsafe or out of bounds'
    }
    $json = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $path -Root $ServerRoot `
        -MaximumBytes ([int64]$Policy.maximumBytes) `
        -RoleLabel 'generated newserv metadata cache'
    $properties = @($json.Properties())
    if ($properties.Count -lt 1 -or $properties.Count -gt 16384) {
        throw 'A generated newserv metadata cache has an invalid entry count'
    }
    $prefix = [string]$Policy.keyPrefix
    foreach ($property in $properties) {
        $name = [string]$property.Name
        $value = $property.Value
        if (-not $name.StartsWith(
                $prefix, [System.StringComparison]::Ordinal) -or
            $name.Length -le $prefix.Length -or $name.Length -gt 1024 -or
            $name.Contains('\') -or $name.Contains(':') -or
            $name.Contains('//') -or
            $name.Substring(2) -match '(?:^|/)\.\.?(?:/|$)' -or
            $value -isnot [Newtonsoft.Json.Linq.JArray] -or
            $value.Count -ne 4 -or
            $value[3] -isnot [Newtonsoft.Json.Linq.JArray] -or
            $value[3].Count -lt 1 -or $value[3].Count -gt 16384) {
            throw 'A generated newserv metadata cache entry is invalid'
        }
        foreach ($number in @($value[0], $value[1], $value[2]) +
            @($value[3].Children())) {
            if ($number -isnot [Newtonsoft.Json.Linq.JValue] -or
                $number.Type -notin @(
                    [Newtonsoft.Json.Linq.JTokenType]::Integer) -or
                [System.Numerics.BigInteger]$number.Value -lt 0 -or
                [System.Numerics.BigInteger]$number.Value -gt [int64]::MaxValue) {
                throw 'A generated newserv metadata cache contains invalid metadata'
            }
        }
    }
    $true
}

function Get-PSOBBCombatStableShadowSource {
    param(
        [Parameter(Mandatory)]$RootLayout,
        [Parameter(Mandatory)]$ContractSelection,
        [switch]$VerifyPayload
    )

    $contract = $ContractSelection.Value
    $sourceLockPath = Join-Path $script:RepositoryRoot `
        'config\sources.lock.json'
    $sourceLockJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $sourceLockPath -Root $script:RepositoryRoot `
        -MaximumBytes 2MB -RoleLabel 'tracked source lock'
    $sourceLock = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $sourceLockJson -RoleLabel 'tracked source lock'
    $serverComponents = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq [string]$contract.source.serverComponentId
        })
    $clientComponents = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq [string]$contract.source.clientComponentId
        })
    $serverMembers = if ($serverComponents.Count -eq 1) {
        @($serverComponents[0].members | Where-Object {
                [string]$_.path -ceq 'release/newserv-windows.exe'
            })
    } else { @() }
    $clientMembers = if ($clientComponents.Count -eq 1) {
        @($clientComponents[0].members | Where-Object {
                [string]$_.path -ceq 'Psobb.exe'
            })
    } else { @() }
    if ($serverComponents.Count -ne 1 -or $clientComponents.Count -ne 1 -or
        $serverMembers.Count -ne 1 -or $clientMembers.Count -ne 1 -or
        [string]$serverComponents[0].commit -cne
            [string]$contract.source.serverCommit -or
        [string]$serverComponents[0].sha256 -cne
            [string]$contract.source.serverArchiveSha256 -or
        [int64]$serverMembers[0].size -ne
            [int64]$contract.source.serverExecutable.size -or
        [string]$serverMembers[0].sha256 -cne
            [string]$contract.source.serverExecutable.sha256) {
        throw 'StableShadow does not match the tracked source lock'
    }
    $stable = Get-PSOBBServerEnvironmentLayout `
        -Layout $RootLayout -Environment Stable
    $installSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $stable.InstallRecord -Root $stable.EnvironmentRoot `
        -MaximumBytes 256KB -RoleLabel 'Stable installation record' `
        -PassThruSnapshot
    if (-not (Test-PSOBBProtectedAcl -Path $stable.InstallRecord)) {
        throw 'The Stable installation record is not protected'
    }
    $install = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $installSnapshot.Value `
        -RoleLabel 'Stable installation record'
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $install `
        -Label 'Stable installation record' `
        -Expected @('schemaVersion', 'installationId', 'initializedAtUtc',
            'runtimeRoot', 'serverVersion', 'serverArchiveSha256',
            'serverExecutableSha256', 'serverBaseManifestSha256',
            'clientVersion', 'clientArchiveSha256',
            'baseClientExecutableSha256', 'baseClientManifestSha256',
            'clientExecutableSha256', 'rendererVersion',
            'rendererArchiveSha256', 'rendererWrapperSha256',
            'rendererConfigurationSha256', 'patchManifestSha256',
            'synchronizedPatchFiles', 'clientPatchProfile',
            'clientPatchPolicySha256', 'networkScope')
    $marker = Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $RootLayout
    if ([int]$install.schemaVersion -ne 2 -or
        [string]$install.installationId -cne [string]$marker.installationId -or
        [string]$install.runtimeRoot -cne [string]$RootLayout.Root -or
        [string]$install.serverArchiveSha256 -cne
            [string]$contract.source.serverArchiveSha256 -or
        [string]$install.serverExecutableSha256 -cne
            [string]$contract.source.serverExecutable.sha256 -or
        [string]$install.clientArchiveSha256 -cne
            [string]$clientComponents[0].sha256 -or
        [string]$install.baseClientExecutableSha256 -cne
            [string]$clientMembers[0].sha256 -or
        [string]$install.baseClientManifestSha256 -cnotmatch
            '^[a-f0-9]{64}$' -or
        [int]$install.synchronizedPatchFiles -ne
            [int]$contract.source.patchDataFileCount -or
        [string]$install.clientPatchProfile -cne 'baseline' -or
        [string]$install.networkScope -cne 'loopback-only') {
        throw 'Stable is not the exact accepted source for StableShadow'
    }

    $baseManifestPath = Assert-PathWithinRoot `
        -Path (Join-Path $RootLayout.Root (
            ([string]$contract.source.serverBaseManifestRelativePath).Replace('/', '\'))) `
        -Root $RootLayout.Root
    $baseManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $baseManifestPath -Root $stable.EnvironmentRoot `
        -MaximumBytes 16MB `
        -ExpectedSha256 ([string]$install.serverBaseManifestSha256) `
        -RoleLabel 'Stable server base manifest' -PassThruSnapshot
    $baseManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $baseManifestSnapshot.Value `
        -RoleLabel 'Stable server base manifest'
    if ([int]$baseManifest.schemaVersion -ne 1 -or
        [string]$baseManifest.sourceArchiveSha256 -cne
            [string]$contract.source.serverArchiveSha256) {
        throw 'Stable server-base provenance is invalid'
    }

    $patchManifestPath = Assert-PathWithinRoot `
        -Path (Join-Path $RootLayout.Root (
            ([string]$contract.source.patchManifestRelativePath).Replace('/', '\'))) `
        -Root $RootLayout.Root
    $patchManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $patchManifestPath -Root $stable.EnvironmentRoot `
        -MaximumBytes 4MB `
        -ExpectedSha256 ([string]$install.patchManifestSha256) `
        -RoleLabel 'Stable BB patch-data manifest' -PassThruSnapshot
    $patchManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $patchManifestSnapshot.Value `
        -RoleLabel 'Stable BB patch-data manifest'
    if ([int]$patchManifest.schemaVersion -ne 1 -or
        [string]$patchManifest.sourceClientArchiveSha256 -cne
            [string]$clientComponents[0].sha256 -or
        @($patchManifest.files).Count -ne
            [int]$contract.source.patchDataFileCount) {
        throw 'Stable BB patch-data provenance is invalid'
    }

    $patchDataPath = Assert-PathWithinRoot `
        -Path (Join-Path $RootLayout.Root (
            ([string]$contract.source.patchDataRelativePath).Replace('/', '\'))) `
        -Root $RootLayout.Root
    if ($VerifyPayload.IsPresent) {
        $serverBaseParent = Split-Path -Parent $stable.ServerBase
        if (-not (Test-PSOBBDirectoryManifest `
                -Root $serverBaseParent -Files @($baseManifest.files)) -or
            -not (Test-PSOBBDirectoryManifest `
                -Root $patchDataPath -Files @($patchManifest.files))) {
            throw 'Stable source payload differs from its accepted manifests'
        }
    }

    $releaseEntries = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($baseManifest.files)) {
        $path = [string]$entry.path
        if (-not $path.StartsWith(
                'release/', [System.StringComparison]::Ordinal)) {
            continue
        }
        $relative = $path.Substring('release/'.Length)
        if ($relative -cmatch '^system/patch-bb/data/') { continue }
        if (-not $seen.Add($relative)) {
            throw 'Stable server-base release manifest contains a collision'
        }
        $releaseEntries.Add([pscustomobject]@{
                path = $relative
                size = [int64]$entry.size
                sha256 = [string]$entry.sha256
            })
    }
    foreach ($entry in @($patchManifest.files)) {
        $relative = [string]$contract.source.patchDataTargetRelativePath +
            '/' + [string]$entry.path
        if (-not $seen.Add($relative)) {
            throw 'Stable BB patch-data overlay contains a collision'
        }
        $releaseEntries.Add([pscustomobject]@{
                path = $relative
                size = [int64]$entry.size
                sha256 = [string]$entry.sha256
            })
    }
    $executable = @($releaseEntries | Where-Object {
            [string]$_.path -ceq
                [string]$contract.source.serverExecutable.path
        })
    if ($executable.Count -ne 1 -or
        [int64]$executable[0].size -ne
            [int64]$contract.source.serverExecutable.size -or
        [string]$executable[0].sha256 -cne
            [string]$contract.source.serverExecutable.sha256) {
        throw 'StableShadow source does not contain its exact server executable'
    }
    [pscustomobject]@{
        StableLayout = $stable
        StableInstallation = $install
        ServerBaseManifestPath = $baseManifestPath
        ServerBaseManifestSha256 = [string]$baseManifestSnapshot.Sha256
        PatchManifestPath = $patchManifestPath
        PatchManifestSha256 = [string]$patchManifestSnapshot.Sha256
        BaseClientManifestSha256 =
            [string]$install.baseClientManifestSha256
        BaseClientExecutableSha256 =
            [string]$install.baseClientExecutableSha256
        PatchDataPath = $patchDataPath
        ReleaseEntries = $releaseEntries.ToArray()
    }
}

function Get-PSOBBCombatCanaryTrustedFingerprint {
    param([string]$ExplicitFingerprint)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitFingerprint)) {
        return $ExplicitFingerprint.ToLowerInvariant()
    }
    $trustPath = Join-Path $script:RepositoryRoot 'config\release-trust.json'
    $trustJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $trustPath -Root $script:RepositoryRoot `
        -MaximumBytes 256KB -RoleLabel 'release trust policy'
    $trust = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $trustJson -RoleLabel 'release trust policy'
    $keys = @($trust.keys | Where-Object {
            [string]$_.id -ceq [string]$trust.activeKeyId
        })
    if ([int]$trust.schemaVersion -ne 1 -or $keys.Count -ne 1 -or
        [string]$keys[0].spkiSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The release trust policy does not identify one local acceptance key'
    }
    [string]$keys[0].spkiSha256
}

function Assert-PSOBBCombatCanaryProtectedTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    try {
        $safeRoot = Assert-PathWithinRoot -Path $Path -Root $Root
        $rootItem = Get-Item -Force -LiteralPath $safeRoot -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or
            ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Unsafe snapshot root'
        }
        $pending = [System.Collections.Generic.Queue[string]]::new()
        $pending.Enqueue($safeRoot)
        while ($pending.Count -gt 0) {
            $directory = Assert-PathWithinRoot -Path $pending.Dequeue() -Root $safeRoot
            $directoryItem = Get-Item -Force -LiteralPath $directory -ErrorAction Stop
            if (($directoryItem.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not (Test-PSOBBProtectedAcl -Path $directory)) {
                throw 'Unsafe snapshot directory'
            }
            foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory `
                        -ErrorAction Stop)) {
                $safeChild = Assert-PathWithinRoot `
                    -Path $child.FullName -Root $safeRoot
                if (($child.Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    -not (Test-PSOBBProtectedAcl -Path $safeChild)) {
                    throw 'Unsafe snapshot item'
                }
                if ($child.PSIsContainer) {
                    $pending.Enqueue($safeChild)
                }
            }
        }
        $safeRoot
    } catch {
        throw 'The combat-canary snapshot tree is unreadable or unsafe'
    }
}

function Test-PSOBBCombatCanaryAllowedPayloadPath {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -ceq $script:ContractRelativePath -or
        $Path -ceq $script:PublicKeyRelativePath) {
        return $true
    }
    $Path -cmatch ('^state/system/(?:licenses/[^/\\:]+\.json|' +
        'players/[^/\\:]+\.(?:psochar|psobank|psosys|psocard)|' +
        'teams/[^/\\:]+\.json)$')
}

function Get-PSOBBCombatCanaryExpectedRole {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -ceq $script:ContractRelativePath) { return 'twills-contract' }
    if ($Path -ceq $script:PublicKeyRelativePath) { return 'signing-public-key' }
    if ($Path -cmatch '^state/system/licenses/') { return 'license-state' }
    if ($Path -cmatch '\.psochar$') { return 'twills-character' }
    if ($Path -cmatch '\.psobank$') { return 'twills-bank' }
    if ($Path -cmatch '\.psosys$') { return 'twills-system' }
    if ($Path -cmatch '\.psocard$') { return 'twills-card' }
    if ($Path -cmatch '^state/system/teams/') { return 'team-state' }
    throw 'The combat-canary snapshot payload contains an unsupported role'
}

function Assert-PSOBBCombatCanaryAccountBinding {
    param(
        [Parameter(Mandatory)]$Roles,
        [Parameter(Mandatory)][string]$SnapshotRoot
    )

    $characterName = [System.IO.Path]::GetFileName(
        [string]$Roles['twills-character'][0].Entry.path)
    if ($characterName -cnotmatch
        '^player_(?<account>[a-z][a-z0-9_-]{2,15})_0\.psochar$') {
        throw 'The sealed snapshot character path is not an exact slot-0 BB account path'
    }
    $accountName = [string]$Matches.account
    $expectedNames = [ordered]@{
        'twills-bank' = "player_${accountName}_0.psobank"
        'twills-system' = "system_${accountName}.psosys"
        'twills-card' = "guild_cards_${accountName}.psocard"
    }
    foreach ($role in $expectedNames.Keys) {
        if ([System.IO.Path]::GetFileName(
                [string]$Roles[$role][0].Entry.path) -cne
            [string]$expectedNames[$role]) {
            throw 'The sealed snapshot protected state does not belong to one BB account'
        }
    }

    $licenseMatches = 0
    $licenseIdentities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($license in @($Roles['license-state'])) {
        try {
            $licenseText = Read-PSOBBCombatCanaryStrictUtf8Text `
                -LiteralPath ([string]$license.Path) `
                -Root $SnapshotRoot -MaximumBytes 256KB `
                -ExpectedLength ([int64]$license.Entry.size) `
                -ExpectedSha256 ([string]$license.Entry.sha256) `
                -RoleLabel 'sealed snapshot protected license state'
            $state = Read-PSOBBCombatCanaryStrictJsonObject `
                -Text $licenseText -RoleLabel 'sealed snapshot protected license state'
            $identities = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
                    -State $state -RawText $licenseText `
                    -ExpectedAccountName $accountName `
                    -RoleLabel 'sealed snapshot protected license state')
        } catch {
            throw 'The sealed snapshot contains invalid protected license JSON'
        }
        foreach ($identity in $identities) {
            if (-not [bool]$identity.IsSafeAccountName -or
                [string]$identity.IdentitySha256 -cnotmatch '^[a-f0-9]{64}$' -or
                -not $licenseIdentities.Add(
                    [string]$identity.IdentitySha256)) {
                throw 'The sealed snapshot has duplicate or invalid BB license identities'
            }
            if ([bool]$identity.MatchesExpectedAccount) { $licenseMatches++ }
        }
    }
    if ($licenseMatches -ne 1) {
        throw 'The sealed snapshot does not bind exactly one BB license to Twills state'
    }
    $true
}

function Get-PSOBBCombatCanarySemanticResult {
    param(
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)][string]$BankPath,
        [Parameter(Mandatory)][string]$ContractPath,
        [Parameter(Mandatory)][string]$ContractSha256
    )

    try {
        $characterOutput = @(& (Join-Path $PSScriptRoot 'Test-PSOBBCharacterBuild.ps1') `
                -Path $CharacterPath -BuildPath $ContractPath)
        $characterResults = @($characterOutput | Where-Object {
                $_.PSObject.Properties.Name -contains 'Valid'
            })
        $bankOutput = @(& (Join-Path $PSScriptRoot 'Test-PSOBBTwillsBank.ps1') `
                -Path $BankPath -BuildPath $ContractPath `
                -ExpectedBuildSha256 $ContractSha256)
        $bankResults = @($bankOutput | Where-Object {
                $_.PSObject.Properties.Name -contains 'Valid'
            })
    } catch {
        throw 'The sealed combat-canary state failed independent Twills semantic verification'
    }
    if ($characterResults.Count -ne 1 -or $bankResults.Count -ne 1 -or
        -not [bool]$characterResults[0].Valid -or -not [bool]$bankResults[0].Valid -or
        [string]$characterResults[0].BuildSha256 -cne $ContractSha256 -or
        [string]$bankResults[0].BuildSha256 -cne $ContractSha256 -or
        [int]$characterResults[0].SlotIndex -ne 0 -or
        [int]$characterResults[0].DisplayedLevel -ne 200 -or
        [string]$bankResults[0].Character -cne 'Twills' -or
        [string]$bankResults[0].Class -cne 'FOnewearl' -or
        [int]$bankResults[0].SlotIndex -ne 0) {
        throw 'Independent Twills semantic verification returned an inexact result'
    }
    [pscustomobject]@{
        Character = $characterResults[0]
        Bank = $bankResults[0]
    }
}

function Test-PSOBBCombatCanarySnapshot {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ContractHash,
        [Parameter(Mandatory)][string]$SigningFingerprint
    )

    try {
        $safeRoot = Assert-PathWithinRoot -Path $Path -Root $Layout.Snapshots
    } catch {
        throw 'The requested combat-canary snapshot path is outside its sealed root'
    }
    if (-not (Test-Path -LiteralPath $safeRoot -PathType Container)) {
        throw 'The requested combat-canary snapshot does not exist'
    }
    $snapshotName = (Get-Item -Force -LiteralPath $safeRoot).Name
    if ($snapshotName -cnotmatch '^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$') {
        throw 'The combat-canary snapshot name is not an exact sealed-snapshot identifier'
    }
    [void](Assert-PSOBBCombatCanaryProtectedTree `
            -Path $safeRoot -Root $Layout.Snapshots)

    $manifestPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot $script:ManifestRelativePath) -Root $safeRoot
    $signaturePath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot $script:SignatureRelativePath) -Root $safeRoot
    $publicKeyPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot ($script:PublicKeyRelativePath.Replace('/', '\'))) `
        -Root $safeRoot
    foreach ($requiredFile in @($manifestPath, $signaturePath, $publicKeyPath)) {
        $item = Get-Item -Force -LiteralPath $requiredFile -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -le 0) {
            throw 'The sealed snapshot is missing required signature material'
        }
    }

    $signatureText = Read-PSOBBCombatCanaryStrictUtf8Text `
        -LiteralPath $signaturePath -Root $safeRoot -MaximumBytes 4KB `
        -RoleLabel 'sealed snapshot signature'
    try {
        $signature = [Convert]::FromBase64String($signatureText)
    } catch {
        throw 'The sealed snapshot signature is not valid Base64'
    }
    if ($signature.Length -ne 64) {
        throw 'The sealed snapshot signature is not a P-256 P1363 signature'
    }
    $publicKeySnapshot = Read-PSOBBCombatCanaryStrictUtf8Text `
        -LiteralPath $publicKeyPath -Root $safeRoot -MaximumBytes 16KB `
        -RoleLabel 'archived snapshot public key' -PassThruSnapshot
    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        try {
            $verifier.ImportFromPem([string]$publicKeySnapshot.Value)
        } catch {
            throw 'The archived snapshot public key is not valid ECDSA P-256 PEM'
        }
        $fingerprint = ([Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData(
                    $verifier.ExportSubjectPublicKeyInfo()))).ToLowerInvariant()
        if ($fingerprint -cne $SigningFingerprint) {
            throw 'The sealed snapshot public-key trust pin is invalid'
        }
        $manifestSnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
            -LiteralPath $manifestPath -Root $safeRoot -MaximumBytes 256KB `
            -RoleLabel 'sealed snapshot manifest' `
            -Consumer {
                param([byte[]]$Bytes)
                if (-not $verifier.VerifyData(
                        $Bytes,
                        $signature,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                        [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
                    throw 'The sealed snapshot signature is invalid'
                }
                $strictText = $null
                try {
                    $strictText = [System.Text.UTF8Encoding]::new(
                        $false, $true).GetString($Bytes)
                } catch {
                    throw 'The sealed snapshot manifest is not valid UTF-8'
                }
                ConvertFrom-PSOBBCombatCanaryStrictJsonText `
                    -Text $strictText -RoleLabel 'sealed snapshot manifest'
            }
    } finally {
        $verifier.Dispose()
        if ($signature) {
            [Array]::Clear($signature, 0, $signature.Length)
        }
    }
    $manifestJson = $manifestSnapshot.Value
    $manifestSchemaPath = Join-Path $script:RepositoryRoot `
        'config\schemas\combat-canary-snapshot.schema.json'
    $manifestSchemaValid = $false
    try {
        $normalizedManifest = $manifestJson.ToString(
            [Newtonsoft.Json.Formatting]::None)
        $manifestSchemaValid = [bool](Test-Json `
                -Json $normalizedManifest -SchemaFile $manifestSchemaPath `
                -ErrorAction Stop)
    } catch {
        $manifestSchemaValid = $false
    }
    if (-not $manifestSchemaValid) {
        throw 'The sealed snapshot manifest does not satisfy its exact tracked schema'
    }
    $manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $manifestJson -RoleLabel 'sealed snapshot manifest'

    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $manifest `
        -Label 'Snapshot manifest' `
        -Expected @('$schema', 'schemaVersion', 'snapshotId', 'createdAtUtc',
            'sourceBackup', 'twillsContract', 'character', 'semanticSummary',
            'files', 'signing')
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $manifest.sourceBackup `
        -Label 'Snapshot source-backup binding' `
        -Expected @('backupId', 'backupKind', 'createdAtUtc', 'manifestSha256',
            'clientPatchProfile')
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $manifest.twillsContract `
        -Label 'Snapshot Twills-contract binding' `
        -Expected @('path', 'size', 'sha256', 'profileId')
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $manifest.character `
        -Label 'Snapshot character identity' `
        -Expected @('name', 'classId', 'className', 'slotIndex')
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $manifest.semanticSummary `
        -Label 'Snapshot semantic summary' `
        -Expected @('displayedLevel', 'profileId', 'activeLoadoutId',
            'characterSha256', 'bankSha256', 'inventoryItems',
            'embeddedBankItems', 'authoritativeBankItems', 'exactOwnedItems',
            'characterChecksPassed', 'bankUniqueItemIds')
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $manifest.signing `
        -Label 'Snapshot signing binding' `
        -Expected @('algorithm', 'publicKeyPath', 'publicKeySpkiSha256', 'signaturePath')

    $snapshotGuid = [Guid]::Empty
    $createdAt = [DateTimeOffset]::MinValue
    $backupGuid = [Guid]::Empty
    $backupCreatedAt = [DateTimeOffset]::MinValue
    if ([string]$manifest.'$schema' -cne
            'https://psobb.local/schemas/combat-canary-snapshot.schema.json' -or
        [int]$manifest.schemaVersion -ne 1 -or
        -not [Guid]::TryParse([string]$manifest.snapshotId, [ref]$snapshotGuid) -or
        -not [DateTimeOffset]::TryParse([string]$manifest.createdAtUtc, [ref]$createdAt) -or
        -not [Guid]::TryParse([string]$manifest.sourceBackup.backupId, [ref]$backupGuid) -or
        -not [DateTimeOffset]::TryParse(
            [string]$manifest.sourceBackup.createdAtUtc, [ref]$backupCreatedAt) -or
        [string]$manifest.sourceBackup.backupKind -cne 'state' -or
        [string]$manifest.sourceBackup.clientPatchProfile -cne 'baseline' -or
        [string]$manifest.sourceBackup.manifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.twillsContract.path -cne $script:ContractRelativePath -or
        [int64]$manifest.twillsContract.size -le 0 -or
        [string]$manifest.twillsContract.sha256 -cne $ContractHash -or
        [string]::IsNullOrWhiteSpace([string]$manifest.twillsContract.profileId) -or
        [string]$manifest.character.name -cne 'Twills' -or
        [int]$manifest.character.classId -ne 8 -or
        [string]$manifest.character.className -cne 'FOnewearl' -or
        [int]$manifest.character.slotIndex -ne 0 -or
        [string]$manifest.signing.algorithm -cne 'ECDSA-P256-SHA256-P1363' -or
        [string]$manifest.signing.publicKeyPath -cne $script:PublicKeyRelativePath -or
        [string]$manifest.signing.publicKeySpkiSha256 -cne $SigningFingerprint -or
        [string]$manifest.signing.signaturePath -cne $script:SignatureRelativePath) {
        throw 'The sealed snapshot manifest has an invalid fixed contract'
    }

    $manifestEntries = @($manifest.files)
    [void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
            -Entries $manifestEntries -Scope Snapshot)
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $roles = @{}
    foreach ($entry in $manifestEntries) {
        Assert-PSOBBCombatCanaryVerifierExactProperties -Value $entry `
            -Label 'Snapshot file entry' `
            -Expected @('path', 'role', 'size', 'sha256')
        $relative = [string]$entry.path
        $expectedRole = Get-PSOBBCombatCanaryExpectedRole -Path $relative
        if (-not (Test-PSOBBCombatCanaryAllowedPayloadPath -Path $relative) -or
            -not $seenPaths.Add($relative) -or
            [string]$entry.role -cne $expectedRole -or
            [int64]$entry.size -le 0 -or
            [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The sealed snapshot contains a disallowed, colliding, or invalid payload entry'
        }
        try {
            $payloadPath = Assert-PathWithinRoot `
                -Path (Join-Path $safeRoot ($relative.Replace('/', '\'))) `
                -Root $safeRoot
            $payloadSnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
                -LiteralPath $payloadPath -Root $safeRoot `
                -MaximumBytes ([long](Get-PSOBBCombatCanaryPayloadRolePolicy `
                        -Role $expectedRole).MaximumBytes) `
                -ExpectedLength ([int64]$entry.size) `
                -ExpectedSha256 ([string]$entry.sha256) `
                -RoleLabel 'sealed snapshot payload' `
                -Consumer { param([byte[]]$Bytes) $Bytes.Length -gt 0 }
        } catch {
            throw "The sealed snapshot payload for role '$($entry.role)' failed readback"
        }
        if (-not $roles.ContainsKey([string]$entry.role)) {
            $roles[[string]$entry.role] = [System.Collections.Generic.List[object]]::new()
        }
        $roles[[string]$entry.role].Add([pscustomobject]@{
                Entry = $entry
                Path = $payloadPath
                Snapshot = $payloadSnapshot
            })
    }
    try {
        $actualPayloads = @(Get-ChildItem -Force -LiteralPath $safeRoot `
                -Recurse -File -ErrorAction Stop | ForEach-Object {
                [void](Assert-PathWithinRoot -Path $_.FullName -Root $safeRoot)
                [System.IO.Path]::GetRelativePath(
                    $safeRoot, $_.FullName).Replace('\', '/')
            } | Where-Object {
                $_ -cnotin @($script:ManifestRelativePath, $script:SignatureRelativePath)
            })
    } catch {
        throw 'The sealed snapshot payload inventory is unreadable or unsafe'
    }
    if ($actualPayloads.Count -ne $seenPaths.Count -or
        @($actualPayloads | Where-Object { -not $seenPaths.Contains($_) }).Count -ne 0) {
        throw 'The sealed snapshot contains missing or unmanifested payload files'
    }
    $expectedDirectories = Get-PSOBBCombatCanaryExpectedDirectories `
        -FilePaths @($manifestEntries | ForEach-Object { [string]$_.path }) `
        -RequiredDirectories @('contract', 'trust', 'state', 'state/system',
            'state/system/licenses', 'state/system/players', 'state/system/teams')
    [void](Assert-PSOBBCombatCanaryExactDirectoryInventory -Root $safeRoot `
            -ExpectedDirectories $expectedDirectories `
            -RoleLabel 'sealed snapshot' -RequireProtected)
    foreach ($role in @('twills-contract', 'signing-public-key', 'twills-character',
            'twills-bank', 'twills-system', 'twills-card', 'team-state')) {
        if (-not $roles.ContainsKey($role) -or $roles[$role].Count -ne 1) {
            throw "The sealed snapshot does not contain exactly one '$role' payload"
        }
    }
    if (-not $roles.ContainsKey('license-state') -or $roles['license-state'].Count -lt 1) {
        throw 'The sealed snapshot does not contain its complete protected license state'
    }
    [void](Assert-PSOBBCombatCanaryAccountBinding `
            -Roles $roles -SnapshotRoot $safeRoot)

    $contractPath = [string]$roles['twills-contract'][0].Path
    if ([string]$roles['twills-contract'][0].Snapshot.Sha256 -cne $ContractHash -or
        [int64]$manifest.twillsContract.size -ne [int64](
            $roles['twills-contract'][0].Snapshot.Length) -or
        [string]$roles['twills-contract'][0].Entry.sha256 -cne $ContractHash -or
        [string]$publicKeySnapshot.Sha256 -cne
            [string]$roles['signing-public-key'][0].Entry.sha256 -or
        [int64]$publicKeySnapshot.Length -ne
            [int64]$roles['signing-public-key'][0].Entry.size) {
        throw 'The archived contract or public key does not match the signed payload index'
    }
    $contractJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $contractPath -Root $safeRoot -MaximumBytes 128KB `
        -ExpectedLength ([int64]$roles['twills-contract'][0].Entry.size) `
        -ExpectedSha256 $ContractHash -RoleLabel 'archived Twills contract'
    $contract = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $contractJson -RoleLabel 'archived Twills contract'
    if ([int]$contract.schemaVersion -ne 2 -or
        [string]$contract.profileId -cne [string]$manifest.twillsContract.profileId -or
        [string]$contract.character.name -cne 'Twills' -or
        [int]$contract.character.classId -ne 8 -or
        [string]$contract.character.className -cne 'FOnewearl' -or
        [int]$contract.character.slotIndex -ne 0) {
        throw 'The archived snapshot contract is not slot-0 Twills FOnewearl'
    }

    $semantic = Get-PSOBBCombatCanarySemanticResult `
        -CharacterPath ([string]$roles['twills-character'][0].Path) `
        -BankPath ([string]$roles['twills-bank'][0].Path) `
        -ContractPath (Join-Path $script:RepositoryRoot `
            'config\twills-fonewearl-build.json') `
        -ContractSha256 $ContractHash
    $actualSemantic = [ordered]@{
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
    foreach ($property in $actualSemantic.Keys) {
        if ([string]$manifest.semanticSummary.$property -cne
            [string]$actualSemantic[$property]) {
            throw 'The signed semantic summary no longer matches independent Twills verification'
        }
    }

    [pscustomobject]@{
        Valid = $true
        Target = 'Snapshot'
        SnapshotId = [string]$manifest.snapshotId
        SnapshotPath = $safeRoot
        ManifestSha256 = [string]$manifestSnapshot.Sha256
        SourceBackupId = [string]$manifest.sourceBackup.backupId
        SourceBackupManifestSha256 = [string]$manifest.sourceBackup.manifestSha256
        TwillsContractSha256 = $ContractHash
        SigningPublicKeySpkiSha256 = $SigningFingerprint
        Character = 'Twills'
        Class = 'FOnewearl'
        SlotIndex = 0
        DisplayedLevel = 200
        StateFiles = @($manifestEntries | Where-Object {
                [string]$_.path -cmatch '^state/'
            }).Count
    }
}

function Assert-PSOBBCombatCanaryOrdinaryTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    try {
        $safeRoot = Assert-PathWithinRoot -Path $Path -Root $Root
        $pending = [System.Collections.Generic.Queue[string]]::new()
        $pending.Enqueue($safeRoot)
        while ($pending.Count -gt 0) {
            $directory = Assert-PathWithinRoot -Path $pending.Dequeue() -Root $safeRoot
            $item = Get-Item -Force -LiteralPath $directory -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Unsafe directory'
            }
            foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory `
                        -ErrorAction Stop)) {
                [void](Assert-PathWithinRoot -Path $child.FullName -Root $safeRoot)
                if (($child.Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Unsafe tree item'
                }
                if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) }
            }
        }
        $safeRoot
    } catch {
        throw "$Label is unreadable or contains an unsafe tree item"
    }
}

function Test-PSOBBCombatCanaryConfigStrictJson {
    param([Parameter(Mandatory)][string]$Text)

    try {
        if ($Text.StartsWith([char]0xFEFF) -or $Text.Contains("`r")) {
            return $false
        }
        Read-PSOBBCombatCanaryStrictJsonObject -Text $Text `
            -RoleLabel 'combat canary configuration' | Out-Null
        $true
    } catch {
        $false
    }
}

function Test-PSOBBCombatCanaryConfigKeyUnique {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Key
    )

    $keyPattern = '(?m)^\s*"' + [regex]::Escape($Key) + '"\s*:'
    [regex]::Matches($Text, $keyPattern).Count -eq 1
}

function Test-PSOBBCombatCanaryConfigScalar {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$JsonPattern
    )

    if (-not (Test-PSOBBCombatCanaryConfigKeyUnique `
            -Text $Text -Key $Key)) {
        return $false
    }
    $pattern = '(?m)^\s*"' + [regex]::Escape($Key) +
        '"\s*:\s*' + $JsonPattern + '\s*,?\s*(?://.*)?$'
    [regex]::Matches($Text, $pattern).Count -eq 1
}

function Test-PSOBBCombatCanaryArtifactConfigurationPolicy {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)]
        [ValidateSet('CurrentUpstream', 'StableShadow')]
        [string]$ServerArtifact
    )

    if ($ServerArtifact -ceq 'CurrentUpstream') {
        return (Test-PSOBBCombatCanaryConfigScalar `
                -Text $Text -Key 'CensorCredentials' `
                -JsonPattern 'true') -and
            (Test-PSOBBCombatCanaryConfigScalar `
                -Text $Text -Key 'AllowSameAccountConcurrentLogins' `
                -JsonPattern 'false')
    }
    try {
        $configurationJson = Read-PSOBBCombatCanaryStrictJsonObject `
            -Text $Text -RoleLabel 'StableShadow configuration policy'
        $configurationProperties = @($configurationJson.Properties())
        foreach ($unsupportedKey in @(
                'CensorCredentials',
                'AllowSameAccountConcurrentLogins')) {
            if (@($configurationProperties | Where-Object {
                        [string]$_.Name -ceq $unsupportedKey
                    }).Count -ne 0) {
                return $false
            }
        }
        $true
    } catch {
        $false
    }
}

function Get-PSOBBCombatCanaryInstallation {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ContractHash,
        [Parameter(Mandatory)][string]$SigningFingerprint,
        [string]$ExplicitBuildContractHash
    )

    $requestedBuildContractHash = if ([string]::IsNullOrWhiteSpace(
            $ExplicitBuildContractHash)) { '' } else {
        $ExplicitBuildContractHash.ToLowerInvariant()
    }
    $explicitSelection = if ([string]::IsNullOrEmpty(
            $requestedBuildContractHash)) { $null } else {
        Get-PSOBBCombatCanaryBuildContractSelection `
            -RepositoryRoot $script:RepositoryRoot `
            -ExpectedSha256 $requestedBuildContractHash
    }
    $installItem = Get-Item -Force -LiteralPath $Layout.InstallRecord `
        -ErrorAction Stop
    if ($installItem.PSIsContainer -or
        ($installItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-PSOBBProtectedAcl -Path $Layout.InstallRecord)) {
        throw 'The combat-canary installation record is missing or unprotected'
    }
    $installationJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $Layout.InstallRecord `
        -Root $Layout.EnvironmentRoot -MaximumBytes 256KB `
        -RoleLabel 'combat canary installation record'
    $installation = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $installationJson `
        -RoleLabel 'combat canary installation record'
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $installation `
        -Label 'Combat-canary installation record' `
        -Expected @('schemaVersion', 'environment', 'environmentId',
            'initializedAtUtc', 'buildContractSha256',
            'serverReleaseManifestSha256', 'baseClientManifestSha256',
            'clientBindingSha256', 'snapshotDirectoryName', 'snapshotId',
            'snapshotManifestSha256', 'stateBindingSha256',
            'twillsContractSha256', 'signingPublicKeySpkiSha256',
            'configurationSha256')
    $boundBuildContractHash = [string]$installation.buildContractSha256
    if ($boundBuildContractHash -cnotmatch '^[a-f0-9]{64}$' -or
        (-not [string]::IsNullOrEmpty($requestedBuildContractHash) -and
            $boundBuildContractHash -cne $requestedBuildContractHash)) {
        throw 'The combat-canary installation has an unexpected build contract'
    }
    $selection = if ($null -ne $explicitSelection) {
        $explicitSelection
    } else {
        Get-PSOBBCombatCanaryBuildContractSelection `
            -RepositoryRoot $script:RepositoryRoot `
            -ExpectedSha256 $boundBuildContractHash
    }
    $buildContractHash = [string]$selection.Hash
    $build = $selection.Value
    $stableShadowSource = if ($selection.Artifact -ceq 'StableShadow') {
        Get-PSOBBCombatStableShadowSource `
            -RootLayout (Get-PSOBBLayout -RuntimeRoot $Layout.Root) `
            -ContractSelection $selection
    } else {
        $null
    }

    [void](Assert-PSOBBCombatCanaryOrdinaryTree `
            -Path $Layout.ServerBase -Root $Layout.EnvironmentRoot `
            -Label 'Combat-canary server base')
    if ($selection.Artifact -ceq 'CurrentUpstream') {
        [void](Assert-PSOBBCombatCanaryRequiredReleaseDirectories `
                -Build $build -Root $Layout.ServerBase)
    }
    $releaseManifestPath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.ServerBase 'release-manifest.json') `
        -Root $Layout.ServerBase
    $releaseManifestParameters = @{
        LiteralPath = $releaseManifestPath
        Root = $Layout.ServerBase
        MaximumBytes = 16MB
        ExpectedSha256 = [string]$installation.serverReleaseManifestSha256
        RoleLabel = 'built server release manifest'
        PassThruSnapshot = $true
    }
    if ($selection.Artifact -ceq 'CurrentUpstream') {
        $releaseManifestParameters.ExpectedLength =
            [int64]$build.output.releaseManifest.size
        if ([string]$build.output.releaseManifest.sha256 -cne
                [string]$installation.serverReleaseManifestSha256) {
            throw 'The current-upstream release manifest binding changed'
        }
    }
    $releaseManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        @releaseManifestParameters
    $releaseManifestJson = $releaseManifestSnapshot.Value
    $releaseManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $releaseManifestJson -RoleLabel 'built server release manifest'
    if ($selection.Artifact -ceq 'CurrentUpstream') {
        Assert-PSOBBCombatCanaryVerifierExactProperties -Value $releaseManifest `
            -Label 'Combat-canary release manifest' `
            -Expected @('schemaVersion', 'profileId', 'sourceCommit',
                'patchSeriesSha256', 'files')
        if ([int]$releaseManifest.schemaVersion -ne 1 -or
            [string]$releaseManifest.profileId -cne [string]$build.profileId -or
            [string]$releaseManifest.sourceCommit -cne
                [string]$build.source.commit -or
            [string]$releaseManifest.patchSeriesSha256 -cne
                [string]$build.patchSeries.sha256) {
            throw 'The server release manifest is not bound to the tracked build contract'
        }
    } else {
        Assert-PSOBBCombatCanaryVerifierExactProperties -Value $releaseManifest `
            -Label 'StableShadow release manifest' `
            -Expected @('schemaVersion', 'profileId', 'serverComponentId',
                'serverCommit', 'serverBaseManifestSha256',
                'patchDataManifestSha256', 'files')
        if ([int]$releaseManifest.schemaVersion -ne 1 -or
            [string]$releaseManifest.profileId -cne
                [string]$build.profileId -or
            [string]$releaseManifest.serverComponentId -cne
                [string]$build.source.serverComponentId -or
            [string]$releaseManifest.serverCommit -cne
                [string]$build.source.serverCommit -or
            [string]$releaseManifest.serverBaseManifestSha256 -cne
                [string]$stableShadowSource.ServerBaseManifestSha256 -or
            [string]$releaseManifest.patchDataManifestSha256 -cne
                [string]$stableShadowSource.PatchManifestSha256) {
            throw 'The StableShadow release manifest is not source-bound'
        }
    }
    $releaseEntries = @($releaseManifest.files)
    $releasePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $releaseBytes = [int64]0
    foreach ($entry in $releaseEntries) {
        Assert-PSOBBCombatCanaryVerifierExactProperties -Value $entry `
            -Label 'Combat-canary release file' `
            -Expected @('path', 'size', 'sha256')
        $relative = [string]$entry.path
        if ($relative -cnotmatch '^(?!/)(?!.*(?:^|/)\.\.?(/|$))[^:\\]+$' -or
            $relative -ceq 'release-manifest.json' -or
            -not $releasePaths.Add($relative) -or
            [int64]$entry.size -lt 0 -or
            [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The server release manifest contains an unsafe or colliding path'
        }
        $file = Assert-PathWithinRoot `
            -Path (Join-Path $Layout.ServerBase ($relative.Replace('/', '\'))) `
            -Root $Layout.ServerBase
        $item = Get-Item -Force -LiteralPath $file -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -ne [int64]$entry.size -or
            (Get-LowerSha256 $file) -cne [string]$entry.sha256) {
            throw 'The server-base release file does not match its exact manifest'
        }
        $releaseBytes += [int64]$entry.size
    }
    $actualReleasePaths = @(Get-ChildItem -Force -LiteralPath $Layout.ServerBase `
        -Recurse -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath(
                $Layout.ServerBase, $_.FullName).Replace('\', '/')
        } | Where-Object { $_ -cne 'release-manifest.json' })
    $manifestClaimsInvalid = if ($selection.Artifact -ceq 'CurrentUpstream') {
        $releaseEntries.Count -ne [int]$build.output.fileCount -or
            $releaseBytes -ne [int64]$build.output.totalBytes
    } else {
        -not (Test-PSOBBManifestEntriesEqual `
            -Left @($stableShadowSource.ReleaseEntries) `
            -Right $releaseEntries)
    }
    if ($manifestClaimsInvalid -or
        $actualReleasePaths.Count -ne $releasePaths.Count -or
        @($actualReleasePaths | Where-Object {
                -not $releasePaths.Contains($_)
            }).Count -ne 0) {
        throw 'The server-base release inventory differs from its build contract'
    }
    $baseExecutablePath = Join-Path $Layout.ServerBase 'newserv-windows.exe'
    $expectedExecutable = if ($selection.Artifact -ceq 'CurrentUpstream') {
        $build.output.executable
    } else {
        $build.source.serverExecutable
    }
    if ((Get-Item -Force -LiteralPath $baseExecutablePath).Length -ne
            [int64]$expectedExecutable.size -or
        (Get-LowerSha256 $baseExecutablePath) -cne
            [string]$expectedExecutable.sha256) {
        throw 'The server-base executable does not match its build contract'
    }
    $initializedAt = [DateTimeOffset]::MinValue
    if ([int]$installation.schemaVersion -ne 1 -or
        [string]$installation.environment -cne 'CombatCanary' -or
        [string]$installation.environmentId -cne 'combat-canary' -or
        -not [DateTimeOffset]::TryParse(
            [string]$installation.initializedAtUtc, [ref]$initializedAt) -or
        [string]$installation.buildContractSha256 -cne $buildContractHash -or
        [string]$installation.serverReleaseManifestSha256 -cne
            [string]$releaseManifestSnapshot.Sha256 -or
        [string]$installation.twillsContractSha256 -cne $ContractHash -or
        [string]$installation.signingPublicKeySpkiSha256 -cne
            $SigningFingerprint -or
        [string]$installation.snapshotDirectoryName -cnotmatch
            '^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$' -or
        [string]$installation.snapshotId -cnotmatch '^[0-9a-fA-F-]{36}$' -or
        [string]$installation.snapshotManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$installation.stateBindingSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The combat-canary installation record has an invalid fixed binding'
    }

    [void](Assert-PSOBBCombatCanaryOrdinaryTree `
            -Path $Layout.Server -Root $Layout.EnvironmentRoot `
            -Label 'Mutable combat-canary server')
    if ($selection.Artifact -ceq 'CurrentUpstream') {
        [void](Assert-PSOBBCombatCanaryRequiredReleaseDirectories `
                -Build $build -Root $Layout.Server)
    }
    $expectedMutableEntries = @(
        @($releaseEntries | Where-Object {
                -not (Test-PSOBBCombatCanaryVerifierMutableServerExemptPath `
                    -Path ([string]$_.path))
            }) +
        @([pscustomobject]@{
                path = 'release-manifest.json'
                size = [int64]$releaseManifestSnapshot.Length
                sha256 = [string]$releaseManifestSnapshot.Sha256
            }))
    $actualMutableEntries = @(Get-PSOBBDirectoryManifest -Root $Layout.Server)
    $comparableMutableEntries = @($actualMutableEntries | Where-Object {
            -not (Test-PSOBBCombatCanaryVerifierMutableServerExemptPath `
                -Path ([string]$_.path))
        })
    if (-not (Test-PSOBBManifestEntriesEqual `
            -Left $expectedMutableEntries -Right $comparableMutableEntries)) {
        throw 'The mutable combat-canary server inventory differs from server-base outside its sealed state and configuration'
    }
    $cacheContract = @(
        (Get-PSOBBCombatCanaryBuildContractSelection `
            -RepositoryRoot $script:RepositoryRoot) | Where-Object {
                [string]$_.Artifact -ceq 'StableShadow'
            })
    if ($cacheContract.Count -ne 1) {
        throw 'The generated metadata-cache policy is unavailable'
    }
    foreach ($cachePolicy in @(
            $cacheContract[0].Value.output.generatedMetadataCaches)) {
        [void](Assert-PSOBBCombatCanaryMetadataCache `
                -ServerRoot $Layout.Server -Policy $cachePolicy)
    }

    $configurationPath = Join-Path $Layout.Server 'system\config.json'
    $configurationSnapshot = Read-PSOBBCombatCanaryStrictUtf8Text `
        -LiteralPath $configurationPath -Root $Layout.Server -MaximumBytes 16MB `
        -ExpectedSha256 ([string]$installation.configurationSha256) `
        -RoleLabel 'combat canary configuration' -PassThruSnapshot
    $configurationText = [string]$configurationSnapshot.Value
    $credentialPolicyValid =
        Test-PSOBBCombatCanaryArtifactConfigurationPolicy `
            -Text $configurationText -ServerArtifact $selection.Artifact
    if (-not (Test-PSOBBCombatCanaryConfigStrictJson `
            -Text $configurationText) -or
        -not $credentialPolicyValid -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'ServerName' `
            -JsonPattern '"PSOBB Combat"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'LocalAddress' `
            -JsonPattern '"127\.0\.0\.1"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'ExternalAddress' `
            -JsonPattern '"127\.0\.0\.1"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'DNSServerPort' -JsonPattern '0') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'IPStackListen' -JsonPattern '\[\]') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'PPPStackListen' -JsonPattern '\[\]') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'PPPRawListen' -JsonPattern '\[\]') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'HTTPListen' -JsonPattern '\[\]') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'RunInteractiveShell' `
            -JsonPattern 'true') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'AllowUnregisteredUsers' `
            -JsonPattern 'false') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'CheatModeBehavior' `
            -JsonPattern '"Off"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'DefaultDropModeV4Normal' `
            -JsonPattern '"SERVER_PRIVATE"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'DefaultDropModeV4Battle' `
            -JsonPattern '"SERVER_SHARED"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'DefaultDropModeV4Challenge' `
            -JsonPattern '"SERVER_SHARED"') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'BBEXPShareMultiplier' `
            -JsonPattern '0') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'EnableSwitchAssistByDefault' `
            -JsonPattern 'true') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText `
            -Key 'RareNotificationsEnabledByDefaultV3V4' `
            -JsonPattern 'true') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'CommandData' `
            -JsonPattern '"DISABLED"') -or
        -not (Test-PSOBBCombatCanaryConfigKeyUnique `
            -Text $configurationText -Key 'AutoPatches') -or
        @(Get-ActiveConfigStringArray `
            -Text $configurationText -Key 'AutoPatches').Count -ne 0 -or
        -not (Test-PSOBBCombatCanaryConfigKeyUnique `
            -Text $configurationText -Key 'BBRequiredPatches') -or
        @(Get-ActiveConfigStringArray `
            -Text $configurationText -Key 'BBRequiredPatches').Count -ne 0 -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'bb-patch' `
            -JsonPattern '\[\["127\.0\.0\.1",\s*11000\],\s*"patch",\s*"patch_server_bb"\]') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'bb-data1' `
            -JsonPattern '\[\["127\.0\.0\.1",\s*12000\],\s*"bb",\s*"game_server"\]') -or
        -not (Test-PSOBBCombatCanaryConfigScalar `
            -Text $configurationText -Key 'bb-data2' `
            -JsonPattern '\[\["127\.0\.0\.1",\s*12001\],\s*"bb",\s*"game_server"\]')) {
        throw 'The combat-canary configuration is not the exact loopback baseline policy'
    }
    $mutableExecutablePath = Join-Path $Layout.Server 'newserv-windows.exe'
    if ((Get-Item -Force -LiteralPath $mutableExecutablePath).Length -ne
            [int64]$expectedExecutable.size -or
        (Get-LowerSha256 $mutableExecutablePath) -cne
            [string]$expectedExecutable.sha256) {
        throw 'The mutable combat-canary server executable differs from server-base'
    }

    [void](Assert-PSOBBCombatCanaryOrdinaryTree `
            -Path $Layout.BaseClient -Root $Layout.EnvironmentRoot `
            -Label 'Immutable combat-canary base client')
    [void](Assert-PSOBBCombatCanaryOrdinaryTree `
            -Path $Layout.Client -Root $Layout.EnvironmentRoot `
            -Label 'Mutable combat-canary runtime client')
    if ($selection.Artifact -ceq 'StableShadow' -and
        [string]$installation.baseClientManifestSha256 -cne
            [string]$stableShadowSource.BaseClientManifestSha256) {
        throw 'The StableShadow client manifest is not bound to Stable'
    }
    $baseManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $Layout.BaseClientManifest -Root $Layout.EnvironmentRoot `
        -MaximumBytes 16MB `
        -ExpectedSha256 ([string]$installation.baseClientManifestSha256) `
        -RoleLabel 'combat canary base client manifest' -PassThruSnapshot
    $baseManifestJson = $baseManifestSnapshot.Value
    $baseManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $baseManifestJson `
        -RoleLabel 'combat canary base client manifest'
    if ([int]$baseManifest.schemaVersion -ne 1 -or
        -not (Test-PSOBBDirectoryManifest `
            -Root $Layout.BaseClient -Files @($baseManifest.files))) {
        throw 'The immutable combat-canary base client differs from its manifest'
    }

    $clientBindingPath = Join-Path $Layout.EnvironmentRoot 'client-binding.json'
    $bindingItem = Get-Item -Force -LiteralPath $clientBindingPath -ErrorAction Stop
    if ($bindingItem.PSIsContainer -or
        ($bindingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-PSOBBProtectedAcl -Path $clientBindingPath) -or
        $bindingItem.Length -le 0 -or $bindingItem.Length -gt 256KB) {
        throw 'The combat-canary client binding is missing, unsafe, or changed'
    }
    $bindingSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $clientBindingPath -Root $Layout.EnvironmentRoot `
        -MaximumBytes 256KB `
        -ExpectedSha256 ([string]$installation.clientBindingSha256) `
        -RoleLabel 'combat canary client binding' -PassThruSnapshot
    $bindingJson = $bindingSnapshot.Value
    $binding = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $bindingJson -RoleLabel 'combat canary client binding'
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $binding `
        -Label 'Combat-canary client binding' `
        -Expected @('schemaVersion', 'environment', 'environmentId', 'profile',
            'renderer', 'serverAddress', 'patchPort', 'gamePorts',
            'clientExecutablePath', 'clientExecutableSize',
            'clientExecutableSha256', 'clientProfileSha256',
            'baseClientManifestSha256', 'createdAtUtc')
    $clientExecutable = Join-Path $Layout.Client 'Psobb.exe'
    $clientProfilePath = Join-Path $Layout.Client 'client-profile.json'
    $clientProfileSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $clientProfilePath -Root $Layout.Client -MaximumBytes 256KB `
        -ExpectedSha256 ([string]$binding.clientProfileSha256) `
        -RoleLabel 'combat canary client profile' -PassThruSnapshot
    $runtimeClientEntries = @(@($baseManifest.files) + @([pscustomobject]@{
                path = 'client-profile.json'
                size = [int64]$clientProfileSnapshot.Length
                sha256 = [string]$clientProfileSnapshot.Sha256
            }))
    if (-not (Test-PSOBBDirectoryManifest `
            -Root $Layout.Client -Files $runtimeClientEntries)) {
        throw 'The combat-canary runtime client is not an exact base-client copy plus client-profile.json'
    }
    $approvedClient = Get-PSOBBCombatCanaryApprovedClientIdentity `
        -RepositoryRoot $script:RepositoryRoot
    if ([int]$binding.schemaVersion -ne 1 -or
        [string]$binding.environment -cne 'CombatCanary' -or
        [string]$binding.environmentId -cne 'combat-canary' -or
        [string]$binding.profile -cne 'baseline' -or
        [string]$binding.renderer -cne 'Native' -or
        [string]$binding.serverAddress -cne '127.0.0.1' -or
        [int]$binding.patchPort -ne 11000 -or
        [string]::Join(',', @($binding.gamePorts)) -cne '12000,12001' -or
        [string]$binding.clientExecutablePath -cne 'runtime/client/Psobb.exe' -or
        [int64]$binding.clientExecutableSize -ne $approvedClient.Size -or
        [string]$binding.clientExecutableSha256 -cne $approvedClient.Sha256 -or
        ($selection.Artifact -ceq 'StableShadow' -and
            [string]$approvedClient.Sha256 -cne
                [string]$stableShadowSource.BaseClientExecutableSha256) -or
        [string]$binding.clientProfileSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$binding.baseClientManifestSha256 -cne
            [string]$baseManifestSnapshot.Sha256 -or
        (Get-Item -Force -LiteralPath $clientExecutable).Length -ne
            $approvedClient.Size -or
        (Get-LowerSha256 $clientExecutable) -cne $approvedClient.Sha256 -or
        [string]$clientProfileSnapshot.Sha256 -cne
            [string]$binding.clientProfileSha256) {
        throw 'The combat-canary client is not the exact baseline/native 59NL binding'
    }
    $clientProfileJson = $clientProfileSnapshot.Value
    $clientProfile = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $clientProfileJson -RoleLabel 'combat canary client profile'
    if ([int]$clientProfile.schemaVersion -ne 5 -or
        [string]$clientProfile.channel -cne 'combat-canary' -or
        [string]$clientProfile.profileId -cne 'safe-native-4x3' -or
        [string]$clientProfile.renderer -cne 'Native' -or
        [string]$clientProfile.baseExecutableSha256 -cne $approvedClient.Sha256 -or
        $null -ne $clientProfile.wrapperSha256 -or
        $null -ne $clientProfile.sourceConfigurationSha256 -or
        $null -ne $clientProfile.configurationSha256 -or
        $null -ne $clientProfile.outputApi -or
        [string]$clientProfile.graphicsPreset -cne 'Native') {
        throw 'The combat-canary materialized client profile is not baseline/native'
    }

    [pscustomobject]@{
        Valid = $true
        Installation = $installation
        Build = $build
        ServerArtifact = [string]$selection.Artifact
        ServerComponentId = [string]$selection.ComponentId
        BuildContractSha256 = $buildContractHash
        ReleaseManifest = $releaseManifest
        ReleaseManifestSha256 = [string]$releaseManifestSnapshot.Sha256
        BaseClientManifestSha256 = [string]$baseManifestSnapshot.Sha256
        ClientBindingSha256 = [string]$bindingSnapshot.Sha256
        ConfigurationSha256 = [string]$configurationSnapshot.Sha256
    }
}

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if (-not (Get-Command Get-PSOBBServerEnvironmentLayout -ErrorAction SilentlyContinue)) {
    throw 'Get-PSOBBServerEnvironmentLayout is required for combat-canary state verification'
}
[void](Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $rootLayout)
$layout = Assert-PSOBBCombatCanaryLayoutContract -Value (
    Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment CombatCanary)
$contractPath = Join-Path $script:RepositoryRoot 'config\twills-fonewearl-build.json'
$expectedTrackedContractHash = if ([string]::IsNullOrWhiteSpace(
        $ExpectedTwillsContractSha256)) { '' } else {
    $ExpectedTwillsContractSha256.ToLowerInvariant()
}
$trackedContractSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
    -LiteralPath $contractPath -Root $script:RepositoryRoot -MaximumBytes 128KB `
    -ExpectedSha256 $expectedTrackedContractHash -PassThruSnapshot `
    -RoleLabel 'tracked Twills contract'
$trackedContractHash = [string]$trackedContractSnapshot.Sha256
$trackedContractJson = $trackedContractSnapshot.Value
$trackedContract = ConvertTo-PSOBBCombatCanaryPowerShellObject `
    -JsonObject $trackedContractJson -RoleLabel 'tracked Twills contract'
if ([int]$trackedContract.schemaVersion -ne 2 -or
    [string]$trackedContract.character.name -cne 'Twills' -or
    [int]$trackedContract.character.classId -ne 8 -or
    [string]$trackedContract.character.className -cne 'FOnewearl' -or
    [int]$trackedContract.character.slotIndex -ne 0) {
    throw 'The tracked contract is not exact slot-0 Twills FOnewearl'
}
$trustedFingerprint = Get-PSOBBCombatCanaryTrustedFingerprint `
    -ExplicitFingerprint $ExpectedSigningPublicKeySpkiSha256
$snapshotResult = $null
$installationResult = $null
$installedResult = $null

if ($Target -in @('Installation', 'Installed', 'Both')) {
    $installationResult = Get-PSOBBCombatCanaryInstallation `
        -Layout $layout -ContractHash $trackedContractHash `
        -SigningFingerprint $trustedFingerprint `
        -ExplicitBuildContractHash $ExpectedBuildContractSha256
    [void](Assert-PSOBBLifecyclePathAcl `
            -Path $layout.ControlDirectory -Root $layout.Root `
            -IsContainer $true)
}

if ($Target -in @('Snapshot', 'Installed', 'Both')) {
    if ([string]::IsNullOrWhiteSpace($SnapshotPath)) {
        if ($null -ne $installationResult) {
            $SnapshotPath = Join-Path $layout.Snapshots (
                [string]$installationResult.Installation.snapshotDirectoryName)
        } else {
            $candidates = @(if (Test-Path -LiteralPath $layout.Snapshots `
                        -PathType Container) {
                    Get-ChildItem -Force -LiteralPath $layout.Snapshots -Directory |
                        Where-Object { $_.Name -cmatch '^twills-slot0-' } |
                        Sort-Object Name -Descending
                })
            if ($candidates.Count -eq 0) {
                throw 'No sealed combat-canary Twills snapshot is available'
            }
            $SnapshotPath = $candidates[0].FullName
        }
    }
    $snapshotResult = Test-PSOBBCombatCanarySnapshot `
        -Layout $layout -Path $SnapshotPath `
        -ContractHash $trackedContractHash `
        -SigningFingerprint $trustedFingerprint
}

if ($Target -in @('Installed', 'Both')) {
    $installation = $installationResult.Installation
    if ((Get-Item -Force -LiteralPath $snapshotResult.SnapshotPath).Name -cne
            [string]$installation.snapshotDirectoryName -or
        [string]$installation.snapshotId -cne $snapshotResult.SnapshotId -or
        [string]$installation.snapshotManifestSha256 -cne
            $snapshotResult.ManifestSha256) {
        throw 'The installed combat-canary state is not bound to the verified snapshot'
    }

    $stateBindingPath = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot 'state-binding.json') `
        -Root $layout.EnvironmentRoot
    $stateBindingItem = Get-Item -Force -LiteralPath $stateBindingPath -ErrorAction Stop
    if ($stateBindingItem.PSIsContainer -or
        ($stateBindingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-PSOBBProtectedAcl -Path $stateBindingPath) -or
        $stateBindingItem.Length -le 0 -or $stateBindingItem.Length -gt 256KB) {
        throw 'The installed combat-canary state binding is missing or changed'
    }
    $stateBindingSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $stateBindingPath -Root $layout.EnvironmentRoot `
        -MaximumBytes 256KB `
        -ExpectedSha256 ([string]$installation.stateBindingSha256) `
        -RoleLabel 'combat canary state binding' -PassThruSnapshot
    $stateBindingJson = $stateBindingSnapshot.Value
    $stateBinding = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $stateBindingJson -RoleLabel 'combat canary state binding'
    Assert-PSOBBCombatCanaryVerifierExactProperties -Value $stateBinding `
        -Label 'Combat-canary state binding' `
        -Expected @('schemaVersion', 'environment', 'environmentId',
            'restoredAtUtc', 'snapshotDirectoryName', 'snapshotId',
            'snapshotManifestSha256', 'twillsContractSha256',
            'signingPublicKeySpkiSha256', 'stateFiles')
    if ([int]$stateBinding.schemaVersion -ne 1 -or
        [string]$stateBinding.environment -cne 'CombatCanary' -or
        [string]$stateBinding.environmentId -cne 'combat-canary' -or
        [string]$stateBinding.snapshotDirectoryName -cne
            [string]$installation.snapshotDirectoryName -or
        [string]$stateBinding.snapshotId -cne [string]$snapshotResult.SnapshotId -or
        [string]$stateBinding.snapshotManifestSha256 -cne
            [string]$snapshotResult.ManifestSha256 -or
        [string]$stateBinding.twillsContractSha256 -cne $trackedContractHash -or
        [string]$stateBinding.signingPublicKeySpkiSha256 -cne $trustedFingerprint -or
        [int]$stateBinding.stateFiles -ne [int]$snapshotResult.StateFiles) {
        throw 'The installed combat-canary state binding is not exact'
    }

    $snapshotManifestJson = Read-PSOBBCombatCanaryStrictJsonObject -LiteralPath (
        Join-Path $snapshotResult.SnapshotPath 'manifest.json') `
        -Root $snapshotResult.SnapshotPath -MaximumBytes 256KB `
        -ExpectedSha256 ([string]$snapshotResult.ManifestSha256) `
        -RoleLabel 'installed state snapshot manifest'
    $snapshotManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $snapshotManifestJson `
        -RoleLabel 'installed state snapshot manifest'
    $stateEntries = @($snapshotManifest.files | Where-Object {
            [string]$_.path -cmatch '^state/system/'
        })
    [void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
            -Entries $stateEntries -Scope State)
    $systemRoot = Assert-PathWithinRoot `
        -Path (Join-Path $layout.Server 'system') -Root $layout.Server
    $expectedStatePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $installedCharacterPath = $null
    $installedBankPath = $null
    foreach ($entry in $stateEntries) {
        $relative = ([string]$entry.path).Substring('state/system/'.Length)
        if (-not $expectedStatePaths.Add($relative)) {
            throw 'The verified snapshot contains colliding installed-state paths'
        }
        try {
            $installedPath = Assert-PathWithinRoot `
                -Path (Join-Path $systemRoot ($relative.Replace('/', '\'))) `
                -Root $systemRoot
            [void](Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
                    -LiteralPath $installedPath -Root $systemRoot `
                    -MaximumBytes ([long](Get-PSOBBCombatCanaryPayloadRolePolicy `
                            -Role ([string]$entry.role)).MaximumBytes) `
                    -ExpectedLength ([int64]$entry.size) `
                    -ExpectedSha256 ([string]$entry.sha256) `
                    -RoleLabel 'installed combat canary state payload' `
                    -Consumer { param([byte[]]$Bytes) $Bytes.Length -gt 0 })
            if (-not (Test-PSOBBProtectedAcl -Path $installedPath)) {
                throw 'Installed state mismatch'
            }
        } catch {
            throw "Installed state readback failed for role '$($entry.role)'"
        }
        if ([string]$entry.role -ceq 'twills-character') {
            $installedCharacterPath = $installedPath
        } elseif ([string]$entry.role -ceq 'twills-bank') {
            $installedBankPath = $installedPath
        }
    }
    try {
        $actualStatePaths = @(foreach ($directoryName in @(
                    'licenses', 'players', 'teams')) {
                $directory = Join-Path $systemRoot $directoryName
                Get-ChildItem -Force -LiteralPath $directory -Recurse -File `
                    -ErrorAction Stop | ForEach-Object {
                        [void](Assert-PathWithinRoot `
                                -Path $_.FullName -Root $systemRoot)
                        [System.IO.Path]::GetRelativePath(
                            $systemRoot, $_.FullName).Replace('\', '/')
                    }
            })
    } catch {
        throw 'The installed combat-canary state inventory is unreadable or unsafe'
    }
    if ($actualStatePaths.Count -ne $expectedStatePaths.Count -or
        @($actualStatePaths | Where-Object {
                -not $expectedStatePaths.Contains($_)
            }).Count -ne 0 -or
        [string]::IsNullOrWhiteSpace($installedCharacterPath) -or
        [string]::IsNullOrWhiteSpace($installedBankPath)) {
        throw 'The installed combat-canary state contains missing or extra payloads'
    }
    foreach ($directoryName in @('licenses', 'players', 'teams')) {
        $prefix = $directoryName + '/'
        $directoryFiles = @($stateEntries | ForEach-Object {
                ([string]$_.path).Substring('state/system/'.Length)
            } | Where-Object { $_.StartsWith(
                    $prefix, [System.StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { $_.Substring($prefix.Length) })
        $expectedStateDirectories = Get-PSOBBCombatCanaryExpectedDirectories `
            -FilePaths $directoryFiles
        [void](Assert-PSOBBCombatCanaryExactDirectoryInventory `
                -Root (Join-Path $systemRoot $directoryName) `
                -ExpectedDirectories $expectedStateDirectories `
                -RoleLabel 'installed combat canary state' -RequireProtected)
    }
    [void](Get-PSOBBCombatCanarySemanticResult `
            -CharacterPath $installedCharacterPath -BankPath $installedBankPath `
            -ContractPath (Join-Path $script:RepositoryRoot `
                'config\twills-fonewearl-build.json') `
            -ContractSha256 $trackedContractHash)

    $installedResult = [pscustomobject]@{
        Valid = $true
        Target = 'Installed'
        Environment = 'CombatCanary'
        SnapshotId = $snapshotResult.SnapshotId
        SnapshotManifestSha256 = $snapshotResult.ManifestSha256
        ServerArtifact = $installationResult.ServerArtifact
        ServerComponentId = $installationResult.ServerComponentId
        BuildContractSha256 = $installationResult.BuildContractSha256
        ServerReleaseManifestSha256 = $installationResult.ReleaseManifestSha256
        BaseClientManifestSha256 = $installationResult.BaseClientManifestSha256
        ClientBindingSha256 = $installationResult.ClientBindingSha256
        ConfigurationSha256 = $installationResult.ConfigurationSha256
        StateBindingSha256 = [string]$stateBindingSnapshot.Sha256
        TwillsContractSha256 = $trackedContractHash
        SigningPublicKeySpkiSha256 = $trustedFingerprint
    }
}

if ($Target -ceq 'Snapshot') { $snapshotResult }
elseif ($Target -ceq 'Installation') {
    [pscustomobject]@{
        Valid = $true
        Target = 'Installation'
        Environment = 'CombatCanary'
        ServerArtifact = $installationResult.ServerArtifact
        ServerComponentId = $installationResult.ServerComponentId
        BuildContractSha256 = $installationResult.BuildContractSha256
        ServerReleaseManifestSha256 = $installationResult.ReleaseManifestSha256
        BaseClientManifestSha256 = $installationResult.BaseClientManifestSha256
        ClientBindingSha256 = $installationResult.ClientBindingSha256
        ConfigurationSha256 = $installationResult.ConfigurationSha256
        TwillsContractSha256 = $trackedContractHash
        SigningPublicKeySpkiSha256 = $trustedFingerprint
    }
}
elseif ($Target -ceq 'Installed') { $installedResult }
else {
    [pscustomobject]@{
        Valid = $true
        Target = 'Both'
        Snapshot = $snapshotResult
        Installation = $installationResult
        Installed = $installedResult
    }
}
