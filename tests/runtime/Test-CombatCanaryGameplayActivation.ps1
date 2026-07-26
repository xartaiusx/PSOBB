[CmdletBinding()]
param(
    [string]$RuntimeRoot,

    [ValidateSet('Core', 'ActivateHardExit', 'RollbackHardExit')]
    [string]$Shard = 'Core',

    [ValidateSet('', 'after-transaction-publish', 'after-loader',
        'after-module', 'after-configuration', 'after-binding',
        'after-installation', 'after-rollback-marker-staging',
        'after-rollback-marker')]
    [string]$Boundary = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Shard = switch ($Shard.ToLowerInvariant()) {
    'core' { 'Core' }
    'activatehardexit' { 'ActivateHardExit' }
    'rollbackhardexit' { 'RollbackHardExit' }
    default { throw "Unsupported Gameplay activation test shard: $Shard" }
}
$Boundary = $Boundary.ToLowerInvariant()

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$publisherPath = Join-Path $repositoryRoot `
    'scripts\Set-PSOBBCombatCanaryGameplay.ps1'
$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
$aclPolicyPath = Join-Path $repositoryRoot `
    'scripts\PSOBB.RuntimeAclPolicy.ps1'
$combatCommonPath = Join-Path $repositoryRoot `
    'scripts\PSOBB.CombatCanary.Common.ps1'
$results = [System.Collections.Generic.List[object]]::new()
$runCore = $Shard -ceq 'Core'
$runActivateHardExit = $Shard -ceq 'ActivateHardExit'
$runRollbackHardExit = $Shard -ceq 'RollbackHardExit'

if ($Shard -ceq 'Core' -and
    -not [string]::IsNullOrWhiteSpace($Boundary)) {
    throw 'Boundary filtering requires an action-specific hard-exit shard'
}
if ($Shard -cne 'Core' -and
    [string]::IsNullOrWhiteSpace($Boundary)) {
    throw 'Each hard-exit shard invocation requires exactly one Boundary'
}
if ($Shard -ceq 'ActivateHardExit' -and
    $Boundary -in @('after-rollback-marker-staging',
        'after-rollback-marker')) {
    throw "$Boundary is not an Activate boundary"
}

. $commonPath
. $aclPolicyPath
. $combatCommonPath

function Write-TestProgress {
    param([Parameter(Mandatory)][string]$Message)

    Write-Information "[GameplayActivation:$Shard] $Message" `
        -InformationAction Continue
}

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [AllowEmptyString()][Parameter(Mandatory)][string]$Detail
    )

    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
    if (-not $Passed) {
        throw "$Name failed: $Detail"
    }
}

function Write-FixtureBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes,
        [switch]$Protect
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }
    [void](Write-PSOBBDurableFileBytes -Path $Path -Root $Root -Bytes $Bytes `
            -Label 'Gameplay activation fixture artifact')
    if ($Protect) {
        Set-PSOBBProtectedAcl -Path $Path
        if (-not (Test-PSOBBProtectedAcl -Path $Path)) {
            throw 'Gameplay activation fixture protection did not persist'
        }
    }
}

function Write-FixtureJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Value,
        [switch]$Protect
    )

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 16))
    try {
        Write-FixtureBytes -Path $Path -Root $Root -Bytes $bytes `
            -Protect:$Protect
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-FixtureTreeFingerprint {
    param([Parameter(Mandatory)][string]$Root)

    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @(Get-ChildItem -Force -LiteralPath $Root -Recurse |
                Sort-Object FullName)) {
        $relative = [System.IO.Path]::GetRelativePath(
            $Root, $entry.FullName).Replace('\', '/')
        $acl = (Get-Acl -LiteralPath $entry.FullName).Sddl
        if ($entry.PSIsContainer) {
            $records.Add("$relative|directory|$acl")
        } else {
            $records.Add(
                "$relative|file|$($entry.Length)|$(Get-LowerSha256 $entry.FullName)|$acl")
        }
    }
    @($records)
}

function Get-GameplayPublisherSurfaceFingerprint {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$StableLayout,
        [Parameter(Mandatory)]$CombatLayout
    )

    $leafPaths = @(
        (Join-Path $StableLayout.Client 'Psobb.exe'),
        $StableLayout.InstallRecord,
        (Join-Path $CombatLayout.Client 'dinput8.dll'),
        (Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.asi'),
        (Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.ini'),
        (Join-Path $CombatLayout.EnvironmentRoot 'client-binding.json'),
        $CombatLayout.InstallRecord,
        (Join-Path $CombatLayout.Client '.psobb-gameplay-loader.new'),
        (Join-Path $CombatLayout.Client 'plugins\.psobb-gameplay-module.new'),
        (Join-Path $CombatLayout.Client 'plugins\.psobb-gameplay-configuration.new'),
        (Join-Path $CombatLayout.EnvironmentRoot '.psobb-gameplay-binding.new'),
        (Join-Path $CombatLayout.EnvironmentRoot '.psobb-gameplay-installation.new'))
    $treePaths = @(
        (Join-Path $CombatLayout.EnvironmentRoot '.gameplay-transaction'),
        (Join-Path $CombatLayout.EnvironmentRoot '.gameplay-transaction.next'),
        (Join-Path $CombatLayout.Backups 'gameplay-activations'))
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $leafPaths) {
        $relative = [System.IO.Path]::GetRelativePath(
            $Layout.Root, $path).Replace('\', '/')
        if (-not (Test-Path -LiteralPath $path)) {
            $records.Add("$relative|absent")
            continue
        }
        [void](Assert-PSOBBOrdinaryContainedPath -Path $path -Root $Layout.Root `
                -Kind File -Label 'canonical Gameplay publisher surface')
        $item = Get-Item -Force -LiteralPath $path
        if ([string]$item.LinkType -ceq 'HardLink') {
            throw 'A canonical Gameplay publisher surface file is hard-linked'
        }
        $records.Add(
            "$relative|file|$($item.Length)|$(Get-LowerSha256 $path)|$((Get-Acl -LiteralPath $path).Sddl)")
    }
    foreach ($tree in $treePaths) {
        $relativeRoot = [System.IO.Path]::GetRelativePath(
            $Layout.Root, $tree).Replace('\', '/')
        if (-not (Test-Path -LiteralPath $tree)) {
            $records.Add("$relativeRoot|absent")
            continue
        }
        [void](Assert-PSOBBOrdinaryContainedPath -Path $tree -Root $Layout.Root `
                -Kind Directory -Label 'canonical Gameplay publisher tree')
        $records.Add(
            "$relativeRoot|directory|$((Get-Acl -LiteralPath $tree).Sddl)")
        foreach ($entry in @(Get-ChildItem -Force -LiteralPath $tree -Recurse |
                    Sort-Object FullName)) {
            $relative = [System.IO.Path]::GetRelativePath(
                $Layout.Root, $entry.FullName).Replace('\', '/')
            [void](Assert-PSOBBOrdinaryContainedPath -Path $entry.FullName `
                    -Root $tree -Kind $(if ($entry.PSIsContainer) {
                            'Directory'
                        } else { 'File' }) `
                    -Label 'canonical Gameplay publisher tree entry')
            $acl = (Get-Acl -LiteralPath $entry.FullName).Sddl
            if ($entry.PSIsContainer) {
                $records.Add("$relative|directory|$acl")
            } else {
                if ([string]$entry.LinkType -ceq 'HardLink') {
                    throw 'A canonical Gameplay publisher tree file is hard-linked'
                }
                $records.Add(
                    "$relative|file|$($entry.Length)|$(Get-LowerSha256 $entry.FullName)|$acl")
            }
        }
    }
    @($records | Sort-Object)
}

function Get-GameplayBackupDirectoryNames {
    param([Parameter(Mandatory)]$CombatLayout)

    $root = Join-Path $CombatLayout.Backups 'gameplay-activations'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    @(
        Get-ChildItem -Force -LiteralPath $root -Directory |
            ForEach-Object Name |
            Sort-Object
    )
}

function Get-NewGameplayBackupDirectories {
    param(
        [AllowEmptyCollection()][Parameter(Mandatory)][string[]]$Before,
        [Parameter(Mandatory)]$CombatLayout
    )

    @(
        Get-GameplayBackupDirectoryNames -CombatLayout $CombatLayout |
            Where-Object { $_ -cnotin $Before }
    )
}

function Assert-FixtureOrdinaryFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Protected
    )

    [void](Assert-PSOBBOrdinaryContainedPath -Path $Path -Root $Root `
            -Kind File -Label $Label)
    $item = Get-Item -Force -LiteralPath $Path
    if ([string]$item.LinkType -ceq 'HardLink' -or
        ($Protected -and -not (Test-PSOBBProtectedAcl -Path $Path))) {
        throw "$Label is hard-linked or insufficiently protected"
    }
    $item
}

function Assert-GameplayInstallationShape {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    $properties = @(
        'schemaVersion', 'environment', 'environmentId', 'initializedAtUtc',
        'buildContractSha256', 'serverReleaseManifestSha256',
        'baseClientManifestSha256', 'clientBindingSha256',
        'snapshotDirectoryName', 'snapshotId', 'snapshotManifestSha256',
        'stateBindingSha256', 'twillsContractSha256',
        'signingPublicKeySpkiSha256', 'configurationSha256')
    [void](Assert-PSOBBStrictDataObjectProperties -Value $Value `
            -Expected $properties -Label $Label)
    if ($Value.schemaVersion -isnot [long] -or
        [long]$Value.schemaVersion -ne 1 -or
        $Value.environment -isnot [string] -or
        [string]$Value.environment -cne 'CombatCanary' -or
        $Value.environmentId -isnot [string] -or
        [string]$Value.environmentId -cne 'combat-canary') {
        throw "$Label has an invalid fixed identity"
    }
    foreach ($name in @($properties | Where-Object { $_ -cne 'schemaVersion' })) {
        if ($Value.$name -isnot [string]) {
            throw "$Label contains a non-string $name"
        }
    }
    foreach ($name in @(
            'buildContractSha256', 'serverReleaseManifestSha256',
            'baseClientManifestSha256', 'clientBindingSha256',
            'snapshotManifestSha256', 'stateBindingSha256',
            'twillsContractSha256', 'signingPublicKeySpkiSha256',
            'configurationSha256')) {
        if ([string]$Value.$name -cnotmatch '^[a-f0-9]{64}$') {
            throw "$Label contains an invalid $name"
        }
    }
}

function Assert-GameplayMetadataPreserved {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)][string]$ExpectedClientBindingSha256
    )

    Assert-GameplayInstallationShape -Value $Expected `
        -Label 'expected Gameplay installation metadata'
    Assert-GameplayInstallationShape -Value $Actual `
        -Label 'actual Gameplay installation metadata'
    $expectedNames = @($Expected.PSObject.Properties.Name | Sort-Object)
    $actualNames = @($Actual.PSObject.Properties.Name | Sort-Object)
    if ([string]::Join("`n", $expectedNames) -cne
        [string]::Join("`n", $actualNames)) {
        throw 'Gameplay installation metadata property topology changed'
    }
    foreach ($property in $Expected.PSObject.Properties) {
        if ($property.Name -ceq 'clientBindingSha256') { continue }
        $actualValue = $Actual.($property.Name)
        if ($null -eq $property.Value -or $null -eq $actualValue -or
            $property.Value.GetType() -ne $actualValue.GetType() -or
            -not ($property.Value -ceq $actualValue)) {
            throw "Gameplay installation metadata changed at $($property.Name)"
        }
    }
    if ($Actual.clientBindingSha256 -isnot [string] -or
        [string]$Actual.clientBindingSha256 -cne $ExpectedClientBindingSha256) {
        throw 'Gameplay installation metadata has the wrong client binding'
    }
}

function Get-GameplayLiveState {
    param(
        [Parameter(Mandatory)]$StableLayout,
        [Parameter(Mandatory)]$CombatLayout
    )

    $paths = @(
        [pscustomobject]@{
            Name = 'stable-client'
            Path = Join-Path $StableLayout.Client 'Psobb.exe'
        },
        [pscustomobject]@{
            Name = 'stable-installation'
            Path = $StableLayout.InstallRecord
        },
        [pscustomobject]@{
            Name = 'combat-loader'
            Path = Join-Path $CombatLayout.Client 'dinput8.dll'
        },
        [pscustomobject]@{
            Name = 'combat-module'
            Path = Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.asi'
        },
        [pscustomobject]@{
            Name = 'combat-configuration'
            Path = Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.ini'
        },
        [pscustomobject]@{
            Name = 'combat-binding'
            Path = Join-Path $CombatLayout.EnvironmentRoot 'client-binding.json'
        },
        [pscustomobject]@{
            Name = 'combat-installation'
            Path = $CombatLayout.InstallRecord
        })
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $paths) {
        if (Test-Path -LiteralPath $entry.Path -PathType Leaf) {
            $item = Get-Item -Force -LiteralPath $entry.Path
            $records.Add(
                "$($entry.Name)|file|$($item.Length)|$(Get-LowerSha256 $entry.Path)|$((Get-Acl -LiteralPath $entry.Path).Sddl)")
        } else {
            $records.Add("$($entry.Name)|absent")
        }
    }
    $plugins = Join-Path $CombatLayout.Client 'plugins'
    $pluginNames = if (Test-Path -LiteralPath $plugins -PathType Container) {
        @(Get-ChildItem -Force -LiteralPath $plugins |
            ForEach-Object Name | Sort-Object)
    } else { @() }
    $pluginInventory = if (@($pluginNames).Count -eq 0) {
        ''
    } else {
        [string]::Join(',', [string[]]@($pluginNames))
    }
    $records.Add('plugins|' + $pluginInventory)
    @($records)
}

function Get-GameplayIdempotentFingerprint {
    param(
        [Parameter(Mandatory)]$StableLayout,
        [Parameter(Mandatory)]$CombatLayout,
        [string]$ActiveActivationId = ''
    )

    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($record in @(Get-GameplayLiveState -StableLayout $StableLayout `
                -CombatLayout $CombatLayout)) {
        $records.Add([string]$record)
    }
    $records.Add('backups|' + [string]::Join(',', @(
                Get-GameplayBackupDirectoryNames -CombatLayout $CombatLayout)))
    foreach ($path in @(
            (Join-Path $CombatLayout.EnvironmentRoot '.gameplay-transaction'),
            (Join-Path $CombatLayout.EnvironmentRoot '.gameplay-transaction.next'),
            (Join-Path $CombatLayout.Client '.psobb-gameplay-loader.new'),
            (Join-Path $CombatLayout.Client 'plugins\.psobb-gameplay-module.new'),
            (Join-Path $CombatLayout.Client `
                'plugins\.psobb-gameplay-configuration.new'),
            (Join-Path $CombatLayout.EnvironmentRoot `
                '.psobb-gameplay-binding.new'),
            (Join-Path $CombatLayout.EnvironmentRoot `
                '.psobb-gameplay-installation.new'))) {
        $relative = [System.IO.Path]::GetRelativePath(
            $CombatLayout.EnvironmentRoot, $path).Replace('\', '/')
        $records.Add("debris:$relative|$([bool](Test-Path -LiteralPath $path))")
    }
    if (-not [string]::IsNullOrWhiteSpace($ActiveActivationId)) {
        $activationRoot = Join-Path (Join-Path $CombatLayout.Backups `
                'gameplay-activations') $ActiveActivationId
        foreach ($record in @(Get-FixtureTreeFingerprint -Root $activationRoot)) {
            $records.Add("active-snapshot:$record")
        }
    }
    @($records)
}

function Assert-BaselineState {
    param(
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)][string]$ExpectedBindingSha256
    )

    $bindingPath = Join-Path $CombatLayout.EnvironmentRoot `
        'client-binding.json'
    [void](Assert-FixtureOrdinaryFile -Path $bindingPath `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'baseline Gameplay binding' -Protected)
    [void](Assert-FixtureOrdinaryFile -Path $CombatLayout.InstallRecord `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'baseline Gameplay installation' -Protected)
    $bindingSnapshot = Read-PSOBBStrictJsonSnapshot -Path $bindingPath `
        -Root $CombatLayout.EnvironmentRoot -MaximumBytes 64KB `
        -MaximumDepth 8 -Label 'baseline Gameplay binding'
    $installationSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $CombatLayout.InstallRecord -Root $CombatLayout.EnvironmentRoot `
        -MaximumBytes 64KB -MaximumDepth 8 `
        -Label 'baseline Gameplay installation'
    $binding = $bindingSnapshot.Value
    $installation = $installationSnapshot.Value
    [void](Assert-PSOBBStrictDataObjectProperties -Value $binding `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'profile', 'renderer', 'serverAddress', 'patchPort',
                'gamePorts', 'clientExecutablePath', 'clientExecutableSize',
                'clientExecutableSha256', 'clientProfileSha256',
                'baseClientManifestSha256', 'createdAtUtc') `
            -Label 'baseline Gameplay binding')
    Assert-GameplayInstallationShape -Value $installation `
        -Label 'baseline Gameplay installation'
    $overlayPaths = @(
        (Join-Path $CombatLayout.Client 'dinput8.dll'),
        (Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.asi'),
        (Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.ini'))
    $plugins = Join-Path $CombatLayout.Client 'plugins'
    $valid =
        $binding.schemaVersion -is [long] -and
        [long]$binding.schemaVersion -eq 1 -and
        $binding.environment -is [string] -and
        [string]$binding.environment -ceq 'CombatCanary' -and
        $binding.environmentId -is [string] -and
        [string]$binding.environmentId -ceq 'combat-canary' -and
        $binding.profile -is [string] -and
        [string]$binding.profile -ceq 'baseline' -and
        $binding.renderer -is [string] -and
        [string]$binding.renderer -ceq 'Native' -and
        $binding.serverAddress -is [string] -and
        [string]$binding.serverAddress -ceq '127.0.0.1' -and
        $binding.patchPort -is [long] -and
        [long]$binding.patchPort -eq 11000 -and
        $binding.gamePorts -is [System.Array] -and
        @($binding.gamePorts).Count -eq 2 -and
        @($binding.gamePorts | Where-Object { $_ -isnot [long] }).Count -eq 0 -and
        [string]::Join(',', @($binding.gamePorts)) -ceq '12000,12001' -and
        $binding.clientExecutablePath -is [string] -and
        [string]$binding.clientExecutablePath -ceq 'runtime/client/Psobb.exe' -and
        $binding.clientExecutableSize -is [long] -and
        [long]$binding.clientExecutableSize -eq 6971904 -and
        $binding.clientExecutableSha256 -is [string] -and
        [string]$binding.clientExecutableSha256 -ceq
            'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535' -and
        $binding.clientProfileSha256 -is [string] -and
        [string]$binding.clientProfileSha256 -cmatch '^[a-f0-9]{64}$' -and
        $binding.baseClientManifestSha256 -is [string] -and
        [string]$binding.baseClientManifestSha256 -cmatch '^[a-f0-9]{64}$' -and
        $binding.createdAtUtc -is [string] -and
        [string]$installation.clientBindingSha256 -ceq $ExpectedBindingSha256 -and
        [string]$bindingSnapshot.Sha256 -ceq $ExpectedBindingSha256 -and
        -not ($overlayPaths | Where-Object { Test-Path -LiteralPath $_ }) -and
        -not (Test-Path -LiteralPath $plugins)
    if (-not $valid) {
        throw 'The Gameplay fixture is not in its exact baseline state'
    }
}

function Assert-ActiveState {
    param(
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$ConfigurationIdentity
    )

    $bindingPath = Join-Path $CombatLayout.EnvironmentRoot `
        'client-binding.json'
    [void](Assert-FixtureOrdinaryFile -Path $bindingPath `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'active Gameplay binding' -Protected)
    [void](Assert-FixtureOrdinaryFile -Path $CombatLayout.InstallRecord `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'active Gameplay installation' -Protected)
    $bindingSnapshot = Read-PSOBBStrictJsonSnapshot -Path $bindingPath `
        -Root $CombatLayout.EnvironmentRoot -MaximumBytes 64KB `
        -MaximumDepth 8 -Label 'active Gameplay binding'
    $installationSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $CombatLayout.InstallRecord -Root $CombatLayout.EnvironmentRoot `
        -MaximumBytes 64KB -MaximumDepth 8 `
        -Label 'active Gameplay installation'
    $binding = $bindingSnapshot.Value
    $installation = $installationSnapshot.Value
    [void](Assert-PSOBBStrictDataObjectProperties -Value $binding `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'profile', 'renderer', 'serverAddress', 'patchPort',
                'gamePorts', 'clientExecutablePath', 'clientExecutableSize',
                'clientExecutableSha256', 'clientProfileSha256',
                'baseClientManifestSha256', 'createdAtUtc', 'gameplayOverlay') `
            -Label 'active Gameplay binding')
    [void](Assert-PSOBBStrictDataObjectProperties `
            -Value $binding.gameplayOverlay `
            -Expected @('loaderPath', 'loaderSize', 'loaderSha256',
                'modulePath', 'moduleSize', 'moduleSha256',
                'configurationPath', 'configurationSize',
                'configurationSha256') -Label 'active Gameplay overlay')
    Assert-GameplayInstallationShape -Value $installation `
        -Label 'active Gameplay installation'
    $expected = @(
        [pscustomobject]@{
            Path = Join-Path $CombatLayout.Client 'dinput8.dll'
            Size = [long]$Authority.LoaderSize
            Sha256 = [string]$Authority.LoaderSha256
        },
        [pscustomobject]@{
            Path = Join-Path $CombatLayout.Client `
                'plugins\PSOBB.Gameplay.asi'
            Size = [long]$Authority.ModuleSize
            Sha256 = [string]$Authority.ModuleSha256
        },
        [pscustomobject]@{
            Path = Join-Path $CombatLayout.Client `
                'plugins\PSOBB.Gameplay.ini'
            Size = [long]$ConfigurationIdentity.Size
            Sha256 = [string]$ConfigurationIdentity.Sha256
        })
    $valid =
        $binding.schemaVersion -is [long] -and
        [long]$binding.schemaVersion -eq 2 -and
        $binding.environment -is [string] -and
        [string]$binding.environment -ceq 'CombatCanary' -and
        $binding.environmentId -is [string] -and
        [string]$binding.environmentId -ceq 'combat-canary' -and
        $binding.profile -is [string] -and
        [string]$binding.profile -ceq 'baseline' -and
        $binding.renderer -is [string] -and
        [string]$binding.renderer -ceq 'Native' -and
        $binding.serverAddress -is [string] -and
        [string]$binding.serverAddress -ceq '127.0.0.1' -and
        $binding.patchPort -is [long] -and
        [long]$binding.patchPort -eq 11000 -and
        $binding.gamePorts -is [System.Array] -and
        @($binding.gamePorts).Count -eq 2 -and
        @($binding.gamePorts | Where-Object { $_ -isnot [long] }).Count -eq 0 -and
        [string]::Join(',', @($binding.gamePorts)) -ceq '12000,12001' -and
        $binding.clientExecutablePath -is [string] -and
        [string]$binding.clientExecutablePath -ceq 'runtime/client/Psobb.exe' -and
        $binding.clientExecutableSize -is [long] -and
        [long]$binding.clientExecutableSize -eq 6971904 -and
        $binding.clientExecutableSha256 -is [string] -and
        [string]$binding.clientExecutableSha256 -ceq
            'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535' -and
        $binding.clientProfileSha256 -is [string] -and
        [string]$binding.clientProfileSha256 -cmatch '^[a-f0-9]{64}$' -and
        $binding.baseClientManifestSha256 -is [string] -and
        [string]$binding.baseClientManifestSha256 -cmatch '^[a-f0-9]{64}$' -and
        $binding.createdAtUtc -is [string] -and
        [string]$installation.clientBindingSha256 -ceq
            [string]$bindingSnapshot.Sha256 -and
        $binding.gameplayOverlay.loaderPath -is [string] -and
        [string]$binding.gameplayOverlay.loaderPath -ceq
            'runtime/client/dinput8.dll' -and
        $binding.gameplayOverlay.loaderSize -is [long] -and
        [long]$binding.gameplayOverlay.loaderSize -eq [long]$Authority.LoaderSize -and
        [string]$binding.gameplayOverlay.loaderSha256 -ceq
            [string]$Authority.LoaderSha256 -and
        $binding.gameplayOverlay.modulePath -is [string] -and
        [string]$binding.gameplayOverlay.modulePath -ceq
            'runtime/client/plugins/PSOBB.Gameplay.asi' -and
        $binding.gameplayOverlay.moduleSize -is [long] -and
        [long]$binding.gameplayOverlay.moduleSize -eq [long]$Authority.ModuleSize -and
        [string]$binding.gameplayOverlay.moduleSha256 -ceq
            [string]$Authority.ModuleSha256 -and
        $binding.gameplayOverlay.configurationPath -is [string] -and
        [string]$binding.gameplayOverlay.configurationPath -ceq
            'runtime/client/plugins/PSOBB.Gameplay.ini' -and
        $binding.gameplayOverlay.configurationSize -is [long] -and
        [long]$binding.gameplayOverlay.configurationSize -eq
            [long]$ConfigurationIdentity.Size -and
        [string]$binding.gameplayOverlay.configurationSha256 -ceq
            [string]$ConfigurationIdentity.Sha256
    foreach ($entry in $expected) {
        $valid = $valid -and
            (Test-Path -LiteralPath $entry.Path -PathType Leaf) -and
            $null -ne (Assert-FixtureOrdinaryFile -Path $entry.Path `
                -Root $CombatLayout.EnvironmentRoot `
                -Label 'active Gameplay payload') -and
            (Get-Item -Force -LiteralPath $entry.Path).Length -eq $entry.Size -and
            (Get-LowerSha256 $entry.Path) -ceq $entry.Sha256
    }
    $plugins = Join-Path $CombatLayout.Client 'plugins'
    $pluginNames = if (Test-Path -LiteralPath $plugins -PathType Container) {
        @(Get-ChildItem -Force -LiteralPath $plugins | ForEach-Object Name |
            Sort-Object)
    } else { @() }
    $valid = $valid -and
        [string]::Join("`n", $pluginNames) -ceq
            "PSOBB.Gameplay.asi`nPSOBB.Gameplay.ini"
    if (-not $valid) {
        throw 'The Gameplay fixture is not in its exact observation state'
    }
}

function Assert-GameplayTransactionBoundary {
    param(
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)][ValidateSet('Activate', 'Rollback')]
        [string]$Action,
        [Parameter(Mandatory)][string]$Point,
        [Parameter(Mandatory)][string]$RuntimeInstallationId
    )

    $root = Join-Path $CombatLayout.EnvironmentRoot '.gameplay-transaction'
    [void](Assert-PSOBBOrdinaryContainedPath -Path $root `
            -Root $CombatLayout.EnvironmentRoot -Kind Directory `
            -Label 'Gameplay abrupt-exit transaction')
    if (-not (Test-PSOBBProtectedAcl -Path $root)) {
        throw 'Gameplay abrupt-exit transaction root is not protected'
    }
    $expectedNames = @(
        'PSOBB.Gameplay.asi', 'PSOBB.Gameplay.ini', 'activation.json',
        'candidate-client-binding.json', 'candidate-installation.json',
        'dinput8.dll', 'original-client-binding.json',
        'original-installation.json')
    if ($Point -in @('after-binding', 'after-installation',
            'after-rollback-marker-staging',
            'after-rollback-marker')) {
        $expectedNames += 'replaced-original-client-binding.json'
    }
    if ($Point -in @('after-installation',
            'after-rollback-marker-staging', 'after-rollback-marker')) {
        $expectedNames += 'replaced-original-installation.json'
    }
    $entries = @(Get-ChildItem -Force -LiteralPath $root)
    if (@($entries | Where-Object PSIsContainer).Count -ne 0 -or
        [string]::Join("`n", @($entries.Name | Sort-Object)) -cne
            [string]::Join("`n", @($expectedNames | Sort-Object))) {
        throw "Gameplay abrupt-exit transaction inventory is wrong at $Point"
    }

    $manifestPath = Join-Path $root 'activation.json'
    [void](Assert-FixtureOrdinaryFile -Path $manifestPath -Root $root `
            -Label 'Gameplay abrupt-exit manifest' -Protected)
    $manifestSnapshot = Read-PSOBBStrictJsonSnapshot -Path $manifestPath `
        -Root $root -MaximumBytes 64KB -MaximumDepth 8 `
        -Label 'Gameplay abrupt-exit manifest'
    $manifest = $manifestSnapshot.Value
    [void](Assert-PSOBBStrictDataObjectProperties -Value $manifest `
            -Expected @('schemaVersion', 'runtimeInstallationId',
                'transactionId', 'activationId', 'action', 'createdAtUtc',
                'pluginsDirectoryExisted', 'originalBindingSize',
                'originalBindingSha256', 'originalInstallationSize',
                'originalInstallationSha256', 'activeBindingSize',
                'activeBindingSha256', 'candidateBindingSize',
                'candidateBindingSha256', 'candidateInstallationSize',
                'candidateInstallationSha256', 'loaderSize', 'loaderSha256',
                'moduleSize', 'moduleSha256', 'configurationSize',
                'configurationSha256') -Label 'Gameplay abrupt-exit manifest')
    $createdAt = [DateTimeOffset]::MinValue
    if ($manifest.schemaVersion -isnot [long] -or
        [long]$manifest.schemaVersion -ne 1 -or
        $manifest.runtimeInstallationId -isnot [string] -or
        [string]$manifest.runtimeInstallationId -cne $RuntimeInstallationId -or
        $manifest.transactionId -isnot [string] -or
        [string]$manifest.transactionId -cnotmatch '^[a-f0-9]{32}$' -or
        $manifest.activationId -isnot [string] -or
        [string]$manifest.activationId -cnotmatch
            '^gameplay-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' -or
        $manifest.action -isnot [string] -or
        [string]$manifest.action -cne $Action -or
        $manifest.createdAtUtc -isnot [string] -or
        -not [DateTimeOffset]::TryParse(
            [string]$manifest.createdAtUtc, [ref]$createdAt) -or
        $manifest.pluginsDirectoryExisted -isnot [bool]) {
        throw 'Gameplay abrupt-exit manifest identity is invalid'
    }
    $definitions = @(
        [pscustomobject]@{ Name = 'original-client-binding.json'; Size = 'originalBindingSize'; Sha = 'originalBindingSha256' },
        [pscustomobject]@{ Name = 'original-installation.json'; Size = 'originalInstallationSize'; Sha = 'originalInstallationSha256' },
        [pscustomobject]@{ Name = 'candidate-client-binding.json'; Size = 'candidateBindingSize'; Sha = 'candidateBindingSha256' },
        [pscustomobject]@{ Name = 'candidate-installation.json'; Size = 'candidateInstallationSize'; Sha = 'candidateInstallationSha256' },
        [pscustomobject]@{ Name = 'dinput8.dll'; Size = 'loaderSize'; Sha = 'loaderSha256' },
        [pscustomobject]@{ Name = 'PSOBB.Gameplay.asi'; Size = 'moduleSize'; Sha = 'moduleSha256' },
        [pscustomobject]@{ Name = 'PSOBB.Gameplay.ini'; Size = 'configurationSize'; Sha = 'configurationSha256' })
    foreach ($definition in $definitions) {
        if ($manifest.($definition.Size) -isnot [long] -or
            [long]$manifest.($definition.Size) -lt 1 -or
            $manifest.($definition.Sha) -isnot [string] -or
            [string]$manifest.($definition.Sha) -cnotmatch '^[a-f0-9]{64}$') {
            throw 'Gameplay abrupt-exit manifest has an invalid artifact identity'
        }
        $path = Join-Path $root $definition.Name
        [void](Assert-FixtureOrdinaryFile -Path $path -Root $root `
                -Label "Gameplay abrupt-exit artifact $($definition.Name)" `
                -Protected)
        $item = Get-Item -Force -LiteralPath $path
        if ($item.Length -ne [long]$manifest.($definition.Size) -or
            (Get-LowerSha256 $path) -cne [string]$manifest.($definition.Sha)) {
            throw "Gameplay abrupt-exit artifact $($definition.Name) is unauthentic"
        }
    }
    if ($Point -in @('after-binding', 'after-installation',
            'after-rollback-marker-staging',
            'after-rollback-marker')) {
        $path = Join-Path $root 'replaced-original-client-binding.json'
        [void](Assert-FixtureOrdinaryFile -Path $path -Root $root `
                -Label 'Gameplay displaced original binding' -Protected)
        if ((Get-Item -Force -LiteralPath $path).Length -ne
                [long]$manifest.originalBindingSize -or
            (Get-LowerSha256 $path) -cne
                [string]$manifest.originalBindingSha256) {
            throw 'Gameplay displaced original binding is unauthentic'
        }
    }
    if ($Point -in @('after-installation',
            'after-rollback-marker-staging', 'after-rollback-marker')) {
        $path = Join-Path $root 'replaced-original-installation.json'
        [void](Assert-FixtureOrdinaryFile -Path $path -Root $root `
                -Label 'Gameplay displaced original installation' -Protected)
        if ((Get-Item -Force -LiteralPath $path).Length -ne
                [long]$manifest.originalInstallationSize -or
            (Get-LowerSha256 $path) -cne
                [string]$manifest.originalInstallationSha256) {
            throw 'Gameplay displaced original installation is unauthentic'
        }
    }
    $manifest
}

function Assert-GameplayBoundaryFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$Present,
        [Parameter(Mandatory)][long]$ExpectedLength,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Protected
    )

    if (-not $Present) {
        if (Test-Path -LiteralPath $Path) {
            throw "$Label is present at an absent abrupt-exit boundary"
        }
        return
    }
    [void](Assert-FixtureOrdinaryFile -Path $Path -Root $Root -Label $Label `
            -Protected:$Protected)
    $item = Get-Item -Force -LiteralPath $Path
    if ($item.Length -ne $ExpectedLength -or
        (Get-LowerSha256 $Path) -cne $ExpectedSha256) {
        throw "$Label differs from its abrupt-exit identity"
    }
}

function Assert-GameplayHardExitLiveStage {
    param(
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][ValidateSet('Activate', 'Rollback')]
        [string]$Action,
        [Parameter(Mandatory)][string]$Point
    )

    $activate = $Action -ceq 'Activate'
    $activatePresent = @{
        'after-transaction-publish' = @()
        'after-loader' = @('loader')
        'after-module' = @('loader', 'module')
        'after-configuration' = @('loader', 'module', 'configuration')
        'after-binding' = @('loader', 'module', 'configuration')
        'after-installation' = @('loader', 'module', 'configuration')
    }
    $rollbackPresent = @{
        'after-transaction-publish' = @('loader', 'module', 'configuration')
        'after-configuration' = @('loader', 'module')
        'after-module' = @('loader')
        'after-loader' = @()
        'after-binding' = @()
        'after-installation' = @()
        'after-rollback-marker-staging' = @()
        'after-rollback-marker' = @()
    }
    $presentNames = if ($activate) {
        @($activatePresent[$Point])
    } else { @($rollbackPresent[$Point]) }
    $payloads = @(
        [pscustomobject]@{ Name = 'loader'; Path = Join-Path $CombatLayout.Client 'dinput8.dll'; Size = 'loaderSize'; Sha = 'loaderSha256' },
        [pscustomobject]@{ Name = 'module'; Path = Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.asi'; Size = 'moduleSize'; Sha = 'moduleSha256' },
        [pscustomobject]@{ Name = 'configuration'; Path = Join-Path $CombatLayout.Client 'plugins\PSOBB.Gameplay.ini'; Size = 'configurationSize'; Sha = 'configurationSha256' })
    foreach ($payload in $payloads) {
        Assert-GameplayBoundaryFile -Path $payload.Path `
            -Root $CombatLayout.EnvironmentRoot `
            -Present:($payload.Name -cin $presentNames) `
            -ExpectedLength ([long]$Manifest.($payload.Size)) `
            -ExpectedSha256 ([string]$Manifest.($payload.Sha)) `
            -Label "Gameplay abrupt-exit $($payload.Name)"
    }
    $bindingPost = $Point -in @('after-binding', 'after-installation',
        'after-rollback-marker-staging',
        'after-rollback-marker')
    $installationPost = $Point -in @('after-installation',
        'after-rollback-marker-staging',
        'after-rollback-marker')
    Assert-GameplayBoundaryFile `
        -Path (Join-Path $CombatLayout.EnvironmentRoot 'client-binding.json') `
        -Root $CombatLayout.EnvironmentRoot -Present $true `
        -ExpectedLength ([long]$(if ($bindingPost) {
                    $Manifest.candidateBindingSize
                } else { $Manifest.originalBindingSize })) `
        -ExpectedSha256 ([string]$(if ($bindingPost) {
                    $Manifest.candidateBindingSha256
                } else { $Manifest.originalBindingSha256 })) `
        -Label 'Gameplay abrupt-exit binding' -Protected
    Assert-GameplayBoundaryFile -Path $CombatLayout.InstallRecord `
        -Root $CombatLayout.EnvironmentRoot -Present $true `
        -ExpectedLength ([long]$(if ($installationPost) {
                    $Manifest.candidateInstallationSize
                } else { $Manifest.originalInstallationSize })) `
        -ExpectedSha256 ([string]$(if ($installationPost) {
                    $Manifest.candidateInstallationSha256
                } else { $Manifest.originalInstallationSha256 })) `
        -Label 'Gameplay abrupt-exit installation' -Protected
}

function Assert-GameplayRollbackMarker {
    param(
        [Parameter(Mandatory)][string]$ActivationRoot,
        [Parameter(Mandatory)][string]$ActivationId,
        [Parameter(Mandatory)][string]$BaselineBindingSha256,
        [switch]$Temporary
    )

    $path = Join-Path $ActivationRoot $(if ($Temporary) {
            '.rolled-back.next'
        } else { 'rolled-back.json' })
    [void](Assert-FixtureOrdinaryFile -Path $path -Root $ActivationRoot `
            -Label 'Gameplay rollback marker' -Protected)
    $snapshot = Read-PSOBBStrictJsonSnapshot -Path $path `
        -Root $ActivationRoot -MaximumBytes 16KB -MaximumDepth 4 `
        -Label 'Gameplay rollback marker'
    [void](Assert-PSOBBStrictDataObjectProperties -Value $snapshot.Value `
            -Expected @('schemaVersion', 'activationId', 'rolledBackAtUtc',
                'baselineBindingSha256') -Label 'Gameplay rollback marker')
    $rolledBackAt = [DateTimeOffset]::MinValue
    if ($snapshot.Value.schemaVersion -isnot [long] -or
        [long]$snapshot.Value.schemaVersion -ne 1 -or
        $snapshot.Value.activationId -isnot [string] -or
        [string]$snapshot.Value.activationId -cne $ActivationId -or
        $snapshot.Value.rolledBackAtUtc -isnot [string] -or
        -not [DateTimeOffset]::TryParse(
            [string]$snapshot.Value.rolledBackAtUtc, [ref]$rolledBackAt) -or
        $snapshot.Value.baselineBindingSha256 -isnot [string] -or
        [string]$snapshot.Value.baselineBindingSha256 -cne
            $BaselineBindingSha256) {
        throw 'Gameplay rollback marker identity is invalid'
    }
    $snapshot
}

function Assert-NewGameplayBackup {
    param(
        [AllowEmptyCollection()][Parameter(Mandatory)][string[]]$Before,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)][string]$ExpectedPattern,
        [Parameter(Mandatory)][string]$Label
    )

    $new = @(Get-NewGameplayBackupDirectories -Before $Before `
            -CombatLayout $CombatLayout)
    if ($new.Count -ne 1 -or $new[0] -cnotmatch $ExpectedPattern) {
        throw "$Label did not create exactly one expected evidence directory"
    }
    $path = Join-Path (Join-Path $CombatLayout.Backups 'gameplay-activations') `
        $new[0]
    [void](Assert-PSOBBOrdinaryContainedPath -Path $path `
            -Root $CombatLayout.EnvironmentRoot -Kind Directory -Label $Label)
    if (-not (Test-PSOBBProtectedAcl -Path $path)) {
        throw "$Label evidence directory is not protected"
    }
    $new[0]
}

function Invoke-FixtureHardExit {
    param(
        [Parameter(Mandatory)][ValidateSet('Activate', 'Rollback')]
        [string]$Action,
        [Parameter(Mandatory)][string]$Point,
        [Parameter(Mandatory)][string]$FixtureRoot,
        [Parameter(Mandatory)][string]$FixtureToken
    )

    $quote = {
        param([string]$Value)
        "'" + $Value.Replace("'", "''") + "'"
    }
    $command = '& ' + (& $quote $publisherPath) +
        ' -Action ' + $Action +
        ' -RuntimeRoot ' + (& $quote $FixtureRoot) +
        ' -InternalTestFaultToken ' + (& $quote $FixtureToken) +
        ' -InternalTestHardExitPoint ' + (& $quote $Point) +
        ' -Confirm:$false'
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoLogo', '-NoProfile', '-EncodedCommand', $encoded) `
        -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(30000)) {
        $process.Kill($true)
        if (-not $process.WaitForExit(5000)) {
            throw "Gameplay hard-exit child could not be terminated at $Point"
        }
        throw "Gameplay hard-exit child timed out at $Point"
    }
    if ($process.ExitCode -ne 86) {
        throw "Gameplay hard-exit child returned $($process.ExitCode) at $Point"
    }
}

function Write-BoundedVerifierHarness {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]
        [ValidateSet('Valid', 'InvalidShape', 'Oversized', 'Timeout')]
        [string]$Mode
    )

    $scripts = Join-Path $Root 'scripts'
    [void][System.IO.Directory]::CreateDirectory($scripts)
    $validResult = @'
    [ordered]@{
        Valid = $true
        Target = 'Installed'
        Environment = 'CombatCanary'
        SnapshotId = 'bounded-verifier-fixture'
        SnapshotManifestSha256 = ('a' * 64 -join '')
        ServerArtifact = 'fixture'
        ServerComponentId = 'fixture'
        BuildContractSha256 = ('b' * 64 -join '')
        ServerReleaseManifestSha256 = ('c' * 64 -join '')
        BaseClientManifestSha256 = ('d' * 64 -join '')
        ClientBindingSha256 = ('e' * 64 -join '')
        ConfigurationSha256 = ('f' * 64 -join '')
        StateBindingSha256 = ('1' * 64 -join '')
        TwillsContractSha256 = ('2' * 64 -join '')
        SigningPublicKeySpkiSha256 = ('3' * 64 -join '')
    }
'@
    $body = switch ($Mode) {
        'Valid' { $validResult }
        'InvalidShape' {
            $validResult.Replace(
                "        Valid = `$true",
                "        Unexpected = `$true`n        Valid = `$true")
        }
        'Oversized' {
            "    [Console]::Out.Write(('x' * 300000 -join ''))`n$validResult"
        }
        'Timeout' {
            @'
    [System.IO.File]::WriteAllText(
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'child.pid'),
        [string]$PID)
    Start-Sleep -Seconds 30
'@
        }
    }
    $common = @"
function Get-PSOBBLayout {
    param([string]`$RuntimeRoot)
    [pscustomobject]@{ Root = `$RuntimeRoot }
}
function Get-PSOBBCombatCanaryInstalledBinding {
    param(`$Layout)
$body
}
"@
    [System.IO.File]::WriteAllText(
        (Join-Path $scripts 'PSOBB.Common.ps1'), $common,
        [System.Text.UTF8Encoding]::new($false))
}

$publisherTokens = $null
$publisherErrors = $null
$publisherAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $publisherPath, [ref]$publisherTokens, [ref]$publisherErrors)
$testTokens = $null
$testErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $PSCommandPath, [ref]$testTokens, [ref]$testErrors)
Add-Result 'PowerShell syntax: Gameplay publisher' `
    ($publisherErrors.Count -eq 0) `
    (($publisherErrors | ForEach-Object Message) -join '; ')
Add-Result 'PowerShell syntax: Gameplay activation test' `
    ($testErrors.Count -eq 0) `
    (($testErrors | ForEach-Object Message) -join '; ')
$publisherSource = Get-Content -Raw -LiteralPath $publisherPath
$boundedVerifierDefinitions = @($publisherAst.FindAll({
            param($node)
            $node -is
                [System.Management.Automation.Language.FunctionDefinitionAst] -and
            [string]$node.Name -ceq
                'Get-GameplayBoundedCanonicalInstalledBinding'
        }, $true))
if ($boundedVerifierDefinitions.Count -ne 1) {
    throw 'The bounded canonical verifier function is missing or ambiguous'
}
. ([scriptblock]::Create($boundedVerifierDefinitions[0].Extent.Text))
Add-Result 'publisher exposes a guarded ShouldProcess transaction' (
    $publisherSource -match
        '(?s)CmdletBinding\s*\(\s*SupportsShouldProcess' -and
    $publisherSource -match '\$PSCmdlet\.ShouldProcess\s*\(' -and
    $publisherSource -match 'InternalTestFaultToken' -and
    $publisherSource -match '\.recovery-test\.json') `
    'the integration test exercises the production transaction surface'
$publisherParameters = @($publisherAst.ParamBlock.Parameters)
$parameterNames = @(
    $publisherParameters |
        ForEach-Object { [string]$_.Name.VariablePath.UserPath }
)
$expectedParameterNames = @(
    'Action', 'InternalTestFaultPoint', 'InternalTestFaultToken',
    'InternalTestHardExitPoint', 'RuntimeRoot')
$internalParameters = @($publisherParameters | Where-Object {
        [string]$_.Name.VariablePath.UserPath -clike 'InternalTest*'
    })
Add-Result 'publisher parameter surface is closed and guarded' (
    [string]::Join("`n", @($parameterNames | Sort-Object)) -ceq
        [string]::Join("`n", @($expectedParameterNames | Sort-Object)) -and
    $internalParameters.Count -eq 3 -and
    @($internalParameters | Where-Object {
            $_.Extent.Text -cnotmatch 'DontShow\s*=\s*\$true'
        }).Count -eq 0) `
    'only Action and RuntimeRoot are public; fault controls are hidden test-only parameters'

$activationFaultPoints = @(
    'after-loader',
    'after-module',
    'after-configuration',
    'after-binding',
    'after-installation',
    'after-loader-commit',
    'after-binding-commit',
    'after-installation-commit')
$rollbackFaultPoints = @(
    'after-loader',
    'after-module',
    'after-configuration',
    'after-binding',
    'after-installation',
    'after-binding-commit',
    'after-installation-commit')
$allFaultPoints = @($activationFaultPoints + $rollbackFaultPoints |
    Sort-Object -Unique)
foreach ($faultPoint in $allFaultPoints) {
    Add-Result "publisher retains fault boundary: $faultPoint" (
        @($publisherAst.FindAll({
                    param($node)
                    $node -is
                        [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    [string]$node.Value -ceq $faultPoint
                }, $true)).Count -ge 1) `
        'each implemented commit boundary is covered by the isolated fault matrix'
}
Add-Result 'canonical verifier is bounded and binding-closed' (
    $publisherSource -match
        'Get-GameplayBoundedCanonicalInstalledBinding' -and
    $publisherSource -match
        'PSOBBCombatCanary\.BoundedMemoryStream' -and
    $publisherSource -match
        '\[ValidateRange\(1,\s*220\)\]' -and
    $publisherSource -match
        'GameplayOperationLimitSeconds\s*=\s*285' -and
    $publisherSource -match
        'installedPreflight\.ClientBindingSha256\s+-cne\s*\r?\n?\s*\[string\]\$binding\.Sha256') `
    'canonical publication uses bounded child output, an outer operation budget, and exact binding readback'
$hardExitPoints = @(
    'after-transaction-publish', 'after-loader', 'after-module',
    'after-configuration', 'after-binding', 'after-installation',
    'after-rollback-marker-staging', 'after-rollback-marker')
foreach ($hardExitPoint in $hardExitPoints) {
    Add-Result "publisher retains hard-exit boundary: $hardExitPoint" (
        @($publisherAst.FindAll({
                    param($node)
                    $node -is
                        [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    [string]$node.Value -ceq $hardExitPoint
                }, $true)).Count -ge 1) `
        'each durable commit/recovery boundary remains explicitly testable'
}

$fixtureId = [Guid]::NewGuid().ToString('N')
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    "PSOBB-GameplayTests-$fixtureId"
$expectedFixtureRoot = [System.IO.Path]::GetFullPath($fixtureRoot).TrimEnd('\')
$temporaryRoot = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$preserveFixture = $false
$fixtureRootIdentity = $null
$sourceRuntime = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$canonicalRoot = [System.IO.Path]::GetFullPath(
    $script:PSOBBCanonicalRuntimeRoot).TrimEnd('\')
if (-not ([System.IO.Path]::GetFullPath($sourceRuntime.Root).TrimEnd('\').Equals(
            $canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase))) {
    throw 'Gameplay activation tests require the exact canonical source runtime'
}
$sourceStableLayout = Get-PSOBBServerEnvironmentLayout `
    -Layout $sourceRuntime -Environment Stable
$sourceCombatLayout = Get-PSOBBServerEnvironmentLayout `
    -Layout $sourceRuntime -Environment CombatCanary
$canonicalBefore = @(Get-GameplayPublisherSurfaceFingerprint `
        -Layout $sourceRuntime -StableLayout $sourceStableLayout `
        -CombatLayout $sourceCombatLayout)
try {
    if (-not $expectedFixtureRoot.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($expectedFixtureRoot) -cnotmatch
            '^PSOBB-GameplayTests-[a-f0-9]{32}$') {
        throw 'The Gameplay fixture root failed its exact temporary-path gate'
    }
    [void][System.IO.Directory]::CreateDirectory($expectedFixtureRoot)
    $fixtureLayout = Get-PSOBBLayout -RuntimeRoot $expectedFixtureRoot
    $fixtureMarker = Initialize-PSOBBRuntimeMarker -Layout $fixtureLayout
    $fixtureToken = [string]$fixtureMarker.installationId
    Write-FixtureJson `
        -Path (Join-Path $fixtureLayout.Root '.recovery-test.json') `
        -Root $fixtureLayout.Root -Protect -Value ([ordered]@{
            schemaVersion = 1
            fixture = 'CombatCanary Gameplay activation'
            installationId = $fixtureToken
        })
    $fixtureRootHandle = $null
    try {
        $fixtureRootHandle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $fixtureLayout.Root -Directory $true
        $fixtureRootIdentity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $fixtureRootHandle -ExpectedPath $fixtureLayout.Root `
            -Root $temporaryRoot.TrimEnd('\') -Directory $true `
            -RoleLabel 'Gameplay fixture creation root'
    } finally {
        if ($null -ne $fixtureRootHandle) { $fixtureRootHandle.Dispose() }
    }

    $stableLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $fixtureLayout -Environment Stable
    $combatLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $fixtureLayout -Environment CombatCanary
    foreach ($directory in @(
            $stableLayout.Client,
            $combatLayout.Client,
            $combatLayout.EnvironmentRoot,
            (Join-Path $fixtureLayout.Root 'archives\graphics-lab'))) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }

    $stableClientBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        'synthetic-stable-client-sentinel')
    $stableInstallationBytes =
        [System.Text.UTF8Encoding]::new($false).GetBytes(
            '{"fixture":"synthetic-stable-installation-sentinel"}')
    try {
        Write-FixtureBytes `
            -Path (Join-Path $stableLayout.Client 'Psobb.exe') `
            -Root $stableLayout.EnvironmentRoot -Bytes $stableClientBytes
        Write-FixtureBytes -Path $stableLayout.InstallRecord `
            -Root $stableLayout.EnvironmentRoot `
            -Bytes $stableInstallationBytes -Protect
    } finally {
        [Array]::Clear($stableClientBytes, 0, $stableClientBytes.Length)
        [Array]::Clear(
            $stableInstallationBytes, 0, $stableInstallationBytes.Length)
    }

    $sourceClientExecutable = Join-Path $sourceCombatLayout.Client 'Psobb.exe'
    $sourceClientProfile = Join-Path $sourceCombatLayout.Client `
        'client-profile.json'
    [System.IO.File]::Copy(
        $sourceClientExecutable,
        (Join-Path $combatLayout.Client 'Psobb.exe'), $false)
    [System.IO.File]::Copy(
        $sourceClientProfile,
        (Join-Path $combatLayout.Client 'client-profile.json'), $false)
    $clientExecutableSize = (Get-Item -Force `
            -LiteralPath $sourceClientExecutable).Length
    $clientExecutableSha256 = Get-LowerSha256 $sourceClientExecutable
    $clientProfileSha256 = Get-LowerSha256 $sourceClientProfile

    $baselineBinding = [ordered]@{
        schemaVersion = 1
        environment = 'CombatCanary'
        environmentId = 'combat-canary'
        profile = 'baseline'
        renderer = 'Native'
        serverAddress = '127.0.0.1'
        patchPort = 11000
        gamePorts = @(12000, 12001)
        clientExecutablePath = 'runtime/client/Psobb.exe'
        clientExecutableSize = [long]$clientExecutableSize
        clientExecutableSha256 = $clientExecutableSha256
        clientProfileSha256 = $clientProfileSha256
        baseClientManifestSha256 = ('2' * 64) -join ''
        createdAtUtc = '2026-07-21T00:00:00.0000000Z'
    }
    $bindingPath = Join-Path $combatLayout.EnvironmentRoot `
        'client-binding.json'
    Write-FixtureJson -Path $bindingPath -Root $combatLayout.EnvironmentRoot `
        -Value $baselineBinding -Protect
    $baselineBindingSha256 = Get-LowerSha256 $bindingPath
    $buildContractSha256 = Get-LowerSha256 (
        Join-Path $repositoryRoot 'config\combat-canary-build.json')
    $baselineInstallation = [ordered]@{
        schemaVersion = 1
        environment = 'CombatCanary'
        environmentId = 'combat-canary'
        initializedAtUtc = '2026-07-21T00:00:00.0000000Z'
        buildContractSha256 = $buildContractSha256
        serverReleaseManifestSha256 = ('3' * 64) -join ''
        baseClientManifestSha256 = ('2' * 64) -join ''
        clientBindingSha256 = $baselineBindingSha256
        snapshotDirectoryName =
            'twills-slot0-20260721T000000000Z-deadbeef'
        snapshotId = [Guid]::NewGuid().ToString('D')
        snapshotManifestSha256 = ('4' * 64) -join ''
        stateBindingSha256 = ('5' * 64) -join ''
        twillsContractSha256 = ('6' * 64) -join ''
        signingPublicKeySpkiSha256 = ('7' * 64) -join ''
        configurationSha256 = ('8' * 64) -join ''
    }
    Write-FixtureJson -Path $combatLayout.InstallRecord `
        -Root $combatLayout.EnvironmentRoot -Value $baselineInstallation `
        -Protect

    $authority = Get-PSOBBGameplayObservationAuthority
    $configurationIdentity =
        Get-PSOBBGameplayObservationConfigurationIdentity
    $loaderArchiveSource = Join-Path $sourceRuntime.Root `
        'archives\graphics-lab\Ultimate-ASI-Loader-v9.7.2-x86.zip'
    $loaderArchiveDestination = Join-Path $fixtureLayout.Root `
        'archives\graphics-lab\Ultimate-ASI-Loader-v9.7.2-x86.zip'
    if (-not (Test-Path -LiteralPath $loaderArchiveSource -PathType Leaf)) {
        throw 'The pinned Gameplay loader archive is unavailable for the isolated fixture'
    }
    if (-not (Test-Path -LiteralPath $authority.ModulePath -PathType Leaf)) {
        throw 'The exact Gameplay observation build is unavailable for the isolated fixture'
    }
    Copy-Item -LiteralPath $loaderArchiveSource `
        -Destination $loaderArchiveDestination

    Assert-BaselineState -CombatLayout $combatLayout `
        -ExpectedBindingSha256 $baselineBindingSha256
    $stableBefore = @(Get-GameplayLiveState `
            -StableLayout $stableLayout -CombatLayout $combatLayout |
            Where-Object { $_ -like 'stable-*' })

    if ($runCore) {
        $verifierHarnessRoot = Join-Path $fixtureLayout.Root 'verifier-harness'
        $publisherRootBeforeHarness = $script:PSOBBRepositoryRoot
        try {
            $script:PSOBBRepositoryRoot = $verifierHarnessRoot
            Write-BoundedVerifierHarness -Root $verifierHarnessRoot -Mode Valid
            $boundedResult = Get-GameplayBoundedCanonicalInstalledBinding `
                -Layout $fixtureLayout -TimeoutSeconds 5
            Add-Result 'canonical verifier returns exact strict bounded output' (
                $boundedResult.Valid -eq $true -and
                $boundedResult.Target -ceq 'Installed' -and
                $boundedResult.Environment -ceq 'CombatCanary' -and
                $boundedResult.ClientBindingSha256 -ceq ('e' * 64 -join '')) `
                'a real child process returns the closed installed-binding contract'

            Write-BoundedVerifierHarness -Root $verifierHarnessRoot `
                -Mode InvalidShape
            $invalidShapeRejected = $false
            try {
                Get-GameplayBoundedCanonicalInstalledBinding `
                    -Layout $fixtureLayout -TimeoutSeconds 5 | Out-Null
            } catch {
                $invalidShapeRejected =
                    $_.Exception.Message -like '*exact property set*'
            }
            Add-Result 'canonical verifier rejects an expanded JSON shape' `
                $invalidShapeRejected `
                'strict transport rejects an undeclared child property'

            Write-BoundedVerifierHarness -Root $verifierHarnessRoot `
                -Mode Oversized
            $oversizedRejected = $false
            try {
                Get-GameplayBoundedCanonicalInstalledBinding `
                    -Layout $fixtureLayout -TimeoutSeconds 5 | Out-Null
            } catch {
                $oversizedRejected =
                    $_.Exception.Message -like '*exceeded its output bound*'
            }
            Add-Result 'canonical verifier rejects oversized child output' `
                $oversizedRejected `
                'stdout is capped before it can be buffered by the publisher'

            Write-BoundedVerifierHarness -Root $verifierHarnessRoot `
                -Mode Timeout
            $verifierPidPath = Join-Path $verifierHarnessRoot 'child.pid'
            $timeoutRejected = $false
            $timeoutClock = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                Get-GameplayBoundedCanonicalInstalledBinding `
                    -Layout $fixtureLayout -TimeoutSeconds 1 | Out-Null
            } catch {
                $timeoutRejected =
                    $_.Exception.Message -like '*exceeded 1 seconds*'
            } finally {
                $timeoutClock.Stop()
            }
            $timedOutChildAbsent = $false
            if (Test-Path -LiteralPath $verifierPidPath -PathType Leaf) {
                $timedOutPid = [int][System.IO.File]::ReadAllText(
                    $verifierPidPath)
                $timedOutChildAbsent =
                    $null -eq (Get-Process -Id $timedOutPid `
                        -ErrorAction SilentlyContinue)
            }
            Add-Result 'canonical verifier timeout is monotonic and terminating' (
                $timeoutRejected -and $timedOutChildAbsent -and
                $timeoutClock.Elapsed.TotalSeconds -lt 8) `
                'a one-second deadline terminates its child within the bounded cleanup window'
        } finally {
            $script:PSOBBRepositoryRoot = $publisherRootBeforeHarness
        }

        $canonicalGateBefore = @(Get-GameplayPublisherSurfaceFingerprint `
                -Layout $sourceRuntime -StableLayout $sourceStableLayout `
                -CombatLayout $sourceCombatLayout)
        $canonicalGateRejected = $false
        $canonicalGateDetail = ''
        try {
            & $publisherPath -Action Activate -RuntimeRoot $sourceRuntime.Root `
                -InternalTestFaultToken $fixtureToken -WhatIf -Confirm:$false |
                Out-Null
        } catch {
            $canonicalGateDetail = [string]$_.Exception.Message
            $canonicalGateRejected = $canonicalGateDetail -cmatch
                'Internal Gameplay test controls are forbidden for the canonical runtime'
        }
        $canonicalGateAfter = @(Get-GameplayPublisherSurfaceFingerprint `
                -Layout $sourceRuntime -StableLayout $sourceStableLayout `
                -CombatLayout $sourceCombatLayout)
        Add-Result 'canonical internal-control WhatIf is rejected without mutation' (
            $canonicalGateRejected -and
            @(Compare-Object $canonicalGateBefore $canonicalGateAfter).Count -eq 0) `
            "the exact canonical fault gate rejected the request: $canonicalGateDetail"
    }

    $beforeWhatIf = @(Get-FixtureTreeFingerprint -Root $fixtureLayout.Root)
    $whatIf = & $publisherPath -Action Activate `
        -RuntimeRoot $fixtureLayout.Root `
        -InternalTestFaultToken $fixtureToken -WhatIf -Confirm:$false
    $afterWhatIf = @(Get-FixtureTreeFingerprint -Root $fixtureLayout.Root)
    Add-Result 'WhatIf is an exact fixture no-op' (
        $whatIf.Count -eq 1 -and -not [bool]$whatIf.Changed -and
        [bool]$whatIf.Pending -and $whatIf.Profile -ceq 'observation' -and
        @(Compare-Object $beforeWhatIf $afterWhatIf).Count -eq 0) `
        'the protected marker, bindings, payloads, ACLs, and backup tree are unchanged'

    foreach ($faultPoint in $(if ($runCore) {
                $activationFaultPoints
            } else { @() })) {
        Write-TestProgress "Activate compensating fault $faultPoint"
        $beforeFault = @(Get-GameplayLiveState `
                -StableLayout $stableLayout -CombatLayout $combatLayout)
        $faultObserved = $false
        $faultDetail = ''
        try {
            & $publisherPath -Action Activate `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultPoint $faultPoint `
                -InternalTestFaultToken $fixtureToken -Confirm:$false |
                Out-Null
        } catch {
            $faultDetail = [string]$_.Exception.Message
            $faultObserved = $faultDetail -cmatch
                'transaction failed and restored its original state' -and
                $faultDetail -cmatch [regex]::Escape(
                    "Injected CombatCanary Gameplay fault at $faultPoint")
        }
        if (-not $faultObserved) {
            throw "Activate fault '$faultPoint' did not compensate: $faultDetail"
        }
        $afterFault = @(Get-GameplayLiveState `
                -StableLayout $stableLayout -CombatLayout $combatLayout)
        Assert-BaselineState -CombatLayout $combatLayout `
            -ExpectedBindingSha256 $baselineBindingSha256
        Add-Result "Activate compensates fault: $faultPoint" (
            $faultObserved -and
            @(Compare-Object $beforeFault $afterFault).Count -eq 0) `
            'exact baseline live state is restored; rejected evidence may remain isolated'
    }

    $activateHardExitPoints = @(
        'after-transaction-publish', 'after-loader', 'after-module',
        'after-configuration', 'after-binding', 'after-installation')
    if (-not $runActivateHardExit) {
        $activateHardExitPoints = @()
    } elseif (-not [string]::IsNullOrWhiteSpace($Boundary)) {
        $activateHardExitPoints = @($activateHardExitPoints | Where-Object {
                $_ -ceq $Boundary
            })
        if ($activateHardExitPoints.Count -ne 1) {
            throw "Activate boundary did not select exactly one case: $Boundary"
        }
    }
    foreach ($hardExitPoint in $activateHardExitPoints) {
        Write-TestProgress "Activate abrupt boundary $hardExitPoint"
        $backupBeforeHardExit = @(Get-GameplayBackupDirectoryNames `
                -CombatLayout $combatLayout)
        Invoke-FixtureHardExit -Action Activate -Point $hardExitPoint `
            -FixtureRoot $fixtureLayout.Root -FixtureToken $fixtureToken
        $manifest = Assert-GameplayTransactionBoundary `
            -CombatLayout $combatLayout -Action Activate `
            -Point $hardExitPoint -RuntimeInstallationId $fixtureToken
        Assert-GameplayHardExitLiveStage -CombatLayout $combatLayout `
            -Manifest $manifest -Action Activate -Point $hardExitPoint
        Add-Result "Activate exposes exact abrupt boundary: $hardExitPoint" $true `
            'the authenticated transaction and every live target match one exact commit prefix'

        if ($hardExitPoint -ceq 'after-installation') {
            $recovered = & $publisherPath -Action Activate `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
                -ConfigurationIdentity $configurationIdentity
            $newEvidence = Assert-NewGameplayBackup `
                -Before $backupBeforeHardExit -CombatLayout $combatLayout `
                -ExpectedPattern ('^' + [regex]::Escape(
                        [string]$manifest.activationId) + '$') `
                -Label 'completed abrupt activation'
            Add-Result "Activate finalizes all-post abrupt boundary: $hardExitPoint" (
                $recovered.Count -eq 1 -and
                -not [bool]$recovered.Changed -and
                $recovered.Profile -ceq 'observation' -and
                $newEvidence -ceq [string]$manifest.activationId -and
                -not (Test-Path -LiteralPath (Join-Path `
                        $combatLayout.EnvironmentRoot '.gameplay-transaction'))) `
                'all-post state is finalized as its authenticated activation snapshot'
            & $publisherPath -Action Rollback -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false | Out-Null
        } else {
            $recovered = & $publisherPath -Action Rollback `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-BaselineState -CombatLayout $combatLayout `
                -ExpectedBindingSha256 $baselineBindingSha256
            $newEvidence = Assert-NewGameplayBackup `
                -Before $backupBeforeHardExit -CombatLayout $combatLayout `
                -ExpectedPattern '^recovered-abort-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' `
                -Label 'aborted abrupt activation'
            Add-Result "Activate restores pre-state abrupt boundary: $hardExitPoint" (
                $recovered.Count -eq 1 -and
                -not [bool]$recovered.Changed -and
                $recovered.Profile -ceq 'baseline' -and
                $newEvidence -cmatch '^recovered-abort-' -and
                -not (Test-Path -LiteralPath (Join-Path `
                        $combatLayout.EnvironmentRoot '.gameplay-transaction'))) `
                'all-pre or mixed state is restored, archived, and observed before another activation'
        }
        Assert-BaselineState -CombatLayout $combatLayout `
            -ExpectedBindingSha256 $baselineBindingSha256
    }

    if ($Shard -cne 'ActivateHardExit') {
        if ($runCore) {
            Write-TestProgress 'case-insensitive Action regression'
            $lowerActivation = & $publisherPath -Action activate `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
                -ConfigurationIdentity $configurationIdentity
            $lowerRollback = & $publisherPath -Action rollback `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-BaselineState -CombatLayout $combatLayout `
                -ExpectedBindingSha256 $baselineBindingSha256
            Add-Result 'Action values are case-insensitive without semantic inversion' (
                $lowerActivation.Count -eq 1 -and
                [bool]$lowerActivation.Changed -and
                $lowerActivation.Profile -ceq 'observation' -and
                $lowerRollback.Count -eq 1 -and
                [bool]$lowerRollback.Changed -and
                $lowerRollback.Profile -ceq 'baseline') `
                'ValidateSet casing cannot turn Activate into Rollback or vice versa'
        }

        Write-TestProgress 'exact activation and idempotency'
        $activation = & $publisherPath -Action Activate `
        -RuntimeRoot $fixtureLayout.Root `
        -InternalTestFaultToken $fixtureToken -Confirm:$false
    Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
        -ConfigurationIdentity $configurationIdentity
    Add-Result 'Activate publishes the exact observation overlay' (
        $activation.Count -eq 1 -and [bool]$activation.Changed -and
        $activation.Profile -ceq 'observation' -and
        [string]$activation.ActivationId -match
            '^gameplay-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$') `
        'loader, module, configuration, schema-2 binding, and installation marker agree'

        $activeBeforeIdempotent = @(Get-GameplayIdempotentFingerprint `
            -StableLayout $stableLayout -CombatLayout $combatLayout `
            -ActiveActivationId ([string]$activation.ActivationId))
        $secondActivation = & $publisherPath -Action Activate `
        -RuntimeRoot $fixtureLayout.Root `
        -InternalTestFaultToken $fixtureToken -Confirm:$false
        $activeAfterIdempotent = @(Get-GameplayIdempotentFingerprint `
            -StableLayout $stableLayout -CombatLayout $combatLayout `
            -ActiveActivationId ([string]$activation.ActivationId))
        Add-Result 'Activate is idempotent' (
        $secondActivation.Count -eq 1 -and
        -not [bool]$secondActivation.Changed -and
        $secondActivation.Profile -ceq 'observation' -and
        @(Compare-Object $activeBeforeIdempotent `
                $activeAfterIdempotent).Count -eq 0) `
        'an accepted schema-2 state does not create another transaction or backup'

        $evolvedInstallationSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $combatLayout.InstallRecord -Root $combatLayout.EnvironmentRoot `
        -MaximumBytes 64KB -MaximumDepth 8 `
        -Label 'Gameplay evolved installation source'
    $evolvedInstallation = $evolvedInstallationSnapshot.Value
    $evolvedInstallation.stateBindingSha256 = ('9' * 64) -join ''
    $evolvedInstallation.configurationSha256 = ('a' * 64) -join ''
    $evolvedNext = Join-Path $combatLayout.EnvironmentRoot `
        '.fixture-evolved-installation.next'
    $evolvedPrevious = Join-Path $combatLayout.EnvironmentRoot `
        '.fixture-evolved-installation.previous'
    Write-FixtureJson -Path $evolvedNext `
        -Root $combatLayout.EnvironmentRoot -Value $evolvedInstallation -Protect
    [System.IO.File]::Replace(
        $evolvedNext, $combatLayout.InstallRecord, $evolvedPrevious, $true)
    Set-PSOBBProtectedAcl -Path $combatLayout.InstallRecord
    [void](Assert-PSOBBOrdinaryContainedPath -Path $evolvedPrevious `
            -Root $combatLayout.EnvironmentRoot -Kind File `
            -Label 'Gameplay evolved-installation replacement backup')
    [System.IO.File]::Delete($evolvedPrevious)
    if (Test-Path -LiteralPath $evolvedPrevious) {
        throw 'Gameplay evolved-installation replacement backup remained'
    }

    $rollbackHardExitPoints = @(
        'after-transaction-publish', 'after-configuration', 'after-module',
        'after-loader', 'after-binding', 'after-installation',
        'after-rollback-marker-staging', 'after-rollback-marker')
    if (-not $runRollbackHardExit) {
        $rollbackHardExitPoints = @()
    } elseif (-not [string]::IsNullOrWhiteSpace($Boundary)) {
        $rollbackHardExitPoints = @($rollbackHardExitPoints | Where-Object {
                $_ -ceq $Boundary
            })
        if ($rollbackHardExitPoints.Count -ne 1) {
            throw "Rollback boundary did not select exactly one case: $Boundary"
        }
    }
    foreach ($hardExitPoint in $rollbackHardExitPoints) {
        Write-TestProgress "Rollback abrupt boundary $hardExitPoint"
        $activeInstallationSnapshot = Read-PSOBBStrictJsonSnapshot `
            -Path $combatLayout.InstallRecord -Root $combatLayout.EnvironmentRoot `
            -MaximumBytes 64KB -MaximumDepth 8 `
            -Label 'Gameplay pre-rollback installation metadata'
        Assert-GameplayMetadataPreserved -Expected $evolvedInstallation `
            -Actual $activeInstallationSnapshot.Value `
            -ExpectedClientBindingSha256 (
                Get-LowerSha256 (Join-Path $combatLayout.EnvironmentRoot `
                    'client-binding.json'))
        $activationId = [string]$activation.ActivationId
        $activationRoot = Join-Path (Join-Path $combatLayout.Backups `
                'gameplay-activations') $activationId
        [void](Assert-PSOBBOrdinaryContainedPath -Path $activationRoot `
                -Root $combatLayout.EnvironmentRoot -Kind Directory `
                -Label 'Gameplay active activation snapshot')
        if (-not (Test-PSOBBProtectedAcl -Path $activationRoot)) {
            throw 'Gameplay active activation snapshot is not protected'
        }
        $backupBeforeHardExit = @(Get-GameplayBackupDirectoryNames `
                -CombatLayout $combatLayout)
        Invoke-FixtureHardExit -Action Rollback -Point $hardExitPoint `
            -FixtureRoot $fixtureLayout.Root -FixtureToken $fixtureToken
        $manifest = Assert-GameplayTransactionBoundary `
            -CombatLayout $combatLayout -Action Rollback `
            -Point $hardExitPoint -RuntimeInstallationId $fixtureToken
        if ([string]$manifest.activationId -cne $activationId) {
            throw 'Abrupt rollback transaction selected the wrong activation snapshot'
        }
        Assert-GameplayHardExitLiveStage -CombatLayout $combatLayout `
            -Manifest $manifest -Action Rollback -Point $hardExitPoint
        $markerPath = Join-Path $activationRoot 'rolled-back.json'
        $stagedRollbackMarker = $null
        if ($hardExitPoint -ceq 'after-rollback-marker-staging') {
            if (Test-Path -LiteralPath $markerPath) {
                throw 'Final rollback marker appeared before its atomic move'
            }
            $stagedRollbackMarker = Assert-GameplayRollbackMarker `
                    -ActivationRoot $activationRoot -ActivationId $activationId `
                    -BaselineBindingSha256 $baselineBindingSha256 -Temporary
        } elseif ($hardExitPoint -ceq 'after-rollback-marker') {
            $completedRollbackMarker = Assert-GameplayRollbackMarker `
                    -ActivationRoot $activationRoot -ActivationId $activationId `
                    -BaselineBindingSha256 $baselineBindingSha256
            if ($stagedRollbackMarker -and
                ([long]$completedRollbackMarker.Length -ne
                    [long]$stagedRollbackMarker.Length -or
                [string]$completedRollbackMarker.Sha256 -cne
                    [string]$stagedRollbackMarker.Sha256)) {
                throw 'Recovered rollback marker differs from its durable staged identity'
            }
            if (Test-Path -LiteralPath (Join-Path $activationRoot `
                    '.rolled-back.next')) {
                throw 'Rollback-marker temporary remained after its atomic move'
            }
        } elseif (Test-Path -LiteralPath $markerPath) {
            throw "Rollback marker appeared before its exact boundary at $hardExitPoint"
        }
        Add-Result "Rollback exposes exact abrupt boundary: $hardExitPoint" $true `
            'the authenticated transaction, marker state, and live targets match one exact commit prefix'

        if ($hardExitPoint -in @('after-installation',
                'after-rollback-marker-staging',
                'after-rollback-marker')) {
            $recovered = & $publisherPath -Action Rollback `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-BaselineState -CombatLayout $combatLayout `
                -ExpectedBindingSha256 $baselineBindingSha256
            $recoveredInstallation = Read-PSOBBStrictJsonSnapshot `
                -Path $combatLayout.InstallRecord `
                -Root $combatLayout.EnvironmentRoot -MaximumBytes 64KB `
                -MaximumDepth 8 -Label 'recovered baseline installation metadata'
            Assert-GameplayMetadataPreserved -Expected $evolvedInstallation `
                -Actual $recoveredInstallation.Value `
                -ExpectedClientBindingSha256 $baselineBindingSha256
            $completedRollbackMarker = Assert-GameplayRollbackMarker `
                -ActivationRoot $activationRoot -ActivationId $activationId `
                -BaselineBindingSha256 $baselineBindingSha256
            if ($stagedRollbackMarker -and
                ([long]$completedRollbackMarker.Length -ne
                    [long]$stagedRollbackMarker.Length -or
                [string]$completedRollbackMarker.Sha256 -cne
                    [string]$stagedRollbackMarker.Sha256)) {
                throw 'Recovered rollback marker differs from its durable staged identity'
            }
            if (Test-Path -LiteralPath (Join-Path $activationRoot `
                    '.rolled-back.next')) {
                throw 'Recovered rollback-marker temporary was not consumed'
            }
            $newEvidence = Assert-NewGameplayBackup `
                -Before $backupBeforeHardExit -CombatLayout $combatLayout `
                -ExpectedPattern '^rollback-recovered-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' `
                -Label 'completed abrupt rollback'
            Add-Result "Rollback finalizes all-post abrupt boundary: $hardExitPoint" (
                $recovered.Count -eq 1 -and
                -not [bool]$recovered.Changed -and
                $recovered.Profile -ceq 'baseline' -and
                $newEvidence -cmatch '^rollback-recovered-' -and
                -not (Test-Path -LiteralPath (Join-Path `
                        $combatLayout.EnvironmentRoot '.gameplay-transaction'))) `
                'completed baseline, typed metadata, marker, and archived recovery evidence agree'
        } else {
            $recovered = & $publisherPath -Action Activate `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
                -ConfigurationIdentity $configurationIdentity
            $recoveredInstallation = Read-PSOBBStrictJsonSnapshot `
                -Path $combatLayout.InstallRecord `
                -Root $combatLayout.EnvironmentRoot -MaximumBytes 64KB `
                -MaximumDepth 8 -Label 'recovered active installation metadata'
            Assert-GameplayMetadataPreserved -Expected $evolvedInstallation `
                -Actual $recoveredInstallation.Value `
                -ExpectedClientBindingSha256 ([string]$manifest.originalBindingSha256)
            $newEvidence = Assert-NewGameplayBackup `
                -Before $backupBeforeHardExit -CombatLayout $combatLayout `
                -ExpectedPattern '^recovered-abort-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' `
                -Label 'aborted abrupt rollback'
            Add-Result "Rollback restores pre-state abrupt boundary: $hardExitPoint" (
                $recovered.Count -eq 1 -and
                -not [bool]$recovered.Changed -and
                $recovered.Profile -ceq 'observation' -and
                $newEvidence -cmatch '^recovered-abort-' -and
                -not (Test-Path -LiteralPath (Join-Path `
                        $combatLayout.EnvironmentRoot '.gameplay-transaction'))) `
                'all-pre or mixed state restores exact active metadata before a new rollback'
            & $publisherPath -Action Rollback -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false | Out-Null
            Assert-BaselineState -CombatLayout $combatLayout `
                -ExpectedBindingSha256 $baselineBindingSha256
            $normalRollbackInstallation = Read-PSOBBStrictJsonSnapshot `
                -Path $combatLayout.InstallRecord `
                -Root $combatLayout.EnvironmentRoot -MaximumBytes 64KB `
                -MaximumDepth 8 -Label 'post-recovery normal rollback metadata'
            Assert-GameplayMetadataPreserved -Expected $evolvedInstallation `
                -Actual $normalRollbackInstallation.Value `
                -ExpectedClientBindingSha256 $baselineBindingSha256
        }
        Add-Result "Rollback preserves typed metadata: $hardExitPoint" $true `
            'all closed installation fields retain type and value except the exact binding hash'
        if ($hardExitPoint -cne $rollbackHardExitPoints[-1]) {
            $activation = & $publisherPath -Action Activate `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultToken $fixtureToken -Confirm:$false
            Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
                -ConfigurationIdentity $configurationIdentity
        }
    }

    if ($runCore) {
        Write-TestProgress 'reactivation for rollback compensation matrix'
        $activation = & $publisherPath -Action Activate `
            -RuntimeRoot $fixtureLayout.Root `
            -InternalTestFaultToken $fixtureToken -Confirm:$false
        Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
            -ConfigurationIdentity $configurationIdentity
    }

    foreach ($faultPoint in $(if ($runCore) {
                $rollbackFaultPoints
            } else { @() })) {
        Write-TestProgress "Rollback compensating fault $faultPoint"
        $beforeFault = @(Get-GameplayLiveState `
                -StableLayout $stableLayout -CombatLayout $combatLayout)
        $faultObserved = $false
        $faultDetail = ''
        try {
            & $publisherPath -Action Rollback `
                -RuntimeRoot $fixtureLayout.Root `
                -InternalTestFaultPoint $faultPoint `
                -InternalTestFaultToken $fixtureToken -Confirm:$false |
                Out-Null
        } catch {
            $faultDetail = [string]$_.Exception.Message
            $faultObserved = $faultDetail -cmatch
                'transaction failed and restored its original state' -and
                $faultDetail -cmatch [regex]::Escape(
                    "Injected CombatCanary Gameplay fault at $faultPoint")
        }
        if (-not $faultObserved) {
            throw "Rollback fault '$faultPoint' did not compensate: $faultDetail"
        }
        $afterFault = @(Get-GameplayLiveState `
                -StableLayout $stableLayout -CombatLayout $combatLayout)
        Assert-ActiveState -CombatLayout $combatLayout -Authority $authority `
            -ConfigurationIdentity $configurationIdentity
        Add-Result "Rollback compensates fault: $faultPoint" (
            $faultObserved -and
            @(Compare-Object $beforeFault $afterFault).Count -eq 0) `
            'exact active live state is restored; rejected evidence may remain isolated'
    }

    if ($runCore) {
        $rollback = & $publisherPath -Action Rollback `
            -RuntimeRoot $fixtureLayout.Root `
            -InternalTestFaultToken $fixtureToken -Confirm:$false
        Assert-BaselineState -CombatLayout $combatLayout `
            -ExpectedBindingSha256 $baselineBindingSha256
    }
    $rolledBackInstallation = Read-PSOBBStrictJsonSnapshot `
        -Path $combatLayout.InstallRecord -Root $combatLayout.EnvironmentRoot `
        -MaximumBytes 64KB -MaximumDepth 8 `
        -Label 'final rolled-back Gameplay installation'
    Assert-GameplayMetadataPreserved -Expected $evolvedInstallation `
        -Actual $rolledBackInstallation.Value `
        -ExpectedClientBindingSha256 $baselineBindingSha256
    Add-Result 'Rollback preserves current installation metadata' $true `
        'only clientBindingSha256 changes when the baseline binding is restored'
    if ($runCore) {
        Add-Result 'Rollback restores the exact baseline binding' (
            $rollback.Count -eq 1 -and [bool]$rollback.Changed -and
            $rollback.Profile -ceq 'baseline') `
            'all overlay payloads are absent and installation metadata binds schema 1'
    }
    }

    $baselineBeforeIdempotent = @(Get-GameplayIdempotentFingerprint `
            -StableLayout $stableLayout -CombatLayout $combatLayout)
    $secondRollback = & $publisherPath -Action Rollback `
        -RuntimeRoot $fixtureLayout.Root `
        -InternalTestFaultToken $fixtureToken -Confirm:$false
    $baselineAfterIdempotent = @(Get-GameplayIdempotentFingerprint `
            -StableLayout $stableLayout -CombatLayout $combatLayout)
    Add-Result 'Rollback is idempotent' (
        $secondRollback.Count -eq 1 -and
        -not [bool]$secondRollback.Changed -and
        $secondRollback.Profile -ceq 'baseline' -and
        @(Compare-Object $baselineBeforeIdempotent `
                $baselineAfterIdempotent).Count -eq 0) `
        'an accepted schema-1 state does not create another transaction or backup'

    $stableAfter = @(Get-GameplayLiveState `
            -StableLayout $stableLayout -CombatLayout $combatLayout |
            Where-Object { $_ -like 'stable-*' })
    Add-Result 'Stable publisher authorities remain byte- and ACL-exact' (
        @(Compare-Object $stableBefore $stableAfter).Count -eq 0) `
        'every preview, fault, activation, idempotent call, and rollback preserves Stable Psobb.exe and installation.json'
    $canonicalAfter = @(Get-GameplayPublisherSurfaceFingerprint `
            -Layout $sourceRuntime -StableLayout $sourceStableLayout `
            -CombatLayout $sourceCombatLayout)
    Add-Result 'canonical publisher-owned surface remains exact' (
        @(Compare-Object $canonicalBefore $canonicalAfter).Count -eq 0) `
        'fixture previews, faults, abrupt exits, recovery, and cleanup preparation never target canonical state'
} catch {
    $preserveFixture = $true
    $failure = $_.Exception
    $canonicalFailureDetail = 'canonical publisher-owned surface unchanged'
    try {
        $canonicalOnFailure = @(Get-GameplayPublisherSurfaceFingerprint `
                -Layout $sourceRuntime -StableLayout $sourceStableLayout `
                -CombatLayout $sourceCombatLayout)
        if (@(Compare-Object $canonicalBefore $canonicalOnFailure).Count -ne 0) {
            $canonicalFailureDetail = 'CANONICAL PUBLISHER-OWNED SURFACE CHANGED'
        }
    } catch {
        $canonicalFailureDetail =
            'canonical publisher-owned surface could not be reverified: ' +
            $_.Exception.Message
    }
    throw [System.InvalidOperationException]::new(
        ("Gameplay activation test failed; isolated evidence is preserved at " +
            "'$expectedFixtureRoot'; $canonicalFailureDetail. " +
            "Original failure: $($failure.Message)"), $failure)
} finally {
    if (-not $preserveFixture -and
        (Test-Path -LiteralPath $expectedFixtureRoot)) {
        $resolvedFixture = [System.IO.Path]::GetFullPath(
            (Get-Item -Force -LiteralPath $expectedFixtureRoot).FullName).
            TrimEnd('\')
        if (-not $resolvedFixture.StartsWith(
                $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            [System.IO.Path]::GetFileName($resolvedFixture) -cnotmatch
                '^PSOBB-GameplayTests-[a-f0-9]{32}$') {
            throw 'Refusing to remove a Gameplay fixture outside its exact temporary gate'
        }
        $cleanupMarkerPath = Join-Path $resolvedFixture '.recovery-test.json'
        [void](Assert-FixtureOrdinaryFile -Path $cleanupMarkerPath `
                -Root $resolvedFixture -Label 'Gameplay fixture cleanup marker' `
                -Protected)
        $cleanupMarker = Read-PSOBBStrictJsonSnapshot `
            -Path $cleanupMarkerPath -Root $resolvedFixture `
            -MaximumBytes 16KB -MaximumDepth 4 `
            -Label 'Gameplay fixture cleanup marker'
        [void](Assert-PSOBBStrictDataObjectProperties `
                -Value $cleanupMarker.Value `
                -Expected @('schemaVersion', 'fixture', 'installationId') `
                -Label 'Gameplay fixture cleanup marker')
        if (-not (Test-PSOBBProtectedAcl -Path $cleanupMarkerPath) -or
            $cleanupMarker.Value.schemaVersion -isnot [long] -or
            [long]$cleanupMarker.Value.schemaVersion -ne 1 -or
            [string]$cleanupMarker.Value.fixture -cne
                'CombatCanary Gameplay activation' -or
            [string]$cleanupMarker.Value.installationId -cne $fixtureToken) {
            throw 'The Gameplay fixture cleanup marker is not authentic'
        }
        $rootHandle = $null
        try {
            $rootHandle = Open-PSOBBCombatCanaryNativePathHandle `
                -Path $resolvedFixture -Directory $true
            $rootIdentity = Assert-PSOBBCombatCanaryNativeHandlePath `
                -Handle $rootHandle -ExpectedPath $resolvedFixture `
                -Root $temporaryRoot.TrimEnd('\') -Directory $true `
                -RoleLabel 'Gameplay fixture cleanup root'
        } finally {
            if ($null -ne $rootHandle) { $rootHandle.Dispose() }
        }
        if ($null -eq $fixtureRootIdentity -or
            -not (Test-PSOBBCombatCanaryNativeIdentityEqual `
                    -Left $fixtureRootIdentity -Right $rootIdentity)) {
            throw 'The Gameplay fixture root identity changed since creation; evidence was preserved'
        }
        Remove-PSOBBCombatCanaryOwnedTree -Path $resolvedFixture `
            -Root $temporaryRoot.TrimEnd('\') `
            -ExpectedVolumeSerialNumber $fixtureRootIdentity.VolumeSerialNumber `
            -ExpectedFileId $fixtureRootIdentity.FileId `
            -RoleLabel 'Gameplay activation fixture'
    }
}

Write-Output (
    "Combat-canary Gameplay activation tests passed ($Shard" +
    $(if ([string]::IsNullOrWhiteSpace($Boundary)) { '' } else {
            ":$Boundary"
        }) + '): ' +
    "$($results.Count)/$($results.Count)")
