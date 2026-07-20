[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,

    [Parameter(Mandatory)]
    [string]$SnapshotPath,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedBuildContractSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedTwillsContractSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSigningPublicKeySpkiSha256,

    [Parameter(DontShow = $true)]
    [ValidateRange(0, 11)]
    [int]$InternalTestFailAfterSwap = 0,

    [Parameter(DontShow = $true)]
    [string]$InternalTestFaultToken,

    [Parameter(DontShow = $true)]
    [switch]$InternalTestLeaveCompensationIncomplete,

    [Parameter(DontShow = $true)]
    [ValidateRange(0, 11)]
    [int]$InternalTestCreateUnexpectedTargetBeforeSwap = 0,

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

$script:RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Assert-PSOBBCombatInitializeLayout {
    param([Parameter(Mandatory)]$Value)

    $required = @(
        'Environment', 'EnvironmentId', 'Root', 'EnvironmentRoot',
        'ServerBase', 'Server', 'Client', 'ControlDirectory', 'PidFile',
        'LegacyPidFile', 'HostPidFile', 'ControlState', 'ControlRequest',
        'InstallRecord', 'Backups', 'Logs', 'Snapshots', 'Builds',
        'RuntimeMarker', 'BaseClient', 'BaseClientManifest', 'Secrets')
    if ([string]$Value.Environment -cne 'CombatCanary' -or
        [string]$Value.EnvironmentId -cne 'combat-canary' -or
        @($required | Where-Object {
                $Value.PSObject.Properties.Name -notcontains $_ -or
                [string]::IsNullOrWhiteSpace([string]$Value.$_)
            }).Count -ne 0) {
        throw 'The combat-canary server-environment layout contract is incomplete'
    }
    $Value
}

function Assert-PSOBBCombatInitializeStopped {
    $running = @(Get-Process -ErrorAction Stop | Where-Object {
            $_.ProcessName -like 'newserv*' -or
            $_.ProcessName -in @('Psobb', 'online', 'option')
        })
    if ($running.Count -gt 0) {
        $identities = @($running | Sort-Object ProcessName, Id | ForEach-Object {
                '{0} PID {1}' -f $_.ProcessName, $_.Id
            })
        throw ('Combat-canary initialization requires every PSOBB/newserv ' +
            "process to be stopped. Running: $($identities -join ', ')")
    }
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { [int]$_.LocalPort -in @(11000, 12000, 12001) })
    } catch {
        throw ('Cannot verify that PSOBB listeners are stopped: ' +
            $_.Exception.Message)
    }
    if ($listeners.Count -gt 0) {
        throw 'Combat-canary initialization requires all three PSOBB ports to be free'
    }
    $true
}

function Assert-PSOBBCombatInitializeInternalFaultGate {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Marker
    )

    $requested = $InternalTestFailAfterSwap -ne 0 -or
        $InternalTestCreateUnexpectedTargetBeforeSwap -ne 0 -or
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
        [int]($InternalTestCreateUnexpectedTargetBeforeSwap -gt 0) +
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
        -LiteralPath $fixtureMarkerPath -Root $Layout.Root -MaximumBytes 4KB `
        -RoleLabel 'internal combat canary fault fixture marker'
    $fixtureMarker = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $fixtureMarkerJson `
        -RoleLabel 'internal combat canary fault fixture marker'
    Assert-PSOBBCombatInitializeExactProperties -Value $fixtureMarker `
        -Label 'Internal combat-canary fault fixture marker' `
        -Expected @('schemaVersion', 'purpose', 'installationId')
    if ([int]$fixtureMarker.schemaVersion -ne 1 -or
        [string]$fixtureMarker.purpose -cne 'combat-canary-state-transaction-test' -or
        [string]$fixtureMarker.installationId -cne [string]$Marker.installationId) {
        throw 'The internal combat-canary fault fixture marker is not bound to this runtime'
    }
    $true
}

function Assert-PSOBBCombatInitializeFirstInstallEmpty {
    param([Parameter(Mandatory)]$Layout)

    if (-not (Test-Path -LiteralPath $Layout.EnvironmentRoot -PathType Container)) {
        return $true
    }
    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('server-base', 'snapshots', 'builds')) {
        [void]$allowed.Add($name)
    }
    $unexpected = @(Get-ChildItem -Force -LiteralPath $Layout.EnvironmentRoot |
        Where-Object { -not $allowed.Contains($_.Name) })
    if ($unexpected.Count -ne 0) {
        throw 'First combat-canary initialization refuses preexisting mutable state or evidence'
    }
    $true
}

function Assert-PSOBBCombatInitializeExactProperties {
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

function Assert-PSOBBCombatInitializeOrdinaryTree {
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

function Move-PSOBBCombatInitializeNoClobber {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Label
    )

    try {
        $sourceItem = Get-Item -Force -LiteralPath $Source -ErrorAction Stop
        if (($sourceItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Unsafe staged item'
        }
        if ($sourceItem.PSIsContainer) {
            [System.IO.Directory]::Move($Source, $Destination)
        } else {
            [System.IO.File]::Move($Source, $Destination, $false)
        }
    } catch {
        throw "No-clobber move failed for initialization target '$Label'"
    }
}

function Copy-PSOBBCombatInitializeTree {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$DestinationRoot
    )

    [void](Assert-PSOBBCombatInitializeOrdinaryTree `
            -Path $Source -Root $Source -Label 'Immutable initialization source')
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($child in @(Get-ChildItem -Force -LiteralPath $Source)) {
        $target = Assert-PathWithinRoot `
            -Path (Join-Path $Destination $child.Name) -Root $DestinationRoot
        Copy-Item -LiteralPath $child.FullName -Destination $target -Recurse
    }
}

function Get-PSOBBCombatInitializeBuild {
    param(
        [Parameter(Mandatory)]$Layout,
        [string]$ExplicitHash
    )

    $path = Join-Path $script:RepositoryRoot 'config\combat-canary-build.json'
    $expectedHash = if ([string]::IsNullOrWhiteSpace($ExplicitHash)) {
        ''
    } else {
        $ExplicitHash.ToLowerInvariant()
    }
    $buildSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $path -Root $script:RepositoryRoot -MaximumBytes 512KB `
        -ExpectedSha256 $expectedHash -PassThruSnapshot `
        -RoleLabel 'combat canary build contract'
    $hash = [string]$buildSnapshot.Sha256
    $buildJson = $buildSnapshot.Value
    $build = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $buildJson -RoleLabel 'combat canary build contract'
    [void](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $build)
    [void](Assert-PSOBBCombatInitializeOrdinaryTree `
            -Path $Layout.ServerBase -Root $Layout.EnvironmentRoot `
            -Label 'Combat-canary server base')
    $manifestPath = Join-Path $Layout.ServerBase 'release-manifest.json'
    $manifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $manifestPath -Root $Layout.ServerBase `
        -MaximumBytes 16MB `
        -ExpectedLength ([int64]$build.output.releaseManifest.size) `
        -ExpectedSha256 ([string]$build.output.releaseManifest.sha256) `
        -PassThruSnapshot -RoleLabel 'combat canary release manifest'
    $manifestJson = $manifestSnapshot.Value
    $manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $manifestJson -RoleLabel 'combat canary release manifest'
    Assert-PSOBBCombatInitializeExactProperties -Value $manifest `
        -Label 'Combat-canary release manifest' `
        -Expected @('schemaVersion', 'profileId', 'sourceCommit',
            'patchSeriesSha256', 'files')
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.profileId -cne [string]$build.profileId -or
        [string]$manifest.sourceCommit -cne [string]$build.source.commit -or
        [string]$manifest.patchSeriesSha256 -cne [string]$build.patchSeries.sha256) {
        throw 'The release manifest is not bound to the build contract'
    }
    $paths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $totalBytes = [int64]0
    foreach ($entry in @($manifest.files)) {
        Assert-PSOBBCombatInitializeExactProperties -Value $entry `
            -Label 'Combat-canary release file' -Expected @('path', 'size', 'sha256')
        $relative = [string]$entry.path
        if ($relative -cnotmatch '^(?!/)(?!.*(?:^|/)\.\.?(/|$))[^:\\]+$' -or
            $relative -ceq 'release-manifest.json' -or
            -not $paths.Add($relative) -or
            [int64]$entry.size -lt 0 -or
            [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The release manifest contains an unsafe or colliding path'
        }
        $file = Assert-PathWithinRoot `
            -Path (Join-Path $Layout.ServerBase ($relative.Replace('/', '\'))) `
            -Root $Layout.ServerBase
        if ((Get-Item -Force -LiteralPath $file).Length -ne [int64]$entry.size -or
            (Get-LowerSha256 $file) -cne [string]$entry.sha256) {
            throw 'The server-base release differs from its exact manifest'
        }
        $totalBytes += [int64]$entry.size
    }
    $actual = @(Get-ChildItem -Force -LiteralPath $Layout.ServerBase -Recurse -File |
        ForEach-Object {
            [System.IO.Path]::GetRelativePath(
                $Layout.ServerBase, $_.FullName).Replace('\', '/')
        } | Where-Object { $_ -cne 'release-manifest.json' })
    if ($paths.Count -ne [int]$build.output.fileCount -or
        $totalBytes -ne [int64]$build.output.totalBytes -or
        $actual.Count -ne $paths.Count -or
        @($actual | Where-Object { -not $paths.Contains($_) }).Count -ne 0) {
        throw 'The server-base inventory differs from the build contract'
    }
    $serverExecutable = Join-Path $Layout.ServerBase 'newserv-windows.exe'
    if ((Get-Item -Force -LiteralPath $serverExecutable).Length -ne
            [int64]$build.output.executable.size -or
        (Get-LowerSha256 $serverExecutable) -cne
            [string]$build.output.executable.sha256) {
        throw 'The server-base executable differs from the build contract'
    }
    [pscustomobject]@{
        Path = $path
        Hash = $hash
        Value = $build
        ManifestPath = $manifestPath
        ManifestHash = [string]$manifestSnapshot.Sha256
    }
}

function Get-PSOBBCombatInitializeNativeProfile {
    param([Parameter(Mandatory)]$ApprovedClient)

    $catalogJson = Read-PSOBBCombatCanaryStrictJsonObject -LiteralPath (
        Join-Path $script:RepositoryRoot 'config\graphics-profiles.json') `
        -Root $script:RepositoryRoot -MaximumBytes 1MB `
        -RoleLabel 'tracked graphics catalog'
    $catalog = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $catalogJson -RoleLabel 'tracked graphics catalog'
    $profiles = @($catalog.profiles | Where-Object {
            [string]$_.id -ceq 'safe-native-4x3'
        })
    if ([int]$catalog.schemaVersion -ne 1 -or $profiles.Count -ne 1) {
        throw 'The tracked graphics catalog does not declare safe-native-4x3 exactly once'
    }
    $native = Assert-PSOBBNativeGraphicsContract `
        -NativeGraphics $profiles[0].nativeGraphics `
        -Label 'Combat-canary native graphics contract'
    [ordered]@{
        schemaVersion = 5
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
        channel = 'combat-canary'
        profileId = 'safe-native-4x3'
        nativeGraphics = [ordered]@{
            presetId = $native.PresetId
            graphicCtrlDwords = [uint32[]]$native.GraphicCtrlDwords
            graphicCtrlSha256 = $native.GraphicCtrlSha256
            advancedEffectsPolicy = $native.AdvancedEffectsPolicy
            pixelFogPolicy = $native.PixelFogPolicy
            lowResolutionTexturesPolicy = $native.LowResolutionTexturesPolicy
            frameSkipPolicy = $native.FrameSkipPolicy
        }
        renderer = 'Native'
        baseExecutableSha256 = $ApprovedClient.Sha256
        wrapperSha256 = $null
        sourceConfigurationSha256 = $null
        configurationSha256 = $null
        outputApi = $null
        graphicsPreset = 'Native'
        desktopWidth = $null
        desktopHeight = $null
        renderWidth = $null
        renderHeight = $null
        aspectPolicy = $null
        resamplingFilter = $null
        textureFilterPolicy = $null
        edgeSmoothingPolicy = $null
        bilinear2DOperations = $null
        defaultWindowMode = $null
        resizableClientWidth = $null
        resizableClientHeight = $null
        watermarkEnabled = $null
        compatibilityFirst = $false
    }
}

function Get-PSOBBCombatInitializeBaselinePolicyHash {
    $policyPath = Join-Path $script:RepositoryRoot `
        'config\client-patch-profiles.json'
    $policySnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $policyPath -Root $script:RepositoryRoot `
        -MaximumBytes 1MB -PassThruSnapshot `
        -RoleLabel 'tracked client patch policy'
    $policyJson = $policySnapshot.Value
    $policy = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $policyJson -RoleLabel 'tracked client patch policy'
    $profiles = @($policy.profiles | Where-Object {
            [string]$_.id -ceq 'baseline'
        })
    if ([int]$policy.schemaVersion -ne 1 -or $profiles.Count -ne 1 -or
        [string]$profiles[0].channel -cne 'stable' -or
        $profiles[0].autoPatches -isnot [System.Array] -or
        $profiles[0].bbRequiredPatches -isnot [System.Array] -or
        @($profiles[0].autoPatches).Count -ne 0 -or
        @($profiles[0].bbRequiredPatches).Count -ne 0) {
        throw 'The tracked baseline client patch policy is not exact and patch-free'
    }
    [string]$policySnapshot.Sha256
}

function Set-PSOBBCombatInitializeLocalConfiguration {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$Root
    )

    $text = Read-PSOBBCombatCanaryStrictUtf8Text `
        -LiteralPath $ConfigPath -Root $Root -MaximumBytes 16MB `
        -RoleLabel 'staged combat canary configuration source'
    if ($text.StartsWith([char]0xFEFF)) {
        throw 'The staged combat-canary configuration source has a BOM'
    }
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $values = [ordered]@{
        ServerName = '"PSOBB Combat"'
        LocalAddress = '"127.0.0.1"'
        ExternalAddress = '"127.0.0.1"'
        DNSServerPort = '0'
        IPStackListen = '[]'
        PPPStackListen = '[]'
        PPPRawListen = '[]'
        HTTPListen = '[]'
        AllowUnregisteredUsers = 'false'
        CheatModeBehavior = '"Off"'
        DefaultDropModeV4Normal = '"SERVER_PRIVATE"'
        BBEXPShareMultiplier = '0'
        EnableSwitchAssistByDefault = 'true'
        RareNotificationsEnabledByDefaultV3V4 = 'true'
        CommandData = '"DISABLED"'
    }
    foreach ($key in $values.Keys) {
        $text = Set-ConfigScalar -Text $text -Key $key `
            -JsonValue ([string]$values[$key])
    }
    if ($text -match '(?m)^\s*"RunInteractiveShell"\s*:') {
        $text = Set-ConfigScalar -Text $text `
            -Key 'RunInteractiveShell' -JsonValue 'true'
    } else {
        $httpPattern = '(?m)^(\s*"HTTPListen"\s*:\s*\[\],\s*)$'
        if ([regex]::Matches($text, $httpPattern).Count -ne 1) {
            throw 'Could not safely insert the combat-canary interactive-shell policy'
        }
        $text = [regex]::Replace(
            $text,
            $httpPattern,
            '$1' + "`n" + '  "RunInteractiveShell": true,',
            1)
    }
    $text = Set-ConfigStringArray -Text $text `
        -Key 'BBRequiredPatches' -Values @()
    $text = Set-ConfigStringArray -Text $text `
        -Key 'AutoPatches' -Values @()

    $portPattern =
        '(?ms)(\s*"PortConfiguration"\s*:\s*)\{.*?^\s{2}\},\s*\r?\n\s*// Where to listen for IP'
    $portRegex = [regex]::new($portPattern)
    if ($portRegex.Matches($text).Count -ne 1) {
        throw 'Could not locate the combat-canary port configuration safely'
    }
    $ports = @'
{
    "bb-patch": [["127.0.0.1", 11000], "patch", "patch_server_bb"],
    "bb-data1": [["127.0.0.1", 12000], "bb", "game_server"],
    "bb-data2": [["127.0.0.1", 12001], "bb", "game_server"],
  },

  // Where to listen for IP
'@
    $ports = $ports.Replace("`r`n", "`n").Replace("`r", "`n")
    $text = $portRegex.Replace(
        $text, { param($match) $match.Groups[1].Value + $ports }, 1)
    if ($text.StartsWith([char]0xFEFF) -or $text.Contains("`r")) {
        throw 'The generated combat-canary configuration is not LF-only UTF-8'
    }
    [System.IO.File]::WriteAllText(
        $ConfigPath, $text, [System.Text.UTF8Encoding]::new($false))
}

function Test-PSOBBCombatInitializeSemantic {
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
        $bank = @(& (Join-Path $PSScriptRoot 'Test-PSOBBTwillsBank.ps1') `
                -Path $BankPath -BuildPath $ContractPath `
                -ExpectedBuildSha256 $ContractHash | Where-Object {
                $_.PSObject.Properties.Name -contains 'Valid'
            })
    } catch {
        throw 'Staged combat-canary state failed independent Twills verification'
    }
    if ($character.Count -ne 1 -or $bank.Count -ne 1 -or
        -not [bool]$character[0].Valid -or -not [bool]$bank[0].Valid -or
        [int]$character[0].SlotIndex -ne 0 -or
        [int]$character[0].DisplayedLevel -ne 200 -or
        [string]$bank[0].Character -cne 'Twills' -or
        [string]$bank[0].Class -cne 'FOnewearl') {
        throw 'Staged combat-canary state is not slot-0 Twills FOnewearl'
    }
    $true
}

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if (-not (Get-Command Get-PSOBBServerEnvironmentLayout -ErrorAction SilentlyContinue)) {
    throw 'Get-PSOBBServerEnvironmentLayout is required for combat-canary initialization'
}
$layout = Assert-PSOBBCombatInitializeLayout -Value (
    Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment CombatCanary)
$stableLayout = Get-PSOBBServerEnvironmentLayout -Layout $rootLayout -Environment Stable
[void](Assert-PSOBBServerEnvironmentIsolation -Layout $rootLayout)
[void](Assert-PSOBBCombatInitializeStopped)
$build = Get-PSOBBCombatInitializeBuild `
    -Layout $layout -ExplicitHash $ExpectedBuildContractSha256
$snapshot = & (Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
    -RuntimeRoot $rootLayout.Root -Target Snapshot -SnapshotPath $SnapshotPath `
    -ExpectedTwillsContractSha256 $ExpectedTwillsContractSha256 `
    -ExpectedSigningPublicKeySpkiSha256 $ExpectedSigningPublicKeySpkiSha256
if ($null -eq $snapshot -or -not [bool]$snapshot.Valid) {
    throw 'The initialization snapshot did not pass sealed verification'
}
$snapshotRoot = [string]$snapshot.SnapshotPath
$snapshotDirectoryName = (Get-Item -Force -LiteralPath $snapshotRoot).Name
$snapshotManifestJson = Read-PSOBBCombatCanaryStrictJsonObject -LiteralPath (
    Join-Path $snapshotRoot 'manifest.json') -Root $snapshotRoot `
    -MaximumBytes 256KB -ExpectedSha256 ([string]$snapshot.ManifestSha256) `
    -RoleLabel 'initialization snapshot manifest'
$snapshotManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
    -JsonObject $snapshotManifestJson -RoleLabel 'initialization snapshot manifest'
$stateEntries = @($snapshotManifest.files | Where-Object {
        [string]$_.path -cmatch '^state/system/'
    })
[void](Assert-PSOBBCombatCanaryPayloadSetPolicy `
        -Entries $stateEntries -Scope State)
$contractPath = Join-Path $script:RepositoryRoot 'config\twills-fonewearl-build.json'
$approvedClient = Get-PSOBBCombatCanaryApprovedClientIdentity `
    -RepositoryRoot $script:RepositoryRoot
$baselinePolicyHash = Get-PSOBBCombatInitializeBaselinePolicyHash

[void](Assert-PSOBBCombatInitializeOrdinaryTree `
        -Path $stableLayout.BaseClient -Root $stableLayout.Root `
        -Label 'Stable immutable base client')
$stableBaseManifestSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
    -LiteralPath $stableLayout.BaseClientManifest `
    -Root $stableLayout.Root -MaximumBytes 16MB -PassThruSnapshot `
    -RoleLabel 'stable base client manifest'
$stableBaseManifestJson = $stableBaseManifestSnapshot.Value
$stableBaseManifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
    -JsonObject $stableBaseManifestJson -RoleLabel 'stable base client manifest'
if ([int]$stableBaseManifest.schemaVersion -ne 1 -or
    -not (Test-PSOBBDirectoryManifest `
        -Root $stableLayout.BaseClient -Files @($stableBaseManifest.files)) -or
    (Get-Item -Force -LiteralPath (
        Join-Path $stableLayout.BaseClient 'Psobb.exe')).Length -ne $approvedClient.Size -or
    (Get-LowerSha256 (Join-Path $stableLayout.BaseClient 'Psobb.exe')) -cne
        $approvedClient.Sha256) {
    throw 'The Stable immutable 59NL base client failed manifest verification'
}
$stableBaseManifestHash = [string]$stableBaseManifestSnapshot.Sha256

$marker = Get-PSOBBCombatCanaryStrictRuntimeMarker -Layout $rootLayout
[void](Assert-PSOBBCombatInitializeInternalFaultGate `
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
    if (-not $ownsMutex) { throw 'Another PSOBB lifecycle operation is in progress' }
    [void](Assert-PSOBBCombatInitializeStopped)

    if (Test-Path -LiteralPath $layout.InstallRecord -PathType Leaf) {
        $existing = & (Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
            -RuntimeRoot $rootLayout.Root -Target Installed `
            -SnapshotPath $snapshotRoot `
            -ExpectedBuildContractSha256 $build.Hash `
            -ExpectedTwillsContractSha256 $snapshot.TwillsContractSha256 `
            -ExpectedSigningPublicKeySpkiSha256 $snapshot.SigningPublicKeySpkiSha256
        if (-not [bool]$existing.Valid) {
            throw 'The existing combat-canary installation failed idempotent verification'
        }
        return [pscustomobject]@{
            Initialized = $true
            Changed = $false
            Environment = 'CombatCanary'
            SnapshotId = [string]$snapshot.SnapshotId
            BuildContractSha256 = $build.Hash
            TwillsContractSha256 = [string]$snapshot.TwillsContractSha256
        }
    }
    [void](Assert-PSOBBCombatInitializeFirstInstallEmpty -Layout $layout)
    if (-not $PSCmdlet.ShouldProcess(
            $layout.EnvironmentRoot,
            'Atomically materialize the isolated combat-canary runtime')) {
        return [pscustomobject]@{
            Initialized = $false
            Changed = $false
            WhatIf = $true
            Environment = 'CombatCanary'
            SnapshotId = [string]$snapshot.SnapshotId
            BuildContractSha256 = $build.Hash
        }
    }

    $transactionId = [Guid]::NewGuid().ToString('N')
    $stageRoot = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot ('.initialize-stage-' + $transactionId)) `
        -Root $layout.EnvironmentRoot
    $rollbackRoot = Assert-PathWithinRoot `
        -Path (Join-Path $layout.EnvironmentRoot ('.initialize-rollback-' + $transactionId)) `
        -Root $layout.EnvironmentRoot
    $processed = [System.Collections.Generic.List[object]]::new()
    $completed = $false
    $stageTransaction = $null
    $rollbackTransaction = $null
    try {
        $stageTransaction = New-PSOBBCombatCanaryTransactionTree `
            -Path $stageRoot -Root $layout.EnvironmentRoot `
            -TransactionId $transactionId -Purpose 'initialize-stage'
        Set-PSOBBProtectedAcl -Path $stageRoot
        $stageServer = Join-Path $stageRoot 'server\release'
        $stageBaseClient = Join-Path $stageRoot 'client'
        $stageClient = Join-Path $stageRoot 'runtime\client'
        Copy-PSOBBCombatInitializeTree `
            -Source $layout.ServerBase -Destination $stageServer `
            -DestinationRoot $stageRoot
        Copy-PSOBBCombatInitializeTree `
            -Source $stableLayout.BaseClient -Destination $stageBaseClient `
            -DestinationRoot $stageRoot
        Copy-PSOBBCombatInitializeTree `
            -Source $stageBaseClient -Destination $stageClient `
            -DestinationRoot $stageRoot
        $stageBaseManifestPath = Join-Path $stageRoot 'base-client.manifest.json'
        Copy-Item -LiteralPath $stableLayout.BaseClientManifest `
            -Destination $stageBaseManifestPath
        if ((Get-LowerSha256 $stageBaseManifestPath) -cne $stableBaseManifestHash -or
            -not (Test-PSOBBDirectoryManifest `
                -Root $stageBaseClient -Files @($stableBaseManifest.files))) {
            throw 'The staged immutable base client failed exact readback'
        }

        $stageSystem = Join-Path $stageServer 'system'
        foreach ($directoryName in @('licenses', 'players', 'teams')) {
            $path = Join-Path $stageSystem $directoryName
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force
            }
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        $stageCharacterPath = $null
        $stageBankPath = $null
        if ($null -ne $InternalTestBeforePayloadCopy) {
            & $InternalTestBeforePayloadCopy
        }
        foreach ($entry in $stateEntries) {
            try {
                $source = Assert-PathWithinRoot `
                    -Path (Join-Path $snapshotRoot (
                        ([string]$entry.path).Replace('/', '\'))) `
                    -Root $snapshotRoot
                $relative = ([string]$entry.path).Substring('state/system/'.Length)
                $destination = Assert-PathWithinRoot `
                    -Path (Join-Path $stageSystem ($relative.Replace('/', '\'))) `
                    -Root $stageSystem
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
                    -RoleLabel ("initialization $($entry.role) payload") `
                    -InternalTestAfterSourceLease `
                        $InternalTestAfterPayloadSourceLease | Out-Null
            } catch {
                throw "Staged state copy failed for role '$($entry.role)'"
            }
            if ([string]$entry.role -ceq 'twills-character') {
                $stageCharacterPath = $destination
            } elseif ([string]$entry.role -ceq 'twills-bank') {
                $stageBankPath = $destination
            }
        }
        [void](Test-PSOBBCombatInitializeSemantic `
                -CharacterPath $stageCharacterPath -BankPath $stageBankPath `
                -ContractPath $contractPath `
                -ContractHash ([string]$snapshot.TwillsContractSha256))

        $configurationPath = Join-Path $stageSystem 'config.json'
        Set-PSOBBCombatInitializeLocalConfiguration `
            -ConfigPath $configurationPath -Root $stageRoot
        if ((Get-LowerSha256 (Join-Path $script:RepositoryRoot `
                    'config\client-patch-profiles.json')) -cne
            $baselinePolicyHash) {
            throw 'The tracked client patch policy changed during initialization'
        }
        $configurationText = Read-PSOBBCombatCanaryStrictUtf8Text `
            -LiteralPath $configurationPath -Root $stageRoot `
            -MaximumBytes 16MB `
            -RoleLabel 'staged combat canary configuration'
        $configurationText = Set-ConfigScalar -Text $configurationText `
            -Key 'DefaultDropModeV4Battle' -JsonValue '"SERVER_SHARED"'
        $configurationText = Set-ConfigScalar -Text $configurationText `
            -Key 'DefaultDropModeV4Challenge' -JsonValue '"SERVER_SHARED"'
        $configurationText = Set-ConfigScalar -Text $configurationText `
            -Key 'CensorCredentials' -JsonValue 'true'
        $configurationText = Set-ConfigScalar -Text $configurationText `
            -Key 'AllowSameAccountConcurrentLogins' -JsonValue 'false'
        if ($configurationText.StartsWith([char]0xFEFF) -or
            $configurationText.Contains("`r")) {
            throw 'The finalized combat-canary configuration is not LF-only UTF-8'
        }
        [System.IO.File]::WriteAllText(
            $configurationPath, $configurationText,
            [System.Text.UTF8Encoding]::new($false))
        Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $configurationPath -Root $stageRoot `
            -MaximumBytes 16MB `
            -RoleLabel 'staged combat canary configuration' | Out-Null

        $clientProfilePath = Join-Path $stageClient 'client-profile.json'
        $profile = Get-PSOBBCombatInitializeNativeProfile -ApprovedClient $approvedClient
        [System.IO.File]::WriteAllText(
            $clientProfilePath,
            ($profile | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false))
        $clientProfileHash = Get-LowerSha256 $clientProfilePath
        $clientBinding = [ordered]@{
            schemaVersion = 1
            environment = 'CombatCanary'
            environmentId = 'combat-canary'
            profile = 'baseline'
            renderer = 'Native'
            serverAddress = '127.0.0.1'
            patchPort = 11000
            gamePorts = @(12000, 12001)
            clientExecutablePath = 'runtime/client/Psobb.exe'
            clientExecutableSize = $approvedClient.Size
            clientExecutableSha256 = $approvedClient.Sha256
            clientProfileSha256 = $clientProfileHash
            baseClientManifestSha256 = $stableBaseManifestHash
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
        }
        $stageClientBindingPath = Join-Path $stageRoot 'client-binding.json'
        [System.IO.File]::WriteAllText(
            $stageClientBindingPath,
            ($clientBinding | ConvertTo-Json -Depth 8),
            [System.Text.UTF8Encoding]::new($false))

        $stateBinding = [ordered]@{
            schemaVersion = 1
            environment = 'CombatCanary'
            environmentId = 'combat-canary'
            restoredAtUtc = [DateTime]::UtcNow.ToString('o')
            snapshotDirectoryName = $snapshotDirectoryName
            snapshotId = [string]$snapshot.SnapshotId
            snapshotManifestSha256 = [string]$snapshot.ManifestSha256
            twillsContractSha256 = [string]$snapshot.TwillsContractSha256
            signingPublicKeySpkiSha256 =
                [string]$snapshot.SigningPublicKeySpkiSha256
            stateFiles = $stateEntries.Count
        }
        $stageStateBindingPath = Join-Path $stageRoot 'state-binding.json'
        [System.IO.File]::WriteAllText(
            $stageStateBindingPath,
            ($stateBinding | ConvertTo-Json -Depth 8),
            [System.Text.UTF8Encoding]::new($false))
        $stageControl = Join-Path $stageRoot 'control'
        $stageBackups = Join-Path $stageRoot 'backups'
        $stageLogs = Join-Path $stageRoot 'logs'
        $stageSecrets = Join-Path $stageRoot 'secrets'
        New-Item -ItemType Directory -Path $stageControl, $stageBackups,
            $stageLogs, $stageSecrets -Force | Out-Null

        try {
            foreach ($protectedTree in @(
                    (Join-Path $stageSystem 'licenses'),
                    (Join-Path $stageSystem 'players'),
                    (Join-Path $stageSystem 'teams'),
                    $stageControl, $stageBackups, $stageLogs, $stageSecrets)) {
                Set-PSOBBProtectedTreeAcl -Path $protectedTree -Root $stageRoot
            }
            foreach ($protectedFile in @(
                    $stageClientBindingPath, $stageStateBindingPath)) {
                Set-PSOBBProtectedAcl -Path $protectedFile
            }
        } catch {
            throw 'The staged combat-canary protected state could not be sealed'
        }

        $stageInstallPath = Join-Path $stageRoot 'installation.json'
        $install = [ordered]@{
            schemaVersion = 1
            environment = 'CombatCanary'
            environmentId = 'combat-canary'
            initializedAtUtc = [DateTime]::UtcNow.ToString('o')
            buildContractSha256 = $build.Hash
            serverReleaseManifestSha256 = $build.ManifestHash
            baseClientManifestSha256 = $stableBaseManifestHash
            clientBindingSha256 = Get-LowerSha256 $stageClientBindingPath
            snapshotDirectoryName = $snapshotDirectoryName
            snapshotId = [string]$snapshot.SnapshotId
            snapshotManifestSha256 = [string]$snapshot.ManifestSha256
            stateBindingSha256 = Get-LowerSha256 $stageStateBindingPath
            twillsContractSha256 = [string]$snapshot.TwillsContractSha256
            signingPublicKeySpkiSha256 =
                [string]$snapshot.SigningPublicKeySpkiSha256
            configurationSha256 = Get-LowerSha256 $configurationPath
        }
        [System.IO.File]::WriteAllText(
            $stageInstallPath,
            ($install | ConvertTo-Json -Depth 8),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $stageInstallPath
        [void](Assert-PSOBBCombatInitializeStopped)

        $rollbackTransaction = New-PSOBBCombatCanaryTransactionTree `
            -Path $rollbackRoot -Root $layout.EnvironmentRoot `
            -TransactionId ([Guid]::NewGuid().ToString('N')) `
            -Purpose 'initialize-rollback'
        Set-PSOBBProtectedAcl -Path $rollbackRoot
        $targets = @(
            [pscustomobject]@{ Name = 'server'; Current = Split-Path -Parent $layout.Server; Staged = Split-Path -Parent $stageServer },
            [pscustomobject]@{ Name = 'base-client'; Current = $layout.BaseClient; Staged = $stageBaseClient },
            [pscustomobject]@{ Name = 'runtime'; Current = Split-Path -Parent $layout.Client; Staged = Split-Path -Parent $stageClient },
            [pscustomobject]@{ Name = 'control'; Current = $layout.ControlDirectory; Staged = $stageControl },
            [pscustomobject]@{ Name = 'backups'; Current = $layout.Backups; Staged = $stageBackups },
            [pscustomobject]@{ Name = 'logs'; Current = $layout.Logs; Staged = $stageLogs },
            [pscustomobject]@{ Name = 'secrets'; Current = $layout.Secrets; Staged = $stageSecrets },
            [pscustomobject]@{ Name = 'base-client-manifest'; Current = $layout.BaseClientManifest; Staged = $stageBaseManifestPath },
            [pscustomobject]@{ Name = 'client-binding'; Current = Join-Path $layout.EnvironmentRoot 'client-binding.json'; Staged = $stageClientBindingPath },
            [pscustomobject]@{ Name = 'state-binding'; Current = Join-Path $layout.EnvironmentRoot 'state-binding.json'; Staged = $stageStateBindingPath },
            [pscustomobject]@{ Name = 'installation'; Current = $layout.InstallRecord; Staged = $stageInstallPath })
        if ($InternalTestFailAfterSwap -gt $targets.Count -or
            $InternalTestCreateUnexpectedTargetBeforeSwap -gt $targets.Count) {
            throw 'The requested internal initialization swap boundary does not exist'
        }
        $swapCount = 0
        foreach ($target in $targets) {
            $target | Add-Member -NotePropertyName Rollback `
                -NotePropertyValue (Join-Path $rollbackRoot $target.Name)
            if ($InternalTestCreateUnexpectedTargetBeforeSwap -eq
                ($swapCount + 1)) {
                $stagedItem = Get-Item -Force -LiteralPath $target.Staged
                if ($stagedItem.PSIsContainer) {
                    [void][System.IO.Directory]::CreateDirectory($target.Current)
                    [System.IO.File]::WriteAllText(
                        (Join-Path $target.Current '.unexpected-preserve'),
                        'preserve', [System.Text.UTF8Encoding]::new($false))
                } else {
                    [System.IO.File]::WriteAllText(
                        $target.Current, 'preserve',
                        [System.Text.UTF8Encoding]::new($false))
                }
            }
            if (Test-Path -LiteralPath $target.Current) {
                throw 'First combat-canary initialization detected an unexpected target before publication'
            }
            $stagedItem = Get-Item -Force -LiteralPath $target.Staged `
                -ErrorAction Stop
            $stagedIsDirectory = [bool]$stagedItem.PSIsContainer
            $stagedIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $target.Staged -Root $stageRoot `
                -Directory $stagedIsDirectory `
                -RoleLabel ("staged initialization target '$($target.Name)'")
            $record = [pscustomobject]@{
                Item = $target
                HadCurrent = $false
                NeedsCompensation = $false
                Directory = $stagedIsDirectory
                VolumeSerialNumber = [uint32]$stagedIdentity.VolumeSerialNumber
                FileId = [uint64]$stagedIdentity.FileId
            }
            $processed.Add($record)
            Move-PSOBBCombatInitializeNoClobber -Source $target.Staged `
                -Destination $target.Current -Label $target.Name
            $record.NeedsCompensation = $true
            if ($null -ne $InternalTestAfterPublishedMove) {
                & $InternalTestAfterPublishedMove $target.Current $target.Name
            }
            $currentIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $target.Current -Root $layout.EnvironmentRoot `
                -Directory $record.Directory `
                -RoleLabel ("published initialization target '$($target.Name)'")
            if ([uint32]$currentIdentity.VolumeSerialNumber -ne
                    [uint32]$record.VolumeSerialNumber -or
                [uint64]$currentIdentity.FileId -ne [uint64]$record.FileId) {
                throw "Initialization target '$($target.Name)' changed identity after publication"
            }
            $swapCount++
            if ($InternalTestFailAfterSwap -eq $swapCount) {
                throw 'Injected temporary-fixture initialization swap failure'
            }
        }
        $readback = & (Join-Path $PSScriptRoot 'Test-PSOBBCombatCanary.ps1') `
            -RuntimeRoot $rootLayout.Root -Target Installed `
            -SnapshotPath $snapshotRoot `
            -ExpectedBuildContractSha256 $build.Hash `
            -ExpectedTwillsContractSha256 $snapshot.TwillsContractSha256 `
            -ExpectedSigningPublicKeySpkiSha256 $snapshot.SigningPublicKeySpkiSha256
        if (-not [bool]$readback.Valid) {
            throw 'The materialized combat-canary failed exact installed readback'
        }
        $completed = $true
        [pscustomobject]@{
            Initialized = $true
            Changed = $true
            Environment = 'CombatCanary'
            SnapshotId = [string]$snapshot.SnapshotId
            SnapshotDirectoryName = $snapshotDirectoryName
            SnapshotManifestSha256 = [string]$snapshot.ManifestSha256
            BuildContractSha256 = $build.Hash
            ServerReleaseManifestSha256 = $build.ManifestHash
            BaseClientManifestSha256 = $stableBaseManifestHash
            ClientBindingSha256 = [string]$readback.ClientBindingSha256
            StateBindingSha256 = [string]$readback.StateBindingSha256
            ConfigurationSha256 = [string]$readback.ConfigurationSha256
            TwillsContractSha256 = [string]$snapshot.TwillsContractSha256
            SigningPublicKeySpkiSha256 =
                [string]$snapshot.SigningPublicKeySpkiSha256
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
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
                if (Test-Path -LiteralPath $record.Item.Current) {
                    if ([bool]$record.Directory) {
                        Remove-PSOBBCombatCanaryOwnedTree `
                            -Path $record.Item.Current `
                            -Root $layout.EnvironmentRoot `
                            -ExpectedVolumeSerialNumber `
                                $record.VolumeSerialNumber `
                            -ExpectedFileId $record.FileId `
                            -RoleLabel ("initialization compensation '$($record.Item.Name)'")
                    } else {
                        Remove-PSOBBCombatCanaryOwnedFile `
                            -Path $record.Item.Current `
                            -Root $layout.EnvironmentRoot `
                            -ExpectedVolumeSerialNumber `
                                $record.VolumeSerialNumber `
                            -ExpectedFileId $record.FileId `
                            -RoleLabel ("initialization compensation '$($record.Item.Name)'")
                    }
                }
                if ($record.HadCurrent -and
                    (Test-Path -LiteralPath $record.Item.Rollback)) {
                    Move-PSOBBCombatInitializeNoClobber `
                        -Source $record.Item.Rollback `
                        -Destination $record.Item.Current `
                        -Label $record.Item.Name
                }
                $record.NeedsCompensation = $false
            } catch {
                $rollbackErrors.Add($record.Item.Name)
            }
        }
        if ($rollbackErrors.Count -ne 0) {
            throw ('Combat-canary initialization failed and compensation was ' +
                'incomplete for: ' + ($rollbackErrors -join ', ') +
                '. Original error: ' + $failure.Exception.Message)
        }
        throw $failure
    } finally {
        if (Test-Path -LiteralPath $stageRoot) {
            try {
                if ($null -eq $stageTransaction) {
                    throw 'The initialization stage has no transaction identity'
                }
                Remove-PSOBBCombatCanaryTransactionTree `
                    -Transaction $stageTransaction `
                    -RoleLabel 'combat-canary initialization staging cleanup'
            } catch {
                throw 'Combat-canary initialization staging cleanup retained identity-mismatched evidence'
            }
        }
        if (Test-Path -LiteralPath $rollbackRoot) {
            try {
                if ($null -eq $rollbackTransaction) {
                    throw 'The initialization rollback tree has no transaction identity'
                }
                Remove-PSOBBCombatCanaryTransactionTree `
                    -Transaction $rollbackTransaction `
                    -RoleLabel 'combat-canary initialization rollback cleanup'
            } catch {
                throw 'Combat-canary initialization rollback cleanup retained identity-mismatched evidence'
            }
        }
    }
} finally {
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
