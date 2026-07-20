[CmdletBinding()]
param(
    [ValidateSet('All', 'SyntheticTransactions', 'VerifierScopeRegression',
        'RealPublishedReadOnly')]
    [string]$Mode = 'All'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scriptsRoot = Join-Path $repositoryRoot 'scripts'
. (Join-Path $scriptsRoot 'PSOBB.Common.ps1')
. (Join-Path $scriptsRoot 'PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $scriptsRoot 'PSOBB.CombatCanary.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
$sectionTimings = [System.Collections.Generic.List[object]]::new()
$overallStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:ActiveSection = $null
function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Start-TestSection([string]$Name) {
    if ($null -ne $script:ActiveSection) {
        throw "Test section '$($script:ActiveSection.Name)' was not completed"
    }
    $script:ActiveSection = [pscustomobject]@{
        Name = $Name
        ResultsBefore = $results.Count
        Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
    Write-Host "[combat-canary-state] section-start name=$Name"
}

function Complete-TestSection {
    if ($null -eq $script:ActiveSection) {
        throw 'No combat-canary test section is active'
    }
    $script:ActiveSection.Stopwatch.Stop()
    $sectionTimings.Add([pscustomobject]@{
            Name = [string]$script:ActiveSection.Name
            DurationMilliseconds = [int64][Math]::Round(
                $script:ActiveSection.Stopwatch.Elapsed.TotalMilliseconds)
            Tests = $results.Count - [int]$script:ActiveSection.ResultsBefore
        })
    Write-Host (
        '[combat-canary-state] section-complete name={0} durationMs={1} tests={2}' -f
        $sectionTimings[$sectionTimings.Count - 1].Name,
        $sectionTimings[$sectionTimings.Count - 1].DurationMilliseconds,
        $sectionTimings[$sectionTimings.Count - 1].Tests)
    $script:ActiveSection = $null
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Name
    )

    $rejected = $false
    try {
        & $Action | Out-Null
    } catch {
        $rejected = $true
    }
    Add-Result $Name $rejected $(if ($rejected) { 'rejected' } else { 'accepted unexpectedly' })
}

function Assert-RejectedWithoutText {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ForbiddenText,
        [string]$ExactMessage
    )

    $passed = $false
    try {
        & $Action | Out-Null
    } catch {
        $message = [string]$_.Exception.Message
        $passed = $message.IndexOf(
            $ForbiddenText, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
            ([string]::IsNullOrWhiteSpace($ExactMessage) -or
                $message -ceq $ExactMessage)
    }
    Add-Result $Name $passed $(if ($passed) {
            'rejected with role-only error'
        } else { 'accepted or exposed protected identity text' })
}

function New-TestSnapshotClone {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SnapshotsRoot
    )

    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 8)
    $destination = Join-Path $SnapshotsRoot "twills-slot0-$stamp-$suffix"
    Copy-Item -LiteralPath $Source -Destination $destination -Recurse
    Set-PSOBBProtectedTreeAcl -Path $destination -Root $SnapshotsRoot
    $destination
}

function Set-TestSnapshotManifest {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [Parameter(Mandatory)]$Manifest
    )

    $manifestPath = Join-Path $SnapshotPath 'manifest.json'
    [System.IO.File]::WriteAllText(
        $manifestPath,
        ($Manifest | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false))
    $key = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem([System.IO.File]::ReadAllText($PrivateKeyPath))
        $signature = $key.SignData(
            [System.IO.File]::ReadAllBytes($manifestPath),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        [System.IO.File]::WriteAllText(
            (Join-Path $SnapshotPath 'manifest.sig'),
            [Convert]::ToBase64String($signature),
            [System.Text.Encoding]::ASCII)
    } finally {
        $key.Dispose()
    }
    Set-PSOBBProtectedTreeAcl -Path $SnapshotPath -Root (Split-Path -Parent $SnapshotPath)
}

function Set-TestSnapshotManifestText {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [Parameter(Mandatory)][string]$Text
    )

    $manifestPath = Join-Path $SnapshotPath 'manifest.json'
    [System.IO.File]::WriteAllText(
        $manifestPath, $Text, [System.Text.UTF8Encoding]::new($false))
    $key = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem([System.IO.File]::ReadAllText($PrivateKeyPath))
        $signature = $key.SignData(
            [System.IO.File]::ReadAllBytes($manifestPath),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        [System.IO.File]::WriteAllText(
            (Join-Path $SnapshotPath 'manifest.sig'),
            [Convert]::ToBase64String($signature),
            [System.Text.Encoding]::ASCII)
    } finally {
        $key.Dispose()
    }
    Set-PSOBBProtectedTreeAcl -Path $SnapshotPath `
        -Root (Split-Path -Parent $SnapshotPath)
}

function New-TestSignedLicenseMutation {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SnapshotsRoot,
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [Parameter(Mandatory)][scriptblock]$Mutation,
        [switch]$RawText
    )

    $clone = New-TestSnapshotClone -Source $Source -SnapshotsRoot $SnapshotsRoot
    $manifestPath = Join-Path $clone 'manifest.json'
    $manifest = Get-Content -Raw -LiteralPath $manifestPath |
        ConvertFrom-Json -Depth 100 -DateKind String
    $characterEntry = @($manifest.files | Where-Object {
            [string]$_.role -ceq 'twills-character'
        })
    if ($characterEntry.Count -ne 1 -or
        [System.IO.Path]::GetFileName([string]$characterEntry[0].path) `
            -cnotmatch '^player_(?<account>[a-z][a-z0-9_-]{2,15})_0\.psochar$') {
        throw 'The signed license fixture cannot derive its protected identity'
    }
    $accountStem = [string]$Matches.account
    $changed = 0
    foreach ($entry in @($manifest.files | Where-Object {
                [string]$_.role -ceq 'license-state'
            })) {
        $licensePath = Join-Path $clone (([string]$entry.path).Replace('/', '\'))
        $licenseText = [System.IO.File]::ReadAllText($licensePath)
        $licenseState = $licenseText | ConvertFrom-Json -Depth 100 -DateKind String
        $hasMatch = $false
        if ($licenseState.PSObject.Properties.Name -contains 'BBUsername' -and
            [string]$licenseState.BBUsername -ceq $accountStem) {
            $hasMatch = $true
        }
        if ($licenseState.PSObject.Properties.Name -contains 'BBLicenses') {
            foreach ($bbLicense in @($licenseState.BBLicenses)) {
                if ($null -ne $bbLicense -and
                    $bbLicense.PSObject.Properties.Name -contains 'UserName' -and
                    [string]$bbLicense.UserName -ceq $accountStem) {
                    $hasMatch = $true
                }
            }
        }
        if (-not $hasMatch) { continue }
        if ($RawText.IsPresent) {
            $mutatedText = [string](& $Mutation $licenseText $accountStem)
            [System.IO.File]::WriteAllText(
                $licensePath, $mutatedText,
                [System.Text.UTF8Encoding]::new($false))
        } else {
            & $Mutation $licenseState $accountStem | Out-Null
            [System.IO.File]::WriteAllText(
                $licensePath,
                ($licenseState | ConvertTo-Json -Depth 100),
                [System.Text.UTF8Encoding]::new($false))
        }
        $entry.size = (Get-Item -Force -LiteralPath $licensePath).Length
        $entry.sha256 = Get-LowerSha256 $licensePath
        $changed++
    }
    if ($changed -ne 1) {
        throw 'The signed license fixture did not mutate exactly one payload'
    }
    Set-TestSnapshotManifest -SnapshotPath $clone `
        -PrivateKeyPath $PrivateKeyPath -Manifest $manifest
    [pscustomobject]@{ Path = $clone; AccountStem = $accountStem }
}

function Get-TestTreeFingerprint {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string[]]$ExcludedTopLevel = @()
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return 'absent'
    }
    $excluded = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ExcludedTopLevel) { [void]$excluded.Add($name) }
    $entries = @(Get-ChildItem -Force -LiteralPath $Root -Recurse |
        ForEach-Object {
            $relative = [System.IO.Path]::GetRelativePath(
                $Root, $_.FullName).Replace('\', '/')
            $topLevel = $relative.Split('/')[0]
            if (-not $excluded.Contains($topLevel)) {
                [ordered]@{
                    path = $relative
                    kind = $(if ($_.PSIsContainer) { 'directory' } else { 'file' })
                    size = $(if ($_.PSIsContainer) { 0L } else { [int64]$_.Length })
                    sha256 = $(if ($_.PSIsContainer) { $null } else {
                            Get-LowerSha256 $_.FullName
                        })
                }
            }
        } | Where-Object { $null -ne $_ } | Sort-Object path)
    $json = if ($entries.Count -eq 0) {
        '[]'
    } else {
        $entries | ConvertTo-Json -Depth 5 -Compress
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$json)
    ([Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
}

function Get-TestMutableCanaryFingerprint {
    param([Parameter(Mandatory)]$Layout)

    Get-TestTreeFingerprint -Root $Layout.EnvironmentRoot `
        -ExcludedTopLevel @('server-base', 'snapshots', 'builds')
}

function New-TestCombatCanarySourceGateEvidence {
    param([Parameter(Mandatory)]$Layout)

    $evidenceRoot = Join-Path $Layout.EnvironmentRoot 'evidence'
    $gateRoot = Join-Path $evidenceRoot 'source-gate-20260720T064219Z'
    $matrixRoot = Join-Path $gateRoot 'recovery-matrix'
    New-Item -ItemType Directory -Path $matrixRoot -Force | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $gateRoot 'source-gate.json'),
        '{"schemaVersion":1,"canonicalStateMaterialized":false}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $matrixRoot 'manifest.json'),
        '{"schemaVersion":1,"totalFailed":0}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $matrixRoot 'shard-00.stdout.log'),
        'synthetic source gate',
        [System.Text.UTF8Encoding]::new($false))
    $olderEvidence = Join-Path $evidenceRoot 'older-source-evidence'
    New-Item -ItemType Directory -Path $olderEvidence | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $olderEvidence 'receipt.json'),
        '{"schemaVersion":1}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $evidenceRoot 'cleanup-receipt.json'),
        '{"schemaVersion":1,"outcome":"preserved"}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $evidenceRoot 'cleanup-addendum.json'),
        '{"schemaVersion":1,"outcome":"preserved"}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $evidenceRoot `
        -Root $Layout.EnvironmentRoot
    [pscustomobject]@{
        EvidenceRoot = $evidenceRoot
        GateRoot = $gateRoot
        PayloadPath = Join-Path $matrixRoot 'shard-00.stdout.log'
    }
}

function Remove-TestTemporaryTree {
    param([Parameter(Mandatory)][string]$Root)

    $resolvedRoot = [System.IO.Path]::GetFullPath($Root)
    $temporaryPrefix = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $leaf = [System.IO.Path]::GetFileName($resolvedRoot.TrimEnd('\'))
    if (-not $resolvedRoot.StartsWith(
            $temporaryPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $leaf -cnotmatch '^psobb-combat-canary-state-test-[a-f0-9]{32}$') {
        throw 'The combat-canary state test cleanup target is not an exact temporary fixture'
    }
    if (-not (Test-Path -LiteralPath $resolvedRoot)) { return }
    $rootItem = Get-Item -Force -LiteralPath $resolvedRoot -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The combat-canary state test cleanup target is not an ordinary directory'
    }

    $pending = [System.Collections.Generic.Queue[string]]::new()
    $directories = [System.Collections.Generic.List[string]]::new()
    $leaves = [System.Collections.Generic.List[object]]::new()
    $rootPrefix = $resolvedRoot.TrimEnd('\') + '\'
    $pending.Enqueue($resolvedRoot)
    while ($pending.Count -gt 0) {
        $directory = Assert-PathWithinRoot `
            -Path $pending.Dequeue() -Root $resolvedRoot
        $directories.Add($directory)
        foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory `
                    -ErrorAction Stop)) {
            $safeChild = [System.IO.Path]::GetFullPath($child.FullName)
            if (-not $safeChild.StartsWith(
                    $rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'The combat-canary state test cleanup item escaped its fixture'
            }
            if (($child.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $leaves.Add([pscustomobject]@{
                        Path = $safeChild
                        IsDirectory = [bool]$child.PSIsContainer
                    })
            } else {
                [void](Assert-PathWithinRoot `
                        -Path $safeChild -Root $resolvedRoot)
                if ($child.PSIsContainer) {
                    $pending.Enqueue($safeChild)
                } else {
                    $leaves.Add([pscustomobject]@{
                            Path = $safeChild
                            IsDirectory = $false
                        })
                }
            }
        }
    }
    foreach ($leafItem in $leaves) {
        if ([bool]$leafItem.IsDirectory) {
            [System.IO.Directory]::Delete([string]$leafItem.Path, $false)
        } else {
            [System.IO.File]::Delete([string]$leafItem.Path)
        }
    }
    foreach ($directory in @($directories | Sort-Object Length -Descending)) {
        [System.IO.Directory]::Delete($directory, $false)
    }
    if (Test-Path -LiteralPath $resolvedRoot) {
        throw 'The exact temporary combat-canary state fixture cleanup was incomplete'
    }
}

function New-TestSyntheticCombatCanaryHarness {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$FixtureRoot,
        [Parameter(Mandatory)]$CanaryLayout,
        [Parameter(Mandatory)][string]$BaseClientPath,
        [Parameter(Mandatory)][string]$ConfigurationSourcePath,
        [switch]$UseSyntheticSemanticStubs
    )

    $harnessRoot = Assert-PathWithinRoot `
        -Path (Join-Path $FixtureRoot 'synthetic-repository') `
        -Root $FixtureRoot
    $harnessScripts = Join-Path $harnessRoot 'scripts'
    $harnessConfig = Join-Path $harnessRoot 'config'
    $harnessSchemas = Join-Path $harnessConfig 'schemas'
    foreach ($directory in @($harnessScripts, $harnessConfig, $harnessSchemas)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    foreach ($name in @(
            'PSOBB.Common.ps1',
            'PSOBB.RuntimeAclPolicy.ps1',
            'PSOBB.CombatCanary.Common.ps1',
            'Backup-PSOBB.ps1',
            'Restore-PSOBB.ps1',
            'New-PSOBBManifestSignature.ps1',
            'New-PSOBBCombatCanarySnapshot.ps1',
            'Initialize-PSOBBCombatCanary.ps1',
            'Test-PSOBBCombatCanary.ps1',
            'Reset-PSOBBCombatCanaryState.ps1',
            'Test-PSOBBCharacterBuild.ps1',
            'Test-PSOBBTwillsBank.ps1',
            'Get-PSOBBCharacterSummary.ps1')) {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot "scripts\$name") `
            -Destination (Join-Path $harnessScripts $name)
    }
    if ($UseSyntheticSemanticStubs.IsPresent) {
        $characterStub = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$BuildPath
)
$buildHash = (Get-FileHash -LiteralPath $BuildPath -Algorithm SHA256).Hash.ToLowerInvariant()
$build = Get-Content -Raw -LiteralPath $BuildPath | ConvertFrom-Json -Depth 30
[pscustomobject]@{
    Valid = $true
    BuildSha256 = $buildHash
    SlotIndex = 0
    DisplayedLevel = 200
    ProfileId = [string]$build.profileId
    ActiveLoadoutId = [string]$build.activeLoadoutId
    CharacterSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    InventoryItems = 1
    BankItems = 1
    ExactOwnedItems = 2
    ChecksPassed = 1
}
'@
        $bankStub = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$BuildPath,
    [Parameter(Mandatory)][string]$ExpectedBuildSha256
)
$buildHash = (Get-FileHash -LiteralPath $BuildPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($buildHash -cne $ExpectedBuildSha256.ToLowerInvariant()) {
    throw 'Synthetic bank contract pin mismatch'
}
[pscustomobject]@{
    Valid = $true
    BuildSha256 = $buildHash
    Character = 'Twills'
    Class = 'FOnewearl'
    SlotIndex = 0
    Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    Count = 1
    UniqueItemIds = 1
}
'@
        [System.IO.File]::WriteAllText(
            (Join-Path $harnessScripts 'Test-PSOBBCharacterBuild.ps1'),
            $characterStub, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText(
            (Join-Path $harnessScripts 'Test-PSOBBTwillsBank.ps1'),
            $bankStub, [System.Text.UTF8Encoding]::new($false))
    }
    foreach ($name in @(
            'twills-fonewearl-build.json',
            'graphics-profiles.json',
            'client-patch-profiles.json',
            'release-trust.json',
            'sources.lock.json')) {
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot "config\$name") `
            -Destination (Join-Path $harnessConfig $name)
    }
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot `
            'config\schemas\combat-canary-snapshot.schema.json') `
        -Destination (Join-Path $harnessSchemas `
            'combat-canary-snapshot.schema.json')

    $serverBase = [string]$CanaryLayout.ServerBase
    $serverSystem = Join-Path $serverBase 'system'
    New-Item -ItemType Directory -Path $serverSystem -Force | Out-Null
    $serverExecutable = Join-Path $serverBase 'newserv-windows.exe'
    # Transaction tests exercise exact inventory, publication, and rollback.
    # They never execute this synthetic artifact; the separately tested build
    # verifier remains the executable, import, and reproducibility boundary.
    [System.IO.File]::WriteAllBytes(
        $serverExecutable,
        [System.Text.Encoding]::ASCII.GetBytes(
            "synthetic combat-canary transaction fixture`n"))
    Copy-Item -LiteralPath $ConfigurationSourcePath `
        -Destination (Join-Path $serverSystem 'config.json')

    $releaseEntries = @(Get-PSOBBDirectoryManifest -Root $serverBase |
        Where-Object { [string]$_.path -cne 'release-manifest.json' })
    $trackedBuildPath = Join-Path $RepositoryRoot `
        'config\combat-canary-build.json'
    $trackedBuild = Get-Content -Raw -LiteralPath $trackedBuildPath |
        ConvertFrom-Json -Depth 100 -DateKind String
    $releaseManifest = [ordered]@{
        schemaVersion = 1
        profileId = [string]$trackedBuild.profileId
        sourceCommit = [string]$trackedBuild.source.commit
        patchSeriesSha256 = [string]$trackedBuild.patchSeries.sha256
        files = $releaseEntries
    }
    $releaseManifestPath = Join-Path $serverBase 'release-manifest.json'
    [System.IO.File]::WriteAllText(
        $releaseManifestPath,
        ($releaseManifest | ConvertTo-Json -Depth 20),
        [System.Text.UTF8Encoding]::new($false))

    $serverExecutableItem = Get-Item -Force -LiteralPath $serverExecutable
    $releaseManifestItem = Get-Item -Force -LiteralPath $releaseManifestPath
    $trackedBuild.output.executable.size = [int64]$serverExecutableItem.Length
    $trackedBuild.output.executable.sha256 = Get-LowerSha256 $serverExecutable
    $trackedBuild.output.executable.authenticode = 'NotSigned'
    $trackedBuild.output.releaseManifest.size = [int64]$releaseManifestItem.Length
    $trackedBuild.output.releaseManifest.sha256 = `
        Get-LowerSha256 $releaseManifestPath
    $trackedBuild.output.releaseManifest.authenticode = 'NotApplicable'
    $trackedBuild.output.fileCount = [int64]$releaseEntries.Count
    $releaseBytes = [int64]0
    foreach ($entry in $releaseEntries) {
        $releaseBytes += [int64]$entry['size']
    }
    $trackedBuild.output.totalBytes = $releaseBytes
    $buildContractPath = Join-Path $harnessConfig `
        'combat-canary-build.json'
    [System.IO.File]::WriteAllText(
        $buildContractPath,
        ($trackedBuild | ConvertTo-Json -Depth 100),
        [System.Text.UTF8Encoding]::new($false))

    $sourceLockPath = Join-Path $harnessConfig 'sources.lock.json'
    $sourceLock = Get-Content -Raw -LiteralPath $sourceLockPath |
        ConvertFrom-Json -Depth 100 -DateKind String
    $serverComponent = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq 'newserv-combat-canary-build'
        })
    $serverMember = if ($serverComponent.Count -eq 1) {
        @($serverComponent[0].members | Where-Object {
                [string]$_.path -ceq 'release/newserv-windows.exe'
            })
    } else { @() }
    $clientComponent = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq 'tethealla-59nl-english'
        })
    $clientMember = if ($clientComponent.Count -eq 1) {
        @($clientComponent[0].members | Where-Object {
                [string]$_.path -ceq 'Psobb.exe'
            })
    } else { @() }
    if ($serverMember.Count -ne 1 -or $clientMember.Count -ne 1) {
        throw 'Synthetic harness could not resolve its exact source-lock members'
    }
    $serverMember[0].size = [int64]$serverExecutableItem.Length
    $serverMember[0].sha256 = Get-LowerSha256 $serverExecutable
    $serverMember[0].authenticode = 'NotSigned'
    $baseClientItem = Get-Item -Force -LiteralPath $BaseClientPath
    $clientMember[0].size = [int64]$baseClientItem.Length
    $clientMember[0].sha256 = Get-LowerSha256 $BaseClientPath
    $clientMember[0].authenticode = 'NotSigned'
    [System.IO.File]::WriteAllText(
        $sourceLockPath,
        ($sourceLock | ConvertTo-Json -Depth 100),
        [System.Text.UTF8Encoding]::new($false))

    $buildJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $buildContractPath `
        -Root $harnessRoot -MaximumBytes 512KB `
        -RoleLabel 'synthetic combat-canary build contract'
    $build = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $buildJson `
        -RoleLabel 'synthetic combat-canary build contract'
    [void](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $build)
    if (-not (Test-PSOBBDirectoryManifest `
            -Root $serverBase -Files @($releaseEntries + @([pscustomobject]@{
                        path = 'release-manifest.json'
                        size = [int64]$releaseManifestItem.Length
                        sha256 = Get-LowerSha256 $releaseManifestPath
                    })))) {
        throw 'Synthetic server-base exact inventory did not read back'
    }

    [pscustomobject]@{
        RepositoryRoot = $harnessRoot
        ScriptsRoot = $harnessScripts
        BuildContractPath = $buildContractPath
        BuildContractSha256 = Get-LowerSha256 $buildContractPath
        ReleaseManifestPath = $releaseManifestPath
        ReleaseFiles = $releaseEntries.Count
        ReleaseBytes = [int64]$trackedBuild.output.totalBytes
    }
}

function Get-TestSyntheticNewservConfiguration {
    @'
{
  "ServerName": "Synthetic",
  "LocalAddress": "127.0.0.1",
  "ExternalAddress": "127.0.0.1",
  "DNSServerPort": 0,
  "IPStackListen": [],
  "PPPStackListen": [],
  "PPPRawListen": [],
  "HTTPListen": [],
  "RunInteractiveShell": false,
  "CensorCredentials": false,
  "AllowSameAccountConcurrentLogins": true,
  "AllowUnregisteredUsers": true,
  "CheatModeBehavior": "Off",
  "DefaultDropModeV4Normal": "SERVER_SHARED",
  "DefaultDropModeV4Battle": "SERVER_SHARED",
  "DefaultDropModeV4Challenge": "SERVER_SHARED",
  "BBEXPShareMultiplier": 0,
  "EnableSwitchAssistByDefault": false,
  "RareNotificationsEnabledByDefaultV3V4": false,
  "CommandData": "DISABLED",
  "AutoPatches": [],
  "BBRequiredPatches": [],
  "PortConfiguration": {
    "synthetic": [["127.0.0.1", 1], "patch", "patch_server_bb"],
  },

  // Where to listen for IP
}
'@
}

function New-TestSyntheticRecoveryBackup {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$StableLayout,
        [Parameter(Mandatory)][string]$HarnessRoot,
        [Parameter(Mandatory)][string]$InstallationId
    )

    $serverPath = Join-Path $StableLayout.Server 'newserv-windows.exe'
    [System.IO.File]::WriteAllBytes(
        $serverPath,
        [System.Text.Encoding]::ASCII.GetBytes(
            "synthetic stable server fixture`n"))
    $serverItem = Get-Item -Force -LiteralPath $serverPath
    $serverHash = Get-LowerSha256 $serverPath

    $sourceLockPath = Join-Path $HarnessRoot 'config\sources.lock.json'
    $sourceLock = Get-Content -Raw -LiteralPath $sourceLockPath |
        ConvertFrom-Json -Depth 50 -DateKind String
    $stableComponent = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq 'newserv-stable-release'
        })
    if ($stableComponent.Count -ne 1) {
        throw 'Synthetic source lock has no singular Stable component'
    }
    $serverMember = @($stableComponent[0].members | Where-Object {
            [string]$_.path -ceq 'release/newserv-windows.exe'
        })
    if ($serverMember.Count -ne 1) {
        throw 'Synthetic source lock has no singular Stable executable member'
    }
    $serverMember[0].size = [int64]$serverItem.Length
    $serverMember[0].sha256 = $serverHash
    [System.IO.File]::WriteAllText(
        $sourceLockPath, ($sourceLock | ConvertTo-Json -Depth 50),
        [System.Text.UTF8Encoding]::new($false))

    $systemRoot = Join-Path $StableLayout.Server 'system'
    foreach ($directory in @('licenses', 'players', 'teams')) {
        New-Item -ItemType Directory -Path (Join-Path $systemRoot $directory) `
            -Force | Out-Null
    }
    $configurationPath = Join-Path $systemRoot 'config.json'
    [System.IO.File]::WriteAllText(
        $configurationPath,
        (Get-TestSyntheticNewservConfiguration),
        [System.Text.UTF8Encoding]::new($false))
    $account = 'fixtureacct'
    $payloadText = [ordered]@{
        'licenses\fixture-license.json' =
            ('{"FormatVersion":1,"AutoPatchesEnabled":[],' +
                '"BBLicenses":[{"UserName":"fixtureacct",' +
                '"Password":"fixturepass"}]}')
        "players\player_${account}_0.psochar" = 'synthetic character state'
        "players\player_${account}_0.psobank" = 'synthetic bank state'
        "players\system_${account}.psosys" = 'synthetic system state'
        "players\guild_cards_${account}.psocard" = 'synthetic card state'
        "teams\team_${account}.json" = '{}'
    }
    foreach ($entry in $payloadText.GetEnumerator()) {
        [System.IO.File]::WriteAllText(
            (Join-Path $systemRoot ([string]$entry.Key)),
            [string]$entry.Value, [System.Text.UTF8Encoding]::new($false))
    }

    $policyPath = Join-Path $HarnessRoot 'config\client-patch-profiles.json'
    $policyHash = Get-LowerSha256 $policyPath
    $zeroHash = '0' * 64
    $installRecord = [ordered]@{
        schemaVersion = 2
        installationId = $InstallationId
        initializedAtUtc = [DateTime]::UtcNow.ToString('o')
        runtimeRoot = $Layout.Root
        serverVersion = 'synthetic'
        serverArchiveSha256 = $zeroHash
        serverExecutableSha256 = $serverHash
        serverBaseManifestSha256 = $zeroHash
        clientVersion = 'synthetic'
        clientArchiveSha256 = $zeroHash
        baseClientExecutableSha256 = $zeroHash
        baseClientManifestSha256 = $zeroHash
        clientExecutableSha256 = $zeroHash
        rendererVersion = 'synthetic'
        rendererArchiveSha256 = $zeroHash
        rendererWrapperSha256 = $zeroHash
        rendererConfigurationSha256 = $zeroHash
        patchManifestSha256 = $zeroHash
        synchronizedPatchFiles = 0
        clientPatchProfile = 'baseline'
        clientPatchPolicySha256 = $policyHash
        networkScope = 'loopback-only'
    }
    [System.IO.File]::WriteAllText(
        $StableLayout.InstallRecord,
        ($installRecord | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))

    $backupPath = Join-Path $StableLayout.Backups 'state-fixture'
    foreach ($directory in @('system\licenses', 'system\players',
            'system\teams', 'stable')) {
        New-Item -ItemType Directory -Path (Join-Path $backupPath $directory) `
            -Force | Out-Null
    }
    Copy-Item -LiteralPath $configurationPath `
        -Destination (Join-Path $backupPath 'system\config.json')
    foreach ($directory in @('licenses', 'players', 'teams')) {
        foreach ($file in @(Get-ChildItem -File -LiteralPath (
                    Join-Path $systemRoot $directory))) {
            Copy-Item -LiteralPath $file.FullName -Destination (
                Join-Path $backupPath ("system\$directory\" + $file.Name))
        }
    }
    Copy-Item -LiteralPath $StableLayout.InstallRecord `
        -Destination (Join-Path $backupPath 'stable\installation.json')
    $files = @(Get-PSOBBDirectoryManifest -Root $backupPath)
    $configEntry = @($files | Where-Object {
            [string]$_.path -ceq 'system/config.json'
        })
    $installEntry = @($files | Where-Object {
            [string]$_.path -ceq 'stable/installation.json'
        })
    if ($configEntry.Count -ne 1 -or $installEntry.Count -ne 1) {
        throw 'Synthetic recovery backup has incomplete metadata entries'
    }
    $manifest = [ordered]@{
        schemaVersion = 3
        backupId = [Guid]::NewGuid().ToString('D')
        backupKind = 'state'
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        serverExecutable = [ordered]@{
            path = 'newserv-windows.exe'
            sourceLockComponent = 'newserv-stable-release'
            size = [int64]$serverItem.Length
            sha256 = $serverHash
        }
        clientPatchState = [ordered]@{
            profile = 'baseline'
            policySha256 = $policyHash
            configPath = 'system/config.json'
            configSha256 = [string]$configEntry[0].sha256
            installationPath = 'stable/installation.json'
            installationSha256 = [string]$installEntry[0].sha256
            installationId = $InstallationId
        }
        stateRoots = @(
            [ordered]@{ path = 'system/config.json'; kind = 'file' }
            [ordered]@{ path = 'system/licenses'; kind = 'directory' }
            [ordered]@{ path = 'system/players'; kind = 'directory' }
            [ordered]@{ path = 'system/teams'; kind = 'directory' }
            [ordered]@{ path = 'stable/installation.json'; kind = 'file' }
        )
        files = $files
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $backupPath 'manifest.json'),
        ($manifest | ConvertTo-Json -Depth 12),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $backupPath -Root $StableLayout.Backups
    [pscustomobject]@{
        Path = $backupPath
        Files = $files.Count
        ServerSha256 = $serverHash
    }
}

function Test-RealPublishedCombatCanaryPackage {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)]$CanaryLayout
    )

    $buildPath = Join-Path $RepositoryRoot 'config\combat-canary-build.json'
    $buildJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $buildPath -Root $RepositoryRoot -MaximumBytes 512KB `
        -RoleLabel 'published combat-canary build contract'
    $build = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $buildJson -RoleLabel 'published combat-canary build contract'
    [void](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $build)
    $manifestPath = Join-Path $CanaryLayout.ServerBase 'release-manifest.json'
    $manifestItem = Get-Item -Force -LiteralPath $manifestPath
    if ($manifestItem.Length -ne [int64]$build.output.releaseManifest.size -or
        (Get-LowerSha256 $manifestPath) -cne
            [string]$build.output.releaseManifest.sha256) {
        throw 'Published release manifest differs from the frozen build contract'
    }
    $manifestJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $manifestPath -Root $CanaryLayout.ServerBase `
        -MaximumBytes 16MB -RoleLabel 'published release manifest'
    $manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $manifestJson -RoleLabel 'published release manifest'
    Assert-PSOBBCombatCanaryExactProperties -Value $manifest `
        -RoleLabel 'published release manifest' `
        -Expected @('schemaVersion', 'profileId', 'sourceCommit',
            'patchSeriesSha256', 'files') | Out-Null
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.profileId -cne [string]$build.profileId -or
        [string]$manifest.sourceCommit -cne [string]$build.source.commit -or
        [string]$manifest.patchSeriesSha256 -cne
            [string]$build.patchSeries.sha256) {
        throw 'Published release manifest is not bound to the frozen contract'
    }
    $paths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $bytes = [int64]0
    foreach ($entry in @($manifest.files)) {
        Assert-PSOBBCombatCanaryExactProperties -Value $entry `
            -RoleLabel 'published release file' `
            -Expected @('path', 'size', 'sha256') | Out-Null
        $relative = [string]$entry.path
        if ($relative -cnotmatch
                '^(?!/)(?!.*(?:^|/)\.\.?(/|$))[^:\\]+$' -or
            $relative -ceq 'release-manifest.json' -or
            -not $paths.Add($relative) -or
            [int64]$entry.size -lt 0 -or
            [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'Published release manifest contains an invalid inventory path'
        }
        $file = Assert-PathWithinRoot `
            -Path (Join-Path $CanaryLayout.ServerBase (
                $relative.Replace('/', '\'))) -Root $CanaryLayout.ServerBase
        $item = Get-Item -Force -LiteralPath $file
        if ($item.PSIsContainer -or $item.Length -ne [int64]$entry.size -or
            (Get-LowerSha256 $file) -cne [string]$entry.sha256) {
            throw 'Published release file differs from its exact manifest'
        }
        $bytes += [int64]$entry.size
    }
    $actual = @(Get-ChildItem -Force -LiteralPath $CanaryLayout.ServerBase `
        -Recurse -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath(
                $CanaryLayout.ServerBase, $_.FullName).Replace('\', '/')
        } | Where-Object { $_ -cne 'release-manifest.json' })
    $executable = Join-Path $CanaryLayout.ServerBase 'newserv-windows.exe'
    if ($paths.Count -ne [int]$build.output.fileCount -or
        $bytes -ne [int64]$build.output.totalBytes -or
        $actual.Count -ne $paths.Count -or
        @($actual | Where-Object { -not $paths.Contains($_) }).Count -ne 0 -or
        (Get-Item -Force -LiteralPath $executable).Length -ne
            [int64]$build.output.executable.size -or
        (Get-LowerSha256 $executable) -cne
            [string]$build.output.executable.sha256) {
        throw 'Published package does not match its exact frozen inventory'
    }
    [pscustomobject]@{
        Valid = $true
        Files = $paths.Count
        Bytes = $bytes
        BuildContractSha256 = Get-LowerSha256 $buildPath
        ReleaseManifestSha256 = Get-LowerSha256 $manifestPath
    }
}

function Test-RealPublishedPSOBBClient {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)]$StableLayout
    )

    $approved = Get-PSOBBCombatCanaryApprovedClientIdentity `
        -RepositoryRoot $RepositoryRoot
    $manifestJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $StableLayout.BaseClientManifest `
        -Root $StableLayout.EnvironmentRoot -MaximumBytes 16MB `
        -RoleLabel 'real Stable base-client manifest'
    $manifest = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $manifestJson -RoleLabel 'real Stable base-client manifest'
    [void](Assert-PSOBBCombatCanaryExactProperties -Value $manifest `
            -RoleLabel 'real Stable base-client manifest' `
            -Expected @('schemaVersion', 'sourceArchiveSha256',
                'generatedAtUtc', 'files'))
    foreach ($entry in @($manifest.files)) {
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $entry `
                -RoleLabel 'real Stable base-client file' `
                -Expected @('path', 'size', 'sha256'))
    }
    $sourcesJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath (Join-Path $RepositoryRoot 'config\sources.lock.json') `
        -Root $RepositoryRoot -MaximumBytes 16MB `
        -RoleLabel 'tracked source lock'
    $sources = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $sourcesJson -RoleLabel 'tracked source lock'
    $clientComponents = @($sources.components | Where-Object {
            [string]$_.id -ceq 'tethealla-59nl-english'
        })
    $generatedAt = [DateTimeOffset]::MinValue
    $clientPath = Join-Path $StableLayout.BaseClient 'Psobb.exe'
    if ([int]$manifest.schemaVersion -ne 1 -or
        $clientComponents.Count -ne 1 -or
        [string]$manifest.sourceArchiveSha256 -cne
            [string]$clientComponents[0].sha256 -or
        -not [DateTimeOffset]::TryParse(
            [string]$manifest.generatedAtUtc, [ref]$generatedAt) -or
        -not (Test-PSOBBDirectoryManifest `
            -Root $StableLayout.BaseClient -Files @($manifest.files)) -or
        (Get-Item -Force -LiteralPath $clientPath).Length -ne
            [int64]$approved.Size -or
        (Get-LowerSha256 $clientPath) -cne [string]$approved.Sha256) {
        throw 'Real Stable base client differs from its exact 59NL binding'
    }
    [pscustomobject]@{
        Valid = $true
        Files = @($manifest.files).Count
        ClientSha256 = [string]$approved.Sha256
    }
}

function New-TestAccountPathMismatch {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SnapshotsRoot,
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$ReplacementName
    )

    $clone = New-TestSnapshotClone -Source $Source -SnapshotsRoot $SnapshotsRoot
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $clone 'manifest.json') |
        ConvertFrom-Json -Depth 20 -DateKind String
    $entries = @($manifest.files | Where-Object { [string]$_.role -ceq $Role })
    if ($entries.Count -ne 1) { throw 'Account mismatch fixture role is not singular' }
    $oldRelative = [string]$entries[0].path
    $newRelative = ([System.IO.Path]::GetDirectoryName(
            $oldRelative.Replace('/', '\')).Replace('\', '/') + '/' + $ReplacementName)
    $oldPath = Join-Path $clone ($oldRelative.Replace('/', '\'))
    $newPath = Join-Path $clone ($newRelative.Replace('/', '\'))
    Move-Item -LiteralPath $oldPath -Destination $newPath
    $entries[0].path = $newRelative
    Set-TestSnapshotManifest -SnapshotPath $clone `
        -PrivateKeyPath $PrivateKeyPath -Manifest $manifest
    $clone
}

function Test-SnapshotSchema {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][string]$SchemaPath
    )

    try {
        [bool](Test-Json -LiteralPath (Join-Path $SnapshotPath 'manifest.json') `
                -SchemaFile $SchemaPath -ErrorAction Stop)
    } catch {
        $false
    }
}

if ($Mode -eq 'RealPublishedReadOnly') {
    Start-TestSection 'RealPublishedReadOnly'
    $canonicalLayout = Get-PSOBBLayout -RuntimeRoot (
        Join-Path $repositoryRoot 'PSOBB-Runtime')
    $canonicalStable = Get-PSOBBServerEnvironmentLayout `
        -Layout $canonicalLayout -Environment Stable
    $canonicalCanary = Get-PSOBBServerEnvironmentLayout `
        -Layout $canonicalLayout -Environment CombatCanary
    $stableSystemRoot = Join-Path $canonicalStable.Server 'system'
    $stableBefore = @(Get-PSOBBDirectoryManifest -Root $stableSystemRoot)
    $stableWriteBefore = (@(
            Get-Item -Force -LiteralPath $stableSystemRoot) + @(
            Get-ChildItem -Force -LiteralPath $stableSystemRoot -Recurse) |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1).LastWriteTimeUtc.ToString('o')
    $published = Test-RealPublishedCombatCanaryPackage `
        -RepositoryRoot $repositoryRoot -CanaryLayout $canonicalCanary
    $publishedClient = Test-RealPublishedPSOBBClient `
        -RepositoryRoot $repositoryRoot -StableLayout $canonicalStable
    $stableAfter = @(Get-PSOBBDirectoryManifest -Root $stableSystemRoot)
    $stableWriteAfter = (@(
            Get-Item -Force -LiteralPath $stableSystemRoot) + @(
            Get-ChildItem -Force -LiteralPath $stableSystemRoot -Recurse) |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1).LastWriteTimeUtc.ToString('o')
    Add-Result 'real published package matches its frozen exact inventory' `
        ([bool]$published.Valid) "files=$($published.Files)"
    Add-Result 'real Stable base client matches its exact 59NL binding' `
        ([bool]$publishedClient.Valid) "files=$($publishedClient.Files)"
    Add-Result 'targeted canonical Stable state remains unchanged' (
        (Test-PSOBBManifestEntriesEqual -Left $stableBefore -Right $stableAfter) -and
        $stableWriteBefore -ceq $stableWriteAfter) `
        "files=$($stableAfter.Count)"
    Complete-TestSection
    $overallStopwatch.Stop()
    $results | Format-Table -AutoSize
    $sectionTimings | Format-Table -AutoSize
    $failed = @($results | Where-Object { -not $_.Passed })
    if ($failed.Count -ne 0) {
        throw "$($failed.Count) real published combat-canary test(s) failed"
    }
    [pscustomobject]@{
        Valid = $true
        Tests = $results.Count
        Passed = $results.Count
        Mode = $Mode
        DurationMilliseconds = [int64][Math]::Round(
            $overallStopwatch.Elapsed.TotalMilliseconds)
        Sections = @($sectionTimings)
    }
    return
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-combat-canary-state-test-' + [Guid]::NewGuid().ToString('N'))
Start-TestSection 'FixtureSetup'
$canonicalLayout = $null
$canonicalStableBefore = @()
if ($Mode -eq 'All') {
    $canonicalRuntime = Join-Path $repositoryRoot 'PSOBB-Runtime'
    $canonicalLayout = Get-PSOBBLayout -RuntimeRoot $canonicalRuntime
    $canonicalStableBefore = @(Get-PSOBBDirectoryManifest `
        -Root (Join-Path $canonicalLayout.Server 'system'))
}

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $layout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    $stable = Get-PSOBBServerEnvironmentLayout -Layout $layout -Environment Stable
    $canary = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment CombatCanary
    foreach ($directory in @(
            $stable.Server,
            $stable.Backups,
            $stable.Secrets,
            $stable.EnvironmentRoot)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $fixtureInstallationId = [Guid]::NewGuid().ToString('D')
    $marker = [ordered]@{
        schemaVersion = 1
        installationId = $fixtureInstallationId
        runtimeRoot = $layout.Root
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    [System.IO.File]::WriteAllText(
        $layout.RuntimeMarker,
        ($marker | ConvertTo-Json -Depth 3),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $layout.RuntimeMarker
    [System.IO.File]::WriteAllText(
        (Join-Path $layout.Root '.combat-canary-state-test.json'),
        ([ordered]@{
                schemaVersion = 1
                purpose = 'combat-canary-state-transaction-test'
                installationId = $fixtureInstallationId
            } | ConvertTo-Json -Depth 3),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path (
        Join-Path $layout.Root '.combat-canary-state-test.json')

    if ($Mode -eq 'All') {
    $serverSource = Join-Path $canonicalLayout.Server 'newserv-windows.exe'
    Copy-Item -LiteralPath $serverSource -Destination (
        Join-Path $stable.Server 'newserv-windows.exe')
    $sourceBackup = Get-ChildItem -Force -LiteralPath $canonicalLayout.Backups `
        -Directory -Filter 'state-*' |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $sourceBackup) {
        throw 'A canonical schema-3 state backup is required for fixture construction'
    }
    $fixtureBackup = Join-Path $stable.Backups 'state-fixture'
    Copy-Item -LiteralPath $sourceBackup.FullName -Destination $fixtureBackup -Recurse
    $backupManifestPath = Join-Path $fixtureBackup 'manifest.json'
    $backupManifest = Get-Content -Raw -LiteralPath $backupManifestPath |
        ConvertFrom-Json -Depth 20 -DateKind String
    $fixtureInstallPath = Join-Path $fixtureBackup 'stable\installation.json'
    $fixtureInstall = Get-Content -Raw -LiteralPath $fixtureInstallPath |
        ConvertFrom-Json -Depth 20 -DateKind String
    $fixturePolicyHash = Get-LowerSha256 (
        Join-Path $repositoryRoot 'config\client-patch-profiles.json')
    $fixtureInstall.installationId = $fixtureInstallationId
    $installEntries = @($backupManifest.files | Where-Object {
            [string]$_.path -ceq 'stable/installation.json'
        })
    if ($installEntries.Count -ne 1) {
        throw 'The fixture backup does not bind exactly one installation record'
    }

    $stalePolicyHash = '0' * 64
    $fixtureInstall.clientPatchPolicySha256 = $stalePolicyHash
    [System.IO.File]::WriteAllText(
        $fixtureInstallPath,
        ($fixtureInstall | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $fixtureInstallItem = Get-Item -Force -LiteralPath $fixtureInstallPath
    $fixtureInstallHash = Get-LowerSha256 $fixtureInstallPath
    $installEntries[0].size = [int64]$fixtureInstallItem.Length
    $installEntries[0].sha256 = $fixtureInstallHash
    $backupManifest.clientPatchState.installationId = $fixtureInstallationId
    $backupManifest.clientPatchState.installationSha256 = $fixtureInstallHash
    $backupManifest.clientPatchState.policySha256 = $stalePolicyHash
    $backupManifest.createdAtUtc = [DateTime]::UtcNow.ToString('o')
    [System.IO.File]::WriteAllText(
        $backupManifestPath,
        ($backupManifest | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $stalePolicyRejected = $false
    try {
        & (Join-Path $scriptsRoot 'Restore-PSOBB.ps1') `
            -RuntimeRoot $layout.Root -BackupPath $fixtureBackup `
            -ValidateOnly | Out-Null
    } catch {
        $stalePolicyRejected = $_.Exception.Message -ceq
            'Runtime installation record client-patch policy hash does not match the current pinned policy'
    }
    Add-Result 'schema-3 backup with a stale policy binding fails closed' `
        $stalePolicyRejected 'production Restore validator rejected before snapshot use'

    $fixtureInstall.clientPatchPolicySha256 = $fixturePolicyHash
    [System.IO.File]::WriteAllText(
        $fixtureInstallPath,
        ($fixtureInstall | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    $fixtureInstallItem = Get-Item -Force -LiteralPath $fixtureInstallPath
    $fixtureInstallHash = Get-LowerSha256 $fixtureInstallPath
    $installEntries[0].size = [int64]$fixtureInstallItem.Length
    $installEntries[0].sha256 = $fixtureInstallHash
    $backupManifest.clientPatchState.installationSha256 = $fixtureInstallHash
    $backupManifest.clientPatchState.policySha256 = $fixturePolicyHash
    [System.IO.File]::WriteAllText(
        $backupManifestPath,
        ($backupManifest | ConvertTo-Json -Depth 10),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $fixtureBackup -Root $stable.Backups
    }

    $key = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $privateKeyPath = Join-Path $stable.Secrets `
            'local-acceptance-signing-private.pem'
        $publicKeyPath = Join-Path $stable.EnvironmentRoot 'release-public-key.pem'
        [System.IO.File]::WriteAllText(
            $privateKeyPath,
            $key.ExportPkcs8PrivateKeyPem(),
            [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText(
            $publicKeyPath,
            $key.ExportSubjectPublicKeyInfoPem(),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $privateKeyPath
        $spkiFingerprint = ([Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData(
                    $key.ExportSubjectPublicKeyInfo()))).ToLowerInvariant()
    } finally {
        $key.Dispose()
    }
    New-Item -ItemType Directory -Path $stable.BaseClient -Force | Out-Null
    [System.IO.File]::WriteAllBytes(
        (Join-Path $stable.BaseClient 'Psobb.exe'),
        [System.Text.Encoding]::ASCII.GetBytes(
            "synthetic exact-client transaction fixture`n"))
    [System.IO.File]::WriteAllText(
        $stable.BaseClientManifest,
        ([ordered]@{
                schemaVersion = 1
                files = @(Get-PSOBBDirectoryManifest -Root $stable.BaseClient)
            } | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
    $contractPath = Join-Path $repositoryRoot 'config\twills-fonewearl-build.json'
    $contractHash = Get-LowerSha256 $contractPath
    $stableBefore = Get-PSOBBDirectoryManifest -Root $stable.EnvironmentRoot
    Complete-TestSection

    Start-TestSection 'BoundedStateReaders'
    $boundedRoot = Join-Path $temporaryRoot 'bounded-state-readers'
    New-Item -ItemType Directory -Path $boundedRoot | Out-Null
    $boundedJsonPath = Join-Path $boundedRoot 'valid.json'
    [System.IO.File]::WriteAllText(
        $boundedJsonPath,
        '{"schemaVersion":1,"value":"bounded-ok"}',
        [System.Text.UTF8Encoding]::new($false))
    $boundedJsonItem = Get-Item -Force -LiteralPath $boundedJsonPath
    $boundedJsonHash = Get-LowerSha256 $boundedJsonPath
    $boundedSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $boundedJsonPath -Root $boundedRoot -MaximumBytes 4KB `
        -ExpectedLength ([int64]$boundedJsonItem.Length) `
        -ExpectedSha256 $boundedJsonHash -PassThruSnapshot `
        -RoleLabel 'bounded state reader fixture'
    Add-Result 'bounded reader parses and identifies one held file snapshot' (
        [int64]$boundedSnapshot.Value.schemaVersion.Value -eq 1 -and
        [string]$boundedSnapshot.Value.value.Value -ceq 'bounded-ok' -and
        [int64]$boundedSnapshot.Length -eq [int64]$boundedJsonItem.Length -and
        [string]$boundedSnapshot.Sha256 -ceq $boundedJsonHash) `
        "bytes=$($boundedSnapshot.Length)"

    $oversizeSecret = 'oversize-sensitive-fixture-value'
    $oversizePath = Join-Path $boundedRoot 'oversize.json'
    [System.IO.File]::WriteAllText(
        $oversizePath,
        ('{"value":"' + $oversizeSecret + ('x' * 2048) + '"}'),
        [System.Text.UTF8Encoding]::new($false))
    Assert-RejectedWithoutText `
        -Name 'bounded reader rejects an oversized state document before parsing' `
        -ForbiddenText $oversizeSecret `
        -Action {
            Read-PSOBBCombatCanaryStrictJsonObject `
                -LiteralPath $oversizePath -Root $boundedRoot `
                -MaximumBytes 1KB -RoleLabel 'oversize state fixture'
        }

    $mutationPath = Join-Path $boundedRoot 'mutation.json'
    [System.IO.File]::WriteAllText(
        $mutationPath,
        '{"schemaVersion":1,"value":"original-sensitive-value"}',
        [System.Text.UTF8Encoding]::new($false))
    $mutationHash = Get-LowerSha256 $mutationPath
    $mutationHook = {
        param([string]$Path)
        [System.IO.File]::WriteAllText(
            $Path,
            '{"schemaVersion":1,"value":"replacement-sensitive-value"}',
            [System.Text.UTF8Encoding]::new($false))
    }.GetNewClosure()
    $mutationRejected = $false
    try {
        Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $mutationPath -Root $boundedRoot -MaximumBytes 4KB `
            -ExpectedSha256 $mutationHash `
            -InternalTestAfterIdentity $mutationHook `
            -RoleLabel 'mutation seam state fixture' | Out-Null
    } catch {
        $mutationRejected = $true
    }
    Add-Result 'bounded reader denies mutation between identity and parse' (
        $mutationRejected -and
        (Get-LowerSha256 $mutationPath) -ceq $mutationHash) `
        'write denied while the exact read lease remained held'

    $sensitivePath = Join-Path $boundedRoot 'sensitive.bin'
    [System.IO.File]::WriteAllText(
        $sensitivePath,
        'sensitive-buffer-fixture',
        [System.Text.UTF8Encoding]::new($false))
    $sensitiveSnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $sensitivePath -Root $boundedRoot -MaximumBytes 1KB `
        -RoleLabel 'sensitive buffer fixture' `
        -Consumer {
            param([byte[]]$Bytes)
            [pscustomobject]@{ Reference = $Bytes }
        }
    Add-Result 'bounded reader clears consumed sensitive bytes' (
        @($sensitiveSnapshot.Value.Reference | Where-Object { $_ -ne 0 }).Count -eq 0) `
        "bytes=$($sensitiveSnapshot.Length)"

    $reparseParent = Join-Path $boundedRoot 'reparse-parent'
    $reparseDirectory = Join-Path $reparseParent 'current'
    $reparseSavedDirectory = Join-Path $reparseParent 'saved'
    $reparseOutside = Join-Path $boundedRoot 'reparse-outside'
    New-Item -ItemType Directory -Path $reparseDirectory, $reparseOutside `
        -Force | Out-Null
    $reparsePath = Join-Path $reparseDirectory 'document.json'
    [System.IO.File]::WriteAllText(
        $reparsePath,
        '{"schemaVersion":1,"value":"inside"}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $reparseOutside 'document.json'),
        '{"schemaVersion":1,"value":"outside"}',
        [System.Text.UTF8Encoding]::new($false))
    $reparseHook = {
        param([string]$Path)
        Move-Item -LiteralPath $reparseDirectory `
            -Destination $reparseSavedDirectory
        New-Item -ItemType Junction -Path $reparseDirectory `
            -Target $reparseOutside | Out-Null
    }.GetNewClosure()
    $reparseRejected = $false
    try {
        Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $reparsePath -Root $boundedRoot -MaximumBytes 4KB `
            -InternalTestAfterInitialValidation $reparseHook `
            -RoleLabel 'reparse seam state fixture' | Out-Null
    } catch {
        $reparseRejected = $true
    } finally {
        if (Test-Path -LiteralPath $reparseDirectory) {
            $reparseItem = Get-Item -Force -LiteralPath $reparseDirectory
            if (($reparseItem.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Remove-Item -LiteralPath $reparseDirectory -Force
            }
        }
        if (Test-Path -LiteralPath $reparseSavedDirectory) {
            Move-Item -LiteralPath $reparseSavedDirectory `
                -Destination $reparseDirectory
        }
    }
    Add-Result 'bounded reader rejects a reparse swap before opening state' `
        $reparseRejected 'ordinary-path identity was revalidated after the seam'

    $hardLinkSource = Join-Path $boundedRoot 'hard-link-source.json'
    $hardLinkPath = Join-Path $boundedRoot 'hard-link-alias.json'
    [System.IO.File]::WriteAllText(
        $hardLinkSource, '{"schemaVersion":1}',
        [System.Text.UTF8Encoding]::new($false))
    New-Item -ItemType HardLink -Path $hardLinkPath `
        -Target $hardLinkSource | Out-Null
    Assert-Rejected -Name 'bounded reader rejects multiply linked state files' `
        -Action {
            Read-PSOBBCombatCanaryStrictJsonObject `
                -LiteralPath $hardLinkSource -Root $boundedRoot `
                -MaximumBytes 1KB -RoleLabel 'hard-link state fixture'
        }

    $junctionOutside = Join-Path $temporaryRoot 'junction-state-outside'
    $junctionPath = Join-Path $boundedRoot 'junction-state-parent'
    New-Item -ItemType Directory -Path $junctionOutside | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $junctionOutside 'document.json'),
        '{"schemaVersion":1}', [System.Text.UTF8Encoding]::new($false))
    New-Item -ItemType Junction -Path $junctionPath `
        -Target $junctionOutside | Out-Null
    Assert-Rejected -Name 'bounded reader rejects a present parent junction' `
        -Action {
            Read-PSOBBCombatCanaryStrictJsonObject `
                -LiteralPath (Join-Path $junctionPath 'document.json') `
                -Root $boundedRoot -MaximumBytes 1KB `
                -RoleLabel 'parent-junction state fixture'
        }
    [System.IO.Directory]::Delete($junctionPath, $false)

    $finalSwapPath = Join-Path $boundedRoot 'final-swap.json'
    $finalSwapSaved = Join-Path $boundedRoot 'final-swap.saved'
    [System.IO.File]::WriteAllText(
        $finalSwapPath, '{"schemaVersion":1,"value":"original"}',
        [System.Text.UTF8Encoding]::new($false))
    $finalSwapHash = Get-LowerSha256 $finalSwapPath
    $finalSwapHook = {
        param([string]$Path)
        [System.IO.File]::Move($Path, $finalSwapSaved, $false)
    }.GetNewClosure()
    $finalSwapRejected = $false
    try {
        Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $finalSwapPath -Root $boundedRoot `
            -MaximumBytes 1KB -ExpectedSha256 $finalSwapHash `
            -InternalTestAfterIdentity $finalSwapHook `
            -RoleLabel 'final swap state fixture' | Out-Null
    } catch {
        $finalSwapRejected = $true
    }
    Add-Result 'bounded reader blocks final-file replacement while leased' (
        $finalSwapRejected -and
        (Get-LowerSha256 $finalSwapPath) -ceq $finalSwapHash -and
        -not (Test-Path -LiteralPath $finalSwapSaved)) `
        'rename denied before replacement could be published'

    $oneBytePath = Join-Path $boundedRoot 'one-byte-zero.bin'
    [System.IO.File]::WriteAllBytes($oneBytePath, [byte[]]@(0))
    $oneByteSnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $oneBytePath -Root $boundedRoot -MaximumBytes 1 `
        -RoleLabel 'one-byte sensitive buffer fixture' `
        -Consumer {
            param([byte[]]$Bytes)
            $Bytes[0] = 0x7F
            [pscustomobject]@{ Reference = $Bytes }
        }
    Add-Result 'bounded reader clears a one-byte zero-origin buffer' (
        $oneByteSnapshot.Value.Reference.Length -eq 1 -and
        $oneByteSnapshot.Value.Reference[0] -eq 0) `
        'consumer mutation was cleared in finally'

    $copySourceRoot = Join-Path $boundedRoot 'copy-source'
    $copyDestinationRoot = Join-Path $boundedRoot 'copy-destination'
    New-Item -ItemType Directory -Path $copySourceRoot,
        $copyDestinationRoot | Out-Null
    $copySource = Join-Path $copySourceRoot 'state.bin'
    $copyDestination = Join-Path $copyDestinationRoot 'state.bin'
    [System.IO.File]::WriteAllBytes(
        $copySource, [System.Text.Encoding]::ASCII.GetBytes('bounded-copy'))
    $copySourceItem = Get-Item -Force -LiteralPath $copySource
    $copySourceHash = Get-LowerSha256 $copySource
    $copyResult = Copy-PSOBBCombatCanaryBoundedFileSnapshot `
        -Source $copySource -SourceRoot $copySourceRoot `
        -Destination $copyDestination -DestinationRoot $copyDestinationRoot `
        -MaximumBytes 1KB -ExpectedLength $copySourceItem.Length `
        -ExpectedSha256 $copySourceHash -RoleLabel 'bounded copy fixture'
    Add-Result 'bounded copy publishes one exact no-clobber file' (
        $copyResult.Sha256 -ceq $copySourceHash -and
        (Get-LowerSha256 $copyDestination) -ceq $copySourceHash) `
        "bytes=$($copyResult.Length)"
    Assert-Rejected -Name 'bounded copy rejects destination clobbering' `
        -Action {
            Copy-PSOBBCombatCanaryBoundedFileSnapshot `
                -Source $copySource -SourceRoot $copySourceRoot `
                -Destination $copyDestination `
                -DestinationRoot $copyDestinationRoot `
                -MaximumBytes 1KB -ExpectedLength $copySourceItem.Length `
                -ExpectedSha256 $copySourceHash `
                -RoleLabel 'bounded copy clobber fixture'
        }
    $oversizeCopyDestination = Join-Path $copyDestinationRoot 'oversize.bin'
    Assert-Rejected -Name 'bounded copy rejects oversize before destination publication' `
        -Action {
            Copy-PSOBBCombatCanaryBoundedFileSnapshot `
                -Source $copySource -SourceRoot $copySourceRoot `
                -Destination $oversizeCopyDestination `
                -DestinationRoot $copyDestinationRoot `
                -MaximumBytes 4 -ExpectedLength $copySourceItem.Length `
                -ExpectedSha256 $copySourceHash `
                -RoleLabel 'oversize bounded copy fixture'
        }
    Add-Result 'oversize bounded copy leaves no destination' (
        -not (Test-Path -LiteralPath $oversizeCopyDestination)) `
        'publication did not begin'
    $swapCopySource = Join-Path $copySourceRoot 'swap-source.bin'
    $swapCopySaved = Join-Path $copySourceRoot 'swap-source.saved'
    $swapCopyDestination = Join-Path $copyDestinationRoot 'swap-source.bin'
    [System.IO.File]::WriteAllBytes(
        $swapCopySource,
        [System.Text.Encoding]::ASCII.GetBytes('swap-copy-source'))
    $swapCopyItem = Get-Item -Force -LiteralPath $swapCopySource
    $swapCopyHash = Get-LowerSha256 $swapCopySource
    $swapCopyHook = {
        param([string]$Path)
        [System.IO.File]::Move($Path, $swapCopySaved, $false)
    }.GetNewClosure()
    Assert-Rejected -Name 'bounded copy blocks source replacement while leased' `
        -Action {
            Copy-PSOBBCombatCanaryBoundedFileSnapshot `
                -Source $swapCopySource -SourceRoot $copySourceRoot `
                -Destination $swapCopyDestination `
                -DestinationRoot $copyDestinationRoot `
                -MaximumBytes 1KB -ExpectedLength $swapCopyItem.Length `
                -ExpectedSha256 $swapCopyHash `
                -RoleLabel 'source-swap bounded copy fixture' `
                -InternalTestAfterSourceLease $swapCopyHook
        }
    Add-Result 'source-swap bounded copy publishes nothing and preserves source' (
        -not (Test-Path -LiteralPath $swapCopyDestination) -and
        -not (Test-Path -LiteralPath $swapCopySaved) -and
        (Get-LowerSha256 $swapCopySource) -ceq $swapCopyHash) `
        'source identity stayed fixed under the held lease'

    foreach ($resourceProbe in @(
            [pscustomobject]@{
                Name = 'character count'
                Text = '{"value":"' + ('x' * (512KB)) + '"}'
                Role = 'snapshot manifest'
            },
            [pscustomobject]@{
                Name = 'depth'
                Text = ('[' * 34) + '0' + (']' * 34)
                Role = 'snapshot manifest'
            },
            [pscustomobject]@{
                Name = 'token count'
                Text = '[' + ((@('0') * 17000) -join ',') + ']'
                Role = 'snapshot manifest'
            })) {
        Assert-Rejected -Name ("strict JSON preflight enforces $($resourceProbe.Name)") `
            -Action {
                Read-PSOBBCombatCanaryStrictJsonObject `
                    -Text $resourceProbe.Text -RoleLabel $resourceProbe.Role
            }
    }
    $normalizedPolicy = Get-PSOBBCombatCanaryJsonResourcePolicy `
        -RoleLabel 'snapshot manifest'
    foreach ($budgetProbe in @(
            [pscustomobject]@{
                Name = 'token budget'
                Property = 'Tokens'
                Limit = [int]$normalizedPolicy.MaximumTokens
                Action = 'token'
            },
            [pscustomobject]@{
                Name = 'property budget'
                Property = 'Properties'
                Limit = [int]$normalizedPolicy.MaximumProperties
                Action = 'property'
            },
            [pscustomobject]@{
                Name = 'item budget'
                Property = 'Items'
                Limit = [int]$normalizedPolicy.MaximumItems
                Action = 'item'
            })) {
        $budget = [pscustomobject]@{
            Tokens = 0
            TokenNormalizedCharacters = [int64]0
            Properties = 0
            Items = 0
            NormalizedWork = [int64]0
        }
        $budget.($budgetProbe.Property) = $budgetProbe.Limit
        Assert-Rejected -Name ("strict JSON preflight enforces $($budgetProbe.Name)") `
            -Action {
                if ($budgetProbe.Action -ceq 'token') {
                    Add-PSOBBCombatCanaryJsonTokenBudget `
                        -Budget $budget -Policy $normalizedPolicy `
                        -NormalizedCharacters 0
                } elseif ($budgetProbe.Action -ceq 'property') {
                    Add-PSOBBCombatCanaryJsonPropertyBudget `
                        -Budget $budget -Policy $normalizedPolicy
                } else {
                    Add-PSOBBCombatCanaryJsonItemBudget `
                        -Budget $budget -Policy $normalizedPolicy
                }
            }
    }
    $normalizedBudget = [pscustomobject]@{
        Tokens = 0
        TokenNormalizedCharacters = [int64]0
        Properties = 0
        Items = 0
        NormalizedWork = [int64]$normalizedPolicy.MaximumNormalizedWork
    }
    Assert-Rejected -Name 'strict JSON preflight enforces normalized-output work' `
        -Action {
            Add-PSOBBCombatCanaryJsonNormalizedWork `
                -Budget $normalizedBudget -Policy $normalizedPolicy `
                -Characters 1
        }

    $invalidCredentialClears = [System.Collections.Generic.List[object]]::new()
    $invalidCredentialClearHook = {
        param([string]$Label, [byte[]]$Bytes)
        $invalidCredentialClears.Add([pscustomobject]@{
                Label = $Label
                Length = $Bytes.Length
                Cleared = @($Bytes | Where-Object { $_ -ne 0 }).Count -eq 0
            })
    }.GetNewClosure()
    $invalidSecondCredentialText =
        '{"FormatVersion":1,"BBLicenses":[' +
        '{"UserName":"legacyuser","Password":"first"},' +
        '{"UserName":"abcdefghijklmnopq","Password":"\u0000"}]}'
    $invalidSecondCredentialState = Read-PSOBBCombatCanaryStrictJsonObject `
        -Text $invalidSecondCredentialText `
        -RoleLabel 'credential cleanup fixture'
    Assert-Rejected -Name 'credential parser rejects an invalid second credential' `
        -Action {
            Get-PSOBBCombatCanaryBBLicenseIdentities `
                -State $invalidSecondCredentialState `
                -RawText $invalidSecondCredentialText `
                -ExpectedAccountName 'legacyuser' `
                -RoleLabel 'credential cleanup fixture' `
                -InternalTestAfterBufferClear $invalidCredentialClearHook
        }
    Add-Result 'invalid second credential clears accepted and pending buffers' (
        $invalidCredentialClears.Count -ge 4 -and
        @($invalidCredentialClears | Where-Object { -not $_.Cleared }).Count -eq 0 -and
        @($invalidCredentialClears | Where-Object {
                $_.Label -ceq 'phosg-work' -and $_.Length -gt 0
            }).Count -ge 4 -and
        @($invalidCredentialClears | Where-Object {
                $_.Label -ceq 'pending-password' -and $_.Length -eq 1
            }).Count -eq 1) `
        "buffers=$($invalidCredentialClears.Count)"

    $zeroCredentialClears = [System.Collections.Generic.List[object]]::new()
    $zeroCredentialClearHook = {
        param([string]$Label, [byte[]]$Bytes)
        $zeroCredentialClears.Add([pscustomobject]@{
                Label = $Label
                Length = $Bytes.Length
                Cleared = @($Bytes | Where-Object { $_ -ne 0 }).Count -eq 0
            })
    }.GetNewClosure()
    $zeroCredentialText =
        '{"FormatVersion":1,"BBLicenses":[' +
        '{"UserName":"legacyuser","Password":"\u0000"}]}'
    $zeroCredentialState = Read-PSOBBCombatCanaryStrictJsonObject `
        -Text $zeroCredentialText -RoleLabel 'zero credential fixture'
    $zeroCredentialIdentities = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
            -State $zeroCredentialState -RawText $zeroCredentialText `
            -ExpectedAccountName 'legacyuser' `
            -RoleLabel 'zero credential fixture' `
            -InternalTestAfterBufferClear $zeroCredentialClearHook)
    Add-Result 'credential parser clears a one-byte zero password buffer' (
        $zeroCredentialIdentities.Count -eq 1 -and
        @($zeroCredentialClears | Where-Object {
                $_.Label -ceq 'credential-password' -and
                $_.Length -eq 1 -and $_.Cleared
            }).Count -eq 1 -and
        @($zeroCredentialClears | Where-Object {
                $_.Label -ceq 'phosg-work' -and
                $_.Length -gt 0 -and $_.Cleared
            }).Count -ge 2 -and
        @($zeroCredentialClears | Where-Object { -not $_.Cleared }).Count -eq 0) `
        "buffers=$($zeroCredentialClears.Count)"
    Complete-TestSection

    if ($Mode -eq 'All') {
        Start-TestSection 'ContractAndParser'
    $strictLoaderValid = $false
    try {
        $strictObject = Read-PSOBBCombatCanaryStrictJsonObject `
            -Text '{"schemaVersion":1}' -RoleLabel 'strict loader fixture'
        $strictLoaderValid = $strictObject -is [Newtonsoft.Json.Linq.JObject] -and
            @($strictObject.Properties()).Count -eq 1
    } catch {}
    Add-Result 'shared strict JObject loader accepts one exact object' `
        $strictLoaderValid 'one root object'
    foreach ($validJson in @(
            [pscustomobject]@{
                Name = 'phosg line comments including trailing comments'
                Text = ('{// leading' + "`n" + '"schemaVersion":1// value' +
                    "`n" + '}// trailing')
                Expected = 1
            },
            [pscustomobject]@{
                Name = 'phosg trailing object comma'
                Text = '{"schemaVersion":1,}'
                Expected = 1
            },
            [pscustomobject]@{
                Name = 'phosg lowercase hexadecimal integer'
                Text = '{"schemaVersion":0x7F}'
                Expected = 127
            },
            [pscustomobject]@{
                Name = 'quoted extension-like text remains string data'
                Text = '{"schemaVersion":1,"text":"// /* '' undefined 0x10"}'
                Expected = 1
            })) {
        $compatible = $false
        try {
            $compatibleObject = Read-PSOBBCombatCanaryStrictJsonObject `
                -Text $validJson.Text -RoleLabel 'strict loader fixture'
            $compatible = [int64]$compatibleObject.schemaVersion.Value -eq
                [int64]$validJson.Expected
        } catch {}
        Add-Result ("shared strict JObject loader accepts $($validJson.Name)") `
            $compatible 'phosg-compatible lexical preflight'
    }
    $phosgByteStringsAccepted = $false
    try {
        $byteStringObject = Read-PSOBBCombatCanaryStrictJsonObject `
            -Text '{"\u00FF":"\u00FF"}' `
            -RoleLabel 'strict loader fixture'
        $phosgByteStringsAccepted = @($byteStringObject.Properties()).Count -eq 1
    } catch {}
    Add-Result 'shared strict JObject loader accepts phosg byte escapes in keys and values' `
        $phosgByteStringsAccepted 'ordinary noncredential byte string'

    $byteDistinctKeysAccepted = $false
    try {
        $byteDistinctObject = Read-PSOBBCombatCanaryStrictJsonObject `
            -Text '{"\u00E9":1,"é":2}' `
            -RoleLabel 'strict loader fixture'
        $byteDistinctKeysAccepted = @($byteDistinctObject.Properties()).Count -eq 2
    } catch {}
    Add-Result 'shared strict JObject loader preserves phosg byte-distinct keys' `
        $byteDistinctKeysAccepted 'does not use Newtonsoft Unicode key identity'

    foreach ($invalidJson in @(
            [pscustomobject]@{
                Name = 'duplicate decoded key'
                Text = '{"schemaVersion":1,"\u0073chemaVersion":2}'
            },
            [pscustomobject]@{
                Name = 'trailing object'
                Text = '{"schemaVersion":1} {"other":2}'
            },
            [pscustomobject]@{
                Name = 'nonobject root'
                Text = '[]'
            },
            [pscustomobject]@{
                Name = 'block comment'
                Text = '{/* unsupported */"schemaVersion":1}'
            },
            [pscustomobject]@{
                Name = 'single-quoted key'
                Text = "{'schemaVersion':1}"
            },
            [pscustomobject]@{
                Name = 'single-quoted value'
                Text = '{"schemaVersion":1,"text":''value''}'
            },
            [pscustomobject]@{
                Name = 'unquoted key'
                Text = '{schemaVersion:1}'
            },
            [pscustomobject]@{
                Name = 'undefined token'
                Text = '{"schemaVersion":1,"value":undefined}'
            },
            [pscustomobject]@{
                Name = 'non-byte unicode escape in ordinary value'
                Text = '{"value":"\u0100"}'
            },
            [pscustomobject]@{
                Name = 'non-byte unicode escape in ordinary key'
                Text = '{"\u0100":1}'
            },
            [pscustomobject]@{
                Name = 'lone surrogate escape in ordinary value'
                Text = '{"value":"\uD800"}'
            },
            [pscustomobject]@{
                Name = 'lone surrogate escape in ordinary key'
                Text = '{"\uD800":1}'
            },
            [pscustomobject]@{
                Name = 'surrogate pair escape in ordinary value'
                Text = '{"value":"\uD83D\uDE00"}'
            },
            [pscustomobject]@{
                Name = 'surrogate pair escape in ordinary key'
                Text = '{"\uD83D\uDE00":1}'
            },
            [pscustomobject]@{
                Name = 'phosg byte-equivalent object keys'
                Text = '{"\u00C3\u00A9":1,"é":2}'
            })) {
        $strictRejected = $false
        try {
            Read-PSOBBCombatCanaryStrictJsonObject -Text $invalidJson.Text `
                -RoleLabel 'strict loader fixture' | Out-Null
        } catch {
            $strictRejected = $_.Exception.Message -ceq
                'The strict loader fixture is not a valid strict JSON object'
        }
        Add-Result ("shared strict JObject loader rejects $($invalidJson.Name)") `
            $strictRejected 'fixed role-only rejection'
    }

    $trackedBuildShapeAccepted = $false
    $trackedBuildText = [System.IO.File]::ReadAllText((
            Join-Path $repositoryRoot 'config\combat-canary-build.json'))
    try {
        $trackedBuild = $trackedBuildText |
            ConvertFrom-Json -Depth 100 -DateKind String
        $trackedBuildShapeAccepted =
            [bool](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $trackedBuild)
    } catch {}
    Add-Result 'shared build-contract verifier accepts the frozen contract' `
        $trackedBuildShapeAccepted 'all frozen top-level and nested fields present'

    foreach ($buildShapeMutation in @(
            [pscustomobject]@{
                Name = 'missing signatureVerification'
                Mutation = { param($value)
                    $value.PSObject.Properties.Remove('signatureVerification')
                }
            },
            [pscustomobject]@{
                Name = 'extra top-level field'
                Mutation = { param($value)
                    $value | Add-Member -NotePropertyName unexpected `
                        -NotePropertyValue $true
                }
            },
            [pscustomobject]@{
                Name = 'missing keyring readOnly field'
                Mutation = { param($value)
                    $value.signatureVerification.keyring.PSObject.Properties.Remove(
                        'readOnly')
                }
            },
            [pscustomobject]@{
                Name = 'extra keyring field'
                Mutation = { param($value)
                    $value.signatureVerification.keyring | Add-Member `
                        -NotePropertyName unexpected -NotePropertyValue $true
                }
            },
            [pscustomobject]@{
                Name = 'missing native manifest schema hash'
                Mutation = { param($value)
                    $value.toolchain.nativeExecutionManifest.PSObject.Properties.Remove(
                        'schemaSha256')
                }
            },
            [pscustomobject]@{
                Name = 'missing objdump tool role'
                Mutation = { param($value)
                    $value.toolchain.tools = @($value.toolchain.tools |
                        Where-Object { [string]$_.id -cne 'objdump' })
                }
            },
            [pscustomobject]@{
                Name = 'objdump tool in the wrong schema position'
                Mutation = { param($value)
                    $objdump = $value.toolchain.tools[3]
                    $value.toolchain.tools[3] = $value.toolchain.tools[4]
                    $value.toolchain.tools[4] = $objdump
                }
            },
            [pscustomobject]@{
                Name = 'duplicate objdump tool role'
                Mutation = { param($value)
                    $value.toolchain.tools[4].id = 'objdump'
                }
            })) {
        $buildShapeRejected = $false
        try {
            $mutatedBuild = $trackedBuildText |
                ConvertFrom-Json -Depth 100 -DateKind String
            & $buildShapeMutation.Mutation $mutatedBuild
            Assert-PSOBBCombatCanaryBuildContractShape `
                -Build $mutatedBuild | Out-Null
        } catch {
            $buildShapeRejected = $_.Exception.Message -ceq
                'The combat-canary build contract does not have the exact combat-canary schema'
        }
        Add-Result ("shared build-contract verifier rejects $($buildShapeMutation.Name)") `
            $buildShapeRejected 'fixed exact-schema rejection'
    }

    foreach ($buildIdentityMutation in @(
            [pscustomobject]@{
                Name = 'wrong signature tool identity'
                Mutation = { param($value)
                    $value.signatureVerification.toolId = 'gpg'
                }
            },
            [pscustomobject]@{
                Name = 'writable signature keyring'
                Mutation = { param($value)
                    $value.signatureVerification.keyring.readOnly = $false
                }
            },
            [pscustomobject]@{
                Name = 'string signature keyring policy'
                Mutation = { param($value)
                    $value.signatureVerification.keyring.readOnly = 'true'
                }
            },
            [pscustomobject]@{
                Name = 'wrong output root'
                Mutation = { param($value)
                    $value.output.rootRelative = 'combat-canary/server-base/other'
                }
            },
            [pscustomobject]@{
                Name = 'wrong objdump command identity'
                Mutation = { param($value)
                    $value.toolchain.tools[3].command = 'other'
                }
            },
            [pscustomobject]@{
                Name = 'wrong objdump payload path identity'
                Mutation = { param($value)
                    $value.toolchain.tools[3].relativePath = 'bin\objdump.exe'
                }
            },
            [pscustomobject]@{
                Name = 'wrong objdump version probe identity'
                Mutation = { param($value)
                    $value.toolchain.tools[3].versionArguments = @('-h')
                }
            },
            [pscustomobject]@{
                Name = 'wrong objdump version identity'
                Mutation = { param($value)
                    $value.toolchain.tools[3].version = 'other version'
                }
            },
            [pscustomobject]@{
                Name = 'wrong objdump executable size identity'
                Mutation = { param($value)
                    $value.toolchain.tools[3].executableSize++
                }
            },
            [pscustomobject]@{
                Name = 'wrong objdump executable hash identity'
                Mutation = { param($value)
                    $value.toolchain.tools[3].sha256 = '0' * 64
                }
            })) {
        $buildIdentityRejected = $false
        try {
            $mutatedBuild = $trackedBuildText |
                ConvertFrom-Json -Depth 100 -DateKind String
            & $buildIdentityMutation.Mutation $mutatedBuild
            Assert-PSOBBCombatCanaryBuildContractIdentity `
                -Build $mutatedBuild | Out-Null
        } catch {
            $buildIdentityRejected = $_.Exception.Message -ceq
                'The combat-canary build contract has an invalid fixed identity'
        }
        Add-Result ("shared build-contract verifier rejects $($buildIdentityMutation.Name)") `
            $buildIdentityRejected 'fixed identity rejection'
    }

    $verifierTokens = $null
    $verifierParseErrors = $null
    $verifierAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1'),
        [ref]$verifierTokens, [ref]$verifierParseErrors)
    $verifierIdentityCalls = @($verifierAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq
                    'Assert-PSOBBCombatCanaryBuildContractIdentity'
            }, $true))
    Add-Result 'Installed verifier consumes the shared frozen build identity gate' (
        @($verifierParseErrors).Count -eq 0 -and
        $verifierIdentityCalls.Count -eq 1) `
        'one exact shared-helper consumer and no stale schema copy'

    $licenseSemanticsExact = $true
    try {
        $currentText = (
            '{"FormatVersion":1,"AutoPatchesEnabled":[],"BBLicenses":[' +
            '{"UserName":"sixteenbyteuser1","Password":"sixteenbytepass1"}]}')
        $currentState = Read-PSOBBCombatCanaryStrictJsonObject -Text $currentText `
            -RoleLabel 'current BB license fixture'
        $currentIdentities = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
                -State $currentState -RawText $currentText `
                -ExpectedAccountName 'sixteenbyteuser1' `
                -RoleLabel 'current BB license fixture')
        $legacyText = (
            '{"BBUsername":"legacyuser","BBPassword":' +
            '"legacy-password-longer-than-sixteen"}')
        $legacyState = Read-PSOBBCombatCanaryStrictJsonObject -Text $legacyText `
            -RoleLabel 'legacy BB license fixture'
        $legacyIdentities = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
                -State $legacyState -RawText $legacyText `
                -ExpectedAccountName 'legacyuser' `
                -RoleLabel 'legacy BB license fixture')
        $partialLegacyText = '{"FormatVersion":0,"BBUsername":"legacyuser"}'
        $partialLegacyState = Read-PSOBBCombatCanaryStrictJsonObject `
            -Text $partialLegacyText `
            -RoleLabel 'partial legacy BB license fixture'
        $partialLegacyIdentities = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
                -State $partialLegacyState -RawText $partialLegacyText `
                -ExpectedAccountName 'legacyuser' `
                -RoleLabel 'partial legacy BB license fixture')
        $licenseSemanticsExact = $currentIdentities.Count -eq 1 -and
            [bool]$currentIdentities[0].MatchesExpectedAccount -and
            $legacyIdentities.Count -eq 1 -and
            [bool]$legacyIdentities[0].MatchesExpectedAccount -and
            $partialLegacyIdentities.Count -eq 0
    } catch {
        $licenseSemanticsExact = $false
    }
    Add-Result 'BB license parser preserves exact current and legacy semantics' `
        $licenseSemanticsExact 'current byte limits and legacy insertion rule'

    foreach ($invalidLicense in @(
            [pscustomobject]@{
                Name = 'zero version with current shape'
                Text = '{"FormatVersion":0,"BBLicenses":[]}'
            },
            [pscustomobject]@{
                Name = 'positive version with legacy shape'
                Text = '{"FormatVersion":1,"BBUsername":"legacyuser","BBPassword":"x"}'
            },
            [pscustomobject]@{
                Name = 'nonempty account autopatch list'
                Text = '{"FormatVersion":1,"AutoPatchesEnabled":["Palette"],"BBLicenses":[]}'
            },
            [pscustomobject]@{
                Name = 'FormatVersion one above Int64 maximum'
                Text = '{"FormatVersion":9223372036854775808,"BBLicenses":[]}'
            },
            [pscustomobject]@{
                Name = 'FormatVersion at two to the sixty-fourth power'
                Text = '{"FormatVersion":18446744073709551616,"BBLicenses":[]}'
            },
            [pscustomobject]@{
                Name = 'negative FormatVersion'
                Text = '{"FormatVersion":-1,"BBLicenses":[]}'
            })) {
        $licenseRejected = $false
        try {
            $invalidState = Read-PSOBBCombatCanaryStrictJsonObject `
                -Text $invalidLicense.Text `
                -RoleLabel 'invalid BB license fixture'
            Get-PSOBBCombatCanaryBBLicenseIdentities -State $invalidState `
                -RawText $invalidLicense.Text -ExpectedAccountName 'legacyuser' `
                -RoleLabel 'invalid BB license fixture' | Out-Null
        } catch {
            $licenseRejected = $_.Exception.Message -ceq
                'The invalid BB license fixture has an invalid BB credential shape'
        }
        Add-Result ("BB license parser rejects $($invalidLicense.Name)") `
            $licenseRejected 'fixed credential-shape rejection'
    }

    foreach ($validVersion in @(
            [pscustomobject]@{
                Name = 'Int64 maximum FormatVersion'
                Text = '{"FormatVersion":9223372036854775807,"BBLicenses":[]}'
            },
            [pscustomobject]@{
                Name = 'zero FormatVersion with legacy shape'
                Text = '{"FormatVersion":0}'
            },
            [pscustomobject]@{
                Name = 'positive FormatVersion with current shape'
                Text = '{"FormatVersion":1,"BBLicenses":[]}'
            })) {
        $validVersionAccepted = $false
        try {
            $validVersionState = Read-PSOBBCombatCanaryStrictJsonObject `
                -Text $validVersion.Text -RoleLabel 'valid BB license fixture'
            $validVersionAccepted = @(
                Get-PSOBBCombatCanaryBBLicenseIdentities `
                    -State $validVersionState -RawText $validVersion.Text `
                    -ExpectedAccountName 'legacyuser' `
                    -RoleLabel 'valid BB license fixture').Count -eq 0
        } catch {}
        Add-Result ("BB license parser accepts $($validVersion.Name)") `
            $validVersionAccepted 'bounded integer version semantics'
    }

    foreach ($credentialProbe in @(
            [pscustomobject]@{
                Name = 'two escaped phosg bytes'
                Password = '\u00C3\u00A9' + ('a' * 14)
                Accepted = $true
            },
            [pscustomobject]@{
                Name = 'exact sixteen escaped phosg bytes'
                Password = '\u00FF' * 16
                Accepted = $true
            },
            [pscustomobject]@{
                Name = 'seventeen escaped phosg bytes'
                Password = '\u00FF' * 17
                Accepted = $false
            },
            [pscustomobject]@{
                Name = 'exact sixteen raw UTF-8 bytes'
                Password = 'é' * 8
                Accepted = $true
            },
            [pscustomobject]@{
                Name = 'seventeen raw UTF-8 bytes'
                Password = ('é' * 8) + 'a'
                Accepted = $false
            },
            [pscustomobject]@{
                Name = 'non-byte unicode escape'
                Password = '\u0100'
                Accepted = $false
            },
            [pscustomobject]@{
                Name = 'high surrogate escape'
                Password = '\uD800'
                Accepted = $false
            },
            [pscustomobject]@{
                Name = 'surrogate-pair escape'
                Password = '\uD83D\uDE00'
                Accepted = $false
            })) {
        $credentialText = (
            '{"FormatVersion":1,"BBLicenses":[{"UserName":"legacyuser",' +
            '"Password":"' + $credentialProbe.Password + '"}]}')
        $accepted = $false
        try {
            $credentialState = Read-PSOBBCombatCanaryStrictJsonObject `
                -Text $credentialText -RoleLabel 'credential byte fixture'
            $accepted = @(Get-PSOBBCombatCanaryBBLicenseIdentities `
                    -State $credentialState -RawText $credentialText `
                    -ExpectedAccountName 'legacyuser' `
                    -RoleLabel 'credential byte fixture').Count -eq 1
        } catch {
            $accepted = $false
        }
        Add-Result ("BB license parser handles $($credentialProbe.Name)") `
            ($accepted -eq [bool]$credentialProbe.Accepted) `
            'raw byte count checked without credential output'
    }
        Complete-TestSection
    }

    Start-TestSection 'SyntheticExactInventory'
    $syntheticConfigSource = Join-Path $temporaryRoot `
        'synthetic-newserv-config.json'
    [System.IO.File]::WriteAllText(
        $syntheticConfigSource,
        (Get-TestSyntheticNewservConfiguration),
        [System.Text.UTF8Encoding]::new($false))
    $syntheticHarness = New-TestSyntheticCombatCanaryHarness `
        -RepositoryRoot $repositoryRoot -FixtureRoot $temporaryRoot `
        -CanaryLayout $canary `
        -BaseClientPath (Join-Path $stable.BaseClient 'Psobb.exe') `
        -ConfigurationSourcePath $syntheticConfigSource `
        -UseSyntheticSemanticStubs:($Mode -in @(
                'SyntheticTransactions', 'VerifierScopeRegression'))
    $transactionScriptsRoot = [string]$syntheticHarness.ScriptsRoot
    $buildContractHash = [string]$syntheticHarness.BuildContractSha256
    Add-Result 'synthetic transaction package has an exact minimal inventory' (
        [int]$syntheticHarness.ReleaseFiles -eq 2 -and
        [int64]$syntheticHarness.ReleaseBytes -gt 0) `
        "files=$($syntheticHarness.ReleaseFiles)"
    foreach ($transactionScriptName in @(
            'New-PSOBBCombatCanarySnapshot.ps1',
            'Initialize-PSOBBCombatCanary.ps1',
            'Reset-PSOBBCombatCanaryState.ps1',
            'Test-PSOBBCombatCanary.ps1',
            'Restore-PSOBB.ps1')) {
        Add-Result ("synthetic harness keeps $transactionScriptName exact") (
            (Get-LowerSha256 (Join-Path $scriptsRoot $transactionScriptName)) `
                -ceq (Get-LowerSha256 (
                    Join-Path $transactionScriptsRoot $transactionScriptName))) `
            'source and harness hashes match'
    }
    if ($Mode -ne 'All') {
        $syntheticBackup = New-TestSyntheticRecoveryBackup `
            -Layout $layout -StableLayout $stable `
            -HarnessRoot ([string]$syntheticHarness.RepositoryRoot) `
            -InstallationId $fixtureInstallationId
        $fixtureBackup = [string]$syntheticBackup.Path
        $syntheticBackupValidation = & (Join-Path $transactionScriptsRoot `
            'Restore-PSOBB.ps1') -RuntimeRoot $layout.Root `
            -BackupPath $fixtureBackup -ValidateOnly
        Add-Result 'real Restore validator accepts the synthetic schema-3 backup' (
            [int]$syntheticBackupValidation.FileCount -eq
                [int]$syntheticBackup.Files -and
            [string]$syntheticBackupValidation.BackupPath -ieq $fixtureBackup) `
            "files=$($syntheticBackup.Files)"
        $stableBefore = Get-PSOBBDirectoryManifest -Root $stable.EnvironmentRoot
    }
    Complete-TestSection

    Start-TestSection 'SnapshotSeed'
    $snapshotScriptsRoot = if ($Mode -eq 'All') {
        $scriptsRoot
    } else {
        $transactionScriptsRoot
    }
    $whatIfOutput = & (Join-Path $snapshotScriptsRoot `
        'New-PSOBBCombatCanarySnapshot.ps1') `
        -RuntimeRoot $layout.Root -StableBackupPath $fixtureBackup `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint `
        -MaximumBackupAgeMinutes 15 -WhatIf -Confirm:$false
    $whatIfClean = -not (Test-Path -LiteralPath $canary.Snapshots) -and
        (Test-PSOBBManifestEntriesEqual `
            -Left $stableBefore `
            -Right (Get-PSOBBDirectoryManifest -Root $stable.EnvironmentRoot))
    Add-Result 'explicit-backup WhatIf is mutation-free' $whatIfClean `
        "whatIf=$([bool]$whatIfOutput.WhatIf)"

    $publishCollisionRejected = $false
    try {
        & (Join-Path $snapshotScriptsRoot `
            'New-PSOBBCombatCanarySnapshot.ps1') `
            -RuntimeRoot $layout.Root -StableBackupPath $fixtureBackup `
            -ExpectedTwillsContractSha256 $contractHash `
            -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint `
            -MaximumBackupAgeMinutes 15 -Confirm:$false `
            -InternalTestCreatePublishCollision `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $publishCollisionRejected = $_.Exception.Message -ceq
            'No-clobber snapshot publication failed'
    }
    $collisionSnapshots = @(Get-ChildItem -Force -LiteralPath $canary.Snapshots `
        -Directory | Where-Object {
            Test-Path -LiteralPath (Join-Path $_.FullName '.unexpected-preserve') `
                -PathType Leaf
        })
    $publishCollisionPreserved = $publishCollisionRejected -and
        $collisionSnapshots.Count -eq 1 -and
        [System.IO.File]::ReadAllText((Join-Path $collisionSnapshots[0].FullName `
                    '.unexpected-preserve')) -ceq 'preserve' -and
        @(Get-ChildItem -Force -LiteralPath $collisionSnapshots[0].FullName).Count -eq 1 -and
        @(Get-ChildItem -Force -LiteralPath $canary.Snapshots -Directory `
            -Filter '*.partial-*').Count -eq 0
    Add-Result 'snapshot publication collision is preserved without nesting or debris' `
        $publishCollisionPreserved 'unexpected destination retained byte-for-byte'
    if ($collisionSnapshots.Count -eq 1) {
        Remove-Item -LiteralPath $collisionSnapshots[0].FullName -Recurse -Force
    }

    $fixtureBackupManifest = Get-Content -Raw -LiteralPath (
        Join-Path $fixtureBackup 'manifest.json') |
        ConvertFrom-Json -Depth 20 -DateKind String
    $fixtureTeamEntry = @($fixtureBackupManifest.files | Where-Object {
            [string]$_.path -cmatch '^system/teams/'
        })
    if ($fixtureTeamEntry.Count -ne 1) {
        throw 'The snapshot copy-fault fixture has no singular team payload'
    }
    $fixtureTeamPath = Join-Path $fixtureBackup (
        ([string]$fixtureTeamEntry[0].path).Replace('/', '\'))
    $fixtureTeamBytes = [System.IO.File]::ReadAllBytes($fixtureTeamPath)
    $snapshotOversizeHook = {
        [System.IO.File]::WriteAllBytes(
            $fixtureTeamPath, [byte[]]::new((1MB) + 1))
    }.GetNewClosure()
    $snapshotOversizeRejected = $false
    try {
        try {
            & (Join-Path $snapshotScriptsRoot `
                'New-PSOBBCombatCanarySnapshot.ps1') `
                -RuntimeRoot $layout.Root -StableBackupPath $fixtureBackup `
                -ExpectedTwillsContractSha256 $contractHash `
                -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint `
                -MaximumBackupAgeMinutes 15 -Confirm:$false `
                -InternalTestBeforePayloadCopy $snapshotOversizeHook `
                -InternalTestFaultToken $fixtureInstallationId | Out-Null
        } catch {
            $snapshotOversizeRejected = $true
        }
    } finally {
        [System.IO.File]::WriteAllBytes($fixtureTeamPath, $fixtureTeamBytes)
        Set-PSOBBProtectedTreeAcl -Path $fixtureBackup -Root $stable.Backups
    }
    Add-Result 'snapshot producer rejects post-validation oversize source state' (
        $snapshotOversizeRejected -and
        @(Get-ChildItem -Force -LiteralPath $canary.Snapshots `
            -Directory -Filter '*.partial-*').Count -eq 0) `
        'bounded copy rejected before payload publication'

    $snapshotSwapSaved = $fixtureTeamPath + '.swap-attempt'
    $snapshotSwapHook = {
        param([string]$Path)
        if ($Path -ieq $fixtureTeamPath) {
            [System.IO.File]::Move($Path, $snapshotSwapSaved, $false)
        }
    }.GetNewClosure()
    $snapshotSwapRejected = $false
    try {
        & (Join-Path $snapshotScriptsRoot `
            'New-PSOBBCombatCanarySnapshot.ps1') `
            -RuntimeRoot $layout.Root -StableBackupPath $fixtureBackup `
            -ExpectedTwillsContractSha256 $contractHash `
            -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint `
            -MaximumBackupAgeMinutes 15 -Confirm:$false `
            -InternalTestAfterPayloadSourceLease $snapshotSwapHook `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $snapshotSwapRejected = $true
    }
    Add-Result 'snapshot producer blocks source swap under its copy lease' (
        $snapshotSwapRejected -and
        -not (Test-Path -LiteralPath $snapshotSwapSaved) -and
        (Get-LowerSha256 $fixtureTeamPath) -ceq
            [string]$fixtureTeamEntry[0].sha256 -and
        @(Get-ChildItem -Force -LiteralPath $canary.Snapshots `
            -Directory -Filter '*.partial-*').Count -eq 0) `
        'held source and transaction cleanup remained exact'

    $snapshotSubstitution = [pscustomobject]@{
        Published = ''
        Saved = ''
    }
    $snapshotSubstitutionHook = {
        param([string]$Path)
        $snapshotSubstitution.Published = $Path
        $snapshotSubstitution.Saved = $Path + '.owned-evidence'
        [System.IO.Directory]::Move($Path, $snapshotSubstitution.Saved)
        [void][System.IO.Directory]::CreateDirectory($Path)
        [System.IO.File]::WriteAllText(
            (Join-Path $Path '.replacement-evidence'), 'replacement',
            [System.Text.UTF8Encoding]::new($false))
    }.GetNewClosure()
    $snapshotSubstitutionRejected = $false
    try {
        & (Join-Path $snapshotScriptsRoot `
            'New-PSOBBCombatCanarySnapshot.ps1') `
            -RuntimeRoot $layout.Root -StableBackupPath $fixtureBackup `
            -ExpectedTwillsContractSha256 $contractHash `
            -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint `
            -MaximumBackupAgeMinutes 15 -Confirm:$false `
            -InternalTestAfterPublishMove $snapshotSubstitutionHook `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $snapshotSubstitutionRejected = $_.Exception.Message -ceq
            'Published snapshot rollback retained an identity-mismatched tree as evidence'
    }
    $snapshotSubstitutionRetained = $snapshotSubstitutionRejected -and
        (Test-Path -LiteralPath $snapshotSubstitution.Published -PathType Container) -and
        (Test-Path -LiteralPath $snapshotSubstitution.Saved -PathType Container)
    Add-Result 'snapshot rollback retains post-move substitution evidence' `
        $snapshotSubstitutionRetained 'both identities retained without broad deletion'
    foreach ($path in @($snapshotSubstitution.Published,
            $snapshotSubstitution.Saved)) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and
            (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }

    $created = & (Join-Path $snapshotScriptsRoot `
        'New-PSOBBCombatCanarySnapshot.ps1') `
        -RuntimeRoot $layout.Root -StableBackupPath $fixtureBackup `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint `
        -MaximumBackupAgeMinutes 15 -Confirm:$false
    Complete-TestSection
    if ($Mode -eq 'All') {
        Start-TestSection 'SnapshotVerification'
    $validFirst = & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $layout.Root -Target Snapshot `
        -SnapshotPath $created.SnapshotPath `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
    $validSecond = & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $layout.Root -Target Snapshot `
        -SnapshotPath $created.SnapshotPath `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
    Add-Result 'valid signed snapshot verifies idempotently' (
        [bool]$validFirst.Valid -and [bool]$validSecond.Valid -and
        [string]$validFirst.ManifestSha256 -ceq [string]$validSecond.ManifestSha256) `
        "stateFiles=$($validFirst.StateFiles)"
    $validManifest = Get-Content -Raw -LiteralPath (
        Join-Path $created.SnapshotPath 'manifest.json') |
        ConvertFrom-Json -Depth 100 -DateKind String
    $validCharacterEntry = @($validManifest.files | Where-Object {
            [string]$_.role -ceq 'twills-character'
        })
    if ($validCharacterEntry.Count -ne 1 -or
        [System.IO.Path]::GetFileName([string]$validCharacterEntry[0].path) `
            -cnotmatch '^player_(?<account>[a-z][a-z0-9_-]{2,15})_0\.psochar$') {
        throw 'The valid snapshot fixture cannot derive its protected identity stem'
    }
    $protectedAccountStem = [string]$Matches.account
    $snapshotSchemaPath = Join-Path $repositoryRoot `
        'config\schemas\combat-canary-snapshot.schema.json'
    Add-Result 'valid signed snapshot satisfies its Draft 2020-12 schema' (
        Test-SnapshotSchema -SnapshotPath $created.SnapshotPath `
            -SchemaPath $snapshotSchemaPath) 'schema-valid'

    $verifyParameters = @{
        RuntimeRoot = $layout.Root
        Target = 'Snapshot'
        ExpectedTwillsContractSha256 = $contractHash
        ExpectedSigningPublicKeySpkiSha256 = $spkiFingerprint
    }
    Assert-RejectedWithoutText -Name `
        'out-of-root snapshot error does not expose protected identity text' `
        -ForbiddenText $protectedAccountStem -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath (
                Join-Path $temporaryRoot ($protectedAccountStem + '-outside'))
    }

    $signatureTamper = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $signatureManifestPath = Join-Path $signatureTamper 'manifest.json'
    $signatureText = [System.IO.File]::ReadAllText($signatureManifestPath)
    [System.IO.File]::WriteAllText(
        $signatureManifestPath,
        $signatureText.Replace('"schemaVersion": 1', '"schemaVersion": 2'),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $signatureTamper -Root $canary.Snapshots
    Assert-Rejected -Name 'manifest signature tamper is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $signatureTamper
    }

    foreach ($duplicateKey in @('"schemaVersion"', '"\u0073chemaVersion"')) {
        $duplicateManifest = New-TestSnapshotClone `
            -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
        $duplicateManifestPath = Join-Path $duplicateManifest 'manifest.json'
        $duplicateManifestText = [regex]::new('^\s*\{').Replace(
            [System.IO.File]::ReadAllText($duplicateManifestPath),
            '{' + $duplicateKey + ':1,', 1)
        Set-TestSnapshotManifestText -SnapshotPath $duplicateManifest `
            -PrivateKeyPath $privateKeyPath -Text $duplicateManifestText
        Assert-Rejected -Name 'signed duplicate snapshot manifest key is rejected' `
            -Action {
            & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
                @verifyParameters -SnapshotPath $duplicateManifest
        }
    }

    $payloadTamper = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $payloadManifest = Get-Content -Raw -LiteralPath (
        Join-Path $payloadTamper 'manifest.json') | ConvertFrom-Json -Depth 20
    $characterEntry = @($payloadManifest.files | Where-Object role -eq 'twills-character')[0]
    $characterPath = Join-Path $payloadTamper (([string]$characterEntry.path).Replace('/', '\'))
    $bytes = [System.IO.File]::ReadAllBytes($characterPath)
    $bytes[0x100] = $bytes[0x100] -bxor 1
    [System.IO.File]::WriteAllBytes($characterPath, $bytes)
    Set-PSOBBProtectedTreeAcl -Path $payloadTamper -Root $canary.Snapshots
    Assert-Rejected -Name 'payload tamper is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $payloadTamper
    }

    $missing = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $missingManifest = Get-Content -Raw -LiteralPath (Join-Path $missing 'manifest.json') |
        ConvertFrom-Json -Depth 20
    $teamEntry = @($missingManifest.files | Where-Object role -eq 'team-state')[0]
    Remove-Item -LiteralPath (Join-Path $missing (
        ([string]$teamEntry.path).Replace('/', '\'))) -Force
    Set-PSOBBProtectedTreeAcl -Path $missing -Root $canary.Snapshots
    Assert-Rejected -Name 'missing payload is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $missing
    }

    $missingProtected = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    Remove-Item -LiteralPath (Join-Path $missingProtected (
        ([string]$validCharacterEntry[0].path).Replace('/', '\'))) -Force
    Set-PSOBBProtectedTreeAcl -Path $missingProtected -Root $canary.Snapshots
    Assert-RejectedWithoutText -Name `
        'unreadable protected payload error does not expose identity text' `
        -ForbiddenText $protectedAccountStem -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $missingProtected
    }

    $extra = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    [System.IO.File]::WriteAllText(
        (Join-Path $extra 'state\system\teams\unexpected.json'),
        '{}', [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $extra -Root $canary.Snapshots
    Assert-Rejected -Name 'unmanifested extra payload is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $extra
    }

    $extraDirectory = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    New-Item -ItemType Directory -Path (Join-Path $extraDirectory `
        'state\system\players\empty-unmanifested') | Out-Null
    Set-PSOBBProtectedTreeAcl -Path $extraDirectory -Root $canary.Snapshots
    Assert-Rejected -Name 'signed snapshot with an empty extra directory is rejected' `
        -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $extraDirectory
    }

    $traversal = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $traversalManifest = Get-Content -Raw -LiteralPath (
        Join-Path $traversal 'manifest.json') | ConvertFrom-Json -Depth 20
    $license = @($traversalManifest.files | Where-Object role -eq 'license-state')[0]
    $license.path = 'state/system/licenses/../escaped.json'
    Set-TestSnapshotManifest -SnapshotPath $traversal `
        -PrivateKeyPath $privateKeyPath -Manifest $traversalManifest
    Assert-Rejected -Name 'signed traversal path is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $traversal
    }

    $caseCollision = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $caseManifest = Get-Content -Raw -LiteralPath (
        Join-Path $caseCollision 'manifest.json') | ConvertFrom-Json -Depth 20
    $original = @($caseManifest.files | Where-Object role -eq 'license-state')[0]
    $duplicate = [pscustomobject]@{
        path = ([string]$original.path).ToUpperInvariant()
        role = [string]$original.role
        size = [int64]$original.size
        sha256 = [string]$original.sha256
    }
    $caseManifest.files = @($caseManifest.files) + @($duplicate)
    Set-TestSnapshotManifest -SnapshotPath $caseCollision `
        -PrivateKeyPath $privateKeyPath -Manifest $caseManifest
    Assert-Rejected -Name 'signed case-colliding path is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $caseCollision
    }

    $wrongProfile = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $profileManifest = Get-Content -Raw -LiteralPath (
        Join-Path $wrongProfile 'manifest.json') | ConvertFrom-Json -Depth 20
    $profileManifest.sourceBackup.clientPatchProfile = 'stable-qol'
    Set-TestSnapshotManifest -SnapshotPath $wrongProfile `
        -PrivateKeyPath $privateKeyPath -Manifest $profileManifest
    Assert-Rejected -Name 'signed non-baseline source profile is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $wrongProfile
    }

    $reparse = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $outside = Join-Path $temporaryRoot 'outside'
    New-Item -ItemType Directory -Path $outside | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $reparse (
        'escape-' + $protectedAccountStem)) `
        -Target $outside | Out-Null
    Assert-RejectedWithoutText -Name `
        'snapshot reparse error does not expose protected identity text' `
        -ForbiddenText $protectedAccountStem -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $reparse
    }

    foreach ($mismatch in @(
            [pscustomobject]@{
                Role = 'twills-bank'
                Name = 'player_differentacct_0.psobank'
                TestName = 'signed cross-account bank is rejected'
            },
            [pscustomobject]@{
                Role = 'twills-system'
                Name = 'system_differentacct.psosys'
                TestName = 'signed cross-account system state is rejected'
            },
            [pscustomobject]@{
                Role = 'twills-card'
                Name = 'guild_cards_differentacct.psocard'
                TestName = 'signed cross-account guild-card state is rejected'
            })) {
        $mismatchSnapshot = New-TestAccountPathMismatch `
            -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots `
            -PrivateKeyPath $privateKeyPath -Role $mismatch.Role `
            -ReplacementName $mismatch.Name
        Assert-Rejected -Name $mismatch.TestName -Action {
            & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
                @verifyParameters -SnapshotPath $mismatchSnapshot
        }
    }

    $licenseMismatch = New-TestSnapshotClone `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
    $licenseManifestPath = Join-Path $licenseMismatch 'manifest.json'
    $licenseManifest = Get-Content -Raw -LiteralPath $licenseManifestPath |
        ConvertFrom-Json -Depth 20 -DateKind String
    $characterIdentityEntry = @($licenseManifest.files | Where-Object {
            [string]$_.role -ceq 'twills-character'
        })
    if ($characterIdentityEntry.Count -ne 1 -or
        [System.IO.Path]::GetFileName([string]$characterIdentityEntry[0].path) `
            -cnotmatch '^player_(?<account>[a-z][a-z0-9_-]{2,15})_0\.psochar$') {
        throw 'License mismatch fixture cannot derive its sealed account identity'
    }
    $fixtureAccountName = [string]$Matches.account
    $licenseChanges = 0
    foreach ($entry in @($licenseManifest.files | Where-Object {
                [string]$_.role -ceq 'license-state'
            })) {
        $licensePath = Join-Path $licenseMismatch (
            ([string]$entry.path).Replace('/', '\'))
        $licenseState = Get-Content -Raw -LiteralPath $licensePath |
            ConvertFrom-Json -Depth 100 -DateKind String
        $changed = $false
        if ($licenseState.PSObject.Properties.Name -contains 'BBUsername' -and
            [string]$licenseState.BBUsername -ceq $fixtureAccountName) {
            $licenseState.BBUsername = 'differentacct'
            $changed = $true
        }
        if ($licenseState.PSObject.Properties.Name -contains 'BBLicenses') {
            foreach ($bbLicense in @($licenseState.BBLicenses)) {
                if ($null -ne $bbLicense -and
                    $bbLicense.PSObject.Properties.Name -contains 'UserName' -and
                    [string]$bbLicense.UserName -ceq $fixtureAccountName) {
                    $bbLicense.UserName = 'differentacct'
                    $changed = $true
                }
            }
        }
        if ($changed) {
            [System.IO.File]::WriteAllText(
                $licensePath,
                ($licenseState | ConvertTo-Json -Depth 100),
                [System.Text.UTF8Encoding]::new($false))
            $entry.size = (Get-Item -Force -LiteralPath $licensePath).Length
            $entry.sha256 = Get-LowerSha256 $licensePath
            $licenseChanges++
        }
    }
    if ($licenseChanges -ne 1) {
        throw 'License mismatch fixture did not change exactly one account payload'
    }
    Set-TestSnapshotManifest -SnapshotPath $licenseMismatch `
        -PrivateKeyPath $privateKeyPath -Manifest $licenseManifest
    Assert-Rejected -Name 'signed cross-account BB license is rejected' -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $licenseMismatch
    }

    $licenseMutations = @(
        [pscustomobject]@{
            Name = 'signed FormatVersion shape mismatch is rejected'
            Mutation = {
                param($state, $account)
                $state.FormatVersion = 0
            }
        },
        [pscustomobject]@{
            Name = 'signed missing current BB password is rejected'
            Mutation = {
                param($state, $account)
                $match = @($state.BBLicenses | Where-Object {
                        [string]$_.UserName -ceq $account
                    })[0]
                $match.PSObject.Properties.Remove('Password')
            }
        },
        [pscustomobject]@{
            Name = 'signed nonstring current BB password is rejected'
            Mutation = {
                param($state, $account)
                $match = @($state.BBLicenses | Where-Object {
                        [string]$_.UserName -ceq $account
                    })[0]
                $match.Password = 7
            }
        },
        [pscustomobject]@{
            Name = 'signed oversized current BB password is rejected'
            Mutation = {
                param($state, $account)
                $match = @($state.BBLicenses | Where-Object {
                        [string]$_.UserName -ceq $account
                    })[0]
                $match.Password = '12345678901234567'
            }
        },
        [pscustomobject]@{
            Name = 'signed nonempty account autopatch list is rejected'
            Mutation = {
                param($state, $account)
                $state.AutoPatchesEnabled = @('NoRareSelling')
            }
        },
        [pscustomobject]@{
            Name = 'signed duplicate current BB identity is rejected globally'
            Mutation = {
                param($state, $account)
                $match = @($state.BBLicenses | Where-Object {
                        [string]$_.UserName -ceq $account
                    })[0]
                $state.BBLicenses = @($state.BBLicenses) + @($match)
            }
        })
    foreach ($mutation in $licenseMutations) {
        $fixture = New-TestSignedLicenseMutation `
            -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots `
            -PrivateKeyPath $privateKeyPath -Mutation $mutation.Mutation
        Assert-RejectedWithoutText -Name $mutation.Name `
            -ForbiddenText $fixture.AccountStem -Action {
            & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
                @verifyParameters -SnapshotPath $fixture.Path
        }
    }

    $duplicateLicenseFixture = New-TestSignedLicenseMutation `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots `
        -PrivateKeyPath $privateKeyPath -RawText -Mutation {
        param($text, $account)
        [regex]::new('(?m)^(\s*)"Password"\s*:').Replace(
            $text,
            '$1"\u0050assword":"duplicate",' + "`r`n" + '$1"Password":',
            1)
    }
    Assert-RejectedWithoutText -Name `
        'signed escaped duplicate BB credential key is rejected' `
        -ForbiddenText $duplicateLicenseFixture.AccountStem -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $duplicateLicenseFixture.Path
    }

    $unreadableLicenseFixture = New-TestSignedLicenseMutation `
        -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots `
        -PrivateKeyPath $privateKeyPath -RawText -Mutation {
        param($text, $account)
        '{"FormatVersion":1,"BBUsername":"' + $account + '",'
    }
    Assert-RejectedWithoutText -Name `
        'signed unreadable BB text error does not expose identity text' `
        -ForbiddenText $unreadableLicenseFixture.AccountStem -Action {
        & (Join-Path $scriptsRoot 'Test-PSOBBCombatCanary.ps1') `
            @verifyParameters -SnapshotPath $unreadableLicenseFixture.Path
    }
        Complete-TestSection
    }

    if ($Mode -eq 'All') {
        $canonicalCanary = Get-PSOBBServerEnvironmentLayout `
            -Layout $canonicalLayout -Environment CombatCanary
        Start-TestSection 'PublishedPackageReadOnly'
        $published = Test-RealPublishedCombatCanaryPackage `
            -RepositoryRoot $repositoryRoot -CanaryLayout $canonicalCanary
        $publishedClient = Test-RealPublishedPSOBBClient `
            -RepositoryRoot $repositoryRoot -StableLayout (
                Get-PSOBBServerEnvironmentLayout `
                    -Layout $canonicalLayout -Environment Stable)
    $configCheckPath = Join-Path $temporaryRoot 'config-check.json'
    Copy-Item -LiteralPath (Join-Path $canonicalCanary.ServerBase `
        'system\config.json') -Destination $configCheckPath
    Set-NewservLocalConfiguration -ConfigPath $configCheckPath `
        -ServerName 'PSOBB Combat' -ClientPatchProfile baseline
    $configText = Get-Content -Raw -LiteralPath $configCheckPath
    $configText = Set-ConfigScalar -Text $configText `
        -Key 'DefaultDropModeV4Battle' -JsonValue '"SERVER_SHARED"'
    $configText = Set-ConfigScalar -Text $configText `
        -Key 'DefaultDropModeV4Challenge' -JsonValue '"SERVER_SHARED"'
    $configText = Set-ConfigScalar -Text $configText `
        -Key 'CensorCredentials' -JsonValue 'true'
    $configText = Set-ConfigScalar -Text $configText `
        -Key 'AllowSameAccountConcurrentLogins' -JsonValue 'false'
    $patchPortPattern =
        '(?m)^\s*"bb-patch"\s*:\s*\[\["127\.0\.0\.1",\s*11000\],\s*"patch",\s*"patch_server_bb"\]\s*,?\s*(?://.*)?$'
    $data1PortPattern =
        '(?m)^\s*"bb-data1"\s*:\s*\[\["127\.0\.0\.1",\s*12000\],\s*"bb",\s*"game_server"\]\s*,?\s*(?://.*)?$'
    $data2PortPattern =
        '(?m)^\s*"bb-data2"\s*:\s*\[\["127\.0\.0\.1",\s*12001\],\s*"bb",\s*"game_server"\]\s*,?\s*(?://.*)?$'
    $extraEndpointConfig = [regex]::new(
        '(?m)^(\s*"bb-patch"\s*:\s*)\[\["127\.0\.0\.1",\s*11000\],\s*"patch",\s*"patch_server_bb"\](\s*,?.*)$',
        [System.Text.RegularExpressions.RegexOptions]::None).Replace(
        $configText,
        '$1[["127.0.0.1", 11000], ["127.0.0.1", 11001], "patch", "patch_server_bb"]$2',
        1)
    $changedDispatchConfig = [regex]::new(
        '(?m)^(\s*"bb-data1"\s*:\s*\[\["127\.0\.0\.1",\s*12000\],\s*"bb",\s*)"game_server"',
        [System.Text.RegularExpressions.RegexOptions]::None).Replace(
        $configText,
        '$1"patch_server_bb"',
        1)
    $criticalConfigKeys = @(
        'ServerName', 'LocalAddress', 'ExternalAddress', 'DNSServerPort',
        'IPStackListen', 'PPPStackListen', 'PPPRawListen', 'HTTPListen',
        'RunInteractiveShell', 'CensorCredentials',
        'AllowSameAccountConcurrentLogins', 'AllowUnregisteredUsers',
        'CheatModeBehavior', 'DefaultDropModeV4Normal',
        'DefaultDropModeV4Battle', 'DefaultDropModeV4Challenge',
        'BBEXPShareMultiplier', 'EnableSwitchAssistByDefault',
        'RareNotificationsEnabledByDefaultV3V4', 'CommandData',
        'AutoPatches', 'BBRequiredPatches', 'bb-patch', 'bb-data1', 'bb-data2')
    $criticalConfigKeysUnique = @($criticalConfigKeys | Where-Object {
            [regex]::Matches(
                $configText,
                '(?m)^\s*"' + [regex]::Escape($_) + '"\s*:').Count -ne 1
        }).Count -eq 0
    $configReady =
        $criticalConfigKeysUnique -and
        [regex]::Matches($configText,
            '(?m)^\s*"ServerName"\s*:\s*"PSOBB Combat"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"LocalAddress"\s*:\s*"127\.0\.0\.1"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"ExternalAddress"\s*:\s*"127\.0\.0\.1"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"DNSServerPort"\s*:\s*0\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"IPStackListen"\s*:\s*\[\]\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"PPPStackListen"\s*:\s*\[\]\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"PPPRawListen"\s*:\s*\[\]\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"HTTPListen"\s*:\s*\[\]\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"RunInteractiveShell"\s*:\s*true\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"CheatModeBehavior"\s*:\s*"Off"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"DefaultDropModeV4Normal"\s*:\s*"SERVER_PRIVATE"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"DefaultDropModeV4Battle"\s*:\s*"SERVER_SHARED"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"DefaultDropModeV4Challenge"\s*:\s*"SERVER_SHARED"\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"BBEXPShareMultiplier"\s*:\s*0\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"EnableSwitchAssistByDefault"\s*:\s*true\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"RareNotificationsEnabledByDefaultV3V4"\s*:\s*true\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"AllowUnregisteredUsers"\s*:\s*false\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"CommandData"\s*:\s*"DISABLED"\s*,?').Count -eq 1 -and
        @(Get-ActiveConfigStringArray -Text $configText -Key 'AutoPatches').Count -eq 0 -and
        @(Get-ActiveConfigStringArray -Text $configText -Key 'BBRequiredPatches').Count -eq 0 -and
        [regex]::Matches($configText,
            '(?m)^\s*"CensorCredentials"\s*:\s*true\s*,?').Count -eq 1 -and
        [regex]::Matches($configText,
            '(?m)^\s*"AllowSameAccountConcurrentLogins"\s*:\s*false\s*,?').Count -eq 1
    $exactPortPolicy =
        [regex]::Matches($configText, $patchPortPattern).Count -eq 1 -and
        [regex]::Matches($configText, $data1PortPattern).Count -eq 1 -and
        [regex]::Matches($configText, $data2PortPattern).Count -eq 1 -and
        $extraEndpointConfig -cne $configText -and
        [regex]::Matches($extraEndpointConfig, $patchPortPattern).Count -eq 0 -and
        $changedDispatchConfig -cne $configText -and
        [regex]::Matches($changedDispatchConfig, $data1PortPattern).Count -eq 0
    Add-Result 'final build and baseline config inputs read back exactly' (
        [bool]$published.Valid -and $configReady -and $exactPortPolicy) `
        "files=$($published.Files)"
    Add-Result 'real Stable base client matches its exact 59NL binding' `
        ([bool]$publishedClient.Valid) "files=$($publishedClient.Files)"
        Complete-TestSection
    }


    Start-TestSection 'SignedManifestTypes'
    Add-Result 'transaction snapshot satisfies the exact tracked schema' (
        Test-SnapshotSchema -SnapshotPath $created.SnapshotPath `
            -SchemaPath (Join-Path $repositoryRoot `
                'config\schemas\combat-canary-snapshot.schema.json')) `
        'valid producer or synthetic seed accepted'
    foreach ($wrongTypeProbe in @(
            [pscustomobject]@{
                Name = 'signed string classId'
                Mutation = {
                    param($Manifest)
                    $Manifest.character.classId = '8'
                }
            },
            [pscustomobject]@{
                Name = 'signed string file size'
                Mutation = {
                    param($Manifest)
                    $entry = @($Manifest.files | Where-Object {
                            [string]$_.role -ceq 'twills-character'
                        })
                    if ($entry.Count -ne 1) {
                        throw 'Wrong-type fixture has no singular character entry'
                    }
                    $entry[0].size = [string]$entry[0].size
                }
            })) {
        $wrongTypeSnapshot = New-TestSnapshotClone `
            -Source $created.SnapshotPath -SnapshotsRoot $canary.Snapshots
        try {
            $wrongTypeManifest = Get-Content -Raw -LiteralPath (
                Join-Path $wrongTypeSnapshot 'manifest.json') |
                ConvertFrom-Json -Depth 20 -DateKind String
            & $wrongTypeProbe.Mutation $wrongTypeManifest
            Set-TestSnapshotManifest -SnapshotPath $wrongTypeSnapshot `
                -PrivateKeyPath $privateKeyPath -Manifest $wrongTypeManifest
            Assert-Rejected -Name ("snapshot verifier rejects $($wrongTypeProbe.Name)") `
                -Action {
                    & (Join-Path $transactionScriptsRoot `
                        'Test-PSOBBCombatCanary.ps1') `
                        -RuntimeRoot $layout.Root -Target Snapshot `
                        -SnapshotPath $wrongTypeSnapshot `
                        -ExpectedTwillsContractSha256 $contractHash `
                        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
                }
        } finally {
            Remove-Item -LiteralPath $wrongTypeSnapshot -Recurse -Force
        }
    }
    Complete-TestSection
    $initializeParameters = @{
        RuntimeRoot = $layout.Root
        SnapshotPath = $created.SnapshotPath
        ExpectedBuildContractSha256 = $buildContractHash
        ExpectedTwillsContractSha256 = $contractHash
        ExpectedSigningPublicKeySpkiSha256 = $spkiFingerprint
        Confirm = $false
    }

    if ($Mode -eq 'VerifierScopeRegression') {
        Start-TestSection 'VerifierScopeRegression'
        $predicateTokens = $null
        $predicateErrors = $null
        $predicateAst = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $transactionScriptsRoot 'Test-PSOBBCombatCanary.ps1'),
            [ref]$predicateTokens, [ref]$predicateErrors)
        $predicateDefinitions = @($predicateAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq
                        'Test-PSOBBCombatCanaryVerifierMutableServerExemptPath'
                }, $true))
        if (@($predicateErrors).Count -ne 0 -or
            $predicateDefinitions.Count -ne 1) {
            throw 'The mutable-server exemption predicate is not uniquely parseable'
        }
        . ([scriptblock]::Create($predicateDefinitions[0].Extent.Text))
        $acceptedExemptPaths = @(
            'system/config.json',
            'system/licenses',
            'system/licenses/account.json',
            'system/players/player_fixture_0.psochar',
            'system/players/nested/file.bin',
            'system/teams/team_fixture.json')
        $rejectedExemptPaths = @(
            'system/config.json/extra',
            'system/licenses-evil/account.json',
            'system/players2/player.psochar',
            'system/teams.old/team.json',
            'system/licenses\account.json',
            'system/licenses//account.json',
            'system/licenses/./account.json',
            'system/licenses/../account.json',
            'system/licenses/a/../../account.json',
            'system/licenses/account:name.json',
            'System/licenses/account.json',
            'other/system/licenses/account.json')
        $predicateExact =
            @($acceptedExemptPaths | Where-Object {
                    -not (Test-PSOBBCombatCanaryVerifierMutableServerExemptPath `
                        -Path $_)
                }).Count -eq 0 -and
            @($rejectedExemptPaths | Where-Object {
                    Test-PSOBBCombatCanaryVerifierMutableServerExemptPath `
                        -Path $_
                }).Count -eq 0
        Add-Result 'mutable-server exemption is exact and traversal-safe' `
            $predicateExact `
            "accepted=$($acceptedExemptPaths.Count); rejected=$($rejectedExemptPaths.Count)"

        $initialized = & (Join-Path $transactionScriptsRoot `
            'Initialize-PSOBBCombatCanary.ps1') @initializeParameters
        $validInstalled = & (Join-Path $transactionScriptsRoot `
            'Test-PSOBBCombatCanary.ps1') `
            -RuntimeRoot $layout.Root -Target Installed `
            -SnapshotPath $created.SnapshotPath `
            -ExpectedBuildContractSha256 $buildContractHash `
            -ExpectedTwillsContractSha256 $contractHash `
            -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
        Add-Result 'Installed verifier reaches the shared build gate in script scope' (
            [bool]$initialized.Initialized -and [bool]$initialized.Changed -and
            [bool]$validInstalled.Valid) 'valid synthetic frozen contract accepted'

        $syntheticBuildPath = [string]$syntheticHarness.BuildContractPath
        $originalBuildBytes = [System.IO.File]::ReadAllBytes($syntheticBuildPath)
        $shapeRejected = $false
        try {
            $mutatedBuild = [System.Text.Encoding]::UTF8.GetString(
                $originalBuildBytes) | ConvertFrom-Json -Depth 100 -DateKind String
            $objdump = $mutatedBuild.toolchain.tools[3]
            $mutatedBuild.toolchain.tools[3] = $mutatedBuild.toolchain.tools[4]
            $mutatedBuild.toolchain.tools[4] = $objdump
            [System.IO.File]::WriteAllText(
                $syntheticBuildPath,
                ($mutatedBuild | ConvertTo-Json -Depth 100),
                [System.Text.UTF8Encoding]::new($false))
            $mutatedBuildHash = Get-LowerSha256 $syntheticBuildPath
            try {
                & (Join-Path $transactionScriptsRoot `
                    'Test-PSOBBCombatCanary.ps1') `
                    -RuntimeRoot $layout.Root -Target Installed `
                    -SnapshotPath $created.SnapshotPath `
                    -ExpectedBuildContractSha256 $mutatedBuildHash `
                    -ExpectedTwillsContractSha256 $contractHash `
                    -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint | Out-Null
            } catch {
                $shapeRejected = $_.Exception.Message -ceq
                    'The combat-canary build contract does not have the exact combat-canary schema'
            }
        } finally {
            [System.IO.File]::WriteAllBytes(
                $syntheticBuildPath, $originalBuildBytes)
        }
        $restoredInstalled = & (Join-Path $transactionScriptsRoot `
            'Test-PSOBBCombatCanary.ps1') `
            -RuntimeRoot $layout.Root -Target Installed `
            -SnapshotPath $created.SnapshotPath `
            -ExpectedBuildContractSha256 $buildContractHash `
            -ExpectedTwillsContractSha256 $contractHash `
            -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
        Add-Result 'Installed verifier preserves shared role-only shape rejection' (
            $shapeRejected -and [bool]$restoredInstalled.Valid) `
            'tool-order mutation rejected without dynamic parameter mismatch'
        Complete-TestSection
    } else {
    Start-TestSection 'InitializeTransactions'
    $preexistingPaths = @($canary.Backups, $canary.Logs, $canary.Secrets)
    foreach ($path in $preexistingPaths) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        [System.IO.File]::WriteAllText(
            (Join-Path $path 'preserve.txt'),
            'preserve', [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedTreeAcl -Path $path -Root $canary.EnvironmentRoot
    }
    $preexistingFingerprint = Get-TestMutableCanaryFingerprint -Layout $canary
    $preexistingRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot 'Initialize-PSOBBCombatCanary.ps1') `
            @initializeParameters | Out-Null
    } catch {
        $preexistingRejected = $_.Exception.Message -ceq
            'First combat-canary initialization refuses preexisting mutable state or evidence'
    }
    $preexistingPreserved = $preexistingRejected -and
        (Get-TestMutableCanaryFingerprint -Layout $canary) -ceq
            $preexistingFingerprint
    Add-Result 'first install rejects and preserves preexisting evidence' `
        $preexistingPreserved 'backup/log/secret retained byte-for-byte'
    foreach ($path in $preexistingPaths) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }

    $sourceGate = New-TestCombatCanarySourceGateEvidence -Layout $canary
    $sourceGateFingerprint = Get-TestTreeFingerprint `
        -Root $sourceGate.EvidenceRoot
    $sourceGateWhatIf = & (Join-Path $transactionScriptsRoot `
        'Initialize-PSOBBCombatCanary.ps1') @initializeParameters -WhatIf
    Add-Result 'first install WhatIf accepts and preserves sealed source evidence' (
        [bool]$sourceGateWhatIf.WhatIf -and
        (Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -ceq
            $sourceGateFingerprint -and
        -not (Test-Path -LiteralPath $canary.InstallRecord)) `
        'protected evidence remained byte-for-byte exact'

    $entryBoundRejected = $false
    $byteBoundRejected = $false
    try {
        Get-PSOBBOrdinaryTreeSnapshot -Path $sourceGate.GateRoot `
            -Root $sourceGate.EvidenceRoot -RequireProtectedAcl `
            -MaximumEntries 1 -MaximumBytes 64MB | Out-Null
    } catch { $entryBoundRejected = $true }
    try {
        Get-PSOBBOrdinaryTreeSnapshot -Path $sourceGate.GateRoot `
            -Root $sourceGate.EvidenceRoot -RequireProtectedAcl `
            -MaximumEntries 512 -MaximumBytes 1 | Out-Null
    } catch { $byteBoundRejected = $true }
    Add-Result 'source evidence traversal enforces count and byte bounds' (
        $entryBoundRejected -and $byteBoundRejected) `
        'existing ordinary-tree helper rejected both bounded inventories'

    $renamedSourceGatePath = Join-Path $sourceGate.EvidenceRoot `
        'renamed-source-evidence'
    [System.IO.Directory]::Move(
        $sourceGate.GateRoot, $renamedSourceGatePath)
    $missingSourceGateFingerprint = Get-TestTreeFingerprint `
        -Root $sourceGate.EvidenceRoot
    $missingSourceGateRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Initialize-PSOBBCombatCanary.ps1') @initializeParameters | Out-Null
    } catch {
        $missingSourceGateRejected = $_.Exception.Message -ceq
            'First combat-canary initialization refuses preexisting mutable state or evidence'
    }
    Add-Result 'first install rejects evidence without a source gate' (
        $missingSourceGateRejected -and
        (Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -ceq
            $missingSourceGateFingerprint) `
        'all structurally safe non-source evidence remained byte-for-byte'
    [System.IO.Directory]::Move(
        $renamedSourceGatePath, $sourceGate.GateRoot)

    $payloadAcl = Get-Acl -LiteralPath $sourceGate.PayloadPath
    $payloadAcl.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $sourceGate.PayloadPath -AclObject $payloadAcl
    $unprotectedFingerprint = Get-TestTreeFingerprint `
        -Root $sourceGate.EvidenceRoot
    $unprotectedRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Initialize-PSOBBCombatCanary.ps1') @initializeParameters | Out-Null
    } catch {
        $unprotectedRejected = $_.Exception.Message -ceq
            'First combat-canary initialization refuses preexisting mutable state or evidence'
    }
    Add-Result 'first install rejects and preserves unprotected evidence' (
        $unprotectedRejected -and
        -not (Test-PSOBBProtectedAcl -Path $sourceGate.PayloadPath) -and
        (Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -ceq
            $unprotectedFingerprint) `
        'initializer did not normalize the rejected ACL or bytes'
    Set-PSOBBProtectedAcl -Path $sourceGate.PayloadPath

    $reparseTarget = Join-Path $canary.Builds 'source-gate-reparse-target'
    $reparsePath = Join-Path $sourceGate.GateRoot 'unexpected-link'
    New-Item -ItemType Directory -Path $reparseTarget -Force | Out-Null
    New-Item -ItemType Junction -Path $reparsePath `
        -Target $reparseTarget | Out-Null
    $reparseFingerprint = Get-TestTreeFingerprint `
        -Root $sourceGate.EvidenceRoot
    $reparseRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Initialize-PSOBBCombatCanary.ps1') @initializeParameters | Out-Null
    } catch {
        $reparseRejected = $_.Exception.Message -ceq
            'First combat-canary initialization refuses preexisting mutable state or evidence'
    }
    Add-Result 'first install rejects and preserves reparse evidence' (
        $reparseRejected -and
        (Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -ceq
            $reparseFingerprint) `
        'reparse evidence remained present and untraversed'
    [System.IO.Directory]::Delete($reparsePath, $false)
    if ((Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -cne
        $sourceGateFingerprint) {
        throw 'The sealed source-gate fixture did not restore exactly'
    }

    $emptyMutableFingerprint = Get-TestMutableCanaryFingerprint -Layout $canary
    $initializeManifest = Get-Content -Raw -LiteralPath (
        Join-Path $created.SnapshotPath 'manifest.json') |
        ConvertFrom-Json -Depth 20 -DateKind String
    $initializeTeamEntry = @($initializeManifest.files | Where-Object {
            [string]$_.role -ceq 'team-state'
        })
    if ($initializeTeamEntry.Count -ne 1) {
        throw 'The initialization copy-fault fixture has no singular team payload'
    }
    $initializeTeamPath = Join-Path $created.SnapshotPath (
        ([string]$initializeTeamEntry[0].path).Replace('/', '\'))
    $initializeTeamBytes = [System.IO.File]::ReadAllBytes($initializeTeamPath)
    $initializeOversizeHook = {
        [System.IO.File]::WriteAllBytes(
            $initializeTeamPath, [byte[]]::new((1MB) + 1))
    }.GetNewClosure()
    $initializeOversizeRejected = $false
    try {
        try {
            & (Join-Path $transactionScriptsRoot `
                'Initialize-PSOBBCombatCanary.ps1') `
                @initializeParameters `
                -InternalTestBeforePayloadCopy $initializeOversizeHook `
                -InternalTestFaultToken $fixtureInstallationId | Out-Null
        } catch {
            $initializeOversizeRejected = $true
        }
    } finally {
        [System.IO.File]::WriteAllBytes(
            $initializeTeamPath, $initializeTeamBytes)
        Set-PSOBBProtectedTreeAcl -Path $created.SnapshotPath `
            -Root $canary.Snapshots
    }
    $initializeOversizeClean = $initializeOversizeRejected -and
        (Get-TestMutableCanaryFingerprint -Layout $canary) -ceq
            $emptyMutableFingerprint -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
            -Directory | Where-Object {
                $_.Name -like '.initialize-stage-*' -or
                $_.Name -like '.initialize-rollback-*'
            }).Count -eq 0
    Add-Result 'Initialize rejects a post-validation oversized state source' `
        $initializeOversizeClean 'bounded copy left no published state or transaction debris'

    $initializeSwapSaved = $initializeTeamPath + '.swap-attempt'
    $initializeSwapHook = {
        param([string]$Path)
        if ($Path -ieq $initializeTeamPath) {
            [System.IO.File]::Move($Path, $initializeSwapSaved, $false)
        }
    }.GetNewClosure()
    $initializeSwapRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Initialize-PSOBBCombatCanary.ps1') `
            @initializeParameters `
            -InternalTestAfterPayloadSourceLease $initializeSwapHook `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $initializeSwapRejected = $true
    }
    $initializeSwapClean = $initializeSwapRejected -and
        -not (Test-Path -LiteralPath $initializeSwapSaved) -and
        (Get-LowerSha256 $initializeTeamPath) -ceq
            [string]$initializeTeamEntry[0].sha256 -and
        (Get-TestMutableCanaryFingerprint -Layout $canary) -ceq
            $emptyMutableFingerprint -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
            -Directory | Where-Object {
                $_.Name -like '.initialize-stage-*' -or
                $_.Name -like '.initialize-rollback-*'
            }).Count -eq 0
    Add-Result 'Initialize blocks state-source replacement while leased' `
        $initializeSwapClean 'source identity and empty target state remained exact'

    $initializeSubstitution = [pscustomobject]@{
        Published = ''
        Saved = ''
    }
    $initializeSubstitutionHook = {
        param([string]$Path, [string]$Name)
        if ([string]::IsNullOrWhiteSpace($initializeSubstitution.Published)) {
            $initializeSubstitution.Published = $Path
            $initializeSubstitution.Saved = $Path + '.owned-evidence'
            [System.IO.Directory]::Move(
                $Path, $initializeSubstitution.Saved)
            [void][System.IO.Directory]::CreateDirectory($Path)
            [System.IO.File]::WriteAllText(
                (Join-Path $Path '.replacement-evidence'), 'replacement',
                [System.Text.UTF8Encoding]::new($false))
        }
    }.GetNewClosure()
    $initializeSubstitutionRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Initialize-PSOBBCombatCanary.ps1') `
            @initializeParameters `
            -InternalTestAfterPublishedMove $initializeSubstitutionHook `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $initializeSubstitutionRejected = $_.Exception.Message -like
            'Combat-canary initialization failed and compensation was incomplete for:*'
    }
    $initializeSubstitutionRetained = $initializeSubstitutionRejected -and
        (Test-Path -LiteralPath $initializeSubstitution.Published `
            -PathType Container) -and
        (Test-Path -LiteralPath $initializeSubstitution.Saved `
            -PathType Container) -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
            -Directory | Where-Object {
                $_.Name -like '.initialize-stage-*' -or
                $_.Name -like '.initialize-rollback-*'
            }).Count -eq 0
    Add-Result 'Initialize retains post-publication substitution evidence' `
        $initializeSubstitutionRetained 'replacement and owned identities were both retained'
    foreach ($path in @($initializeSubstitution.Published,
            $initializeSubstitution.Saved)) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and
            (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
    if ((Get-TestMutableCanaryFingerprint -Layout $canary) -cne
        $emptyMutableFingerprint) {
        throw 'The initialization substitution fixture could not be safely removed'
    }

    $initializeCollisionRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot 'Initialize-PSOBBCombatCanary.ps1') `
            @initializeParameters `
            -InternalTestCreateUnexpectedTargetBeforeSwap 1 `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $initializeCollisionRejected = $_.Exception.Message -ceq
            'First combat-canary initialization detected an unexpected target before publication'
    }
    $unexpectedServerRoot = Split-Path -Parent $canary.Server
    $initializeCollisionPreserved = $initializeCollisionRejected -and
        (Test-Path -LiteralPath (Join-Path $unexpectedServerRoot `
                '.unexpected-preserve') -PathType Leaf) -and
        [System.IO.File]::ReadAllText((Join-Path $unexpectedServerRoot `
                    '.unexpected-preserve')) -ceq 'preserve' -and
        @(Get-ChildItem -Force -LiteralPath $unexpectedServerRoot).Count -eq 1 -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot -Directory |
            Where-Object { $_.Name -like '.initialize-stage-*' -or
                $_.Name -like '.initialize-rollback-*' }).Count -eq 0
    Add-Result 'Initialize preserves a target that appears before no-clobber publication' `
        $initializeCollisionPreserved 'unexpected target retained without transaction debris'
    if (Test-Path -LiteralPath $unexpectedServerRoot) {
        Remove-Item -LiteralPath $unexpectedServerRoot -Recurse -Force
    }
    if ((Get-TestMutableCanaryFingerprint -Layout $canary) -cne
        $emptyMutableFingerprint) {
        throw 'The initialization collision fixture could not be safely removed'
    }

    $initializeCompensationExact = $true
    $initializeBoundariesPassed = 0
    for ($boundary = 1; $boundary -le 11; $boundary++) {
        $rejected = $false
        try {
            & (Join-Path $transactionScriptsRoot 'Initialize-PSOBBCombatCanary.ps1') `
                @initializeParameters -InternalTestFailAfterSwap $boundary `
                -InternalTestFaultToken $fixtureInstallationId | Out-Null
        } catch {
            $rejected = $_.Exception.Message -ceq
                'Injected temporary-fixture initialization swap failure'
        }
        if (-not $rejected -or
            (Get-TestMutableCanaryFingerprint -Layout $canary) -cne
                $emptyMutableFingerprint) {
            $initializeCompensationExact = $false
            break
        }
        $initializeBoundariesPassed++
    }
    Add-Result 'Initialize compensates exactly after every swap boundary' `
        $initializeCompensationExact `
        "boundaries=$initializeBoundariesPassed/11"
    Add-Result 'Initialize failures never mutate sealed source evidence' (
        (Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -ceq
            $sourceGateFingerprint) `
        'all injected publication failures preserved exact evidence bytes'
    if (-not $initializeCompensationExact) {
        throw "Initialize compensation failed at boundary $boundary"
    }

    $initialized = & (Join-Path $transactionScriptsRoot 'Initialize-PSOBBCombatCanary.ps1') `
        @initializeParameters
    $idempotent = & (Join-Path $transactionScriptsRoot 'Initialize-PSOBBCombatCanary.ps1') `
        @initializeParameters
    $installedBeforeMutation = & (
        Join-Path $transactionScriptsRoot 'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $layout.Root -Target Installed `
        -SnapshotPath $created.SnapshotPath `
        -ExpectedBuildContractSha256 $buildContractHash `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
    Add-Result 'isolated Initialize succeeds and is an exact idempotent no-op' (
        [bool]$initialized.Initialized -and [bool]$initialized.Changed -and
        [bool]$idempotent.Initialized -and -not [bool]$idempotent.Changed -and
        [bool]$installedBeforeMutation.Valid) 'changed=true then changed=false'
    $initializedControlValid = $false
    try {
        [void](Assert-PSOBBLifecyclePathAcl `
                -Path $canary.ControlDirectory -Root $canary.Root `
                -IsContainer $true)
        $initializedControlValid = $true
    } catch { $initializedControlValid = $false }
    Add-Result 'Initialize publishes a lifecycle-owned control directory' `
        $initializedControlValid `
        'the current user owns the exact protected lifecycle directory'

    $controlAclBeforeOwnerProbe = Get-Acl -LiteralPath $canary.ControlDirectory
    $controlAccessBeforeOwnerProbe =
        $controlAclBeforeOwnerProbe.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access)
    $controlGroupBeforeOwnerProbe = $controlAclBeforeOwnerProbe.GetGroup(
        [System.Security.Principal.SecurityIdentifier]).Value
    $administratorsSid =
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $ownerOnlyMutation = $false
    $ownerMismatchRejected = $false
    $ownerRestored = $false
    try {
        $administratorOwned = New-PSOBBLifecycleDacl -IsContainer $true
        $administratorOwned.SetOwner($administratorsSid)
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo](Get-Item -Force -LiteralPath (
                    $canary.ControlDirectory)),
            [System.Security.AccessControl.DirectorySecurity]$administratorOwned)
        $mutatedControlAcl = Get-Acl -LiteralPath $canary.ControlDirectory
        $ownerOnlyMutation =
            $mutatedControlAcl.GetOwner(
                [System.Security.Principal.SecurityIdentifier]).Value -ceq
                    $administratorsSid.Value -and
            $mutatedControlAcl.GetGroup(
                [System.Security.Principal.SecurityIdentifier]).Value -ceq
                    $controlGroupBeforeOwnerProbe -and
            $mutatedControlAcl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::Access) -ceq
                    $controlAccessBeforeOwnerProbe
        try {
            & (Join-Path $transactionScriptsRoot `
                    'Test-PSOBBCombatCanary.ps1') `
                -RuntimeRoot $layout.Root -Target Both `
                -SnapshotPath $created.SnapshotPath `
                -ExpectedBuildContractSha256 $buildContractHash `
                -ExpectedTwillsContractSha256 $contractHash `
                -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint |
                Out-Null
        } catch {
            $ownerMismatchRejected = $_.Exception.Message -ceq
                ('Protected lifecycle path owner is not the current user: ' +
                    $canary.ControlDirectory)
        }
    } finally {
        Set-PSOBBLifecyclePathAcl `
            -Path $canary.ControlDirectory -Root $canary.Root | Out-Null
        try {
            [void](Assert-PSOBBLifecyclePathAcl `
                    -Path $canary.ControlDirectory -Root $canary.Root `
                    -IsContainer $true)
            $ownerRestored = $true
        } catch { $ownerRestored = $false }
    }
    $ownerRestoredReadback = & (Join-Path $transactionScriptsRoot `
            'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $layout.Root -Target Both `
        -SnapshotPath $created.SnapshotPath `
        -ExpectedBuildContractSha256 $buildContractHash `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
    Add-Result 'Both rejects an owner-only lifecycle control mutation' (
        $ownerOnlyMutation -and $ownerMismatchRejected -and $ownerRestored -and
        [bool]$ownerRestoredReadback.Valid) `
        'Administrators ownership fails closed and exact current-user ownership restores'
    $sourceGateAfterInstallValid = $false
    try {
        $sourceGateAfterInstall = Get-PSOBBOrdinaryTreeSnapshot `
            -Path $sourceGate.EvidenceRoot -Root $canary.EnvironmentRoot `
            -RequireProtectedAcl -MaximumEntries 512 -MaximumBytes 64MB
        $sourceGateAfterInstallValid =
            @($sourceGateAfterInstall.Items | Where-Object {
                    -not $_.IsDirectory
                }).Count -ge 1
    } catch { $sourceGateAfterInstallValid = $false }
    Add-Result 'successful Initialize never mutates sealed source evidence' (
        $sourceGateAfterInstallValid -and
        (Get-TestTreeFingerprint -Root $sourceGate.EvidenceRoot) -ceq
            $sourceGateFingerprint) `
        'apply and idempotent readback preserved bytes, inventory, and ACL safety'

    $installedExtraDirectory = Join-Path $canary.Server `
        'system\players\empty-unmanifested'
    New-Item -ItemType Directory -Path $installedExtraDirectory | Out-Null
    Set-PSOBBProtectedAcl -Path $installedExtraDirectory
    try {
        Assert-Rejected -Name `
            'installed state with an empty extra directory is rejected' -Action {
            & (Join-Path $transactionScriptsRoot 'Test-PSOBBCombatCanary.ps1') `
                -RuntimeRoot $layout.Root -Target Installed `
                -SnapshotPath $created.SnapshotPath `
                -ExpectedBuildContractSha256 $buildContractHash `
                -ExpectedTwillsContractSha256 $contractHash `
                -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
        }
    } finally {
        Remove-Item -LiteralPath $installedExtraDirectory -Force
    }

    $configurationPath = Join-Path $canary.Server 'system\config.json'
    $originalConfigurationBytes = [System.IO.File]::ReadAllBytes($configurationPath)
    $originalInstallationBytes = [System.IO.File]::ReadAllBytes($canary.InstallRecord)
    $installedConfigurationText = [System.Text.Encoding]::UTF8.GetString(
        $originalConfigurationBytes)
    Add-Result 'Initialize emits LF-only UTF-8 configuration bytes' (
        -not $installedConfigurationText.StartsWith([char]0xFEFF) -and
        -not $installedConfigurationText.Contains("`r") -and
        -not ($originalConfigurationBytes.Length -ge 3 -and
            $originalConfigurationBytes[0] -eq 0xEF -and
            $originalConfigurationBytes[1] -eq 0xBB -and
            $originalConfigurationBytes[2] -eq 0xBF)) `
        "bytes=$($originalConfigurationBytes.Length)"

    foreach ($encodingProbe in @('CR', 'BOM')) {
        $encodingRejected = $false
        try {
            if ($encodingProbe -ceq 'CR') {
                $crConfiguration = [regex]::new("`n").Replace(
                    $installedConfigurationText, "`r`n", 1)
                [System.IO.File]::WriteAllText(
                    $configurationPath, $crConfiguration,
                    [System.Text.UTF8Encoding]::new($false))
            } else {
                $bomConfiguration = [byte[]]::new(
                    $originalConfigurationBytes.Length + 3)
                $bomConfiguration[0] = 0xEF
                $bomConfiguration[1] = 0xBB
                $bomConfiguration[2] = 0xBF
                [System.Buffer]::BlockCopy(
                    $originalConfigurationBytes, 0,
                    $bomConfiguration, 3,
                    $originalConfigurationBytes.Length)
                [System.IO.File]::WriteAllBytes(
                    $configurationPath, $bomConfiguration)
            }
            $encodingInstallation = [System.Text.Encoding]::UTF8.GetString(
                $originalInstallationBytes) |
                ConvertFrom-Json -Depth 20 -DateKind String
            $encodingInstallation.configurationSha256 =
                Get-LowerSha256 $configurationPath
            [System.IO.File]::WriteAllText(
                $canary.InstallRecord,
                ($encodingInstallation | ConvertTo-Json -Depth 20),
                [System.Text.UTF8Encoding]::new($false))
            Set-PSOBBProtectedAcl -Path $canary.InstallRecord
            try {
                & (Join-Path $transactionScriptsRoot `
                    'Test-PSOBBCombatCanary.ps1') `
                    -RuntimeRoot $layout.Root -Target Installation `
                    -ExpectedBuildContractSha256 $buildContractHash `
                    -ExpectedTwillsContractSha256 $contractHash `
                    -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint |
                    Out-Null
            } catch {
                $encodingRejected = $true
            }
        } finally {
            [System.IO.File]::WriteAllBytes(
                $configurationPath, $originalConfigurationBytes)
            [System.IO.File]::WriteAllBytes(
                $canary.InstallRecord, $originalInstallationBytes)
            Set-PSOBBProtectedAcl -Path $canary.InstallRecord
        }
        Add-Result ("installed configuration rejects $encodingProbe bytes") `
            $encodingRejected 'hash binding aligned before verifier call'
    }

    foreach ($duplicateKey in @('"ServerName"', '"\u0053erverName"')) {
        $duplicateRejected = $false
        try {
            $duplicateConfiguration = [regex]::new('^\s*\{').Replace(
                [System.Text.Encoding]::UTF8.GetString($originalConfigurationBytes),
                '{' + $duplicateKey + ':"Conflict",', 1)
            [System.IO.File]::WriteAllText(
                $configurationPath, $duplicateConfiguration,
                [System.Text.UTF8Encoding]::new($false))
            $duplicateInstallation = [System.Text.Encoding]::UTF8.GetString(
                $originalInstallationBytes) |
                ConvertFrom-Json -Depth 20 -DateKind String
            $duplicateInstallation.configurationSha256 =
                Get-LowerSha256 $configurationPath
            [System.IO.File]::WriteAllText(
                $canary.InstallRecord,
                ($duplicateInstallation | ConvertTo-Json -Depth 20),
                [System.Text.UTF8Encoding]::new($false))
            Set-PSOBBProtectedAcl -Path $canary.InstallRecord
            try {
                & (Join-Path $transactionScriptsRoot 'Test-PSOBBCombatCanary.ps1') `
                    -RuntimeRoot $layout.Root -Target Installation `
                    -ExpectedBuildContractSha256 $buildContractHash `
                    -ExpectedTwillsContractSha256 $contractHash `
                    -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint | Out-Null
            } catch {
                $duplicateRejected = $_.Exception.Message -ceq
                    'The combat-canary configuration is not the exact loopback baseline policy'
            }
        } finally {
            [System.IO.File]::WriteAllBytes(
                $configurationPath, $originalConfigurationBytes)
            [System.IO.File]::WriteAllBytes(
                $canary.InstallRecord, $originalInstallationBytes)
            Set-PSOBBProtectedAcl -Path $canary.InstallRecord
        }
        Add-Result 'inline or escaped duplicate critical config key is rejected' `
            $duplicateRejected 'hash binding aligned before verifier call'
    }
    Complete-TestSection

    Start-TestSection 'ResetTransactions'
    $sealedManifest = Get-Content -Raw -LiteralPath (
        Join-Path $created.SnapshotPath 'manifest.json') |
        ConvertFrom-Json -Depth 20 -DateKind String
    $systemEntry = @($sealedManifest.files | Where-Object {
            [string]$_.role -ceq 'twills-system'
        })
    if ($systemEntry.Count -ne 1) {
        throw 'The dynamic reset fixture has no singular system-state payload'
    }
    $resetParameters = @{
        RuntimeRoot = $layout.Root
        SnapshotPath = $created.SnapshotPath
        ExpectedBuildContractSha256 = $buildContractHash
        ExpectedTwillsContractSha256 = $contractHash
        ExpectedSigningPublicKeySpkiSha256 = $spkiFingerprint
        Confirm = $false
    }
    $resetTeamEntry = @($sealedManifest.files | Where-Object {
            [string]$_.role -ceq 'team-state'
        })
    if ($resetTeamEntry.Count -ne 1) {
        throw 'The reset copy-fault fixture has no singular team payload'
    }
    $resetTeamPath = Join-Path $created.SnapshotPath (
        ([string]$resetTeamEntry[0].path).Replace('/', '\'))
    $resetTeamBytes = [System.IO.File]::ReadAllBytes($resetTeamPath)
    $preResetCopyFingerprint = Get-TestMutableCanaryFingerprint -Layout $canary
    $resetOversizeHook = {
        [System.IO.File]::WriteAllBytes(
            $resetTeamPath, [byte[]]::new((1MB) + 1))
    }.GetNewClosure()
    $resetOversizeRejected = $false
    try {
        try {
            & (Join-Path $transactionScriptsRoot `
                'Reset-PSOBBCombatCanaryState.ps1') `
                @resetParameters `
                -InternalTestBeforePayloadCopy $resetOversizeHook `
                -InternalTestFaultToken $fixtureInstallationId | Out-Null
        } catch {
            $resetOversizeRejected = $true
        }
    } finally {
        [System.IO.File]::WriteAllBytes($resetTeamPath, $resetTeamBytes)
        Set-PSOBBProtectedTreeAcl -Path $created.SnapshotPath `
            -Root $canary.Snapshots
    }
    $resetOversizeClean = $resetOversizeRejected -and
        (Get-TestMutableCanaryFingerprint -Layout $canary) -ceq
            $preResetCopyFingerprint -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
            -Directory | Where-Object {
                $_.Name -like '.state-stage-*' -or
                $_.Name -like '.state-rollback-*'
            }).Count -eq 0
    Add-Result 'Reset rejects a post-validation oversized state source' `
        $resetOversizeClean 'installed state and transaction inventory remained exact'

    $resetSwapSaved = $resetTeamPath + '.swap-attempt'
    $resetSwapHook = {
        param([string]$Path)
        if ($Path -ieq $resetTeamPath) {
            [System.IO.File]::Move($Path, $resetSwapSaved, $false)
        }
    }.GetNewClosure()
    $resetSwapRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Reset-PSOBBCombatCanaryState.ps1') `
            @resetParameters `
            -InternalTestAfterPayloadSourceLease $resetSwapHook `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $resetSwapRejected = $true
    }
    $resetSwapClean = $resetSwapRejected -and
        -not (Test-Path -LiteralPath $resetSwapSaved) -and
        (Get-LowerSha256 $resetTeamPath) -ceq
            [string]$resetTeamEntry[0].sha256 -and
        (Get-TestMutableCanaryFingerprint -Layout $canary) -ceq
            $preResetCopyFingerprint -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
            -Directory | Where-Object {
                $_.Name -like '.state-stage-*' -or
                $_.Name -like '.state-rollback-*'
            }).Count -eq 0
    Add-Result 'Reset blocks state-source replacement while leased' `
        $resetSwapClean 'source and installed state identities remained exact'

    $installedSystemPath = Join-Path $canary.Server (
        ([string]$systemEntry[0].path).Substring('state/'.Length).Replace('/', '\'))
    $mutatedBytes = [System.IO.File]::ReadAllBytes($installedSystemPath)
    $mutatedBytes[0] = $mutatedBytes[0] -bxor 1
    [System.IO.File]::WriteAllBytes($installedSystemPath, $mutatedBytes)
    $mutatedFingerprint = Get-TestMutableCanaryFingerprint -Layout $canary
    $installMoveRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot 'Reset-PSOBBCombatCanaryState.ps1') `
            @resetParameters -InternalTestFailInstallMove `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $installMoveRejected = $_.Exception.Message -ceq
            'Injected temporary-fixture installation move failure'
    }
    $transactionDebris = @(Get-ChildItem -Force `
        -LiteralPath $canary.EnvironmentRoot | Where-Object {
            $_.Name -like '.state-stage-*' -or
            $_.Name -like '.state-rollback-*' -or
            $_.Name -like 'installation.json.new-*'
        })
    $installMoveCompensated = $installMoveRejected -and
        $transactionDebris.Count -eq 0 -and
        (Get-TestMutableCanaryFingerprint -Layout $canary) -ceq
            $mutatedFingerprint
    Add-Result 'Reset install-move failure restores old install with no debris' `
        $installMoveCompensated 'stage rollback and legacy sibling temp absent'
    if (-not $installMoveCompensated) {
        throw 'The deterministic reset installation-move fixture did not compensate exactly'
    }

    $resetCompensationExact = $true
    $resetBoundariesPassed = 0
    for ($boundary = 1; $boundary -le 5; $boundary++) {
        $rejected = $false
        try {
            & (Join-Path $transactionScriptsRoot 'Reset-PSOBBCombatCanaryState.ps1') `
                @resetParameters -InternalTestFailAfterSwap $boundary `
                -InternalTestFaultToken $fixtureInstallationId | Out-Null
        } catch {
            $rejected = $_.Exception.Message -ceq
                'Injected temporary-fixture reset swap failure'
        }
        if (-not $rejected -or
            (Get-TestMutableCanaryFingerprint -Layout $canary) -cne
                $mutatedFingerprint) {
            $resetCompensationExact = $false
            break
        }
        $resetBoundariesPassed++
    }
    Add-Result 'Reset compensates exactly after every swap boundary' `
        $resetCompensationExact "boundaries=$resetBoundariesPassed/5"
    if (-not $resetCompensationExact) {
        throw "Reset compensation failed at boundary $boundary"
    }

    $incompleteRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot 'Reset-PSOBBCombatCanaryState.ps1') `
            @resetParameters -InternalTestFailAfterSwap 1 `
            -InternalTestFaultToken $fixtureInstallationId `
            -InternalTestLeaveCompensationIncomplete | Out-Null
    } catch {
        $incompleteRejected = $_.Exception.Message -like
            'Combat-canary reset failed and compensation was incomplete for:*'
    }
    $rollbackEvidence = @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
        -Directory -Filter '.state-rollback-*')
    $evidenceRetained = $incompleteRejected -and $rollbackEvidence.Count -eq 1 -and
        (Test-Path -LiteralPath (Join-Path $rollbackEvidence[0].FullName 'licenses') `
            -PathType Container) -and
        (Test-PSOBBProtectedAcl -Path $rollbackEvidence[0].FullName)
    Add-Result 'incomplete compensation retains protected rollback evidence' `
        $evidenceRetained 'one protected rollback tree retained'
    if ($rollbackEvidence.Count -eq 1) {
        $installedLicenses = Join-Path $canary.Server 'system\licenses'
        if (Test-Path -LiteralPath $installedLicenses) {
            Remove-Item -LiteralPath $installedLicenses -Recurse -Force
        }
        Move-Item -LiteralPath (Join-Path $rollbackEvidence[0].FullName 'licenses') `
            -Destination $installedLicenses
        Remove-Item -LiteralPath $rollbackEvidence[0].FullName -Recurse -Force
    }
    if ((Get-TestMutableCanaryFingerprint -Layout $canary) -cne
        $mutatedFingerprint) {
        throw 'The dynamic fixture could not safely repair retained rollback evidence'
    }

    $restored = & (Join-Path $transactionScriptsRoot 'Reset-PSOBBCombatCanaryState.ps1') `
        @resetParameters
    $installedAfterReset = & (Join-Path $transactionScriptsRoot 'Test-PSOBBCombatCanary.ps1') `
        -RuntimeRoot $layout.Root -Target Installed `
        -SnapshotPath $created.SnapshotPath `
        -ExpectedBuildContractSha256 $buildContractHash `
        -ExpectedTwillsContractSha256 $contractHash `
        -ExpectedSigningPublicKeySpkiSha256 $spkiFingerprint
    $expectedState = @($sealedManifest.files | Where-Object {
            [string]$_.path -cmatch '^state/system/'
        } | ForEach-Object {
            [pscustomobject]@{
                path = ([string]$_.path).Substring('state/system/'.Length)
                size = [int64]$_.size
                sha256 = [string]$_.sha256
            }
        })
    $actualState = @(Get-PSOBBDirectoryManifest `
        -Root (Join-Path $canary.Server 'system') | Where-Object {
            [string]$_.path -cmatch '^(?:licenses|players|teams)/'
        })
    Add-Result 'Reset restores exact sealed Twills state and installed identity' (
        [bool]$restored.Restored -and [bool]$installedAfterReset.Valid -and
        (Test-PSOBBManifestEntriesEqual -Left $expectedState -Right $actualState)) `
        "stateFiles=$($expectedState.Count)"

    $resetSubstitution = [pscustomobject]@{
        Published = ''
        Saved = ''
    }
    $resetSubstitutionHook = {
        param([string]$Path, [string]$Name)
        if ([string]::IsNullOrWhiteSpace($resetSubstitution.Published)) {
            $resetSubstitution.Published = $Path
            $resetSubstitution.Saved = $Path + '.owned-evidence'
            [System.IO.Directory]::Move($Path, $resetSubstitution.Saved)
            [void][System.IO.Directory]::CreateDirectory($Path)
            [System.IO.File]::WriteAllText(
                (Join-Path $Path '.replacement-evidence'), 'replacement',
                [System.Text.UTF8Encoding]::new($false))
        }
    }.GetNewClosure()
    $resetSubstitutionRejected = $false
    try {
        & (Join-Path $transactionScriptsRoot `
            'Reset-PSOBBCombatCanaryState.ps1') `
            @resetParameters `
            -InternalTestAfterPublishedMove $resetSubstitutionHook `
            -InternalTestFaultToken $fixtureInstallationId | Out-Null
    } catch {
        $resetSubstitutionRejected = $_.Exception.Message -like
            'Combat-canary reset failed and compensation was incomplete for:*'
    }
    $resetSubstitutionRollback = @(Get-ChildItem -Force `
        -LiteralPath $canary.EnvironmentRoot -Directory `
        -Filter '.state-rollback-*')
    $resetSubstitutionRetained = $resetSubstitutionRejected -and
        (Test-Path -LiteralPath $resetSubstitution.Published `
            -PathType Container) -and
        (Test-Path -LiteralPath $resetSubstitution.Saved `
            -PathType Container) -and
        $resetSubstitutionRollback.Count -eq 1 -and
        (Test-Path -LiteralPath (Join-Path `
                $resetSubstitutionRollback[0].FullName 'licenses') `
            -PathType Container) -and
        @(Get-ChildItem -Force -LiteralPath $canary.EnvironmentRoot `
            -Directory -Filter '.state-stage-*').Count -eq 0
    Add-Result 'Reset retains post-publication substitution evidence' `
        $resetSubstitutionRetained `
        'replacement, published, and rollback identities were retained'
    Complete-TestSection
    }

    Start-TestSection 'StableInvariance'
    $stableAfter = Get-PSOBBDirectoryManifest -Root $stable.EnvironmentRoot
    $stableUnchanged = Test-PSOBBManifestEntriesEqual `
        -Left $stableBefore -Right $stableAfter
    if ($Mode -eq 'All') {
        $canonicalStableAfter = Get-PSOBBDirectoryManifest `
            -Root (Join-Path $canonicalLayout.Server 'system')
        $stableUnchanged = $stableUnchanged -and
            (Test-PSOBBManifestEntriesEqual `
                -Left $canonicalStableBefore -Right $canonicalStableAfter)
    }
    Add-Result 'Stable bytes remain unchanged' $stableUnchanged `
        "fixtureFiles=$($stableAfter.Count)"
    Complete-TestSection
} finally {
    if ($null -ne $script:ActiveSection) {
        $script:ActiveSection.Stopwatch.Stop()
        Write-Host (
            '[combat-canary-state] section-aborted name={0} durationMs={1}' -f
            $script:ActiveSection.Name,
            [int64][Math]::Round(
                $script:ActiveSection.Stopwatch.Elapsed.TotalMilliseconds))
    }
    Remove-TestTemporaryTree -Root $temporaryRoot
}

$overallStopwatch.Stop()
$results | Format-Table -AutoSize
$sectionTimings | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -ne 0) {
    throw "$($failed.Count) combat-canary state test(s) failed"
}
[pscustomobject]@{
    Valid = $true
    Tests = $results.Count
    Passed = $results.Count
    Mode = $Mode
    DurationMilliseconds = [int64][Math]::Round(
        $overallStopwatch.Elapsed.TotalMilliseconds)
    Sections = @($sectionTimings)
}
