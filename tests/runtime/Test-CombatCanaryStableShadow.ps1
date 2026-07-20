[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.Common.ps1')

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

function Import-FunctionDefinition {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    $definitions = @($ast.FindAll({
                param($node)
                $node -is
                    [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $Name
            }, $true))
    if (@($errors).Count -ne 0 -or $definitions.Count -ne 1) {
        throw "Function $Name is not uniquely parseable"
    }
    [scriptblock]::Create($definitions[0].Extent.Text)
}

$contractPath = Join-Path $repositoryRoot 'config\combat-stable-shadow.json'
$schemaPath = Join-Path $repositoryRoot `
    'config\schemas\combat-stable-shadow.schema.json'
$contractText = Get-Content -Raw -LiteralPath $contractPath
$schemaValid = Test-Json -Json $contractText -SchemaFile $schemaPath
Add-Result 'StableShadow contract satisfies its exact schema' $schemaValid `
    'Draft 2020-12 validation passed'

$contractHash = Get-LowerSha256 $contractPath
$selections = @(Get-PSOBBCombatCanaryBuildContractSelection `
        -RepositoryRoot $repositoryRoot)
$shadowSelection = Get-PSOBBCombatCanaryBuildContractSelection `
    -RepositoryRoot $repositoryRoot -ExpectedSha256 $contractHash
$currentSelection = @($selections | Where-Object {
        [string]$_.Artifact -ceq 'CurrentUpstream'
    })
Add-Result 'dual contract selection is exact and unambiguous' (
    $selections.Count -eq 2 -and $currentSelection.Count -eq 1 -and
    [string]$shadowSelection.Artifact -ceq 'StableShadow' -and
    [string]$shadowSelection.ComponentId -ceq 'newserv-stable-release' -and
    [string]$shadowSelection.Hash -ceq $contractHash -and
    [string]$currentSelection[0].Hash -cne $contractHash) `
    'CurrentUpstream and StableShadow remain separate sealed identities'

$sourceLock = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'config\sources.lock.json') |
    ConvertFrom-Json -Depth 30 -DateKind String
$serverComponents = @($sourceLock.components | Where-Object {
        [string]$_.id -ceq
            [string]$shadowSelection.Value.source.serverComponentId
    })
$clientComponents = @($sourceLock.components | Where-Object {
        [string]$_.id -ceq
            [string]$shadowSelection.Value.source.clientComponentId
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
Add-Result 'StableShadow server and client identities match sources.lock' (
    $serverComponents.Count -eq 1 -and $clientComponents.Count -eq 1 -and
    $serverMembers.Count -eq 1 -and $clientMembers.Count -eq 1 -and
    [string]$serverComponents[0].commit -ceq
        [string]$shadowSelection.Value.source.serverCommit -and
    [string]$serverComponents[0].sha256 -ceq
        [string]$shadowSelection.Value.source.serverArchiveSha256 -and
    [int64]$serverMembers[0].size -eq
        [int64]$shadowSelection.Value.source.serverExecutable.size -and
    [string]$serverMembers[0].sha256 -ceq
        [string]$shadowSelection.Value.source.serverExecutable.sha256 -and
    [int64]$clientMembers[0].size -eq 6971904 -and
    [string]$clientMembers[0].sha256 -ceq
        'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535') `
    'release archive, executable, and exact 59NL client member are pinned'

$verifierPath = Join-Path $repositoryRoot `
    'scripts\Test-PSOBBCombatCanary.ps1'
$initializerPath = Join-Path $repositoryRoot `
    'scripts\Initialize-PSOBBCombatCanary.ps1'
. (Import-FunctionDefinition -Path $verifierPath `
    -Name 'Test-PSOBBCombatCanaryVerifierMutableServerExemptPath')
. (Import-FunctionDefinition -Path $verifierPath `
    -Name 'Assert-PSOBBCombatCanaryMetadataCache')
. (Import-FunctionDefinition -Path $initializerPath `
    -Name 'Move-PSOBBCombatInitializeNoClobber')
. (Import-FunctionDefinition -Path $initializerPath `
    -Name 'Publish-PSOBBCombatInitializeTarget')
. (Import-FunctionDefinition -Path $initializerPath `
    -Name 'Undo-PSOBBCombatInitializeTarget')

$exactCachePaths = @(
    'system/patch-bb/.metadata-cache.json',
    'system/patch-pc/.metadata-cache.json')
$nearMissCachePaths = @(
    'system/patch-bb/data/.metadata-cache.json',
    'system/patch-bb/.metadata-cache.json.extra',
    'system/patch-pc/.metadata-cache.json/child',
    'system/patch-gc/.metadata-cache.json')
Add-Result 'only the two exact generated metadata caches are exempt' (
    @($exactCachePaths | Where-Object {
            -not (Test-PSOBBCombatCanaryVerifierMutableServerExemptPath `
                -Path $_)
        }).Count -eq 0 -and
    @($nearMissCachePaths | Where-Object {
            Test-PSOBBCombatCanaryVerifierMutableServerExemptPath -Path $_
        }).Count -eq 0) `
    'no patch subtree or filename-prefix exemption exists'

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-stable-shadow-test-' + [Guid]::NewGuid().ToString('N'))
try {
    $serverRoot = Join-Path $fixtureRoot 'server'
    $cachePolicy = @($shadowSelection.Value.output.generatedMetadataCaches)[0]
    $cachePath = Join-Path $serverRoot (
        ([string]$cachePolicy.path).Replace('/', '\'))
    New-Item -ItemType Directory -Path (Split-Path -Parent $cachePath) `
        -Force | Out-Null
    [System.IO.File]::WriteAllText(
        $cachePath, '{"./data/item.bin":[1,2,3,[4,5]]}',
        [System.Text.UTF8Encoding]::new($false))
    $validCacheAccepted = $false
    $validCacheError = ''
    try {
        $validCacheAccepted =
            Assert-PSOBBCombatCanaryMetadataCache `
                -ServerRoot $serverRoot -Policy $cachePolicy
    } catch { $validCacheError = $_.Exception.Message }
    Add-Result 'bounded generated metadata cache shape is accepted' `
        $validCacheAccepted $(if ($validCacheAccepted) {
            'integer tuple and checksum array validated'
        } else { $validCacheError })

    [System.IO.File]::WriteAllText(
        $cachePath, '{"../escape":[1,2,3,[4]]}',
        [System.Text.UTF8Encoding]::new($false))
    $traversalRejected = $false
    try {
        Assert-PSOBBCombatCanaryMetadataCache `
            -ServerRoot $serverRoot -Policy $cachePolicy | Out-Null
    } catch { $traversalRejected = $true }
    [System.IO.File]::WriteAllText(
        $cachePath, '{"./data/item.bin":[1,2,3,[-1]]}',
        [System.Text.UTF8Encoding]::new($false))
    $negativeRejected = $false
    try {
        Assert-PSOBBCombatCanaryMetadataCache `
            -ServerRoot $serverRoot -Policy $cachePolicy | Out-Null
    } catch { $negativeRejected = $true }
    Add-Result 'unsafe generated metadata cache entries are rejected' (
        $traversalRejected -and $negativeRejected) `
        'path traversal and negative metadata both fail closed'
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

$swapFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-stable-shadow-swap-test-' + [Guid]::NewGuid().ToString('N'))
try {
    $stageRoot = Join-Path $swapFixtureRoot 'stage'
    $rollbackRoot = Join-Path $swapFixtureRoot 'rollback'
    $currentPath = Join-Path $swapFixtureRoot 'current'
    $stagedPath = Join-Path $stageRoot 'candidate'
    $rollbackPath = Join-Path $rollbackRoot 'current'
    New-Item -ItemType Directory -Path $currentPath, $stagedPath,
        $rollbackRoot -Force | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $currentPath 'payload.txt'), 'frozen-old',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        (Join-Path $stagedPath 'payload.txt'), 'candidate-new',
        [System.Text.UTF8Encoding]::new($false))
    $target = [pscustomobject]@{
        Name = 'current'
        Current = $currentPath
        Staged = $stagedPath
        Rollback = $rollbackPath
    }
    $processed = [System.Collections.Generic.List[object]]::new()
    $record = Publish-PSOBBCombatInitializeTarget `
        -Target $target -StageRoot $stageRoot `
        -RollbackRoot $rollbackRoot `
        -EnvironmentRoot $swapFixtureRoot -Replacement $true `
        -Processed $processed
    $replacementPublished =
        $processed.Count -eq 1 -and $record.HadCurrent -and
        $record.OldMoved -and $record.NewPublished -and
        [System.IO.File]::ReadAllText((
                Join-Path $currentPath 'payload.txt')) -ceq 'candidate-new' -and
        [System.IO.File]::ReadAllText((
                Join-Path $rollbackPath 'payload.txt')) -ceq 'frozen-old'
    Add-Result 'replacement publishes the candidate and retains the old tree' `
        $replacementPublished `
        'old and new directory identities remain separately owned'

    [void](Undo-PSOBBCombatInitializeTarget `
            -Record $record -EnvironmentRoot $swapFixtureRoot)
    Add-Result 'replacement compensation restores the exact old tree' (
        -not $record.OldMoved -and -not $record.NewPublished -and
        -not $record.NeedsCompensation -and
        -not (Test-Path -LiteralPath $rollbackPath) -and
        [System.IO.File]::ReadAllText((
                Join-Path $currentPath 'payload.txt')) -ceq 'frozen-old') `
        'candidate is removed by identity and the prior directory is restored'
} finally {
    if (Test-Path -LiteralPath $swapFixtureRoot) {
        Remove-Item -LiteralPath $swapFixtureRoot -Recurse -Force
    }
}

$initializerSource = Get-Content -Raw -LiteralPath $initializerPath
Add-Result 'StableShadow assembly uses only approved Stable source layers' (
    $initializerSource -match
        'StableServerBase[\s\S]*StablePatchData' -and
    $initializerSource -match
        'patchDataTargetRelativePath' -and
    $initializerSource -notmatch
        '-Source\s+\$stableLayout\.(?:Server|Secrets|Backups|Logs|ControlDirectory)' -and
    $initializerSource -notmatch 'Build-PSOBBCombatCanaryServer') `
    'no Stable mutable state, secret, control, log, backup, or newserv build source is used'
Add-Result 'replacement is staged, compensating, and preserves the prior install' (
    $initializerSource -match
        "Only exact CurrentUpstream-to-StableShadow replacement is permitted" -and
    $initializerSource -match 'OldMoved' -and
    $initializerSource -match 'NewPublished' -and
    $initializerSource -match 'frozen-installation\.json' -and
    $initializerSource -match 'frozen-current-upstream-') `
    'the existing CombatCanary tree is moved to bounded protected evidence after readback'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -ne 0) {
    throw "$($failed.Count) StableShadow test(s) failed"
}
[pscustomobject]@{
    Suite = 'CombatCanaryStableShadow'
    Total = $results.Count
    Passed = $results.Count
    Failed = 0
}
