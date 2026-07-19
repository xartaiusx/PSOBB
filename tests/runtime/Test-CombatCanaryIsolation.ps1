[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Detail
    )
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Test-ExactPath {
    param(
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][string]$Expected
    )
    ([System.IO.Path]::GetFullPath($Actual)).Equals(
        [System.IO.Path]::GetFullPath($Expected),
        [System.StringComparison]::OrdinalIgnoreCase)
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-CombatCanaryLayout-' + [Guid]::NewGuid().ToString('N'))
$outsideRoot = $temporaryRoot + '-outside'
$junction = Join-Path $temporaryRoot 'combat-canary\server'
try {
    $layout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    $expectedLayoutProperties = @(
        'Archives',
        'Backups',
        'BaseClient',
        'BaseClientManifest',
        'Canary',
        'Client',
        'CombatCanary',
        'ControlDirectory',
        'ControlRequest',
        'ControlState',
        'HostPidFile',
        'InstallRecord',
        'LegacyPidFile',
        'LocalLab',
        'Logs',
        'PidFile',
        'Root',
        'RuntimeMarker',
        'Secrets',
        'Server',
        'ServerBase',
        'Stable') | Sort-Object
    $actualLayoutProperties = @($layout.PSObject.Properties.Name | Sort-Object)
    Add-Result 'base layout adds only the combat-canary root' `
        (@(Compare-Object $expectedLayoutProperties $actualLayoutProperties).Count -eq 0) `
        'all prior Get-PSOBBLayout properties remain present with one new root property'

    $expectedEnvironmentProperties = @(
        'Backups',
        'BaseClient',
        'BaseClientManifest',
        'Builds',
        'Client',
        'ControlDirectory',
        'ControlRequest',
        'ControlState',
        'Environment',
        'EnvironmentId',
        'EnvironmentRoot',
        'HostPidFile',
        'InstallRecord',
        'LegacyPidFile',
        'Logs',
        'PidFile',
        'Root',
        'RuntimeMarker',
        'Secrets',
        'Server',
        'ServerBase',
        'Snapshots') | Sort-Object

    $stable = Get-PSOBBServerEnvironmentLayout -Layout $layout
    $stableProperties = @($stable.PSObject.Properties.Name | Sort-Object)
    Add-Result 'stable environment exposes the exact server-helper shape' `
        (@(Compare-Object $expectedEnvironmentProperties $stableProperties).Count -eq 0) `
        'the environment projection is explicit and contains no ambiguous graphics channel fields'

    $stablePathsExact =
        $stable.Environment -ceq 'Stable' -and
        $stable.EnvironmentId -ceq 'stable' -and
        (Test-ExactPath $stable.Root $temporaryRoot) -and
        (Test-ExactPath $stable.EnvironmentRoot (Join-Path $temporaryRoot 'stable')) -and
        (Test-ExactPath $stable.ServerBase (Join-Path $temporaryRoot 'stable\server-base\release')) -and
        (Test-ExactPath $stable.Server (Join-Path $temporaryRoot 'stable\server\release')) -and
        (Test-ExactPath $stable.Client (Join-Path $temporaryRoot 'stable\runtime\client')) -and
        (Test-ExactPath $stable.ControlDirectory (Join-Path $temporaryRoot 'stable\control')) -and
        (Test-ExactPath $stable.PidFile (Join-Path $temporaryRoot 'stable\control\newserv.process.json')) -and
        (Test-ExactPath $stable.LegacyPidFile (Join-Path $temporaryRoot 'stable\control\newserv.pid')) -and
        (Test-ExactPath $stable.HostPidFile (Join-Path $temporaryRoot 'stable\control\newserv-host.pid')) -and
        (Test-ExactPath $stable.ControlState (Join-Path $temporaryRoot 'stable\control\newserv-control.json')) -and
        (Test-ExactPath $stable.ControlRequest (Join-Path $temporaryRoot 'stable\control\newserv-control.request.json')) -and
        (Test-ExactPath $stable.InstallRecord (Join-Path $temporaryRoot 'stable\installation.json')) -and
        (Test-ExactPath $stable.Backups (Join-Path $temporaryRoot 'backups')) -and
        (Test-ExactPath $stable.Logs (Join-Path $temporaryRoot 'logs')) -and
        (Test-ExactPath $stable.Snapshots (Join-Path $temporaryRoot 'backups')) -and
        (Test-ExactPath $stable.Builds (Join-Path $temporaryRoot 'stable\server-base')) -and
        (Test-ExactPath $stable.RuntimeMarker (Join-Path $temporaryRoot '.psobb-runtime.json')) -and
        (Test-ExactPath $stable.BaseClient (Join-Path $temporaryRoot 'stable\client')) -and
        (Test-ExactPath $stable.BaseClientManifest (Join-Path $temporaryRoot 'stable\base-client.manifest.json')) -and
        (Test-ExactPath $stable.Secrets (Join-Path $temporaryRoot 'secrets'))
    Add-Result 'stable environment preserves every established path' `
        $stablePathsExact `
        'default server selection remains backward compatible'

    $combatCanary = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment ' combat-canary '
    $combatCanaryProperties = @($combatCanary.PSObject.Properties.Name | Sort-Object)
    $canaryRoot = Join-Path $temporaryRoot 'combat-canary'
    $combatCanaryPathsExact =
        @(Compare-Object $expectedEnvironmentProperties $combatCanaryProperties).Count -eq 0 -and
        $combatCanary.Environment -ceq 'CombatCanary' -and
        $combatCanary.EnvironmentId -ceq 'combat-canary' -and
        (Test-ExactPath $combatCanary.EnvironmentRoot $canaryRoot) -and
        (Test-ExactPath $combatCanary.ServerBase (Join-Path $canaryRoot 'server-base\release')) -and
        (Test-ExactPath $combatCanary.Server (Join-Path $canaryRoot 'server\release')) -and
        (Test-ExactPath $combatCanary.Client (Join-Path $canaryRoot 'runtime\client')) -and
        (Test-ExactPath $combatCanary.ControlDirectory (Join-Path $canaryRoot 'control')) -and
        (Test-ExactPath $combatCanary.PidFile (Join-Path $canaryRoot 'control\newserv.process.json')) -and
        (Test-ExactPath $combatCanary.LegacyPidFile (Join-Path $canaryRoot 'control\newserv.pid')) -and
        (Test-ExactPath $combatCanary.HostPidFile (Join-Path $canaryRoot 'control\newserv-host.pid')) -and
        (Test-ExactPath $combatCanary.ControlState (Join-Path $canaryRoot 'control\newserv-control.json')) -and
        (Test-ExactPath $combatCanary.ControlRequest (Join-Path $canaryRoot 'control\newserv-control.request.json')) -and
        (Test-ExactPath $combatCanary.InstallRecord (Join-Path $canaryRoot 'installation.json')) -and
        (Test-ExactPath $combatCanary.Backups (Join-Path $canaryRoot 'backups')) -and
        (Test-ExactPath $combatCanary.Logs (Join-Path $canaryRoot 'logs')) -and
        (Test-ExactPath $combatCanary.Snapshots (Join-Path $canaryRoot 'snapshots')) -and
        (Test-ExactPath $combatCanary.Builds (Join-Path $canaryRoot 'builds')) -and
        (Test-ExactPath $combatCanary.RuntimeMarker (Join-Path $temporaryRoot '.psobb-runtime.json')) -and
        (Test-ExactPath $combatCanary.BaseClient (Join-Path $canaryRoot 'client')) -and
        (Test-ExactPath $combatCanary.BaseClientManifest (Join-Path $canaryRoot 'base-client.manifest.json')) -and
        (Test-ExactPath $combatCanary.Secrets (Join-Path $canaryRoot 'secrets'))
    Add-Result 'combat canary maps every mutable path beneath its own root' `
        $combatCanaryPathsExact `
        'server, client, control, evidence, snapshots, builds, and secrets are isolated'

    Add-Result 'graphics canary remains distinct from combat canary' `
        ((Test-ExactPath $layout.Canary (Join-Path $temporaryRoot 'canary')) -and
         (Test-ExactPath $layout.CombatCanary $canaryRoot) -and
         -not (Test-ExactPath $layout.Canary $layout.CombatCanary)) `
        'the established graphics channel retains PSOBB-Runtime\canary'

    $graphicsCanaryRejected = $false
    try {
        Get-PSOBBServerEnvironmentLayout -Layout $layout -Environment Canary | Out-Null
    } catch {
        $graphicsCanaryRejected = $_.Exception.Message -match 'Stable or CombatCanary'
    }
    Add-Result 'graphics canary is rejected as a server environment name' `
        $graphicsCanaryRejected `
        'normalization cannot silently alias graphics Canary to CombatCanary'

    $isolation = Assert-PSOBBServerEnvironmentIsolation -Layout $layout
    Add-Result 'stable and combat-canary mutable paths are pairwise disjoint' `
        ($isolation.Passed -and
         $isolation.StablePathsChecked -eq 9 -and
         $isolation.CombatCanaryPathsChecked -eq 9 -and
         $isolation.PairwiseChecks -eq 81) `
        'server, client, control, logs, backups, account trees, and snapshots cannot overlap'

    $overlapLayout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    $overlapLayout.CombatCanary = $overlapLayout.Stable
    $overlapRejected = $false
    try {
        Assert-PSOBBServerEnvironmentIsolation -Layout $overlapLayout | Out-Null
    } catch {
        $overlapRejected = $_.Exception.Message -match 'overlaps CombatCanary'
    }
    Add-Result 'equal or ancestor-overlapping environment paths fail closed' `
        $overlapRejected `
        'a tampered combat-canary root cannot resolve into Stable'

    $networkLayout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    $networkLayout.Root = '\\server\share\PSOBB-Runtime'
    $localVolumeRejected = $false
    try {
        Get-PSOBBServerEnvironmentLayout -Layout $networkLayout | Out-Null
    } catch {
        $localVolumeRejected = $_.Exception.Message -match 'local Windows volume'
    }
    Add-Result 'server environment roots reject network paths' `
        $localVolumeRejected `
        'server state cannot resolve onto a UNC share'

    $baseTargets = @(Get-PSOBBRuntimeAclTargets -Layout $layout)
    Add-Result 'absent combat canary does not expand the stable ACL inventory' `
        ($baseTargets.Count -eq 11 -and
         @($baseTargets.Name | Where-Object { $_ -like 'combat-canary-*' }).Count -eq 0) `
        'optional canary ACL targets appear only after their sensitive trees exist'

    New-Item -ItemType Directory -Path $combatCanary.Logs -Force | Out-Null
    New-Item -ItemType Directory -Path $combatCanary.Snapshots -Force | Out-Null
    $partialTargets = @(Get-PSOBBRuntimeAclTargets -Layout $layout)
    $partialCanaryTargets = @($partialTargets | Where-Object {
            $_.Name -like 'combat-canary-*'
        } | Sort-Object Name)
    $partialTargetIdentity =
        $partialTargets.Count -eq 13 -and
        $partialCanaryTargets.Count -eq 2 -and
        $partialCanaryTargets[0].Name -ceq 'combat-canary-logs' -and
        (Test-ExactPath $partialCanaryTargets[0].Path $combatCanary.Logs) -and
        $partialCanaryTargets[1].Name -ceq 'combat-canary-snapshots' -and
        (Test-ExactPath $partialCanaryTargets[1].Path $combatCanary.Snapshots)
    Add-Result 'existing combat-canary ACL targets have exact names and paths' `
        $partialTargetIdentity `
        'adaptive target discovery neither invents absent trees nor aliases stable paths'

    New-Item -ItemType Directory -Path (Split-Path -Parent $junction) -Force | Out-Null
    New-Item -ItemType Directory -Path $outsideRoot -Force | Out-Null
    New-Item -ItemType Junction -Path $junction -Target $outsideRoot | Out-Null
    $nestedJunctionRejected = $false
    try {
        Get-PSOBBServerEnvironmentLayout -Layout $layout -Environment CombatCanary | Out-Null
    } catch {
        $nestedJunctionRejected = $_.Exception.Message -match 'traverses a reparse point'
    }
    Add-Result 'nested combat-canary junctions fail closed' `
        $nestedJunctionRejected `
        'environment paths are reparse-safe before any mutable operation'
    [System.IO.Directory]::Delete($junction)
} finally {
    if (Test-Path -LiteralPath $junction) {
        [System.IO.Directory]::Delete($junction)
    }
    foreach ($candidate in @($temporaryRoot, $outsideRoot)) {
        if (Test-Path -LiteralPath $candidate) {
            $safeCandidate = [System.IO.Path]::GetFullPath($candidate)
            $tempPrefix = [System.IO.Path]::GetFullPath(
                [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
            if (-not $safeCandidate.StartsWith(
                    $tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
                -not ([System.IO.Path]::GetFileName($safeCandidate)).StartsWith(
                    'PSOBB-CombatCanaryLayout-', [System.StringComparison]::Ordinal)) {
                throw 'Refusing to remove an unexpected combat-canary layout test directory'
            }
            Remove-Item -LiteralPath $safeCandidate -Recurse -Force
        }
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) combat-canary isolation test(s) failed"
}
[pscustomobject]@{
    Suite = 'CombatCanaryIsolation'
    Passed = $results.Count
    Failed = 0
}
