[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Detail
    )
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

$savedEnvironmentRoot = $env:PSOBB_RUNTIME_ROOT
try {
    $env:PSOBB_RUNTIME_ROOT = $null
    $canonicalRuntime = [System.IO.Path]::GetFullPath(
        (Join-Path $repositoryRoot 'PSOBB-Runtime')).TrimEnd('\')

    $defaultRuntime = Get-PSOBBRuntimeRoot
    Add-Result 'default runtime is the canonical nested directory' `
        $defaultRuntime.Equals($canonicalRuntime, [System.StringComparison]::OrdinalIgnoreCase) `
        $defaultRuntime

    $layout = Get-PSOBBLayout -RuntimeRoot $canonicalRuntime
    $stableEnvironment = Get-PSOBBServerEnvironmentLayout -Layout $layout
    Add-Result 'default server environment preserves the stable layout' `
        ($stableEnvironment.Environment -ceq 'Stable' -and
         $stableEnvironment.EnvironmentId -ceq 'stable' -and
         $stableEnvironment.EnvironmentRoot -ceq $layout.Stable -and
         $stableEnvironment.ServerBase -ceq $layout.ServerBase -and
         $stableEnvironment.Server -ceq $layout.Server -and
         $stableEnvironment.Client -ceq $layout.Client -and
         $stableEnvironment.ControlDirectory -ceq $layout.ControlDirectory -and
         $stableEnvironment.Backups -ceq $layout.Backups -and
         $stableEnvironment.Logs -ceq $layout.Logs -and
         $stableEnvironment.Snapshots -ceq $layout.Backups) `
        'omitting -Environment remains byte-for-byte mapped to Stable paths'

    Add-Result 'combat canary does not replace the graphics canary root' `
        ($layout.Canary -ceq (Join-Path $canonicalRuntime 'canary') -and
         $layout.CombatCanary -ceq (Join-Path $canonicalRuntime 'combat-canary') -and
         $layout.Canary -cne $layout.CombatCanary) `
        'graphics canary and combat-canary remain distinct runtime namespaces'

    & git -C $repositoryRoot check-ignore -q --no-index -- 'PSOBB-Runtime/probe.bin'
    Add-Result 'Git ignores the canonical runtime recursively' ($LASTEXITCODE -eq 0) `
        'git check-ignore accepted an untracked runtime probe'

    $trackedRuntimeFiles = @(& git -C $repositoryRoot ls-files -- 'PSOBB-Runtime')
    Add-Result 'no canonical runtime file is tracked' ($LASTEXITCODE -eq 0 -and $trackedRuntimeFiles.Count -eq 0) `
        "$($trackedRuntimeFiles.Count) tracked runtime path(s)"

    $nestedEvidence = Join-Path $canonicalRuntime 'graphics-evidence\probe.csv'
    $acceptedEvidence = Assert-PSOBBPathOutsideTrackedSource `
        -Path $nestedEvidence `
        -Purpose 'Test evidence'
    Add-Result 'ignored runtime state is accepted inside the project home' `
        $acceptedEvidence.Equals(
            [System.IO.Path]::GetFullPath($nestedEvidence),
            [System.StringComparison]::OrdinalIgnoreCase) `
        $acceptedEvidence

    $arbitraryNestedRejected = $false
    try {
        Get-PSOBBRuntimeRoot -RuntimeRoot (Join-Path $repositoryRoot 'runtime-other') | Out-Null
    } catch {
        $arbitraryNestedRejected = $_.Exception.Message -match 'Only the canonical ignored'
    }
    Add-Result 'arbitrary in-repository runtime roots fail closed' $arbitraryNestedRejected `
        'only PSOBB-Runtime is allowed beneath the repository root'

    $trackedSourceRejected = $false
    try {
        Assert-PSOBBPathOutsideTrackedSource `
            -Path (Join-Path $repositoryRoot 'config\graphics-evidence.json') `
            -Purpose 'Test evidence' | Out-Null
    } catch {
        $trackedSourceRejected = $_.Exception.Message -match 'outside Git-tracked source'
    }
    Add-Result 'private state in tracked source fails closed' $trackedSourceRejected `
        'tracked configuration cannot be mistaken for private runtime evidence'

    $outsideRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('psobb-layout-test-' + [Guid]::NewGuid().ToString('N'))
    $resolvedOutside = Get-PSOBBRuntimeRoot -RuntimeRoot $outsideRoot
    Add-Result 'explicit isolated local runtime roots remain supported' `
        $resolvedOutside.Equals(
            [System.IO.Path]::GetFullPath($outsideRoot),
            [System.StringComparison]::OrdinalIgnoreCase) `
        $resolvedOutside

    $graphicsValidatorSource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'scripts\Test-PSOBBGraphicsProfiles.ps1')
    $graphicsRuntimePortable =
        $graphicsValidatorSource -match '\[string\]\$RuntimeRoot' -and
        $graphicsValidatorSource -match 'Get-PSOBBRuntimeRoot -RuntimeRoot \$RequestedRuntimeRoot' -and
        $graphicsValidatorSource -match '\$root = if \(\$scope -ceq ''repo''\)'
    Add-Result 'graphics evidence resolves the selected runtime root' `
        $graphicsRuntimePortable `
        'runtime-scoped artifacts honor -RuntimeRoot and PSOBB_RUNTIME_ROOT'

    $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('psobb-layout-git-' + [Guid]::NewGuid().ToString('N'))
    $fixtureRuntime = Join-Path $fixtureRoot 'PSOBB-Runtime'
    $fixtureEvidence = Join-Path $fixtureRuntime 'graphics-evidence'
    $fixtureTracked = Join-Path $fixtureRoot 'tracked-source'
    $fixtureJunction = Join-Path $fixtureEvidence 'escape'
    $savedRepositoryRoot = $script:PSOBBRepositoryRoot
    $savedCanonicalRuntimeRoot = $script:PSOBBCanonicalRuntimeRoot
    try {
        New-Item -ItemType Directory -Path $fixtureEvidence -Force | Out-Null
        New-Item -ItemType Directory -Path $fixtureTracked -Force | Out-Null
        [System.IO.File]::WriteAllText(
            (Join-Path $fixtureRoot '.gitignore'),
            "/PSOBB-Runtime/`r`n",
            [System.Text.UTF8Encoding]::new($false))
        & git -C $fixtureRoot init --quiet
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not initialize the temporary Git boundary fixture'
        }
        $script:PSOBBRepositoryRoot = $fixtureRoot
        $script:PSOBBCanonicalRuntimeRoot = $fixtureRuntime

        Assert-PSOBBCanonicalRuntimeIgnoreContract
        [System.IO.File]::AppendAllText(
            (Join-Path $fixtureRoot '.gitignore'),
            "!/PSOBB-Runtime/`r`n!/PSOBB-Runtime/**`r`n",
            [System.Text.UTF8Encoding]::new($false))
        $negatedIgnoreRejected = $false
        try {
            Assert-PSOBBCanonicalRuntimeIgnoreContract
        } catch {
            $negatedIgnoreRejected = $_.Exception.Message -match 'does not effectively ignore'
        }
        Add-Result 'later Git negation cannot reopen the runtime tree' `
            $negatedIgnoreRejected `
            'effective git check-ignore fails closed'

        [System.IO.File]::WriteAllText(
            (Join-Path $fixtureRoot '.gitignore'),
            (@(
                '/PSOBB-Runtime/',
                '!/PSOBB-Runtime/',
                '/PSOBB-Runtime/*',
                '!/PSOBB-Runtime/secrets/',
                '!/PSOBB-Runtime/secrets/**') -join "`r`n") + "`r`n",
            [System.Text.UTF8Encoding]::new($false))
        $targetedNegationRejected = $false
        try {
            Assert-PSOBBCanonicalRuntimeIgnoreContract
        } catch {
            $targetedNegationRejected = $_.Exception.Message -match 'complete canonical'
        }
        Add-Result 'targeted Git negation cannot reopen a sensitive runtime subtree' `
            $targetedNegationRejected `
            'closed representative probes include runtime secrets'

        [System.IO.File]::WriteAllText(
            (Join-Path $fixtureRoot '.gitignore'),
            "/PSOBB-Runtime/`r`n",
            [System.Text.UTF8Encoding]::new($false))
        $forceTrackedPath = Join-Path $fixtureRuntime 'force-tracked.secret'
        [System.IO.File]::WriteAllText(
            $forceTrackedPath,
            'fixture',
            [System.Text.UTF8Encoding]::new($false))
        & git -C $fixtureRoot add -f -- 'PSOBB-Runtime/force-tracked.secret'
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not stage the temporary force-tracked fixture'
        }
        $forceTrackedRejected = $false
        try {
            Assert-PSOBBCanonicalRuntimeIgnoreContract
        } catch {
            $forceTrackedRejected = $_.Exception.Message -match 'already tracks 1 path'
        }
        Add-Result 'force-tracked runtime content fails closed' `
            $forceTrackedRejected `
            'git ls-files detects indexed runtime state even when ignored'
        & git -C $fixtureRoot rm --cached --quiet -- 'PSOBB-Runtime/force-tracked.secret'
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not clear the temporary force-tracked fixture'
        }

        New-Item -ItemType Junction -Path $fixtureJunction -Target $fixtureTracked | Out-Null
        $reparseEscapeRejected = $false
        try {
            Assert-PSOBBPathOutsideTrackedSource `
                -Path (Join-Path $fixtureJunction 'private-output.png') `
                -Purpose 'Test evidence' | Out-Null
        } catch {
            $reparseEscapeRejected = $_.Exception.Message -match 'traverses a reparse point'
        }
        Add-Result 'runtime reparse escapes fail closed' `
            $reparseEscapeRejected `
            'lexical containment cannot redirect private output into tracked source'
    } finally {
        $script:PSOBBRepositoryRoot = $savedRepositoryRoot
        $script:PSOBBCanonicalRuntimeRoot = $savedCanonicalRuntimeRoot
        if (Test-Path -LiteralPath $fixtureJunction) {
            Remove-Item -LiteralPath $fixtureJunction -Force
        }
        if (Test-Path -LiteralPath $fixtureRoot) {
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
        }
    }
} finally {
    $env:PSOBB_RUNTIME_ROOT = $savedEnvironmentRoot
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) project-layout test(s) failed"
}
[pscustomobject]@{
    Suite = 'ProjectLayout'
    Passed = $results.Count
    Failed = 0
}
