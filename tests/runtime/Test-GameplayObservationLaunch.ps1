[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$clientPath = Join-Path $repositoryRoot 'scripts\Start-PSOBBClient.ps1'
$stopClientPath = Join-Path $repositoryRoot 'scripts\Stop-PSOBBClient.ps1'
$sessionPath = Join-Path $repositoryRoot 'scripts\Start-PSOBBSession.ps1'
$credentialPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1'
$clientSource = Get-Content -Raw -LiteralPath $clientPath
$stopClientSource = Get-Content -Raw -LiteralPath $stopClientPath
$sessionSource = Get-Content -Raw -LiteralPath $sessionPath
$credentialSource = Get-Content -Raw -LiteralPath $credentialPath
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

function Test-ThrowsMessage {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Pattern
    )

    try {
        & $Action
        $false
    } catch {
        $_.Exception.Message -match $Pattern
    }
}

function Set-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint32]$Value
    )

    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

function Set-UInt64LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint64]$Value
    )

    [BitConverter]::GetBytes($Value).CopyTo($Bytes, $Offset)
}

foreach ($scriptPath in @(
        $clientPath, $stopClientPath, $sessionPath, $credentialPath)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath,
        [ref]$tokens,
        [ref]$parseErrors) | Out-Null
    Add-Result `
        -Name "$(Split-Path -Leaf $scriptPath) parses cleanly" `
        -Passed ($parseErrors.Count -eq 0) `
        -Detail "$($parseErrors.Count) parser error(s)"
}

Add-Result `
    -Name 'observation evidence is a hidden explicit lifecycle option' `
    -Passed (
        $clientSource -match
            '\[Parameter\(DontShow\)\]\[switch\]\$GameplayObservationEvidence' -and
        $sessionSource -match
            '\[Parameter\(DontShow\)\]\[switch\]\$GameplayObservationEvidence' -and
        $sessionSource -match
            '-GameplayObservationEvidence:\$GameplayObservationEvidence') `
    -Detail 'ordinary launcher and shortcut behavior remains unchanged'

$clientEnvironmentGate = $clientSource.IndexOf(
    "serverEnvironmentName -cne 'CombatCanary'",
    [System.StringComparison]::Ordinal)
$clientLayoutResolution = $clientSource.IndexOf(
    'Get-PSOBBServerEnvironmentLayout',
    [System.StringComparison]::Ordinal)
$sessionEnvironmentGate = $sessionSource.IndexOf(
    "serverEnvironmentName -cne 'CombatCanary'",
    [System.StringComparison]::Ordinal)
$sessionLayoutResolution = $sessionSource.IndexOf(
    'Get-PSOBBServerEnvironmentLayout',
    [System.StringComparison]::Ordinal)
Add-Result `
    -Name 'Stable evidence requests fail before lifecycle work' `
    -Passed (
        $clientEnvironmentGate -ge 0 -and
        $clientEnvironmentGate -lt $clientLayoutResolution -and
        $sessionEnvironmentGate -ge 0 -and
        $sessionEnvironmentGate -lt $sessionLayoutResolution) `
    -Detail 'both entry points reject the hidden option before acquiring a lock or starting a server'

Add-Result `
    -Name 'client requires the exact active Gameplay overlay contract' `
    -Passed (
        $clientSource -match
            'Assert-PSOBBGameplayObservationClientContract' -and
        $credentialSource -match
            'schemaVersion\s+-eq\s+2L' -and
        $credentialSource -match "'dinput8\.dll'" -and
        $credentialSource -match "'plugins/PSOBB\.Gameplay\.asi'" -and
        $credentialSource -match "'plugins/PSOBB\.Gameplay\.ini'") `
    -Detail 'the hash-verified launch contract must contain exactly the schema-2 loader, module, and canonical INI'

Add-Result `
    -Name 'observation activation passes only a generated run ID' `
    -Passed (
        $clientSource -match
            'New-PSOBBGameplayObservationRunDirectory' -and
        $clientSource -match
            '-GameplayObservationRunId\s+\$\(if \(\$gameplayObservationRun\)' -and
        $credentialSource -match
            'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID' -and
        $credentialSource -notmatch
            'PSOBB_GAMEPLAY_OBSERVATION_(?:PATH|ROOT|DIRECTORY)') `
    -Detail 'no caller-controlled evidence path crosses the child-process boundary'

Add-Result `
    -Name 'CreateProcess receives an explicit child-only Unicode environment' `
    -Passed (
        $credentialSource -match 'BuildEnvironmentBlock' -and
        $credentialSource -match 'CreateUnicodeEnvironment' -and
        $credentialSource -match 'variables\.Remove\(ObservationRunIdName\)' -and
        $credentialSource -notmatch 'SetEnvironmentVariable') `
    -Detail 'RunAsInvoker and optional observation activation are composed without mutating the parent process environment'

$readinessIndex = $clientSource.IndexOf(
    'Wait-PSOBBGameplayObservationEvidenceReady',
    [System.StringComparison]::Ordinal)
$startedIndex = $clientSource.IndexOf(
    'Started = $true',
    [System.StringComparison]::Ordinal)
Add-Result `
    -Name 'evidence readiness is required before launch success' `
    -Passed (
        $readinessIndex -ge 0 -and $startedIndex -gt $readinessIndex -and
        $clientSource -match
            'GameplayObservationEvidencePath = if \(\$gameplayObservationReadiness\)') `
    -Detail 'the lifecycle returns the exact validated events-v1.partial path only after readiness'

Add-Result `
    -Name 'a protected no-clobber run manifest follows readiness' `
    -Passed (
        $clientSource -match 'New-PSOBBGameplayObservationRunManifest' -and
        $clientSource -match 'GameplayObservationManifestPath' -and
        $clientSource -match 'GameplayObservationManifestSha256' -and
        $credentialSource -match
            "run-manifest-v1\.json" -and
        $credentialSource -match
            '\[System\.IO\.File\]::Move\(\$temporaryPath, \$manifestPath, \$false\)') `
    -Detail 'durable provenance is separate from the established startup receipt and cannot overwrite an existing manifest'

$leaseOpenIndex = $clientSource.IndexOf(
    'Open-PSOBBGameplayOverlayLaunchLeaseSet',
    [System.StringComparison]::Ordinal)
$leaseRevalidateIndex = $clientSource.IndexOf(
    'Assert-PSOBBGameplayOverlayLaunchLeaseSet',
    [System.StringComparison]::Ordinal)
$manifestCreateIndex = $clientSource.IndexOf(
    'New-PSOBBGameplayObservationRunManifest',
    [System.StringComparison]::Ordinal)
Add-Result `
    -Name 'overlay files remain locked and revalidated through readiness' `
    -Passed (
        $leaseOpenIndex -ge 0 -and
        $leaseRevalidateIndex -gt $leaseOpenIndex -and
        $manifestCreateIndex -gt $leaseRevalidateIndex -and
        $credentialSource -match 'OpenReadLockedFile' -and
        $credentialSource -match 'ComputeSha256') `
    -Detail 'loader, module, and configuration identities cannot be replaced by a new writer between preflight and manifest creation'

$finalizeBeforeCloseIndex = $stopClientSource.IndexOf(
    'FinalizeObservationEvidence',
    [System.StringComparison]::Ordinal)
$normalCloseIndex = $stopClientSource.IndexOf(
    'CloseMainWindow',
    [System.StringComparison]::Ordinal)
Add-Result `
    -Name 'client stop finalizes native evidence before normal window close' `
    -Passed (
        $finalizeBeforeCloseIndex -ge 0 -and
        $normalCloseIndex -gt $finalizeBeforeCloseIndex -and
        $stopClientSource -match 'GameplayObservationFinalizedCount' -and
        $stopClientSource -match 'GameplayObservationFinalizationFailures') `
    -Detail 'ordinary lifecycle shutdown requests a final drain and reports any evidence failure without broad process control'

$receiptStart = $clientSource.IndexOf('$receipt = [ordered]@{')
$receiptEnd = $clientSource.IndexOf('$temporaryReceipt =', $receiptStart)
$receiptSource = if ($receiptStart -ge 0 -and $receiptEnd -gt $receiptStart) {
    $clientSource.Substring($receiptStart, $receiptEnd - $receiptStart)
} else {
    ''
}
Add-Result `
    -Name 'the established client startup receipt contract remains schema 3' `
    -Passed (
        $receiptSource -match 'schemaVersion\s*=\s*3' -and
        $receiptSource -notmatch 'GameplayObservation') `
    -Detail 'the evidence header itself durably binds client SHA, PID, process start time, and native consumer identity'

. $credentialPath

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-GameplayObservationLaunch-' + [Guid]::NewGuid().ToString('N'))
$savedObservationRunId = [Environment]::GetEnvironmentVariable(
    'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID', 'Process')
$savedCompatibilityLayer = [Environment]::GetEnvironmentVariable(
    '__COMPAT_LAYER', 'Process')
$junctionPath = $null
$startedChildren = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
try {
    [void][System.IO.Directory]::CreateDirectory($temporaryRoot)
    $layout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
    Initialize-PSOBBRuntimeMarker -Layout $layout | Out-Null
    $clientStableRejected = Test-ThrowsMessage `
        -Action {
            & $clientPath `
                -ServerEnvironment Stable `
                -RuntimeRoot $temporaryRoot `
                -GameplayObservationEvidence | Out-Null
        } `
        -Pattern 'only for CombatCanary'
    $sessionStableRejected = Test-ThrowsMessage `
        -Action {
            & $sessionPath `
                -ServerEnvironment Stable `
                -RuntimeRoot $temporaryRoot `
                -GameplayObservationEvidence | Out-Null
        } `
        -Pattern 'only for CombatCanary'
    Add-Result `
        -Name 'Stable rejects observation evidence without starting PSOBB' `
        -Passed ($clientStableRejected -and $sessionStableRejected) `
        -Detail 'both concrete entry points stopped at the environment gate in an isolated runtime fixture'

    $schema1Contract = [pscustomobject]@{
        Binding = [pscustomobject]@{ schemaVersion = 1L }
        GameplayOverlayEntries = @(
            [pscustomobject]@{ path = 'dinput8.dll' },
            [pscustomobject]@{ path = 'plugins/PSOBB.Gameplay.asi' },
            [pscustomobject]@{ path = 'plugins/PSOBB.Gameplay.ini' })
    }
    $schema2Contract = [pscustomobject]@{
        Verification = [pscustomobject]@{
            ClientBindingSha256 = '1' * 64
        }
        Binding = [pscustomobject]@{ schemaVersion = 2L }
        GameplayOverlayEntries = @(
            [pscustomobject]@{
                path = 'dinput8.dll'
                size = 101L
                sha256 = 'a' * 64
            },
            [pscustomobject]@{
                path = 'plugins/PSOBB.Gameplay.asi'
                size = 202L
                sha256 = 'b' * 64
            },
            [pscustomobject]@{
                path = 'plugins/PSOBB.Gameplay.ini'
                size = 303L
                sha256 = 'c' * 64
            })
    }
    $schema2Duplicate = [pscustomobject]@{
        Binding = [pscustomobject]@{ schemaVersion = 2L }
        GameplayOverlayEntries = @(
            [pscustomobject]@{ path = 'dinput8.dll' },
            [pscustomobject]@{ path = 'plugins/PSOBB.Gameplay.asi' },
            [pscustomobject]@{ path = 'plugins/PSOBB.Gameplay.asi' })
    }
    $schema1Rejected = Test-ThrowsMessage `
        -Action {
            Assert-PSOBBGameplayObservationClientContract `
                -Contract $schema1Contract | Out-Null
        } `
        -Pattern 'schema-2 Gameplay overlay'
    $schema2Accepted = try {
        Assert-PSOBBGameplayObservationClientContract `
            -Contract $schema2Contract | Out-Null
        $true
    } catch {
        $false
    }
    $schema2DuplicateRejected = Test-ThrowsMessage `
        -Action {
            Assert-PSOBBGameplayObservationClientContract `
                -Contract $schema2Duplicate | Out-Null
        } `
        -Pattern 'schema-2 Gameplay overlay'
    Add-Result `
        -Name 'schema 1 is rejected and exact schema 2 is accepted' `
        -Passed (
            $schema1Rejected -and $schema2Accepted -and
            $schema2DuplicateRejected) `
        -Detail 'schema and overlay cardinality are independently fail-closed'

    $overlayClientRoot = Join-Path $temporaryRoot 'overlay-client'
    $overlayPluginsRoot = Join-Path $overlayClientRoot 'plugins'
    [void][System.IO.Directory]::CreateDirectory($overlayPluginsRoot)
    $overlayPaths = @(
        [pscustomobject]@{
            Path = 'dinput8.dll'
            File = Join-Path $overlayClientRoot 'dinput8.dll'
            Bytes = [byte[]](1..101)
        },
        [pscustomobject]@{
            Path = 'plugins/PSOBB.Gameplay.asi'
            File = Join-Path $overlayPluginsRoot 'PSOBB.Gameplay.asi'
            Bytes = [byte[]](1..202)
        },
        [pscustomobject]@{
            Path = 'plugins/PSOBB.Gameplay.ini'
            File = Join-Path $overlayPluginsRoot 'PSOBB.Gameplay.ini'
            Bytes = [byte[]](1..30)
        })
    foreach ($overlay in $overlayPaths) {
        [System.IO.File]::WriteAllBytes($overlay.File, $overlay.Bytes)
    }
    $lockedContract = [pscustomobject]@{
        Binding = [pscustomobject]@{ schemaVersion = 2L }
        GameplayOverlayEntries = @($overlayPaths | ForEach-Object {
                [pscustomobject]@{
                    path = [string]$_.Path
                    size = [long]$_.Bytes.Length
                    sha256 = (Get-LowerSha256 -Path $_.File)
                }
            })
    }
    $overlayLeaseSet = Open-PSOBBGameplayOverlayLaunchLeaseSet `
        -Layout $layout -ClientRoot $overlayClientRoot `
        -Contract $lockedContract
    try {
        $newWriterRejected = $false
        try {
            $unexpectedWriter = [System.IO.File]::Open(
                $overlayPaths[1].File,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite)
            $unexpectedWriter.Dispose()
        } catch {
            $newWriterRejected = $true
        }
        $leaseSetStillExact = try {
            Assert-PSOBBGameplayOverlayLaunchLeaseSet `
                -LeaseSet $overlayLeaseSet | Out-Null
            $true
        } catch {
            $false
        }
    } finally {
        Close-PSOBBGameplayOverlayLaunchLeaseSet `
            -LeaseSet $overlayLeaseSet
    }
    $writerAfterRelease = [System.IO.File]::Open(
        $overlayPaths[1].File,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::ReadWrite)
    $writerAfterRelease.Dispose()
    Add-Result `
        -Name 'locked overlay leases exclude writers until manifest binding' `
        -Passed ($newWriterRejected -and $leaseSetStillExact) `
        -Detail 'all three handle-bound hashes remained exact and a new module writer was excluded until release'

    Initialize-PSOBBClientProcessLauncherType
    $currentIdentityProcess = [System.Diagnostics.Process]::GetCurrentProcess()
    $currentStartFileTime = [uint64](
        $currentIdentityProcess.StartTime.ToUniversalTime().ToFileTimeUtc())
    $missingFinalizeReturnsFalse =
        -not [PSOBBClientProcessLauncher]::FinalizeObservationEvidence(
            [uint32]$currentIdentityProcess.Id,
            $currentStartFileTime,
            1000U)
    $eventSuffix = '{0:x8}.{1:x16}' -f `
        [uint32]$currentIdentityProcess.Id, $currentStartFileTime
    $finalizeEvent = [System.Threading.EventWaitHandle]::new(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        ('Local\PSOBB.Gameplay.Observation.Finalize.' + $eventSuffix))
    $completionEvent = [System.Threading.EventWaitHandle]::new(
        $true,
        [System.Threading.EventResetMode]::ManualReset,
        ('Local\PSOBB.Gameplay.Observation.Completed.' + $eventSuffix))
    try {
        $finalized = [PSOBBClientProcessLauncher]::FinalizeObservationEvidence(
            [uint32]$currentIdentityProcess.Id,
            $currentStartFileTime,
            1000U)
        $finalizeSignaled = $finalizeEvent.WaitOne(0)
    } finally {
        $completionEvent.Dispose()
        $finalizeEvent.Dispose()
        $currentIdentityProcess.Dispose()
    }
    Add-Result `
        -Name 'lifecycle finalization uses exact process-bound native events' `
        -Passed (
            $missingFinalizeReturnsFalse -and $finalized -and
            $finalizeSignaled) `
        -Detail 'ordinary clients have no event; evidence clients signal only the PID/start-time pair and wait for native completion'

    $combatLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment CombatCanary
    $evidenceRoot = Join-Path $combatLayout.EnvironmentRoot 'evidence'
    [void][System.IO.Directory]::CreateDirectory($evidenceRoot)
    Set-PSOBBProtectedAcl -Path $evidenceRoot

    $firstRun = New-PSOBBGameplayObservationRunDirectory `
        -Layout $layout -ServerLayout $combatLayout
    $secondRun = New-PSOBBGameplayObservationRunDirectory `
        -Layout $layout -ServerLayout $combatLayout
    $observationRoot = Split-Path -Parent $firstRun.Path
    $firstItem = Get-Item -Force -LiteralPath $firstRun.Path
    Add-Result `
        -Name 'run directory creation is unique, identity-bound, and canonical' `
        -Passed (
            [string]$firstRun.RunId -cmatch
                '\A[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}\z' -and
            [string]$secondRun.RunId -cmatch
                '\A[0-9]{8}T[0-9]{9}Z-gameplay-[a-f0-9]{12}\z' -and
            [string]$firstRun.RunId -cne [string]$secondRun.RunId -and
            [uint64]$firstRun.FileId -gt 0 -and
            [string]$firstRun.EvidenceFilePath -ceq
                (Join-Path $firstRun.Path 'events-v1.partial') -and
            [System.IO.Path]::GetFullPath([string]$firstRun.Path).Equals(
                [System.IO.Path]::GetFullPath(
                    (Join-Path $observationRoot $firstRun.RunId)),
                [System.StringComparison]::OrdinalIgnoreCase)) `
        -Detail "$($firstRun.RunId); file ID $($firstRun.FileId)"

    Add-Result `
        -Name 'evidence directories are protected and non-reparse' `
        -Passed (
            (Test-PSOBBProtectedAcl -Path $evidenceRoot) -and
            (Test-PSOBBProtectedAcl -Path $observationRoot) -and
            (Test-PSOBBProtectedAcl -Path $firstRun.Path) -and
            (($firstItem.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -eq 0)) `
        -Detail 'evidence root, gameplay-observation root, and run root have exact protected DACLs'

    $stableLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment Stable
    Add-Result `
        -Name 'run directory helper rejects Stable independently' `
        -Passed (Test-ThrowsMessage `
            -Action {
                New-PSOBBGameplayObservationRunDirectory `
                    -Layout $layout -ServerLayout $stableLayout | Out-Null
            } `
            -Pattern 'exact CombatCanary') `
        -Detail 'the directory helper cannot be reused against Stable'

    $unprotectedRoot = Join-Path $temporaryRoot 'unprotected-fixture'
    $unprotectedLayout = Get-PSOBBLayout -RuntimeRoot $unprotectedRoot
    $unprotectedCombat = Get-PSOBBServerEnvironmentLayout `
        -Layout $unprotectedLayout -Environment CombatCanary
    [void][System.IO.Directory]::CreateDirectory(
        (Join-Path $unprotectedCombat.EnvironmentRoot 'evidence'))
    Add-Result `
        -Name 'unprotected evidence roots fail closed' `
        -Passed (Test-ThrowsMessage `
            -Action {
                New-PSOBBGameplayObservationRunDirectory `
                    -Layout $unprotectedLayout `
                    -ServerLayout $unprotectedCombat | Out-Null
            } `
            -Pattern 'not an exact protected non-reparse directory') `
        -Detail 'the launch path does not normalize an unknown evidence root'

    $reparseRoot = Join-Path $temporaryRoot 'reparse-fixture'
    $reparseLayout = Get-PSOBBLayout -RuntimeRoot $reparseRoot
    $reparseCombat = Get-PSOBBServerEnvironmentLayout `
        -Layout $reparseLayout -Environment CombatCanary
    [void][System.IO.Directory]::CreateDirectory(
        $reparseCombat.EnvironmentRoot)
    $reparseTarget = Join-Path $temporaryRoot 'reparse-target'
    [void][System.IO.Directory]::CreateDirectory($reparseTarget)
    Set-PSOBBProtectedAcl -Path $reparseTarget
    $junctionPath = Join-Path $reparseCombat.EnvironmentRoot 'evidence'
    New-Item -ItemType Junction -Path $junctionPath `
        -Target $reparseTarget | Out-Null
    $reparseRejected = Test-ThrowsMessage `
        -Action {
            New-PSOBBGameplayObservationRunDirectory `
                -Layout $reparseLayout -ServerLayout $reparseCombat | Out-Null
        } `
        -Pattern 'reparse|native path|exact protected'
    Add-Result `
        -Name 'reparse-backed evidence paths fail closed' `
        -Passed $reparseRejected `
        -Detail 'a junction cannot redirect the evidence root outside its exact directory identity'
    Remove-Item -LiteralPath $junctionPath -Force
    $junctionPath = $null

    $script:registryGateObservations =
        [System.Collections.Generic.List[string]]::new()
    function Assert-PSOBBClientLoginRegistry {
        $script:registryGateObservations.Add(('{0}|{1}' -f
                ([Environment]::GetEnvironmentVariable(
                    'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID', 'Process')),
                ([Environment]::GetEnvironmentVariable(
                    '__COMPAT_LAYER', 'Process'))))
        [pscustomobject]@{ Valid = $true }
    }

    $childSourcePath = Join-Path $temporaryRoot 'EnvironmentChild.cs'
    $childExecutable = Join-Path $temporaryRoot 'EnvironmentChild.exe'
    $childSource = @'
using System;
using System.IO;
using System.Threading;

public static class EnvironmentChild
{
    public static int Main()
    {
        string observation = Environment.GetEnvironmentVariable(
            "PSOBB_GAMEPLAY_OBSERVATION_RUN_ID") ?? "<null>";
        string compatibility = Environment.GetEnvironmentVariable(
            "__COMPAT_LAYER") ?? "<null>";
        File.WriteAllText(
            Path.Combine(Environment.CurrentDirectory, "child-environment.txt"),
            observation + "|" + compatibility);
        Thread.Sleep(250);
        return 0;
    }
}
'@
    [System.IO.File]::WriteAllText(
        $childSourcePath, $childSource,
        [System.Text.UTF8Encoding]::new($false))
    $compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $compilerOutput = @(& $compiler /nologo /target:exe `
            "/out:$childExecutable" $childSourcePath 2>&1)
    if ($LASTEXITCODE -ne 0 -or
        -not (Test-Path -LiteralPath $childExecutable -PathType Leaf)) {
        throw "The child environment fixture did not compile: $($compilerOutput -join ' ')"
    }

    [Environment]::SetEnvironmentVariable(
        'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID', 'ambient-sentinel', 'Process')
    [Environment]::SetEnvironmentVariable(
        '__COMPAT_LAYER', 'compat-sentinel', 'Process')
    $requestedWorking = Join-Path $temporaryRoot 'requested-child'
    $ordinaryWorking = Join-Path $temporaryRoot 'ordinary-child'
    [void][System.IO.Directory]::CreateDirectory($requestedWorking)
    [void][System.IO.Directory]::CreateDirectory($ordinaryWorking)

    $requestedChild = Start-PSOBBClientProcess `
        -ClientExecutable $childExecutable `
        -WorkingDirectory $requestedWorking `
        -GameplayObservationRunId $firstRun.RunId
    $startedChildren.Add($requestedChild)
    $requestedExited = $requestedChild.WaitForExit(5000)
    $requestedEnvironment = if ($requestedExited) {
        Get-Content -Raw -LiteralPath (
            Join-Path $requestedWorking 'child-environment.txt')
    } else {
        ''
    }

    $ordinaryChild = Start-PSOBBClientProcess `
        -ClientExecutable $childExecutable `
        -WorkingDirectory $ordinaryWorking
    $startedChildren.Add($ordinaryChild)
    $ordinaryExited = $ordinaryChild.WaitForExit(5000)
    $ordinaryEnvironment = if ($ordinaryExited) {
        Get-Content -Raw -LiteralPath (
            Join-Path $ordinaryWorking 'child-environment.txt')
    } else {
        ''
    }
    $parentUnchanged =
        [Environment]::GetEnvironmentVariable(
            'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID', 'Process') -ceq
                'ambient-sentinel' -and
        [Environment]::GetEnvironmentVariable('__COMPAT_LAYER', 'Process') -ceq
            'compat-sentinel'
    $registryUnchanged =
        $script:registryGateObservations.Count -eq 2 -and
        @($script:registryGateObservations | Where-Object {
                $_ -ceq 'ambient-sentinel|compat-sentinel'
            }).Count -eq 2
    Add-Result `
        -Name 'real child receives only its requested launch environment' `
        -Passed (
            $requestedExited -and $requestedChild.ExitCode -eq 0 -and
            $requestedEnvironment -ceq
                "$($firstRun.RunId)|RunAsInvoker" -and
            $parentUnchanged -and $registryUnchanged) `
        -Detail ('exited={0}; code={1}; env={2}; parent={3}; registry={4}' -f
            $requestedExited, $requestedChild.ExitCode,
            $requestedEnvironment, $parentUnchanged, $registryUnchanged)
    Add-Result `
        -Name 'ordinary real child does not inherit ambient observation activation' `
        -Passed (
            $ordinaryExited -and $ordinaryChild.ExitCode -eq 0 -and
            $ordinaryEnvironment -ceq '<null>|RunAsInvoker' -and
            $parentUnchanged) `
        -Detail ('exited={0}; code={1}; env={2}; parent={3}' -f
            $ordinaryExited, $ordinaryChild.ExitCode,
            $ordinaryEnvironment, $parentUnchanged)

    $missingExecutable = Join-Path $temporaryRoot 'missing-client.exe'
    $missingCreatedFlag = $null
    $missingRejected = try {
        Start-PSOBBClientProcess `
            -ClientExecutable $missingExecutable `
            -WorkingDirectory $temporaryRoot | Out-Null
        $false
    } catch {
        $missingCreatedFlag = $_.Exception.Data['PSOBBClientCreated']
        $true
    }
    Add-Result `
        -Name 'failed CreateProcess is marked as pre-process failure' `
        -Passed (
            $missingRejected -and $missingCreatedFlag -ne $true -and
            [Environment]::GetEnvironmentVariable(
                'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID', 'Process') -ceq
                'ambient-sentinel') `
        -Detail 'the caller can safely remove only an exact empty run when no child existed'

    $registryCallsBeforeInvalid = $script:registryGateObservations.Count
    $invalidRejected = Test-ThrowsMessage `
        -Action {
            Start-PSOBBClientProcess `
                -ClientExecutable $missingExecutable `
                -WorkingDirectory $temporaryRoot `
                -GameplayObservationRunId '..\outside' | Out-Null
        } `
        -Pattern 'run ID is invalid'
    Add-Result `
        -Name 'arbitrary run IDs fail before registry or process work' `
        -Passed (
            $invalidRejected -and
            $script:registryGateObservations.Count -eq
                $registryCallsBeforeInvalid) `
        -Detail 'path separators and non-canonical input never reach the child environment'

    $missingRun = New-PSOBBGameplayObservationRunDirectory `
        -Layout $layout -ServerLayout $combatLayout
    $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
    $missingReadinessRejected = Test-ThrowsMessage `
        -Action {
            Wait-PSOBBGameplayObservationEvidenceReady `
                -Layout $layout -Run $missingRun -Process $currentProcess `
                -ExpectedClientSha256 ('0' * 64) `
                -TimeoutMilliseconds 100 | Out-Null
        } `
        -Pattern 'did not become ready'
    $missingRunRemoved =
        Remove-PSOBBGameplayObservationEmptyRunDirectory `
            -Layout $layout -Run $missingRun
    Add-Result `
        -Name 'missing readiness rejects and exact empty run cleanup succeeds' `
        -Passed (
            $missingReadinessRejected -and $missingRunRemoved -and
            -not (Test-Path -LiteralPath $missingRun.Path)) `
        -Detail 'no file and no process evidence leaves no orphan candidate directory'

    $nonemptyRun = New-PSOBBGameplayObservationRunDirectory `
        -Layout $layout -ServerLayout $combatLayout
    [System.IO.File]::WriteAllText(
        (Join-Path $nonemptyRun.Path 'diagnostic.txt'),
        'preserve', [System.Text.UTF8Encoding]::new($false))
    $nonemptyRemoved =
        Remove-PSOBBGameplayObservationEmptyRunDirectory `
            -Layout $layout -Run $nonemptyRun
    Add-Result `
        -Name 'nonempty diagnostic runs are preserved' `
        -Passed (
            -not $nonemptyRemoved -and
            (Test-Path -LiteralPath $nonemptyRun.Path -PathType Container)) `
        -Detail 'cleanup refuses any run containing a file'

    $readyRun = New-PSOBBGameplayObservationRunDirectory `
        -Layout $layout -ServerLayout $combatLayout
    $header = [byte[]]::new(256)
    [System.Text.Encoding]::ASCII.GetBytes('PSOBBOBS').CopyTo($header, 0)
    Set-UInt32LittleEndian -Bytes $header -Offset 8 -Value 256
    Set-UInt32LittleEndian -Bytes $header -Offset 12 -Value 1
    Set-UInt32LittleEndian -Bytes $header -Offset 16 -Value 0x01020304
    Set-UInt32LittleEndian -Bytes $header -Offset 20 -Value 524544
    Set-UInt32LittleEndian -Bytes $header -Offset 24 -Value 1
    Set-UInt32LittleEndian -Bytes $header -Offset 28 -Value 32
    Set-UInt32LittleEndian -Bytes $header -Offset 32 -Value 16384
    Set-UInt32LittleEndian -Bytes $header -Offset 36 -Value 0
    Set-UInt32LittleEndian -Bytes $header -Offset 40 -Value 1
    Set-UInt32LittleEndian -Bytes $header -Offset 44 -Value 32
    Set-UInt32LittleEndian -Bytes $header -Offset 84 -Value 123
    Set-UInt32LittleEndian -Bytes $header -Offset 88 `
        -Value ([uint32]$currentProcess.Id)
    Set-UInt64LittleEndian -Bytes $header -Offset 96 `
        -Value ([uint64](
            $currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc()))
    [System.Text.Encoding]::ASCII.GetBytes(
        '0.4.0-observation-evidence').CopyTo($header, 152)
    Set-UInt32LittleEndian -Bytes $header -Offset 184 -Value 1
    $captureStartFileTime = [uint64]([DateTime]::UtcNow.ToFileTimeUtc())
    Set-UInt64LittleEndian -Bytes $header -Offset 192 `
        -Value $captureStartFileTime
    Set-UInt64LittleEndian -Bytes $header -Offset 200 `
        -Value $captureStartFileTime
    $readyStream = [System.IO.FileStream]::new(
        $readyRun.EvidenceFilePath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::Read)
    try {
        $readyStream.SetLength(524544)
        $readyStream.Position = 0
        $readyStream.Write($header, 0, $header.Length)
        $readyStream.Flush($true)
    } finally {
        $readyStream.Dispose()
    }
    $readyLifecycleRejected = Test-ThrowsMessage `
        -Action {
            Wait-PSOBBGameplayObservationEvidenceReady `
                -Layout $layout -Run $readyRun -Process $currentProcess `
                -ExpectedClientSha256 ('0' * 64) `
                -TimeoutMilliseconds 100 | Out-Null
        } `
        -Pattern 'did not become ready'
    Set-UInt32LittleEndian -Bytes $header -Offset 184 -Value 4
    Set-UInt32LittleEndian -Bytes $header -Offset 188 -Value 7
    Set-UInt64LittleEndian -Bytes $header -Offset 208 `
        -Value $captureStartFileTime
    Set-UInt64LittleEndian -Bytes $header -Offset 216 -Value 1
    Set-UInt64LittleEndian -Bytes $header -Offset 224 -Value 1000
    Set-UInt64LittleEndian -Bytes $header -Offset 232 -Value 1000
    $failedStream = [System.IO.FileStream]::new(
        $readyRun.EvidenceFilePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    try {
        $failedStream.Write($header, 0, $header.Length)
        $failedStream.Flush($true)
    } finally {
        $failedStream.Dispose()
    }
    $failedLifecycleRejected = Test-ThrowsMessage `
        -Action {
            Wait-PSOBBGameplayObservationEvidenceReady `
                -Layout $layout -Run $readyRun -Process $currentProcess `
                -ExpectedClientSha256 ('0' * 64) `
                -TimeoutMilliseconds 100 | Out-Null
        } `
        -Pattern 'did not become ready'
    Set-UInt32LittleEndian -Bytes $header -Offset 184 -Value 2
    Set-UInt32LittleEndian -Bytes $header -Offset 188 -Value 0
    Set-UInt64LittleEndian -Bytes $header -Offset 208 -Value 0
    $activeStream = [System.IO.FileStream]::new(
        $readyRun.EvidenceFilePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    try {
        $activeStream.Write($header, 0, $header.Length)
        $activeStream.Flush($true)
    } finally {
        $activeStream.Dispose()
        [Array]::Clear($header, 0, $header.Length)
    }
    $readyEvidence = Wait-PSOBBGameplayObservationEvidenceReady `
        -Layout $layout -Run $readyRun -Process $currentProcess `
        -ExpectedClientSha256 ('0' * 64) `
        -TimeoutMilliseconds 500
    Add-Result `
        -Name 'readiness binds exact evidence header to the producer' `
        -Passed (
            $readyLifecycleRejected -and $failedLifecycleRejected -and
            [string]$readyEvidence.Path -ceq
                [string]$readyRun.EvidenceFilePath -and
            [long]$readyEvidence.Length -eq 524544 -and
            [int]$readyEvidence.ProcessId -eq $currentProcess.Id -and
            [uint32]$readyEvidence.ConsumerThreadId -eq 123 -and
            [uint32]$readyEvidence.LifecycleState -eq 2 -and
            [uint64]$readyEvidence.HeartbeatCount -eq 1 -and
            [uint64]$readyEvidence.FileId -gt 0) `
        -Detail "PID $($readyEvidence.ProcessId), file ID $($readyEvidence.FileId)"

    $manifestClientIdentity = [pscustomobject]@{
        Size = 404L
        Sha256 = 'd' * 64
    }
    $runManifest = New-PSOBBGameplayObservationRunManifest `
        -Layout $layout -ServerLayout $combatLayout `
        -Run $readyRun -Readiness $readyEvidence `
        -ClientContract $schema2Contract `
        -ClientIdentity $manifestClientIdentity
    $manifestSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $runManifest.Path -Root $readyRun.Path `
        -MaximumBytes 32KB -MaximumDepth 4 `
        -Label 'test Gameplay observation run manifest'
    $manifestNoClobber = Test-ThrowsMessage `
        -Action {
            New-PSOBBGameplayObservationRunManifest `
                -Layout $layout -ServerLayout $combatLayout `
                -Run $readyRun -Readiness $readyEvidence `
                -ClientContract $schema2Contract `
                -ClientIdentity $manifestClientIdentity | Out-Null
        } `
        -Pattern 'already exists'
    Add-Result `
        -Name 'run manifest durably binds readiness and overlay provenance' `
        -Passed (
            (Test-PSOBBProtectedAcl -Path $runManifest.Path) -and
            [string]$runManifest.Sha256 -ceq
                [string]$manifestSnapshot.Sha256 -and
            [long]$manifestSnapshot.Value.schemaVersion -eq 1 -and
            [string]$manifestSnapshot.Value.runId -ceq
                [string]$readyRun.RunId -and
            [string]$manifestSnapshot.Value.evidenceFileName -ceq
                'events-v1.partial' -and
            [long]$manifestSnapshot.Value.evidenceLength -eq 524544 -and
            [string]$manifestSnapshot.Value.evidenceFileId -ceq
                ('{0:x16}' -f [uint64]$readyEvidence.FileId) -and
            [long]$manifestSnapshot.Value.processId -eq
                $currentProcess.Id -and
            [long]$manifestSnapshot.Value.consumerThreadId -eq 123 -and
            [string]$manifestSnapshot.Value.clientBindingSha256 -ceq
                ('1' * 64) -and
            [string]$manifestSnapshot.Value.gameplayModuleSha256 -ceq
                ('b' * 64) -and
            [string]$manifestSnapshot.Value.gameplayConfigurationSha256 -ceq
                ('c' * 64) -and
            $manifestNoClobber -and
            (Get-LowerSha256 -Path $runManifest.Path) -ceq
                [string]$runManifest.Sha256) `
        -Detail "manifest $($runManifest.Sha256)"
} finally {
    foreach ($child in $startedChildren) {
        try {
            if (-not $child.HasExited) {
                $child.Kill($true)
                [void]$child.WaitForExit(5000)
            }
        } catch { }
        $child.Dispose()
    }
    [Environment]::SetEnvironmentVariable(
        'PSOBB_GAMEPLAY_OBSERVATION_RUN_ID',
        $(if ($null -eq $savedObservationRunId) {
                [System.Management.Automation.Language.NullString]::Value
            } else { $savedObservationRunId }),
        'Process')
    [Environment]::SetEnvironmentVariable(
        '__COMPAT_LAYER',
        $(if ($null -eq $savedCompatibilityLayer) {
                [System.Management.Automation.Language.NullString]::Value
            } else { $savedCompatibilityLayer }),
        'Process')
    if ($junctionPath -and (Test-Path -LiteralPath $junctionPath)) {
        Remove-Item -LiteralPath $junctionPath -Force
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $safeTemporaryRoot = Assert-PathWithinRoot `
            -Path $temporaryRoot -Root ([System.IO.Path]::GetTempPath())
        Remove-Item -LiteralPath $safeTemporaryRoot -Recurse -Force
    }
}

$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    $failed | Format-List
    throw "$($failed.Count) Gameplay observation launch test(s) failed"
}

[pscustomobject]@{
    Suite = 'GameplayObservationLaunch'
    Passed = $results.Count
    Failed = 0
}
