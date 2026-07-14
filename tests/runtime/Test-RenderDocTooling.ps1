[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$captureScript = Join-Path $repositoryRoot 'scripts\Invoke-PSOBBRenderDocCapture.ps1'
$registerScript = Join-Path $repositoryRoot 'scripts\Register-PSOBBRenderDocCapture.ps1'
$captureSource = Get-Content -Raw -LiteralPath $captureScript
$registerSource = Get-Content -Raw -LiteralPath $registerScript
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

foreach ($scriptPath in @($captureScript, $registerScript)) {
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

$prelaunchGuard =
    $captureSource -match 'Get-PSOBBClientProcessRecords -Layout \$layout -Channel All' -and
    $captureSource -match "Get-Process -Name 'Psobb'" -and
    $captureSource -match 'approvedProcesses\.Count -ne 0' -and
    $captureSource -match 'anyNamedProcesses\.Count -ne 0' -and
    $captureSource -match 'Assert-PSOBBLocalLabClientRuntimeContract'
Add-Result 'capture refuses every pre-existing PSOBB process and requires LocalLab' `
    $prelaunchGuard 'approved and same-name inventories must both be empty before launch'

$artifactGuard =
    $captureSource -match "id -ceq 'renderdoc-diagnostic'" -and
    $captureSource -match "version -cne 'v1\.45'" -and
    $captureSource -match 'RenderDoc_1\.45_64\.zip' -and
    $captureSource -match 'Assert-PSOBBZipArchiveSafe' -and
    $captureSource -match 'RenderDoc_1\.45_64/renderdoccmd\.exe' -and
    $captureSource -match 'byte-identical to the member in the locked archive' -and
    $captureSource -match 'Get-AuthenticodeSignature' -and
    $captureSource -match 'CN=Baldur Scott Karlsson,'
Add-Result 'capture pins the archive, x64 member, version, hash, and author signature' `
    $artifactGuard 'the executable is derived from the exact locked v1.45 archive member'

$profileGuard =
    $captureSource -match "channel -ceq 'local-lab'" -and
    $captureSource -match 'Assert-PSOBBApprovedClientExecutable' -and
    $captureSource -match 'baseExecutableSha256' -and
    $captureSource -match 'internalRenderCandidates' -and
    $captureSource -match 'materialized\.renderWidth' -and
    $captureSource -match 'ProfileSha256'
Add-Result 'capture pins one exact catalog and materialized profile' $profileGuard `
    'profile ID, channel, executable, render/output configuration, and materialization hash are required'

$commandGuard =
    $captureSource -match "'capture'," -and
    $captureSource -match '''-d'', \$profile\.ClientRoot' -and
    $captureSource -match '''-c'', \$captureTemplate' -and
    $captureSource -match '\$profile\.ClientExecutable' -and
    $captureSource -notmatch "'--wait-for-exit'|'--opt-disallow-vsync'|'--opt-disallow-fullscreen'"
Add-Result 'capture uses the official launch command without presentation overrides' `
    $commandGuard 'working directory, private template, and exact executable are the only launch inputs'

$identityGuard =
    $captureSource -match 'Launched as ID \(\[0-9\]\+\)' -and
    $captureSource -match 'ConvertTo-PSOBBUInt32ExitCode' -and
    $captureSource -match 'unsignedExitCode -ne \$captureIdentity' -and
    $captureSource -match 'MainWindowHandle -ne \[IntPtr\]::Zero' -and
    $captureSource -match 'Test-PSOBBProcessAtExactPath' -and
    $captureSource -match 'StartTimeUtc'
Add-Result 'capture validates RenderDoc and target process identities' $identityGuard `
    'the intentional nonzero CLI identity, PID, path, hash, start time, and window are checked'

$privacyGuard =
    $captureSource -match 'graphics-evidence' -and
    $captureSource -match 'Assert-PSOBBPrivateRenderDocPath' -and
    $captureSource -match "trigger = 'manual-f12'" -and
    $captureSource -notmatch '(?i)password|twills|sendkeys|read-host'
Add-Result 'capture leaves credentials and the manual trigger outside automation' $privacyGuard `
    'private runtime evidence is used and F12 remains a human action'

$claimGuard =
    $captureSource -match "evidenceClass = 'configuration-only'" -and
    $captureSource -match "status = 'pending-replay-inspection'" -and
    $captureSource -match 'observedInternalRender = \$null' -and
    $captureSource -match 'observedOutput = \$null' -and
    $registerSource -match "validationClass = 'artifact-integrity-only'" -and
    $registerSource -match "status = 'not-provided'" -and
    $registerSource -match "DimensionClaim = 'none'"
Add-Result 'configured dimensions are never promoted to replay-proven facts' $claimGuard `
    'launch and artifact manifests retain null observed dimensions until separate replay evidence exists'

$registrationGuard =
    $registerSource -match 'Assert-PSOBBPrivateRenderDocEvidencePath' -and
    $registerSource -match 'GetExtension\(\$CapturePath\) -cne ''\.rdc''' -and
    $registerSource -match 'Get-PSOBBStableFileIdentity' -and
    $registerSource -match 'SHA256\]::HashData' -and
    $registerSource -match 'changed while its identity was being computed' -and
    $registerSource -match 'Refusing to overwrite existing RenderDoc capture metadata'
Add-Result 'registration is path-contained, streaming, stable, and append-only' `
    $registrationGuard 'RDC size/SHA-256 are computed only for a stable file matching the private template'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-RenderDocTests-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
try {
    $runtimeRoot = Join-Path $temporaryRoot 'runtime'
    [void][System.IO.Directory]::CreateDirectory($runtimeRoot)
    $marker = [ordered]@{
        schemaVersion = 1
        installationId = [Guid]::NewGuid().ToString('D')
        runtimeRoot = $runtimeRoot
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $runtimeRoot '.psobb-runtime.json'),
        ($marker | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))

    function New-SyntheticRun {
        param(
            [Parameter(Mandatory)][string]$Suffix,
            [switch]$EmptyCapture,
            [string]$EvidenceStatus = 'pending-replay-inspection'
        )

        $runId = "20260714T120000000Z-renderdoc-$Suffix"
        $runRoot = Join-Path $runtimeRoot "graphics-evidence\lab-widescreen-16x10\$runId"
        $captureRoot = Join-Path $runRoot 'capture'
        [void][System.IO.Directory]::CreateDirectory($captureRoot)
        $capturePath = Join-Path $captureRoot 'psobb-frame_frame000123.rdc'
        if ($EmptyCapture) {
            [System.IO.File]::WriteAllBytes($capturePath, [byte[]]::new(0))
        } else {
            [System.IO.File]::WriteAllBytes(
                $capturePath,
                [System.Text.Encoding]::ASCII.GetBytes('synthetic-rdc-fixture'))
        }
        $launch = [ordered]@{
            schemaVersion = 1
            kind = 'psobb-renderdoc-launch'
            runId = $runId
            state = 'capture-armed-awaiting-manual-trigger'
            startedAtUtc = '2026-07-14T12:00:00.0000000Z'
            readyAtUtc = '2026-07-14T12:00:01.0000000Z'
            channel = 'local-lab'
            profile = [ordered]@{
                id = 'lab-widescreen-16x10'
                materializedFile = 'client-profile.json'
                materializedSha256 = ('a' * 64)
                requestedExpectations = [ordered]@{
                    internalRender = [ordered]@{
                        width = 3840
                        height = 2400
                        evidenceClass = 'configuration-only'
                    }
                    output = [ordered]@{
                        width = 2560
                        height = 1600
                        evidenceClass = 'configuration-and-window-only'
                    }
                    aspectPolicy = 'true-16:10'
                    outputApi = 'D3D11 FL11'
                }
            }
            target = [ordered]@{
                application = 'Psobb.exe'
                processId = 4242
            }
            renderDoc = [ordered]@{
                componentId = 'renderdoc-diagnostic'
                version = 'v1.45'
                commit = ('b' * 40)
                archiveSha256 = ('c' * 64)
                executableSha256 = ('d' * 64)
                captureIdentity = 31337
            }
            capture = [ordered]@{
                template = 'capture/psobb-frame'
                trigger = 'manual-f12'
                artifact = $null
            }
            renderTargetEvidence = [ordered]@{
                status = $EvidenceStatus
                observedInternalRender = $null
                observedOutput = $null
            }
        }
        [System.IO.File]::WriteAllText(
            (Join-Path $runRoot 'renderdoc-launch-manifest.json'),
            ($launch | ConvertTo-Json -Depth 20),
            [System.Text.UTF8Encoding]::new($false))
        [pscustomobject]@{
            RunRoot = $runRoot
            CapturePath = $capturePath
        }
    }

    $accepted = New-SyntheticRun -Suffix 'abcdef123456'
    $registered = & $registerScript `
        -RuntimeRoot $runtimeRoot `
        -RunRoot $accepted.RunRoot `
        -CapturePath $accepted.CapturePath
    $artifact = Get-Content -Raw -LiteralPath $registered.ArtifactManifestPath |
        ConvertFrom-Json -Depth 30
    $expectedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $accepted.CapturePath).
        Hash.ToLowerInvariant()
    Add-Result 'synthetic capture registration records exact immutable identity' (
        $registered.Registered -and
        [string]$registered.CaptureSha256 -ceq $expectedHash -and
        [long]$registered.CaptureByteSize -eq (Get-Item $accepted.CapturePath).Length -and
        [string]$artifact.capture.sha256 -ceq $expectedHash) `
        "sha256=$expectedHash"

    Add-Result 'synthetic capture registration preserves expectations without claims' (
        [int]$artifact.profile.requestedExpectations.internalRender.width -eq 3840 -and
        [int]$artifact.profile.requestedExpectations.output.width -eq 2560 -and
        [string]$artifact.replayEvidence.status -ceq 'not-provided' -and
        $null -eq $artifact.replayEvidence.observedInternalRender -and
        $null -eq $artifact.replayEvidence.observedOutput -and
        [string]$registered.DimensionClaim -ceq 'none') `
        '3840x2400 and 2560x1600 remain requested expectations only'

    $overwriteRejected = $false
    try {
        & $registerScript `
            -RuntimeRoot $runtimeRoot `
            -RunRoot $accepted.RunRoot `
            -CapturePath $accepted.CapturePath | Out-Null
    } catch {
        $overwriteRejected = $_.Exception.Message -match 'Refusing to overwrite'
    }
    Add-Result 'capture registration is append-only' $overwriteRejected `
        'an existing artifact manifest cannot be replaced'

    $wrongTemplate = New-SyntheticRun -Suffix 'abcdef123457'
    $wrongPath = Join-Path $wrongTemplate.RunRoot 'capture\unrelated.rdc'
    [System.IO.File]::WriteAllBytes(
        $wrongPath,
        [System.Text.Encoding]::ASCII.GetBytes('wrong-template'))
    $wrongTemplateRejected = $false
    try {
        & $registerScript `
            -RuntimeRoot $runtimeRoot `
            -RunRoot $wrongTemplate.RunRoot `
            -CapturePath $wrongPath | Out-Null
    } catch {
        $wrongTemplateRejected = $_.Exception.Message -match 'exact private capture template'
    }
    Add-Result 'registration rejects an unrelated RDC in the same run' `
        $wrongTemplateRejected 'capture name must begin with the launch-time template'

    $empty = New-SyntheticRun -Suffix 'abcdef123458' -EmptyCapture
    $emptyRejected = $false
    try {
        & $registerScript `
            -RuntimeRoot $runtimeRoot `
            -RunRoot $empty.RunRoot `
            -CapturePath $empty.CapturePath | Out-Null
    } catch {
        $emptyRejected = $_.Exception.Message -match 'invalid byte size'
    }
    Add-Result 'registration rejects an empty RDC' $emptyRejected `
        'a capture must contain at least one byte before hashing'

    $prematureClaim = New-SyntheticRun `
        -Suffix 'abcdef123459' `
        -EvidenceStatus 'verified'
    $claimRejected = $false
    try {
        & $registerScript `
            -RuntimeRoot $runtimeRoot `
            -RunRoot $prematureClaim.RunRoot `
            -CapturePath $prematureClaim.CapturePath | Out-Null
    } catch {
        $claimRejected = $_.Exception.Message -match 'capture-registration contract'
    }
    Add-Result 'registration rejects an unsupported pre-existing dimension claim' `
        $claimRejected 'launch metadata must still say replay inspection is pending'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    throw "$($failed.Count) RenderDoc tooling test(s) failed"
}

[pscustomobject]@{
    Suite = 'RenderDocTooling'
    Passed = $results.Count
    Failed = 0
}
