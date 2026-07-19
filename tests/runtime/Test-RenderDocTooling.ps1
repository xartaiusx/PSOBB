[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$captureScript = Join-Path $repositoryRoot 'scripts\Invoke-PSOBBRenderDocCapture.ps1'
$registerScript = Join-Path $repositoryRoot 'scripts\Register-PSOBBRenderDocCapture.ps1'
$replayScript = Join-Path $repositoryRoot 'scripts\Register-PSOBBRenderDocReplayEvidence.ps1'
$captureSource = Get-Content -Raw -LiteralPath $captureScript
$registerSource = Get-Content -Raw -LiteralPath $registerScript
$replaySource = Get-Content -Raw -LiteralPath $replayScript
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

foreach ($scriptPath in @($captureScript, $registerScript, $replayScript)) {
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

$compatibilityCallIndex = $captureSource.IndexOf(
    '$renderDocCompatibility = Assert-PSOBBRenderDocProfileCompatibility')
$evidenceDirectoryIndex = $captureSource.IndexOf(
    '[void][System.IO.Directory]::CreateDirectory($evidenceRoot)')
$registryMutationIndex = $captureSource.IndexOf(
    '$graphicsRegistryTransaction = Set-PSOBBClientNativeGraphics')
$processStartIndex = $captureSource.IndexOf(
    '$runner = [System.Diagnostics.Process]::Start($startInfo)')
Add-Result 'capture rejects an incompatible dgVoodoo import contract before side effects' (
    $compatibilityCallIndex -ge 0 -and
    $evidenceDirectoryIndex -gt $compatibilityCallIndex -and
    $registryMutationIndex -gt $compatibilityCallIndex -and
    $processStartIndex -gt $compatibilityCallIndex -and
    $captureSource -match
        'OriginalFirstThunk=0; launching it would produce API: None') `
    'the exact owner is inspected before evidence directories, registry changes, or RenderDoc start'

$compatibilitySource = [regex]::Match(
    $captureSource,
    '(?s)function Get-PSOBBDgVoodooRenderDocImportContract.*?(?=function ConvertTo-PSOBBUInt32ExitCode)').Value
Add-Result 'dgVoodoo compatibility inspection is read-only and leaves shared state alone' (
    -not [string]::IsNullOrWhiteSpace($compatibilitySource) -and
    $compatibilitySource -notmatch
        '(?i)renderdoc\.conf|Set-ItemProperty|New-ItemProperty|Set-Content|Add-Content|Copy-Item|Move-Item|Remove-Item|WriteAll(?:Bytes|Text)') `
    'the preflight reads only the exact D3D8 owner and never opens shared RenderDoc configuration'

Add-Result 'capture preserves validated local login persistence before delegated process creation' (
    $captureSource -match
        'Assert-PSOBBClientLoginRegistry\s*\|\s*Out-Null[\s\S]*?Set-PSOBBClientNativeGraphics[\s\S]*?\$runner\s*=\s*\[System\.Diagnostics\.Process\]::Start\(\$startInfo\)') `
    'RenderDoc validates registry types without reading or clearing the saved login'

Add-Result 'capture applies profile-owned native graphics under the lifecycle lock' (
    $captureSource -match 'Enter-PSOBBClientOperationLock' -and
    $captureSource -match
        'Set-PSOBBClientNativeGraphics[\s\S]*?\[System\.Diagnostics\.Process\]::Start\(\$startInfo\)' -and
    $captureSource -match 'nativeGraphicsPresetId' -and
    $captureSource -match 'graphicCtrlSha256' -and
    $captureSource -match 'Exit-PSOBBClientOperationLock') `
    'capture and ordinary launch share the exact hash-verified GRAPHICCTRL policy'

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
    $captureSource -notmatch '(?i)password|username|accountname|sendkeys|read-host'
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

$replayGuard =
    $replaySource -match 'manual-qrenderdoc-v1\.45-replay' -and
    $replaySource -match 'ReplayConfirmed' -and
    $replaySource -match 'requestedDimensionsMatched = \$true' -and
    $replaySource -match 'capture no longer matches its registered identity' -and
    $replaySource -match 'Refusing to overwrite existing RenderDoc replay evidence' -and
    $replaySource -match 'does not infer dimensions from configuration or the RDC file hash'
Add-Result 'replay attestation is explicit exact-capture and append-only' `
    $replayGuard 'manual qrenderdoc values must match the configured dimensions and registered RDC identity'

function Set-FixtureUInt16 {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint16]$Value
    )
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 2)
}

function Set-FixtureUInt32 {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint32]$Value
    )
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 4)
}

function Set-FixtureAscii {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][string]$Value
    )
    $encoded = [Text.Encoding]::ASCII.GetBytes($Value)
    [Array]::Copy($encoded, 0, $Bytes, $Offset, $encoded.Length)
}

function New-RenderDocPeImportFixture {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][uint32]$OriginalFirstThunkRva
    )

    $bytes = [byte[]]::new(0x600)
    $bytes[0] = 0x4D
    $bytes[1] = 0x5A
    Set-FixtureUInt32 -Bytes $bytes -Offset 0x3C -Value 0x80
    Set-FixtureUInt32 -Bytes $bytes -Offset 0x80 -Value 0x00004550
    Set-FixtureUInt16 -Bytes $bytes -Offset 0x84 -Value 0x014C
    Set-FixtureUInt16 -Bytes $bytes -Offset 0x86 -Value 1
    Set-FixtureUInt16 -Bytes $bytes -Offset 0x94 -Value 0x00E0
    Set-FixtureUInt16 -Bytes $bytes -Offset 0x96 -Value 0x210E

    $optionalHeader = 0x98
    Set-FixtureUInt16 -Bytes $bytes -Offset $optionalHeader -Value 0x010B
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 28) -Value 0x00400000
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 32) -Value 0x1000
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 36) -Value 0x200
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 56) -Value 0x2000
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 60) -Value 0x200
    Set-FixtureUInt16 -Bytes $bytes -Offset ($optionalHeader + 68) -Value 3
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 92) -Value 16
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 104) -Value 0x1000
    Set-FixtureUInt32 -Bytes $bytes -Offset ($optionalHeader + 108) -Value 40

    $sectionHeader = $optionalHeader + 0xE0
    Set-FixtureAscii -Bytes $bytes -Offset $sectionHeader -Value '.rdata'
    Set-FixtureUInt32 -Bytes $bytes -Offset ($sectionHeader + 8) -Value 0x400
    Set-FixtureUInt32 -Bytes $bytes -Offset ($sectionHeader + 12) -Value 0x1000
    Set-FixtureUInt32 -Bytes $bytes -Offset ($sectionHeader + 16) -Value 0x400
    Set-FixtureUInt32 -Bytes $bytes -Offset ($sectionHeader + 20) -Value 0x200
    Set-FixtureUInt32 -Bytes $bytes -Offset ($sectionHeader + 36) -Value 0x40000040

    Set-FixtureUInt32 -Bytes $bytes -Offset 0x200 -Value $OriginalFirstThunkRva
    Set-FixtureUInt32 -Bytes $bytes -Offset 0x20C -Value 0x1080
    Set-FixtureUInt32 -Bytes $bytes -Offset 0x210 -Value 0x1060
    foreach ($thunkOffset in @(0x240, 0x260)) {
        Set-FixtureUInt32 -Bytes $bytes -Offset $thunkOffset -Value 0x10A0
        Set-FixtureUInt32 -Bytes $bytes -Offset ($thunkOffset + 4) -Value 0x10C0
    }
    Set-FixtureAscii -Bytes $bytes -Offset 0x280 -Value "KERNEL32.DLL`0"
    Set-FixtureUInt16 -Bytes $bytes -Offset 0x2A0 -Value 0
    Set-FixtureAscii -Bytes $bytes -Offset 0x2A2 -Value "LoadLibraryA`0"
    Set-FixtureUInt16 -Bytes $bytes -Offset 0x2C0 -Value 0
    Set-FixtureAscii -Bytes $bytes -Offset 0x2C2 -Value "GetProcAddress`0"
    [IO.File]::WriteAllBytes($Path, $bytes)
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-RenderDocTests-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($temporaryRoot)
try {
    $fixtureRoot = Join-Path $temporaryRoot 'pe-fixtures'
    [void][System.IO.Directory]::CreateDirectory($fixtureRoot)
    $supportedFixture = Join-Path $fixtureRoot 'supported-d3d8.dll'
    $zeroOriginalThunkFixture = Join-Path $fixtureRoot 'zero-oft-d3d8.dll'
    New-RenderDocPeImportFixture `
        -Path $supportedFixture `
        -OriginalFirstThunkRva 0x1040
    New-RenderDocPeImportFixture `
        -Path $zeroOriginalThunkFixture `
        -OriginalFirstThunkRva 0
    $fixtureHashesBefore = @(
        @($supportedFixture, $zeroOriginalThunkFixture) | ForEach-Object {
            (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash
        })
    $fixtureNamesBefore = @(
        Get-ChildItem -LiteralPath $fixtureRoot -File | Sort-Object Name |
            ForEach-Object Name)
    $psobbIdsBefore = @(
        Get-Process -Name 'Psobb' -ErrorAction SilentlyContinue |
            Sort-Object Id | ForEach-Object Id)

    . $captureScript -ProfileId 'renderdoc-test-probe'
    $supportedContract = Get-PSOBBDgVoodooRenderDocImportContract `
        -Path $supportedFixture
    $zeroOriginalThunkContract = Get-PSOBBDgVoodooRenderDocImportContract `
        -Path $zeroOriginalThunkFixture
    Add-Result 'synthetic PE fixtures expose the exact KERNEL32 import contract' (
        [uint32]$supportedContract.OriginalFirstThunkRva -eq 0x1040 -and
        [uint32]$zeroOriginalThunkContract.OriginalFirstThunkRva -eq 0 -and
        @($supportedContract.Imports) -ccontains 'LoadLibraryA' -and
        @($supportedContract.Imports) -ccontains 'GetProcAddress') `
        'the executable parser reads named loader imports and OriginalFirstThunk from PE32 bytes'

    $supportedAccepted = $false
    try {
        $acceptedContract = Assert-PSOBBDgVoodooRenderDocCompatibility `
            -Path $supportedFixture
        $supportedAccepted = $acceptedContract.RenderDocV145Compatible
    } catch { }
    Add-Result 'nonzero OriginalFirstThunk passes the RenderDoc compatibility gate' `
        $supportedAccepted 'a normal named-import lookup table remains eligible for capture'

    $zeroOriginalThunkRejected = $false
    $zeroOriginalThunkMessage = ''
    try {
        Assert-PSOBBDgVoodooRenderDocCompatibility `
            -Path $zeroOriginalThunkFixture | Out-Null
    } catch {
        $zeroOriginalThunkMessage = $_.Exception.Message
        $zeroOriginalThunkRejected =
            $zeroOriginalThunkMessage -match 'OriginalFirstThunk=0' -and
            $zeroOriginalThunkMessage -match 'API: None'
    }
    Add-Result 'zero OriginalFirstThunk fails closed with the API-None diagnosis' `
        $zeroOriginalThunkRejected $zeroOriginalThunkMessage

    $fixtureHashesAfter = @(
        @($supportedFixture, $zeroOriginalThunkFixture) | ForEach-Object {
            (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash
        })
    $fixtureNamesAfter = @(
        Get-ChildItem -LiteralPath $fixtureRoot -File | Sort-Object Name |
            ForEach-Object Name)
    Add-Result 'compatibility inspection does not mutate its PE inputs' (
        @(Compare-Object $fixtureHashesBefore $fixtureHashesAfter).Count -eq 0 -and
        @(Compare-Object $fixtureNamesBefore $fixtureNamesAfter).Count -eq 0) `
        'both fixture hashes and the containing file inventory remain unchanged'

    Add-Result 'zero-OFT preflight creates no evidence or process artifacts' (
        @(Get-ChildItem -LiteralPath $temporaryRoot -Directory |
            Where-Object Name -ne 'pe-fixtures').Count -eq 0 -and
        @(Compare-Object `
            $psobbIdsBefore `
            @(Get-Process -Name 'Psobb' -ErrorAction SilentlyContinue |
                Sort-Object Id | ForEach-Object Id)).Count -eq 0) `
        'the executable rejection path only reads the supplied PE fixture'

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

    $replay = & $replayScript `
        -RuntimeRoot $runtimeRoot `
        -RunRoot $accepted.RunRoot `
        -PresentEventId 123 `
        -BackbufferWidth 2560 `
        -BackbufferHeight 1600 `
        -InternalRenderWidth 3840 `
        -InternalRenderHeight 2400 `
        -BackbufferFormat DXGI_FORMAT_R8G8B8A8_UNORM `
        -InternalRenderFormat DXGI_FORMAT_R8G8B8A8_UNORM `
        -ReplayConfirmed `
        -Confirm:$false
    $replayRecord = Get-Content -Raw -LiteralPath $replay.EvidencePath |
        ConvertFrom-Json -Depth 30
    Add-Result 'synthetic replay attestation records exact observed dimensions' (
        $replay.Registered -and
        [string]$replayRecord.status -ceq 'replay-inspected-pass' -and
        [int]$replayRecord.observedOutput.width -eq 2560 -and
        [int]$replayRecord.observedOutput.height -eq 1600 -and
        [int]$replayRecord.observedInternalRender.width -eq 3840 -and
        [int]$replayRecord.observedInternalRender.height -eq 2400 -and
        [bool]$replayRecord.requestedDimensionsMatched) `
        'manual replay evidence is separate from the integrity-only capture artifact'

    $mismatch = New-SyntheticRun -Suffix 'abcdef123460'
    & $registerScript -RuntimeRoot $runtimeRoot `
        -RunRoot $mismatch.RunRoot -CapturePath $mismatch.CapturePath | Out-Null
    $mismatchRejected = $false
    try {
        & $replayScript `
            -RuntimeRoot $runtimeRoot `
            -RunRoot $mismatch.RunRoot `
            -PresentEventId 124 `
            -BackbufferWidth 1920 `
            -BackbufferHeight 1080 `
            -InternalRenderWidth 3840 `
            -InternalRenderHeight 2400 `
            -BackbufferFormat DXGI_FORMAT_R8G8B8A8_UNORM `
            -InternalRenderFormat DXGI_FORMAT_R8G8B8A8_UNORM `
            -ReplayConfirmed `
            -Confirm:$false | Out-Null
    } catch {
        $mismatchRejected = $_.Exception.Message -match
            'does not confirm the exact configured'
    }
    Add-Result 'replay attestation rejects mismatched dimensions' `
        $mismatchRejected 'observed replay values cannot be promoted when they differ from the exact profile'

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
