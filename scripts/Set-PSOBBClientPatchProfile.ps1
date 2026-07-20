[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('stable-qol', 'baseline')]
    [string]$Profile = 'baseline',
    [string]$RuntimeRoot,
    [Parameter(DontShow = $true)][string]$InternalTestFaultPoint,
    [Parameter(DontShow = $true)][string]$InternalTestFaultToken
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$script:PatchProfileFaultArmed = $false

function Assert-PatchProfileInternalFaultGate(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Marker
) {
    if ([string]::IsNullOrWhiteSpace($InternalTestFaultPoint) -and
        [string]::IsNullOrWhiteSpace($InternalTestFaultToken)) {
        return $true
    }
    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root)
    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $fixtureName = [System.IO.Path]::GetFileName($root.TrimEnd('\'))
    $fixtureMarker = Join-Path $root '.recovery-test.json'
    if ([string]::IsNullOrWhiteSpace($InternalTestFaultPoint) -or
        [string]$Marker.installationId -cne $InternalTestFaultToken -or
        -not $root.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fixtureName -cnotmatch '^PSOBB-RecoveryTests-[a-f0-9]{32}$' -or
        -not (Test-Path -LiteralPath $fixtureMarker -PathType Leaf) -or
        -not (Test-PSOBBProtectedAcl -Path $fixtureMarker)) {
        throw 'Internal patch-profile fault injection is restricted to an explicit protected temporary fixture'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $fixtureMarker -Root $root -Kind File `
            -Label 'internal patch-profile test marker')
    $script:PatchProfileFaultArmed = $true
    $true
}

function Invoke-PatchProfileInternalFault(
    [Parameter(Mandatory)][string]$Point
) {
    if ($script:PatchProfileFaultArmed -and
        $InternalTestFaultPoint -ceq $Point) {
        $script:PatchProfileFaultArmed = $false
        throw "Injected internal patch-profile fault at $Point"
    }
}

function Get-PatchProfileTransactionPaths(
    [Parameter(Mandatory)]$Layout
) {
    $transactionRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Stable '.client-patch-profile-transaction') `
        -Root $Layout.Root
    [pscustomobject]@{
        Root = $transactionRoot
        Journal = Join-Path $transactionRoot 'journal.json'
        JournalNext = Join-Path $transactionRoot 'journal.next'
        OriginalConfig = Join-Path $transactionRoot 'original-config.bin'
        OriginalInstallation = Join-Path $transactionRoot 'original-installation.json'
        CandidateConfig = Join-Path $transactionRoot 'candidate-config.json'
        CandidateInstallation = Join-Path $transactionRoot 'candidate-installation.json'
        ConfigInstallTemporary = Join-Path $Layout.Server `
            'system\.client-patch-profile-config.new'
        InstallationInstallTemporary = Join-Path $Layout.Stable `
            '.client-patch-profile-installation.new'
    }
}

function Get-PatchProfileFileDigest(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Label
) {
    Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Path -Root $Root -MaximumBytes 16MB -AllowEmpty -Label $Label
}

function Assert-PatchProfileDigest(
    [Parameter(Mandatory)]$Digest,
    [Parameter(Mandatory)][long]$ExpectedLength,
    [Parameter(Mandatory)][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$Label
) {
    if ($Digest.Length -ne $ExpectedLength -or
        $Digest.Sha256 -cne $ExpectedSha256) {
        throw "$Label differs from its sealed transaction digest"
    }
    $true
}

function Write-PatchProfileArtifact(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Root,
    [AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][string]$FaultPrefix
) {
    [void](Write-PSOBBDurableFileBytes `
            -Path $Path -Root $Root -Bytes $Bytes `
            -Label 'patch-profile transaction artifact')
    try {
        Invoke-PatchProfileInternalFault -Point "$FaultPrefix-before-acl"
    } finally {
        Set-PSOBBProtectedAcl -Path $Path
    }
    Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-acl"
    $expectedSha256 = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
    $readback = Get-PatchProfileFileDigest `
        -Path $Path -Root $Root -Label 'patch-profile transaction artifact'
    [void](Assert-PatchProfileDigest `
            -Digest $readback -ExpectedLength $Bytes.Length `
            -ExpectedSha256 $expectedSha256 `
            -Label 'Patch-profile transaction artifact')
    Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-readback"
    [pscustomobject]@{
        Length = [long]$Bytes.Length
        Sha256 = $expectedSha256
    }
}

function Assert-PatchProfileJournalValue(
    [Parameter(Mandatory)]$Value,
    [Parameter(Mandatory)][string]$InstallationId
) {
    $properties = @(
        'schemaVersion', 'installationId', 'transactionId', 'phase',
        'requestedProfile', 'originalProfile', 'originalConfigSha256',
        'originalConfigSize', 'originalInstallationSha256',
        'originalInstallationSize', 'candidateConfigSha256',
        'candidateConfigSize', 'candidateInstallationSha256',
        'candidateInstallationSize')
    Assert-PSOBBStrictDataObjectProperties `
        -Value $Value -Expected $properties `
        -Label 'patch-profile transaction journal' | Out-Null
    foreach ($name in @($properties | Where-Object {
                $_ -notin @(
                    'schemaVersion', 'originalConfigSize',
                    'originalInstallationSize', 'candidateConfigSize',
                    'candidateInstallationSize')
            })) {
        if ($Value.$name -isnot [string]) {
            throw "Patch-profile transaction journal '$name' is not text"
        }
    }
    foreach ($name in @(
            'schemaVersion', 'originalConfigSize', 'originalInstallationSize',
            'candidateConfigSize', 'candidateInstallationSize')) {
        if ($Value.$name -isnot [long]) {
            throw "Patch-profile transaction journal '$name' is not an Int64"
        }
    }
    if ($Value.schemaVersion -ne 1 -or
        [string]$Value.installationId -cne $InstallationId -or
        [string]$Value.transactionId -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$Value.phase -cnotin @(
            'prepared', 'installing-config', 'config-installed',
            'installing-installation', 'pair-installed', 'verified',
            'compensating') -or
        [string]$Value.requestedProfile -cnotmatch
            '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
        [string]$Value.originalProfile -cnotmatch
            '^[a-z0-9]+(?:-[a-z0-9]+)*$') {
        throw 'Patch-profile transaction journal identity or phase is invalid'
    }
    foreach ($name in @(
            'originalConfigSha256', 'originalInstallationSha256',
            'candidateConfigSha256', 'candidateInstallationSha256')) {
        if ([string]$Value.$name -cnotmatch '^[a-f0-9]{64}$') {
            throw "Patch-profile transaction journal '$name' is invalid"
        }
    }
    foreach ($name in @(
            'originalConfigSize', 'originalInstallationSize',
            'candidateConfigSize', 'candidateInstallationSize')) {
        if ([long]$Value.$name -lt 0 -or [long]$Value.$name -gt 16MB) {
            throw "Patch-profile transaction journal '$name' is out of range"
        }
    }
    $Value
}

function Read-PatchProfileJournal(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)][string]$InstallationId
) {
    $snapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $Paths.Journal -Root $Paths.Root -MaximumBytes 64KB `
        -MaximumDepth 5 -Label 'patch-profile transaction journal'
    [pscustomobject]@{
        Value = Assert-PatchProfileJournalValue `
            -Value $snapshot.Value -InstallationId $InstallationId
        Sha256 = [string]$snapshot.Sha256
    }
}

function Write-PatchProfileJournal(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Journal,
    [Parameter(Mandatory)][string]$InstallationId
) {
    if (Test-Path -LiteralPath $Paths.JournalNext) {
        Remove-Item -LiteralPath $Paths.JournalNext -Force -ErrorAction Stop
    }
    $journalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Journal | ConvertTo-Json -Depth 4))
    try {
        [void](Write-PSOBBDurableFileBytes `
                -Path $Paths.JournalNext -Root $Paths.Root -Bytes $journalBytes `
                -Label 'patch-profile transaction journal staging')
        try {
            Invoke-PatchProfileInternalFault -Point 'journal-before-acl'
        } finally {
            Set-PSOBBProtectedAcl -Path $Paths.JournalNext
        }
        Invoke-PatchProfileInternalFault -Point 'journal-after-acl'
        $staged = Read-PSOBBStrictJsonSnapshot `
            -Path $Paths.JournalNext -Root $Paths.Root -MaximumBytes 64KB `
            -MaximumDepth 5 -Label 'patch-profile transaction journal staging'
        [void](Assert-PatchProfileJournalValue `
                -Value $staged.Value -InstallationId $InstallationId)
        Invoke-PatchProfileInternalFault -Point 'journal-after-readback'
        [System.IO.File]::Move($Paths.JournalNext, $Paths.Journal, $true)
        Invoke-PatchProfileInternalFault -Point 'journal-after-move'
        $installed = Read-PatchProfileJournal `
            -Paths $Paths -InstallationId $InstallationId
        if ($installed.Sha256 -cne $staged.Sha256) {
            throw 'Patch-profile transaction journal changed during publication'
        }
    } finally {
        [Array]::Clear($journalBytes, 0, $journalBytes.Length)
        if (Test-Path -LiteralPath $Paths.JournalNext) {
            Remove-Item -LiteralPath $Paths.JournalNext -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

function Set-PatchProfileJournalPhase(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Journal,
    [Parameter(Mandatory)][string]$Phase,
    [Parameter(Mandatory)][string]$InstallationId
) {
    $Journal.phase = $Phase
    Write-PatchProfileJournal `
        -Paths $Paths -Journal $Journal -InstallationId $InstallationId
}

function Install-PatchProfileArtifact(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$TransactionRoot,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$DestinationRoot,
    [Parameter(Mandatory)][string]$Temporary,
    [Parameter(Mandatory)][long]$ExpectedLength,
    [Parameter(Mandatory)][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$FaultPrefix
) {
    $sourceSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Source -Root $TransactionRoot -MaximumBytes 16MB `
        -AllowEmpty -IncludeBytes -Label 'patch-profile transaction source'
    try {
        [void](Assert-PatchProfileDigest `
                -Digest $sourceSnapshot -ExpectedLength $ExpectedLength `
                -ExpectedSha256 $ExpectedSha256 `
                -Label 'Patch-profile transaction source')
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force -ErrorAction Stop
        }
        [void](Write-PSOBBDurableFileBytes `
                -Path $Temporary -Root $DestinationRoot `
                -Bytes ([byte[]]$sourceSnapshot.Bytes) `
                -Label 'patch-profile install staging')
        try {
            Invoke-PatchProfileInternalFault -Point "$FaultPrefix-before-acl"
        } finally {
            Set-PSOBBProtectedAcl -Path $Temporary
        }
        Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-acl"
        $temporaryDigest = Get-PatchProfileFileDigest `
            -Path $Temporary -Root $DestinationRoot `
            -Label 'patch-profile install staging'
        [void](Assert-PatchProfileDigest `
                -Digest $temporaryDigest -ExpectedLength $ExpectedLength `
                -ExpectedSha256 $ExpectedSha256 `
                -Label 'Patch-profile install staging')
        Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-staging-readback"
        [System.IO.File]::Move($Temporary, $Destination, $true)
        Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-move"
        Set-PSOBBProtectedAcl -Path $Destination
        Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-destination-acl"
        $installedDigest = Get-PatchProfileFileDigest `
            -Path $Destination -Root $DestinationRoot `
            -Label 'patch-profile installed file'
        [void](Assert-PatchProfileDigest `
                -Digest $installedDigest -ExpectedLength $ExpectedLength `
                -ExpectedSha256 $ExpectedSha256 `
                -Label 'Patch-profile installed file')
        Invoke-PatchProfileInternalFault -Point "$FaultPrefix-after-destination-readback"
    } finally {
        if ($sourceSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$sourceSnapshot.Bytes, 0,
                ([byte[]]$sourceSnapshot.Bytes).Length)
        }
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

function Remove-PatchProfileTransaction(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout
) {
    if (Test-Path -LiteralPath $Paths.Root) {
        Remove-PSOBBValidatedRecoveryTree `
            -Path $Paths.Root -Root $Layout.Stable `
            -Label 'patch-profile transaction' -RequireProtectedAcl
    }
}

function Assert-PatchProfileTransactionArtifacts(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Journal
) {
    $definitions = @(
        [pscustomobject]@{
            Path = $Paths.OriginalConfig
            Size = [long]$Journal.originalConfigSize
            Sha256 = [string]$Journal.originalConfigSha256
        }
        [pscustomobject]@{
            Path = $Paths.OriginalInstallation
            Size = [long]$Journal.originalInstallationSize
            Sha256 = [string]$Journal.originalInstallationSha256
        }
        [pscustomobject]@{
            Path = $Paths.CandidateConfig
            Size = [long]$Journal.candidateConfigSize
            Sha256 = [string]$Journal.candidateConfigSha256
        }
        [pscustomobject]@{
            Path = $Paths.CandidateInstallation
            Size = [long]$Journal.candidateInstallationSize
            Sha256 = [string]$Journal.candidateInstallationSha256
        }
    )
    foreach ($definition in $definitions) {
        if (-not (Test-PSOBBProtectedAcl -Path $definition.Path)) {
            throw 'Patch-profile transaction artifact ACL is not exact'
        }
        $digest = Get-PatchProfileFileDigest `
            -Path $definition.Path -Root $Paths.Root `
            -Label 'patch-profile transaction artifact'
        [void](Assert-PatchProfileDigest `
                -Digest $digest -ExpectedLength $definition.Size `
                -ExpectedSha256 $definition.Sha256 `
                -Label 'Patch-profile transaction artifact')
    }
    $true
}

function Repair-PatchProfileTransactionProtection(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout
) {
    if (-not (Test-Path -LiteralPath $Paths.Root -PathType Container)) {
        return
    }
    [void](Get-PSOBBOrdinaryTreeSnapshot `
            -Path $Paths.Root -Root $Layout.Stable `
            -Label 'patch-profile transaction recovery')
    Set-PSOBBProtectedTreeAcl -Path $Paths.Root -Root $Layout.Stable
}

function Restore-PatchProfileOriginalPair(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Journal,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$InstallRecordPath,
    [Parameter(Mandatory)][string]$InstallationId
) {
    Set-PatchProfileJournalPhase `
        -Paths $Paths -Journal $Journal -Phase 'compensating' `
        -InstallationId $InstallationId
    Install-PatchProfileArtifact `
        -Source $Paths.OriginalInstallation -TransactionRoot $Paths.Root `
        -Destination $InstallRecordPath -DestinationRoot $Layout.Root `
        -Temporary $Paths.InstallationInstallTemporary `
        -ExpectedLength ([long]$Journal.originalInstallationSize) `
        -ExpectedSha256 ([string]$Journal.originalInstallationSha256) `
        -FaultPrefix 'compensate-installation'
    Install-PatchProfileArtifact `
        -Source $Paths.OriginalConfig -TransactionRoot $Paths.Root `
        -Destination $ConfigPath -DestinationRoot $Layout.Root `
        -Temporary $Paths.ConfigInstallTemporary `
        -ExpectedLength ([long]$Journal.originalConfigSize) `
        -ExpectedSha256 ([string]$Journal.originalConfigSha256) `
        -FaultPrefix 'compensate-config'
    $configDigest = Get-PatchProfileFileDigest `
        -Path $ConfigPath -Root $Layout.Root -Label 'restored patch-profile config'
    $recordDigest = Get-PatchProfileFileDigest `
        -Path $InstallRecordPath -Root $Layout.Root `
        -Label 'restored patch-profile installation record'
    [void](Assert-PatchProfileDigest `
            -Digest $configDigest `
            -ExpectedLength ([long]$Journal.originalConfigSize) `
            -ExpectedSha256 ([string]$Journal.originalConfigSha256) `
            -Label 'Restored patch-profile config')
    [void](Assert-PatchProfileDigest `
            -Digest $recordDigest `
            -ExpectedLength ([long]$Journal.originalInstallationSize) `
            -ExpectedSha256 ([string]$Journal.originalInstallationSha256) `
            -Label 'Restored patch-profile installation record')
    Invoke-PatchProfileInternalFault -Point 'compensate-after-pair-readback'
}

function Resolve-PatchProfileInterruptedTransaction(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$InstallRecordPath,
    [Parameter(Mandatory)][string]$InstallationId
) {
    if (-not (Test-Path -LiteralPath $Paths.Root)) {
        return $false
    }
    Repair-PatchProfileTransactionProtection -Paths $Paths -Layout $Layout
    if (-not (Test-Path -LiteralPath $Paths.Journal -PathType Leaf)) {
        $currentConfig = Get-PatchProfileFileDigest `
            -Path $ConfigPath -Root $Layout.Root -Label 'current patch-profile config'
        $currentRecord = Get-PatchProfileFileDigest `
            -Path $InstallRecordPath -Root $Layout.Root `
            -Label 'current patch-profile installation record'
        if (Test-Path -LiteralPath $Paths.OriginalConfig -PathType Leaf) {
            $originalConfig = Get-PatchProfileFileDigest `
                -Path $Paths.OriginalConfig -Root $Paths.Root `
                -Label 'orphaned original patch-profile config'
            if ($currentConfig.Sha256 -cne $originalConfig.Sha256 -or
                $currentConfig.Length -ne $originalConfig.Length) {
                throw ('An unjournaled patch-profile transaction does not match ' +
                    'the live config. Keep the runtime stopped and preserve it.')
            }
        }
        if (Test-Path -LiteralPath $Paths.OriginalInstallation -PathType Leaf) {
            $originalRecord = Get-PatchProfileFileDigest `
                -Path $Paths.OriginalInstallation -Root $Paths.Root `
                -Label 'orphaned original patch-profile installation record'
            if ($currentRecord.Sha256 -cne $originalRecord.Sha256 -or
                $currentRecord.Length -ne $originalRecord.Length) {
                throw ('An unjournaled patch-profile transaction does not match ' +
                    'the live installation record. Keep the runtime stopped and ' +
                    'preserve it.')
            }
        }
        $liveRecord = (Read-PSOBBInstallationRecordSnapshot `
                -Path $InstallRecordPath -Root $Layout.Root `
                -ExpectedInstallationId $InstallationId `
                -ExpectedRuntimeRoot $Layout.Root).Value
        $livePolicy = Get-PSOBBClientPatchPolicy
        $liveProfiles = @($livePolicy.profiles | Where-Object {
                $_.id -ceq [string]$liveRecord.clientPatchProfile -and
                $_.channel -ceq 'stable'
            })
        $liveConfigSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
            -Path $ConfigPath -Root $Layout.Root -MaximumBytes 16MB `
            -IncludeBytes -Label 'live patch-profile config'
        try {
            $liveConfigText = [System.Text.UTF8Encoding]::new(
                $false, $true).GetString([byte[]]$liveConfigSnapshot.Bytes)
            if ($liveProfiles.Count -ne 1 -or
                -not (Test-ExactStringSequence `
                    -Expected @($liveProfiles[0].autoPatches) `
                    -Actual @(Get-ActiveConfigStringArray `
                        -Text $liveConfigText -Key 'AutoPatches')) -or
                -not (Test-ExactStringSequence `
                    -Expected @($liveProfiles[0].bbRequiredPatches) `
                    -Actual @(Get-ActiveConfigStringArray `
                        -Text $liveConfigText -Key 'BBRequiredPatches'))) {
                throw ('An unjournaled patch-profile transaction has no provable ' +
                    'unchanged live pair. Keep the runtime stopped and preserve it.')
            }
        } finally {
            [Array]::Clear(
                [byte[]]$liveConfigSnapshot.Bytes, 0,
                ([byte[]]$liveConfigSnapshot.Bytes).Length)
        }
        Remove-PatchProfileTransaction -Paths $Paths -Layout $Layout
        return $true
    }

    $journal = (Read-PatchProfileJournal `
            -Paths $Paths -InstallationId $InstallationId).Value
    [void](Assert-PatchProfileTransactionArtifacts `
            -Paths $Paths -Journal $journal)
    $currentConfig = Get-PatchProfileFileDigest `
        -Path $ConfigPath -Root $Layout.Root -Label 'current patch-profile config'
    $currentRecord = Get-PatchProfileFileDigest `
        -Path $InstallRecordPath -Root $Layout.Root `
        -Label 'current patch-profile installation record'
    $isOriginal =
        $currentConfig.Length -eq [long]$journal.originalConfigSize -and
        $currentConfig.Sha256 -ceq [string]$journal.originalConfigSha256 -and
        $currentRecord.Length -eq [long]$journal.originalInstallationSize -and
        $currentRecord.Sha256 -ceq [string]$journal.originalInstallationSha256
    $isCandidate =
        $currentConfig.Length -eq [long]$journal.candidateConfigSize -and
        $currentConfig.Sha256 -ceq [string]$journal.candidateConfigSha256 -and
        $currentRecord.Length -eq [long]$journal.candidateInstallationSize -and
        $currentRecord.Sha256 -ceq [string]$journal.candidateInstallationSha256

    if ($isCandidate) {
        Set-PSOBBProtectedAcl -Path $ConfigPath
        Set-PSOBBProtectedAcl -Path $InstallRecordPath
        $accepted = Assert-PSOBBClientPatchStateCoherent `
            -ConfigPath $ConfigPath -InstallRecordPath $InstallRecordPath `
            -InstallationId $InstallationId -RuntimeRoot $Layout.Root
        if ($accepted.Profile -cne [string]$journal.requestedProfile) {
            throw 'Interrupted patch-profile candidate does not match its journal'
        }
    } elseif (-not $isOriginal) {
        Restore-PatchProfileOriginalPair `
            -Paths $Paths -Layout $Layout -Journal $journal `
            -ConfigPath $ConfigPath -InstallRecordPath $InstallRecordPath `
            -InstallationId $InstallationId
    } else {
        Set-PSOBBProtectedAcl -Path $ConfigPath
        Set-PSOBBProtectedAcl -Path $InstallRecordPath
    }
    Remove-PatchProfileTransaction -Paths $Paths -Layout $Layout
    $true
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$clientOperationMutex = $null
$serverMutex = $null
$ownsServerMutex = $false
try {
    $clientOperationMutex = Enter-PSOBBClientOperationLock `
        -Layout $layout -TimeoutSeconds 0
    $marker = Assert-PSOBBRuntimeMarker -Layout $layout
    $mutexName = 'Local\PSOBB.Newserv.Start.' +
        ([string]$marker.installationId).Replace('-', '')
    $serverMutex = [System.Threading.Mutex]::new($false, $mutexName)
    try {
        $ownsServerMutex = $serverMutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $ownsServerMutex = $true
    }
    if (-not $ownsServerMutex) {
        throw 'Another PSOBB lifecycle or recovery operation is already in progress'
    }
    Assert-PatchProfileInternalFaultGate `
        -Layout $layout -Marker $marker | Out-Null
    Assert-PSOBBGlobalStoppedRuntime `
        -Layout $layout -Operation 'changing the Stable client-patch profile' |
        Out-Null

    $configPath = Assert-PathWithinRoot `
        -Path (Join-Path $layout.Server 'system\config.json') `
        -Root $layout.Root
    $installRecordPath = Assert-PathWithinRoot `
        -Path $layout.InstallRecord -Root $layout.Root
    $paths = Get-PatchProfileTransactionPaths -Layout $layout
    foreach ($path in @($configPath, $installRecordPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Required Stable patch-profile metadata is missing'
        }
    }
    if ([System.IO.Path]::GetPathRoot($paths.Root) -cne
            [System.IO.Path]::GetPathRoot($configPath) -or
        [System.IO.Path]::GetPathRoot($paths.Root) -cne
            [System.IO.Path]::GetPathRoot($installRecordPath)) {
        throw 'Patch-profile journal and both target files are not on one volume'
    }

    $recoveredInterruptedTransaction = $false
    try {
        $recoveredInterruptedTransaction = Resolve-PatchProfileInterruptedTransaction `
            -Paths $paths -Layout $layout -ConfigPath $configPath `
            -InstallRecordPath $installRecordPath `
            -InstallationId ([string]$marker.installationId)
    } catch {
        throw ('Protected patch-profile recovery did not complete. Keep both ' +
            'server environments stopped, preserve the transaction tree, and ' +
            'rerun Set-PSOBBClientPatchProfile.ps1 to resume recovery.')
    }

    $policyPath = Join-Path $script:PSOBBRepositoryRoot `
        'config\client-patch-profiles.json'
    $policySnapshot = Read-PSOBBClientPatchPolicySnapshot -Path $policyPath
    $policy = $policySnapshot.Value
    $selectedProfiles = @($policy.profiles | Where-Object id -CEQ $Profile)
    if ($selectedProfiles.Count -ne 1 -or
        [string]$selectedProfiles[0].channel -cne 'stable') {
        throw "The requested client-patch profile is not approved for stable: $Profile"
    }
    Assert-NewservClientPatchProfileAvailable `
        -ServerRoot $layout.Server -Profile $Profile -PolicyPath $policyPath |
        Out-Null

    $originalConfigSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $configPath -Root $layout.Root -MaximumBytes 16MB `
        -IncludeBytes -Label 'Stable client-patch config'
    $originalRecordSnapshot = Read-PSOBBInstallationRecordSnapshot `
        -Path $installRecordPath -Root $layout.Root `
        -ExpectedInstallationId ([string]$marker.installationId) `
        -ExpectedRuntimeRoot $layout.Root
    $originalRecordBytesSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $installRecordPath -Root $layout.Root -MaximumBytes 256KB `
        -IncludeBytes -Label 'Stable installation record bytes'
    try {
        $originalConfig = [System.Text.UTF8Encoding]::new(
            $false, $true).GetString([byte[]]$originalConfigSnapshot.Bytes)
        $updatedConfig = Get-NewservClientPatchConfiguration `
            -Text $originalConfig -Profile $Profile -PolicyPath $policyPath
        $observedAutoPatches = @(
            Get-ActiveConfigStringArray -Text $updatedConfig -Key 'AutoPatches')
        $observedRequiredPatches = @(
            Get-ActiveConfigStringArray -Text $updatedConfig `
                -Key 'BBRequiredPatches')
        if (-not (Test-ExactStringSequence `
                -Expected @($selectedProfiles[0].autoPatches) `
                -Actual $observedAutoPatches) -or
            -not (Test-ExactStringSequence `
                -Expected @($selectedProfiles[0].bbRequiredPatches) `
                -Actual $observedRequiredPatches)) {
            throw 'Client-patch profile transform did not produce the selected profile'
        }

        $record = $originalRecordSnapshot.Value
        $originalRecordProfile = [string]$record.clientPatchProfile
        $originalRecordPolicySha256 = [string]$record.clientPatchPolicySha256
        $record.clientPatchProfile = $Profile
        $record.clientPatchPolicySha256 = [string]$policySnapshot.Sha256
        $updatedRecordText = $record | ConvertTo-Json -Depth 6
        $updatedConfigBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            $updatedConfig)
        $updatedRecordBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            $updatedRecordText)
        try {
            $alreadyApplied =
                $originalConfig -ceq $updatedConfig -and
                $originalRecordProfile -ceq $Profile -and
                $originalRecordPolicySha256 -ceq
                    [string]$policySnapshot.Sha256 -and
                (Test-PSOBBProtectedAcl -Path $configPath) -and
                (Test-PSOBBProtectedAcl -Path $installRecordPath)
            $applied = $false
            if (-not $alreadyApplied -and $PSCmdlet.ShouldProcess(
                    $layout.Root,
                    "apply the journaled Stable client-patch profile '$Profile'")) {
                if (Test-Path -LiteralPath $paths.Root) {
                    throw 'A patch-profile transaction unexpectedly exists after recovery'
                }
                New-Item -ItemType Directory -Path $paths.Root | Out-Null
                try {
                    Invoke-PatchProfileInternalFault `
                        -Point 'transaction-root-before-acl'
                } finally {
                    Set-PSOBBProtectedAcl -Path $paths.Root
                }
                Invoke-PatchProfileInternalFault `
                    -Point 'transaction-root-after-acl'

                $originalConfigArtifact = Write-PatchProfileArtifact `
                    -Path $paths.OriginalConfig -Root $paths.Root `
                    -Bytes ([byte[]]$originalConfigSnapshot.Bytes) `
                    -FaultPrefix 'prepare-original-config'
                $originalRecordArtifact = Write-PatchProfileArtifact `
                    -Path $paths.OriginalInstallation -Root $paths.Root `
                    -Bytes ([byte[]]$originalRecordBytesSnapshot.Bytes) `
                    -FaultPrefix 'prepare-original-installation'
                $candidateConfigArtifact = Write-PatchProfileArtifact `
                    -Path $paths.CandidateConfig -Root $paths.Root `
                    -Bytes $updatedConfigBytes `
                    -FaultPrefix 'prepare-candidate-config'
                $candidateRecordArtifact = Write-PatchProfileArtifact `
                    -Path $paths.CandidateInstallation -Root $paths.Root `
                    -Bytes $updatedRecordBytes `
                    -FaultPrefix 'prepare-candidate-installation'

                $candidateState = Assert-PSOBBClientPatchStateCoherent `
                    -ConfigPath $paths.CandidateConfig `
                    -InstallRecordPath $paths.CandidateInstallation `
                    -InstallationId ([string]$marker.installationId) `
                    -RuntimeRoot $layout.Root -PolicyPath $policyPath
                if ($candidateState.Profile -cne $Profile -or
                    $candidateState.PolicySha256 -cne $policySnapshot.Sha256) {
                    throw 'Staged patch-profile pair failed semantic coherence'
                }
                $journal = [ordered]@{
                    schemaVersion = 1
                    installationId = [string]$marker.installationId
                    transactionId = [Guid]::NewGuid().ToString('N')
                    phase = 'prepared'
                    requestedProfile = $Profile
                    originalProfile = $originalRecordProfile
                    originalConfigSha256 = $originalConfigArtifact.Sha256
                    originalConfigSize = $originalConfigArtifact.Length
                    originalInstallationSha256 = $originalRecordArtifact.Sha256
                    originalInstallationSize = $originalRecordArtifact.Length
                    candidateConfigSha256 = $candidateConfigArtifact.Sha256
                    candidateConfigSize = $candidateConfigArtifact.Length
                    candidateInstallationSha256 = $candidateRecordArtifact.Sha256
                    candidateInstallationSize = $candidateRecordArtifact.Length
                }
                Write-PatchProfileJournal `
                    -Paths $paths -Journal $journal `
                    -InstallationId ([string]$marker.installationId)

                Assert-PSOBBGlobalStoppedRuntime `
                    -Layout $layout `
                    -Operation 'installing the Stable client-patch profile pair' |
                    Out-Null
                Set-PatchProfileJournalPhase `
                    -Paths $paths -Journal $journal -Phase 'installing-config' `
                    -InstallationId ([string]$marker.installationId)
                Install-PatchProfileArtifact `
                    -Source $paths.CandidateConfig `
                    -TransactionRoot $paths.Root -Destination $configPath `
                    -DestinationRoot $layout.Root `
                    -Temporary $paths.ConfigInstallTemporary `
                    -ExpectedLength $candidateConfigArtifact.Length `
                    -ExpectedSha256 $candidateConfigArtifact.Sha256 `
                    -FaultPrefix 'install-config'
                Set-PatchProfileJournalPhase `
                    -Paths $paths -Journal $journal -Phase 'config-installed' `
                    -InstallationId ([string]$marker.installationId)
                if ($script:PatchProfileFaultArmed -and
                    $InternalTestFaultPoint.StartsWith(
                        'compensate-', [System.StringComparison]::Ordinal)) {
                    throw 'Injected internal pre-compensation patch-profile failure'
                }
                Set-PatchProfileJournalPhase `
                    -Paths $paths -Journal $journal `
                    -Phase 'installing-installation' `
                    -InstallationId ([string]$marker.installationId)
                Install-PatchProfileArtifact `
                    -Source $paths.CandidateInstallation `
                    -TransactionRoot $paths.Root `
                    -Destination $installRecordPath `
                    -DestinationRoot $layout.Root `
                    -Temporary $paths.InstallationInstallTemporary `
                    -ExpectedLength $candidateRecordArtifact.Length `
                    -ExpectedSha256 $candidateRecordArtifact.Sha256 `
                    -FaultPrefix 'install-installation'
                Set-PatchProfileJournalPhase `
                    -Paths $paths -Journal $journal -Phase 'pair-installed' `
                    -InstallationId ([string]$marker.installationId)
                $installedState = Assert-PSOBBClientPatchStateCoherent `
                    -ConfigPath $configPath `
                    -InstallRecordPath $installRecordPath `
                    -InstallationId ([string]$marker.installationId) `
                    -RuntimeRoot $layout.Root -PolicyPath $policyPath
                if ($installedState.Profile -cne $Profile -or
                    $installedState.ConfigSha256 -cne
                        $candidateConfigArtifact.Sha256 -or
                    $installedState.InstallationSha256 -cne
                        $candidateRecordArtifact.Sha256 -or
                    -not (Test-PSOBBProtectedAcl -Path $configPath) -or
                    -not (Test-PSOBBProtectedAcl -Path $installRecordPath)) {
                    throw 'Installed patch-profile pair failed exact protected readback'
                }
                Invoke-PatchProfileInternalFault `
                    -Point 'installed-pair-after-coherence'
                Assert-PSOBBGlobalStoppedRuntime `
                    -Layout $layout `
                    -Operation 'accepting the Stable client-patch profile pair' |
                    Out-Null
                Set-PatchProfileJournalPhase `
                    -Paths $paths -Journal $journal -Phase 'verified' `
                    -InstallationId ([string]$marker.installationId)
                Remove-PatchProfileTransaction -Paths $paths -Layout $layout
                $applied = $true
            }

            [pscustomobject]@{
                RuntimeRoot = $layout.Root
                Profile = $Profile
                AutoPatches = $observedAutoPatches
                BBRequiredPatches = $observedRequiredPatches
                Changed = $applied
                RestartRequired = $applied
                RecoveredInterruptedTransaction = $recoveredInterruptedTransaction
                Pending = (-not $alreadyApplied) -and (-not $applied)
            }
        } catch {
            $operationFailure = $_
            if (Test-Path -LiteralPath $paths.Root) {
                try {
                    Repair-PatchProfileTransactionProtection `
                        -Paths $paths -Layout $layout
                    [void](Resolve-PatchProfileInterruptedTransaction `
                            -Paths $paths -Layout $layout `
                            -ConfigPath $configPath `
                            -InstallRecordPath $installRecordPath `
                            -InstallationId ([string]$marker.installationId))
                } catch {
                    throw ('Patch-profile transaction failed and protected ' +
                        'compensation did not complete. Keep both environments ' +
                        'stopped, preserve the transaction tree, and rerun ' +
                        'Set-PSOBBClientPatchProfile.ps1 to resume recovery.')
                }
            }
            throw $operationFailure
        } finally {
            [Array]::Clear($updatedConfigBytes, 0, $updatedConfigBytes.Length)
            [Array]::Clear($updatedRecordBytes, 0, $updatedRecordBytes.Length)
        }
    } finally {
        if ($originalConfigSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$originalConfigSnapshot.Bytes, 0,
                ([byte[]]$originalConfigSnapshot.Bytes).Length)
        }
        if ($originalRecordBytesSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$originalRecordBytesSnapshot.Bytes, 0,
                ([byte[]]$originalRecordBytesSnapshot.Bytes).Length)
        }
    }
} finally {
    try {
        if ($ownsServerMutex) {
            $serverMutex.ReleaseMutex()
        }
    } finally {
        try {
            if ($serverMutex) { $serverMutex.Dispose() }
        } finally {
            if ($clientOperationMutex) {
                Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
            }
        }
    }
}
