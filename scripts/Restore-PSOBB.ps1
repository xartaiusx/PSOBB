[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$BackupPath,
    [string]$RuntimeRoot,
    [switch]$ValidateOnly,
    [Parameter(DontShow = $true)][string]$InternalTestFaultPoint,
    [Parameter(DontShow = $true)][string]$InternalTestFaultToken,
    [Parameter(DontShow = $true)][string]$InternalTestFaultNonce,
    [Parameter(DontShow = $true)][string]$InternalTestHardExitPoint
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedServerExecutable {
    Get-PSOBBStableServerSourceLockIdentity
}

function Get-RecoveryItemLabel(
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][int]$Ordinal
) {
    "$Category item $Ordinal"
}

function Get-RecoveryPathCategory([string]$RelativePath) {
    if ($RelativePath -match '^system/(licenses|players|teams)/') {
        return $Matches[1]
    }
    'Stable metadata'
}

$script:RecoveryFaultArmed = $false
$script:RecoveryHardExitArmed = $false
$script:RecoveryFaultEvidencePath = $null
$script:RecoveryFaultInstallationId = $null
function Assert-RecoveryInternalFaultGate(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Marker
) {
    $hasFaultPoint = -not [string]::IsNullOrWhiteSpace(
        $InternalTestFaultPoint)
    $hasHardExitPoint = -not [string]::IsNullOrWhiteSpace(
        $InternalTestHardExitPoint)
    $hasToken = -not [string]::IsNullOrWhiteSpace(
        $InternalTestFaultToken)
    $hasNonce = -not [string]::IsNullOrWhiteSpace(
        $InternalTestFaultNonce)
    if (-not $hasFaultPoint -and -not $hasHardExitPoint -and
        -not $hasToken -and -not $hasNonce) {
        return $true
    }
    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root)
    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $fixtureName = [System.IO.Path]::GetFileName($root.TrimEnd('\'))
    $fixtureMarker = Join-Path $root '.recovery-test.json'
    if (($hasFaultPoint -eq $hasHardExitPoint) -or
        -not $hasToken -or -not $hasNonce -or
        $InternalTestFaultNonce -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$Marker.installationId -cne $InternalTestFaultToken -or
        -not $root.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fixtureName -cnotmatch '^PSOBB-RecoveryTests-[a-f0-9]{32}$' -or
        -not (Test-Path -LiteralPath $fixtureMarker -PathType Leaf) -or
        -not (Test-PSOBBProtectedAcl -Path $fixtureMarker)) {
        throw 'Internal recovery fault injection is restricted to an explicit protected temporary fixture'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $fixtureMarker -Root $root -Kind File `
            -Label 'internal recovery test marker')
    $evidencePath = Join-Path $root '.recovery-fault-observed.json'
    $evidenceNext = $evidencePath + '.next'
    if (Test-Path -LiteralPath $evidencePath) {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $evidencePath -Root $root -Kind File `
                -Label 'internal recovery fault evidence')
        if (-not (Test-PSOBBProtectedAcl -Path $evidencePath)) {
            throw 'Internal recovery fault evidence has an invalid ACL'
        }
    }
    if (Test-Path -LiteralPath $evidenceNext) {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $evidenceNext -Root $root -Kind File `
                -Label 'internal recovery fault evidence staging')
        throw 'Internal recovery fault evidence staging is not clean'
    }
    $script:RecoveryFaultArmed = $true
    $script:RecoveryHardExitArmed = $hasHardExitPoint
    $script:RecoveryFaultEvidencePath = $evidencePath
    $script:RecoveryFaultInstallationId = [string]$Marker.installationId
    $true
}

function Write-RecoveryObservedPoint(
    [Parameter(Mandatory)][string]$Point,
    [Parameter(Mandatory)][ValidateSet('fault', 'hard-exit')][string]$Kind
) {
    if (-not $script:RecoveryFaultEvidencePath -or
        -not $script:RecoveryFaultInstallationId) {
        throw 'Internal recovery fault evidence is not armed'
    }
    $record = [ordered]@{
        schemaVersion = [long]1
        installationId = $script:RecoveryFaultInstallationId
        nonce = $InternalTestFaultNonce
        kind = $Kind
        point = $Point
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($record | ConvertTo-Json -Depth 3))
    $root = Split-Path $script:RecoveryFaultEvidencePath -Parent
    $nextPath = $script:RecoveryFaultEvidencePath + '.next'
    try {
        [void](Write-PSOBBDurableFileBytes `
                -Path $nextPath -Root $root -Bytes $bytes `
                -Label 'internal recovery fault evidence staging')
        Set-PSOBBProtectedAcl -Path $nextPath
        $staged = Read-PSOBBStrictJsonSnapshot `
            -Path $nextPath -Root $root `
            -MaximumBytes 4KB -MaximumDepth 3 `
            -Label 'internal recovery fault evidence staging'
        Assert-PSOBBStrictDataObjectProperties `
            -Value $staged.Value -Expected @(
                'schemaVersion', 'installationId', 'nonce', 'kind', 'point') `
            -Label 'internal recovery fault evidence staging' | Out-Null
        if ($staged.Value.schemaVersion -isnot [long] -or
            $staged.Value.schemaVersion -ne 1 -or
            [string]$staged.Value.installationId -cne
                $script:RecoveryFaultInstallationId -or
            [string]$staged.Value.nonce -cne $InternalTestFaultNonce -or
            [string]$staged.Value.kind -cne $Kind -or
            [string]$staged.Value.point -cne $Point -or
            -not (Test-PSOBBProtectedAcl -Path $nextPath)) {
            throw 'Internal recovery fault evidence failed exact readback'
        }
        [System.IO.File]::Move(
            $nextPath, $script:RecoveryFaultEvidencePath, $true)
        Set-PSOBBProtectedAcl -Path $script:RecoveryFaultEvidencePath
        $published = Read-PSOBBStrictJsonSnapshot `
            -Path $script:RecoveryFaultEvidencePath -Root $root `
            -MaximumBytes 4KB -MaximumDepth 3 `
            -Label 'internal recovery fault evidence'
        if ($published.Sha256 -cne $staged.Sha256 -or
            -not (Test-PSOBBProtectedAcl `
                -Path $script:RecoveryFaultEvidencePath)) {
            throw 'Internal recovery fault evidence publication failed exact readback'
        }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Invoke-RecoveryInternalFault([Parameter(Mandatory)][string]$Point) {
    if ($script:RecoveryHardExitArmed -and
        $InternalTestHardExitPoint -ceq $Point) {
        $script:RecoveryHardExitArmed = $false
        Write-RecoveryObservedPoint -Point $Point -Kind 'hard-exit'
        [Environment]::Exit(86)
    }
    if ($script:RecoveryFaultArmed -and
        $InternalTestFaultPoint -ceq $Point) {
        $script:RecoveryFaultArmed = $false
        Write-RecoveryObservedPoint -Point $Point -Kind 'fault'
        throw "Injected internal recovery fault at $Point"
    }
}

function Get-RestoreJournalPaths([Parameter(Mandatory)]$Layout) {
    [pscustomobject]@{
        Journal = Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Stable '.psobb-restore-transaction.json') `
            -Root $Layout.Root
        JournalNext = Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Stable '.psobb-restore-transaction.next') `
            -Root $Layout.Root
    }
}

function Assert-RestoreJournalValue(
    [Parameter(Mandatory)]$Value,
    [Parameter(Mandatory)][string]$InstallationId
) {
    $properties = @(
        'schemaVersion', 'installationId', 'transactionId', 'phase',
        'stageLeaf', 'rollbackLeaf', 'emergencyBackupLeaf',
        'emergencyManifestSha256', 'targetBackupLeaf',
        'targetManifestSha256')
    Assert-PSOBBStrictDataObjectProperties `
        -Value $Value -Expected $properties `
        -Label 'restore transaction journal' | Out-Null
    if ($Value.schemaVersion -isnot [long] -or $Value.schemaVersion -ne 1) {
        throw 'Restore transaction journal version is invalid'
    }
    foreach ($name in @($properties | Where-Object { $_ -ne 'schemaVersion' })) {
        if ($Value.$name -isnot [string]) {
            throw 'Restore transaction journal field types are invalid'
        }
    }
    if ([string]$Value.installationId -cne $InstallationId -or
        [string]$Value.transactionId -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$Value.phase -cnotin @(
            'prepared', 'swapping', 'compensating', 'accepted') -or
        [string]$Value.stageLeaf -cne
            ('.psobb-restore-stage-' + [string]$Value.transactionId) -or
        [string]$Value.rollbackLeaf -cne
            ('.psobb-restore-rollback-' + [string]$Value.transactionId) -or
        [string]$Value.emergencyBackupLeaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
        [string]$Value.targetBackupLeaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
        [string]$Value.emergencyManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Value.targetManifestSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Restore transaction journal identity or binding is invalid'
    }
    $Value
}

function Read-RestoreJournal(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId
) {
    try {
        if (-not (Test-PSOBBProtectedAcl -Path $Paths.Journal)) {
            throw 'incorrect ACL'
        }
        $snapshot = Read-PSOBBRedactedRecoveryStrictJsonSnapshot `
            -Path $Paths.Journal -Root $Layout.Stable -MaximumBytes 64KB `
            -MaximumDepth 5 -Label 'restore transaction journal'
        [pscustomobject]@{
            Value = Assert-RestoreJournalValue `
                -Value $snapshot.Value -InstallationId $InstallationId
            Sha256 = [string]$snapshot.Sha256
        }
    } catch {
        throw 'The retained restore transaction journal is invalid; keep the runtime stopped and preserve its recovery artifacts'
    }
}

function Write-RestoreJournal(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Journal,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$FaultPrefix
) {
    [void](Assert-RestoreJournalValue `
            -Value ([pscustomobject]$Journal) -InstallationId $InstallationId)
    if (Test-Path -LiteralPath $Paths.JournalNext) {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $Paths.JournalNext -Root $Layout.Stable -Kind File `
                -Label 'restore transaction journal staging')
        Remove-Item -LiteralPath $Paths.JournalNext -Force -ErrorAction Stop
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Journal | ConvertTo-Json -Depth 4))
    try {
        [void](Write-PSOBBDurableFileBytes `
                -Path $Paths.JournalNext -Root $Layout.Stable -Bytes $bytes `
                -Label 'restore transaction journal staging')
        try {
            Invoke-RecoveryInternalFault -Point "$FaultPrefix-before-acl"
        } finally {
            Set-PSOBBProtectedAcl -Path $Paths.JournalNext
        }
        Invoke-RecoveryInternalFault -Point "$FaultPrefix-after-acl"
        $staged = Read-PSOBBRedactedRecoveryStrictJsonSnapshot `
            -Path $Paths.JournalNext -Root $Layout.Stable -MaximumBytes 64KB `
            -MaximumDepth 5 -Label 'restore transaction journal staging'
        [void](Assert-RestoreJournalValue `
                -Value $staged.Value -InstallationId $InstallationId)
        Invoke-RecoveryInternalFault -Point "$FaultPrefix-after-readback"
        [System.IO.File]::Move($Paths.JournalNext, $Paths.Journal, $true)
        Invoke-RecoveryInternalFault -Point "$FaultPrefix-after-move"
        Set-PSOBBProtectedAcl -Path $Paths.Journal
        Invoke-RecoveryInternalFault -Point "$FaultPrefix-after-destination-acl"
        $published = Read-RestoreJournal `
            -Paths $Paths -Layout $Layout -InstallationId $InstallationId
        if ($published.Sha256 -cne $staged.Sha256) {
            throw 'Restore transaction journal changed during publication'
        }
        Invoke-RecoveryInternalFault -Point "$FaultPrefix-after-destination-readback"
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        if (Test-Path -LiteralPath $Paths.JournalNext) {
            Remove-Item -LiteralPath $Paths.JournalNext -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

function Set-RestoreJournalPhase(
    [Parameter(Mandatory)]$Paths,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Journal,
    [Parameter(Mandatory)][string]$Phase,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$FaultPrefix
) {
    $Journal.phase = $Phase
    Write-RestoreJournal `
        -Paths $Paths -Layout $Layout -Journal $Journal `
        -InstallationId $InstallationId -FaultPrefix $FaultPrefix
}

function Test-AllowedStateFilePath([string]$Path) {
    if ($Path -in @('system/config.json', 'stable/installation.json')) {
        return $true
    }
    if ($Path -notmatch '^system/(licenses|players|teams)/') {
        return $false
    }
    $segments = $Path.Split('/')
    if ($segments.Count -lt 3) {
        return $false
    }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or ($segment -in @('.', '..')) -or
            ($segment.IndexOfAny([char[]]@('\', ':')) -ge 0) -or
            ($segment.ToCharArray() | Where-Object { [char]::IsControl($_) })) {
            return $false
        }
    }
    $true
}

function Get-LiveStatePath(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$RelativePath
) {
    if ($RelativePath -eq 'stable/installation.json') {
        return Assert-PathWithinRoot -Path $Layout.InstallRecord -Root $Layout.Root
    }
    if (($RelativePath -eq 'system/config.json') -or
        ($RelativePath -match '^system/(licenses|players|teams)/')) {
        return Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Server ($RelativePath.Replace('/', '\'))) `
            -Root $Layout.Server
    }
    throw "Unsupported restore state path: $RelativePath"
}

function Add-ExpectedParentDirectories(
    [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$Set,
    [Parameter(Mandatory)][string]$FilePath
) {
    $parent = $FilePath.Substring(0, $FilePath.LastIndexOf('/'))
    while ($parent) {
        $null = $Set.Add($parent)
        $separator = $parent.LastIndexOf('/')
        if ($separator -lt 0) { break }
        $parent = $parent.Substring(0, $separator)
    }
}

function Get-RestoreSwapItems(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$StageRoot,
    [Parameter(Mandatory)][string]$RollbackRoot
) {
    $systemRoot = Join-Path $Layout.Server 'system'
    @(
        [pscustomobject]@{ Name = 'licenses'; IsDirectory = $true; Current = Join-Path $systemRoot 'licenses'; Staged = Join-Path $StageRoot 'system\licenses'; Rollback = Join-Path $RollbackRoot 'licenses' }
        [pscustomobject]@{ Name = 'players'; IsDirectory = $true; Current = Join-Path $systemRoot 'players'; Staged = Join-Path $StageRoot 'system\players'; Rollback = Join-Path $RollbackRoot 'players' }
        [pscustomobject]@{ Name = 'teams'; IsDirectory = $true; Current = Join-Path $systemRoot 'teams'; Staged = Join-Path $StageRoot 'system\teams'; Rollback = Join-Path $RollbackRoot 'teams' }
        [pscustomobject]@{ Name = 'config.json'; IsDirectory = $false; Current = Join-Path $systemRoot 'config.json'; Staged = Join-Path $StageRoot 'system\config.json'; Rollback = Join-Path $RollbackRoot 'config.json' }
        [pscustomobject]@{ Name = 'installation.json'; IsDirectory = $false; Current = $Layout.InstallRecord; Staged = Join-Path $StageRoot 'stable\installation.json'; Rollback = Join-Path $RollbackRoot 'installation.json' }
    )
}

function Get-RestoreJournalBackupBinding(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$Leaf,
    [Parameter(Mandatory)][string]$ExpectedManifestSha256,
    [Parameter(Mandatory)][string]$Label
) {
    try {
        $path = Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Backups $Leaf) -Root $Layout.Backups
        $parent = [System.IO.Path]::GetFullPath(
            (Split-Path -Parent $path)).TrimEnd('\')
        $backupsRoot = [System.IO.Path]::GetFullPath(
            $Layout.Backups).TrimEnd('\')
        if (-not $parent.Equals(
                $backupsRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'not a direct backup child'
        }
        [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $path -Root $Layout.Backups -Label $Label `
                -RequireProtectedAcl)
        $manifest = Read-PSOBBRecoveryManifestSnapshot `
            -Path (Join-Path $path 'manifest.json') -Root $path
        if ($manifest.Sha256 -cne $ExpectedManifestSha256) {
            throw 'manifest digest mismatch'
        }
        [pscustomobject]@{
            Path = $path
            Manifest = $manifest.Value
            ManifestSha256 = [string]$manifest.Sha256
        }
    } catch {
        throw "The retained $Label binding is invalid; keep the runtime stopped and preserve its recovery artifacts"
    }
}

function Assert-LiveStateMatchesRecoveryManifest(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Marker,
    [Parameter(Mandatory)]$Manifest,
    [Parameter(Mandatory)][string]$Label
) {
    try {
        $expected = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::Ordinal)
        $ordinal = 0
        foreach ($entry in @($Manifest.files)) {
            $ordinal++
            $relative = [string]$entry.path
            if (-not (Test-AllowedStateFilePath $relative) -or
                $expected.ContainsKey($relative)) {
                throw 'invalid manifest path set'
            }
            $expected.Add($relative, $entry)
            $itemLabel = Get-RecoveryItemLabel `
                -Category (Get-RecoveryPathCategory $relative) -Ordinal $ordinal
            $livePath = Get-LiveStatePath `
                -Layout $Layout -RelativePath $relative
            $snapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
                -Path $livePath -Root $Layout.Root -MaximumBytes 64MB `
                -AllowEmpty -Label $itemLabel
            if ($snapshot.Length -ne [long]$entry.size -or
                $snapshot.Sha256 -cne [string]$entry.sha256 -or
                -not (Test-PSOBBProtectedAcl -Path $livePath)) {
                throw 'sealed live item mismatch'
            }
        }
        $actual = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        [void]$actual.Add('system/config.json')
        [void]$actual.Add('stable/installation.json')
        foreach ($category in @('licenses', 'players', 'teams')) {
            $treeRoot = Join-Path $Layout.Server ('system\' + $category)
            $tree = Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $treeRoot -Root $Layout.Root `
                -Label "$Label $category tree" -RequireProtectedAcl
            foreach ($item in @($tree.Items | Where-Object { -not $_.IsDirectory })) {
                $relative = [System.IO.Path]::GetRelativePath(
                    $Layout.Server, [string]$item.Path).Replace('\', '/')
                [void]$actual.Add($relative)
            }
        }
        if ($actual.Count -ne $expected.Count -or
            @($actual | Where-Object { -not $expected.ContainsKey($_) }).Count -gt 0) {
            throw 'live file census mismatch'
        }
        $patchState = Assert-PSOBBClientPatchStateCoherent `
            -ConfigPath (Join-Path $Layout.Server 'system\config.json') `
            -InstallRecordPath $Layout.InstallRecord `
            -InstallationId ([string]$Marker.installationId) `
            -RuntimeRoot $Layout.Root
        if ($patchState.Profile -cne [string]$Manifest.clientPatchState.profile -or
            $patchState.PolicySha256 -cne [string]$Manifest.clientPatchState.policySha256 -or
            $patchState.ConfigSha256 -cne [string]$Manifest.clientPatchState.configSha256 -or
            $patchState.InstallationSha256 -cne [string]$Manifest.clientPatchState.installationSha256) {
            throw 'client-patch binding mismatch'
        }
        $patchState
    } catch {
        throw "The $Label does not reproduce its exact sealed live-state manifest"
    }
}

function Remove-RestoreCurrentItem(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Item,
    [Parameter(Mandatory)][int]$Ordinal,
    [Parameter(Mandatory)][string]$Operation
) {
    if (-not (Test-Path -LiteralPath $Item.Current)) {
        return
    }
    try {
        if ($Item.IsDirectory) {
            Remove-PSOBBRedactedRecoveryTree `
                -Path $Item.Current -Root $Layout.Root `
                -Label "$Operation category $Ordinal"
        } else {
            [void](Assert-PSOBBOrdinaryContainedPath `
                    -Path $Item.Current -Root $Layout.Root -Kind File `
                    -Label "$Operation category $Ordinal")
            Remove-Item -LiteralPath $Item.Current -Force -ErrorAction Stop
        }
    } catch {
        throw "$Operation category $Ordinal could not be removed safely"
    }
}

function Remove-RestoreJournalArtifacts(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Paths,
    [string]$StageRoot,
    [string]$RollbackRoot
) {
    foreach ($entry in @(
            [pscustomobject]@{ Path = $StageRoot; Label = 'restore staging tree'; FaultName = 'stage' },
            [pscustomobject]@{ Path = $RollbackRoot; Label = 'restore rollback tree'; FaultName = 'rollback' })) {
        if ($entry.Path -and (Test-Path -LiteralPath $entry.Path)) {
            Invoke-RecoveryInternalFault `
                -Point "cleanup-$($entry.FaultName)-before-removal"
            Remove-PSOBBRedactedRecoveryTree `
                -Path $entry.Path -Root $Layout.Stable `
                -Label $entry.Label -RequireProtectedAcl
            Invoke-RecoveryInternalFault `
                -Point "cleanup-$($entry.FaultName)-after-removal"
        }
    }
    foreach ($journalEntry in @(
            [pscustomobject]@{ Path = $Paths.JournalNext; FaultName = 'journal-next' },
            [pscustomobject]@{ Path = $Paths.Journal; FaultName = 'journal' })) {
        $journalFile = [string]$journalEntry.Path
        if (Test-Path -LiteralPath $journalFile) {
            try {
                [void](Assert-PSOBBOrdinaryContainedPath `
                        -Path $journalFile -Root $Layout.Stable -Kind File `
                        -Label 'restore transaction journal')
                if (-not (Test-PSOBBProtectedAcl -Path $journalFile)) {
                    throw 'incorrect journal ACL'
                }
                Invoke-RecoveryInternalFault `
                    -Point "cleanup-$($journalEntry.FaultName)-before-removal"
                Remove-Item -LiteralPath $journalFile -Force -ErrorAction Stop
                Invoke-RecoveryInternalFault `
                    -Point "cleanup-$($journalEntry.FaultName)-after-removal"
            } catch {
                throw 'The restore transaction journal could not be removed safely'
            }
        }
    }
}

function Resolve-RestoreInterruptedTransaction(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)]$Marker,
    [switch]$ReadOnly
) {
    $paths = Get-RestoreJournalPaths -Layout $Layout
    $journalExists = Test-Path -LiteralPath $paths.Journal -PathType Leaf
    $journalNextExists = Test-Path -LiteralPath $paths.JournalNext -PathType Leaf
    $orphans = @(Get-ChildItem -Force -LiteralPath $Layout.Stable |
        Where-Object {
            $_.Name -match '^\.psobb-restore-(stage|rollback)-[a-f0-9]{32}$'
        })

    if (-not $journalExists -and $journalNextExists -and -not $ReadOnly) {
        try {
            if (-not (Test-PSOBBProtectedAcl -Path $paths.JournalNext)) {
                throw 'incorrect staged journal ACL'
            }
            $nextSnapshot = Read-PSOBBRedactedRecoveryStrictJsonSnapshot `
                -Path $paths.JournalNext -Root $Layout.Stable -MaximumBytes 64KB `
                -MaximumDepth 5 -Label 'restore transaction journal staging'
            [void](Assert-RestoreJournalValue `
                    -Value $nextSnapshot.Value `
                    -InstallationId ([string]$Marker.installationId))
            [System.IO.File]::Move($paths.JournalNext, $paths.Journal)
            Set-PSOBBProtectedAcl -Path $paths.Journal
            $journalExists = $true
        } catch {
            throw 'The staged restore transaction journal is invalid; keep the runtime stopped and preserve its recovery artifacts'
        }
    }

    if ($ReadOnly -and -not $journalExists -and -not $journalNextExists) {
        foreach ($orphan in $orphans) {
            [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                    -Path $orphan.FullName -Root $Layout.Stable `
                    -Label 'orphaned restore transaction tree' `
                    -RequireProtectedAcl)
        }
        return ($orphans.Count -gt 0)
    }

    if (-not $journalExists -and
        -not ($ReadOnly -and $journalNextExists)) {
        foreach ($orphan in $orphans) {
            $tree = Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $orphan.FullName -Root $Layout.Stable `
                -Label 'orphaned restore transaction tree' -RequireProtectedAcl
            if ($orphan.Name -match '^\.psobb-restore-rollback-' -and
                @($tree.Items).Count -gt 1) {
                throw 'An unjournaled restore rollback tree contains state; keep the runtime stopped and preserve it'
            }
            Remove-PSOBBRedactedRecoveryTree `
                -Path $orphan.FullName -Root $Layout.Stable `
                -Label 'orphaned restore transaction tree' -RequireProtectedAcl
        }
        return $false
    }

    $journalSnapshot = if ($journalExists) {
        Read-RestoreJournal `
            -Paths $paths -Layout $Layout `
            -InstallationId ([string]$Marker.installationId)
    } else {
        try {
            if (-not (Test-PSOBBProtectedAcl -Path $paths.JournalNext)) {
                throw 'incorrect staged journal ACL'
            }
            $nextSnapshot = Read-PSOBBRedactedRecoveryStrictJsonSnapshot `
                -Path $paths.JournalNext -Root $Layout.Stable `
                -MaximumBytes 64KB -MaximumDepth 5 `
                -Label 'restore transaction journal staging'
            [pscustomobject]@{
                Value = Assert-RestoreJournalValue `
                    -Value $nextSnapshot.Value `
                    -InstallationId ([string]$Marker.installationId)
                Sha256 = [string]$nextSnapshot.Sha256
            }
        } catch {
            throw 'The staged restore transaction journal is invalid; keep the runtime stopped and preserve its recovery artifacts'
        }
    }
    $journal = $journalSnapshot.Value
    $stageRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Stable ([string]$journal.stageLeaf)) `
        -Root $Layout.Stable
    $rollbackRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Stable ([string]$journal.rollbackLeaf)) `
        -Root $Layout.Stable
    $expectedLeaves = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$expectedLeaves.Add([string]$journal.stageLeaf)
    [void]$expectedLeaves.Add([string]$journal.rollbackLeaf)
    if (@($orphans | Where-Object { -not $expectedLeaves.Contains($_.Name) }).Count -gt 0) {
        throw 'Unexpected restore transaction trees exist; keep the runtime stopped and preserve them'
    }
    $emergency = Get-RestoreJournalBackupBinding `
        -Layout $Layout -Leaf ([string]$journal.emergencyBackupLeaf) `
        -ExpectedManifestSha256 ([string]$journal.emergencyManifestSha256) `
        -Label 'emergency backup'
    $target = Get-RestoreJournalBackupBinding `
        -Layout $Layout -Leaf ([string]$journal.targetBackupLeaf) `
        -ExpectedManifestSha256 ([string]$journal.targetManifestSha256) `
        -Label 'target backup'

    if ([string]$journal.phase -ceq 'accepted') {
        [void](Assert-LiveStateMatchesRecoveryManifest `
                -Layout $Layout -Marker $Marker -Manifest $target.Manifest `
                -Label 'accepted interrupted restore')
        foreach ($treeBinding in @(
                [pscustomobject]@{ Path = $stageRoot; Label = 'retained restore staging tree' },
                [pscustomobject]@{ Path = $rollbackRoot; Label = 'retained restore rollback tree' })) {
            if (Test-Path -LiteralPath $treeBinding.Path) {
                [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                        -Path $treeBinding.Path -Root $Layout.Stable `
                        -Label $treeBinding.Label -RequireProtectedAcl)
            }
        }
        if ($ReadOnly) {
            return $true
        }
        Remove-RestoreJournalArtifacts `
            -Layout $Layout -Paths $paths -StageRoot $stageRoot `
            -RollbackRoot $rollbackRoot
        return $true
    }


    foreach ($treeBinding in @(
            [pscustomobject]@{ Path = $stageRoot; Label = 'retained restore staging tree' },
            [pscustomobject]@{ Path = $rollbackRoot; Label = 'retained restore rollback tree' })) {
        [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
                -Path $treeBinding.Path -Root $Layout.Stable `
                -Label $treeBinding.Label -RequireProtectedAcl)
    }
    if ($ReadOnly) {
        return $true
    }

    $items = @(Get-RestoreSwapItems `
            -Layout $Layout -StageRoot $stageRoot -RollbackRoot $rollbackRoot)
    for ($index = $items.Count - 1; $index -ge 0; $index--) {
        $item = $items[$index]
        $ordinal = $index + 1
        if (Test-Path -LiteralPath $item.Rollback) {
            Invoke-RecoveryInternalFault `
                -Point "recover-$ordinal-before-candidate-removal"
            Remove-RestoreCurrentItem `
                -Layout $Layout -Item $item -Ordinal $ordinal `
                -Operation 'interrupted restore recovery'
            Invoke-RecoveryInternalFault `
                -Point "recover-$ordinal-after-candidate-removal"
            Move-Item -LiteralPath $item.Rollback -Destination $item.Current
            Invoke-RecoveryInternalFault `
                -Point "recover-$ordinal-after-original-move"
        }
    }
    Invoke-RecoveryInternalFault -Point 'recover-before-acl'
    & (Join-Path $PSScriptRoot 'Set-PSOBBRuntimeAcl.ps1') `
        -RuntimeRoot $Layout.Root | Out-Null
    Invoke-RecoveryInternalFault -Point 'recover-after-acl'
    [void](Assert-LiveStateMatchesRecoveryManifest `
            -Layout $Layout -Marker $Marker -Manifest $emergency.Manifest `
            -Label 'recovered interrupted restore')
    Invoke-RecoveryInternalFault -Point 'recover-after-exact-readback'
    Remove-RestoreJournalArtifacts `
        -Layout $Layout -Paths $paths -StageRoot $stageRoot `
        -RollbackRoot $rollbackRoot
    $true
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$clientOperationMutex = $null
$mutex = $null
$ownsMutex = $false
try {
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout -TimeoutSeconds 0
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
try {
    $ownsMutex = $mutex.WaitOne(0)
} catch [System.Threading.AbandonedMutexException] {
    $ownsMutex = $true
}
if (-not $ownsMutex) {
    throw 'Another PSOBB start, stop, backup, restore, or patch-profile operation is already in progress'
}
Assert-RecoveryInternalFaultGate -Layout $layout -Marker $marker | Out-Null
Assert-PSOBBGlobalStoppedRuntime `
    -Layout $layout -Operation 'validating or restoring Stable state' | Out-Null
$restoreRecoveryRequired = Resolve-RestoreInterruptedTransaction `
    -Layout $layout -Marker $marker -ReadOnly
$resolvedBackup = (Resolve-Path -LiteralPath $BackupPath).Path
Assert-PathWithinRoot -Path $resolvedBackup -Root $layout.Backups | Out-Null
$backupParent = [System.IO.Path]::GetFullPath(
    (Split-Path -Parent $resolvedBackup)).TrimEnd('\')
$backupsRoot = [System.IO.Path]::GetFullPath($layout.Backups).TrimEnd('\')
if (-not $backupParent.Equals(
        $backupsRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Restore input must be one direct protected backup directory'
}
[void](Get-PSOBBRedactedRecoveryTreeSnapshot `
        -Path $resolvedBackup -Root $layout.Backups `
        -Label 'recovery backup input' -RequireProtectedAcl)
$manifestPath = Join-Path $resolvedBackup 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Backup manifest is missing'
}

$manifestSnapshot = Read-PSOBBRecoveryManifestSnapshot `
    -Path $manifestPath -Root $resolvedBackup
$manifest = $manifestSnapshot.Value
if ($manifest.schemaVersion -eq 2) {
    throw 'Unsupported incomplete backup manifest schema 2: stable/installation.json is absent; schema 3 is required'
}
if ($manifest.schemaVersion -ne 3) {
    throw "Unsupported backup manifest schema: $($manifest.schemaVersion); schema 3 is required"
}
$parsedGuid = [Guid]::Empty
if (-not [Guid]::TryParse([string]$manifest.backupId, [ref]$parsedGuid)) {
    throw 'Backup manifest backupId is invalid'
}
if ($manifest.backupKind -notin @('state', 'pre-restore')) {
    throw 'Backup manifest backupKind is invalid'
}
$parsedTimestamp = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse([string]$manifest.createdAtUtc, [ref]$parsedTimestamp)) {
    throw 'Backup manifest createdAtUtc is invalid'
}

$approvedServer = Get-ApprovedServerExecutable
if (($manifest.serverExecutable.path -ne 'newserv-windows.exe') -or
    ($manifest.serverExecutable.sourceLockComponent -ne $approvedServer.ComponentId) -or
    ([long]$manifest.serverExecutable.size -ne $approvedServer.Size) -or
    ([string]$manifest.serverExecutable.sha256 -cne $approvedServer.Sha256)) {
    throw 'Backup manifest is not bound to the approved stable server executable'
}
$installedServer = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
if (-not (Test-Path -LiteralPath $installedServer -PathType Leaf)) {
    throw 'The installed stable server executable is missing'
}
if (((Get-Item -LiteralPath $installedServer).Length -ne $approvedServer.Size) -or
    ((Get-LowerSha256 $installedServer) -ne $approvedServer.Sha256)) {
    throw 'The installed stable server executable does not match the backup-approved source-lock member'
}

$expectedStateRoots = [ordered]@{
    'system/config.json' = 'file'
    'system/licenses' = 'directory'
    'system/players' = 'directory'
    'system/teams' = 'directory'
    'stable/installation.json' = 'file'
}
$seenStateRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($stateRoot in @($manifest.stateRoots)) {
    if (-not $expectedStateRoots.Contains([string]$stateRoot.path) -or
        $stateRoot.kind -cne $expectedStateRoots[[string]$stateRoot.path] -or
        -not $seenStateRoots.Add([string]$stateRoot.path)) {
        throw 'Backup manifest contains an invalid or duplicate state-root entry'
    }
}
if ($seenStateRoots.Count -ne $expectedStateRoots.Count) {
    throw 'Backup manifest does not declare the complete required state-root set'
}

$seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$expectedDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($directory in @('system', 'system/licenses', 'system/players', 'system/teams', 'stable')) {
    $null = $expectedDirectories.Add($directory)
}
$manifestFiles = @($manifest.files)
$entryOrdinal = 0
foreach ($entry in $manifestFiles) {
    $entryOrdinal++
    $entryPath = [string]$entry.path
    $entryLabel = Get-RecoveryItemLabel `
        -Category (Get-RecoveryPathCategory $entryPath) `
        -Ordinal $entryOrdinal
    if (-not (Test-AllowedStateFilePath $entryPath)) {
        throw "$entryLabel has a disallowed manifest path"
    }
    if (-not $seenPaths.Add($entryPath)) {
        throw "$entryLabel duplicates an earlier manifest path"
    }
    if (([long]$entry.size -lt 0) -or ([string]$entry.sha256 -notmatch '^[0-9a-f]{64}$')) {
        throw "$entryLabel contains invalid file metadata"
    }
    Add-ExpectedParentDirectories -Set $expectedDirectories -FilePath $entryPath
    $file = Assert-PathWithinRoot -Path (Join-Path $resolvedBackup ($entryPath.Replace('/', '\'))) -Root $resolvedBackup
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "$entryLabel is missing from the recovery backup"
    }
    $fileSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
        -Path $file -Root $resolvedBackup -MaximumBytes 64MB `
        -AllowEmpty -Label $entryLabel
    if ($fileSnapshot.Length -ne [long]$entry.size -or
        $fileSnapshot.Sha256 -cne [string]$entry.sha256) {
        throw "$entryLabel failed its sealed size or checksum"
    }
}
if (-not $seenPaths.Contains('system/config.json')) {
    throw 'Backup manifest does not contain system/config.json'
}
if (-not $seenPaths.Contains('stable/installation.json')) {
    throw 'Backup manifest does not contain stable/installation.json'
}

$actualPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($file in @(Get-ChildItem -Force -LiteralPath $resolvedBackup -Recurse -File)) {
    $relative = [System.IO.Path]::GetRelativePath($resolvedBackup, $file.FullName).Replace('\', '/')
    if ($relative -ne 'manifest.json') {
        $null = $actualPaths.Add($relative)
    }
}
if (($actualPaths.Count -ne $seenPaths.Count) -or @($actualPaths | Where-Object { -not $seenPaths.Contains($_) }).Count -gt 0) {
    throw 'Backup contains files that are absent from its exact manifest, or the manifest lists absent files'
}
$actualDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($directory in @(Get-ChildItem -Force -LiteralPath $resolvedBackup -Recurse -Directory)) {
    $relative = [System.IO.Path]::GetRelativePath($resolvedBackup, $directory.FullName).Replace('\', '/')
    $null = $actualDirectories.Add($relative)
}
if (($actualDirectories.Count -ne $expectedDirectories.Count) -or
    @($actualDirectories | Where-Object { -not $expectedDirectories.Contains($_) }).Count -gt 0) {
    throw 'Backup directory tree differs from the exact state-root and manifest-derived directory set'
}

$patchState = Assert-PSOBBClientPatchStateCoherent `
    -ConfigPath (Join-Path $resolvedBackup 'system\config.json') `
    -InstallRecordPath (Join-Path $resolvedBackup 'stable\installation.json') `
    -InstallationId ([string]$marker.installationId) `
    -RuntimeRoot $layout.Root
if (([string]$manifest.clientPatchState.profile -cne $patchState.Profile) -or
    ([string]$manifest.clientPatchState.policySha256 -cne $patchState.PolicySha256) -or
    ([string]$manifest.clientPatchState.configPath -cne 'system/config.json') -or
    ([string]$manifest.clientPatchState.configSha256 -cne $patchState.ConfigSha256) -or
    ([string]$manifest.clientPatchState.installationPath -cne 'stable/installation.json') -or
    ([string]$manifest.clientPatchState.installationSha256 -cne $patchState.InstallationSha256) -or
    ([string]$manifest.clientPatchState.installationId -cne $patchState.InstallationId)) {
    throw 'Backup clientPatchState does not match its verified config and installation metadata'
}

$validation = [pscustomobject]@{
    BackupPath = $resolvedBackup
    ManifestSha256 = [string]$manifestSnapshot.Sha256
    ApprovedServerExecutableSha256 = $approvedServer.Sha256
    ClientPatchProfile = $patchState.Profile
    ClientPatchPolicySha256 = $patchState.PolicySha256
    ClientPatchConfigSha256 = $patchState.ConfigSha256
    InstallationRecordSha256 = $patchState.InstallationSha256
    FileCount = $manifestFiles.Count
    RecoveryRequired = [bool]$restoreRecoveryRequired
}
if ($ValidateOnly) {
    return $validation
}
if (-not $PSCmdlet.ShouldProcess($layout.Root, "Restore exact PSOBB state from $resolvedBackup")) {
    return $validation
}
$recoveredInterruptedTransaction = Resolve-RestoreInterruptedTransaction `
    -Layout $layout -Marker $marker

$systemRoot = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'system') -Root $layout.Server
$stableRoot = Assert-PathWithinRoot -Path $layout.Stable -Root $layout.Root
$transactionId = [Guid]::NewGuid().ToString('N')
$stageRoot = Assert-PathWithinRoot -Path (Join-Path $stableRoot ('.psobb-restore-stage-' + $transactionId)) -Root $stableRoot
$rollbackRoot = Assert-PathWithinRoot -Path (Join-Path $stableRoot ('.psobb-restore-rollback-' + $transactionId)) -Root $stableRoot
$journalPaths = Get-RestoreJournalPaths -Layout $layout
$journal = $null
$journalPublished = $false
$transactionResolved = $false
$restoreSucceeded = $false
$emergency = $null
try {
    New-Item -ItemType Directory -Path $stageRoot | Out-Null
    Invoke-RecoveryInternalFault -Point 'stage-root-after-create-before-acl'
    Set-PSOBBProtectedAcl -Path $stageRoot
    foreach ($relative in @('system/licenses', 'system/players', 'system/teams', 'stable')) {
        New-Item -ItemType Directory `
            -Path (Join-Path $stageRoot ($relative.Replace('/', '\'))) `
            -Force | Out-Null
    }
    # The source tree is revalidated after validation and immediately before
    # copying any recovery bytes into the same-volume staging tree.
    [void](Get-PSOBBRedactedRecoveryTreeSnapshot `
            -Path $resolvedBackup -Root $layout.Backups `
            -Label 'recovery backup input before copy' -RequireProtectedAcl)
    $copyOrdinal = 0
    foreach ($entry in $manifestFiles) {
        $copyOrdinal++
        $copyLabel = Get-RecoveryItemLabel `
            -Category (Get-RecoveryPathCategory ([string]$entry.path)) `
            -Ordinal $copyOrdinal
        $source = Assert-PathWithinRoot -Path (Join-Path $resolvedBackup (([string]$entry.path).Replace('/', '\'))) -Root $resolvedBackup
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $stageRoot (([string]$entry.path).Replace('/', '\'))) `
            -Root $stageRoot
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Invoke-RecoveryInternalFault -Point "stage-copy-$copyOrdinal-before"
        [void](Copy-PSOBBRedactedRecoveryFile `
                -Source $source -SourceRoot $resolvedBackup `
                -Destination $destination -DestinationRoot $stageRoot `
                -ExpectedLength ([long]$entry.size) `
                -ExpectedSha256 ([string]$entry.sha256) `
                -Label $copyLabel)
        Invoke-RecoveryInternalFault -Point "stage-copy-$copyOrdinal-after-readback"
    }
    Invoke-RecoveryInternalFault -Point 'stage-tree-before-acl'
    Set-PSOBBRedactedRecoveryTreeAcl `
        -Path $stageRoot -Root $stableRoot -Label 'restore staging tree'
    Invoke-RecoveryInternalFault -Point 'stage-tree-after-acl'
    # Capture the exact pre-mutation state using the same schema and verifier.
    $emergency = & (Join-Path $PSScriptRoot 'Backup-PSOBB.ps1') `
        -RuntimeRoot $layout.Root -BackupKind pre-restore -Retention 7 `
        -PreserveBackupPath $resolvedBackup `
        -PreserveBackupManifestSha256 ([string]$manifestSnapshot.Sha256)
    if (-not $emergency -or -not (Test-Path -LiteralPath (Join-Path $emergency.BackupPath 'manifest.json') -PathType Leaf)) {
        throw 'The manifested pre-restore emergency backup was not created'
    }
    New-Item -ItemType Directory -Path $rollbackRoot | Out-Null
    Set-PSOBBProtectedAcl -Path $rollbackRoot
    $items = @(Get-RestoreSwapItems `
            -Layout $layout -StageRoot $stageRoot -RollbackRoot $rollbackRoot)
    $journal = [ordered]@{
        schemaVersion = [long]1
        installationId = [string]$marker.installationId
        transactionId = $transactionId
        phase = 'prepared'
        stageLeaf = [System.IO.Path]::GetFileName($stageRoot)
        rollbackLeaf = [System.IO.Path]::GetFileName($rollbackRoot)
        emergencyBackupLeaf = [System.IO.Path]::GetFileName($emergency.BackupPath)
        emergencyManifestSha256 = [string]$emergency.ManifestSha256
        targetBackupLeaf = [System.IO.Path]::GetFileName($resolvedBackup)
        targetManifestSha256 = [string]$manifestSnapshot.Sha256
    }
    Write-RestoreJournal `
        -Paths $journalPaths -Layout $layout -Journal $journal `
        -InstallationId ([string]$marker.installationId) `
        -FaultPrefix 'journal-prepared'
    $journalPublished = $true
    Set-RestoreJournalPhase `
        -Paths $journalPaths -Layout $layout -Journal $journal `
        -Phase 'swapping' -InstallationId ([string]$marker.installationId) `
        -FaultPrefix 'journal-swapping'
    Assert-PSOBBGlobalStoppedRuntime `
        -Layout $layout -Operation 'starting the Stable restore transaction' | Out-Null
    $processed = [System.Collections.Generic.List[object]]::new()
    try {
        $swapOrdinal = 0
        foreach ($item in $items) {
            $swapOrdinal++
            Invoke-RecoveryInternalFault `
                -Point "swap-$swapOrdinal-before-original-move"
            Move-Item -LiteralPath $item.Current -Destination $item.Rollback
            try {
                Invoke-RecoveryInternalFault `
                    -Point "swap-$swapOrdinal-before-rollback-acl"
                if ($item.IsDirectory) {
                    Set-PSOBBRedactedRecoveryTreeAcl `
                        -Path $item.Rollback -Root $rollbackRoot `
                        -Label "restore rollback category $swapOrdinal"
                } else {
                    Set-PSOBBProtectedAcl -Path $item.Rollback
                }
                Invoke-RecoveryInternalFault `
                    -Point "swap-$swapOrdinal-after-rollback-acl"
                Invoke-RecoveryInternalFault `
                    -Point "swap-$swapOrdinal-after-original-move"
                Invoke-RecoveryInternalFault `
                    -Point "swap-$swapOrdinal-before-candidate-move"
                if ($script:RecoveryFaultArmed -and
                    $InternalTestFaultPoint -in @(
                        "swap-$swapOrdinal-before-immediate-compensation",
                        "swap-$swapOrdinal-after-immediate-compensation")) {
                    throw 'Injected internal candidate-move failure for immediate compensation coverage'
                }
                Move-Item -LiteralPath $item.Staged -Destination $item.Current
            } catch {
                $swapFailure = $_
                try {
                    Invoke-RecoveryInternalFault `
                        -Point "swap-$swapOrdinal-before-immediate-compensation"
                    Move-Item -LiteralPath $item.Rollback -Destination $item.Current
                    Invoke-RecoveryInternalFault `
                        -Point "swap-$swapOrdinal-after-immediate-compensation"
                } catch {
                    throw "Restore category $swapOrdinal failed and its immediate rollback also failed. Use the retained emergency backup and rerun Restore-PSOBB.ps1."
                }
                throw $swapFailure
            }
            $processed.Add($item)
            Invoke-RecoveryInternalFault `
                -Point "swap-$swapOrdinal-after-candidate-move"
            $forceCompensation = $false
            if ($script:RecoveryFaultArmed -and
                $InternalTestFaultPoint -match
                    '^compensate-([1-9][0-9]*)-') {
                $forceCompensation =
                    [int]$Matches[1] -eq $swapOrdinal
            } elseif ($script:RecoveryFaultArmed -and
                $swapOrdinal -eq 1 -and
                $InternalTestFaultPoint.StartsWith(
                    'journal-compensating-',
                    [System.StringComparison]::Ordinal)) {
                $forceCompensation = $true
            }
            if ($forceCompensation) {
                throw 'Injected internal pre-compensation restore failure'
            }
        }

        if ($script:RecoveryFaultArmed -and
            $InternalTestFaultPoint -in @(
                'compensate-before-acl',
                'compensate-after-acl',
                'compensate-after-exact-readback')) {
            throw 'Injected internal pre-compensation restore failure'
        }

        # Verify the installed state before deleting rollback material.
        $installedOrdinal = 0
        foreach ($entry in $manifestFiles) {
            $installedOrdinal++
            $installedLabel = Get-RecoveryItemLabel `
                -Category (Get-RecoveryPathCategory ([string]$entry.path)) `
                -Ordinal $installedOrdinal
            $installed = Get-LiveStatePath -Layout $layout -RelativePath ([string]$entry.path)
            Invoke-RecoveryInternalFault `
                -Point "verify-installed-$installedOrdinal-before"
            if (-not (Test-Path -LiteralPath $installed -PathType Leaf)) {
                throw "$installedLabel is absent after the restore swap"
            }
            $installedSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
                -Path $installed -Root $layout.Root -MaximumBytes 64MB `
                -AllowEmpty -Label $installedLabel
            if ($installedSnapshot.Length -ne [long]$entry.size -or
                $installedSnapshot.Sha256 -cne [string]$entry.sha256) {
                throw "$installedLabel failed installed restore verification"
            }
            Invoke-RecoveryInternalFault `
                -Point "verify-installed-$installedOrdinal-after"
        }
        $installedPatchState = Assert-PSOBBClientPatchStateCoherent `
            -ConfigPath (Join-Path $systemRoot 'config.json') `
            -InstallRecordPath $layout.InstallRecord `
            -InstallationId ([string]$marker.installationId) `
            -RuntimeRoot $layout.Root
        if (($installedPatchState.Profile -cne $patchState.Profile) -or
            ($installedPatchState.PolicySha256 -cne $patchState.PolicySha256)) {
            throw 'Installed config and installation metadata do not match the restored client-patch state'
        }
        Invoke-RecoveryInternalFault -Point 'installed-tree-before-acl'
        & (Join-Path $PSScriptRoot 'Set-PSOBBRuntimeAcl.ps1') `
            -RuntimeRoot $layout.Root | Out-Null
        Invoke-RecoveryInternalFault -Point 'installed-tree-after-acl'
        Assert-PSOBBGlobalStoppedRuntime `
            -Layout $layout `
            -Operation 'accepting the installed Stable restore transaction' |
            Out-Null
        Invoke-RecoveryInternalFault -Point 'installed-tree-after-final-census'
        Set-RestoreJournalPhase `
            -Paths $journalPaths -Layout $layout -Journal $journal `
            -Phase 'accepted' `
            -InstallationId ([string]$marker.installationId) `
            -FaultPrefix 'journal-accepted'
        $restoreSucceeded = $true
    } catch {
        $restoreFailure = $_
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        try {
            if ($journalPublished -or
                (Test-Path -LiteralPath $journalPaths.Journal -PathType Leaf)) {
                Set-RestoreJournalPhase `
                    -Paths $journalPaths -Layout $layout -Journal $journal `
                    -Phase 'compensating' `
                    -InstallationId ([string]$marker.installationId) `
                    -FaultPrefix 'journal-compensating'
            }
        } catch {
            $rollbackErrors.Add('transaction journal')
        }
        for ($index = $processed.Count - 1; $index -ge 0; $index--) {
            $item = $processed[$index]
            $compensationOrdinal = $index + 1
            try {
                Invoke-RecoveryInternalFault `
                    -Point "compensate-$compensationOrdinal-before-candidate-removal"
                if (Test-Path -LiteralPath $item.Current) {
                    $currentItem = Get-Item -Force -LiteralPath $item.Current
                    if ($currentItem.PSIsContainer) {
                        Remove-PSOBBRedactedRecoveryTree `
                            -Path $item.Current -Root $layout.Root `
                            -Label "restore candidate category $compensationOrdinal"
                    } else {
                        [void](Assert-PSOBBOrdinaryContainedPath `
                                -Path $item.Current -Root $layout.Root -Kind File `
                                -Label "restore candidate category $compensationOrdinal")
                        Remove-Item -LiteralPath $item.Current -Force
                    }
                }
                Invoke-RecoveryInternalFault `
                    -Point "compensate-$compensationOrdinal-after-candidate-removal"
                Invoke-RecoveryInternalFault `
                    -Point "compensate-$compensationOrdinal-before-original-move"
                Move-Item -LiteralPath $item.Rollback -Destination $item.Current
                Invoke-RecoveryInternalFault `
                    -Point "compensate-$compensationOrdinal-after-original-move"
            } catch {
                $rollbackErrors.Add("category $compensationOrdinal")
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw ('Restore failed and rollback was incomplete for ' +
                "$($rollbackErrors -join ', '). Use the retained emergency backup " +
                'with Restore-PSOBB.ps1 after confirming the runtime is stopped.')
        }
        Invoke-RecoveryInternalFault -Point 'compensate-before-acl'
        & (Join-Path $PSScriptRoot 'Set-PSOBBRuntimeAcl.ps1') `
            -RuntimeRoot $layout.Root | Out-Null
        Invoke-RecoveryInternalFault -Point 'compensate-after-acl'

        $emergencyManifestSnapshot = Read-PSOBBRecoveryManifestSnapshot `
            -Path (Join-Path $emergency.BackupPath 'manifest.json') `
            -Root $emergency.BackupPath
        $rollbackOrdinal = 0
        foreach ($entry in @($emergencyManifestSnapshot.Value.files)) {
            $rollbackOrdinal++
            $rollbackLabel = Get-RecoveryItemLabel `
                -Category (Get-RecoveryPathCategory ([string]$entry.path)) `
                -Ordinal $rollbackOrdinal
            $restoredOriginal = Get-LiveStatePath `
                -Layout $layout -RelativePath ([string]$entry.path)
            $originalSnapshot = Read-PSOBBRedactedRecoveryFileSnapshot `
                -Path $restoredOriginal -Root $layout.Root -MaximumBytes 64MB `
                -AllowEmpty -Label $rollbackLabel
            if ($originalSnapshot.Length -ne [long]$entry.size -or
                $originalSnapshot.Sha256 -cne [string]$entry.sha256) {
                throw ('Restore compensation did not reproduce the sealed original ' +
                    'state. Use the retained emergency backup with Restore-PSOBB.ps1.')
            }
        }
        Invoke-RecoveryInternalFault -Point 'compensate-after-exact-readback'
        if ($rollbackErrors.Count -eq 0) {
            Remove-RestoreJournalArtifacts `
                -Layout $layout -Paths $journalPaths -StageRoot $stageRoot `
                -RollbackRoot $rollbackRoot
            $transactionResolved = $true
        }
        throw $restoreFailure
    }
} finally {
    if ($restoreSucceeded) {
        Remove-RestoreJournalArtifacts `
            -Layout $layout -Paths $journalPaths -StageRoot $stageRoot `
            -RollbackRoot $rollbackRoot
        $transactionResolved = $true
    } elseif (-not $transactionResolved -and
        -not (Test-Path -LiteralPath $journalPaths.Journal -PathType Leaf)) {
        foreach ($temporaryTree in @($stageRoot, $rollbackRoot)) {
            if (Test-Path -LiteralPath $temporaryTree) {
                Remove-PSOBBRedactedRecoveryTree `
                    -Path $temporaryTree -Root $stableRoot `
                    -Label 'unpublished restore transaction tree'
            }
        }
    }
}

[pscustomobject]@{
    RestoredFrom = $resolvedBackup
    ManifestSha256 = $validation.ManifestSha256
    ClientPatchProfile = $validation.ClientPatchProfile
    ClientPatchPolicySha256 = $validation.ClientPatchPolicySha256
    EmergencyBackup = $emergency.BackupPath
    EmergencyManifestSha256 = $emergency.ManifestSha256
    Transaction = 'same-volume staged swap with verified config-and-installation rollback'
    RecoveredInterruptedTransaction = [bool]$recoveredInterruptedTransaction
}
} finally {
    try {
        if ($ownsMutex) {
            $mutex.ReleaseMutex()
        }
    } finally {
        try {
            if ($mutex) {
                $mutex.Dispose()
            }
        } finally {
            if ($clientOperationMutex) {
                Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
            }
        }
    }
}
