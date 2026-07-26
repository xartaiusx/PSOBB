[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Activate', 'Rollback')]
    [string]$Action,

    [string]$RuntimeRoot,

    [Parameter(DontShow = $true)]
    [ValidateSet('', 'after-loader', 'after-module', 'after-configuration',
        'after-binding', 'after-installation', 'after-loader-commit',
        'after-binding-commit', 'after-installation-commit')]
    [string]$InternalTestFaultPoint = '',

    [Parameter(DontShow = $true)]
    [string]$InternalTestFaultToken,

    [Parameter(DontShow = $true)]
    [ValidateSet('', 'after-transaction-publish', 'after-loader',
        'after-module', 'after-configuration', 'after-binding',
        'after-installation', 'after-rollback-marker-staging',
        'after-rollback-marker')]
    [string]$InternalTestHardExitPoint = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Action = if ($Action.Equals(
        'Activate', [System.StringComparison]::OrdinalIgnoreCase)) {
    'Activate'
} elseif ($Action.Equals(
        'Rollback', [System.StringComparison]::OrdinalIgnoreCase)) {
    'Rollback'
} else {
    throw "Unsupported Gameplay action: $Action"
}

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

$script:GameplayFaultArmed = $false
$script:GameplayHardExitArmed = $false
$script:GameplayOperationLimitSeconds = 285
$script:GameplayOperationStopwatch =
    [System.Diagnostics.Stopwatch]::StartNew()

function Get-GameplayOperationBudgetSeconds {
    param(
        [Parameter(Mandatory)][string]$Label,
        [ValidateRange(0, 120)][int]$ReservedSeconds = 0
    )

    $remaining = [math]::Floor(
        $script:GameplayOperationLimitSeconds -
        $script:GameplayOperationStopwatch.Elapsed.TotalSeconds -
        $ReservedSeconds)
    if ($remaining -lt 1) {
        throw "The Gameplay $Label exhausted its bounded operation budget"
    }
    [int]$remaining
}

function Assert-GameplayFaultGate {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Marker
    )

    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root)
    $canonicalRoot = [System.IO.Path]::GetFullPath(
        $script:PSOBBCanonicalRuntimeRoot).TrimEnd('\')
    if ($root.TrimEnd('\').Equals(
            $canonicalRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not [string]::IsNullOrWhiteSpace($InternalTestFaultPoint) -or
            -not [string]::IsNullOrWhiteSpace($InternalTestFaultToken) -or
            -not [string]::IsNullOrWhiteSpace($InternalTestHardExitPoint)) {
            throw 'Internal Gameplay test controls are forbidden for the canonical runtime'
        }
        return $false
    }

    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $fixtureMarker = Join-Path $root '.recovery-test.json'
    if ([string]::IsNullOrWhiteSpace($InternalTestFaultToken) -or
        [string]$Marker.installationId -cne $InternalTestFaultToken -or
        -not $root.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($root.TrimEnd('\')) -cnotmatch
            '^PSOBB-GameplayTests-[a-f0-9]{32}$' -or
        -not (Test-Path -LiteralPath $fixtureMarker -PathType Leaf) -or
        -not (Test-PSOBBProtectedAcl -Path $fixtureMarker)) {
        throw 'Internal Gameplay fault injection requires an explicit protected temporary fixture'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $fixtureMarker -Root $root -Kind File `
            -Label 'Gameplay temporary-fixture marker')
    $script:GameplayFaultArmed =
        -not [string]::IsNullOrWhiteSpace($InternalTestFaultPoint)
    $script:GameplayHardExitArmed =
        -not [string]::IsNullOrWhiteSpace($InternalTestHardExitPoint)
    $true
}

function Invoke-GameplayFault {
    param([Parameter(Mandatory)][string]$Point)

    if ($script:GameplayFaultArmed -and $InternalTestFaultPoint -ceq $Point) {
        $script:GameplayFaultArmed = $false
        throw "Injected CombatCanary Gameplay fault at $Point"
    }
}

function Invoke-GameplayHardExit {
    param([Parameter(Mandatory)][string]$Point)

    if ($script:GameplayHardExitArmed -and
        $InternalTestHardExitPoint -ceq $Point) {
        [Environment]::Exit(86)
    }
}

function Get-GameplayDigest {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label,
        [long]$MaximumBytes = 16MB
    )

    Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Path -Root $Root -MaximumBytes $MaximumBytes `
        -AllowEmpty -Label $Label
}

function Get-GameplayBytesDigest {
    param([AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes)

    [pscustomobject]@{
        Length = [long]$Bytes.Length
        Sha256 = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($Bytes)
        ).ToLowerInvariant()
    }
}

function Assert-GameplayDigest {
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)][long]$ExpectedLength,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Label
    )

    if ([long]$Actual.Length -ne $ExpectedLength -or
        [string]$Actual.Sha256 -cne $ExpectedSha256) {
        throw "$Label differs from its sealed Gameplay transaction identity"
    }
}

function Read-GameplayStrictJsonWithBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    $snapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Path -Root $Root -MaximumBytes 256KB `
        -IncludeBytes -Label $Label
    $document = $null
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString(
            [byte[]]$snapshot.Bytes)
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 16
        $document = [System.Text.Json.JsonDocument]::Parse($text, $options)
        Test-PSOBBStrictJsonPropertyUniqueness `
            -Element $document.RootElement -Path '$' | Out-Null
        [pscustomobject]@{
            Value = ConvertFrom-PSOBBStrictDataJsonElement `
                -Element $document.RootElement -Label $Label
            Bytes = [byte[]]$snapshot.Bytes
            Length = [long]$snapshot.Length
            Sha256 = [string]$snapshot.Sha256
        }
        $snapshot.Bytes = $null
    } finally {
        if ($document) { $document.Dispose() }
        if ($snapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$snapshot.Bytes, 0, ([byte[]]$snapshot.Bytes).Length)
        }
    }
}

function ConvertTo-GameplayJsonBytes {
    param([Parameter(Mandatory)]$Value)

    ,([System.Text.UTF8Encoding]::new($false).GetBytes(
            ($Value | ConvertTo-Json -Depth 16)))
}

function Read-GameplaySourceBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][long]$ExpectedLength,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Label
    )

    $snapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Path -Root $Root -MaximumBytes $ExpectedLength `
        -IncludeBytes -Label $Label
    if ([string](Get-Item -Force -LiteralPath $Path).LinkType -ceq 'HardLink') {
        [Array]::Clear(
            [byte[]]$snapshot.Bytes, 0, ([byte[]]$snapshot.Bytes).Length)
        throw "$Label is hard-linked"
    }
    Assert-GameplayDigest -Actual $snapshot `
        -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
        -Label $Label
    ,([byte[]]$snapshot.Bytes)
}

function Read-GameplayLoaderBytes {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)]$Authority
    )

    $lease = $null
    $archive = $null
    $loaderBytes = $null
    try {
        $lease = Open-PSOBBCombatCanaryOrdinaryFileLease `
            -LiteralPath $ArchivePath -Root $RuntimeRoot `
            -RoleLabel 'Gameplay loader archive'
        if ([long]$lease.Stream.Length -ne [long]$Authority.LoaderArchiveSize) {
            throw 'The Gameplay loader archive has an unexpected size'
        }
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $lease.Stream.Position = 0
            $archiveHash = [Convert]::ToHexString(
                $sha256.ComputeHash($lease.Stream)).ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
        if ($archiveHash -cne [string]$Authority.LoaderArchiveSha256) {
            throw 'The Gameplay loader archive changed after source locking'
        }
        $lease.Stream.Position = 0
        $archive = [System.IO.Compression.ZipArchive]::new(
            $lease.Stream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
        $members = @($archive.Entries | Where-Object {
                [string]$_.FullName -ceq [string]$Authority.LoaderMemberPath
            })
        if ($archive.Entries.Count -ne 1 -or $members.Count -ne 1 -or
            [long]$members[0].Length -ne [long]$Authority.LoaderSize -or
            [long]$members[0].Length -gt 16MB) {
            throw 'The Gameplay loader archive does not contain its exact bounded x86 member'
        }
        $loaderBytes = [byte[]]::new([int]$members[0].Length)
        $entryStream = $members[0].Open()
        try {
            $entryStream.ReadExactly($loaderBytes)
            if ($entryStream.ReadByte() -ne -1) {
                throw 'The Gameplay loader member changed length while it was read'
            }
        } finally {
            $entryStream.Dispose()
        }
        $identity = Get-GameplayBytesDigest -Bytes $loaderBytes
        Assert-GameplayDigest -Actual $identity `
            -ExpectedLength ([long]$Authority.LoaderSize) `
            -ExpectedSha256 ([string]$Authority.LoaderSha256) `
            -Label 'Gameplay loader member'
        ,([byte[]]$loaderBytes)
        $loaderBytes = $null
    } finally {
        if ($loaderBytes) {
            [Array]::Clear($loaderBytes, 0, $loaderBytes.Length)
        }
        if ($archive) { $archive.Dispose() }
        Close-PSOBBCombatCanaryOrdinaryFileLease -Context $lease
    }
}

function Write-GameplayProtectedArtifact {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes
    )

    [void](Write-PSOBBDurableFileBytes `
            -Path $Path -Root $Root -Bytes $Bytes `
            -Label 'Gameplay transaction artifact')
    Set-PSOBBProtectedAcl -Path $Path
    $expected = Get-GameplayBytesDigest -Bytes $Bytes
    $actual = Get-GameplayDigest -Path $Path -Root $Root `
        -Label 'Gameplay transaction artifact'
    Assert-GameplayDigest -Actual $actual `
        -ExpectedLength $expected.Length -ExpectedSha256 $expected.Sha256 `
        -Label 'Gameplay transaction artifact'
    $expected
}

function Assert-GameplayOrdinaryDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Path -Root $Root -Kind Directory -Label $Label)
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if (($item.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is a reparse point"
    }
    $item.FullName
}

function Initialize-GameplayOrdinaryDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PathWithinRoot -Path $Path -Root $safeRoot
    [void](Assert-GameplayOrdinaryDirectory -Path $safeRoot -Root $safeRoot `
            -Label "$Label root")
    $relative = [System.IO.Path]::GetRelativePath($safeRoot, $safePath)
    if ($relative -eq '.') { return $safeRoot }
    $current = $safeRoot
    foreach ($segment in @($relative.Split('\'))) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            [void][System.IO.Directory]::CreateDirectory($current)
        }
        [void](Assert-GameplayOrdinaryDirectory -Path $current -Root $safeRoot `
                -Label $Label)
    }
    $safePath
}

function Set-GameplayProtectedDirectoryAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    $leases = @()
    try {
        $leases = @(Open-PSOBBCombatCanaryDirectoryLeaseChain `
                -Path $Path -Root $Root -RoleLabel $Label)
        if ($leases.Count -eq 0) {
            throw "$Label did not yield an ordinary directory lease"
        }
        $targetLease = $leases[-1]
        [void](Assert-PSOBBCombatCanaryNativeHandlePath `
                -Handle $targetLease.Handle -ExpectedPath $Path -Root $Root `
                -Directory $true -RoleLabel $Label)
        Set-PSOBBProtectedAcl -Path $Path
        [void](Assert-PSOBBCombatCanaryNativeHandlePath `
                -Handle $targetLease.Handle -ExpectedPath $Path -Root $Root `
                -Directory $true -RoleLabel $Label)
        if (-not (Test-PSOBBProtectedAcl -Path $Path)) {
            throw "$Label protection did not persist"
        }
    } finally {
        Close-PSOBBCombatCanaryDirectoryLeaseChain -Leases $leases
    }
}

function Move-GameplayOrdinaryDirectory {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safeSource = Assert-PathWithinRoot -Path $Source -Root $safeRoot
    $safeDestination = Assert-PathWithinRoot -Path $Destination -Root $safeRoot
    if (Test-Path -LiteralPath $safeDestination) {
        throw "$Label destination already exists"
    }
    $sourceParentLeases = @()
    $destinationParentLeases = @()
    $sourceHandle = $null
    try {
        $sourceParentLeases = @(Open-PSOBBCombatCanaryDirectoryLeaseChain `
                -Path (Split-Path -Parent $safeSource) -Root $safeRoot `
                -RoleLabel "$Label source parent")
        $destinationParentLeases = @(
            Open-PSOBBCombatCanaryDirectoryLeaseChain `
                -Path (Split-Path -Parent $safeDestination) -Root $safeRoot `
                -RoleLabel "$Label destination parent")
        $sourceHandle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $safeSource -Directory $true -Delete
        [void](Assert-PSOBBCombatCanaryNativeHandlePath `
                -Handle $sourceHandle -ExpectedPath $safeSource -Root $safeRoot `
                -Directory $true -RoleLabel $Label)
        [PSOBBCombatCanary.NativeFiles]::Rename(
            $sourceHandle, $safeDestination)
    } finally {
        if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
        Close-PSOBBCombatCanaryDirectoryLeaseChain `
            -Leases $destinationParentLeases
        Close-PSOBBCombatCanaryDirectoryLeaseChain `
            -Leases $sourceParentLeases
    }
}

function Remove-GameplayEmptyDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    [void](Assert-GameplayOrdinaryDirectory -Path $Path -Root $Root `
            -Label $Label)
    if (@(Get-ChildItem -Force -LiteralPath $Path).Count -ne 0) {
        throw "$Label is not empty"
    }
    $handle = $null
    try {
        $handle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $Path -Directory $true -Delete
        [void](Assert-PSOBBCombatCanaryNativeHandlePath `
                -Handle $handle -ExpectedPath $Path -Root $Root `
                -Directory $true -RoleLabel $Label)
        [PSOBBCombatCanary.NativeFiles]::MarkDelete($handle)
    } finally {
        if ($null -ne $handle) { $handle.Dispose() }
    }
    if (Test-Path -LiteralPath $Path) {
        throw "$Label was not removed"
    }
}

function Assert-GameplayDestinationState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][object[]]$AllowedIdentities = @(),
        [switch]$AllowAbsent,
        [switch]$RequireProtected,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if (-not $AllowAbsent) {
            throw "$Label is absent instead of matching its expected pre-transaction state"
        }
        return [pscustomobject]@{ State = 'absent'; Length = 0L; Sha256 = '' }
    }

    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Path -Root $Root -Kind File -Label $Label)
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if ([string]$item.LinkType -ceq 'HardLink') {
        throw "$Label is hard-linked"
    }
    if ($RequireProtected -and -not (Test-PSOBBProtectedAcl -Path $Path)) {
        throw "$Label is not protected"
    }
    $actual = Get-GameplayDigest -Path $Path -Root $Root -Label $Label
    $matches = @($AllowedIdentities | Where-Object {
            $null -ne $_ -and
            [long]$_.Length -eq [long]$actual.Length -and
            [string]$_.Sha256 -ceq [string]$actual.Sha256
        })
    if ($matches.Count -eq 0) {
        throw "$Label changed after Gameplay preflight"
    }
    [pscustomobject]@{
        State = 'matched'
        Length = [long]$actual.Length
        Sha256 = [string]$actual.Sha256
    }
}

function Install-GameplayArtifact {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$TransactionRoot,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][string]$Temporary,
        [Parameter(Mandatory)][long]$ExpectedLength,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [AllowEmptyCollection()][object[]]$AllowedDestinationIdentities = @(),
        [switch]$AllowAbsentDestination,
        [string]$Displaced,
        [switch]$Protect,
        [string]$PostCommitFaultPoint = ''
    )

    $temporaryCreated = $false
    $sourceSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Source -Root $TransactionRoot `
        -MaximumBytes ([Math]::Max(1L, $ExpectedLength)) `
        -AllowEmpty -IncludeBytes -Label 'Gameplay transaction source'
    try {
        Assert-GameplayDigest -Actual $sourceSnapshot `
            -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
            -Label 'Gameplay transaction source'
        $destinationState = Assert-GameplayDestinationState -Path $Destination `
                -Root $DestinationRoot `
                -AllowedIdentities $AllowedDestinationIdentities `
                -AllowAbsent:$AllowAbsentDestination `
                -RequireProtected:$Protect `
                -Label 'Gameplay install destination'
        if ($destinationState.State -ceq 'matched' -and
            [long]$destinationState.Length -eq $ExpectedLength -and
            [string]$destinationState.Sha256 -ceq $ExpectedSha256) {
            return
        }
        if (Test-Path -LiteralPath $Temporary) {
            throw "A Gameplay install temporary already exists: $Temporary"
        }
        [void](Write-PSOBBDurableFileBytes `
                -Path $Temporary -Root $DestinationRoot `
                -Bytes ([byte[]]$sourceSnapshot.Bytes) `
                -Label 'Gameplay install staging')
        $temporaryCreated = $true
        if ($Protect) { Set-PSOBBProtectedAcl -Path $Temporary }
        $staged = Get-GameplayDigest -Path $Temporary -Root $DestinationRoot `
            -Label 'Gameplay install staging'
        Assert-GameplayDigest -Actual $staged `
            -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
            -Label 'Gameplay install staging'
        $destinationState = Assert-GameplayDestinationState -Path $Destination `
                -Root $DestinationRoot `
                -AllowedIdentities $AllowedDestinationIdentities `
                -AllowAbsent:$AllowAbsentDestination `
                -RequireProtected:$Protect `
                -Label 'Gameplay install destination'
        if ($destinationState.State -ceq 'absent') {
            [System.IO.File]::Move($Temporary, $Destination, $false)
            $temporaryCreated = $false
        } else {
            if ([string]::IsNullOrWhiteSpace($Displaced)) {
                throw 'Gameplay replacement requires a transaction-contained displacement path'
            }
            $safeDisplaced = Assert-PathWithinRoot `
                -Path $Displaced -Root $TransactionRoot
            if (Test-Path -LiteralPath $safeDisplaced) {
                throw "A Gameplay displacement already exists: $safeDisplaced"
            }
            [System.IO.File]::Replace(
                $Temporary, $Destination, $safeDisplaced, $true)
            $temporaryCreated = $false
            [void](Assert-GameplayDestinationState -Path $safeDisplaced `
                    -Root $TransactionRoot `
                    -AllowedIdentities $AllowedDestinationIdentities `
                    -RequireProtected:$Protect `
                -Label 'Gameplay displaced destination')
        }
        if (-not [string]::IsNullOrWhiteSpace($PostCommitFaultPoint)) {
            Invoke-GameplayFault -Point $PostCommitFaultPoint
        }
        if ($Protect) { Set-PSOBBProtectedAcl -Path $Destination }
        $installed = Get-GameplayDigest -Path $Destination `
            -Root $DestinationRoot -Label 'Gameplay installed target'
        Assert-GameplayDigest -Actual $installed `
            -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
            -Label 'Gameplay installed target'
    } finally {
        if ($sourceSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$sourceSnapshot.Bytes, 0,
                ([byte[]]$sourceSnapshot.Bytes).Length)
        }
        if ($temporaryCreated -and (Test-Path -LiteralPath $Temporary)) {
            Remove-GameplayExactFile -Path $Temporary -Root $DestinationRoot `
                -ExpectedLength $ExpectedLength `
                -ExpectedSha256 $ExpectedSha256 `
                -Label 'Gameplay install staging cleanup'
        }
    }
}

function Remove-GameplayExactFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][long]$ExpectedLength,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Label,
        [switch]$RequirePresent
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($RequirePresent) { throw "$Label is unexpectedly absent" }
        return
    }
    $handle = $null
    $stream = $null
    $hash = $null
    try {
        $handle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $Path -Directory $false -Read -Delete
        $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $handle -ExpectedPath $Path -Root $Root `
            -Directory $false -RoleLabel $Label -RequireSingleLink
        $stream = [System.IO.FileStream]::new(
            $handle, [System.IO.FileAccess]::Read, 65536, $false)
        $handle = $null
        if ([long]$stream.Length -ne $ExpectedLength) {
            throw "$Label differs from its sealed Gameplay identity"
        }
        $hash = [System.Security.Cryptography.SHA256]::HashData($stream)
        $sha256 = [Convert]::ToHexString($hash).ToLowerInvariant()
        if ($sha256 -cne $ExpectedSha256) {
            throw "$Label differs from its sealed Gameplay identity"
        }
        $current = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $stream.SafeFileHandle -ExpectedPath $Path -Root $Root `
            -Directory $false -RoleLabel $Label -RequireSingleLink
        if (-not (Test-PSOBBCombatCanaryNativeIdentityEqual `
                -Left $identity -Right $current)) {
            throw "$Label changed while its exact deletion was prepared"
        }
        [PSOBBCombatCanary.NativeFiles]::MarkDelete($stream.SafeFileHandle)
    } finally {
        if ($null -ne $hash) { [Array]::Clear($hash, 0, $hash.Length) }
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $handle) { $handle.Dispose() }
    }
    if (Test-Path -LiteralPath $Path) {
        throw "$Label was not removed"
    }
}

function Get-GameplayStableFingerprint {
    param([Parameter(Mandatory)]$StableLayout)

    $client = Join-Path $StableLayout.Client 'Psobb.exe'
    [pscustomobject]@{
        ClientSize = (Get-Item -Force -LiteralPath $client).Length
        ClientSha256 = Get-LowerSha256 $client
        InstallationSize = (Get-Item -Force `
                -LiteralPath $StableLayout.InstallRecord).Length
        InstallationSha256 = Get-LowerSha256 $StableLayout.InstallRecord
    }
}

function Assert-GameplayStableFingerprint {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$StableLayout
    )

    $actual = Get-GameplayStableFingerprint -StableLayout $StableLayout
    if ($actual.ClientSize -ne $Expected.ClientSize -or
        $actual.ClientSha256 -cne $Expected.ClientSha256 -or
        $actual.InstallationSize -ne $Expected.InstallationSize -or
        $actual.InstallationSha256 -cne $Expected.InstallationSha256) {
        throw 'Stable Psobb.exe or installation authority changed during the CombatCanary Gameplay transaction'
    }
}

function Get-GameplayBoundedCanonicalInstalledBinding {
    param(
        [Parameter(Mandatory)]$Layout,
        [ValidateRange(1, 220)][int]$TimeoutSeconds = 220
    )

    $pwshPath = Join-Path $PSHOME 'pwsh.exe'
    [void](Assert-PSOBBOrdinaryContainedPath -Path $pwshPath -Root $PSHOME `
            -Kind File -Label 'Gameplay verification PowerShell host')
    $commonPath = Join-Path $script:PSOBBRepositoryRoot `
        'scripts\PSOBB.Common.ps1'
    [void](Assert-PSOBBOrdinaryContainedPath -Path $commonPath `
            -Root $script:PSOBBRepositoryRoot -Kind File `
            -Label 'Gameplay verification common script')
    $encode = {
        param([Parameter(Mandatory)][string]$Value)
        [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes($Value))
    }
    $commonEncoded = & $encode $commonPath
    $runtimeEncoded = & $encode ([string]$Layout.Root)
    $command = @"
`$ErrorActionPreference = 'Stop'
`$common = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$commonEncoded'))
`$runtime = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$runtimeEncoded'))
. `$common
`$layout = Get-PSOBBLayout -RuntimeRoot `$runtime
`$verification = Get-PSOBBCombatCanaryInstalledBinding -Layout `$layout
[Console]::Out.Write((`$verification | ConvertTo-Json -Depth 8 -Compress))
"@
    $encodedCommand = [Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($command))
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwshPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new(
        $false, $true)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new(
        $false, $true)
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-EncodedCommand', $encodedCommand)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdoutTask = $null
    $stderrTask = $null
    $stdoutBuffer = [PSOBBCombatCanary.BoundedMemoryStream]::new(256KB)
    $stderrBuffer = [PSOBBCombatCanary.BoundedMemoryStream]::new(256KB)
    $exited = $false
    $terminationFailure = $false
    $stopwatch = $null
    try {
        if (-not $process.Start()) {
            throw 'Windows did not start the complete CombatCanary verifier'
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutBuffer)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrBuffer)
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not ($exited = $process.WaitForExit(250))) {
            if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted) {
                try { $process.Kill($true) } catch { }
                $exited = $process.WaitForExit(5000)
                throw 'The complete CombatCanary verifier exceeded its output bound'
            }
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { break }
        }
        if (-not $exited) {
            try { $process.Kill($true) } catch { }
            $exited = $process.WaitForExit(5000)
            if (-not $exited) {
                throw ('The complete CombatCanary verifier exceeded ' +
                    "$TimeoutSeconds seconds and did not terminate within the " +
                    'bounded five-second cleanup window')
            }
            throw "The complete CombatCanary verifier exceeded $TimeoutSeconds seconds"
        }
        $drainTask = [System.Threading.Tasks.Task]::WhenAll(
            [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
        $outputClosed = $false
        try { $outputClosed = $drainTask.Wait(5000) } catch {
            $outputClosed = $true
        }
        if (-not $outputClosed) {
            throw 'The complete CombatCanary verifier output did not close within its bounded drain window'
        }
        try {
            [void]$stdoutTask.GetAwaiter().GetResult()
            [void]$stderrTask.GetAwaiter().GetResult()
        } catch {
            throw 'The complete CombatCanary verifier exceeded its output bound'
        }
        $stdout = $stdoutBuffer.ReadUtf8AndClear()
        $stderr = $stderrBuffer.ReadUtf8AndClear()
        if ($process.ExitCode -ne 0) {
            $detail = if ([string]::IsNullOrWhiteSpace($stderr)) {
                'no diagnostic was returned'
            } else {
                $stderr.Trim()
            }
            throw "The complete CombatCanary verifier failed: $detail"
        }
        if ([string]::IsNullOrWhiteSpace($stdout)) {
            throw 'The complete CombatCanary verifier returned invalid bounded output'
        }
        $document = $null
        try {
            $options = [System.Text.Json.JsonDocumentOptions]::new()
            $options.AllowTrailingCommas = $false
            $options.CommentHandling =
                [System.Text.Json.JsonCommentHandling]::Disallow
            $options.MaxDepth = 8
            $document = [System.Text.Json.JsonDocument]::Parse($stdout, $options)
            Test-PSOBBStrictJsonPropertyUniqueness `
                -Element $document.RootElement -Path '$' | Out-Null
            $verification = ConvertFrom-PSOBBStrictDataJsonElement `
                -Element $document.RootElement `
                -Label 'complete CombatCanary verification result'
        } finally {
            if ($document) { $document.Dispose() }
        }
        [void](Assert-PSOBBStrictDataObjectProperties -Value $verification `
                -Expected @(
                    'Valid', 'Target', 'Environment', 'SnapshotId',
                    'SnapshotManifestSha256', 'ServerArtifact',
                    'ServerComponentId', 'BuildContractSha256',
                    'ServerReleaseManifestSha256', 'BaseClientManifestSha256',
                    'ClientBindingSha256', 'ConfigurationSha256',
                    'StateBindingSha256', 'TwillsContractSha256',
                    'SigningPublicKeySpkiSha256') `
                -Label 'complete CombatCanary verification result')
        if ($verification.Valid -isnot [bool] -or
            -not [bool]$verification.Valid -or
            $verification.Target -isnot [string] -or
            [string]$verification.Target -cne 'Installed' -or
            $verification.Environment -isnot [string] -or
            [string]$verification.Environment -cne 'CombatCanary') {
            throw 'The complete CombatCanary verifier returned an invalid identity'
        }
        foreach ($propertyName in @(
                'SnapshotManifestSha256', 'BuildContractSha256',
                'ServerReleaseManifestSha256', 'BaseClientManifestSha256',
                'ClientBindingSha256', 'ConfigurationSha256',
                'StateBindingSha256', 'TwillsContractSha256',
                'SigningPublicKeySpkiSha256')) {
            if ($verification.$propertyName -isnot [string] -or
                [string]$verification.$propertyName -cnotmatch '^[a-f0-9]{64}$') {
                throw "The complete CombatCanary verifier returned an invalid $propertyName"
            }
        }
        $verification
    } finally {
        if ($stopwatch) { $stopwatch.Stop() }
        if (-not $exited) {
            try { $process.Kill($true) } catch { }
            try { $exited = $process.WaitForExit(5000) } catch { }
            $terminationFailure = -not $exited
        }
        if ($stdoutTask -and $stdoutTask.IsCompleted) {
            try { [void]$stdoutTask.GetAwaiter().GetResult() } catch { }
        }
        if ($stderrTask -and $stderrTask.IsCompleted) {
            try { [void]$stderrTask.GetAwaiter().GetResult() } catch { }
        }
        $process.Dispose()
        $stdoutBuffer.Dispose()
        $stderrBuffer.Dispose()
        if ($terminationFailure) {
            throw 'The complete CombatCanary verifier could not be terminated within its bounded cleanup window'
        }
    }
}

function Get-GameplayPaths {
    param([Parameter(Mandatory)]$CombatLayout)

    $plugins = Join-Path $CombatLayout.Client 'plugins'
    [pscustomobject]@{
        Plugins = $plugins
        Loader = Join-Path $CombatLayout.Client 'dinput8.dll'
        Module = Join-Path $plugins 'PSOBB.Gameplay.asi'
        Configuration = Join-Path $plugins 'PSOBB.Gameplay.ini'
        Binding = Join-Path $CombatLayout.EnvironmentRoot 'client-binding.json'
        Installation = $CombatLayout.InstallRecord
        Transaction = Join-Path $CombatLayout.EnvironmentRoot `
            '.gameplay-transaction'
        TransactionNext = Join-Path $CombatLayout.EnvironmentRoot `
            '.gameplay-transaction.next'
        BackupRoot = Join-Path $CombatLayout.Backups 'gameplay-activations'
        LoaderTemporary = Join-Path $CombatLayout.Client '.psobb-gameplay-loader.new'
        ModuleTemporary = Join-Path $plugins '.psobb-gameplay-module.new'
        ConfigurationTemporary = Join-Path $plugins `
            '.psobb-gameplay-configuration.new'
        BindingTemporary = Join-Path $CombatLayout.EnvironmentRoot `
            '.psobb-gameplay-binding.new'
        InstallationTemporary = Join-Path $CombatLayout.EnvironmentRoot `
            '.psobb-gameplay-installation.new'
    }
}

function Assert-GameplayNoTransactionDebris {
    param([Parameter(Mandatory)]$Paths)

    $candidates = @(
        $Paths.Transaction,
        $Paths.TransactionNext,
        $Paths.LoaderTemporary,
        $Paths.ModuleTemporary,
        $Paths.ConfigurationTemporary,
        $Paths.BindingTemporary,
        $Paths.InstallationTemporary)
    $present = @($candidates | Where-Object { Test-Path -LiteralPath $_ })
    if ($present.Count -ne 0) {
        throw ('A prior Gameplay transaction or temporary remains. Keep both ' +
            'environments stopped and preserve it for exact recovery: ' +
            ($present -join ', '))
    }
}

function Assert-GameplayBaselineBinding {
    param(
        [Parameter(Mandatory)]$Binding,
        [Parameter(Mandatory)]$Installation,
        [Parameter(Mandatory)]$Paths,
        [switch]$SkipOverlayFileCheck
    )

    [void](Assert-PSOBBStrictDataObjectProperties -Value $Binding.Value `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'profile', 'renderer', 'serverAddress', 'patchPort',
                'gamePorts', 'clientExecutablePath', 'clientExecutableSize',
                'clientExecutableSha256', 'clientProfileSha256',
                'baseClientManifestSha256', 'createdAtUtc') `
            -Label 'CombatCanary baseline client binding')
    if ($Binding.Value.schemaVersion -isnot [long] -or
        [long]$Binding.Value.schemaVersion -ne 1 -or
        [string]$Binding.Value.environment -cne 'CombatCanary' -or
        [string]$Binding.Value.environmentId -cne 'combat-canary' -or
        [string]$Binding.Value.profile -cne 'baseline' -or
        [string]$Binding.Value.renderer -cne 'Native' -or
        [string]$Binding.Value.serverAddress -cne '127.0.0.1' -or
        [long]$Binding.Value.patchPort -ne 11000 -or
        [string]::Join(',', @($Binding.Value.gamePorts)) -cne
            '12000,12001' -or
        [string]$Binding.Value.clientExecutablePath -cne
            'runtime/client/Psobb.exe' -or
        [long]$Binding.Value.clientExecutableSize -ne 6971904 -or
        [string]$Binding.Value.clientExecutableSha256 -cne
            'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535' -or
        [string]$Binding.Value.clientProfileSha256 -cnotmatch
            '^[a-f0-9]{64}$' -or
        [string]$Binding.Value.baseClientManifestSha256 -cnotmatch
            '^[a-f0-9]{64}$' -or
        [string]$Installation.Value.clientBindingSha256 -cne
            [string]$Binding.Sha256) {
        throw 'CombatCanary is not at its exact schema-1 Native binding'
    }
    if (-not $SkipOverlayFileCheck) {
        foreach ($path in @($Paths.Loader, $Paths.Module, $Paths.Configuration)) {
            if (Test-Path -LiteralPath $path) {
                throw 'Schema-1 CombatCanary contains an undeclared Gameplay overlay file'
            }
        }
    }
}

function Assert-GameplayActiveBinding {
    param(
        [Parameter(Mandatory)]$Binding,
        [Parameter(Mandatory)]$Installation,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Authority,
        [switch]$SkipOverlayFileCheck
    )

    [void](Assert-PSOBBStrictDataObjectProperties -Value $Binding.Value `
            -Expected @('schemaVersion', 'environment', 'environmentId',
                'profile', 'renderer', 'serverAddress', 'patchPort',
                'gamePorts', 'clientExecutablePath', 'clientExecutableSize',
                'clientExecutableSha256', 'clientProfileSha256',
                'baseClientManifestSha256', 'createdAtUtc', 'gameplayOverlay') `
            -Label 'CombatCanary Gameplay client binding')
    if ($Binding.Value.schemaVersion -isnot [long] -or
        [long]$Binding.Value.schemaVersion -ne 2 -or
        [string]$Binding.Value.environment -cne 'CombatCanary' -or
        [string]$Binding.Value.environmentId -cne 'combat-canary' -or
        [string]$Binding.Value.profile -cne 'baseline' -or
        [string]$Binding.Value.renderer -cne 'Native' -or
        [string]$Binding.Value.serverAddress -cne '127.0.0.1' -or
        [long]$Binding.Value.patchPort -ne 11000 -or
        [string]::Join(',', @($Binding.Value.gamePorts)) -cne
            '12000,12001' -or
        [string]$Binding.Value.clientExecutablePath -cne
            'runtime/client/Psobb.exe' -or
        [long]$Binding.Value.clientExecutableSize -ne 6971904 -or
        [string]$Binding.Value.clientExecutableSha256 -cne
            'dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535' -or
        [string]$Installation.Value.clientBindingSha256 -cne
            [string]$Binding.Sha256) {
        throw 'CombatCanary is not at its exact schema-2 Gameplay binding'
    }
    $entries = @(Get-PSOBBCombatCanaryGameplayOverlayEntries `
            -GameplayOverlay $Binding.Value.gameplayOverlay `
            -ClientRoot $CombatLayout.Client `
            -VerifyFiles:(-not $SkipOverlayFileCheck))
    $loader = @($entries | Where-Object path -CEQ 'dinput8.dll')
    $module = @($entries | Where-Object path -CEQ `
            'plugins/PSOBB.Gameplay.asi')
    if ($loader.Count -ne 1 -or $module.Count -ne 1 -or
        [long]$loader[0].size -ne [long]$Authority.LoaderSize -or
        [string]$loader[0].sha256 -cne [string]$Authority.LoaderSha256 -or
        [long]$module[0].size -ne [long]$Authority.ModuleSize -or
        [string]$module[0].sha256 -cne [string]$Authority.ModuleSha256) {
        throw 'The active Gameplay overlay differs from its tracked authorities'
    }
}

function Assert-GameplayClientBindingFiles {
    param(
        [Parameter(Mandatory)]$Binding,
        [Parameter(Mandatory)]$CombatLayout
    )

    $clientExecutable = Join-Path $CombatLayout.Client 'Psobb.exe'
    $clientProfile = Join-Path $CombatLayout.Client 'client-profile.json'
    $executable = Get-GameplayDigest -Path $clientExecutable `
        -Root $CombatLayout.EnvironmentRoot -Label 'CombatCanary client executable'
    Assert-GameplayDigest -Actual $executable `
        -ExpectedLength ([long]$Binding.Value.clientExecutableSize) `
        -ExpectedSha256 ([string]$Binding.Value.clientExecutableSha256) `
        -Label 'CombatCanary client executable'

    $profile = Read-GameplayStrictJsonWithBytes -Path $clientProfile `
        -Root $CombatLayout.EnvironmentRoot -Label 'CombatCanary client profile'
    try {
        if ([string]$profile.Sha256 -cne
            [string]$Binding.Value.clientProfileSha256) {
            throw 'The CombatCanary client profile differs from its binding'
        }
        [void](Assert-PSOBBStrictDataObjectProperties -Value $profile.Value `
                -Expected @(
                    'schemaVersion', 'builtAtUtc', 'channel', 'profileId',
                    'nativeGraphics', 'renderer', 'baseExecutableSha256',
                    'wrapperSha256', 'sourceConfigurationSha256',
                    'configurationSha256', 'outputApi', 'graphicsPreset',
                    'desktopWidth', 'desktopHeight', 'renderWidth',
                    'renderHeight', 'aspectPolicy', 'resamplingFilter',
                    'textureFilterPolicy', 'edgeSmoothingPolicy',
                    'bilinear2DOperations', 'defaultWindowMode',
                    'resizableClientWidth', 'resizableClientHeight',
                    'watermarkEnabled', 'compatibilityFirst') `
                -Label 'CombatCanary client profile')
        if ($profile.Value.schemaVersion -isnot [long] -or
            [long]$profile.Value.schemaVersion -ne 5 -or
            [string]$profile.Value.channel -cne 'combat-canary' -or
            [string]$profile.Value.profileId -cne 'safe-native-4x3' -or
            [string]$profile.Value.renderer -cne 'Native' -or
            [string]$profile.Value.graphicsPreset -cne 'Native' -or
            [string]$profile.Value.baseExecutableSha256 -cne
                [string]$Binding.Value.clientExecutableSha256 -or
            $null -eq $profile.Value.nativeGraphics) {
            throw 'The CombatCanary client profile is not the exact Native profile'
        }
    } finally {
        if ($profile.Bytes) {
            [Array]::Clear($profile.Bytes, 0, $profile.Bytes.Length)
        }
    }
}

function New-GameplayBindingBytes {
    param(
        [Parameter(Mandatory)]$BaselineBinding,
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$ConfigurationIdentity
    )

    $bytes = ConvertTo-GameplayJsonBytes ([ordered]@{
        schemaVersion = 2
        environment = [string]$BaselineBinding.environment
        environmentId = [string]$BaselineBinding.environmentId
        profile = [string]$BaselineBinding.profile
        renderer = [string]$BaselineBinding.renderer
        serverAddress = [string]$BaselineBinding.serverAddress
        patchPort = [long]$BaselineBinding.patchPort
        gamePorts = @($BaselineBinding.gamePorts)
        clientExecutablePath = [string]$BaselineBinding.clientExecutablePath
        clientExecutableSize = [long]$BaselineBinding.clientExecutableSize
        clientExecutableSha256 = [string]$BaselineBinding.clientExecutableSha256
        clientProfileSha256 = [string]$BaselineBinding.clientProfileSha256
        baseClientManifestSha256 =
            [string]$BaselineBinding.baseClientManifestSha256
        createdAtUtc = [string]$BaselineBinding.createdAtUtc
        gameplayOverlay = [ordered]@{
            loaderPath = 'runtime/client/dinput8.dll'
            loaderSize = [long]$Authority.LoaderSize
            loaderSha256 = [string]$Authority.LoaderSha256
            modulePath = 'runtime/client/plugins/PSOBB.Gameplay.asi'
            moduleSize = [long]$Authority.ModuleSize
            moduleSha256 = [string]$Authority.ModuleSha256
            configurationPath =
                'runtime/client/plugins/PSOBB.Gameplay.ini'
            configurationSize = [long]$ConfigurationIdentity.Size
            configurationSha256 = [string]$ConfigurationIdentity.Sha256
        }
    })
    ,([byte[]]$bytes)
}

function New-GameplayInstallationBytes {
    param(
        [Parameter(Mandatory)]$Installation,
        [Parameter(Mandatory)][string]$ClientBindingSha256
    )

    $bytes = ConvertTo-GameplayJsonBytes ([ordered]@{
        schemaVersion = [long]$Installation.schemaVersion
        environment = [string]$Installation.environment
        environmentId = [string]$Installation.environmentId
        initializedAtUtc = [string]$Installation.initializedAtUtc
        buildContractSha256 = [string]$Installation.buildContractSha256
        serverReleaseManifestSha256 =
            [string]$Installation.serverReleaseManifestSha256
        baseClientManifestSha256 =
            [string]$Installation.baseClientManifestSha256
        clientBindingSha256 = $ClientBindingSha256
        snapshotDirectoryName = [string]$Installation.snapshotDirectoryName
        snapshotId = [string]$Installation.snapshotId
        snapshotManifestSha256 =
            [string]$Installation.snapshotManifestSha256
        stateBindingSha256 = [string]$Installation.stateBindingSha256
        twillsContractSha256 = [string]$Installation.twillsContractSha256
        signingPublicKeySpkiSha256 =
            [string]$Installation.signingPublicKeySpkiSha256
        configurationSha256 = [string]$Installation.configurationSha256
    })
    ,([byte[]]$bytes)
}

function Assert-GameplayInstallationRecordShape {
    param(
        [Parameter(Mandatory)]$Installation,
        [Parameter(Mandatory)][string]$Label
    )

    $properties = @(
        'schemaVersion', 'environment', 'environmentId', 'initializedAtUtc',
        'buildContractSha256', 'serverReleaseManifestSha256',
        'baseClientManifestSha256', 'clientBindingSha256',
        'snapshotDirectoryName', 'snapshotId', 'snapshotManifestSha256',
        'stateBindingSha256', 'twillsContractSha256',
        'signingPublicKeySpkiSha256', 'configurationSha256')
    [void](Assert-PSOBBStrictDataObjectProperties -Value $Installation `
            -Expected $properties -Label $Label)
    foreach ($name in @($properties | Where-Object { $_ -cne 'schemaVersion' })) {
        if ($Installation.$name -isnot [string]) {
            throw "$Label contains a non-string $name"
        }
    }
    $initializedAt = [DateTimeOffset]::MinValue
    $snapshotId = [Guid]::Empty
    if ($Installation.schemaVersion -isnot [long] -or
        [long]$Installation.schemaVersion -ne 1 -or
        [string]$Installation.environment -cne 'CombatCanary' -or
        [string]$Installation.environmentId -cne 'combat-canary' -or
        -not [DateTimeOffset]::TryParse(
            [string]$Installation.initializedAtUtc, [ref]$initializedAt) -or
        [string]$Installation.snapshotDirectoryName -cnotmatch
            '^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$' -or
        -not [Guid]::TryParseExact(
            [string]$Installation.snapshotId, 'D', [ref]$snapshotId)) {
        throw "$Label has an invalid CombatCanary identity"
    }
    foreach ($name in @(
            'buildContractSha256', 'serverReleaseManifestSha256',
            'baseClientManifestSha256', 'clientBindingSha256',
            'snapshotManifestSha256', 'stateBindingSha256',
            'twillsContractSha256', 'signingPublicKeySpkiSha256',
            'configurationSha256')) {
        if ([string]$Installation.$name -cnotmatch '^[a-f0-9]{64}$') {
            throw "$Label contains an invalid $name"
        }
    }
}

function Assert-GameplaySnapshotArtifact {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][long]$ExpectedLength,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$Label
    )

    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Path -Root $Root -Kind File -Label $Label)
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if ([string]$item.LinkType -ceq 'HardLink' -or
        -not (Test-PSOBBProtectedAcl -Path $Path)) {
        throw "$Label is hard-linked or unprotected"
    }
    $actual = Get-GameplayDigest -Path $Path -Root $Root -Label $Label
    Assert-GameplayDigest -Actual $actual `
        -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
        -Label $Label
}

function Find-GameplayActivationSnapshot {
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)][string]$CurrentBindingSha256,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$ConfigurationIdentity,
        [Parameter(Mandatory)][string]$RuntimeInstallationId,
        [switch]$AllowConsumed,
        [string]$ExpectedActivationId = ''
    )

    if (-not (Test-Path -LiteralPath $Paths.BackupRoot -PathType Container)) {
        throw 'No Gameplay activation snapshot exists for exact rollback'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Paths.BackupRoot -Root $CombatLayout.EnvironmentRoot `
            -Kind Directory -Label 'Gameplay activation backup root')
    if (-not (Test-PSOBBProtectedAcl -Path $Paths.BackupRoot)) {
        throw 'The Gameplay activation backup root is not protected'
    }

    $manifestProperties = @(
        'schemaVersion', 'runtimeInstallationId', 'transactionId',
        'activationId', 'action', 'createdAtUtc',
        'pluginsDirectoryExisted', 'originalBindingSize',
        'originalBindingSha256', 'originalInstallationSize',
        'originalInstallationSha256', 'activeBindingSize',
        'activeBindingSha256', 'candidateBindingSize',
        'candidateBindingSha256', 'candidateInstallationSize',
        'candidateInstallationSha256', 'loaderSize', 'loaderSha256',
        'moduleSize', 'moduleSha256', 'configurationSize',
        'configurationSha256')
    $artifactDefinitions = @(
        [pscustomobject]@{
            Name = 'original-client-binding.json'; Size = 'originalBindingSize'
            Sha256 = 'originalBindingSha256'
        },
        [pscustomobject]@{
            Name = 'original-installation.json'; Size = 'originalInstallationSize'
            Sha256 = 'originalInstallationSha256'
        },
        [pscustomobject]@{
            Name = 'candidate-client-binding.json'; Size = 'candidateBindingSize'
            Sha256 = 'candidateBindingSha256'
        },
        [pscustomobject]@{
            Name = 'candidate-installation.json'; Size = 'candidateInstallationSize'
            Sha256 = 'candidateInstallationSha256'
        },
        [pscustomobject]@{
            Name = 'dinput8.dll'; Size = 'loaderSize'; Sha256 = 'loaderSha256'
        },
        [pscustomobject]@{
            Name = 'PSOBB.Gameplay.asi'; Size = 'moduleSize'; Sha256 = 'moduleSha256'
        },
        [pscustomobject]@{
            Name = 'PSOBB.Gameplay.ini'; Size = 'configurationSize'
            Sha256 = 'configurationSha256'
        })
    $snapshotMatches = [System.Collections.Generic.List[object]]::new()
    foreach ($directory in @(Get-ChildItem -Force -LiteralPath $Paths.BackupRoot `
                -Directory)) {
        if ($directory.Name -cnotmatch
            '^gameplay-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$') { continue }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedActivationId) -and
            $directory.Name -cne $ExpectedActivationId) { continue }
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $directory.FullName -Root $Paths.BackupRoot `
                -Kind Directory -Label 'Gameplay activation snapshot')
        if (-not (Test-PSOBBProtectedAcl -Path $directory.FullName)) {
            throw 'A Gameplay activation snapshot directory is not protected'
        }

        $consumedPath = Join-Path $directory.FullName 'rolled-back.json'
        $consumedTemporaryPath = Join-Path $directory.FullName `
            '.rolled-back.next'
        $consumed = Test-Path -LiteralPath $consumedPath -PathType Leaf
        $consumedTemporary = Test-Path -LiteralPath $consumedTemporaryPath `
            -PathType Leaf
        if ($consumed -and $consumedTemporary) {
            throw 'A Gameplay activation snapshot has two rollback markers'
        }
        if ($consumedTemporary -and -not $AllowConsumed) {
            throw 'A Gameplay activation snapshot has an interrupted rollback marker'
        }
        $expectedNames = @(
            'PSOBB.Gameplay.asi', 'PSOBB.Gameplay.ini', 'activation.json',
            'candidate-client-binding.json', 'candidate-installation.json',
            'dinput8.dll', 'original-client-binding.json',
            'original-installation.json',
            'replaced-original-client-binding.json',
            'replaced-original-installation.json')
        if ($consumed) { $expectedNames += 'rolled-back.json' }
        if ($consumedTemporary) { $expectedNames += '.rolled-back.next' }
        $entries = @(Get-ChildItem -Force -LiteralPath $directory.FullName)
        if (@($entries | Where-Object { $_.PSIsContainer }).Count -ne 0 -or
            [string]::Join("`n", @($entries.Name | Sort-Object)) -cne
                [string]::Join("`n", @($expectedNames | Sort-Object))) {
            throw 'A Gameplay activation snapshot has an unexpected inventory'
        }

        $manifestPath = Join-Path $directory.FullName 'activation.json'
        $manifestItem = Get-Item -Force -LiteralPath $manifestPath `
            -ErrorAction Stop
        if ([string]$manifestItem.LinkType -ceq 'HardLink' -or
            -not (Test-PSOBBProtectedAcl -Path $manifestPath)) {
            throw 'A Gameplay activation manifest is hard-linked or unprotected'
        }
        $manifest = Read-GameplayStrictJsonWithBytes `
            -Path $manifestPath -Root $directory.FullName `
            -Label 'Gameplay activation snapshot manifest'
        $originalBinding = $null
        $originalInstallation = $null
        $candidateBinding = $null
        $candidateInstallation = $null
        try {
            [void](Assert-PSOBBStrictDataObjectProperties `
                    -Value $manifest.Value -Expected $manifestProperties `
                    -Label 'Gameplay activation snapshot manifest')
            $createdAt = [DateTimeOffset]::MinValue
            if ($manifest.Value.schemaVersion -isnot [long] -or
                [long]$manifest.Value.schemaVersion -ne 1 -or
                $manifest.Value.runtimeInstallationId -isnot [string] -or
                [string]$manifest.Value.runtimeInstallationId -cne
                    $RuntimeInstallationId -or
                $manifest.Value.transactionId -isnot [string] -or
                [string]$manifest.Value.transactionId -cnotmatch
                    '^[a-f0-9]{32}$' -or
                $manifest.Value.activationId -isnot [string] -or
                [string]$manifest.Value.activationId -cne $directory.Name -or
                $manifest.Value.action -isnot [string] -or
                [string]$manifest.Value.action -cne 'Activate' -or
                $manifest.Value.createdAtUtc -isnot [string] -or
                -not [DateTimeOffset]::TryParse(
                    [string]$manifest.Value.createdAtUtc, [ref]$createdAt) -or
                $manifest.Value.pluginsDirectoryExisted -isnot [bool]) {
                throw 'A Gameplay activation snapshot manifest has an invalid identity'
            }
            foreach ($definition in $artifactDefinitions) {
                if ($manifest.Value.($definition.Size) -isnot [long] -or
                    [long]$manifest.Value.($definition.Size) -lt 1 -or
                    $manifest.Value.($definition.Sha256) -isnot [string] -or
                    [string]$manifest.Value.($definition.Sha256) -cnotmatch
                        '^[a-f0-9]{64}$') {
                    throw 'A Gameplay activation snapshot manifest has an invalid artifact identity'
                }
                Assert-GameplaySnapshotArtifact `
                    -Path (Join-Path $directory.FullName $definition.Name) `
                    -Root $directory.FullName `
                    -ExpectedLength ([long]$manifest.Value.($definition.Size)) `
                    -ExpectedSha256 ([string]$manifest.Value.($definition.Sha256)) `
                    -Label "Gameplay activation artifact $($definition.Name)"
            }
            Assert-GameplaySnapshotArtifact `
                -Path (Join-Path $directory.FullName `
                    'replaced-original-client-binding.json') `
                -Root $directory.FullName `
                -ExpectedLength ([long]$manifest.Value.originalBindingSize) `
                -ExpectedSha256 ([string]$manifest.Value.originalBindingSha256) `
                -Label 'Gameplay displaced original binding'
            Assert-GameplaySnapshotArtifact `
                -Path (Join-Path $directory.FullName `
                    'replaced-original-installation.json') `
                -Root $directory.FullName `
                -ExpectedLength ([long]$manifest.Value.originalInstallationSize) `
                -ExpectedSha256 ([string]$manifest.Value.originalInstallationSha256) `
                -Label 'Gameplay displaced original installation'
            if ([long]$manifest.Value.loaderSize -ne [long]$Authority.LoaderSize -or
                [string]$manifest.Value.loaderSha256 -cne
                    [string]$Authority.LoaderSha256 -or
                [long]$manifest.Value.moduleSize -ne [long]$Authority.ModuleSize -or
                [string]$manifest.Value.moduleSha256 -cne
                    [string]$Authority.ModuleSha256 -or
                [long]$manifest.Value.configurationSize -ne
                    [long]$ConfigurationIdentity.Size -or
                [string]$manifest.Value.configurationSha256 -cne
                    [string]$ConfigurationIdentity.Sha256) {
                throw 'A Gameplay activation snapshot differs from tracked authorities'
            }

            $originalBinding = Read-GameplayStrictJsonWithBytes `
                -Path (Join-Path $directory.FullName 'original-client-binding.json') `
                -Root $directory.FullName -Label 'Gameplay original binding snapshot'
            $originalInstallation = Read-GameplayStrictJsonWithBytes `
                -Path (Join-Path $directory.FullName 'original-installation.json') `
                -Root $directory.FullName -Label 'Gameplay original installation snapshot'
            $candidateBinding = Read-GameplayStrictJsonWithBytes `
                -Path (Join-Path $directory.FullName 'candidate-client-binding.json') `
                -Root $directory.FullName -Label 'Gameplay candidate binding snapshot'
            $candidateInstallation = Read-GameplayStrictJsonWithBytes `
                -Path (Join-Path $directory.FullName 'candidate-installation.json') `
                -Root $directory.FullName -Label 'Gameplay candidate installation snapshot'
            Assert-GameplayInstallationRecordShape `
                -Installation $originalInstallation.Value `
                -Label 'Gameplay original installation snapshot'
            Assert-GameplayInstallationRecordShape `
                -Installation $candidateInstallation.Value `
                -Label 'Gameplay candidate installation snapshot'
            Assert-GameplayBaselineBinding -Binding $originalBinding `
                -Installation $originalInstallation -Paths $Paths `
                -SkipOverlayFileCheck
            Assert-GameplayActiveBinding -Binding $candidateBinding `
                -Installation $candidateInstallation `
                -CombatLayout $CombatLayout -Authority $Authority `
                -SkipOverlayFileCheck

            $expectedBindingBytes = New-GameplayBindingBytes `
                -BaselineBinding $originalBinding.Value -Authority $Authority `
                -ConfigurationIdentity $ConfigurationIdentity
            $expectedInstallationBytes = $null
            try {
                $expectedBinding = Get-GameplayBytesDigest -Bytes $expectedBindingBytes
                if ([long]$expectedBinding.Length -ne [long]$candidateBinding.Length -or
                    [string]$expectedBinding.Sha256 -cne
                        [string]$candidateBinding.Sha256) {
                    throw 'A Gameplay activation snapshot candidate binding is not deterministic'
                }
                $expectedInstallationBytes = New-GameplayInstallationBytes `
                    -Installation $originalInstallation.Value `
                    -ClientBindingSha256 $candidateBinding.Sha256
                $expectedInstallation = Get-GameplayBytesDigest `
                    -Bytes $expectedInstallationBytes
                if ([long]$expectedInstallation.Length -ne
                        [long]$candidateInstallation.Length -or
                    [string]$expectedInstallation.Sha256 -cne
                        [string]$candidateInstallation.Sha256) {
                    throw 'A Gameplay activation snapshot candidate installation is not deterministic'
                }
            } finally {
                if ($expectedBindingBytes) {
                    [Array]::Clear($expectedBindingBytes, 0, $expectedBindingBytes.Length)
                }
                if ($expectedInstallationBytes) {
                    [Array]::Clear(
                        $expectedInstallationBytes, 0,
                        $expectedInstallationBytes.Length)
                }
            }
            if ([long]$manifest.Value.activeBindingSize -ne
                    [long]$candidateBinding.Length -or
                [string]$manifest.Value.activeBindingSha256 -cne
                    [string]$candidateBinding.Sha256 -or
                [string]$manifest.Value.candidateBindingSha256 -cne
                    [string]$candidateBinding.Sha256 -or
                [string]$manifest.Value.candidateInstallationSha256 -cne
                    [string]$candidateInstallation.Sha256) {
                throw 'A Gameplay activation snapshot manifest is not bound to its candidates'
            }

            $rollbackMarkerIdentity = $null
            if ($consumed -or $consumedTemporary) {
                $rollbackMarkerPath = if ($consumed) {
                    $consumedPath
                } else { $consumedTemporaryPath }
                $consumedItem = Get-Item -Force -LiteralPath $rollbackMarkerPath `
                    -ErrorAction Stop
                if ([string]$consumedItem.LinkType -ceq 'HardLink' -or
                    -not (Test-PSOBBProtectedAcl -Path $rollbackMarkerPath)) {
                    throw 'A Gameplay rollback marker is hard-linked or unprotected'
                }
                $consumedSnapshot = Read-GameplayStrictJsonWithBytes `
                    -Path $rollbackMarkerPath -Root $directory.FullName `
                    -Label 'Gameplay rollback marker'
                try {
                    [void](Assert-PSOBBStrictDataObjectProperties `
                            -Value $consumedSnapshot.Value `
                            -Expected @('schemaVersion', 'activationId',
                                'rolledBackAtUtc', 'baselineBindingSha256') `
                            -Label 'Gameplay rollback marker')
                    $rolledBackAt = [DateTimeOffset]::MinValue
                    if ($consumedSnapshot.Value.schemaVersion -isnot [long] -or
                        [long]$consumedSnapshot.Value.schemaVersion -ne 1 -or
                        $consumedSnapshot.Value.activationId -isnot [string] -or
                        [string]$consumedSnapshot.Value.activationId -cne
                            $directory.Name -or
                        $consumedSnapshot.Value.rolledBackAtUtc -isnot [string] -or
                        -not [DateTimeOffset]::TryParse(
                            [string]$consumedSnapshot.Value.rolledBackAtUtc,
                            [ref]$rolledBackAt) -or
                        $consumedSnapshot.Value.baselineBindingSha256 -isnot [string] -or
                        [string]$consumedSnapshot.Value.baselineBindingSha256 -cne
                            [string]$originalBinding.Sha256) {
                        throw 'A Gameplay rollback marker has an invalid identity'
                    }
                    $rollbackMarkerIdentity = [pscustomobject]@{
                        Path = $rollbackMarkerPath
                        Length = [long]$consumedSnapshot.Length
                        Sha256 = [string]$consumedSnapshot.Sha256
                        Temporary = [bool]$consumedTemporary
                    }
                } finally {
                    if ($consumedSnapshot.Bytes) {
                        [Array]::Clear(
                            $consumedSnapshot.Bytes, 0,
                            $consumedSnapshot.Bytes.Length)
                    }
                }
                if ($consumed -and -not $AllowConsumed) { continue }
            }

            if ([string]$candidateBinding.Sha256 -ceq $CurrentBindingSha256) {
                $snapshotMatches.Add([pscustomobject]@{
                        Root = $directory.FullName
                        Manifest = $manifest.Value
                        OriginalBinding = $originalBinding
                        RollbackMarker = $rollbackMarkerIdentity
                    })
                $originalBinding = $null
            }
        } finally {
            foreach ($snapshot in @(
                    $manifest, $originalBinding, $originalInstallation,
                    $candidateBinding, $candidateInstallation)) {
                if ($snapshot -and $snapshot.Bytes) {
                    [Array]::Clear($snapshot.Bytes, 0, $snapshot.Bytes.Length)
                }
            }
        }
    }
    if ($snapshotMatches.Count -ne 1) {
        foreach ($match in $snapshotMatches) {
            if ($match.OriginalBinding.Bytes) {
                [Array]::Clear(
                    $match.OriginalBinding.Bytes, 0,
                    $match.OriginalBinding.Bytes.Length)
            }
        }
        $kind = if ($AllowConsumed) { 'matching' } else { 'unconsumed' }
        throw "Gameplay rollback requires exactly one authenticated $kind activation snapshot"
    }
    $snapshotMatches[0]
}

function Write-GameplayRollbackMarker {
    param(
        [Parameter(Mandatory)][string]$ActivationRoot,
        [Parameter(Mandatory)][string]$ActivationId,
        [Parameter(Mandatory)][string]$BaselineBindingSha256
    )

    $markerPath = Join-Path $ActivationRoot 'rolled-back.json'
    $temporaryPath = Join-Path $ActivationRoot '.rolled-back.next'
    if (Test-Path -LiteralPath $markerPath) {
        throw 'The Gameplay activation snapshot is already marked as rolled back'
    }
    if (Test-Path -LiteralPath $temporaryPath) {
        throw 'A Gameplay rollback-marker temporary already exists'
    }
    $bytes = ConvertTo-GameplayJsonBytes ([ordered]@{
        schemaVersion = 1
        activationId = $ActivationId
        rolledBackAtUtc = [DateTime]::UtcNow.ToString('o')
        baselineBindingSha256 = $BaselineBindingSha256
    })
    $identity = Get-GameplayBytesDigest -Bytes $bytes
    $temporaryCreated = $false
    try {
        $temporaryCreated = $true
        [void](Write-GameplayProtectedArtifact -Path $temporaryPath `
                -Root $ActivationRoot -Bytes $bytes)
        Invoke-GameplayHardExit -Point 'after-rollback-marker-staging'
        [System.IO.File]::Move($temporaryPath, $markerPath, $false)
        [pscustomobject]@{
            Path = $markerPath
            Length = [long]$identity.Length
            Sha256 = [string]$identity.Sha256
        }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        if ($temporaryCreated -and (Test-Path -LiteralPath $temporaryPath)) {
            Remove-GameplayExactFile -Path $temporaryPath `
                -Root $ActivationRoot -ExpectedLength $identity.Length `
                -ExpectedSha256 $identity.Sha256 `
                -Label 'Gameplay rollback-marker staging cleanup'
        }
    }
}

function Complete-GameplayRollbackMarker {
    param(
        [Parameter(Mandatory)]$Activation,
        [Parameter(Mandatory)][string]$ActivationId,
        [Parameter(Mandatory)][string]$BaselineBindingSha256
    )

    $markerPath = Join-Path $Activation.Root 'rolled-back.json'
    $temporaryPath = Join-Path $Activation.Root '.rolled-back.next'
    if (Test-Path -LiteralPath $markerPath) {
        if ($Activation.RollbackMarker -and
            -not [bool]$Activation.RollbackMarker.Temporary) {
            Assert-GameplaySnapshotArtifact -Path $markerPath `
                -Root $Activation.Root `
                -ExpectedLength $Activation.RollbackMarker.Length `
                -ExpectedSha256 $Activation.RollbackMarker.Sha256 `
                -Label 'Gameplay completed rollback marker'
            return $Activation.RollbackMarker
        }
        throw 'The Gameplay rollback marker appeared after authentication'
    }
    if (Test-Path -LiteralPath $temporaryPath) {
        if (-not $Activation.RollbackMarker -or
            -not [bool]$Activation.RollbackMarker.Temporary) {
            throw 'An unauthenticated Gameplay rollback-marker temporary appeared'
        }
        Assert-GameplaySnapshotArtifact -Path $temporaryPath `
            -Root $Activation.Root `
            -ExpectedLength $Activation.RollbackMarker.Length `
            -ExpectedSha256 $Activation.RollbackMarker.Sha256 `
            -Label 'Gameplay interrupted rollback marker'
        [System.IO.File]::Move($temporaryPath, $markerPath, $false)
        Assert-GameplaySnapshotArtifact -Path $markerPath `
            -Root $Activation.Root `
            -ExpectedLength $Activation.RollbackMarker.Length `
            -ExpectedSha256 $Activation.RollbackMarker.Sha256 `
            -Label 'Gameplay completed rollback marker'
        return [pscustomobject]@{
            Path = $markerPath
            Length = [long]$Activation.RollbackMarker.Length
            Sha256 = [string]$Activation.RollbackMarker.Sha256
            Temporary = $false
        }
    }
    Write-GameplayRollbackMarker -ActivationRoot $Activation.Root `
        -ActivationId $ActivationId `
        -BaselineBindingSha256 $BaselineBindingSha256
}

function Restore-GameplayOriginalState {
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)][string]$TransactionRoot,
        [Parameter(Mandatory)]$Original,
        [Parameter(Mandatory)][bool]$PluginsExisted,
        [Parameter(Mandatory)][bool]$OriginalOverlayPresent
    )

    if ($OriginalOverlayPresent) {
        if (-not (Test-Path -LiteralPath $Paths.Plugins -PathType Container)) {
            [void](Initialize-GameplayOrdinaryDirectory -Path $Paths.Plugins `
                    -Root $CombatLayout.EnvironmentRoot `
                    -Label 'Gameplay compensated plugins directory')
        }
        foreach ($definition in @(
                [pscustomobject]@{
                    Source = Join-Path $TransactionRoot 'dinput8.dll'
                    Destination = $Paths.Loader
                    Temporary = $Paths.LoaderTemporary; Identity = $Original.Loader
                    Displaced = Join-Path $TransactionRoot 'compensated-dinput8.dll'
                },
                [pscustomobject]@{
                    Source = Join-Path $TransactionRoot 'PSOBB.Gameplay.asi'
                    Destination = $Paths.Module
                    Temporary = $Paths.ModuleTemporary; Identity = $Original.Module
                    Displaced = Join-Path $TransactionRoot `
                        'compensated-PSOBB.Gameplay.asi'
                },
                [pscustomobject]@{
                    Source = Join-Path $TransactionRoot 'PSOBB.Gameplay.ini'
                    Destination = $Paths.Configuration
                    Temporary = $Paths.ConfigurationTemporary
                    Identity = $Original.Configuration
                    Displaced = Join-Path $TransactionRoot `
                        'compensated-PSOBB.Gameplay.ini'
                })) {
            Install-GameplayArtifact `
                -Source $definition.Source -TransactionRoot $TransactionRoot `
                -Destination $definition.Destination `
                -DestinationRoot $CombatLayout.EnvironmentRoot `
                -Temporary $definition.Temporary `
                -ExpectedLength ([long]$definition.Identity.Length) `
                -ExpectedSha256 ([string]$definition.Identity.Sha256) `
                -AllowedDestinationIdentities @($definition.Identity) `
                -AllowAbsentDestination -Displaced $definition.Displaced
        }
    } else {
        foreach ($definition in @(
                [pscustomobject]@{
                    Path = $Paths.Configuration; Identity = $Original.AfterConfiguration
                    Label = 'Gameplay configuration'
                },
                [pscustomobject]@{
                    Path = $Paths.Module; Identity = $Original.AfterModule
                    Label = 'Gameplay module'
                },
                [pscustomobject]@{
                    Path = $Paths.Loader; Identity = $Original.AfterLoader
                    Label = 'Gameplay loader'
                })) {
            if ($definition.Identity -and
                (Test-Path -LiteralPath $definition.Path)) {
                Remove-GameplayExactFile -Path $definition.Path `
                    -Root $CombatLayout.EnvironmentRoot `
                    -ExpectedLength ([long]$definition.Identity.Length) `
                    -ExpectedSha256 ([string]$definition.Identity.Sha256) `
                    -Label $definition.Label -RequirePresent
            }
        }
    }

    Install-GameplayArtifact `
        -Source (Join-Path $TransactionRoot 'original-client-binding.json') `
        -TransactionRoot $TransactionRoot -Destination $Paths.Binding `
        -DestinationRoot $CombatLayout.EnvironmentRoot `
        -Temporary $Paths.BindingTemporary `
        -ExpectedLength ([long]$Original.Binding.Length) `
        -ExpectedSha256 ([string]$Original.Binding.Sha256) `
        -AllowedDestinationIdentities @(
            $Original.Binding, $Original.AfterBinding) `
        -AllowAbsentDestination `
        -Displaced (Join-Path $TransactionRoot `
            'compensated-client-binding.json') -Protect
    Install-GameplayArtifact `
        -Source (Join-Path $TransactionRoot 'original-installation.json') `
        -TransactionRoot $TransactionRoot -Destination $Paths.Installation `
        -DestinationRoot $CombatLayout.EnvironmentRoot `
        -Temporary $Paths.InstallationTemporary `
        -ExpectedLength ([long]$Original.Installation.Length) `
        -ExpectedSha256 ([string]$Original.Installation.Sha256) `
        -AllowedDestinationIdentities @(
            $Original.Installation, $Original.AfterInstallation) `
        -AllowAbsentDestination `
        -Displaced (Join-Path $TransactionRoot `
            'compensated-installation.json') -Protect

    if (-not $PluginsExisted) {
        Remove-GameplayEmptyDirectory -Path $Paths.Plugins `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay compensated plugins directory'
    }
}

function Get-GameplayIdentityState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        $PreIdentity,
        $PostIdentity,
        [switch]$PreAbsent,
        [switch]$PostAbsent,
        [switch]$RequireProtected,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PreAbsent -and -not $PostAbsent) { return 'Pre' }
        if ($PostAbsent -and -not $PreAbsent) { return 'Post' }
        return 'Unknown'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Path -Root $Root -Kind File -Label $Label)
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if ([string]$item.LinkType -ceq 'HardLink' -or
        ($RequireProtected -and -not (Test-PSOBBProtectedAcl -Path $Path))) {
        return 'Unknown'
    }
    $actual = Get-GameplayDigest -Path $Path -Root $Root -Label $Label
    if (-not $PreAbsent -and $PreIdentity -and
        [long]$actual.Length -eq [long]$PreIdentity.Length -and
        [string]$actual.Sha256 -ceq [string]$PreIdentity.Sha256) {
        return 'Pre'
    }
    if (-not $PostAbsent -and $PostIdentity -and
        [long]$actual.Length -eq [long]$PostIdentity.Length -and
        [string]$actual.Sha256 -ceq [string]$PostIdentity.Sha256) {
        return 'Post'
    }
    'Unknown'
}

function Read-GameplayInterruptedTransaction {
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$ConfigurationIdentity,
        [Parameter(Mandatory)][string]$RuntimeInstallationId
    )

    $root = $Paths.Transaction
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $root -Root $CombatLayout.EnvironmentRoot -Kind Directory `
            -Label 'Gameplay interrupted transaction')
    if (-not (Test-PSOBBProtectedAcl -Path $root)) {
        throw 'The interrupted Gameplay transaction root is not protected'
    }
    $requiredNames = @(
        'PSOBB.Gameplay.asi', 'PSOBB.Gameplay.ini', 'activation.json',
        'candidate-client-binding.json', 'candidate-installation.json',
        'dinput8.dll', 'original-client-binding.json',
        'original-installation.json')
    $optionalNames = @(
        'replaced-original-client-binding.json',
        'replaced-original-installation.json',
        'compensated-client-binding.json', 'compensated-installation.json',
        'recovery-displaced-client-binding.json',
        'recovery-displaced-installation.json')
    $entries = @(Get-ChildItem -Force -LiteralPath $root)
    $names = @($entries.Name)
    if (@($entries | Where-Object { $_.PSIsContainer }).Count -ne 0 -or
        @($requiredNames | Where-Object { $_ -cnotin $names }).Count -ne 0 -or
        @($names | Where-Object {
                $_ -cnotin $requiredNames -and $_ -cnotin $optionalNames
            }).Count -ne 0) {
        throw 'The interrupted Gameplay transaction has an unexpected inventory'
    }

    $manifestPath = Join-Path $root 'activation.json'
    $manifestItem = Get-Item -Force -LiteralPath $manifestPath
    if ([string]$manifestItem.LinkType -ceq 'HardLink' -or
        -not (Test-PSOBBProtectedAcl -Path $manifestPath)) {
        throw 'The interrupted Gameplay manifest is hard-linked or unprotected'
    }
    $manifest = Read-GameplayStrictJsonWithBytes -Path $manifestPath `
        -Root $root -Label 'interrupted Gameplay manifest'
    $originalBinding = $null
    $originalInstallation = $null
    $candidateBinding = $null
    $candidateInstallation = $null
    $activation = $null
    try {
        $properties = @(
            'schemaVersion', 'runtimeInstallationId', 'transactionId',
            'activationId', 'action', 'createdAtUtc',
            'pluginsDirectoryExisted', 'originalBindingSize',
            'originalBindingSha256', 'originalInstallationSize',
            'originalInstallationSha256', 'activeBindingSize',
            'activeBindingSha256', 'candidateBindingSize',
            'candidateBindingSha256', 'candidateInstallationSize',
            'candidateInstallationSha256', 'loaderSize', 'loaderSha256',
            'moduleSize', 'moduleSha256', 'configurationSize',
            'configurationSha256')
        [void](Assert-PSOBBStrictDataObjectProperties `
                -Value $manifest.Value -Expected $properties `
                -Label 'interrupted Gameplay manifest')
        $createdAt = [DateTimeOffset]::MinValue
        if ($manifest.Value.schemaVersion -isnot [long] -or
            [long]$manifest.Value.schemaVersion -ne 1 -or
            $manifest.Value.runtimeInstallationId -isnot [string] -or
            [string]$manifest.Value.runtimeInstallationId -cne
                $RuntimeInstallationId -or
            $manifest.Value.transactionId -isnot [string] -or
            [string]$manifest.Value.transactionId -cnotmatch '^[a-f0-9]{32}$' -or
            $manifest.Value.activationId -isnot [string] -or
            [string]$manifest.Value.activationId -cnotmatch
                '^gameplay-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$' -or
            $manifest.Value.action -isnot [string] -or
            [string]$manifest.Value.action -notin @('Activate', 'Rollback') -or
            $manifest.Value.createdAtUtc -isnot [string] -or
            -not [DateTimeOffset]::TryParse(
                [string]$manifest.Value.createdAtUtc, [ref]$createdAt) -or
            $manifest.Value.pluginsDirectoryExisted -isnot [bool]) {
            throw 'The interrupted Gameplay manifest has an invalid identity'
        }
        $definitions = @(
            [pscustomobject]@{
                Name = 'original-client-binding.json'; Size = 'originalBindingSize'
                Sha = 'originalBindingSha256'
            },
            [pscustomobject]@{
                Name = 'original-installation.json'; Size = 'originalInstallationSize'
                Sha = 'originalInstallationSha256'
            },
            [pscustomobject]@{
                Name = 'candidate-client-binding.json'; Size = 'candidateBindingSize'
                Sha = 'candidateBindingSha256'
            },
            [pscustomobject]@{
                Name = 'candidate-installation.json'; Size = 'candidateInstallationSize'
                Sha = 'candidateInstallationSha256'
            },
            [pscustomobject]@{
                Name = 'dinput8.dll'; Size = 'loaderSize'; Sha = 'loaderSha256'
            },
            [pscustomobject]@{
                Name = 'PSOBB.Gameplay.asi'; Size = 'moduleSize'; Sha = 'moduleSha256'
            },
            [pscustomobject]@{
                Name = 'PSOBB.Gameplay.ini'; Size = 'configurationSize'
                Sha = 'configurationSha256'
            })
        foreach ($definition in $definitions) {
            if ($manifest.Value.($definition.Size) -isnot [long] -or
                [long]$manifest.Value.($definition.Size) -lt 1 -or
                $manifest.Value.($definition.Sha) -isnot [string] -or
                [string]$manifest.Value.($definition.Sha) -cnotmatch
                    '^[a-f0-9]{64}$') {
                throw 'The interrupted Gameplay manifest has an invalid artifact identity'
            }
            Assert-GameplaySnapshotArtifact `
                -Path (Join-Path $root $definition.Name) -Root $root `
                -ExpectedLength ([long]$manifest.Value.($definition.Size)) `
                -ExpectedSha256 ([string]$manifest.Value.($definition.Sha)) `
                -Label "interrupted Gameplay artifact $($definition.Name)"
        }
        if ([long]$manifest.Value.loaderSize -ne [long]$Authority.LoaderSize -or
            [string]$manifest.Value.loaderSha256 -cne
                [string]$Authority.LoaderSha256 -or
            [long]$manifest.Value.moduleSize -ne [long]$Authority.ModuleSize -or
            [string]$manifest.Value.moduleSha256 -cne
                [string]$Authority.ModuleSha256 -or
            [long]$manifest.Value.configurationSize -ne
                [long]$ConfigurationIdentity.Size -or
            [string]$manifest.Value.configurationSha256 -cne
                [string]$ConfigurationIdentity.Sha256) {
            throw 'The interrupted Gameplay transaction differs from tracked authorities'
        }

        $originalBinding = Read-GameplayStrictJsonWithBytes `
            -Path (Join-Path $root 'original-client-binding.json') `
            -Root $root -Label 'interrupted Gameplay original binding'
        $originalInstallation = Read-GameplayStrictJsonWithBytes `
            -Path (Join-Path $root 'original-installation.json') `
            -Root $root -Label 'interrupted Gameplay original installation'
        $candidateBinding = Read-GameplayStrictJsonWithBytes `
            -Path (Join-Path $root 'candidate-client-binding.json') `
            -Root $root -Label 'interrupted Gameplay candidate binding'
        $candidateInstallation = Read-GameplayStrictJsonWithBytes `
            -Path (Join-Path $root 'candidate-installation.json') `
            -Root $root -Label 'interrupted Gameplay candidate installation'
        Assert-GameplayInstallationRecordShape `
            -Installation $originalInstallation.Value `
            -Label 'interrupted Gameplay original installation'
        Assert-GameplayInstallationRecordShape `
            -Installation $candidateInstallation.Value `
            -Label 'interrupted Gameplay candidate installation'

        $expectedBindingBytes = $null
        $expectedInstallationBytes = $null
        try {
            if ([string]$manifest.Value.action -ceq 'Activate') {
                Assert-GameplayBaselineBinding -Binding $originalBinding `
                    -Installation $originalInstallation -Paths $Paths `
                    -SkipOverlayFileCheck
                Assert-GameplayActiveBinding -Binding $candidateBinding `
                    -Installation $candidateInstallation `
                    -CombatLayout $CombatLayout -Authority $Authority `
                    -SkipOverlayFileCheck
                $expectedBindingBytes = New-GameplayBindingBytes `
                    -BaselineBinding $originalBinding.Value -Authority $Authority `
                    -ConfigurationIdentity $ConfigurationIdentity
            } else {
                Assert-GameplayActiveBinding -Binding $originalBinding `
                    -Installation $originalInstallation `
                    -CombatLayout $CombatLayout -Authority $Authority `
                    -SkipOverlayFileCheck
                Assert-GameplayBaselineBinding -Binding $candidateBinding `
                    -Installation $candidateInstallation -Paths $Paths `
                    -SkipOverlayFileCheck
                $activation = Find-GameplayActivationSnapshot `
                    -Paths $Paths `
                    -CurrentBindingSha256 $originalBinding.Sha256 `
                    -CombatLayout $CombatLayout -Authority $Authority `
                    -ConfigurationIdentity $ConfigurationIdentity `
                    -RuntimeInstallationId $RuntimeInstallationId `
                    -AllowConsumed `
                    -ExpectedActivationId ([string]$manifest.Value.activationId)
                if ([long]$activation.OriginalBinding.Length -ne
                        [long]$candidateBinding.Length -or
                    [string]$activation.OriginalBinding.Sha256 -cne
                        [string]$candidateBinding.Sha256) {
                    throw 'The interrupted rollback is not bound to its activation snapshot'
                }
                $expectedBindingBytes = [byte[]]$activation.OriginalBinding.Bytes
                $activation.OriginalBinding.Bytes = $null
            }
            $expectedBinding = Get-GameplayBytesDigest -Bytes $expectedBindingBytes
            if ([long]$expectedBinding.Length -ne [long]$candidateBinding.Length -or
                [string]$expectedBinding.Sha256 -cne
                    [string]$candidateBinding.Sha256) {
                throw 'The interrupted Gameplay candidate binding is not deterministic'
            }
            $expectedInstallationBytes = New-GameplayInstallationBytes `
                -Installation $originalInstallation.Value `
                -ClientBindingSha256 $candidateBinding.Sha256
            $expectedInstallation = Get-GameplayBytesDigest `
                -Bytes $expectedInstallationBytes
            if ([long]$expectedInstallation.Length -ne
                    [long]$candidateInstallation.Length -or
                [string]$expectedInstallation.Sha256 -cne
                    [string]$candidateInstallation.Sha256) {
                throw 'The interrupted Gameplay candidate installation is not deterministic'
            }
        } finally {
            if ($expectedBindingBytes) {
                [Array]::Clear($expectedBindingBytes, 0, $expectedBindingBytes.Length)
            }
            if ($expectedInstallationBytes) {
                [Array]::Clear(
                    $expectedInstallationBytes, 0,
                    $expectedInstallationBytes.Length)
            }
        }

        $expectedActiveBinding = if (
            [string]$manifest.Value.action -ceq 'Activate') {
            $candidateBinding
        } else { $originalBinding }
        if ([long]$manifest.Value.activeBindingSize -ne
                [long]$expectedActiveBinding.Length -or
            [string]$manifest.Value.activeBindingSha256 -cne
                [string]$expectedActiveBinding.Sha256) {
            throw 'The interrupted Gameplay active binding identity is invalid'
        }

        $optionalDefinitions = @(
            [pscustomobject]@{
                Name = 'replaced-original-client-binding.json'
                Identity = $originalBinding
            },
            [pscustomobject]@{
                Name = 'replaced-original-installation.json'
                Identity = $originalInstallation
            },
            [pscustomobject]@{
                Name = 'compensated-client-binding.json'
                Identity = $candidateBinding
            },
            [pscustomobject]@{
                Name = 'compensated-installation.json'
                Identity = $candidateInstallation
            },
            [pscustomobject]@{
                Name = 'recovery-displaced-client-binding.json'
                Identity = $candidateBinding
            },
            [pscustomobject]@{
                Name = 'recovery-displaced-installation.json'
                Identity = $candidateInstallation
            })
        foreach ($definition in $optionalDefinitions) {
            $path = Join-Path $root $definition.Name
            if (Test-Path -LiteralPath $path) {
                Assert-GameplaySnapshotArtifact -Path $path -Root $root `
                    -ExpectedLength $definition.Identity.Length `
                    -ExpectedSha256 $definition.Identity.Sha256 `
                    -Label "interrupted Gameplay displacement $($definition.Name)"
            }
        }

        [pscustomobject]@{
            Kind = 'Transaction'
            Root = $root
            Action = [string]$manifest.Value.action
            ActivationId = [string]$manifest.Value.activationId
            ActivationRoot = if ($activation) { $activation.Root } else { $null }
            ActivationPluginsDirectoryExisted = if ($activation) {
                [bool]$activation.Manifest.pluginsDirectoryExisted
            } else { $null }
            RollbackMarker = if ($activation) {
                $activation.RollbackMarker
            } else { $null }
            PluginsDirectoryExisted =
                [bool]$manifest.Value.pluginsDirectoryExisted
            OriginalBinding = [pscustomobject]@{
                Length = $originalBinding.Length; Sha256 = $originalBinding.Sha256
            }
            OriginalInstallation = [pscustomobject]@{
                Length = $originalInstallation.Length
                Sha256 = $originalInstallation.Sha256
            }
            CandidateBinding = [pscustomobject]@{
                Length = $candidateBinding.Length; Sha256 = $candidateBinding.Sha256
            }
            CandidateInstallation = [pscustomobject]@{
                Length = $candidateInstallation.Length
                Sha256 = $candidateInstallation.Sha256
            }
            Loader = [pscustomobject]@{
                Length = [long]$manifest.Value.loaderSize
                Sha256 = [string]$manifest.Value.loaderSha256
            }
            Module = [pscustomobject]@{
                Length = [long]$manifest.Value.moduleSize
                Sha256 = [string]$manifest.Value.moduleSha256
            }
            Configuration = [pscustomobject]@{
                Length = [long]$manifest.Value.configurationSize
                Sha256 = [string]$manifest.Value.configurationSha256
            }
        }
    } finally {
        foreach ($snapshot in @(
                $manifest, $originalBinding, $originalInstallation,
                $candidateBinding, $candidateInstallation)) {
            if ($snapshot -and $snapshot.Bytes) {
                [Array]::Clear($snapshot.Bytes, 0, $snapshot.Bytes.Length)
            }
        }
        if ($activation -and $activation.OriginalBinding.Bytes) {
            [Array]::Clear(
                $activation.OriginalBinding.Bytes, 0,
                $activation.OriginalBinding.Bytes.Length)
        }
    }
}

function Get-GameplayInterruptedPlan {
    param(
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$ConfigurationIdentity,
        [Parameter(Mandatory)][string]$RuntimeInstallationId
    )

    $hasTransaction = Test-Path -LiteralPath $Paths.Transaction
    $hasNext = Test-Path -LiteralPath $Paths.TransactionNext
    $temporaryPaths = @(
        $Paths.LoaderTemporary, $Paths.ModuleTemporary,
        $Paths.ConfigurationTemporary, $Paths.BindingTemporary,
        $Paths.InstallationTemporary)
    $presentTemporaries = @($temporaryPaths | Where-Object {
            Test-Path -LiteralPath $_
        })
    if ($hasTransaction -and $hasNext) {
        throw 'Both Gameplay transaction roots exist; preserve them for manual inspection'
    }
    if (-not $hasTransaction -and -not $hasNext -and
        $presentTemporaries.Count -ne 0) {
        throw 'An orphaned Gameplay staging file exists without an authenticated transaction'
    }
    if ($hasNext) {
        if ($presentTemporaries.Count -ne 0) {
            throw 'Gameplay preparation and live staging debris coexist unexpectedly'
        }
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $Paths.TransactionNext `
                -Root $CombatLayout.EnvironmentRoot -Kind Directory `
                -Label 'Gameplay interrupted preparation')
        if (-not (Test-PSOBBProtectedAcl -Path $Paths.TransactionNext)) {
            throw 'The interrupted Gameplay preparation root is not protected'
        }
        $order = @(
            'original-client-binding.json', 'original-installation.json',
            'candidate-client-binding.json', 'candidate-installation.json',
            'dinput8.dll', 'PSOBB.Gameplay.asi', 'PSOBB.Gameplay.ini',
            'activation.json')
        $entries = @(Get-ChildItem -Force -LiteralPath $Paths.TransactionNext)
        if (@($entries | Where-Object { $_.PSIsContainer }).Count -ne 0 -or
            $entries.Count -gt $order.Count -or
            @($entries.Name | Where-Object {
                    $_ -cnotin @($order | Select-Object -First $entries.Count)
                }).Count -ne 0 -or
            @($order | Select-Object -First $entries.Count | Where-Object {
                    $_ -cnotin $entries.Name
                }).Count -ne 0) {
            throw 'The interrupted Gameplay preparation is not an exact write prefix'
        }
        foreach ($entry in $entries) {
            [void](Assert-PSOBBOrdinaryContainedPath `
                    -Path $entry.FullName -Root $Paths.TransactionNext `
                    -Kind File -Label 'Gameplay interrupted preparation artifact')
            if ([string]$entry.LinkType -ceq 'HardLink' -or
                -not (Test-PSOBBProtectedAcl -Path $entry.FullName) -or
                $entry.Length -lt 1 -or $entry.Length -gt 16MB) {
                throw 'The interrupted Gameplay preparation contains an unsafe artifact'
            }
        }
        return [pscustomobject]@{
            Kind = 'Preparation'; Root = $Paths.TransactionNext
        }
    }
    if ($hasTransaction) {
        $transaction = Read-GameplayInterruptedTransaction `
            -Paths $Paths -CombatLayout $CombatLayout -Authority $Authority `
            -ConfigurationIdentity $ConfigurationIdentity `
            -RuntimeInstallationId $RuntimeInstallationId
        $transaction | Add-Member -NotePropertyName PresentTemporaries `
            -NotePropertyValue $presentTemporaries
        return $transaction
    }
    $null
}

function Remove-GameplayKnownTemporary {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][Parameter(Mandatory)][object[]]$Identities,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $state = Assert-GameplayDestinationState -Path $Path -Root $Root `
        -AllowedIdentities $Identities -Label $Label
    Remove-GameplayExactFile -Path $Path -Root $Root `
        -ExpectedLength $state.Length -ExpectedSha256 $state.Sha256 `
        -Label $Label -RequirePresent
}

function Invoke-GameplayInterruptedRecovery {
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Paths,
        [Parameter(Mandatory)]$CombatLayout,
        [Parameter(Mandatory)]$Authority
    )

    [void](Initialize-GameplayOrdinaryDirectory -Path $Paths.BackupRoot `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay activation backup root')
    Set-GameplayProtectedDirectoryAcl -Path $Paths.BackupRoot `
        -Root $CombatLayout.EnvironmentRoot `
        -Label 'Gameplay recovery backup root'
    [void](Assert-GameplayOrdinaryDirectory -Path $Paths.BackupRoot `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay activation backup root')
    if ($Plan.Kind -ceq 'Preparation') {
        $destination = Join-Path $Paths.BackupRoot (
            'recovered-next-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') +
            '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        [void](Assert-GameplayOrdinaryDirectory -Path $Plan.Root `
                -Root $CombatLayout.EnvironmentRoot `
                -Label 'Gameplay interrupted preparation')
        Move-GameplayOrdinaryDirectory -Source $Plan.Root `
            -Destination $destination -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay recovery preparation'
        [void](Assert-GameplayOrdinaryDirectory -Path $destination `
                -Root $CombatLayout.EnvironmentRoot `
                -Label 'Gameplay quarantined preparation')
        return [pscustomobject]@{
            Recovered = $true; Disposition = 'quarantined-preparation'
        }
    }

    $temporaryDefinitions = @(
        [pscustomobject]@{
            Path = $Paths.LoaderTemporary; Identities = @($Plan.Loader)
            Label = 'Gameplay loader staging recovery'
        },
        [pscustomobject]@{
            Path = $Paths.ModuleTemporary; Identities = @($Plan.Module)
            Label = 'Gameplay module staging recovery'
        },
        [pscustomobject]@{
            Path = $Paths.ConfigurationTemporary
            Identities = @($Plan.Configuration)
            Label = 'Gameplay configuration staging recovery'
        },
        [pscustomobject]@{
            Path = $Paths.BindingTemporary
            Identities = @($Plan.OriginalBinding, $Plan.CandidateBinding)
            Label = 'Gameplay binding staging recovery'
        },
        [pscustomobject]@{
            Path = $Paths.InstallationTemporary
            Identities = @(
                $Plan.OriginalInstallation, $Plan.CandidateInstallation)
            Label = 'Gameplay installation staging recovery'
        })
    foreach ($definition in $temporaryDefinitions) {
        Remove-GameplayKnownTemporary -Path $definition.Path `
            -Root $CombatLayout.EnvironmentRoot `
            -Identities $definition.Identities -Label $definition.Label
    }

    $activate = $Plan.Action -ceq 'Activate'
    $definitions = @(
        [pscustomobject]@{
            Name = 'loader'; Path = $Paths.Loader; Pre = $Plan.Loader
            Post = $Plan.Loader; PreAbsent = $activate; PostAbsent = -not $activate
            Protected = $false
        },
        [pscustomobject]@{
            Name = 'module'; Path = $Paths.Module; Pre = $Plan.Module
            Post = $Plan.Module; PreAbsent = $activate; PostAbsent = -not $activate
            Protected = $false
        },
        [pscustomobject]@{
            Name = 'configuration'; Path = $Paths.Configuration
            Pre = $Plan.Configuration; Post = $Plan.Configuration
            PreAbsent = $activate; PostAbsent = -not $activate
            Protected = $false
        },
        [pscustomobject]@{
            Name = 'binding'; Path = $Paths.Binding
            Pre = $Plan.OriginalBinding; Post = $Plan.CandidateBinding
            PreAbsent = $false; PostAbsent = $false; Protected = $true
        },
        [pscustomobject]@{
            Name = 'installation'; Path = $Paths.Installation
            Pre = $Plan.OriginalInstallation; Post = $Plan.CandidateInstallation
            PreAbsent = $false; PostAbsent = $false; Protected = $true
        })
    foreach ($definition in $definitions) {
        $definition | Add-Member -NotePropertyName State -NotePropertyValue (
            Get-GameplayIdentityState -Path $definition.Path `
                -Root $CombatLayout.EnvironmentRoot `
                -PreIdentity $definition.Pre -PostIdentity $definition.Post `
                -PreAbsent:$definition.PreAbsent -PostAbsent:$definition.PostAbsent `
                -RequireProtected:$definition.Protected `
                -Label "Gameplay recovery $($definition.Name)")
    }
    if (@($definitions | Where-Object State -CEQ 'Unknown').Count -ne 0) {
        throw 'An interrupted Gameplay live target has an unknown identity; evidence was preserved'
    }
    $allPost = @($definitions | Where-Object State -CNE 'Post').Count -eq 0
    if ($allPost) {
        if ($activate) {
            foreach ($name in @(
                    'replaced-original-client-binding.json',
                    'replaced-original-installation.json')) {
                if (-not (Test-Path -LiteralPath (Join-Path $Plan.Root $name))) {
                    throw 'The completed activation lacks its preserved replacement evidence'
                }
            }
            $destination = Join-Path $Paths.BackupRoot $Plan.ActivationId
            if (Test-Path -LiteralPath $destination) {
                throw 'The interrupted activation destination already exists'
            }
            Set-PSOBBProtectedTreeAcl -Path $Plan.Root `
                -Root $CombatLayout.EnvironmentRoot
            [void](Assert-GameplayOrdinaryDirectory -Path $Plan.Root `
                    -Root $CombatLayout.EnvironmentRoot `
                    -Label 'Gameplay completed activation transaction')
            Move-GameplayOrdinaryDirectory -Source $Plan.Root `
                -Destination $destination -Root $CombatLayout.EnvironmentRoot `
                -Label 'Gameplay recovered activation'
            [void](Assert-GameplayOrdinaryDirectory -Path $destination `
                    -Root $CombatLayout.EnvironmentRoot `
                    -Label 'Gameplay recovered activation snapshot')
            return [pscustomobject]@{
                Recovered = $true; Disposition = 'finalized-activation'
            }
        }
        $activationForRecovery = [pscustomobject]@{
            Root = $Plan.ActivationRoot
            RollbackMarker = $Plan.RollbackMarker
        }
        [void](Complete-GameplayRollbackMarker `
                -Activation $activationForRecovery `
                -ActivationId $Plan.ActivationId `
                -BaselineBindingSha256 $Plan.CandidateBinding.Sha256)
        if (-not [bool]$Plan.ActivationPluginsDirectoryExisted) {
            Remove-GameplayEmptyDirectory -Path $Paths.Plugins `
                -Root $CombatLayout.EnvironmentRoot `
                -Label 'Gameplay baseline plugins directory'
        }
        $destination = Join-Path $Paths.BackupRoot (
            'rollback-recovered-' +
            [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
            [Guid]::NewGuid().ToString('N').Substring(0, 8))
        Set-PSOBBProtectedTreeAcl -Path $Plan.Root `
            -Root $CombatLayout.EnvironmentRoot
        [void](Assert-GameplayOrdinaryDirectory -Path $Plan.Root `
                -Root $CombatLayout.EnvironmentRoot `
                -Label 'Gameplay completed rollback transaction')
        Move-GameplayOrdinaryDirectory -Source $Plan.Root `
            -Destination $destination -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay recovered rollback'
        [void](Assert-GameplayOrdinaryDirectory -Path $destination `
                -Root $CombatLayout.EnvironmentRoot `
                -Label 'Gameplay recovered rollback record')
        return [pscustomobject]@{
            Recovered = $true; Disposition = 'finalized-rollback'
        }
    }

    if (-not $activate -and $Plan.RollbackMarker) {
        throw 'A mixed interrupted rollback already has a completion marker'
    }
    if ($activate) {
        foreach ($definition in @(
                [pscustomobject]@{
                    Path = $Paths.Configuration; Identity = $Plan.Configuration
                    Label = 'Gameplay recovery configuration'
                },
                [pscustomobject]@{
                    Path = $Paths.Module; Identity = $Plan.Module
                    Label = 'Gameplay recovery module'
                },
                [pscustomobject]@{
                    Path = $Paths.Loader; Identity = $Plan.Loader
                    Label = 'Gameplay recovery loader'
                })) {
            if (Test-Path -LiteralPath $definition.Path) {
                Remove-GameplayExactFile -Path $definition.Path `
                    -Root $CombatLayout.EnvironmentRoot `
                    -ExpectedLength $definition.Identity.Length `
                    -ExpectedSha256 $definition.Identity.Sha256 `
                    -Label $definition.Label -RequirePresent
            }
        }
    } else {
        foreach ($definition in @(
                [pscustomobject]@{
                    Source = 'dinput8.dll'; Destination = $Paths.Loader
                    Temporary = $Paths.LoaderTemporary; Identity = $Plan.Loader
                    Displaced = 'recovery-displaced-loader.dll'
                },
                [pscustomobject]@{
                    Source = 'PSOBB.Gameplay.asi'; Destination = $Paths.Module
                    Temporary = $Paths.ModuleTemporary; Identity = $Plan.Module
                    Displaced = 'recovery-displaced-module.asi'
                },
                [pscustomobject]@{
                    Source = 'PSOBB.Gameplay.ini'
                    Destination = $Paths.Configuration
                    Temporary = $Paths.ConfigurationTemporary
                    Identity = $Plan.Configuration
                    Displaced = 'recovery-displaced-configuration.ini'
                })) {
            Install-GameplayArtifact `
                -Source (Join-Path $Plan.Root $definition.Source) `
                -TransactionRoot $Plan.Root `
                -Destination $definition.Destination `
                -DestinationRoot $CombatLayout.EnvironmentRoot `
                -Temporary $definition.Temporary `
                -ExpectedLength $definition.Identity.Length `
                -ExpectedSha256 $definition.Identity.Sha256 `
                -AllowedDestinationIdentities @($definition.Identity) `
                -AllowAbsentDestination `
                -Displaced (Join-Path $Plan.Root $definition.Displaced)
        }
    }
    Install-GameplayArtifact `
        -Source (Join-Path $Plan.Root 'original-client-binding.json') `
        -TransactionRoot $Plan.Root -Destination $Paths.Binding `
        -DestinationRoot $CombatLayout.EnvironmentRoot `
        -Temporary $Paths.BindingTemporary `
        -ExpectedLength $Plan.OriginalBinding.Length `
        -ExpectedSha256 $Plan.OriginalBinding.Sha256 `
        -AllowedDestinationIdentities @(
            $Plan.OriginalBinding, $Plan.CandidateBinding) `
        -AllowAbsentDestination `
        -Displaced (Join-Path $Plan.Root `
            'recovery-displaced-client-binding.json') -Protect
    Install-GameplayArtifact `
        -Source (Join-Path $Plan.Root 'original-installation.json') `
        -TransactionRoot $Plan.Root -Destination $Paths.Installation `
        -DestinationRoot $CombatLayout.EnvironmentRoot `
        -Temporary $Paths.InstallationTemporary `
        -ExpectedLength $Plan.OriginalInstallation.Length `
        -ExpectedSha256 $Plan.OriginalInstallation.Sha256 `
        -AllowedDestinationIdentities @(
            $Plan.OriginalInstallation, $Plan.CandidateInstallation) `
        -AllowAbsentDestination `
        -Displaced (Join-Path $Plan.Root `
            'recovery-displaced-installation.json') -Protect

    $recoveredBinding = Read-GameplayStrictJsonWithBytes -Path $Paths.Binding `
        -Root $CombatLayout.EnvironmentRoot -Label 'recovered Gameplay binding'
    $recoveredInstallation = Read-GameplayStrictJsonWithBytes `
        -Path $Paths.Installation -Root $CombatLayout.EnvironmentRoot `
        -Label 'recovered Gameplay installation'
    try {
        if ($activate) {
            Assert-GameplayBaselineBinding -Binding $recoveredBinding `
                -Installation $recoveredInstallation -Paths $Paths
        } else {
            Assert-GameplayActiveBinding -Binding $recoveredBinding `
                -Installation $recoveredInstallation `
                -CombatLayout $CombatLayout -Authority $Authority
        }
    } finally {
        if ($recoveredBinding.Bytes) {
            [Array]::Clear(
                $recoveredBinding.Bytes, 0, $recoveredBinding.Bytes.Length)
        }
        if ($recoveredInstallation.Bytes) {
            [Array]::Clear(
                $recoveredInstallation.Bytes, 0,
                $recoveredInstallation.Bytes.Length)
        }
    }
    if (-not $Plan.PluginsDirectoryExisted) {
        Remove-GameplayEmptyDirectory -Path $Paths.Plugins `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay recovered plugins directory'
    }
    $destination = Join-Path $Paths.BackupRoot (
        'recovered-abort-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') +
        '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    Set-PSOBBProtectedTreeAcl -Path $Plan.Root `
        -Root $CombatLayout.EnvironmentRoot
    [void](Assert-GameplayOrdinaryDirectory -Path $Plan.Root `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay recovered aborted transaction')
    Move-GameplayOrdinaryDirectory -Source $Plan.Root `
        -Destination $destination -Root $CombatLayout.EnvironmentRoot `
        -Label 'Gameplay recovered aborted transaction'
    [void](Assert-GameplayOrdinaryDirectory -Path $destination `
            -Root $CombatLayout.EnvironmentRoot `
            -Label 'Gameplay recovered aborted record')
    [pscustomobject]@{
        Recovered = $true; Disposition = 'restored-pre-transaction'
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$clientMutex = $null
$serverMutex = $null
$ownsServerMutex = $false
$loaderBytes = $null
$moduleBytes = $null
$configurationBytes = $null
$candidateBindingBytes = $null
$candidateInstallationBytes = $null
$binding = $null
$installation = $null
$activation = $null
$transactionRootCurrent = $null
$rollbackMarker = $null
try {
    $clientMutex = Enter-PSOBBClientOperationLock `
        -Layout $layout -TimeoutSeconds 0
    $marker = Assert-PSOBBRuntimeMarker -Layout $layout
    $serverMutex = [System.Threading.Mutex]::new(
        $false,
        ('Local\PSOBB.Newserv.Start.' +
            ([string]$marker.installationId).Replace('-', '')))
    try {
        $ownsServerMutex = $serverMutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $ownsServerMutex = $true
    }
    if (-not $ownsServerMutex) {
        throw 'Another PSOBB lifecycle or recovery operation is in progress'
    }
    $isTestFixture = Assert-GameplayFaultGate -Layout $layout -Marker $marker
    Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
        -Operation 'changing the CombatCanary Gameplay overlay' | Out-Null

    $combatLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment CombatCanary
    $stableLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment Stable
    $paths = Get-GameplayPaths -CombatLayout $combatLayout
    $stableFingerprint = Get-GameplayStableFingerprint -StableLayout $stableLayout
    $authority = Get-PSOBBGameplayObservationAuthority
    $configurationIdentity = Get-PSOBBGameplayObservationConfigurationIdentity
    $interruptedPlan = Get-GameplayInterruptedPlan -Paths $paths `
        -CombatLayout $combatLayout -Authority $authority `
        -ConfigurationIdentity $configurationIdentity `
        -RuntimeInstallationId ([string]$marker.installationId)
    if ($interruptedPlan) {
        if (-not $PSCmdlet.ShouldProcess(
                $combatLayout.EnvironmentRoot,
                'recover the exact interrupted Gameplay transaction')) {
            [pscustomobject]@{
                Action = $Action
                Changed = $false
                Pending = $true
                PendingRecovery = $true
                Profile = 'unknown-until-recovery'
                Detail = 'WhatIf authenticated an interrupted Gameplay transaction.'
            }
            return
        }
        Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
            -Operation 'recovering the interrupted CombatCanary Gameplay transaction' |
            Out-Null
        $null = Invoke-GameplayInterruptedRecovery `
            -Plan $interruptedPlan -Paths $paths `
            -CombatLayout $combatLayout -Authority $authority
        Assert-GameplayStableFingerprint -Expected $stableFingerprint `
            -StableLayout $stableLayout
        Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
            -Operation 'continuing after CombatCanary Gameplay recovery' |
            Out-Null
    }
    Assert-GameplayNoTransactionDebris -Paths $paths

    $binding = Read-GameplayStrictJsonWithBytes -Path $paths.Binding `
        -Root $combatLayout.EnvironmentRoot -Label 'CombatCanary client binding'
    $installation = Read-GameplayStrictJsonWithBytes `
        -Path $paths.Installation -Root $combatLayout.EnvironmentRoot `
        -Label 'CombatCanary installation record'
    Assert-GameplayInstallationRecordShape -Installation $installation.Value `
        -Label 'CombatCanary installation record'
    if (-not (Test-PSOBBProtectedAcl -Path $paths.Binding) -or
        -not (Test-PSOBBProtectedAcl -Path $paths.Installation)) {
        throw 'CombatCanary binding metadata is not protected'
    }
    [void](Get-PSOBBCombatCanaryInstallationBindingExpectations -Layout $layout)
    Assert-GameplayClientBindingFiles -Binding $binding `
        -CombatLayout $combatLayout

    if ($Action -ceq 'Activate' -and
        [long]$binding.Value.schemaVersion -eq 2) {
        Assert-GameplayActiveBinding -Binding $binding `
            -Installation $installation `
            -CombatLayout $combatLayout -Authority $authority
        $activation = Find-GameplayActivationSnapshot `
            -Paths $paths -CurrentBindingSha256 $binding.Sha256 `
            -CombatLayout $combatLayout -Authority $authority `
            -ConfigurationIdentity $configurationIdentity `
            -RuntimeInstallationId ([string]$marker.installationId)
        if ($activation.OriginalBinding.Bytes) {
            [Array]::Clear(
                $activation.OriginalBinding.Bytes, 0,
                $activation.OriginalBinding.Bytes.Length)
            $activation.OriginalBinding.Bytes = $null
        }
        Assert-GameplayStableFingerprint -Expected $stableFingerprint `
            -StableLayout $stableLayout
        [pscustomobject]@{
            Action = $Action; Changed = $false; Profile = 'observation'
            Detail = 'The exact Gameplay observation overlay is already active.'
        }
        return
    }
    if ($Action -ceq 'Rollback' -and
        [long]$binding.Value.schemaVersion -eq 1) {
        Assert-GameplayBaselineBinding -Binding $binding `
            -Installation $installation -Paths $paths
        Assert-GameplayStableFingerprint -Expected $stableFingerprint `
            -StableLayout $stableLayout
        [pscustomobject]@{
            Action = $Action; Changed = $false; Profile = 'baseline'
            Detail = 'The CombatCanary Gameplay overlay is already absent.'
        }
        return
    }

    $pluginsExisted = Test-Path -LiteralPath $paths.Plugins -PathType Container
    if ($Action -ceq 'Activate' -and $pluginsExisted -and
        @(Get-ChildItem -Force -LiteralPath $paths.Plugins).Count -ne 0) {
        throw 'The CombatCanary plugins directory is not empty and cannot be exclusively owned'
    }
    if ($Action -ceq 'Rollback') {
        $pluginNames = @(Get-ChildItem -Force -LiteralPath $paths.Plugins |
            ForEach-Object Name | Sort-Object)
        if ([string]::Join("`n", $pluginNames) -cne
            "PSOBB.Gameplay.asi`nPSOBB.Gameplay.ini") {
            throw 'The active Gameplay plugins directory has an unexpected entry'
        }
    }

    $activationId = 'gameplay-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') +
        '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $transactionOriginal = $null
    $originalOverlayPresent = $Action -ceq 'Rollback'
    if ($Action -ceq 'Activate') {
        Assert-GameplayBaselineBinding -Binding $binding `
            -Installation $installation -Paths $paths
        $archivePath = Join-Path $layout.Root `
            'archives\graphics-lab\Ultimate-ASI-Loader-v9.7.2-x86.zip'
        $loaderBytes = Read-GameplayLoaderBytes -ArchivePath $archivePath `
            -RuntimeRoot $layout.Root -Authority $authority
        $moduleBytes = Read-GameplaySourceBytes -Path $authority.ModulePath `
            -Root $script:PSOBBRepositoryRoot `
            -ExpectedLength $authority.ModuleSize `
            -ExpectedSha256 $authority.ModuleSha256 `
            -Label 'Gameplay observation module'
        $configurationBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            [string]$configurationIdentity.Text)
        $candidateBindingBytes = New-GameplayBindingBytes `
            -BaselineBinding $binding.Value -Authority $authority `
            -ConfigurationIdentity $configurationIdentity
        $candidateBindingIdentity = Get-GameplayBytesDigest `
            -Bytes $candidateBindingBytes
        $candidateInstallationBytes = New-GameplayInstallationBytes `
            -Installation $installation.Value `
            -ClientBindingSha256 $candidateBindingIdentity.Sha256
    } else {
        Assert-GameplayActiveBinding -Binding $binding `
            -Installation $installation `
            -CombatLayout $combatLayout -Authority $authority
        $activation = Find-GameplayActivationSnapshot `
            -Paths $paths -CurrentBindingSha256 $binding.Sha256 `
            -CombatLayout $combatLayout -Authority $authority `
            -ConfigurationIdentity $configurationIdentity `
            -RuntimeInstallationId ([string]$marker.installationId)
        $activationId = [System.IO.Path]::GetFileName($activation.Root)
        $candidateBindingBytes = [byte[]]$activation.OriginalBinding.Bytes
        $activation.OriginalBinding.Bytes = $null
        $baselineBindingIdentity = Get-GameplayBytesDigest `
            -Bytes $candidateBindingBytes
        $candidateInstallationBytes = New-GameplayInstallationBytes `
            -Installation $installation.Value `
            -ClientBindingSha256 $baselineBindingIdentity.Sha256
        $loaderBytes = Read-GameplaySourceBytes -Path $paths.Loader `
            -Root $combatLayout.EnvironmentRoot `
            -ExpectedLength $authority.LoaderSize `
            -ExpectedSha256 $authority.LoaderSha256 `
            -Label 'active Gameplay loader'
        $moduleBytes = Read-GameplaySourceBytes -Path $paths.Module `
            -Root $combatLayout.EnvironmentRoot `
            -ExpectedLength $authority.ModuleSize `
            -ExpectedSha256 $authority.ModuleSha256 `
            -Label 'active Gameplay module'
        $configurationBytes = Read-GameplaySourceBytes `
            -Path $paths.Configuration -Root $combatLayout.EnvironmentRoot `
            -ExpectedLength $configurationIdentity.Size `
            -ExpectedSha256 $configurationIdentity.Sha256 `
            -Label 'active Gameplay configuration'
    }

    if (-not $PSCmdlet.ShouldProcess(
            $combatLayout.EnvironmentRoot,
            "$Action the exact Gameplay observation overlay")) {
        [pscustomobject]@{
            Action = $Action; Changed = $false; Pending = $true
            Profile = if ($Action -ceq 'Activate') { 'observation' } else { 'baseline' }
            Detail = 'WhatIf completed the read-only Gameplay preflight.'
        }
        return
    }

    if (-not $isTestFixture) {
        $verifierTimeout = [math]::Min(220,
            (Get-GameplayOperationBudgetSeconds `
                -Label 'canonical verification' -ReservedSeconds 45))
        $installedPreflight = Get-GameplayBoundedCanonicalInstalledBinding `
            -Layout $layout -TimeoutSeconds $verifierTimeout
        if ([string]$installedPreflight.ClientBindingSha256 -cne
            [string]$binding.Sha256) {
            throw 'The complete CombatCanary preflight returned a different client binding'
        }
        [void](Get-GameplayOperationBudgetSeconds `
                -Label 'canonical verification' -ReservedSeconds 45)
    }

    [void](Get-GameplayOperationBudgetSeconds `
            -Label 'transaction preparation' -ReservedSeconds 45)
    Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
        -Operation 'committing the CombatCanary Gameplay overlay' | Out-Null
    Assert-GameplayStableFingerprint -Expected $stableFingerprint `
        -StableLayout $stableLayout
    $currentBinding = Get-GameplayDigest -Path $paths.Binding `
        -Root $combatLayout.EnvironmentRoot `
        -Label 'CombatCanary client binding commit check'
    Assert-GameplayDigest -Actual $currentBinding `
        -ExpectedLength $binding.Length -ExpectedSha256 $binding.Sha256 `
        -Label 'CombatCanary client binding commit check'
    $currentInstallation = Get-GameplayDigest -Path $paths.Installation `
        -Root $combatLayout.EnvironmentRoot `
        -Label 'CombatCanary installation commit check'
    Assert-GameplayDigest -Actual $currentInstallation `
        -ExpectedLength $installation.Length `
        -ExpectedSha256 $installation.Sha256 `
        -Label 'CombatCanary installation commit check'
    if (-not (Test-PSOBBProtectedAcl -Path $paths.Binding) -or
        -not (Test-PSOBBProtectedAcl -Path $paths.Installation)) {
        throw 'CombatCanary binding protection changed before Gameplay commit'
    }
    [void](Get-PSOBBCombatCanaryInstallationBindingExpectations -Layout $layout)
    Assert-GameplayClientBindingFiles -Binding $binding `
        -CombatLayout $combatLayout
    $preparationRoot = $paths.TransactionNext
    [void](Initialize-GameplayOrdinaryDirectory -Path $preparationRoot `
            -Root $combatLayout.EnvironmentRoot `
            -Label 'Gameplay transaction preparation')
    Set-GameplayProtectedDirectoryAcl -Path $preparationRoot `
        -Root $combatLayout.EnvironmentRoot `
        -Label 'Gameplay transaction preparation'
    [void](Assert-GameplayOrdinaryDirectory -Path $preparationRoot `
            -Root $combatLayout.EnvironmentRoot `
            -Label 'Gameplay transaction preparation')
    $originalBindingIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'original-client-binding.json') `
        -Root $preparationRoot -Bytes ([byte[]]$binding.Bytes)
    $originalInstallationIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'original-installation.json') `
        -Root $preparationRoot -Bytes ([byte[]]$installation.Bytes)
    $candidateBindingIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'candidate-client-binding.json') `
        -Root $preparationRoot -Bytes $candidateBindingBytes
    $candidateInstallationIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'candidate-installation.json') `
        -Root $preparationRoot -Bytes $candidateInstallationBytes
    $loaderIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'dinput8.dll') `
        -Root $preparationRoot -Bytes $loaderBytes
    $moduleIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'PSOBB.Gameplay.asi') `
        -Root $preparationRoot -Bytes $moduleBytes
    $configurationArtifactIdentity = Write-GameplayProtectedArtifact `
        -Path (Join-Path $preparationRoot 'PSOBB.Gameplay.ini') `
        -Root $preparationRoot -Bytes $configurationBytes
    $manifestBytes = ConvertTo-GameplayJsonBytes ([ordered]@{
        schemaVersion = 1
        runtimeInstallationId = [string]$marker.installationId
        transactionId = [Guid]::NewGuid().ToString('N')
        activationId = $activationId
        action = $Action
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        pluginsDirectoryExisted = [bool]$pluginsExisted
        originalBindingSize = [long]$originalBindingIdentity.Length
        originalBindingSha256 = [string]$originalBindingIdentity.Sha256
        originalInstallationSize = [long]$originalInstallationIdentity.Length
        originalInstallationSha256 =
            [string]$originalInstallationIdentity.Sha256
        activeBindingSize = if ($Action -ceq 'Activate') {
            [long]$candidateBindingIdentity.Length
        } else { [long]$originalBindingIdentity.Length }
        activeBindingSha256 = if ($Action -ceq 'Activate') {
            [string]$candidateBindingIdentity.Sha256
        } else { [string]$originalBindingIdentity.Sha256 }
        candidateBindingSize = [long]$candidateBindingIdentity.Length
        candidateBindingSha256 = [string]$candidateBindingIdentity.Sha256
        candidateInstallationSize = [long]$candidateInstallationIdentity.Length
        candidateInstallationSha256 =
            [string]$candidateInstallationIdentity.Sha256
        loaderSize = [long]$loaderIdentity.Length
        loaderSha256 = [string]$loaderIdentity.Sha256
        moduleSize = [long]$moduleIdentity.Length
        moduleSha256 = [string]$moduleIdentity.Sha256
        configurationSize = [long]$configurationArtifactIdentity.Length
        configurationSha256 = [string]$configurationArtifactIdentity.Sha256
    })
    [void](Write-GameplayProtectedArtifact `
            -Path (Join-Path $preparationRoot 'activation.json') `
            -Root $preparationRoot -Bytes $manifestBytes)
    Set-PSOBBProtectedTreeAcl `
        -Path $preparationRoot -Root $combatLayout.EnvironmentRoot
    [void](Assert-GameplayOrdinaryDirectory -Path $preparationRoot `
            -Root $combatLayout.EnvironmentRoot `
            -Label 'Gameplay transaction preparation')
    Move-GameplayOrdinaryDirectory -Source $preparationRoot `
        -Destination $paths.Transaction -Root $combatLayout.EnvironmentRoot `
        -Label 'Gameplay transaction publication'
    $transactionRootCurrent = $paths.Transaction
    [void](Assert-GameplayOrdinaryDirectory -Path $transactionRootCurrent `
            -Root $combatLayout.EnvironmentRoot `
            -Label 'Gameplay published transaction')
    Invoke-GameplayHardExit -Point 'after-transaction-publish'

    $transactionOriginal = [pscustomobject]@{
        Binding = [pscustomobject]@{
            Length = $originalBindingIdentity.Length
            Sha256 = $originalBindingIdentity.Sha256
        }
        Installation = [pscustomobject]@{
            Length = $originalInstallationIdentity.Length
            Sha256 = $originalInstallationIdentity.Sha256
        }
        Loader = [pscustomobject]@{
            Length = $loaderIdentity.Length; Sha256 = $loaderIdentity.Sha256
        }
        Module = [pscustomobject]@{
            Length = $moduleIdentity.Length; Sha256 = $moduleIdentity.Sha256
        }
        Configuration = [pscustomobject]@{
            Length = $configurationArtifactIdentity.Length
            Sha256 = $configurationArtifactIdentity.Sha256
        }
        AfterLoader = $null
        AfterModule = $null
        AfterConfiguration = $null
        AfterBinding = $null
        AfterInstallation = $null
    }

    try {
        [void](Get-GameplayOperationBudgetSeconds `
                -Label 'live transaction admission' -ReservedSeconds 30)
        if (-not (Test-Path -LiteralPath $paths.Plugins -PathType Container)) {
            [void](Initialize-GameplayOrdinaryDirectory -Path $paths.Plugins `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay plugins directory')
        }
        if ($Action -ceq 'Activate') {
            $transactionOriginal.AfterLoader = $loaderIdentity
            Install-GameplayArtifact `
                -Source (Join-Path $transactionRootCurrent 'dinput8.dll') `
                -TransactionRoot $transactionRootCurrent -Destination $paths.Loader `
                -DestinationRoot $combatLayout.EnvironmentRoot `
                -Temporary $paths.LoaderTemporary `
                -ExpectedLength $loaderIdentity.Length `
                -ExpectedSha256 $loaderIdentity.Sha256 `
                -AllowAbsentDestination `
                -PostCommitFaultPoint 'after-loader-commit'
            Invoke-GameplayHardExit -Point 'after-loader'
            Invoke-GameplayFault -Point 'after-loader'
            [void](Get-GameplayOperationBudgetSeconds `
                    -Label 'loader commit' -ReservedSeconds 20)
            $transactionOriginal.AfterModule = $moduleIdentity
            Install-GameplayArtifact `
                -Source (Join-Path $transactionRootCurrent 'PSOBB.Gameplay.asi') `
                -TransactionRoot $transactionRootCurrent -Destination $paths.Module `
                -DestinationRoot $combatLayout.EnvironmentRoot `
                -Temporary $paths.ModuleTemporary `
                -ExpectedLength $moduleIdentity.Length `
                -ExpectedSha256 $moduleIdentity.Sha256 `
                -AllowAbsentDestination
            Invoke-GameplayHardExit -Point 'after-module'
            Invoke-GameplayFault -Point 'after-module'
            [void](Get-GameplayOperationBudgetSeconds `
                    -Label 'module commit' -ReservedSeconds 20)
            $transactionOriginal.AfterConfiguration =
                $configurationArtifactIdentity
            Install-GameplayArtifact `
                -Source (Join-Path $transactionRootCurrent 'PSOBB.Gameplay.ini') `
                -TransactionRoot $transactionRootCurrent `
                -Destination $paths.Configuration `
                -DestinationRoot $combatLayout.EnvironmentRoot `
                -Temporary $paths.ConfigurationTemporary `
                -ExpectedLength $configurationArtifactIdentity.Length `
                -ExpectedSha256 $configurationArtifactIdentity.Sha256 `
                -AllowAbsentDestination
            Invoke-GameplayHardExit -Point 'after-configuration'
            Invoke-GameplayFault -Point 'after-configuration'
            [void](Get-GameplayOperationBudgetSeconds `
                    -Label 'configuration commit' -ReservedSeconds 20)
        } else {
            Remove-GameplayExactFile -Path $paths.Configuration `
                -Root $combatLayout.EnvironmentRoot `
                -ExpectedLength $configurationArtifactIdentity.Length `
                -ExpectedSha256 $configurationArtifactIdentity.Sha256 `
                -Label 'Gameplay configuration' -RequirePresent
            Invoke-GameplayHardExit -Point 'after-configuration'
            Invoke-GameplayFault -Point 'after-configuration'
            [void](Get-GameplayOperationBudgetSeconds `
                    -Label 'configuration removal' -ReservedSeconds 20)
            Remove-GameplayExactFile -Path $paths.Module `
                -Root $combatLayout.EnvironmentRoot `
                -ExpectedLength $moduleIdentity.Length `
                -ExpectedSha256 $moduleIdentity.Sha256 `
                -Label 'Gameplay module' -RequirePresent
            Invoke-GameplayHardExit -Point 'after-module'
            Invoke-GameplayFault -Point 'after-module'
            [void](Get-GameplayOperationBudgetSeconds `
                    -Label 'module removal' -ReservedSeconds 20)
            Remove-GameplayExactFile -Path $paths.Loader `
                -Root $combatLayout.EnvironmentRoot `
                -ExpectedLength $loaderIdentity.Length `
                -ExpectedSha256 $loaderIdentity.Sha256 `
                -Label 'Gameplay loader' -RequirePresent
            Invoke-GameplayHardExit -Point 'after-loader'
            Invoke-GameplayFault -Point 'after-loader'
            [void](Get-GameplayOperationBudgetSeconds `
                    -Label 'loader removal' -ReservedSeconds 20)
        }
        $transactionOriginal.AfterBinding = $candidateBindingIdentity
        Install-GameplayArtifact `
            -Source (Join-Path $transactionRootCurrent 'candidate-client-binding.json') `
            -TransactionRoot $transactionRootCurrent -Destination $paths.Binding `
            -DestinationRoot $combatLayout.EnvironmentRoot `
            -Temporary $paths.BindingTemporary `
            -ExpectedLength $candidateBindingIdentity.Length `
            -ExpectedSha256 $candidateBindingIdentity.Sha256 `
            -AllowedDestinationIdentities @($originalBindingIdentity) `
            -Displaced (Join-Path $transactionRootCurrent `
                'replaced-original-client-binding.json') -Protect `
            -PostCommitFaultPoint 'after-binding-commit'
        Invoke-GameplayHardExit -Point 'after-binding'
        Invoke-GameplayFault -Point 'after-binding'
        [void](Get-GameplayOperationBudgetSeconds `
                -Label 'binding commit' -ReservedSeconds 20)
        $transactionOriginal.AfterInstallation = $candidateInstallationIdentity
        Install-GameplayArtifact `
            -Source (Join-Path $transactionRootCurrent 'candidate-installation.json') `
            -TransactionRoot $transactionRootCurrent -Destination $paths.Installation `
            -DestinationRoot $combatLayout.EnvironmentRoot `
            -Temporary $paths.InstallationTemporary `
            -ExpectedLength $candidateInstallationIdentity.Length `
            -ExpectedSha256 $candidateInstallationIdentity.Sha256 `
            -AllowedDestinationIdentities @($originalInstallationIdentity) `
            -Displaced (Join-Path $transactionRootCurrent `
                'replaced-original-installation.json') -Protect `
            -PostCommitFaultPoint 'after-installation-commit'
        Invoke-GameplayHardExit -Point 'after-installation'
        Invoke-GameplayFault -Point 'after-installation'
        [void](Get-GameplayOperationBudgetSeconds `
                -Label 'installation commit' -ReservedSeconds 20)

        $finalBinding = Read-GameplayStrictJsonWithBytes -Path $paths.Binding `
            -Root $combatLayout.EnvironmentRoot -Label 'final Gameplay binding'
        $finalInstallation = Read-GameplayStrictJsonWithBytes `
            -Path $paths.Installation -Root $combatLayout.EnvironmentRoot `
            -Label 'final Gameplay installation'
        try {
            if ($Action -ceq 'Activate') {
                Assert-GameplayActiveBinding -Binding $finalBinding `
                    -Installation $finalInstallation `
                    -CombatLayout $combatLayout -Authority $authority
            } else {
                Assert-GameplayBaselineBinding -Binding $finalBinding `
                    -Installation $finalInstallation -Paths $paths
            }
        } finally {
            if ($finalBinding.Bytes) {
                [Array]::Clear($finalBinding.Bytes, 0, $finalBinding.Bytes.Length)
            }
            if ($finalInstallation.Bytes) {
                [Array]::Clear(
                    $finalInstallation.Bytes, 0, $finalInstallation.Bytes.Length)
            }
        }
        Assert-GameplayStableFingerprint -Expected $stableFingerprint `
            -StableLayout $stableLayout
        [void](Get-GameplayOperationBudgetSeconds `
                -Label 'final readback' -ReservedSeconds 15)
        if ($Action -ceq 'Activate') {
            [void](Initialize-GameplayOrdinaryDirectory `
                    -Path $paths.BackupRoot `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay activation backup root')
            Set-GameplayProtectedDirectoryAcl -Path $paths.BackupRoot `
                -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay activation backup root'
            [void](Assert-GameplayOrdinaryDirectory `
                    -Path $paths.BackupRoot `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay activation backup root')
            $activationRoot = Join-Path $paths.BackupRoot $activationId
            [void](Assert-GameplayOrdinaryDirectory `
                    -Path $transactionRootCurrent `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay completed activation transaction')
            Move-GameplayOrdinaryDirectory -Source $transactionRootCurrent `
                -Destination $activationRoot -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay activation snapshot publication'
            $transactionRootCurrent = $activationRoot
            [void](Assert-GameplayOrdinaryDirectory -Path $activationRoot `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay activation snapshot')
            Set-PSOBBProtectedTreeAcl `
                -Path $activationRoot -Root $combatLayout.EnvironmentRoot
        } else {
            $rollbackRoot = Join-Path $paths.BackupRoot (
                'rollback-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') +
                '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            Set-PSOBBProtectedTreeAcl `
                -Path $transactionRootCurrent -Root $combatLayout.EnvironmentRoot
            [void](Assert-GameplayOrdinaryDirectory `
                    -Path $transactionRootCurrent `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay completed rollback transaction')
            if (-not [bool]$activation.Manifest.pluginsDirectoryExisted) {
                Remove-GameplayEmptyDirectory -Path $paths.Plugins `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay baseline plugins directory'
            }
            $rollbackMarker = Write-GameplayRollbackMarker `
                -ActivationRoot $activation.Root `
                -ActivationId $activationId `
                -BaselineBindingSha256 $candidateBindingIdentity.Sha256
            Invoke-GameplayHardExit -Point 'after-rollback-marker'
            Move-GameplayOrdinaryDirectory -Source $transactionRootCurrent `
                -Destination $rollbackRoot -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay rollback archive publication'
            $transactionRootCurrent = $rollbackRoot
            [void](Assert-GameplayOrdinaryDirectory -Path $rollbackRoot `
                    -Root $combatLayout.EnvironmentRoot `
                    -Label 'Gameplay rollback record')
        }
    } catch {
        $failure = $_.Exception.Message
        try {
            Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
                -Operation 'compensating the CombatCanary Gameplay overlay' |
                Out-Null
            if ($rollbackMarker) {
                Remove-GameplayExactFile -Path $rollbackMarker.Path `
                    -Root $activation.Root `
                    -ExpectedLength $rollbackMarker.Length `
                    -ExpectedSha256 $rollbackMarker.Sha256 `
                    -Label 'Gameplay rollback marker compensation' `
                    -RequirePresent
                $rollbackMarker = $null
            }
            Restore-GameplayOriginalState -Paths $paths `
                -CombatLayout $combatLayout `
                -TransactionRoot $transactionRootCurrent `
                -Original $transactionOriginal `
                -PluginsExisted $pluginsExisted `
                -OriginalOverlayPresent $originalOverlayPresent
            Assert-GameplayStableFingerprint -Expected $stableFingerprint `
                -StableLayout $stableLayout
        } catch {
            throw ('The Gameplay transaction failed and compensation could not ' +
                'prove the exact original state. Keep both environments stopped, ' +
                "preserve '$transactionRootCurrent', and inspect it before retrying. " +
                "Original failure: $failure Compensation failure: " +
                $_.Exception.Message)
        }
        [void](Initialize-GameplayOrdinaryDirectory -Path $paths.BackupRoot `
                -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay rejected-transaction backup root')
        Set-GameplayProtectedDirectoryAcl -Path $paths.BackupRoot `
            -Root $combatLayout.EnvironmentRoot `
            -Label 'Gameplay rejected-transaction backup root'
        [void](Assert-GameplayOrdinaryDirectory -Path $paths.BackupRoot `
                -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay rejected-transaction backup root')
        $rejectedRoot = Join-Path $paths.BackupRoot (
            'rejected-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') +
            '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        [void](Assert-GameplayOrdinaryDirectory -Path $transactionRootCurrent `
                -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay compensated transaction')
        Move-GameplayOrdinaryDirectory -Source $transactionRootCurrent `
            -Destination $rejectedRoot -Root $combatLayout.EnvironmentRoot `
            -Label 'Gameplay rejected transaction publication'
        $transactionRootCurrent = $rejectedRoot
        [void](Assert-GameplayOrdinaryDirectory -Path $rejectedRoot `
                -Root $combatLayout.EnvironmentRoot `
                -Label 'Gameplay rejected transaction')
        Set-PSOBBProtectedTreeAcl `
            -Path $rejectedRoot -Root $combatLayout.EnvironmentRoot
        throw "The Gameplay transaction failed and restored its original state: $failure"
    }

    [pscustomobject]@{
        Action = $Action
        Changed = $true
        Profile = if ($Action -ceq 'Activate') { 'observation' } else { 'baseline' }
        ActivationId = $activationId
        ClientBindingSha256 = $candidateBindingIdentity.Sha256
        StableClientSha256 = $stableFingerprint.ClientSha256
        StableInstallationSha256 = $stableFingerprint.InstallationSha256
    }
} finally {
    foreach ($bytes in @(
            $loaderBytes, $moduleBytes, $configurationBytes,
            $candidateBindingBytes,
            $candidateInstallationBytes)) {
        if ($bytes -is [byte[]]) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    if ($binding -and $binding.Bytes) {
        [Array]::Clear($binding.Bytes, 0, $binding.Bytes.Length)
    }
    if ($installation -and $installation.Bytes) {
        [Array]::Clear(
            $installation.Bytes, 0, $installation.Bytes.Length)
    }
    if ($activation -and $activation.OriginalBinding -and
        $activation.OriginalBinding.Bytes) {
        [Array]::Clear(
            $activation.OriginalBinding.Bytes, 0,
            $activation.OriginalBinding.Bytes.Length)
    }
    if ($ownsServerMutex -and $serverMutex) {
        $serverMutex.ReleaseMutex()
    }
    if ($serverMutex) { $serverMutex.Dispose() }
    if ($clientMutex) { Exit-PSOBBClientOperationLock -Mutex $clientMutex }
}
