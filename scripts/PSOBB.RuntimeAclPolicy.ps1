Set-StrictMode -Version Latest
$script:PSOBBRuntimeMarkerStoppedAuthorityToken = [object]::new()

function Initialize-PSOBBRuntimeMarkerFileIdentityQuery {
    [CmdletBinding()]
    param()

    if ('PSOBB.Runtime.MarkerFileIdentityQuery' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PSOBB.Runtime
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    public sealed class MarkerFileIdentityInfo
    {
        public uint VolumeSerialNumber { get; internal set; }
        public ulong FileIndex { get; internal set; }
        public uint NumberOfLinks { get; internal set; }
    }

    public static class MarkerFileIdentityQuery
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation information);

        public static MarkerFileIdentityInfo Query(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new ArgumentException("The file handle is not open.", nameof(handle));
            }

            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new MarkerFileIdentityInfo
            {
                VolumeSerialNumber = information.VolumeSerialNumber,
                FileIndex = ((ulong)information.FileIndexHigh << 32) |
                    information.FileIndexLow,
                NumberOfLinks = information.NumberOfLinks
            };
        }
    }
}
'@ -ErrorAction Stop
}

function Get-PSOBBRuntimeMarkerNativeFileIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.FileStream]$Lease)

    Initialize-PSOBBRuntimeMarkerFileIdentityQuery
    [PSOBB.Runtime.MarkerFileIdentityQuery]::Query($Lease.SafeFileHandle)
}

function Get-PSOBBRuntimeAclPrincipals {
    [CmdletBinding()]
    param()

    @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    )
}

function Get-PSOBBRuntimeMarkerExpectedPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $expectedPath = [System.IO.Path]::GetFullPath(
        (Join-Path $Layout.Root '.psobb-runtime.json'))
    $declaredPath = [System.IO.Path]::GetFullPath(
        ([string]$Layout.RuntimeMarker))
    if (-not $declaredPath.Equals(
            $expectedPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The runtime layout does not identify the exact root marker'
    }
    $expectedPath
}

function Open-PSOBBRuntimeMarkerIdentityLease {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $expectedPath = Get-PSOBBRuntimeMarkerExpectedPath -Layout $Layout
    $trustedLease = Open-PSOBBTrustedExecutableLease `
        -Path $expectedPath -Root $Layout.Root -MaximumBytes 64KB `
        -Label 'runtime ownership marker'
    try {
        $native = Get-PSOBBRuntimeMarkerNativeFileIdentity `
            -Lease $trustedLease.Lease
        if ([uint32]$native.NumberOfLinks -ne 1) {
            throw 'The runtime ownership marker must have exactly one hard link'
        }
        [pscustomobject]@{
            Path = [string]$trustedLease.Path
            Root = [string]$trustedLease.Root
            MaximumBytes = [long]$trustedLease.MaximumBytes
            Length = [long]$trustedLease.Length
            Sha256 = [string]$trustedLease.Sha256
            VolumeSerialNumber = [uint32]$native.VolumeSerialNumber
            FileIndex = [uint64]$native.FileIndex
            InitialNumberOfLinks = [uint32]$native.NumberOfLinks
            Lease = $trustedLease.Lease
        }
        $trustedLease = $null
    } finally {
        if ($trustedLease) {
            Close-PSOBBTrustedExecutableLease -Identity $trustedLease
        }
    }
}

function Close-PSOBBRuntimeMarkerIdentityLease {
    [CmdletBinding()]
    param($IdentityLease)

    Close-PSOBBTrustedExecutableLease -Identity $IdentityLease
}

function Assert-PSOBBRuntimeMarkerIdentityLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$IdentityLease,
        [switch]$AllowAdditionalHardLinks
    )

    $expectedPath = Get-PSOBBRuntimeMarkerExpectedPath -Layout $Layout
    if (-not $IdentityLease.PSObject.Properties['Lease'] -or
        $IdentityLease.Lease -isnot [System.IO.FileStream] -or
        -not $IdentityLease.Lease.CanRead -or
        -not ([System.IO.Path]::GetFullPath(
                [string]$IdentityLease.Path)).Equals(
            $expectedPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The runtime ownership marker identity lease is invalid'
    }

    $retainedNative = Get-PSOBBRuntimeMarkerNativeFileIdentity `
        -Lease $IdentityLease.Lease
    if ([uint32]$retainedNative.VolumeSerialNumber -ne
            [uint32]$IdentityLease.VolumeSerialNumber -or
        [uint64]$retainedNative.FileIndex -ne
            [uint64]$IdentityLease.FileIndex) {
        throw 'The retained runtime ownership marker file identity changed'
    }
    if (-not $AllowAdditionalHardLinks -and
        [uint32]$retainedNative.NumberOfLinks -ne 1) {
        throw 'The runtime ownership marker hard-link identity changed'
    }

    $pathLease = $null
    try {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $expectedPath -Root $Layout.Root -Kind File `
                -Label 'runtime ownership marker')
        $pathLease = [System.IO.FileStream]::new(
            $expectedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read,
            4096,
            [System.IO.FileOptions]::SequentialScan)
        $pathNative = Get-PSOBBRuntimeMarkerNativeFileIdentity `
            -Lease $pathLease
        if ([uint32]$pathNative.VolumeSerialNumber -ne
                [uint32]$IdentityLease.VolumeSerialNumber -or
            [uint64]$pathNative.FileIndex -ne
                [uint64]$IdentityLease.FileIndex -or
            (-not $AllowAdditionalHardLinks -and
                [uint32]$pathNative.NumberOfLinks -ne 1)) {
            throw 'The runtime ownership marker path no longer names the retained file identity'
        }
    } finally {
        if ($pathLease) {
            $pathLease.Dispose()
        }
    }

    $digest = Get-PSOBBLeasedFileDigest `
        -Lease $IdentityLease.Lease `
        -MaximumBytes ([long]$IdentityLease.MaximumBytes) `
        -Label 'runtime ownership marker'
    if ([long]$digest.Length -ne [long]$IdentityLease.Length -or
        [string]$digest.Sha256 -cne [string]$IdentityLease.Sha256) {
        throw 'The runtime ownership marker bytes changed while leased'
    }

    [pscustomobject]@{
        VolumeSerialNumber = [uint32]$retainedNative.VolumeSerialNumber
        FileIndex = [uint64]$retainedNative.FileIndex
        NumberOfLinks = [uint32]$retainedNative.NumberOfLinks
        Length = [long]$digest.Length
        Sha256 = [string]$digest.Sha256
    }
}

function Get-PSOBBRuntimeMarkerMetadataSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        $IdentityLease,
        [switch]$AllowAdditionalHardLinks
    )

    $ownedLease = $null
    try {
        if (-not $IdentityLease) {
            $ownedLease = Open-PSOBBRuntimeMarkerIdentityLease -Layout $Layout
            $IdentityLease = $ownedLease
        }
        $expectedPath = Get-PSOBBRuntimeMarkerExpectedPath -Layout $Layout
        $identity = Assert-PSOBBRuntimeMarkerIdentityLease `
            -Layout $Layout -IdentityLease $IdentityLease `
            -AllowAdditionalHardLinks:$AllowAdditionalHardLinks
        $snapshot = Read-PSOBBStrictJsonSnapshot `
            -Path $expectedPath -Root $Layout.Root -MaximumBytes 64KB `
            -MaximumDepth 4 -Label 'runtime ownership marker'
        if ([long]$snapshot.Length -ne [long]$identity.Length -or
            [string]$snapshot.Sha256 -cne [string]$identity.Sha256) {
            throw 'The runtime ownership marker path snapshot differs from its retained identity'
        }
        $marker = $snapshot.Value
        Assert-PSOBBStrictDataObjectProperties -Value $marker -Expected @(
            'schemaVersion', 'installationId', 'runtimeRoot', 'createdAtUtc') `
            -Label 'runtime ownership marker' | Out-Null

        $installationId = [Guid]::Empty
        $createdAt = [DateTimeOffset]::MinValue
        if ($marker.schemaVersion -isnot [long] -or
            $marker.schemaVersion -ne 1 -or
            $marker.installationId -isnot [string] -or
            -not [Guid]::TryParseExact(
                [string]$marker.installationId, 'D', [ref]$installationId) -or
            $marker.runtimeRoot -isnot [string] -or
            $marker.createdAtUtc -isnot [string] -or
            -not [DateTimeOffset]::TryParse(
                [string]$marker.createdAtUtc, [ref]$createdAt) -or
            -not ([System.IO.Path]::GetFullPath(
                    [string]$marker.runtimeRoot).TrimEnd('\')).Equals(
                ([System.IO.Path]::GetFullPath(
                        [string]$Layout.Root).TrimEnd('\')),
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The runtime ownership marker is invalid or belongs to another root'
        }

        $acl = Get-Acl -LiteralPath $expectedPath
        $finalIdentity = Assert-PSOBBRuntimeMarkerIdentityLease `
            -Layout $Layout -IdentityLease $IdentityLease `
            -AllowAdditionalHardLinks:$AllowAdditionalHardLinks
        [pscustomobject]@{
            Path = $expectedPath
            Length = [long]$snapshot.Length
            Sha256 = [string]$snapshot.Sha256
            InstallationId = $installationId
            VolumeSerialNumber = [uint32]$finalIdentity.VolumeSerialNumber
            FileIndex = [uint64]$finalIdentity.FileIndex
            NumberOfLinks = [uint32]$finalIdentity.NumberOfLinks
            Acl = $acl
            AccessSddl = $acl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::Access)
            OwnerSid = $acl.GetOwner(
                [System.Security.Principal.SecurityIdentifier]).Value
            GroupSid = $acl.GetGroup(
                [System.Security.Principal.SecurityIdentifier]).Value
        }
    } finally {
        if ($ownedLease) {
            Close-PSOBBRuntimeMarkerIdentityLease -IdentityLease $ownedLease
        }
    }
}

function Assert-PSOBBLegacyRuntimeMarkerAclState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        $IdentityLease,
        [switch]$AllowAdditionalHardLinks
    )

    $state = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $Layout -IdentityLease $IdentityLease `
        -AllowAdditionalHardLinks:$AllowAdditionalHardLinks
    $acl = $state.Acl
    if ($acl.AreAccessRulesProtected -or
        -not $acl.AreAccessRulesCanonical) {
        throw 'The runtime marker does not have the one accepted legacy ACL shape'
    }

    $expectedSids = @(Get-PSOBBRuntimeAclPrincipals |
        ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($state.OwnerSid -notin $expectedSids) {
        throw 'The legacy runtime marker owner is not an approved runtime principal'
    }

    $rules = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]))
    $actualSids = @($rules | ForEach-Object {
            $_.IdentityReference.Value
        } | Sort-Object -Unique)
    if ($rules.Count -ne $expectedSids.Count -or
        $actualSids.Count -ne $expectedSids.Count -or
        @(Compare-Object `
                -ReferenceObject $expectedSids `
                -DifferenceObject $actualSids).Count -ne 0) {
        throw 'The legacy runtime marker ACL identities are not exact'
    }
    foreach ($rule in $rules) {
        if (-not $rule.IsInherited -or
            $rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            [int64]$rule.FileSystemRights -ne
                [int64][System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne
                [System.Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None) {
            throw 'The legacy runtime marker ACL rules are not exact inherited FullControl rules'
        }
    }
    $state
}

function Set-PSOBBRuntimeMarkerAccessDacl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$AccessSddl
    )

    $safePath = Assert-PSOBBOrdinaryContainedPath `
        -Path $Path -Root $Root -Kind File `
        -Label 'runtime ownership marker'
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        $AccessSddl,
        [System.Security.AccessControl.AccessControlSections]::Access)
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $safePath),
        $security)
}

function Assert-PSOBBRuntimeMarkerMetadataMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$ExpectedAccessSddl,
        [Parameter(Mandatory)][string]$Boundary,
        [switch]$AllowAdditionalHardLinks
    )

    if ($Actual.Length -ne $Expected.Length -or
        $Actual.Sha256 -cne $Expected.Sha256 -or
        $Actual.VolumeSerialNumber -ne $Expected.VolumeSerialNumber -or
        $Actual.FileIndex -ne $Expected.FileIndex -or
        (-not $AllowAdditionalHardLinks -and
            $Actual.NumberOfLinks -ne 1) -or
        $Actual.AccessSddl -cne $ExpectedAccessSddl -or
        $Actual.OwnerSid -cne $Expected.OwnerSid -or
        $Actual.GroupSid -cne $Expected.GroupSid) {
        throw "Runtime-marker state is not exact at the $Boundary boundary"
    }
    $true
}

function Assert-PSOBBRuntimeMarkerMigrationStopped {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $lifecyclePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($environmentName in @('Stable', 'CombatCanary')) {
        $environment = Get-PSOBBServerEnvironmentLayout `
            -Layout $Layout -Environment $environmentName
        foreach ($path in @(
                $environment.PidFile,
                $environment.LegacyPidFile,
                $environment.HostPidFile,
                $environment.ControlState,
                $environment.ControlRequest)) {
            $safePath = Assert-PathWithinRoot `
                -Path ([string]$path) -Root $Layout.Root
            if (Test-Path -LiteralPath $safePath) {
                $lifecyclePaths.Add($safePath)
            }
        }
    }
    $servers = @(Get-PSOBBServerEnvironmentProcessRecords -Layout $Layout)
    $clients = @(Get-PSOBBAllClientProcessRecords -Layout $Layout)
    $clientHelpers = @(Get-Process -Name 'online', 'option' `
            -ErrorAction SilentlyContinue)
    $listeners = @(Get-PSOBBReservedServerPortListeners)
    if ($lifecyclePaths.Count -ne 0 -or
        $servers.Count -ne 0 -or
        $clients.Count -ne 0 -or
        $clientHelpers.Count -ne 0 -or
        $listeners.Count -ne 0) {
        throw ('Runtime-marker ACL migration requires absent lifecycle ' +
            'evidence, stopped server/client/helper processes, and no ' +
            'reserved listener')
    }
    [pscustomobject]@{
        AuthorityToken = $script:PSOBBRuntimeMarkerStoppedAuthorityToken
        ValidatedAtUtc = [DateTime]::UtcNow
    }
}

function Assert-PSOBBRuntimeMarkerStoppedAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Authority
    )

    if (-not $Authority.PSObject.Properties['AuthorityToken'] -or
        -not [object]::ReferenceEquals(
            $Authority.AuthorityToken,
            $script:PSOBBRuntimeMarkerStoppedAuthorityToken)) {
        throw 'The runtime-marker DACL write lacks stopped-runtime authority'
    }
    # Re-run the complete census at the mutation boundary. A stale authority
    # cannot authorize a write after lifecycle state changes.
    Assert-PSOBBRuntimeMarkerMigrationStopped -Layout $Layout | Out-Null
    $true
}

function Set-PSOBBRuntimeMarkerProtectedDacl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$IdentityLease,
        [Parameter(Mandatory)]$StoppedAuthority,
        [Parameter(Mandatory)]$ExpectedLegacyState,
        [Parameter(Mandatory)]$MutationState
    )

    if (-not $MutationState.PSObject.Properties['Attempted'] -or
        -not $MutationState.PSObject.Properties['ProtectedAccessSddl'] -or
        [bool]$MutationState.Attempted -or
        $null -ne $MutationState.ProtectedAccessSddl) {
        throw 'The runtime-marker DACL mutation state is invalid'
    }
    Assert-PSOBBRuntimeMarkerStoppedAuthority `
        -Layout $Layout -Authority $StoppedAuthority | Out-Null
    $liveLegacy = Assert-PSOBBLegacyRuntimeMarkerAclState `
        -Layout $Layout -IdentityLease $IdentityLease
    Assert-PSOBBRuntimeMarkerMetadataMatches `
        -Actual $liveLegacy -Expected $ExpectedLegacyState `
        -ExpectedAccessSddl ([string]$ExpectedLegacyState.AccessSddl) `
        -Boundary 'prewrite legacy DACL' | Out-Null
    $MutationState.Attempted = $true
    Set-PSOBBProtectedAcl -Path $IdentityLease.Path
    $postWrite = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $Layout -IdentityLease $IdentityLease
    if (-not (Test-PSOBBProtectedAcl -Path $IdentityLease.Path)) {
        throw 'Runtime-marker protected DACL write did not produce its exact policy'
    }
    Assert-PSOBBRuntimeMarkerMetadataMatches `
        -Actual $postWrite -Expected $ExpectedLegacyState `
        -ExpectedAccessSddl ([string]$postWrite.AccessSddl) `
        -Boundary 'post-write protected DACL' | Out-Null
    $MutationState.ProtectedAccessSddl = [string]$postWrite.AccessSddl
}

function Set-PSOBBRuntimeMarkerLegacyRollbackDacl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$IdentityLease,
        [Parameter(Mandatory)]$StoppedAuthority,
        [Parameter(Mandatory)]$ExpectedLegacyState,
        [Parameter(Mandatory)][string]$ExpectedProtectedAccessSddl
    )

    $candidate = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $Layout -IdentityLease $IdentityLease `
        -AllowAdditionalHardLinks
    Assert-PSOBBRuntimeMarkerMetadataMatches `
        -Actual $candidate -Expected $ExpectedLegacyState `
        -ExpectedAccessSddl $ExpectedProtectedAccessSddl `
        -Boundary 'rollback protected DACL' -AllowAdditionalHardLinks |
        Out-Null

    # A prior stopped-state result cannot authorize compensation. Re-run the
    # full lifecycle census, then re-read the exact protected DACL once more at
    # the mutation boundary.
    Assert-PSOBBRuntimeMarkerStoppedAuthority `
        -Layout $Layout -Authority $StoppedAuthority | Out-Null
    $lockedCandidate = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $Layout -IdentityLease $IdentityLease `
        -AllowAdditionalHardLinks
    Assert-PSOBBRuntimeMarkerMetadataMatches `
        -Actual $lockedCandidate -Expected $ExpectedLegacyState `
        -ExpectedAccessSddl $ExpectedProtectedAccessSddl `
        -Boundary 'immediate rollback protected DACL' `
        -AllowAdditionalHardLinks | Out-Null
    Set-PSOBBRuntimeMarkerAccessDacl `
        -Path $IdentityLease.Path -Root $Layout.Root `
        -AccessSddl ([string]$ExpectedLegacyState.AccessSddl)
}

function Repair-PSOBBLegacyRuntimeMarkerAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(DontShow = $true)]
        [scriptblock]$InternalBeforeWriteAction,
        [Parameter(DontShow = $true)]
        [scriptblock]$InternalAfterWriteAction
    )

    try {
        Assert-PSOBBRuntimeMarker -Layout $Layout | Out-Null
        $current = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $Layout
        return [pscustomobject]@{
            Path = $current.Path
            Changed = $false
            MarkerSha256 = $current.Sha256
            PriorAcl = 'already-protected'
        }
    } catch {
        # Only the one explicitly recognized inherited legacy DACL may cross
        # this migration boundary. All other marker failures remain fatal.
    }

    $markerIdentityLease = $null
    $clientMutex = $null
    $serverMutex = $null
    $ownsClientMutex = $false
    $ownsServerMutex = $false
    try {
        $markerIdentityLease = Open-PSOBBRuntimeMarkerIdentityLease `
            -Layout $Layout
        $initial = Assert-PSOBBLegacyRuntimeMarkerAclState `
            -Layout $Layout -IdentityLease $markerIdentityLease
        $clientMutex = [System.Threading.Mutex]::new(
            $false,
            "Local\PSOBB.Client.$($initial.InstallationId.ToString('D'))")
        try {
            $ownsClientMutex = $clientMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsClientMutex = $true
        }
        if (-not $ownsClientMutex) {
            throw 'Another PSOBB client or runtime operation is in progress'
        }

        $serverMutex = [System.Threading.Mutex]::new(
            $false,
            ('Local\PSOBB.Newserv.Start.' +
                $initial.InstallationId.ToString('N')))
        try {
            $ownsServerMutex = $serverMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsServerMutex = $true
        }
        if (-not $ownsServerMutex) {
            throw 'Another PSOBB lifecycle operation is in progress'
        }

        $stoppedAuthority = Assert-PSOBBRuntimeMarkerMigrationStopped `
            -Layout $Layout
        $locked = Assert-PSOBBLegacyRuntimeMarkerAclState `
            -Layout $Layout -IdentityLease $markerIdentityLease
        if ($locked.Length -ne $initial.Length -or
            $locked.Sha256 -cne $initial.Sha256 -or
            $locked.VolumeSerialNumber -ne $initial.VolumeSerialNumber -or
            $locked.FileIndex -ne $initial.FileIndex -or
            $locked.NumberOfLinks -ne 1 -or
            $locked.AccessSddl -cne $initial.AccessSddl -or
            $locked.OwnerSid -cne $initial.OwnerSid -or
            $locked.GroupSid -cne $initial.GroupSid) {
            throw 'The legacy runtime marker changed before ACL migration'
        }

        $mutationState = [pscustomobject]@{
            Attempted = $false
            ProtectedAccessSddl = $null
        }
        try {
            if ($InternalBeforeWriteAction) {
                & $InternalBeforeWriteAction $markerIdentityLease
            }
            Set-PSOBBRuntimeMarkerProtectedDacl `
                -Layout $Layout -IdentityLease $markerIdentityLease `
                -StoppedAuthority $stoppedAuthority `
                -ExpectedLegacyState $locked `
                -MutationState $mutationState
            if ($InternalAfterWriteAction) {
                & $InternalAfterWriteAction `
                    $markerIdentityLease $stoppedAuthority
            }

            $after = Get-PSOBBRuntimeMarkerMetadataSnapshot `
                -Layout $Layout -IdentityLease $markerIdentityLease
            if ($after.Length -ne $locked.Length -or
                $after.Sha256 -cne $locked.Sha256 -or
                $after.VolumeSerialNumber -ne $locked.VolumeSerialNumber -or
                $after.FileIndex -ne $locked.FileIndex -or
                $after.NumberOfLinks -ne 1 -or
                $after.OwnerSid -cne $locked.OwnerSid -or
                $after.GroupSid -cne $locked.GroupSid -or
                -not (Test-PSOBBProtectedAcl -Path $locked.Path)) {
                throw 'Runtime-marker ACL migration did not preserve exact file and ownership state'
            }
            Assert-PSOBBRuntimeMarker -Layout $Layout | Out-Null
            [pscustomobject]@{
                Path = $after.Path
                Changed = $true
                MarkerSha256 = $after.Sha256
                PriorAcl = 'known-legacy-inherited'
            }
        } catch {
            $migrationFailure = $_
            if ([bool]$mutationState.Attempted) {
                try {
                    if ([string]::IsNullOrWhiteSpace(
                            [string]$mutationState.ProtectedAccessSddl)) {
                        throw ('The exact post-write protected DACL was not ' +
                            'captured; legacy rollback is unsafe')
                    }
                    $rollbackCandidate = Get-PSOBBRuntimeMarkerMetadataSnapshot `
                        -Layout $Layout -IdentityLease $markerIdentityLease `
                        -AllowAdditionalHardLinks
                    Assert-PSOBBRuntimeMarkerMetadataMatches `
                        -Actual $rollbackCandidate -Expected $locked `
                        -ExpectedAccessSddl `
                            ([string]$mutationState.ProtectedAccessSddl) `
                        -Boundary 'rollback candidate DACL' `
                        -AllowAdditionalHardLinks | Out-Null
                    Set-PSOBBRuntimeMarkerLegacyRollbackDacl `
                        -Layout $Layout `
                        -IdentityLease $markerIdentityLease `
                        -StoppedAuthority $stoppedAuthority `
                        -ExpectedLegacyState $locked `
                        -ExpectedProtectedAccessSddl `
                            ([string]$mutationState.ProtectedAccessSddl)
                    $rolledBack = Assert-PSOBBLegacyRuntimeMarkerAclState `
                        -Layout $Layout -IdentityLease $markerIdentityLease `
                        -AllowAdditionalHardLinks
                    if ($rolledBack.Length -ne $locked.Length -or
                        $rolledBack.Sha256 -cne $locked.Sha256 -or
                        $rolledBack.VolumeSerialNumber -ne
                            $locked.VolumeSerialNumber -or
                        $rolledBack.FileIndex -ne $locked.FileIndex -or
                        $rolledBack.AccessSddl -cne $locked.AccessSddl -or
                        $rolledBack.OwnerSid -cne $locked.OwnerSid -or
                        $rolledBack.GroupSid -cne $locked.GroupSid) {
                        throw 'Legacy runtime-marker DACL rollback did not read back exactly'
                    }
                    if ($rolledBack.NumberOfLinks -ne 1) {
                        throw ('Legacy runtime-marker DACL rollback completed, ' +
                            'but a hard-link identity race requires operator review')
                    }
                } catch {
                    throw ('Runtime-marker ACL migration failed and exact DACL ' +
                        'rollback also failed. Migration: ' +
                        $migrationFailure.Exception.Message + ' Rollback: ' +
                        $_.Exception.Message)
                }
            }
            throw $migrationFailure
        }
    } finally {
        try {
            if ($ownsServerMutex) {
                $serverMutex.ReleaseMutex()
            }
            if ($serverMutex) {
                $serverMutex.Dispose()
            }
        } finally {
            try {
                if ($ownsClientMutex) {
                    $clientMutex.ReleaseMutex()
                }
                if ($clientMutex) {
                    $clientMutex.Dispose()
                }
            } finally {
                if ($markerIdentityLease) {
                    Close-PSOBBRuntimeMarkerIdentityLease `
                        -IdentityLease $markerIdentityLease
                }
            }
        }
    }
}

function Get-PSOBBRuntimeAclTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($target in @(
        [pscustomobject]@{
            Name = 'licenses'
            Path = Join-Path $Layout.Server 'system\licenses'
        },
        [pscustomobject]@{
            Name = 'players'
            Path = Join-Path $Layout.Server 'system\players'
        },
        [pscustomobject]@{
            Name = 'teams'
            Path = Join-Path $Layout.Server 'system\teams'
        },
        [pscustomobject]@{
            Name = 'secrets'
            Path = $Layout.Secrets
        },
        [pscustomobject]@{
            Name = 'backups'
            Path = $Layout.Backups
        },
        [pscustomobject]@{
            Name = 'logs'
            Path = $Layout.Logs
        },
        [pscustomobject]@{
            Name = 'graphics-evidence'
            Path = Join-Path $Layout.Root 'graphics-evidence'
        },
        [pscustomobject]@{
            Name = 'local-asset-archives'
            Path = Join-Path $Layout.Archives 'graphics-lab\local-assets'
        },
        [pscustomobject]@{
            Name = 'local-asset-overlays'
            Path = Join-Path $Layout.LocalLab 'asset-overlays'
        },
        [pscustomobject]@{
            Name = 'local-asset-activations'
            Path = Join-Path $Layout.LocalLab 'asset-activations'
        },
        [pscustomobject]@{
            Name = 'supplemental-asset-activations'
            Path = Join-Path $Layout.LocalLab 'visual-asset-activations'
        }
    )) {
        [void]$targets.Add($target)
    }

    $combatCanary = Get-PSOBBServerEnvironmentLayout `
        -Layout $Layout -Environment CombatCanary
    foreach ($definition in @(
        [pscustomobject]@{
            Name = 'combat-canary-licenses'
            Path = Join-Path $combatCanary.Server 'system\licenses'
        },
        [pscustomobject]@{
            Name = 'combat-canary-players'
            Path = Join-Path $combatCanary.Server 'system\players'
        },
        [pscustomobject]@{
            Name = 'combat-canary-teams'
            Path = Join-Path $combatCanary.Server 'system\teams'
        },
        [pscustomobject]@{
            Name = 'combat-canary-secrets'
            Path = $combatCanary.Secrets
        },
        [pscustomobject]@{
            Name = 'combat-canary-backups'
            Path = $combatCanary.Backups
        },
        [pscustomobject]@{
            Name = 'combat-canary-logs'
            Path = $combatCanary.Logs
        },
        [pscustomobject]@{
            Name = 'combat-canary-snapshots'
            Path = $combatCanary.Snapshots
        },
        [pscustomobject]@{
            Name = 'combat-canary-control'
            Path = $combatCanary.ControlDirectory
        },
        [pscustomobject]@{
            Name = 'combat-canary-builds'
            Path = $combatCanary.Builds
        },
        [pscustomobject]@{
            Name = 'combat-canary-evidence'
            Path = Join-Path $combatCanary.EnvironmentRoot 'evidence'
        }
    )) {
        # The combat canary is materialized later than the stable runtime. Its
        # sensitive trees join the policy as soon as they exist; an unsafe file
        # or reparse point at an expected directory still joins and fails closed.
        if (Test-Path -LiteralPath $definition.Path) {
            [void]$targets.Add($definition)
        }
    }

    @($targets)
}

function Get-PSOBBRuntimeAclTargetItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Target
    )

    $safeTarget = Assert-PathWithinRoot -Path ([string]$Target.Path) -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $safeTarget -PathType Container)) {
        throw "Sensitive runtime directory is missing: $safeTarget"
    }

    # Walk one proven directory at a time. Assert-PathWithinRoot checks every
    # existing ancestor for reparse points before the item can be returned or
    # a child directory can be entered.
    $items = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($safeTarget)

    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        $safeDirectory = Assert-PathWithinRoot -Path $directory -Root $Layout.Root
        $directoryItem = Get-Item -LiteralPath $safeDirectory -Force
        if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Sensitive runtime tree contains a reparse point: $($directoryItem.FullName)"
        }
        if ($seen.Add($directoryItem.FullName)) {
            [void]$items.Add($directoryItem)
        }

        foreach ($child in @(Get-ChildItem -LiteralPath $safeDirectory -Force |
                Sort-Object -Property FullName)) {
            $safeChild = Assert-PathWithinRoot -Path $child.FullName -Root $Layout.Root
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Sensitive runtime tree contains a reparse point: $safeChild"
            }
            if ($child.PSIsContainer) {
                $pending.Enqueue($safeChild)
            } elseif ($seen.Add($safeChild)) {
                [void]$items.Add($child)
            }
        }
    }

    $items
}

function Get-PSOBBLifecycleAclPrincipals {
    [CmdletBinding()]
    param()

    @(Get-PSOBBRuntimeAclPrincipals)
}

function New-PSOBBLifecycleDacl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][bool]$IsContainer)

    $security = if ($IsContainer) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $security.SetOwner($currentUser)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($principal in @(Get-PSOBBLifecycleAclPrincipals)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    $security
}

function Assert-PSOBBLifecyclePathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$IsContainer
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    if (-not (Test-Path -LiteralPath $safePath)) {
        throw "Protected lifecycle path is missing: $safePath"
    }
    $item = Get-Item -LiteralPath $safePath -Force
    if ($item.PSIsContainer -ne $IsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Protected lifecycle path has an invalid filesystem type: $safePath"
    }

    $acl = Get-Acl -LiteralPath $safePath
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -cne $currentUserSid) {
        throw "Protected lifecycle path owner is not the current user: $safePath"
    }
    if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) {
        throw "Protected lifecycle path does not have one canonical protected DACL: $safePath"
    }

    $expectedSids = @(Get-PSOBBLifecycleAclPrincipals |
        ForEach-Object { $_.Value } | Sort-Object -Unique)
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expectedSids.Count) {
        throw "Protected lifecycle path DACL does not contain exactly $($expectedSids.Count) rules: $safePath"
    }
    $actualSids = @($rules | ForEach-Object {
            $_.IdentityReference.Value
        } | Sort-Object -Unique)
    if ($actualSids.Count -ne $expectedSids.Count -or
        @(Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids).Count -ne 0) {
        throw "Protected lifecycle path DACL identities are not exact: $safePath"
    }

    $expectedInheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            [int64]$rule.FileSystemRights -ne
                [int64][System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None) {
            throw "Protected lifecycle path DACL rule is not exact: $safePath"
        }
    }
    $safePath
}

function Set-PSOBBLifecyclePathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $item = Get-Item -LiteralPath $safePath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to protect a lifecycle reparse point: $safePath"
    }
    $security = New-PSOBBLifecycleDacl -IsContainer $item.PSIsContainer
    if ($item.PSIsContainer) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo]$item,
            [System.Security.AccessControl.DirectorySecurity]$security)
    } else {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo]$item,
            [System.Security.AccessControl.FileSecurity]$security)
    }
    Assert-PSOBBLifecyclePathAcl `
        -Path $safePath -Root $Root -IsContainer $item.PSIsContainer
}

function Initialize-PSOBBLifecycleControlDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $property = $Layout.PSObject.Properties['ControlDirectory']
    if ($null -eq $property -or
        [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw 'The runtime layout does not declare a lifecycle control directory'
    }
    $controlDirectory = Assert-PathWithinRoot `
        -Path ([string]$property.Value) -Root $Layout.Root
    if (Test-Path -LiteralPath $controlDirectory) {
        return Assert-PSOBBLifecyclePathAcl `
            -Path $controlDirectory -Root $Layout.Root -IsContainer $true
    }

    $parent = Split-Path -Parent $controlDirectory
    $safeParent = Assert-PathWithinRoot -Path $parent -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $safeParent -PathType Container)) {
        throw "Lifecycle control directory parent is missing: $safeParent"
    }
    $temporary = Assert-PathWithinRoot `
        -Path (Join-Path $safeParent (
            '.newserv-control.' + [Guid]::NewGuid().ToString('N') + '.new')) `
        -Root $Layout.Root
    [void][System.IO.Directory]::CreateDirectory($temporary)
    try {
        Set-PSOBBLifecyclePathAcl -Path $temporary -Root $Layout.Root | Out-Null
        [System.IO.Directory]::Move($temporary, $controlDirectory)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Container) {
            try { [System.IO.Directory]::Delete($temporary, $false) } catch { }
        }
    }
    Assert-PSOBBLifecyclePathAcl `
        -Path $controlDirectory -Root $Layout.Root -IsContainer $true
}

function Get-PSOBBRetiredLifecyclePaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    @(
        'newserv.process.json',
        'newserv.pid',
        'newserv-host.pid',
        'newserv-control.json',
        'newserv-control.request.json'
    ) | ForEach-Object {
        Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Stable $_) -Root $Layout.Root
    }
}

function Remove-PSOBBRetiredLifecycleFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    foreach ($path in @(Get-PSOBBRetiredLifecyclePaths -Layout $Layout)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            if ($item.PSIsContainer -or
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Retired lifecycle path has an unsafe filesystem type: $path"
            }
            $safePath = Assert-PathWithinRoot -Path $path -Root $Layout.Root
            Remove-Item -LiteralPath $safePath -Force -ErrorAction Stop
        }
    }
}
