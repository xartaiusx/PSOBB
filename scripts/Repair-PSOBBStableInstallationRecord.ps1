[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,
    [Parameter(DontShow = $true)]
    [switch]$MigrateLegacyStableInstallationRecordAcl,
    [Parameter(DontShow = $true)][string]$InternalTestSourcesLockPath,
    [Parameter(DontShow = $true)][string]$InternalTestPolicyPath,
    [Parameter(DontShow = $true)][string[]]$InternalTestFaultPoints,
    [Parameter(DontShow = $true)][string]$InternalTestFaultToken,
    [Parameter(DontShow = $true)][string]$InternalTestHookPoint,
    [Parameter(DontShow = $true)][scriptblock]$InternalTestHook
)

if ($PSBoundParameters.ContainsKey(
        'MigrateLegacyStableInstallationRecordAcl') -and
    -not $MigrateLegacyStableInstallationRecordAcl) {
    throw 'Installation-record ACL mode requires its explicit migration switch'
}

$script:MigrationInternalTestRequested = $false
foreach ($parameterName in @(
        'InternalTestSourcesLockPath', 'InternalTestPolicyPath',
        'InternalTestFaultPoints', 'InternalTestFaultToken',
        'InternalTestHookPoint', 'InternalTestHook')) {
    if ($PSBoundParameters.ContainsKey($parameterName)) {
        $script:MigrationInternalTestRequested = $true
        break
    }
}

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.CombatCanary.Common.ps1')

$script:KnownLegacyPolicySha256 =
    'f3501e6cff0d2fd69b0792036c1361ad521f7b3abfec4d695632c6fcc9c0fffb'
$script:MigrationPurpose = 'stable-installation-record-migration'
$script:MigrationMarkerName = '.psobb-combat-canary-transaction.json'
$script:MigrationTestArmed = $false
$script:MigrationHookConsumed = $false
$script:MigrationFaultsConsumed = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)

function Get-MigrationSha256([byte[]]$Bytes) {
    $digest = [System.Security.Cryptography.SHA256]::HashData($Bytes)
    try { ([Convert]::ToHexString($digest)).ToLowerInvariant() } finally {
        [Array]::Clear($digest, 0, $digest.Length)
    }
}

function Read-MigrationSnapshot(
    [string]$Path,
    [string]$Root,
    [long]$MaximumBytes,
    [string]$Label,
    [long]$ExpectedLength = -1,
    [string]$ExpectedSha256 = '',
    [switch]$Json
) {
    $consumer = if ($Json) {
        {
            param([byte[]]$Bytes)
            $document = $null
            try {
                if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and
                    $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
                    throw 'BOM-prefixed JSON is not accepted'
                }
                $text = [System.Text.UTF8Encoding]::new(
                    $false, $true).GetString($Bytes)
                $options = [System.Text.Json.JsonDocumentOptions]::new()
                $options.AllowTrailingCommas = $false
                $options.CommentHandling =
                    [System.Text.Json.JsonCommentHandling]::Disallow
                $options.MaxDepth = 24
                $document = [System.Text.Json.JsonDocument]::Parse($text, $options)
                Test-PSOBBStrictJsonPropertyUniqueness `
                    -Element $document.RootElement -Path '$' | Out-Null
                ConvertFrom-PSOBBStrictDataJsonElement `
                    -Element $document.RootElement -Label $Label
            } finally {
                if ($null -ne $document) { $document.Dispose() }
            }
        }
    } else {
        { param([byte[]]$Bytes) $Bytes.Length }
    }
    $parameters = @{
        LiteralPath = $Path
        Root = $Root
        MaximumBytes = $MaximumBytes
        RoleLabel = $Label
        Consumer = $consumer
    }
    if ($ExpectedLength -ge 0) { $parameters.ExpectedLength = $ExpectedLength }
    if ($ExpectedSha256) { $parameters.ExpectedSha256 = $ExpectedSha256 }
    Invoke-PSOBBCombatCanaryBoundedFileSnapshot @parameters
}

function Test-MigrationIdentity($Left, $Right) {
    [uint32]$Left.VolumeSerialNumber -eq [uint32]$Right.VolumeSerialNumber -and
        [uint64]$Left.FileId -eq [uint64]$Right.FileId
}

function Get-MigrationInstallationAclState($Layout, $Lease) {
    [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
            -Context $Lease -RoleLabel 'Stable installation record ACL lease')
    $digest = Get-PSOBBLeasedFileDigest `
        -Lease $Lease.Stream -MaximumBytes 256KB `
        -Label 'Stable installation record ACL lease'
    $acl = Get-Acl -LiteralPath $Lease.Path
    [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
            -Context $Lease -RoleLabel 'Stable installation record ACL lease')
    $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
        -Handle $Lease.Stream.SafeFileHandle -ExpectedPath $Lease.Path `
        -Root $Layout.Root -Directory $false `
        -RoleLabel 'Stable installation record ACL lease' -RequireSingleLink
    [pscustomobject]@{
        Path = [string]$Lease.Path
        Length = [long]$digest.Length
        Sha256 = [string]$digest.Sha256
        VolumeSerialNumber = [uint32]$identity.VolumeSerialNumber
        FileId = [uint64]$identity.FileId
        NumberOfLinks = [uint32]$identity.NumberOfLinks
        Acl = $acl
        AccessSddl = $acl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access)
        OwnerSid = $acl.GetOwner(
            [System.Security.Principal.SecurityIdentifier]).Value
        GroupSid = $acl.GetGroup(
            [System.Security.Principal.SecurityIdentifier]).Value
    }
}

function Get-MigrationAclPrincipalSids {
    @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-32-544',
        'S-1-5-18'
    ) | Sort-Object -Unique
}

function Assert-MigrationApprovedAclOwnership($State) {
    $expectedSids = @(Get-MigrationAclPrincipalSids)
    if ($State.OwnerSid -notin $expectedSids -or
        $State.GroupSid -notin $expectedSids) {
        throw ('The Stable installation record owner or group is not an ' +
            'approved runtime principal')
    }
    $true
}

function Assert-MigrationLegacyInstallationAclState(
    $Layout, $Lease, $ExpectedRecordSnapshot) {
    $state = Get-MigrationInstallationAclState $Layout $Lease
    if ($state.Length -ne [long]$ExpectedRecordSnapshot.Length -or
        $state.Sha256 -cne [string]$ExpectedRecordSnapshot.Sha256 -or
        $state.VolumeSerialNumber -ne
            [uint32]$ExpectedRecordSnapshot.VolumeSerialNumber -or
        $state.FileId -ne [uint64]$ExpectedRecordSnapshot.FileId -or
        $state.NumberOfLinks -ne 1) {
        throw 'The legacy Stable installation record identity is not exact'
    }
    [void](Assert-MigrationApprovedAclOwnership $state)
    $acl = $state.Acl
    if ($acl.AreAccessRulesProtected -or
        -not $acl.AreAccessRulesCanonical) {
        throw ('The Stable installation record does not have the one accepted ' +
            'legacy ACL shape')
    }
    $expectedSids = @(Get-MigrationAclPrincipalSids)
    $rules = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]))
    $actualSids = @($rules | ForEach-Object {
            $_.IdentityReference.Value
        } | Sort-Object -Unique)
    if ($rules.Count -ne $expectedSids.Count -or
        $actualSids.Count -ne $expectedSids.Count -or
        @(Compare-Object -ReferenceObject $expectedSids `
                -DifferenceObject $actualSids).Count -ne 0) {
        throw 'The legacy Stable installation record ACL identities are not exact'
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
            throw ('The legacy Stable installation record ACL rules are not ' +
                'exact inherited FullControl rules')
        }
    }
    $state
}

function Assert-MigrationInstallationAclStateMatches(
    $Actual, $Expected, [string]$ExpectedAccessSddl, [string]$Boundary) {
    if ([string]$Actual.Path -ine [string]$Expected.Path -or
        $Actual.Length -ne $Expected.Length -or
        $Actual.Sha256 -cne $Expected.Sha256 -or
        $Actual.VolumeSerialNumber -ne $Expected.VolumeSerialNumber -or
        $Actual.FileId -ne $Expected.FileId -or
        $Actual.NumberOfLinks -ne 1 -or
        $Actual.AccessSddl -cne $ExpectedAccessSddl -or
        $Actual.OwnerSid -cne $Expected.OwnerSid -or
        $Actual.GroupSid -cne $Expected.GroupSid) {
        throw "Stable installation record state is not exact at $Boundary"
    }
    $true
}

function Set-MigrationInstallationAccessDacl(
    $Layout, $Lease, [string]$AccessSddl) {
    [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
            -Context $Lease -RoleLabel 'Stable installation record ACL lease')
    $safePath = Assert-PSOBBOrdinaryContainedPath `
        -Path $Lease.Path -Root $Layout.Root -Kind File `
        -Label 'Stable installation record'
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        $AccessSddl,
        [System.Security.AccessControl.AccessControlSections]::Access)
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $safePath),
        $security)
}

function ConvertTo-MigrationFileId([uint64]$FileId) {
    '{0:x16}' -f $FileId
}

function ConvertFrom-MigrationFileId([string]$FileId) {
    [uint64]$value = 0
    if ($FileId -cnotmatch '^[a-f0-9]{16}$' -or
        -not [uint64]::TryParse(
            $FileId,
            [System.Globalization.NumberStyles]::HexNumber,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$value)) {
        throw 'Installation-record migration journal has an invalid file ID'
    }
    $value
}

function Read-MigrationTransactionMarker(
    [string]$TransactionRoot,
    [string]$TransactionBoundary,
    $RootIdentity,
    $ExpectedTransaction = $null
) {
    $markerPath = Join-Path $TransactionRoot $script:MigrationMarkerName
    $snapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $markerPath -Root $TransactionRoot -MaximumBytes 4KB `
        -PassThruSnapshot -RoleLabel 'Installation migration marker'
    $marker = $snapshot.Value
    $properties = @($marker.Properties())
    $expectedProperties = @('schemaVersion', 'transactionId', 'purpose',
        'rootVolumeSerialNumber', 'rootFileId')
    $transactionId = $marker['transactionId']
    $purpose = $marker['purpose']
    $volume = $marker['rootVolumeSerialNumber']
    $fileId = $marker['rootFileId']
    if ($properties.Count -ne $expectedProperties.Count -or
        @(Compare-Object @($expectedProperties | Sort-Object) `
                @($properties.Name | Sort-Object)).Count -ne 0 -or
        $transactionId.Type -ne
            [Newtonsoft.Json.Linq.JTokenType]::String -or
        [string]$transactionId.Value -cnotmatch '^[a-f0-9]{32}$' -or
        $purpose.Type -ne [Newtonsoft.Json.Linq.JTokenType]::String -or
        [string]$purpose.Value -cne $script:MigrationPurpose -or
        $volume.Type -ne [Newtonsoft.Json.Linq.JTokenType]::Integer -or
        [uint64]$volume.Value -ne [uint32]$RootIdentity.VolumeSerialNumber -or
        $fileId.Type -ne [Newtonsoft.Json.Linq.JTokenType]::String -or
        [string]$fileId.Value -cnotmatch '^[a-f0-9]{16}$' -or
        (ConvertFrom-MigrationFileId ([string]$fileId.Value)) -ne
            [uint64]$RootIdentity.FileId) {
        throw 'Installation migration marker is not exact and identity-bound'
    }
    $transaction = [pscustomobject]@{
        Path = $TransactionRoot
        Root = $TransactionBoundary
        TransactionId = [string]$transactionId.Value
        Purpose = $script:MigrationPurpose
        VolumeSerialNumber = [uint32]$RootIdentity.VolumeSerialNumber
        FileId = [uint64]$RootIdentity.FileId
        MarkerPath = $markerPath
        MarkerLength = [long]$snapshot.Length
        MarkerSha256 = [string]$snapshot.Sha256
        MarkerVolumeSerialNumber = [uint32]$snapshot.VolumeSerialNumber
        MarkerFileId = [uint64]$snapshot.FileId
    }
    [void](Assert-PSOBBCombatCanaryTransactionMarker `
            -Transaction $transaction -Marker $marker)
    if ($null -ne $ExpectedTransaction -and
        ([string]$transaction.TransactionId -cne
            [string]$ExpectedTransaction.TransactionId -or
         [uint32]$transaction.VolumeSerialNumber -ne
            [uint32]$ExpectedTransaction.VolumeSerialNumber -or
         [uint64]$transaction.FileId -ne [uint64]$ExpectedTransaction.FileId -or
         [long]$transaction.MarkerLength -ne
            [long]$ExpectedTransaction.MarkerLength -or
         [string]$transaction.MarkerSha256 -cne
            [string]$ExpectedTransaction.MarkerSha256 -or
         [uint32]$transaction.MarkerVolumeSerialNumber -ne
            [uint32]$ExpectedTransaction.MarkerVolumeSerialNumber -or
         [uint64]$transaction.MarkerFileId -ne
            [uint64]$ExpectedTransaction.MarkerFileId)) {
        throw 'Installation migration marker identity changed'
    }
    $transaction
}

function Assert-MigrationInternalTestGate($Layout, $Marker) {
    $requested = $script:MigrationInternalTestRequested
    if (-not $requested) { return $true }
    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root).TrimEnd('\')
    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $fixtureMarker = Join-Path $root `
        '.stable-installation-record-migration-test.json'
    if (-not $InternalTestSourcesLockPath -or -not $InternalTestPolicyPath -or
        -not $InternalTestFaultToken -or
        [string]$Marker.installationId -cne $InternalTestFaultToken -or
        (($InternalTestHookPoint -or $null -ne $InternalTestHook) -and
            (-not $InternalTestHookPoint -or $null -eq $InternalTestHook)) -or
        -not $root.StartsWith(
            $temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($root) -cnotmatch
            '^PSOBB-StableInstallationRecordMigrationTests-[a-f0-9]{32}$' -or
        -not (Test-PSOBBProtectedAcl -Path $fixtureMarker)) {
        throw 'Internal migration controls require one exact protected temporary fixture'
    }
    foreach ($path in @(
            $fixtureMarker,
            $InternalTestSourcesLockPath,
            $InternalTestPolicyPath)) {
        if (-not (Test-PSOBBProtectedAcl -Path $path)) {
            throw 'Internal migration fixture inputs must have exact protected ACLs'
        }
        [void](Read-MigrationSnapshot `
                -Path $path -Root $root -MaximumBytes 8MB `
                -Label 'Migration test input')
    }
    $script:MigrationTestArmed = $true
    $true
}

function Invoke-MigrationBoundary([string]$Point, $Context) {
    if ($script:MigrationTestArmed -and -not $script:MigrationHookConsumed -and
        $InternalTestHookPoint -ceq $Point) {
        $script:MigrationHookConsumed = $true
        & $InternalTestHook $Context
    }
    if ($script:MigrationTestArmed -and
        $Point -cin @($InternalTestFaultPoints) -and
        $script:MigrationFaultsConsumed.Add($Point)) {
        throw "Injected installation-record migration fault at $Point"
    }
}

function Get-MigrationBindings([string]$SourcesPath, [string]$PolicyPath,
    [string]$Root) {
    $sources = Read-MigrationSnapshot `
        -Path $SourcesPath -Root $Root -MaximumBytes 8MB `
        -Label 'Migration source lock' -Json
    $lock = $sources.Value
    Assert-PSOBBStrictDataObjectProperties -Value $lock -Expected @(
        'schemaVersion', 'generatedAtUtc', 'components', 'behaviorReferences') `
        -Label 'migration source lock' | Out-Null
    if ($lock.schemaVersion -isnot [long] -or $lock.schemaVersion -ne 1 -or
        $lock.components -isnot [System.Array]) {
        throw 'Migration source-lock root is invalid'
    }
    $components = @{}
    foreach ($id in @('newserv-stable-release', 'tethealla-59nl-english',
            'dgvoodoo2-x86-d3d8')) {
        $componentMatches = @($lock.components | Where-Object {
                $_ -is [pscustomobject] -and $_.PSObject.Properties['id'] -and
                [string]$_.id -ceq $id
            })
        if ($componentMatches.Count -ne 1 -or
            $componentMatches[0].version -isnot [string] -or
            $componentMatches[0].size -isnot [long] -or
            [long]$componentMatches[0].size -le 0 -or
            [string]$componentMatches[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $componentMatches[0].members -isnot [System.Array]) {
            throw "Migration source lock lacks one valid $id component"
        }
        $components[$id] = $componentMatches[0]
    }
    function Get-MigrationMember($Component, [string]$Path) {
        $memberMatches = @($Component.members | Where-Object {
                [string]$_.path -ceq $Path
            })
        if ($memberMatches.Count -ne 1 -or
            $memberMatches[0].size -isnot [long] -or
            [long]$memberMatches[0].size -le 0 -or
            [string]$memberMatches[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw "Migration source lock lacks one valid member: $Path"
        }
        $memberMatches[0]
    }
    $policy = Read-MigrationSnapshot `
        -Path $PolicyPath -Root $Root -MaximumBytes 1MB `
        -Label 'Migration patch policy' -Json
    Assert-PSOBBStrictDataObjectProperties -Value $policy.Value -Expected @(
        'schemaVersion', 'defaultProfile', 'profiles', 'gated') `
        -Label 'migration client-patch policy' | Out-Null
    $baseline = @($policy.Value.profiles | Where-Object {
            $_ -is [pscustomobject] -and [string]$_.id -ceq 'baseline'
        })
    if ($baseline.Count -eq 1) {
        Assert-PSOBBStrictDataObjectProperties -Value $baseline[0] -Expected @(
            'id', 'channel', 'description', 'autoPatches',
            'bbRequiredPatches') -Label 'migration baseline profile' | Out-Null
    }
    if ($policy.Value.schemaVersion -isnot [long] -or
        $policy.Value.schemaVersion -ne 1 -or
        [string]$policy.Value.defaultProfile -cne 'baseline' -or
        $baseline.Count -ne 1 -or [string]$baseline[0].channel -cne 'stable' -or
        $baseline[0].autoPatches -isnot [System.Array] -or
        $baseline[0].bbRequiredPatches -isnot [System.Array] -or
        @($baseline[0].autoPatches).Count -ne 0 -or
        @($baseline[0].bbRequiredPatches).Count -ne 0 -or
        $policy.Sha256 -ceq $script:KnownLegacyPolicySha256) {
        throw 'Current policy lacks one empty Stable baseline distinct from the known legacy policy'
    }
    $server = $components['newserv-stable-release']
    $client = $components['tethealla-59nl-english']
    $renderer = $components['dgvoodoo2-x86-d3d8']
    [pscustomobject]@{
        SourceLockSha256 = [string]$sources.Sha256
        PolicySha256 = [string]$policy.Sha256
        Server = $server
        ServerExe = Get-MigrationMember $server 'release/newserv-windows.exe'
        Client = $client
        ClientExe = Get-MigrationMember $client 'Psobb.exe'
        Renderer = $renderer
        RendererDll = Get-MigrationMember $renderer 'MS/x86/D3D8.dll'
        RendererConfig = Get-MigrationMember $renderer 'dgVoodoo.conf'
    }
}

function Get-MigrationLegacyProperties {
    @('schemaVersion', 'installationId', 'initializedAtUtc', 'runtimeRoot',
        'serverVersion', 'serverArchiveSha256', 'serverExecutableSha256',
        'serverBaseManifestSha256', 'clientVersion', 'clientArchiveSha256',
        'baseClientExecutableSha256', 'baseClientManifestSha256',
        'clientExecutableSha256', 'patchManifestSha256',
        'synchronizedPatchFiles', 'clientPatchProfile',
        'clientPatchPolicySha256', 'networkScope')
}

function Test-MigrationShape($Record, [string[]]$Properties) {
    $actual = @($Record.PSObject.Properties.Name)
    $actual.Count -eq $Properties.Count -and
        @(Compare-Object -ReferenceObject @($Properties | Sort-Object) `
            -DifferenceObject @($actual | Sort-Object)).Count -eq 0
}

function Assert-MigrationLegacyRecord(
    $Record, $Layout, $Marker, $Bindings, $RuntimeState) {
    $properties = Get-MigrationLegacyProperties
    Assert-PSOBBStrictDataObjectProperties -Value $Record `
        -Expected $properties -Label 'legacy Stable installation record' |
        Out-Null
    foreach ($name in @($properties | Where-Object {
                $_ -notin @('schemaVersion', 'synchronizedPatchFiles')
            })) {
        if ($Record.$name -isnot [string]) {
            throw "Legacy Stable installation property '$name' is not text"
        }
    }
    foreach ($name in @($properties | Where-Object { $_ -like '*Sha256' })) {
        if ([string]$Record.$name -cnotmatch '^[a-f0-9]{64}$') {
            throw "Legacy Stable installation property '$name' is not a SHA-256"
        }
    }
    $parsedId = [Guid]::Empty
    $parsedTime = [DateTimeOffset]::MinValue
    if ($Record.schemaVersion -isnot [long] -or $Record.schemaVersion -ne 2 -or
        $Record.synchronizedPatchFiles -isnot [long] -or
        [long]$Record.synchronizedPatchFiles -lt 0 -or
        [long]$Record.synchronizedPatchFiles -ne
            [long]$RuntimeState.PatchFileCount -or
        -not [Guid]::TryParseExact(
            [string]$Record.installationId, 'D', [ref]$parsedId) -or
        -not [DateTimeOffset]::TryParse(
            [string]$Record.initializedAtUtc, [ref]$parsedTime) -or
        [string]$Record.installationId -cne [string]$Marker.installationId -or
        -not ([System.IO.Path]::GetFullPath(
                [string]$Record.runtimeRoot).TrimEnd('\')).Equals(
            [string]$Layout.Root,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]$Record.clientPatchProfile -cne 'baseline' -or
        [string]$Record.clientPatchPolicySha256 -cne
            $script:KnownLegacyPolicySha256 -or
        [string]$Record.networkScope -cne 'loopback-only' -or
        [string]$Record.serverVersion -cne [string]$Bindings.Server.version -or
        [string]$Record.serverArchiveSha256 -cne
            [string]$Bindings.Server.sha256 -or
        [string]$Record.serverExecutableSha256 -cne
            [string]$Bindings.ServerExe.sha256 -or
        [string]$Record.clientVersion -cne [string]$Bindings.Client.version -or
        [string]$Record.clientArchiveSha256 -cne
            [string]$Bindings.Client.sha256 -or
        [string]$Record.baseClientExecutableSha256 -cne
            [string]$Bindings.ClientExe.sha256 -or
        [string]$Record.clientExecutableSha256 -cne
            [string]$Bindings.ClientExe.sha256) {
        throw 'Stable installation record is not the exact known pre-bb4be91 baseline state'
    }
    $Record
}

function Read-MigrationPatchManifest($Layout, $Record, $Bindings) {
    $path = Join-Path $Layout.Stable 'patch-bb-data.manifest.json'
    $snapshot = Read-MigrationSnapshot `
        -Path $path -Root $Layout.Root -MaximumBytes 16MB `
        -ExpectedSha256 ([string]$Record.patchManifestSha256) `
        -Label 'Stable patch-data manifest' -Json
    $manifest = $snapshot.Value
    Assert-PSOBBStrictDataObjectProperties -Value $manifest -Expected @(
        'schemaVersion', 'sourceClientArchiveSha256', 'generatedAtUtc', 'files') `
        -Label 'Stable patch-data manifest' | Out-Null
    $generatedAt = [DateTimeOffset]::MinValue
    if ($manifest.schemaVersion -isnot [long] -or
        $manifest.schemaVersion -ne 1 -or
        $manifest.sourceClientArchiveSha256 -isnot [string] -or
        [string]$manifest.sourceClientArchiveSha256 -cne
            [string]$Bindings.Client.sha256 -or
        $manifest.generatedAtUtc -isnot [string] -or
        -not [DateTimeOffset]::TryParse(
            [string]$manifest.generatedAtUtc, [ref]$generatedAt) -or
        $manifest.files -isnot [System.Array]) {
        throw 'Stable patch-data manifest root is invalid'
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $patchRoot = Join-Path $Layout.Server 'system\patch-bb\data'
    foreach ($file in $manifest.files) {
        Assert-PSOBBStrictDataObjectProperties -Value $file -Expected @(
            'path', 'size', 'sha256') -Label 'Stable patch-data manifest file' |
            Out-Null
        if ($file.path -isnot [string] -or
            [string]$file.path -cnotmatch '^[^/\\]+(?:/[^/\\]+)*$' -or
            [string]$file.path -match '(^|/)\.\.?(?:/|$)' -or
            $file.size -isnot [long] -or [long]$file.size -lt 0 -or
            $file.sha256 -isnot [string] -or
            [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            -not $seen.Add([string]$file.path)) {
            throw 'Stable patch-data manifest has an invalid file entry'
        }
        [void](Assert-PathWithinRoot `
                -Path (Join-Path $patchRoot (
                    [string]$file.path).Replace('/', '\')) -Root $patchRoot)
    }
    [pscustomobject]@{
        Snapshot = $snapshot
        FileCount = [long]$manifest.files.Count
    }
}

function Assert-MigrationRuntime($Layout, $Record, $Bindings) {
    $snapshots = [System.Collections.Generic.List[object]]::new()
    $checks = @(
        @((Join-Path $Layout.Server 'newserv-windows.exe'),
            $Bindings.ServerExe.size, $Bindings.ServerExe.sha256),
        @((Join-Path $Layout.BaseClient 'Psobb.exe'),
            $Bindings.ClientExe.size, $Bindings.ClientExe.sha256),
        @((Join-Path $Layout.Client 'Psobb.exe'),
            $Bindings.ClientExe.size, $Bindings.ClientExe.sha256),
        @((Join-Path $Layout.Archives 'dgVoodoo2_87_3.zip'),
            $Bindings.Renderer.size, $Bindings.Renderer.sha256),
        @((Join-Path $Layout.Stable `
                'overlays\dgvoodoo-2.87.3\MS\x86\D3D8.dll'),
            $Bindings.RendererDll.size, $Bindings.RendererDll.sha256),
        @((Join-Path $Layout.Stable `
                'overlays\dgvoodoo-2.87.3\dgVoodoo.conf'),
            $Bindings.RendererConfig.size, $Bindings.RendererConfig.sha256))
    foreach ($check in $checks) {
        $snapshots.Add((Read-MigrationSnapshot `
                -Path $check[0] -Root $Layout.Root `
                -MaximumBytes ([Math]::Max(1L, [long]$check[1])) `
                -ExpectedLength ([long]$check[1]) `
                -ExpectedSha256 ([string]$check[2]) `
                -Label 'Stable runtime binding'))
    }
    foreach ($manifest in @(
            @((Join-Path $Layout.Stable 'server-base.manifest.json'),
                $Record.serverBaseManifestSha256),
            @($Layout.BaseClientManifest, $Record.baseClientManifestSha256))) {
        $snapshots.Add((Read-MigrationSnapshot `
                -Path $manifest[0] -Root $Layout.Root -MaximumBytes 16MB `
                -ExpectedSha256 ([string]$manifest[1]) `
                -Label 'Stable manifest binding'))
    }
    $patchManifest = Read-MigrationPatchManifest $Layout $Record $Bindings
    $snapshots.Add($patchManifest.Snapshot)
    $config = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath (Join-Path $Layout.Server 'system\config.json') `
        -Root $Layout.Root -MaximumBytes 16MB `
        -RoleLabel 'Stable baseline configuration' -Consumer {
            param([byte[]]$Bytes)
            [System.Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        }
    if (@(Get-ActiveConfigStringArray `
                -Text $config.Value -Key 'AutoPatches').Count -ne 0 -or
        @(Get-ActiveConfigStringArray `
                -Text $config.Value -Key 'BBRequiredPatches').Count -ne 0) {
        throw 'Stable server configuration does not have empty baseline patch arrays'
    }
    $snapshots.Add($config)
    [pscustomobject]@{
        Files = @($snapshots)
        PatchFileCount = [long]$patchManifest.FileCount
    }
}

function Assert-MigrationRuntimeIdentity($Expected, $Actual) {
    if ($Expected.Files.Count -ne $Actual.Files.Count) {
        throw 'Stable runtime binding inventory changed during migration'
    }
    for ($index = 0; $index -lt $Expected.Files.Count; $index++) {
        $left = $Expected.Files[$index]
        $right = $Actual.Files[$index]
        if ([string]$left.Path -ine [string]$right.Path -or
            [long]$left.Length -ne [long]$right.Length -or
            [string]$left.Sha256 -cne [string]$right.Sha256 -or
            -not (Test-MigrationIdentity $left $right)) {
            throw 'Stable runtime binding identity changed during migration'
        }
    }
    $true
}

function Assert-MigrationAclExternalBindings(
    $Layout,
    $Marker,
    $Record,
    $Bindings,
    $RuntimeBinding,
    [string]$SourcesPath,
    [string]$PolicyPath,
    [string]$SourceRoot,
    $MarkerLease,
    $SourcesLease,
    $PolicyLease
) {
    $markerAgain = Assert-PSOBBRuntimeMarker -Layout $Layout
    if ([string]$markerAgain.installationId -cne
            [string]$Marker.installationId -or
        [string]$markerAgain.runtimeRoot -cne [string]$Marker.runtimeRoot) {
        throw 'Runtime ownership marker changed during installation ACL migration'
    }
    foreach ($lease in @(
            @($MarkerLease, 'Runtime ownership marker lease'),
            @($SourcesLease, 'Migration source lock lease'),
            @($PolicyLease, 'Migration patch policy lease'))) {
        [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                -Context $lease[0] -RoleLabel $lease[1])
    }
    $bindingsAgain = Get-MigrationBindings `
        $SourcesPath $PolicyPath $SourceRoot
    if ($bindingsAgain.SourceLockSha256 -cne $Bindings.SourceLockSha256 -or
        $bindingsAgain.PolicySha256 -cne $Bindings.PolicySha256) {
        throw 'Installation ACL migration source bindings changed'
    }
    $runtimeAgain = Assert-MigrationRuntime $Layout $Record $bindingsAgain
    [void](Assert-MigrationRuntimeIdentity $RuntimeBinding $runtimeAgain)
    $true
}

function Invoke-MigrationLegacyInstallationAcl(
    $Layout,
    $Marker,
    $RecordSnapshot,
    $Record,
    $Bindings,
    $RuntimeBinding,
    [string]$SourcesPath,
    [string]$PolicyPath,
    [string]$SourceRoot,
    $MarkerLease,
    $SourcesLease,
    $PolicyLease,
    [bool]$OwnsClientMutex,
    [bool]$OwnsServerMutex,
    [System.Management.Automation.PSCmdlet]$CallingCmdlet
) {
    if (-not $OwnsClientMutex -or -not $OwnsServerMutex) {
        throw 'Installation ACL migration does not own both lifecycle locks'
    }
    $lease = $null
    try {
        $lease = Open-PSOBBCombatCanaryOrdinaryFileLease `
            -LiteralPath $Layout.InstallRecord -Root $Layout.Root `
            -RoleLabel 'Stable installation record ACL lease'
        $initial = Get-MigrationInstallationAclState $Layout $lease
        if ($initial.Length -ne [long]$RecordSnapshot.Length -or
            $initial.Sha256 -cne [string]$RecordSnapshot.Sha256 -or
            $initial.VolumeSerialNumber -ne
                [uint32]$RecordSnapshot.VolumeSerialNumber -or
            $initial.FileId -ne [uint64]$RecordSnapshot.FileId -or
            $initial.NumberOfLinks -ne 1) {
            throw 'Stable installation record changed before ACL migration'
        }
        [void](Assert-MigrationApprovedAclOwnership $initial)
        if (Test-PSOBBProtectedAcl -Path $lease.Path) {
            $protected = Get-MigrationInstallationAclState $Layout $lease
            [void](Assert-MigrationInstallationAclStateMatches `
                    $protected $initial $protected.AccessSddl `
                    'already-protected readback')
            if (-not $protected.Acl.AreAccessRulesCanonical -or
                -not (Test-PSOBBProtectedAcl -Path $lease.Path)) {
                throw 'Protected Stable installation record ACL is not exact'
            }
            return [pscustomobject]@{
                Path = $protected.Path
                Changed = $false
                Pending = $false
                PendingRecovery = $false
                Kind = 'stable-installation-record-acl-migration'
                RecordSha256 = $protected.Sha256
                PriorAcl = 'already-protected'
            }
        }
        $legacy = Assert-MigrationLegacyInstallationAclState `
            $Layout $lease $RecordSnapshot
        if (-not $CallingCmdlet.ShouldProcess(
                $legacy.Path,
                'Replace the exact known legacy Stable installation-record DACL')) {
            return [pscustomobject]@{
                Path = $legacy.Path
                Changed = $false
                Pending = $true
                PendingRecovery = $false
                Kind = 'stable-installation-record-acl-migration-preview'
                RecordSha256 = $legacy.Sha256
                PriorAcl = 'known-legacy-inherited'
            }
        }

        [void](Assert-MigrationAclExternalBindings `
                $Layout $Marker $Record $Bindings $RuntimeBinding `
                $SourcesPath $PolicyPath $SourceRoot `
                $MarkerLease $SourcesLease $PolicyLease)
        Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
            -Operation 'protecting Stable installation metadata' | Out-Null
        $locked = Assert-MigrationLegacyInstallationAclState `
            $Layout $lease $RecordSnapshot
        [void](Assert-MigrationInstallationAclStateMatches `
                $locked $legacy $legacy.AccessSddl 'prewrite legacy DACL')
        $context = [pscustomobject]@{
            TargetPath = $legacy.Path
            Lease = $lease
            ExpectedLegacyState = $legacy
        }
        Invoke-MigrationBoundary 'acl-before-write' $context
        Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
            -Operation 'protecting Stable installation metadata' | Out-Null
        [void](Assert-MigrationAclExternalBindings `
                $Layout $Marker $Record $Bindings $RuntimeBinding `
                $SourcesPath $PolicyPath $SourceRoot `
                $MarkerLease $SourcesLease $PolicyLease)
        $lockedAgain = Assert-MigrationLegacyInstallationAclState `
            $Layout $lease $RecordSnapshot
        [void](Assert-MigrationInstallationAclStateMatches `
                $lockedAgain $legacy $legacy.AccessSddl `
                'immediate prewrite legacy DACL')

        $attempted = $false
        try {
            $attempted = $true
            Set-PSOBBProtectedAcl -Path $lease.Path
            Invoke-MigrationBoundary 'acl-after-write' $context
            $after = Get-MigrationInstallationAclState $Layout $lease
            [void](Assert-MigrationInstallationAclStateMatches `
                    $after $legacy $after.AccessSddl 'protected DACL readback')
            if (-not $after.Acl.AreAccessRulesCanonical -or
                -not (Test-PSOBBProtectedAcl -Path $lease.Path)) {
                throw ('Stable installation-record ACL migration did not ' +
                    'produce the exact protected policy')
            }
            [void](Assert-MigrationAclExternalBindings `
                    $Layout $Marker $Record $Bindings $RuntimeBinding `
                    $SourcesPath $PolicyPath $SourceRoot `
                    $MarkerLease $SourcesLease $PolicyLease)
            Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
                -Operation 'accepting protected Stable installation metadata' |
                Out-Null
            $context | Add-Member -NotePropertyName ProtectedAccessSddl `
                -NotePropertyValue ([string]$after.AccessSddl)
            Invoke-MigrationBoundary 'acl-before-accept' $context
            Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
                -Operation 'accepting protected Stable installation metadata' |
                Out-Null
            [void](Assert-MigrationAclExternalBindings `
                    $Layout $Marker $Record $Bindings $RuntimeBinding `
                    $SourcesPath $PolicyPath $SourceRoot `
                    $MarkerLease $SourcesLease $PolicyLease)
            $accepted = Get-MigrationInstallationAclState $Layout $lease
            [void](Assert-MigrationInstallationAclStateMatches `
                    $accepted $legacy $after.AccessSddl `
                    'final protected DACL acceptance')
            if (-not $accepted.Acl.AreAccessRulesCanonical -or
                -not (Test-PSOBBProtectedAcl -Path $lease.Path)) {
                throw ('Stable installation-record ACL changed before final ' +
                    'acceptance')
            }
            return [pscustomobject]@{
                Path = $accepted.Path
                Changed = $true
                Pending = $false
                PendingRecovery = $false
                Kind = 'stable-installation-record-acl-migration'
                RecordSha256 = $accepted.Sha256
                PriorAcl = 'known-legacy-inherited'
            }
        } catch {
            $migrationFailure = $_
            if ($attempted) {
                try {
                    $candidate = Get-MigrationInstallationAclState $Layout $lease
                    if ($candidate.AccessSddl -cne $legacy.AccessSddl) {
                        [void](Assert-MigrationInstallationAclStateMatches `
                                $candidate $legacy $candidate.AccessSddl `
                                'rollback candidate DACL')
                        if (-not $candidate.Acl.AreAccessRulesCanonical -or
                            -not (Test-PSOBBProtectedAcl -Path $lease.Path)) {
                            throw ('The post-write installation-record DACL is ' +
                                'not the exact protected rollback candidate')
                        }
                        Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
                            -Operation 'rolling back Stable installation metadata ACL' |
                            Out-Null
                        Invoke-MigrationBoundary 'acl-before-rollback' $context
                        Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
                            -Operation 'rolling back Stable installation metadata ACL' |
                            Out-Null
                        $candidateAgain = Get-MigrationInstallationAclState `
                            $Layout $lease
                        [void](Assert-MigrationInstallationAclStateMatches `
                                $candidateAgain $legacy $candidate.AccessSddl `
                                'immediate rollback candidate DACL')
                        Set-MigrationInstallationAccessDacl `
                            $Layout $lease $legacy.AccessSddl
                        $rolledBack = Assert-MigrationLegacyInstallationAclState `
                            $Layout $lease $RecordSnapshot
                        [void](Assert-MigrationInstallationAclStateMatches `
                                $rolledBack $legacy $legacy.AccessSddl `
                                'legacy DACL rollback readback')
                    } else {
                        [void](Assert-MigrationInstallationAclStateMatches `
                                $candidate $legacy $legacy.AccessSddl `
                                'unchanged legacy DACL after write failure')
                    }
                } catch {
                    throw ('Stable installation-record ACL migration failed and ' +
                        'exact DACL rollback was unsafe or failed. Migration: ' +
                        $migrationFailure.Exception.Message + ' Rollback: ' +
                        $_.Exception.Message)
                }
            }
            throw $migrationFailure
        }
    } finally {
        Close-PSOBBCombatCanaryOrdinaryFileLease -Context $lease
    }
}

function New-MigrationCandidate($Legacy, $Bindings) {
    $candidate = [ordered]@{}
    foreach ($name in Get-MigrationLegacyProperties) {
        if ($name -ceq 'patchManifestSha256') {
            $candidate.rendererVersion = [string]$Bindings.Renderer.version
            $candidate.rendererArchiveSha256 = [string]$Bindings.Renderer.sha256
            $candidate.rendererWrapperSha256 =
                [string]$Bindings.RendererDll.sha256
            $candidate.rendererConfigurationSha256 =
                [string]$Bindings.RendererConfig.sha256
        }
        $candidate[$name] = if ($name -ceq 'clientPatchPolicySha256') {
            [string]$Bindings.PolicySha256
        } else {
            $Legacy.$name
        }
    }
    [pscustomobject]$candidate
}

function Assert-MigrationCurrentRecord(
    $Record, $Layout, $Marker, $Bindings, $RuntimeState) {
    if ([string]$Record.installationId -cne [string]$Marker.installationId -or
        -not ([System.IO.Path]::GetFullPath(
                [string]$Record.runtimeRoot).TrimEnd('\')).Equals(
            [string]$Layout.Root,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]$Record.clientPatchProfile -cne 'baseline' -or
        [string]$Record.networkScope -cne 'loopback-only' -or
        [string]$Record.serverVersion -cne [string]$Bindings.Server.version -or
        [string]$Record.serverArchiveSha256 -cne
            [string]$Bindings.Server.sha256 -or
        [string]$Record.serverExecutableSha256 -cne
            [string]$Bindings.ServerExe.sha256 -or
        [string]$Record.clientVersion -cne [string]$Bindings.Client.version -or
        [string]$Record.clientArchiveSha256 -cne
            [string]$Bindings.Client.sha256 -or
        [string]$Record.baseClientExecutableSha256 -cne
            [string]$Bindings.ClientExe.sha256 -or
        [string]$Record.clientExecutableSha256 -cne
            [string]$Bindings.ClientExe.sha256 -or
        [string]$Record.rendererVersion -cne
            [string]$Bindings.Renderer.version -or
        [string]$Record.rendererArchiveSha256 -cne
            [string]$Bindings.Renderer.sha256 -or
        [string]$Record.rendererWrapperSha256 -cne
            [string]$Bindings.RendererDll.sha256 -or
        [string]$Record.rendererConfigurationSha256 -cne
            [string]$Bindings.RendererConfig.sha256 -or
        [string]$Record.clientPatchPolicySha256 -cne
            [string]$Bindings.PolicySha256 -or
        [long]$Record.synchronizedPatchFiles -ne
            [long]$RuntimeState.PatchFileCount) {
        throw 'Current installation record does not match exact baseline source bindings'
    }
    $Record
}

function Assert-MigrationClientPatchCoherence($Layout, $Marker,
    [string]$PolicyPath, [bool]$UsingOverrides, $Bindings) {
    if ($UsingOverrides) {
        return $true
    }
    $state = Assert-PSOBBClientPatchStateCoherent `
        -ConfigPath (Join-Path $Layout.Server 'system\config.json') `
        -InstallRecordPath $Layout.InstallRecord `
        -InstallationId ([string]$Marker.installationId) `
        -RuntimeRoot $Layout.Root -PolicyPath $PolicyPath
    if ([string]$state.Profile -cne 'baseline' -or
        [string]$state.PolicySha256 -cne [string]$Bindings.PolicySha256) {
        throw 'Stable installation record failed canonical baseline coherence'
    }
    $true
}

function Get-MigrationArtifactPaths([string]$Root) {
    [pscustomobject]@{
        Root = $Root
        Journal = Join-Path $Root 'journal.json'
        Original = Join-Path $Root 'original-installation.json'
        Candidate = Join-Path $Root 'candidate-installation.json'
        Stage = Join-Path $Root 'candidate-installation.stage'
        Displaced = Join-Path $Root 'displaced-installation.json'
        FailedCandidate = Join-Path $Root 'failed-candidate.json'
    }
}

function Get-MigrationPaths($Layout) {
    $root = Join-Path $Layout.Stable '.stable-installation-record-migration'
    [void](Assert-PathWithinRoot -Path $root -Root $Layout.Root)
    Get-MigrationArtifactPaths $root
}

function Write-MigrationArtifact([string]$Path, [string]$Root,
    [byte[]]$Bytes, [string]$Label) {
    $sha256 = Get-MigrationSha256 $Bytes
    [void](Write-PSOBBCombatCanaryNoClobberBytes `
            -Destination $Path -DestinationRoot $Root -Bytes $Bytes `
            -ExpectedSha256 $sha256 -RoleLabel $Label)
    Set-PSOBBProtectedAcl -Path $Path
    $snapshot = Read-MigrationSnapshot `
        -Path $Path -Root $Root -MaximumBytes ([Math]::Max(1, $Bytes.Length)) `
        -ExpectedLength $Bytes.Length -ExpectedSha256 $sha256 -Label $Label
    if (-not (Test-PSOBBProtectedAcl -Path $Path)) {
        throw "$Label is not protected after exact readback"
    }
    $snapshot
}

function Assert-MigrationJournal($Journal, [string]$InstallationId) {
    $properties = @('schemaVersion', 'installationId', 'transactionId',
        'sourceLockSha256', 'policySha256', 'rootVolume', 'rootFileId', 'originalSize',
        'originalSha256', 'originalTargetVolume', 'originalTargetFileId',
        'originalArtifactVolume', 'originalArtifactFileId', 'candidateSize',
        'candidateSha256', 'candidateStageVolume', 'candidateStageFileId',
        'markerSize', 'markerSha256', 'markerVolume', 'markerFileId')
    Assert-PSOBBStrictDataObjectProperties -Value $Journal `
        -Expected $properties -Label 'installation migration journal' |
        Out-Null
    foreach ($name in @('schemaVersion', 'rootVolume', 'originalSize',
            'originalTargetVolume', 'originalArtifactVolume', 'candidateSize',
            'candidateStageVolume', 'markerSize', 'markerVolume')) {
        if ($Journal.$name -isnot [long] -or [long]$Journal.$name -lt 0) {
            throw "Installation migration journal '$name' is invalid"
        }
    }
    if ($Journal.schemaVersion -ne 1 -or
        [string]$Journal.installationId -cne $InstallationId -or
        [string]$Journal.transactionId -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$Journal.sourceLockSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Journal.policySha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Journal.originalSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Journal.candidateSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Journal.markerSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [long]$Journal.originalSize -gt 256KB -or
        [long]$Journal.candidateSize -gt 256KB -or
        [long]$Journal.markerSize -gt 4KB) {
        throw 'Installation migration journal has invalid identity or bounds'
    }
    foreach ($name in @('rootFileId', 'originalTargetFileId',
            'originalArtifactFileId', 'candidateStageFileId', 'markerFileId')) {
        if ($Journal.$name -isnot [string]) {
            throw "Installation migration journal '$name' is not text"
        }
        [void](ConvertFrom-MigrationFileId ([string]$Journal.$name))
    }
    $Journal
}

function Assert-MigrationCompletion($Completion, $Journal) {
    Assert-PSOBBStrictDataObjectProperties -Value $Completion -Expected @(
        'schemaVersion', 'transactionId', 'installationId', 'completedAtUtc',
        'sourceLockSha256', 'policySha256', 'originalSize', 'originalSha256',
        'candidateSize', 'candidateSha256') `
        -Label 'completed installation migration' | Out-Null
    $completedAt = [DateTimeOffset]::MinValue
    if ($Completion.schemaVersion -isnot [long] -or
        $Completion.schemaVersion -ne 1 -or
        -not [DateTimeOffset]::TryParse(
            [string]$Completion.completedAtUtc, [ref]$completedAt) -or
        [string]$Completion.transactionId -cne [string]$Journal.transactionId -or
        [string]$Completion.installationId -cne [string]$Journal.installationId -or
        [string]$Completion.sourceLockSha256 -cne
            [string]$Journal.sourceLockSha256 -or
        [string]$Completion.policySha256 -cne [string]$Journal.policySha256 -or
        $Completion.originalSize -isnot [long] -or
        [long]$Completion.originalSize -ne [long]$Journal.originalSize -or
        [string]$Completion.originalSha256 -cne
            [string]$Journal.originalSha256 -or
        $Completion.candidateSize -isnot [long] -or
        [long]$Completion.candidateSize -ne [long]$Journal.candidateSize -or
        [string]$Completion.candidateSha256 -cne
            [string]$Journal.candidateSha256) {
        throw 'Completed installation migration does not match its journal'
    }
    $Completion
}

function Read-MigrationTransaction(
    $Layout,
    $Paths,
    [string]$InstallationId,
    [string]$TransactionBoundary = '',
    $ExpectedTransaction = $null
) {
    if (-not $TransactionBoundary) { $TransactionBoundary = $Layout.Stable }
    $root = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $Paths.Root -Root $TransactionBoundary -Directory $true `
        -RoleLabel 'Installation migration transaction'
    if (-not (Test-PSOBBProtectedAcl -Path $Paths.Root)) {
        throw 'Installation migration transaction root is not protected'
    }
    $names = @(Get-ChildItem -Force -LiteralPath $Paths.Root |
        ForEach-Object Name | Sort-Object)
    $allowed = @('.psobb-combat-canary-transaction.json',
        'candidate-installation.json', 'candidate-installation.stage',
        'completed.json', 'displaced-installation.json',
        'failed-candidate.json', 'journal.json', 'original-installation.json')
    if (@($names | Where-Object { $_ -cnotin $allowed }).Count) {
        throw 'Installation migration transaction contains an unexpected artifact'
    }
    if (@($names | Where-Object {
                $_ -ceq $script:MigrationMarkerName
            }).Count -ne 1) {
        throw 'Installation migration transaction lacks its exact ownership marker'
    }
    $transaction = Read-MigrationTransactionMarker `
        -TransactionRoot $Paths.Root `
        -TransactionBoundary $TransactionBoundary -RootIdentity $root `
        -ExpectedTransaction $ExpectedTransaction
    foreach ($item in @(Get-ChildItem -Force -LiteralPath $Paths.Root)) {
        if ($item.PSIsContainer -or
            -not (Test-PSOBBProtectedAcl -Path $item.FullName)) {
            throw 'Installation migration transaction has an unsafe artifact'
        }
        [void](Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $item.FullName -Root $Paths.Root -Directory $false `
                -RoleLabel 'Installation migration artifact')
    }
    $journal = $null
    $journalSnapshot = $null
    if (Test-Path -LiteralPath $Paths.Journal -PathType Leaf) {
        $journalSnapshot = Read-MigrationSnapshot `
            -Path $Paths.Journal -Root $Paths.Root -MaximumBytes 64KB `
            -Label 'Installation migration journal' -Json
        $journal = $journalSnapshot.Value
        [void](Assert-MigrationJournal $journal $InstallationId)
        if ([uint32]$root.VolumeSerialNumber -ne [uint32]$journal.rootVolume -or
            [uint64]$root.FileId -ne
                (ConvertFrom-MigrationFileId ([string]$journal.rootFileId))) {
            throw 'Installation migration transaction root identity changed'
        }
        if ([string]$journal.transactionId -cne
                [string]$transaction.TransactionId -or
            [long]$journal.markerSize -ne
                [long]$transaction.MarkerLength -or
            [string]$journal.markerSha256 -cne
                [string]$transaction.MarkerSha256 -or
            [uint32]$journal.markerVolume -ne
                [uint32]$transaction.MarkerVolumeSerialNumber -or
            (ConvertFrom-MigrationFileId ([string]$journal.markerFileId)) -ne
                [uint64]$transaction.MarkerFileId) {
            throw 'Installation migration journal does not bind its ownership marker'
        }
    }
    [pscustomobject]@{
        RootIdentity = $root
        Transaction = $transaction
        Journal = $journal
        JournalSnapshot = $journalSnapshot
    }
}

function Remove-MigrationTransaction($Layout, $Paths, $State) {
    Invoke-MigrationBoundary 'cleanup-before-remove' ([pscustomobject]@{
            TransactionRoot = $Paths.Root
            MarkerPath = $State.Transaction.MarkerPath
        })
    Remove-PSOBBCombatCanaryOwnedTree `
        -Path $Paths.Root -Root $Layout.Stable `
        -ExpectedVolumeSerialNumber $State.RootIdentity.VolumeSerialNumber `
        -ExpectedFileId $State.RootIdentity.FileId `
        -RoleLabel 'Installation migration transaction' `
        -Transaction $State.Transaction
}

function Publish-MigrationEvidence($Layout, $Paths, $State) {
    $journal = $State.Journal
    if ($null -eq $journal) {
        throw 'Installation migration cannot complete without its journal'
    }
    $backupLeases = @()
    try {
        $backupLeases = @(Open-PSOBBCombatCanaryDirectoryLeaseChain `
                -Path $Layout.Backups -Root $Layout.Root `
                -RoleLabel 'Migration evidence boundary')
        [void](Assert-MigrationDirectoryLeases $backupLeases $Layout.Root)
        if (-not (Test-PSOBBProtectedAcl -Path $Layout.Backups)) {
            throw 'Protected backup boundary is unavailable for completed migration evidence'
        }
        $completedPath = Join-Path $Paths.Root 'completed.json'
        if (-not (Test-Path -LiteralPath $completedPath)) {
            $completion = [ordered]@{
                schemaVersion = 1
                transactionId = [string]$journal.transactionId
                installationId = [string]$journal.installationId
                completedAtUtc = [DateTime]::UtcNow.ToString('o')
                sourceLockSha256 = [string]$journal.sourceLockSha256
                policySha256 = [string]$journal.policySha256
                originalSize = [long]$journal.originalSize
                originalSha256 = [string]$journal.originalSha256
                candidateSize = [long]$journal.candidateSize
                candidateSha256 = [string]$journal.candidateSha256
            }
            $completionBytes = [System.Text.UTF8Encoding]::new(
                $false, $true).GetBytes(
                    ($completion | ConvertTo-Json -Depth 4) + "`n")
            try {
                [void](Write-MigrationArtifact $completedPath $Paths.Root `
                        $completionBytes 'Completed installation migration')
            } finally {
                [Array]::Clear($completionBytes, 0, $completionBytes.Length)
            }
        }
        Set-PSOBBProtectedTreeAcl -Path $Paths.Root -Root $Layout.Stable
        $sealed = Get-MigrationEvidenceSeal $Layout $Paths $State
        $finalPath = Join-Path $Layout.Backups (
            'installation-record-migration-' + [string]$journal.transactionId)
        if (Test-Path -LiteralPath $finalPath) {
            throw 'Completed installation migration evidence destination already exists'
        }
        $publication = [pscustomobject]@{
            Path = $finalPath
            TransactionId = [string]$journal.transactionId
        }
        $context = [pscustomobject]@{
            TransactionRoot = $Paths.Root
            DestinationPath = $finalPath
            TransactionId = [string]$journal.transactionId
            BackupPath = $Layout.Backups
        }
        Invoke-MigrationBoundary 'publish-before-move' $context
        [void](Assert-MigrationDirectoryLeases $backupLeases $Layout.Root)
        $sealedAgain = Get-MigrationEvidenceSeal $Layout $Paths $State
        [void](Assert-MigrationEvidenceSealEqual $sealed $sealedAgain)
        if (Test-Path -LiteralPath $finalPath) {
            throw 'Completed installation migration evidence destination appeared'
        }
        [System.IO.Directory]::Move($Paths.Root, $finalPath)
        Invoke-MigrationBoundary 'publish-after-move' $context
        [void](Assert-MigrationDirectoryLeases $backupLeases $Layout.Root)
        [void](Assert-MigrationPublishedEvidence `
                $Layout ([pscustomobject]@{
                    installationId = [string]$journal.installationId
                }) ([pscustomobject]@{
                    SourceLockSha256 = [string]$journal.sourceLockSha256
                    PolicySha256 = [string]$journal.policySha256
                }) $finalPath $State.JournalSnapshot)
        $publication
    } finally {
        Close-PSOBBCombatCanaryDirectoryLeaseChain -Leases $backupLeases
    }
}

function Assert-MigrationArtifact($Path, $Root, [long]$Size,
    [string]$Sha256, [long]$Volume, [string]$FileId, [string]$Label) {
    if (-not (Test-PSOBBProtectedAcl -Path $Path)) {
        throw "$Label is not protected"
    }
    $snapshot = Read-MigrationSnapshot `
        -Path $Path -Root $Root -MaximumBytes ([Math]::Max(1L, $Size)) `
        -ExpectedLength $Size -ExpectedSha256 $Sha256 -Label $Label
    if ([uint32]$snapshot.VolumeSerialNumber -ne [uint32]$Volume -or
        [uint64]$snapshot.FileId -ne (ConvertFrom-MigrationFileId $FileId)) {
        throw "$Label identity changed"
    }
    $snapshot
}

function Test-MigrationSnapshotExact($Left, $Right) {
    $null -ne $Left -and $null -ne $Right -and
        [long]$Left.Length -eq [long]$Right.Length -and
        [string]$Left.Sha256 -ceq [string]$Right.Sha256 -and
        (Test-MigrationIdentity $Left $Right)
}

function Assert-MigrationDirectoryLeases($Leases, [string]$Root) {
    foreach ($lease in @($Leases)) {
        $current = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $lease.Handle -ExpectedPath $lease.Path -Root $Root `
            -Directory $true -RoleLabel 'Migration evidence boundary lease'
        if (-not (Test-MigrationIdentity $lease.Identity $current)) {
            throw 'Migration evidence boundary lease identity changed'
        }
    }
    $true
}

function Get-MigrationEvidenceSeal($Layout, $Paths, $ExpectedState) {
    $state = Read-MigrationTransaction `
        $Layout $Paths ([string]$ExpectedState.Journal.installationId) `
        $Layout.Stable $ExpectedState.Transaction
    if ($null -eq $state.JournalSnapshot -or
        -not (Test-MigrationSnapshotExact `
            $ExpectedState.JournalSnapshot $state.JournalSnapshot)) {
        throw 'Installation migration journal changed after it was sealed'
    }
    $journal = $state.Journal
    $completion = Read-MigrationSnapshot `
        -Path (Join-Path $Paths.Root 'completed.json') -Root $Paths.Root `
        -MaximumBytes 64KB -Label 'Sealed migration completion' -Json
    [void](Assert-MigrationCompletion $completion.Value $journal)
    $original = Assert-MigrationArtifact $Paths.Original $Paths.Root `
        $journal.originalSize $journal.originalSha256 `
        $journal.originalArtifactVolume $journal.originalArtifactFileId `
        'Sealed migration original'
    $displaced = Assert-MigrationArtifact $Paths.Displaced $Paths.Root `
        $journal.originalSize $journal.originalSha256 `
        $journal.originalTargetVolume $journal.originalTargetFileId `
        'Sealed migration displaced original'
    $candidate = Read-MigrationSnapshot `
        -Path $Paths.Candidate -Root $Paths.Root -MaximumBytes 256KB `
        -ExpectedLength $journal.candidateSize `
        -ExpectedSha256 $journal.candidateSha256 `
        -Label 'Sealed migration candidate'
    [void](Assert-MigrationEvidenceInventory $Paths.Root $Layout.Stable)
    [pscustomobject]@{
        State = $state
        Files = @($state.JournalSnapshot, $completion, $original,
            $displaced, $candidate)
    }
}

function Assert-MigrationEvidenceSealEqual($Expected, $Actual) {
    if (-not (Test-MigrationIdentity `
            $Expected.State.RootIdentity $Actual.State.RootIdentity) -or
        $Expected.Files.Count -ne $Actual.Files.Count) {
        throw 'Installation migration evidence seal root changed'
    }
    for ($index = 0; $index -lt $Expected.Files.Count; $index++) {
        if (-not (Test-MigrationSnapshotExact `
                $Expected.Files[$index] $Actual.Files[$index])) {
            throw 'Installation migration sealed artifact identity changed'
        }
    }
    $true
}

function Get-MigrationEvidenceNames {
    @($script:MigrationMarkerName, 'candidate-installation.json',
        'completed.json', 'displaced-installation.json', 'journal.json',
        'original-installation.json')
}

function Assert-MigrationEvidenceInventory(
    [string]$Path, [string]$Boundary) {
    $tree = Get-PSOBBOrdinaryTreeSnapshot `
        -Path $Path -Root $Boundary `
        -Label 'completed installation migration evidence' `
        -RequireProtectedAcl -MaximumEntries 6 -MaximumBytes 1MB
    $directories = @($tree.Items | Where-Object IsDirectory)
    $actualNames = @($tree.Items | Where-Object { -not $_.IsDirectory } |
        ForEach-Object { [System.IO.Path]::GetFileName($_.Path) } | Sort-Object)
    if ($directories.Count -ne 1 -or
        @(Compare-Object (Get-MigrationEvidenceNames) $actualNames).Count -ne 0) {
        throw 'Completed installation migration evidence inventory is not exact'
    }
    $tree
}

function Get-MigrationPublishedEvidencePaths($Layout) {
    if (-not (Test-Path -LiteralPath $Layout.Backups -PathType Container) -or
        -not (Test-PSOBBProtectedAcl -Path $Layout.Backups)) {
        throw 'Protected backup boundary is unavailable for migration evidence'
    }
    [void](Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $Layout.Backups -Root $Layout.Root -Directory $true `
            -RoleLabel 'Migration evidence boundary')
    $evidenceItems = @(Get-ChildItem -Force -LiteralPath $Layout.Backups |
        Where-Object { $_.Name -clike 'installation-record-migration-*' })
    foreach ($evidenceItem in $evidenceItems) {
        if (-not $evidenceItem.PSIsContainer -or
            $evidenceItem.Name -cnotmatch
                '^installation-record-migration-[a-f0-9]{32}$') {
            throw 'Stable backup boundary has an ambiguous migration evidence entry'
        }
        [void](Get-PSOBBCombatCanaryOwnedPathIdentity `
                -Path $evidenceItem.FullName -Root $Layout.Backups `
                -Directory $true `
                -RoleLabel 'Published installation migration evidence')
    }
    if ($evidenceItems.Count -gt 1) {
        throw 'Stable backup boundary has multiple installation migration bundles'
    }
    @($evidenceItems | ForEach-Object { $_.FullName })
}

function Assert-MigrationPublishedEvidence(
    $Layout, $Marker, $Bindings, [string]$Path,
    $ExpectedJournalSnapshot = $null) {
    $paths = Get-MigrationArtifactPaths $Path
    $state = Read-MigrationTransaction `
        $Layout $paths ([string]$Marker.installationId) $Layout.Backups
    if (($null -ne $ExpectedJournalSnapshot -and
            -not (Test-MigrationSnapshotExact `
                $ExpectedJournalSnapshot $state.JournalSnapshot)) -or
        $null -eq $state.Journal -or
        [string]$state.Journal.transactionId -cne
            [System.IO.Path]::GetFileName($Path).Substring(
                'installation-record-migration-'.Length) -or
        [string]$state.Journal.sourceLockSha256 -cne
            [string]$Bindings.SourceLockSha256 -or
        [string]$state.Journal.policySha256 -cne
            [string]$Bindings.PolicySha256) {
        throw 'Published installation migration evidence has an invalid binding'
    }
    [void](Assert-MigrationEvidenceInventory $Path $Layout.Backups)
    $journal = $state.Journal
    $completion = Read-MigrationSnapshot `
        -Path (Join-Path $Path 'completed.json') -Root $Path `
        -MaximumBytes 64KB -Label 'Published installation migration completion' `
        -Json
    [void](Assert-MigrationCompletion $completion.Value $journal)
    [void](Assert-MigrationArtifact $paths.Original $Path `
            $journal.originalSize $journal.originalSha256 `
            $journal.originalArtifactVolume $journal.originalArtifactFileId `
            'Published migration original')
    [void](Assert-MigrationArtifact $paths.Displaced $Path `
            $journal.originalSize $journal.originalSha256 `
            $journal.originalTargetVolume $journal.originalTargetFileId `
            'Published migration displaced original')
    [void](Read-MigrationSnapshot `
            -Path $paths.Candidate -Root $Path -MaximumBytes 256KB `
            -ExpectedLength $journal.candidateSize `
            -ExpectedSha256 $journal.candidateSha256 `
            -Label 'Published migration candidate')
    $target = Read-MigrationSnapshot `
        -Path $Layout.InstallRecord -Root $Layout.Root -MaximumBytes 256KB `
        -ExpectedLength $journal.candidateSize `
        -ExpectedSha256 $journal.candidateSha256 `
        -Label 'Published migration installed target'
    if ([uint32]$target.VolumeSerialNumber -ne
            [uint32]$journal.candidateStageVolume -or
        [uint64]$target.FileId -ne
            (ConvertFrom-MigrationFileId $journal.candidateStageFileId)) {
        throw 'Published migration target identity does not match its journal'
    }
    $state
}

function Resolve-MigrationTransaction($Layout, $Paths,
    [string]$InstallationId, $ExpectedState = $null) {
    if (-not (Test-Path -LiteralPath $Paths.Root)) { return $false }
    $expectedTransaction = if ($null -ne $ExpectedState) {
        $ExpectedState.Transaction
    } else { $null }
    $state = Read-MigrationTransaction `
        $Layout $Paths $InstallationId $Layout.Stable $expectedTransaction
    if ($null -ne $ExpectedState -and
        $null -ne $ExpectedState.JournalSnapshot -and
        -not (Test-MigrationSnapshotExact `
            $ExpectedState.JournalSnapshot $state.JournalSnapshot)) {
        throw 'Retained migration journal identity changed during recovery'
    }
    $target = Read-MigrationSnapshot `
        -Path $Layout.InstallRecord -Root $Layout.Root -MaximumBytes 256KB `
        -Label 'Installation migration recovery target'
    if ($null -eq $state.Journal) {
        if (Test-Path -LiteralPath $Paths.Original -PathType Leaf) {
            $original = Read-MigrationSnapshot `
                -Path $Paths.Original -Root $Paths.Root -MaximumBytes 256KB `
                -Label 'Unjournaled installation migration original'
            if ($target.Length -ne $original.Length -or
                $target.Sha256 -cne $original.Sha256) {
                throw 'Unjournaled migration does not prove an unchanged target'
            }
        }
        Remove-MigrationTransaction $Layout $Paths $state
        return $true
    }
    $journal = $state.Journal
    [void](Read-MigrationSnapshot `
            -Path $Paths.Candidate -Root $Paths.Root `
            -MaximumBytes ([Math]::Max(1L, [long]$journal.candidateSize) `
            ) -ExpectedLength $journal.candidateSize `
            -ExpectedSha256 $journal.candidateSha256 `
            -Label 'Installation migration candidate evidence')
    if (Test-Path -LiteralPath $Paths.Stage -PathType Leaf) {
        [void](Assert-MigrationArtifact $Paths.Stage $Paths.Root `
                $journal.candidateSize $journal.candidateSha256 `
                $journal.candidateStageVolume $journal.candidateStageFileId `
                'Installation migration retained stage')
    }
    $originalTargetId = ConvertFrom-MigrationFileId $journal.originalTargetFileId
    $originalArtifactId =
        ConvertFrom-MigrationFileId $journal.originalArtifactFileId
    $candidateStageId = ConvertFrom-MigrationFileId $journal.candidateStageFileId
    $originalBytes = $target.Length -eq $journal.originalSize -and
        $target.Sha256 -ceq $journal.originalSha256
    $originalIdentity = $target.VolumeSerialNumber -eq
            $journal.originalTargetVolume -and
        $target.FileId -eq $originalTargetId
    $rollbackIdentity = $target.VolumeSerialNumber -eq
            $journal.originalArtifactVolume -and
        $target.FileId -eq $originalArtifactId
    $candidateIdentity = $target.Length -eq $journal.candidateSize -and
        $target.Sha256 -ceq $journal.candidateSha256 -and
        $target.VolumeSerialNumber -eq $journal.candidateStageVolume -and
        $target.FileId -eq $candidateStageId
    if ($originalBytes -and ($originalIdentity -or $rollbackIdentity)) {
        if ($originalIdentity) {
            [void](Assert-MigrationArtifact $Paths.Original $Paths.Root `
                    $journal.originalSize $journal.originalSha256 `
                    $journal.originalArtifactVolume `
                    $journal.originalArtifactFileId `
                    'Installation migration original')
        } elseif (Test-Path -LiteralPath $Paths.Original) {
            throw 'Rolled-back migration retained an ambiguous original artifact'
        }
        Remove-MigrationTransaction $Layout $Paths $state
        return $true
    }
    if (-not $candidateIdentity) {
        throw 'Migration target is neither its exact original nor candidate identity'
    }
    $displaced = Assert-MigrationArtifact $Paths.Displaced $Paths.Root `
        $journal.originalSize $journal.originalSha256 `
        $journal.originalTargetVolume $journal.originalTargetFileId `
        'Installation migration displaced original'
    if (Test-Path -LiteralPath (Join-Path $Paths.Root 'completed.json')) {
        [void](Publish-MigrationEvidence $Layout $Paths $state)
        return $true
    }
    $original = Assert-MigrationArtifact $Paths.Original $Paths.Root `
        $journal.originalSize $journal.originalSha256 `
        $journal.originalArtifactVolume $journal.originalArtifactFileId `
        'Installation migration rollback original'
    $context = [pscustomobject]@{
        TargetPath = $Layout.InstallRecord
        OriginalPath = $Paths.Displaced
        FailedCandidatePath = $Paths.FailedCandidate
        TransactionRoot = $Paths.Root
    }
    Invoke-MigrationBoundary 'rollback-before-replace' $context
    $targetAgain = Read-MigrationSnapshot `
        -Path $Layout.InstallRecord -Root $Layout.Root -MaximumBytes 256KB `
        -ExpectedLength $journal.candidateSize `
        -ExpectedSha256 $journal.candidateSha256 `
        -Label 'Installation migration rollback target'
    $displacedAgain = Assert-MigrationArtifact $Paths.Displaced $Paths.Root `
        $journal.originalSize $journal.originalSha256 `
        $journal.originalTargetVolume $journal.originalTargetFileId `
        'Installation migration rollback displaced original'
    if (-not (Test-MigrationIdentity $target $targetAgain) -or
        -not (Test-MigrationIdentity $displaced $displacedAgain) -or
        (Test-Path -LiteralPath $Paths.FailedCandidate)) {
        throw 'Installation migration rollback identities changed'
    }
    Assert-PSOBBGlobalStoppedRuntime -Layout $Layout `
        -Operation 'rolling back Stable installation metadata' | Out-Null
    [System.IO.File]::Replace(
        $Paths.Displaced,
        $Layout.InstallRecord,
        $Paths.FailedCandidate,
        $true)
    Invoke-MigrationBoundary 'rollback-after-replace' $context
    Set-PSOBBProtectedAcl -Path $Layout.InstallRecord
    $restored = Read-MigrationSnapshot `
        -Path $Layout.InstallRecord -Root $Layout.Root -MaximumBytes 256KB `
        -ExpectedLength $journal.originalSize `
        -ExpectedSha256 $journal.originalSha256 `
        -Label 'Restored Stable installation record'
    $failedCandidate = Assert-MigrationArtifact `
        $Paths.FailedCandidate $Paths.Root $journal.candidateSize `
        $journal.candidateSha256 $journal.candidateStageVolume `
        $journal.candidateStageFileId `
        'Installation migration rollback candidate'
    if ($restored.VolumeSerialNumber -ne $journal.originalTargetVolume -or
        $restored.FileId -ne $originalTargetId -or
        $failedCandidate.FileId -ne $candidateStageId -or
        -not (Test-PSOBBProtectedAcl -Path $Layout.InstallRecord)) {
        throw 'Installation migration rollback readback failed'
    }
    Remove-MigrationTransaction $Layout $Paths $state
    $true
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$clientMutex = $null
$serverMutex = $null
$ownsClientMutex = $false
$ownsServerMutex = $false
$markerLease = $null
$sourcesLease = $null
$policyLease = $null
try {
    $clientMutex = Enter-PSOBBClientOperationLock -Layout $layout -TimeoutSeconds 0
    $ownsClientMutex = $true
    $marker = Assert-PSOBBRuntimeMarker -Layout $layout
    $markerLease = Open-PSOBBCombatCanaryOrdinaryFileLease `
        -LiteralPath $layout.RuntimeMarker -Root $layout.Root `
        -RoleLabel 'Runtime ownership marker lease'
    $boundMarker = Read-MigrationSnapshot `
            -Path $layout.RuntimeMarker -Root $layout.Root -MaximumBytes 64KB `
            -Label 'Runtime ownership marker' -Json
    Assert-PSOBBStrictDataObjectProperties -Value $boundMarker.Value -Expected @(
        'schemaVersion', 'installationId', 'runtimeRoot', 'createdAtUtc') `
        -Label 'runtime ownership marker' | Out-Null
    if ([string]$boundMarker.Value.installationId -cne
            [string]$marker.installationId -or
        [string]$boundMarker.Value.runtimeRoot -cne [string]$marker.runtimeRoot) {
        throw 'Runtime ownership marker changed during handle-bound validation'
    }
    $serverMutex = [System.Threading.Mutex]::new(
        $false,
        'Local\PSOBB.Newserv.Start.' +
            ([string]$marker.installationId).Replace('-', ''))
    try { $ownsServerMutex = $serverMutex.WaitOne(0) } catch
        [System.Threading.AbandonedMutexException] { $ownsServerMutex = $true }
    if (-not $ownsServerMutex) {
        throw 'Another PSOBB lifecycle or recovery operation is in progress'
    }
    Assert-MigrationInternalTestGate $layout $marker | Out-Null
    Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
        -Operation 'repairing Stable installation metadata' | Out-Null

    $usingOverrides = $script:MigrationTestArmed
    $sourcesPath = if ($usingOverrides) {
        [System.IO.Path]::GetFullPath($InternalTestSourcesLockPath)
    } else { Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json' }
    $policyPath = if ($usingOverrides) {
        [System.IO.Path]::GetFullPath($InternalTestPolicyPath)
    } else {
        Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json'
    }
    $sourceRoot = if ($usingOverrides) {
        $layout.Root
    } else {
        $script:PSOBBRepositoryRoot
    }
    $sourcesLease = Open-PSOBBCombatCanaryOrdinaryFileLease `
        -LiteralPath $sourcesPath -Root $sourceRoot `
        -RoleLabel 'Migration source lock lease'
    $policyLease = Open-PSOBBCombatCanaryOrdinaryFileLease `
        -LiteralPath $policyPath -Root $sourceRoot `
        -RoleLabel 'Migration patch policy lease'
    $bindings = Get-MigrationBindings $sourcesPath $policyPath $sourceRoot
    $paths = Get-MigrationPaths $layout
    if (Test-Path -LiteralPath $paths.Root) {
        if ($MigrateLegacyStableInstallationRecordAcl) {
            throw ('Stable installation-record ACL migration requires no ' +
                'retained metadata transaction')
        }
        $retained = Read-MigrationTransaction `
            $layout $paths ([string]$marker.installationId)
        if ($null -ne $retained.Journal -and
            ([string]$retained.Journal.sourceLockSha256 -cne
                [string]$bindings.SourceLockSha256 -or
             [string]$retained.Journal.policySha256 -cne
                [string]$bindings.PolicySha256)) {
            throw 'Retained installation migration is bound to different source inputs'
        }
        if (-not $PSCmdlet.ShouldProcess(
                $layout.InstallRecord,
                'recover the exact retained installation-record transaction')) {
            [pscustomobject]@{
                Changed = $false; Pending = $true; PendingRecovery = $true
            }
            return
        }
        try {
            [void](Resolve-MigrationTransaction `
                    $layout $paths ([string]$marker.installationId))
        } catch {
            throw ('Installation-record recovery did not complete. Keep both ' +
                'environments stopped, preserve the transaction tree, and rerun ' +
                'Repair-PSOBBStableInstallationRecord.ps1.')
        }
    }
    $recordSnapshot = Read-MigrationSnapshot `
        -Path $layout.InstallRecord -Root $layout.Root -MaximumBytes 256KB `
        -Label 'Stable installation record' -Json
    $record = $recordSnapshot.Value
    $legacyProperties = Get-MigrationLegacyProperties
    $currentProperties = @($legacyProperties[0..12]) + @(
        'rendererVersion', 'rendererArchiveSha256', 'rendererWrapperSha256',
        'rendererConfigurationSha256') + @($legacyProperties[13..17])
    if (Test-MigrationShape $record $currentProperties) {
        if ($MigrateLegacyStableInstallationRecordAcl) {
            throw ('Legacy installation-record ACL migration does not accept ' +
                'current installation metadata')
        }
        [void](Read-PSOBBInstallationRecordSnapshot `
                -Path $layout.InstallRecord -Root $layout.Root `
                -ExpectedInstallationId ([string]$marker.installationId) `
                -ExpectedRuntimeRoot $layout.Root)
        $currentRuntime = Assert-MigrationRuntime $layout $record $bindings
        [void](Assert-MigrationCurrentRecord `
                $record $layout $marker $bindings $currentRuntime)
        [void](Assert-MigrationClientPatchCoherence `
                $layout $marker $policyPath $usingOverrides $bindings)
        if (-not (Test-PSOBBProtectedAcl -Path $layout.InstallRecord)) {
            throw 'Current installation record ACL is not exact and protected'
        }
        foreach ($publishedPath in Get-MigrationPublishedEvidencePaths $layout) {
            [void](Assert-MigrationPublishedEvidence `
                    $layout $marker $bindings $publishedPath)
        }
        [pscustomobject]@{
            Changed = $false; Pending = $false; PendingRecovery = $false
        }
        return
    }
    if (-not (Test-MigrationShape $record (Get-MigrationLegacyProperties))) {
        throw 'Installation record has neither the exact known legacy nor current shape'
    }
    $runtimeBinding = Assert-MigrationRuntime $layout $record $bindings
    [void](Assert-MigrationLegacyRecord `
            $record $layout $marker $bindings $runtimeBinding)
    if (@(Get-MigrationPublishedEvidencePaths $layout).Count -ne 0) {
        throw 'Legacy installation record conflicts with completed migration evidence'
    }
    if (-not (Test-Path -LiteralPath $layout.Backups -PathType Container) -or
        -not (Test-PSOBBProtectedAcl -Path $layout.Backups)) {
        throw 'Protected backup boundary is unavailable for migration evidence'
    }
    [void](Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $layout.Backups -Root $layout.Root -Directory $true `
            -RoleLabel 'Migration evidence boundary')
    if ($MigrateLegacyStableInstallationRecordAcl) {
        Invoke-MigrationLegacyInstallationAcl `
            $layout $marker $recordSnapshot $record $bindings $runtimeBinding `
            $sourcesPath $policyPath $sourceRoot `
            $markerLease $sourcesLease $policyLease `
            $ownsClientMutex $ownsServerMutex $PSCmdlet
        return
    }
    if (-not (Test-PSOBBProtectedAcl -Path $layout.InstallRecord)) {
        throw 'Legacy installation record ACL is not exact and protected'
    }
    $candidate = New-MigrationCandidate $record $bindings
    $candidateBytes = [System.Text.UTF8Encoding]::new(
        $false, $true).GetBytes(($candidate | ConvertTo-Json -Depth 6) + "`n")
    $originalBytes = $null
    try {
        $candidateSha256 = Get-MigrationSha256 $candidateBytes
        $original = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
            -LiteralPath $layout.InstallRecord -Root $layout.Root `
            -MaximumBytes 256KB -ExpectedLength $recordSnapshot.Length `
            -ExpectedSha256 $recordSnapshot.Sha256 `
            -RoleLabel 'Legacy installation record bytes' `
            -Consumer { param([byte[]]$Bytes) [byte[]]$Bytes.Clone() }
        $originalBytes = [byte[]]$original.Value
        if (-not (Test-MigrationIdentity $recordSnapshot $original)) {
            throw 'Legacy installation record identity changed during preflight'
        }
        if (-not $PSCmdlet.ShouldProcess(
                $layout.InstallRecord,
                'add exact renderer provenance and current baseline policy hash')) {
            [pscustomobject]@{
                Changed = $false; Pending = $true; PendingRecovery = $false
            }
            return
        }
        if (Test-Path -LiteralPath $paths.Root) {
            throw 'Installation migration transaction appeared after preflight'
        }
        $state = $null
        try {
            $transactionId = [Guid]::NewGuid().ToString('N')
            $ownedTransaction = New-PSOBBCombatCanaryTransactionTree `
                -Path $paths.Root -Root $layout.Stable `
                -TransactionId $transactionId `
                -Purpose 'stable-installation-record-migration'
            Set-PSOBBProtectedTreeAcl -Path $paths.Root -Root $layout.Stable
            $rootIdentity = $ownedTransaction
            Invoke-MigrationBoundary 'transaction-after-root' $paths
            $originalArtifact = Write-MigrationArtifact `
                $paths.Original $paths.Root $originalBytes `
                'Installation migration original'
            Invoke-MigrationBoundary 'transaction-after-original' $paths
            [void](Write-MigrationArtifact $paths.Candidate $paths.Root `
                    $candidateBytes 'Installation migration candidate')
            $stage = Write-MigrationArtifact $paths.Stage $paths.Root `
                $candidateBytes 'Installation migration stage'
            Invoke-MigrationBoundary 'transaction-after-stage' $paths
            $journal = [ordered]@{
                schemaVersion = 1
                installationId = [string]$marker.installationId
                transactionId = $transactionId
                sourceLockSha256 = [string]$bindings.SourceLockSha256
                policySha256 = [string]$bindings.PolicySha256
                rootVolume = [long]$rootIdentity.VolumeSerialNumber
                rootFileId = ConvertTo-MigrationFileId $rootIdentity.FileId
                originalSize = [long]$original.Length
                originalSha256 = [string]$original.Sha256
                originalTargetVolume = [long]$original.VolumeSerialNumber
                originalTargetFileId = ConvertTo-MigrationFileId $original.FileId
                originalArtifactVolume =
                    [long]$originalArtifact.VolumeSerialNumber
                originalArtifactFileId =
                    ConvertTo-MigrationFileId $originalArtifact.FileId
                candidateSize = [long]$candidateBytes.Length
                candidateSha256 = $candidateSha256
                candidateStageVolume = [long]$stage.VolumeSerialNumber
                candidateStageFileId = ConvertTo-MigrationFileId $stage.FileId
                markerSize = [long]$ownedTransaction.MarkerLength
                markerSha256 = [string]$ownedTransaction.MarkerSha256
                markerVolume =
                    [long]$ownedTransaction.MarkerVolumeSerialNumber
                markerFileId = ConvertTo-MigrationFileId `
                    $ownedTransaction.MarkerFileId
            }
            $journalBytes = [System.Text.UTF8Encoding]::new(
                $false, $true).GetBytes(
                    ($journal | ConvertTo-Json -Depth 4) + "`n")
            try {
                [void](Write-MigrationArtifact $paths.Journal $paths.Root `
                        $journalBytes 'Installation migration journal')
            } finally {
                [Array]::Clear($journalBytes, 0, $journalBytes.Length)
            }
            $state = Read-MigrationTransaction `
                $layout $paths ([string]$marker.installationId) `
                $layout.Stable $ownedTransaction
            Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
                -Operation 'installing repaired Stable installation metadata' |
                Out-Null
            $targetBefore = Read-MigrationSnapshot `
                -Path $layout.InstallRecord -Root $layout.Root `
                -MaximumBytes 256KB -ExpectedLength $original.Length `
                -ExpectedSha256 $original.Sha256 `
                -Label 'Installation migration target preflight'
            $stageBefore = Assert-MigrationArtifact $paths.Stage $paths.Root `
                $journal.candidateSize $journal.candidateSha256 `
                $journal.candidateStageVolume $journal.candidateStageFileId `
                'Installation migration stage preflight'
            if (-not (Test-MigrationIdentity $targetBefore $original)) {
                throw 'Installation migration target identity changed before replace'
            }
            $context = [pscustomobject]@{
                TargetPath = $layout.InstallRecord
                StagePath = $paths.Stage
                DisplacedPath = $paths.Displaced
                TransactionRoot = $paths.Root
            }
            Invoke-MigrationBoundary 'install-before-replace' $context
            $targetAgain = Read-MigrationSnapshot `
                -Path $layout.InstallRecord -Root $layout.Root `
                -MaximumBytes 256KB -ExpectedLength $original.Length `
                -ExpectedSha256 $original.Sha256 `
                -Label 'Installation migration target final preflight'
            $stageAgain = Assert-MigrationArtifact $paths.Stage $paths.Root `
                $journal.candidateSize $journal.candidateSha256 `
                $journal.candidateStageVolume $journal.candidateStageFileId `
                'Installation migration stage final preflight'
            if (-not (Test-MigrationIdentity $targetBefore $targetAgain) -or
                -not (Test-MigrationIdentity $stageBefore $stageAgain)) {
                throw 'Installation migration target or stage identity changed'
            }
            $runtimeAgain = Assert-MigrationRuntime $layout $record $bindings
            [void](Assert-MigrationRuntimeIdentity $runtimeBinding $runtimeAgain)
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $markerLease -RoleLabel 'Runtime ownership marker lease')
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $sourcesLease -RoleLabel 'Migration source lock lease')
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $policyLease -RoleLabel 'Migration patch policy lease')
            Invoke-MigrationBoundary 'install-after-final-validation' $context
            [void](Read-MigrationTransactionMarker `
                    -TransactionRoot $paths.Root `
                    -TransactionBoundary $layout.Stable `
                    -RootIdentity $state.RootIdentity `
                    -ExpectedTransaction $state.Transaction)
            if (Test-Path -LiteralPath $paths.Displaced) {
                throw 'Installation migration displaced-target path is not clean'
            }
            [System.IO.File]::Replace(
                $paths.Stage,
                $layout.InstallRecord,
                $paths.Displaced,
                $true)
            Invoke-MigrationBoundary 'install-after-replace' $context
            Set-PSOBBProtectedAcl -Path $layout.InstallRecord
            $displaced = Assert-MigrationArtifact `
                $paths.Displaced $paths.Root $journal.originalSize `
                $journal.originalSha256 $journal.originalTargetVolume `
                $journal.originalTargetFileId `
                'Installation migration displaced original'
            $installed = Read-MigrationSnapshot `
                -Path $layout.InstallRecord -Root $layout.Root `
                -MaximumBytes 256KB -ExpectedLength $candidateBytes.Length `
                -ExpectedSha256 $candidateSha256 `
                -Label 'Installed Stable installation record' -Json
            if ($installed.VolumeSerialNumber -ne $journal.candidateStageVolume -or
                $installed.FileId -ne
                    (ConvertFrom-MigrationFileId $journal.candidateStageFileId) -or
                -not (Test-PSOBBProtectedAcl -Path $layout.InstallRecord)) {
                throw 'Installed Stable installation record failed exact readback'
            }
            [void](Read-PSOBBInstallationRecordSnapshot `
                    -Path $layout.InstallRecord -Root $layout.Root `
                    -ExpectedInstallationId ([string]$marker.installationId) `
                    -ExpectedRuntimeRoot $layout.Root)
            $runtimeAfter = Assert-MigrationRuntime `
                $layout $installed.Value $bindings
            [void](Assert-MigrationCurrentRecord `
                    $installed.Value $layout $marker $bindings $runtimeAfter)
            [void](Assert-MigrationClientPatchCoherence `
                    $layout $marker $policyPath $usingOverrides $bindings)
            [void](Assert-MigrationRuntimeIdentity $runtimeBinding $runtimeAfter)
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $markerLease -RoleLabel 'Runtime ownership marker lease')
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $sourcesLease -RoleLabel 'Migration source lock lease')
            [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                    -Context $policyLease -RoleLabel 'Migration patch policy lease')
            Assert-PSOBBGlobalStoppedRuntime -Layout $layout `
                -Operation 'accepting repaired Stable installation metadata' |
                Out-Null
            [void](Publish-MigrationEvidence $layout $paths $state)
            [pscustomobject]@{
                Changed = $true; Pending = $false; PendingRecovery = $false
            }
        } catch {
            $failure = $_
            try {
                if (Test-Path -LiteralPath $paths.Root) {
                    [void](Resolve-MigrationTransaction `
                            $layout $paths ([string]$marker.installationId) $state)
                }
                if ($null -ne $state -and $null -ne $state.Journal) {
                    $publishedPath = Join-Path $layout.Backups (
                        'installation-record-migration-' +
                        [string]$state.Journal.transactionId)
                    if (Test-Path -LiteralPath $publishedPath) {
                        [void](Assert-MigrationPublishedEvidence `
                                $layout $marker $bindings $publishedPath `
                                $state.JournalSnapshot)
                    }
                }
            } catch {
                throw ('Installation-record migration failed and exact ' +
                    'conditional recovery did not complete. Keep both ' +
                    'environments stopped, preserve all transaction evidence, ' +
                    'and rerun Repair-PSOBBStableInstallationRecord.ps1.')
            }
            throw $failure
        }
    } finally {
        if ($null -ne $originalBytes) {
            [Array]::Clear($originalBytes, 0, $originalBytes.Length)
        }
        [Array]::Clear($candidateBytes, 0, $candidateBytes.Length)
    }
} finally {
    try {
        Close-PSOBBCombatCanaryOrdinaryFileLease -Context $policyLease
        Close-PSOBBCombatCanaryOrdinaryFileLease -Context $sourcesLease
        Close-PSOBBCombatCanaryOrdinaryFileLease -Context $markerLease
        if ($ownsServerMutex) { $serverMutex.ReleaseMutex() }
    } finally {
        try {
            if ($null -ne $serverMutex) { $serverMutex.Dispose() }
        } finally {
            if ($null -ne $clientMutex) {
                Exit-PSOBBClientOperationLock -Mutex $clientMutex
            }
        }
    }
}
