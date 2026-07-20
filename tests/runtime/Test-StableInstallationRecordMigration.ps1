[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.Common.ps1')

$migrationScript = Join-Path $repositoryRoot `
    'scripts\Repair-PSOBBStableInstallationRecord.ps1'
$aclSetterScript = Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1'
$legacyPolicySha256 =
    'f3501e6cff0d2fd69b0792036c1361ad521f7b3abfec4d695632c6fcc9c0fffb'
$results = [System.Collections.Generic.List[object]]::new()
$fixtureRoots = [System.Collections.Generic.List[string]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Get-TestSha256([byte[]]$Bytes) {
    ([Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Write-TestBytes([string]$Path, [byte[]]$Bytes) {
    $parent = Split-Path -Parent $Path
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    [pscustomobject]@{
        Path = $Path
        Size = [long]$Bytes.Length
        Sha256 = Get-TestSha256 $Bytes
    }
}

function Write-TestJson([string]$Path, $Value, [switch]$Protected) {
    $bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes(
        ($Value | ConvertTo-Json -Depth 12) + "`n")
    try {
        $result = Write-TestBytes $Path $bytes
        if ($Protected) { Set-PSOBBProtectedAcl -Path $Path }
        $result
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function New-TestFixture {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) (
        'PSOBB-StableInstallationRecordMigrationTests-' +
        [Guid]::NewGuid().ToString('N'))
    $fixtureRoots.Add($root)
    $layout = Get-PSOBBLayout -RuntimeRoot $root
    foreach ($directory in @(
            $layout.Root,
            $layout.Stable,
            $layout.Server,
            $layout.BaseClient,
            $layout.Client,
            $layout.Archives,
            $layout.Backups,
            (Join-Path $layout.Server 'system'),
            (Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\MS\x86'))) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    Set-PSOBBProtectedAcl -Path $layout.Backups
    $installationId = [Guid]::NewGuid().ToString('D')
    [void](Write-TestJson $layout.RuntimeMarker ([ordered]@{
                schemaVersion = 1
                installationId = $installationId
                runtimeRoot = $layout.Root
                createdAtUtc = '2026-07-20T00:00:00Z'
            }) -Protected)
    $testMarker = Join-Path $layout.Root `
        '.stable-installation-record-migration-test.json'
    [void](Write-TestJson $testMarker ([ordered]@{
                schemaVersion = 1
                purpose = 'stable-installation-record-migration-tests'
            }) -Protected)

    $serverExe = Write-TestBytes `
        (Join-Path $layout.Server 'newserv-windows.exe') `
        ([System.Text.Encoding]::ASCII.GetBytes('fixture-server'))
    $clientBytes = [System.Text.Encoding]::ASCII.GetBytes('fixture-client')
    $baseClientExe = Write-TestBytes `
        (Join-Path $layout.BaseClient 'Psobb.exe') $clientBytes
    [void](Write-TestBytes (Join-Path $layout.Client 'Psobb.exe') $clientBytes)
    $rendererArchive = Write-TestBytes `
        (Join-Path $layout.Archives 'dgVoodoo2_87_3.zip') `
        ([System.Text.Encoding]::ASCII.GetBytes('fixture-renderer-archive'))
    $rendererDll = Write-TestBytes `
        (Join-Path $layout.Stable `
            'overlays\dgvoodoo-2.87.3\MS\x86\D3D8.dll') `
        ([System.Text.Encoding]::ASCII.GetBytes('fixture-renderer-dll'))
    $rendererConfig = Write-TestBytes `
        (Join-Path $layout.Stable `
            'overlays\dgvoodoo-2.87.3\dgVoodoo.conf') `
        ([System.Text.Encoding]::ASCII.GetBytes('fixture-renderer-config'))
    $serverArchiveHash = ('1' * 64)
    $clientArchiveHash = ('2' * 64)
    $serverManifest = Write-TestJson `
        (Join-Path $layout.Stable 'server-base.manifest.json') `
        ([ordered]@{ schemaVersion = 1; files = @() })
    $clientManifest = Write-TestJson $layout.BaseClientManifest `
        ([ordered]@{ schemaVersion = 1; files = @() })
    $patchManifest = Write-TestJson `
        (Join-Path $layout.Stable 'patch-bb-data.manifest.json') `
        ([ordered]@{
                schemaVersion = 1
                sourceClientArchiveSha256 = $clientArchiveHash
                generatedAtUtc = '2026-07-20T00:00:00Z'
                files = @()
            })
    [void](Write-TestJson (Join-Path $layout.Server 'system\config.json') `
            ([ordered]@{
                AutoPatches = @()
                BBRequiredPatches = @()
                FixtureTerminator = $true
            }))

    $sourceLockPath = Join-Path $layout.Root 'fixture-sources.lock.json'
    [void](Write-TestJson $sourceLockPath ([ordered]@{
                schemaVersion = 1
                generatedAtUtc = '2026-07-20T00:00:00Z'
                components = @(
                    [ordered]@{
                        id = 'newserv-stable-release'
                        version = 'fixture-stable'
                        size = 1
                        sha256 = $serverArchiveHash
                        members = @([ordered]@{
                                path = 'release/newserv-windows.exe'
                                size = $serverExe.Size
                                sha256 = $serverExe.Sha256
                            })
                    },
                    [ordered]@{
                        id = 'tethealla-59nl-english'
                        version = 'fixture-59nl'
                        size = 1
                        sha256 = $clientArchiveHash
                        members = @([ordered]@{
                                path = 'Psobb.exe'
                                size = $baseClientExe.Size
                                sha256 = $baseClientExe.Sha256
                            })
                    },
                    [ordered]@{
                        id = 'dgvoodoo2-x86-d3d8'
                        version = 'fixture-renderer'
                        size = $rendererArchive.Size
                        sha256 = $rendererArchive.Sha256
                        members = @(
                            [ordered]@{
                                path = 'MS/x86/D3D8.dll'
                                size = $rendererDll.Size
                                sha256 = $rendererDll.Sha256
                            },
                            [ordered]@{
                                path = 'dgVoodoo.conf'
                                size = $rendererConfig.Size
                                sha256 = $rendererConfig.Sha256
                            })
                    })
                behaviorReferences = @()
            }) -Protected)
    $policyPath = Join-Path $layout.Root 'fixture-client-patch-policy.json'
    [void](Write-TestJson $policyPath ([ordered]@{
                schemaVersion = 1
                defaultProfile = 'baseline'
                profiles = @([ordered]@{
                        id = 'baseline'
                        channel = 'stable'
                        description = 'Fixture empty baseline.'
                        autoPatches = @()
                        bbRequiredPatches = @()
                    })
                gated = [ordered]@{
                    sourceCanaryOnly = @()
                    protocolRequired = @()
                    migrationRequired = @()
                }
            }) -Protected)
    $policyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $policyPath).
        Hash.ToLowerInvariant()
    if ($policyHash -ceq $legacyPolicySha256) {
        throw 'Fixture current policy unexpectedly matches the known legacy policy'
    }
    $legacyRecord = [ordered]@{
        schemaVersion = 2
        installationId = $installationId
        initializedAtUtc = '2026-07-19T00:00:00Z'
        runtimeRoot = $layout.Root
        serverVersion = 'fixture-stable'
        serverArchiveSha256 = $serverArchiveHash
        serverExecutableSha256 = $serverExe.Sha256
        serverBaseManifestSha256 = $serverManifest.Sha256
        clientVersion = 'fixture-59nl'
        clientArchiveSha256 = $clientArchiveHash
        baseClientExecutableSha256 = $baseClientExe.Sha256
        baseClientManifestSha256 = $clientManifest.Sha256
        clientExecutableSha256 = $baseClientExe.Sha256
        patchManifestSha256 = $patchManifest.Sha256
        synchronizedPatchFiles = 0
        clientPatchProfile = 'baseline'
        clientPatchPolicySha256 = $legacyPolicySha256
        networkScope = 'loopback-only'
    }
    [void](Write-TestJson $layout.InstallRecord $legacyRecord -Protected)
    [pscustomobject]@{
        Layout = $layout
        InstallationId = $installationId
        TestMarker = $testMarker
        SourceLockPath = $sourceLockPath
        PolicyPath = $policyPath
        PolicySha256 = $policyHash
        LegacyRecord = [pscustomobject]$legacyRecord
        RendererArchive = $rendererArchive
        RendererDll = $rendererDll
        RendererConfig = $rendererConfig
        TransactionRoot = Join-Path $layout.Stable `
            '.stable-installation-record-migration'
    }
}

function Get-InvokeParameters($Fixture) {
    @{
        RuntimeRoot = $Fixture.Layout.Root
        InternalTestSourcesLockPath = $Fixture.SourceLockPath
        InternalTestPolicyPath = $Fixture.PolicyPath
        InternalTestFaultToken = $Fixture.InstallationId
        Confirm = $false
    }
}

function Get-AclSetterParameters($Fixture) {
    @{
        RuntimeRoot = $Fixture.Layout.Root
        MigrateLegacyStableInstallationRecordAcl = $true
        InternalTestSourcesLockPath = $Fixture.SourceLockPath
        InternalTestPolicyPath = $Fixture.PolicyPath
        InternalTestFaultToken = $Fixture.InstallationId
        Confirm = $false
    }
}

function Get-TestAccessSddl([string]$Path) {
    (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access)
}

function Get-TestTreeState([string]$Path) {
    $root = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    @(
        Get-ChildItem -Recurse -Force -LiteralPath $root |
            Sort-Object -Property FullName |
            ForEach-Object {
                $relative = [System.IO.Path]::GetRelativePath(
                    $root, $_.FullName).Replace('\', '/')
                if ($_.PSIsContainer) {
                    "D:$relative"
                } else {
                    "F:$($relative):$((Get-FileHash -Algorithm SHA256 `
                        -LiteralPath $_.FullName).Hash)"
                }
            }
    )
}

function Set-TestKnownLegacyInstallationAcl($Fixture) {
    Set-PSOBBProtectedAcl -Path $Fixture.Layout.Stable
    $path = Assert-PSOBBOrdinaryContainedPath `
        -Path $Fixture.Layout.InstallRecord -Root $Fixture.Layout.Root `
        -Kind File -Label 'legacy installation-record ACL fixture'
    $legacy = [System.Security.AccessControl.FileSecurity]::new()
    $legacy.SetAccessRuleProtection($false, $false)
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $path),
        $legacy)
    Get-TestAccessSddl $path
}

function Test-PreservedRecord($Before, $After, $Fixture) {
    $preserved = @($Before.PSObject.Properties.Name | Where-Object {
            $_ -cne 'clientPatchPolicySha256'
        })
    @($preserved | Where-Object {
            $Before.$_ -cne $After.$_
        }).Count -eq 0 -and
        [string]$After.rendererVersion -ceq 'fixture-renderer' -and
        [string]$After.rendererArchiveSha256 -ceq
            $Fixture.RendererArchive.Sha256 -and
        [string]$After.rendererWrapperSha256 -ceq
            $Fixture.RendererDll.Sha256 -and
        [string]$After.rendererConfigurationSha256 -ceq
            $Fixture.RendererConfig.Sha256 -and
        [string]$After.clientPatchPolicySha256 -ceq $Fixture.PolicySha256
}

function Test-FinalMigrationState($Fixture) {
    try {
        if (Test-Path -LiteralPath $Fixture.TransactionRoot) { return $false }
        $record = Get-Content -Raw -LiteralPath $Fixture.Layout.InstallRecord |
            ConvertFrom-Json -DateKind String
        if (-not (Test-PreservedRecord $Fixture.LegacyRecord $record $Fixture) -or
            -not (Test-PSOBBProtectedAcl -Path $Fixture.Layout.InstallRecord)) {
            return $false
        }
        $completed = @(Get-ChildItem -LiteralPath $Fixture.Layout.Backups `
                -Directory -Filter 'installation-record-migration-*')
        if ($completed.Count -ne 1) { return $false }
        $tree = Get-PSOBBOrdinaryTreeSnapshot `
            -Path $completed[0].FullName -Root $Fixture.Layout.Backups `
            -Label 'completed migration convergence evidence' `
            -RequireProtectedAcl
        $expectedNames = @('.psobb-combat-canary-transaction.json',
            'candidate-installation.json', 'completed.json',
            'displaced-installation.json', 'journal.json',
            'original-installation.json')
        $actualNames = @($tree.Items | Where-Object { -not $_.IsDirectory } |
            ForEach-Object { [System.IO.Path]::GetFileName($_.Path) } |
            Sort-Object)
        if (@(Compare-Object $expectedNames $actualNames).Count -ne 0) {
            return $false
        }
        $journal = Get-Content -Raw -LiteralPath (
            Join-Path $completed[0].FullName 'journal.json') |
            ConvertFrom-Json -DateKind String
        $target = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $Fixture.Layout.InstallRecord -Root $Fixture.Layout.Root `
            -Directory $false -RoleLabel 'converged migration target'
        $expectedFileId = [Convert]::ToUInt64(
            [string]$journal.candidateStageFileId, 16)
        [uint32]$target.VolumeSerialNumber -eq
            [uint32]$journal.candidateStageVolume -and
            [uint64]$target.FileId -eq $expectedFileId
    } catch {
        $false
    }
}

try {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $migrationScript, [ref]$tokens, [ref]$parseErrors)
    Add-Result 'migration script parses' ($parseErrors.Count -eq 0) `
        "errors=$($parseErrors.Count)"

    $source = Get-Content -Raw -LiteralPath $migrationScript
    Add-Result 'migration has exact legacy policy and stopped transaction gates' (
        $source -match [regex]::Escape($legacyPolicySha256) -and
        $source -match 'SupportsShouldProcess' -and
        $source -match "ConfirmImpact = 'High'" -and
        @([regex]::Matches($source, 'Assert-PSOBBGlobalStoppedRuntime')).Count `
            -ge 3 -and
        $source -match 'Enter-PSOBBClientOperationLock' -and
        $source -notmatch '(?im)^\s*Stop-Process\b') `
        'known input only; both lifecycle locks; no process termination'

    $setterTokens = $null
    $setterParseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $aclSetterScript, [ref]$setterTokens, [ref]$setterParseErrors)
    $setterSource = Get-Content -Raw -LiteralPath $aclSetterScript
    Add-Result 'ACL setter exposes one explicit installation-record parameter set' (
        $setterParseErrors.Count -eq 0 -and
        $setterSource -match
            'MigrateLegacyStableInstallationRecordAcl' -and
        $setterSource -match "ParameterSetName = 'StableInstallationRecordMigration'" -and
        $setterSource -match 'Mandatory = \$true') `
        'the one-file migration cannot overlap or silently fall into inventory mode'

    $exclusive = New-TestFixture
    $exclusiveBefore = Get-TestAccessSddl $exclusive.Layout.InstallRecord
    $exclusiveRejected = $false
    try {
        & $aclSetterScript -RuntimeRoot $exclusive.Layout.Root `
            -MigrateLegacyRuntimeMarkerAcl `
            -MigrateLegacyStableInstallationRecordAcl -WhatIf | Out-Null
    } catch {
        $exclusiveRejected = $true
    }
    $falseSwitchRejected = $false
    try {
        & $aclSetterScript -RuntimeRoot $exclusive.Layout.Root `
            -MigrateLegacyStableInstallationRecordAcl:$false `
            -InternalTestFaultToken $exclusive.InstallationId -WhatIf |
            Out-Null
    } catch {
        $falseSwitchRejected = $_.Exception.Message -match
            'requires its explicit migration switch'
    }
    $falseMarkerSwitchRejected = $false
    try {
        & $aclSetterScript -RuntimeRoot $exclusive.Layout.Root `
            -MigrateLegacyRuntimeMarkerAcl:$false -WhatIf | Out-Null
    } catch {
        $falseMarkerSwitchRejected = $_.Exception.Message -match
            'requires its explicit migration switch'
    }
    $falseRepairSwitchRejected = $false
    try {
        & $migrationScript -RuntimeRoot $exclusive.Layout.Root `
            -MigrateLegacyStableInstallationRecordAcl:$false `
            -Confirm:$false | Out-Null
    } catch {
        $falseRepairSwitchRejected = $_.Exception.Message -match
            'ACL mode requires its explicit migration switch'
    }
    $pwshPath = (Get-Process -Id $PID).Path
    $falseSwitchChildOutput = @(& $pwshPath -NoLogo -NoProfile `
            -ExecutionPolicy Bypass -File $aclSetterScript `
            -RuntimeRoot $exclusive.Layout.Root `
            -MigrateLegacyStableInstallationRecordAcl:`$false `
            -InternalTestFaultToken $exclusive.InstallationId `
            -Confirm:`$false 2>&1 | ForEach-Object { [string]$_ })
    $falseSwitchChildRejected = $LASTEXITCODE -ne 0 -and
        ($falseSwitchChildOutput -join "`n") -match
            'requires its explicit migration switch'
    $falseRepairChildOutput = @(& $pwshPath -NoLogo -NoProfile `
            -ExecutionPolicy Bypass -File $migrationScript `
            -RuntimeRoot $exclusive.Layout.Root `
            -MigrateLegacyStableInstallationRecordAcl:`$false `
            -Confirm:`$false 2>&1 | ForEach-Object { [string]$_ })
    $falseRepairChildRejected = $LASTEXITCODE -ne 0 -and
        ($falseRepairChildOutput -join "`n") -match
            'ACL mode requires its explicit migration switch'
    Add-Result 'ACL migration parameter sets fail closed before inventory' (
        $exclusiveRejected -and $falseSwitchRejected -and
        $falseMarkerSwitchRejected -and
        $falseRepairSwitchRejected -and $falseSwitchChildRejected -and
        $falseRepairChildRejected -and
        (Get-TestAccessSddl $exclusive.Layout.InstallRecord) -ceq
            $exclusiveBefore) `
        'call and child-process false switches cannot reach any ACL write'

    $aclExplicitNull = New-TestFixture
    [void](Set-TestKnownLegacyInstallationAcl $aclExplicitNull)
    $aclExplicitNullBefore = Get-TestAccessSddl `
        $aclExplicitNull.Layout.InstallRecord
    $aclExplicitNullRejected = $false
    try {
        & $aclSetterScript -RuntimeRoot $aclExplicitNull.Layout.Root `
            -MigrateLegacyStableInstallationRecordAcl `
            -InternalTestFaultPoints $null -WhatIf | Out-Null
    } catch {
        $aclExplicitNullRejected = $_.Exception.Message -match
            'Internal migration controls require one exact protected temporary fixture'
    }
    Add-Result 'ACL wrapper explicit-null hidden control fails closed' (
        $aclExplicitNullRejected -and
        (Get-TestAccessSddl $aclExplicitNull.Layout.InstallRecord) -ceq
            $aclExplicitNullBefore) `
        'wrapper forwarding preserves script-scope hidden-control detection'

    $aclHappy = New-TestFixture
    $legacyAcl = Set-TestKnownLegacyInstallationAcl $aclHappy
    $aclHappyParameters = Get-AclSetterParameters $aclHappy
    $aclBytesBefore = [System.IO.File]::ReadAllBytes(
        $aclHappy.Layout.InstallRecord)
    $aclIdentityBefore = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $aclHappy.Layout.InstallRecord -Root $aclHappy.Layout.Root `
        -Directory $false -RoleLabel 'ACL migration target before preview'
    $aclBefore = Get-Acl -LiteralPath $aclHappy.Layout.InstallRecord
    $aclOwnerBefore = $aclBefore.GetOwner(
        [System.Security.Principal.SecurityIdentifier]).Value
    $aclGroupBefore = $aclBefore.GetGroup(
        [System.Security.Principal.SecurityIdentifier]).Value
    $siblingPath = Join-Path $aclHappy.Layout.Server 'newserv-windows.exe'
    $siblingDaclBefore = Get-TestAccessSddl $siblingPath
    $aclPreview = & $aclSetterScript @aclHappyParameters -WhatIf
    $aclIdentityAfterPreview = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $aclHappy.Layout.InstallRecord -Root $aclHappy.Layout.Root `
        -Directory $false -RoleLabel 'ACL migration target after preview'
    Add-Result 'installation-record ACL wrapper WhatIf is exact and write-free' (
        -not [bool]$aclPreview.Changed -and [bool]$aclPreview.Pending -and
        [string]$aclPreview.Kind -ceq
            'stable-installation-record-acl-migration-preview' -and
        (Get-TestAccessSddl $aclHappy.Layout.InstallRecord) -ceq $legacyAcl -and
        [Convert]::ToBase64String($aclBytesBefore) -ceq
            [Convert]::ToBase64String(
                [System.IO.File]::ReadAllBytes($aclHappy.Layout.InstallRecord)) -and
        $aclIdentityAfterPreview.VolumeSerialNumber -eq
            $aclIdentityBefore.VolumeSerialNumber -and
        $aclIdentityAfterPreview.FileId -eq $aclIdentityBefore.FileId -and
        -not (Test-Path -LiteralPath $aclHappy.TransactionRoot) -and
        @(Get-ChildItem -LiteralPath $aclHappy.Layout.Backups -Directory `
                -Filter 'installation-record-migration-*').Count -eq 0) `
        'preview validates exact legacy state without ACL, content, or evidence writes'

    $aclApplied = & $aclSetterScript @aclHappyParameters
    $aclIdempotent = & $aclSetterScript @aclHappyParameters
    $aclBytesAfterApply = [System.IO.File]::ReadAllBytes(
        $aclHappy.Layout.InstallRecord)
    $aclAfter = Get-Acl -LiteralPath $aclHappy.Layout.InstallRecord
    $aclIdentityAfter = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $aclHappy.Layout.InstallRecord -Root $aclHappy.Layout.Root `
        -Directory $false -RoleLabel 'ACL migration target after apply'
    $metadataParameters = Get-InvokeParameters $aclHappy
    $metadataApplied = & $migrationScript @metadataParameters
    Add-Result 'installation-record ACL migrates once before metadata repair' (
        [bool]$aclApplied.Changed -and -not [bool]$aclIdempotent.Changed -and
        [bool]$metadataApplied.Changed -and
        (Test-PSOBBProtectedAcl -Path $aclHappy.Layout.InstallRecord) -and
        [Convert]::ToBase64String($aclBytesBefore) -ceq
            [Convert]::ToBase64String($aclBytesAfterApply) -and
        [Convert]::ToBase64String($aclBytesBefore) -cne
            [Convert]::ToBase64String(
                [System.IO.File]::ReadAllBytes($aclHappy.Layout.InstallRecord)) -and
        $aclIdentityAfter.VolumeSerialNumber -eq
            $aclIdentityBefore.VolumeSerialNumber -and
        $aclIdentityAfter.FileId -eq $aclIdentityBefore.FileId -and
        $aclAfter.GetOwner(
            [System.Security.Principal.SecurityIdentifier]).Value -ceq
                $aclOwnerBefore -and
        $aclAfter.GetGroup(
            [System.Security.Principal.SecurityIdentifier]).Value -ceq
                $aclGroupBefore -and
        (Get-TestAccessSddl $siblingPath) -ceq $siblingDaclBefore -and
        (Test-FinalMigrationState $aclHappy)) `
        'DACL-only apply preserves target identity and siblings; normal repair then converges'

    $currentAclGuard = New-TestFixture
    $currentAclGuardMigration = Get-InvokeParameters $currentAclGuard
    & $migrationScript @currentAclGuardMigration | Out-Null
    $currentAclGuardHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $currentAclGuard.Layout.InstallRecord).Hash
    $currentAclGuardIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $currentAclGuard.Layout.InstallRecord `
        -Root $currentAclGuard.Layout.Root -Directory $false `
        -RoleLabel 'Current metadata ACL guard target'
    $currentAclGuardDacl = Get-TestAccessSddl `
        $currentAclGuard.Layout.InstallRecord
    $currentAclGuardRejected = $false
    $currentAclGuardParameters = Get-AclSetterParameters $currentAclGuard
    try {
        & $aclSetterScript @currentAclGuardParameters | Out-Null
    } catch {
        $currentAclGuardRejected = $_.Exception.Message -match
            'does not accept current installation metadata'
    }
    $currentAclGuardIdentityAfter = Get-PSOBBCombatCanaryOwnedPathIdentity `
        -Path $currentAclGuard.Layout.InstallRecord `
        -Root $currentAclGuard.Layout.Root -Directory $false `
        -RoleLabel 'Current metadata ACL guard unchanged target'

    $retainedAclGuard = New-TestFixture
    $retainedMigrationParameters = Get-InvokeParameters $retainedAclGuard
    $retainedMigrationParameters.InternalTestFaultPoints = @(
        'transaction-after-root', 'cleanup-before-remove')
    try {
        & $migrationScript @retainedMigrationParameters | Out-Null
    } catch {
    }
    [void](Set-TestKnownLegacyInstallationAcl $retainedAclGuard)
    $retainedAclGuardHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $retainedAclGuard.Layout.InstallRecord).Hash
    $retainedAclGuardDacl = Get-TestAccessSddl `
        $retainedAclGuard.Layout.InstallRecord
    $retainedTreeBefore = @(Get-TestTreeState $retainedAclGuard.TransactionRoot)
    $retainedAclGuardRejected = $false
    $retainedAclGuardParameters = Get-AclSetterParameters $retainedAclGuard
    try {
        & $aclSetterScript @retainedAclGuardParameters | Out-Null
    } catch {
        $retainedAclGuardRejected = $_.Exception.Message -match
            'requires no retained metadata transaction'
    }
    $retainedTreeAfter = @(Get-TestTreeState $retainedAclGuard.TransactionRoot)
    Add-Result 'installation ACL mode rejects current or retained migration state' (
        $currentAclGuardRejected -and
        (Get-FileHash -Algorithm SHA256 -LiteralPath `
            $currentAclGuard.Layout.InstallRecord).Hash -ceq
                $currentAclGuardHash -and
        (Get-TestAccessSddl $currentAclGuard.Layout.InstallRecord) -ceq
            $currentAclGuardDacl -and
        $currentAclGuardIdentityAfter.VolumeSerialNumber -eq
            $currentAclGuardIdentity.VolumeSerialNumber -and
        $currentAclGuardIdentityAfter.FileId -eq
            $currentAclGuardIdentity.FileId -and
        $retainedAclGuardRejected -and
        (Get-FileHash -Algorithm SHA256 -LiteralPath `
            $retainedAclGuard.Layout.InstallRecord).Hash -ceq
                $retainedAclGuardHash -and
        (Get-TestAccessSddl $retainedAclGuard.Layout.InstallRecord) -ceq
            $retainedAclGuardDacl -and
        @(Compare-Object $retainedTreeBefore $retainedTreeAfter).Count -eq 0) `
        'ACL-only mode never repairs current metadata or retained transactions'

    $unknownAclMutations = [ordered]@{
        extraAllow = {
            param($Fixture)
            $acl = Get-Acl -LiteralPath $Fixture.Layout.InstallRecord
            [void]$acl.AddAccessRule(
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    [System.Security.Principal.SecurityIdentifier]::new(
                        'S-1-5-32-546'),
                    [System.Security.AccessControl.FileSystemRights]::Read,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow))
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                    $Fixture.Layout.InstallRecord), $acl)
        }
        wrongRights = {
            param($Fixture)
            $security = [System.Security.AccessControl.DirectorySecurity]::new()
            $security.SetAccessRuleProtection($true, $false)
            $sids = @(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
                [System.Security.Principal.SecurityIdentifier]::new(
                    'S-1-5-32-544'),
                [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
            $inheritance = [System.Security.AccessControl.InheritanceFlags] `
                'ContainerInherit, ObjectInherit'
            foreach ($sid in $sids) {
                $rights = if ($sid.Value -ceq 'S-1-5-32-544') {
                    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                } else {
                    [System.Security.AccessControl.FileSystemRights]::FullControl
                }
                [void]$security.AddAccessRule(
                    [System.Security.AccessControl.FileSystemAccessRule]::new(
                        $sid, $rights,
                        $inheritance,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        [System.Security.AccessControl.AccessControlType]::Allow))
            }
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.DirectoryInfo](Get-Item -Force -LiteralPath `
                    $Fixture.Layout.Stable), $security)
            $fileSecurity = [System.Security.AccessControl.FileSecurity]::new()
            $fileSecurity.SetAccessRuleProtection($false, $false)
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                    $Fixture.Layout.InstallRecord), $fileSecurity)
        }
        explicitRule = {
            param($Fixture)
            $acl = Get-Acl -LiteralPath $Fixture.Layout.InstallRecord
            [void]$acl.AddAccessRule(
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow))
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                    $Fixture.Layout.InstallRecord), $acl)
        }
        denyRule = {
            param($Fixture)
            $acl = Get-Acl -LiteralPath $Fixture.Layout.InstallRecord
            [void]$acl.AddAccessRule(
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    [System.Security.Principal.SecurityIdentifier]::new(
                        'S-1-5-32-546'),
                    [System.Security.AccessControl.FileSystemRights]::Read,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Deny))
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                    $Fixture.Layout.InstallRecord), $acl)
        }
        protectedUnknown = {
            param($Fixture)
            $security = [System.Security.AccessControl.FileSecurity]::new()
            $security.SetAccessRuleProtection($true, $false)
            [void]$security.AddAccessRule(
                [System.Security.AccessControl.FileSystemAccessRule]::new(
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow))
            [System.IO.FileSystemAclExtensions]::SetAccessControl(
                [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                    $Fixture.Layout.InstallRecord), $security)
        }
    }
    $unknownAclPassed = $true
    $unknownAclDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $unknownAclMutations.GetEnumerator()) {
        $fixture = New-TestFixture
        [void](Set-TestKnownLegacyInstallationAcl $fixture)
        & $entry.Value $fixture
        $beforeDacl = Get-TestAccessSddl $fixture.Layout.InstallRecord
        $beforeHash = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $rejected = $false
        $parameters = Get-AclSetterParameters $fixture
        try {
            & $aclSetterScript @parameters | Out-Null
        } catch {
            $rejected = $_.Exception.Message -match
                '(?i)installation.*ACL|ACL (identities|rules)'
        }
        $passed = $rejected -and
            (Get-TestAccessSddl $fixture.Layout.InstallRecord) -ceq $beforeDacl -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $beforeHash -and
            -not (Test-Path -LiteralPath $fixture.TransactionRoot)
        $unknownAclPassed = $unknownAclPassed -and $passed
        $unknownAclDetails.Add("$($entry.Key)=$passed")
    }
    Add-Result 'installation ACL migration rejects unknown DACL variants' (
        $unknownAclPassed) ($unknownAclDetails -join '; ')

    $unknownGroup = New-TestFixture
    [void](Set-TestKnownLegacyInstallationAcl $unknownGroup)
    $unknownGroupAcl = Get-Acl -LiteralPath `
        $unknownGroup.Layout.InstallRecord
    $unknownGroupSid =
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $unknownGroupApplied = $false
    try {
        $unknownGroupAcl.SetGroup($unknownGroupSid)
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                $unknownGroup.Layout.InstallRecord), $unknownGroupAcl)
        $unknownGroupApplied = (Get-Acl -LiteralPath `
            $unknownGroup.Layout.InstallRecord).GetGroup(
                [System.Security.Principal.SecurityIdentifier]).Value -ceq
                    $unknownGroupSid.Value
    } catch {
        $unknownGroupApplied = $false
    }
    $unknownGroupDacl = Get-TestAccessSddl `
        $unknownGroup.Layout.InstallRecord
    $unknownGroupRejected = $false
    $unknownGroupParameters = Get-AclSetterParameters $unknownGroup
    try {
        & $aclSetterScript @unknownGroupParameters | Out-Null
    } catch {
        $unknownGroupRejected = $_.Exception.Message -match 'owner or group'
    }
    Add-Result 'installation ACL migration rejects an unapproved group' (
        $unknownGroupApplied -and $unknownGroupRejected -and
        (Get-TestAccessSddl $unknownGroup.Layout.InstallRecord) -ceq
            $unknownGroupDacl) `
        'owner and group are part of the exact accepted legacy state'

    $aclHardLink = New-TestFixture
    $aclHardLinkLegacy = Set-TestKnownLegacyInstallationAcl $aclHardLink
    $aclHardLinkPath = $aclHardLink.Layout.InstallRecord + '.link'
    New-Item -ItemType HardLink -Path $aclHardLinkPath `
        -Target $aclHardLink.Layout.InstallRecord | Out-Null
    $aclHardLinkRejected = $false
    $aclHardLinkParameters = Get-AclSetterParameters $aclHardLink
    try {
        & $aclSetterScript @aclHardLinkParameters | Out-Null
    } catch {
        $aclHardLinkRejected = $true
    } finally {
        Remove-Item -LiteralPath $aclHardLinkPath -Force
    }
    Add-Result 'installation ACL preflight rejects a hard-linked target' (
        $aclHardLinkRejected -and
        (Get-TestAccessSddl $aclHardLink.Layout.InstallRecord) -ceq
            $aclHardLinkLegacy -and
        -not (Test-PSOBBProtectedAcl -Path $aclHardLink.Layout.InstallRecord)) `
        'single-link native identity is required before ShouldProcess or mutation'

    $aclReparse = New-TestFixture
    [void](Set-TestKnownLegacyInstallationAcl $aclReparse)
    $aclReparseSaved = $aclReparse.Layout.InstallRecord + '.saved'
    $aclReparseHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $aclReparse.Layout.InstallRecord).Hash
    [System.IO.File]::Move(
        $aclReparse.Layout.InstallRecord, $aclReparseSaved, $false)
    [void][System.IO.File]::CreateSymbolicLink(
        $aclReparse.Layout.InstallRecord, $aclReparseSaved)
    $aclReparseRejected = $false
    $aclReparseParameters = Get-AclSetterParameters $aclReparse
    try {
        & $aclSetterScript @aclReparseParameters | Out-Null
    } catch {
        $aclReparseRejected = $true
    } finally {
        Remove-Item -LiteralPath $aclReparse.Layout.InstallRecord -Force
        [System.IO.File]::Move(
            $aclReparseSaved, $aclReparse.Layout.InstallRecord, $false)
    }
    Add-Result 'installation ACL preflight rejects target reparse substitution' (
        $aclReparseRejected -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $aclReparse.Layout.InstallRecord).Hash -ceq
                $aclReparseHash -and
        -not (Test-PSOBBProtectedAcl -Path $aclReparse.Layout.InstallRecord)) `
        'the canonical target must remain one ordinary file throughout validation'

    $beforeWriteCases = @('hard-link', 'content', 'runtime', 'lifecycle')
    $beforeWritePassed = $true
    $beforeWriteDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($case in $beforeWriteCases) {
        $fixture = New-TestFixture
        $legacy = Set-TestKnownLegacyInstallationAcl $fixture
        $beforeHash = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $racePath = $fixture.Layout.InstallRecord + '.race-link'
        $parameters = Get-AclSetterParameters $fixture
        $parameters.InternalTestHookPoint = 'acl-before-write'
        $parameters.InternalTestHook = switch ($case) {
            'hard-link' {
                {
                    param($Context)
                    New-Item -ItemType HardLink -Path $racePath `
                        -Target $Context.TargetPath | Out-Null
                }
            }
            'content' {
                {
                    param($Context)
                    [System.IO.File]::WriteAllText(
                        $Context.TargetPath,
                        'rejected-content-race',
                        [System.Text.UTF8Encoding]::new($false))
                }
            }
            'runtime' {
                {
                    [System.IO.File]::WriteAllText(
                        (Join-Path $fixture.Layout.Stable `
                            'overlays\dgvoodoo-2.87.3\MS\x86\D3D8.dll'),
                        'rejected-runtime-race',
                        [System.Text.UTF8Encoding]::new($false))
                }
            }
            'lifecycle' {
                {
                    [System.IO.Directory]::CreateDirectory(
                        $fixture.Layout.ControlDirectory) | Out-Null
                    [System.IO.File]::WriteAllText(
                        $fixture.Layout.ControlState,
                        '{"race":true}',
                        [System.Text.UTF8Encoding]::new($false))
                }
            }
        }
        $rejected = $false
        try {
            & $aclSetterScript @parameters | Out-Null
        } catch {
            $rejected = $true
        } finally {
            if (Test-Path -LiteralPath $racePath) {
                Remove-Item -LiteralPath $racePath -Force
            }
            if (Test-Path -LiteralPath $fixture.Layout.ControlState) {
                Remove-Item -LiteralPath $fixture.Layout.ControlState -Force
            }
        }
        $passed = $rejected -and
            (Get-TestAccessSddl $fixture.Layout.InstallRecord) -ceq $legacy -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $beforeHash -and
            -not (Test-PSOBBProtectedAcl -Path $fixture.Layout.InstallRecord)
        $beforeWritePassed = $beforeWritePassed -and $passed
        $beforeWriteDetails.Add("$case=$passed")
    }
    Add-Result 'installation ACL prewrite races fail before mutation' (
        $beforeWritePassed) ($beforeWriteDetails -join '; ')

    $prewriteDacl = New-TestFixture
    $prewriteDaclLegacy = Set-TestKnownLegacyInstallationAcl $prewriteDacl
    $prewriteDaclState = [pscustomobject]@{ AccessSddl = $null }
    $prewriteDaclParameters = Get-AclSetterParameters $prewriteDacl
    $prewriteDaclParameters.InternalTestHookPoint = 'acl-before-write'
    $prewriteDaclParameters.InternalTestHook = {
        param($Context)
        $acl = Get-Acl -LiteralPath $Context.TargetPath
        [void]$acl.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow))
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                $Context.TargetPath), $acl)
        $prewriteDaclState.AccessSddl = Get-TestAccessSddl $Context.TargetPath
    }
    $prewriteDaclRejected = $false
    try {
        & $aclSetterScript @prewriteDaclParameters | Out-Null
    } catch {
        $prewriteDaclRejected = $true
    }
    Add-Result 'prewrite DACL tampering remains untouched and fails closed' (
        $prewriteDaclRejected -and
        $null -ne $prewriteDaclState.AccessSddl -and
        $prewriteDaclState.AccessSddl -cne $prewriteDaclLegacy -and
        (Get-TestAccessSddl $prewriteDacl.Layout.InstallRecord) -ceq
            $prewriteDaclState.AccessSddl) `
        'unknown concurrent ACL state is preserved for review, never normalized'

    $aclRollback = New-TestFixture
    $aclRollbackLegacy = Set-TestKnownLegacyInstallationAcl $aclRollback
    $aclRollbackHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $aclRollback.Layout.InstallRecord).Hash
    $aclRollbackParameters = Get-AclSetterParameters $aclRollback
    $aclRollbackParameters.InternalTestFaultPoints = @('acl-after-write')
    $aclRollbackRejected = $false
    try {
        & $aclSetterScript @aclRollbackParameters | Out-Null
    } catch {
        $aclRollbackRejected = $_.Exception.Message -match 'Injected'
    }
    Add-Result 'post-write fault restores the exact legacy installation DACL' (
        $aclRollbackRejected -and
        (Get-TestAccessSddl $aclRollback.Layout.InstallRecord) -ceq
            $aclRollbackLegacy -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $aclRollback.Layout.InstallRecord).Hash -ceq
                $aclRollbackHash -and
        -not (Test-PSOBBProtectedAcl -Path $aclRollback.Layout.InstallRecord)) `
        'rollback compares the captured protected SDDL before restoring access only'

    $postWriteLifecycle = New-TestFixture
    [void](Set-TestKnownLegacyInstallationAcl $postWriteLifecycle)
    $postWriteLifecycleHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $postWriteLifecycle.Layout.InstallRecord).Hash
    $postWriteLifecycleParameters = Get-AclSetterParameters $postWriteLifecycle
    $postWriteLifecycleParameters.InternalTestHookPoint = 'acl-after-write'
    $postWriteLifecycleParameters.InternalTestHook = {
        [System.IO.Directory]::CreateDirectory(
            $postWriteLifecycle.Layout.ControlDirectory) | Out-Null
        [System.IO.File]::WriteAllText(
            $postWriteLifecycle.Layout.ControlState,
            '{"race":true}',
            [System.Text.UTF8Encoding]::new($false))
    }
    $postWriteLifecycleRejected = $false
    try {
        & $aclSetterScript @postWriteLifecycleParameters | Out-Null
    } catch {
        $postWriteLifecycleRejected = $_.Exception.Message -match
            'rollback was unsafe or failed'
    } finally {
        if (Test-Path -LiteralPath $postWriteLifecycle.Layout.ControlState) {
            Remove-Item -LiteralPath $postWriteLifecycle.Layout.ControlState -Force
        }
    }
    Add-Result 'post-write lifecycle race blocks legacy DACL rollback' (
        $postWriteLifecycleRejected -and
        (Test-PSOBBProtectedAcl -Path `
            $postWriteLifecycle.Layout.InstallRecord) -and
        (Get-FileHash -Algorithm SHA256 -LiteralPath `
            $postWriteLifecycle.Layout.InstallRecord).Hash -ceq
                $postWriteLifecycleHash) `
        'new lifecycle evidence leaves the exact protected DACL for review'

    $lateDacl = New-TestFixture
    [void](Set-TestKnownLegacyInstallationAcl $lateDacl)
    $lateDaclHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $lateDacl.Layout.InstallRecord).Hash
    $lateDaclParameters = Get-AclSetterParameters $lateDacl
    $lateDaclParameters.InternalTestHookPoint = 'acl-before-accept'
    $lateDaclParameters.InternalTestHook = {
        param($Context)
        $acl = Get-Acl -LiteralPath $Context.TargetPath
        [void]$acl.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow))
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                $Context.TargetPath), $acl)
    }
    $lateDaclRejected = $false
    try {
        & $aclSetterScript @lateDaclParameters | Out-Null
    } catch {
        $lateDaclRejected = $_.Exception.Message -match
            'rollback was unsafe or failed'
    }
    Add-Result 'late protected-DACL substitution cannot return success' (
        $lateDaclRejected -and
        -not (Test-PSOBBProtectedAcl -Path $lateDacl.Layout.InstallRecord) -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $lateDacl.Layout.InstallRecord).Hash -ceq $lateDaclHash) `
        'final lease readback rejects drift and preserves unknown DACL evidence'

    $omittedHiddenPassed = $true
    $omittedHiddenDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($mode in @('call-operator', 'file-process')) {
        $fixture = New-TestFixture
        $beforeHash = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $beforeInventory = @(Get-ChildItem -Recurse -Force `
            -LiteralPath $fixture.Layout.Root |
            ForEach-Object FullName | Sort-Object)
        $message = ''
        $failedAfterGate = $false
        if ($mode -ceq 'call-operator') {
            try {
                & $migrationScript -RuntimeRoot $fixture.Layout.Root `
                    -WhatIf | Out-Null
            } catch {
                $failedAfterGate = $true
                $message = $_.Exception.Message
            }
        } else {
            $pwshPath = (Get-Process -Id $PID).Path
            $childOutput = @(& $pwshPath -NoLogo -NoProfile `
                    -ExecutionPolicy Bypass -File $migrationScript `
                    -RuntimeRoot $fixture.Layout.Root -WhatIf 2>&1 |
                ForEach-Object { [string]$_ })
            $failedAfterGate = $LASTEXITCODE -ne 0
            $message = $childOutput -join "`n"
        }
        $afterInventory = @(Get-ChildItem -Recurse -Force `
            -LiteralPath $fixture.Layout.Root |
            ForEach-Object FullName | Sort-Object)
        $passed = $failedAfterGate -and
            $message -notmatch [regex]::Escape(
                'Internal migration controls require one exact protected temporary fixture') -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $beforeHash -and
            @(Compare-Object $beforeInventory $afterInventory).Count -eq 0 -and
            -not (Test-Path -LiteralPath $fixture.TransactionRoot)
        $omittedHiddenPassed = $omittedHiddenPassed -and $passed
        $omittedHiddenDetails.Add("$mode=$passed")
    }
    Add-Result 'omitted hidden controls do not arm migration test mode' (
        $omittedHiddenPassed) ($omittedHiddenDetails -join '; ')

    $explicitNull = New-TestFixture
    $explicitNullBefore = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $explicitNull.Layout.InstallRecord).Hash
    $explicitNullRejected = $false
    try {
        & $migrationScript -RuntimeRoot $explicitNull.Layout.Root `
            -InternalTestFaultPoints $null -WhatIf | Out-Null
    } catch {
        $explicitNullRejected = $_.Exception.Message -match
            'Internal migration controls require one exact protected temporary fixture'
    }
    Add-Result 'explicit-null hidden control remains fail-closed' (
        $explicitNullRejected -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $explicitNull.Layout.InstallRecord).Hash -ceq
                $explicitNullBefore -and
        -not (Test-Path -LiteralPath $explicitNull.TransactionRoot)) `
        'script-scope bound-parameter presence controls the hidden test gate'

    $whatIf = New-TestFixture
    $beforeBytes = [System.IO.File]::ReadAllBytes(
        $whatIf.Layout.InstallRecord)
    $beforeInventory = @(Get-ChildItem -Recurse -Force -LiteralPath `
            $whatIf.Layout.Root | ForEach-Object FullName | Sort-Object)
    $whatIfParameters = Get-InvokeParameters $whatIf
    $preview = & $migrationScript @whatIfParameters -WhatIf
    $afterBytes = [System.IO.File]::ReadAllBytes(
        $whatIf.Layout.InstallRecord)
    $afterInventory = @(Get-ChildItem -Recurse -Force -LiteralPath `
            $whatIf.Layout.Root | ForEach-Object FullName | Sort-Object)
    Add-Result 'WhatIf performs no write' (
        -not [bool]$preview.Changed -and [bool]$preview.Pending -and
        [Convert]::ToBase64String($beforeBytes) -ceq
            [Convert]::ToBase64String($afterBytes) -and
        @(Compare-Object $beforeInventory $afterInventory).Count -eq 0 -and
        -not (Test-Path -LiteralPath $whatIf.TransactionRoot)) `
        'installation bytes and complete fixture inventory remain exact'

    $happy = New-TestFixture
    $happyBefore = (Get-Content -Raw -LiteralPath $happy.Layout.InstallRecord |
        ConvertFrom-Json -DateKind String)
    $happyOriginalSha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $happy.Layout.InstallRecord).Hash.ToLowerInvariant()
    $happyParameters = Get-InvokeParameters $happy
    $changed = & $migrationScript @happyParameters
    $happyAfter = (Get-Content -Raw -LiteralPath $happy.Layout.InstallRecord |
        ConvertFrom-Json -DateKind String)
    $idempotent = & $migrationScript @happyParameters
    $completedEvidence = @(Get-ChildItem -LiteralPath $happy.Layout.Backups `
        -Directory -Filter 'installation-record-migration-*')
    $evidenceExact = $completedEvidence.Count -eq 1
    if ($evidenceExact) {
        $evidenceTree = Get-PSOBBOrdinaryTreeSnapshot `
            -Path $completedEvidence[0].FullName -Root $happy.Layout.Backups `
            -Label 'completed migration test evidence' -RequireProtectedAcl
        $evidenceNames = @($evidenceTree.Items | Where-Object {
                -not $_.IsDirectory
            } | ForEach-Object { [System.IO.Path]::GetFileName($_.Path) } |
            Sort-Object)
        $evidenceExact =
            @(Compare-Object @('.psobb-combat-canary-transaction.json',
                    'candidate-installation.json', 'completed.json',
                    'displaced-installation.json', 'journal.json',
                    'original-installation.json') $evidenceNames).Count -eq 0 -and
            (Get-FileHash -Algorithm SHA256 -LiteralPath (
                Join-Path $completedEvidence[0].FullName `
                    'original-installation.json')).Hash.ToLowerInvariant() -ceq
                $happyOriginalSha256
    }
    Add-Result 'exact legacy record migrates once and is idempotent' (
        [bool]$changed.Changed -and -not [bool]$idempotent.Changed -and
        (Test-PreservedRecord $happyBefore $happyAfter $happy) -and
        -not (Test-Path -LiteralPath $happy.TransactionRoot) -and
        $evidenceExact -and
        (Test-PSOBBProtectedAcl -Path $happy.Layout.InstallRecord)) `
        'four fields plus policy; completed protected original/journal evidence'

    $publishedTamper = New-TestFixture
    $publishedTamperParameters = Get-InvokeParameters $publishedTamper
    & $migrationScript @publishedTamperParameters | Out-Null
    $publishedTamperPath = @(Get-ChildItem `
        -LiteralPath $publishedTamper.Layout.Backups -Directory `
        -Filter 'installation-record-migration-*')[0].FullName
    $completionPath = Join-Path $publishedTamperPath 'completed.json'
    $completionValue = Get-Content -Raw -LiteralPath $completionPath |
        ConvertFrom-Json -DateKind String
    Add-Member -InputObject $completionValue -NotePropertyName extra `
        -NotePropertyValue 'rejected'
    [void](Write-TestJson $completionPath $completionValue -Protected)
    $publishedTamperTarget = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $publishedTamper.Layout.InstallRecord).Hash
    $publishedTamperRejected = $false
    try { & $migrationScript @publishedTamperParameters | Out-Null } catch {
        $publishedTamperRejected = $true
    }
    Add-Result 'current path revalidates its completed evidence bundle' (
        $publishedTamperRejected -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $publishedTamper.Layout.InstallRecord).Hash -ceq
                $publishedTamperTarget -and
        -not (Test-Path -LiteralPath $publishedTamper.TransactionRoot)) `
        'post-move evidence cannot be bypassed by the idempotent current path'

    $publishedAmbiguity = New-TestFixture
    $publishedAmbiguityParameters = Get-InvokeParameters $publishedAmbiguity
    & $migrationScript @publishedAmbiguityParameters | Out-Null
    $ambiguousPath = Join-Path $publishedAmbiguity.Layout.Backups (
        'installation-record-migration-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($ambiguousPath) | Out-Null
    Set-PSOBBProtectedAcl -Path $ambiguousPath
    $publishedAmbiguityTarget = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $publishedAmbiguity.Layout.InstallRecord).Hash
    $publishedAmbiguityRejected = $false
    try { & $migrationScript @publishedAmbiguityParameters | Out-Null } catch {
        $publishedAmbiguityRejected = $_.Exception.Message -match
            'multiple installation migration bundles'
    }
    Add-Result 'multiple completed evidence bundles fail closed' (
        $publishedAmbiguityRejected -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $publishedAmbiguity.Layout.InstallRecord).Hash -ceq
                $publishedAmbiguityTarget -and
        -not (Test-Path -LiteralPath $publishedAmbiguity.TransactionRoot)) `
        'transaction-ID publication ambiguity never mutates current metadata'

    $unknown = New-TestFixture
    $unknownValue = Get-Content -Raw -LiteralPath $unknown.Layout.InstallRecord |
        ConvertFrom-Json -DateKind String
    Add-Member -InputObject $unknownValue -NotePropertyName unexpected `
        -NotePropertyValue 'rejected'
    [void](Write-TestJson $unknown.Layout.InstallRecord $unknownValue -Protected)
    $unknownBefore = Get-FileHash -Algorithm SHA256 `
        -LiteralPath $unknown.Layout.InstallRecord
    $unknownRejected = $false
    $unknownParameters = Get-InvokeParameters $unknown
    try { & $migrationScript @unknownParameters | Out-Null } catch {
        $unknownRejected = $_.Exception.Message -match
            'neither the exact known legacy nor current shape'
    }
    Add-Result 'unknown legacy shape is rejected without mutation' (
        $unknownRejected -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $unknown.Layout.InstallRecord).Hash -ceq
            $unknownBefore.Hash -and
        -not (Test-Path -LiteralPath $unknown.TransactionRoot)) `
        'extra property is not normalized'

    $legacyCount = New-TestFixture
    $legacyCountRecord = Get-Content -Raw `
        -LiteralPath $legacyCount.Layout.InstallRecord |
        ConvertFrom-Json -DateKind String
    $legacyCountRecord.synchronizedPatchFiles = 1
    [void](Write-TestJson `
            $legacyCount.Layout.InstallRecord $legacyCountRecord -Protected)
    $legacyCountBefore = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $legacyCount.Layout.InstallRecord).Hash
    $legacyCountRejected = $false
    $legacyCountParameters = Get-InvokeParameters $legacyCount
    try { & $migrationScript @legacyCountParameters | Out-Null } catch {
        $legacyCountRejected = $_.Exception.Message -match
            'exact known pre-bb4be91 baseline state'
    }
    Add-Result 'legacy synchronized patch-file count must match manifest' (
        $legacyCountRejected -and
        (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $legacyCount.Layout.InstallRecord).Hash -ceq
                $legacyCountBefore -and
        -not (Test-Path -LiteralPath $legacyCount.TransactionRoot)) `
        'strict manifest count is bound before transaction creation'

    $currentMutations = [ordered]@{
        profile = { param($Record) $Record.clientPatchProfile = 'stable-qol' }
        server = { param($Record) $Record.serverVersion = 'unbound-server' }
        client = { param($Record) $Record.clientVersion = 'unbound-client' }
        renderer = {
            param($Record)
            $Record.rendererWrapperSha256 = '3' * 64
        }
        policy = {
            param($Record)
            $Record.clientPatchPolicySha256 = '4' * 64
        }
        synchronizedCount = {
            param($Record)
            $Record.synchronizedPatchFiles = 1
        }
    }
    $currentMutationPassed = $true
    $currentMutationDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $currentMutations.GetEnumerator()) {
        $fixture = New-TestFixture
        $parameters = Get-InvokeParameters $fixture
        & $migrationScript @parameters | Out-Null
        $record = Get-Content -Raw -LiteralPath $fixture.Layout.InstallRecord |
            ConvertFrom-Json -DateKind String
        & $entry.Value $record
        [void](Write-TestJson $fixture.Layout.InstallRecord $record -Protected)
        $before = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $rejected = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $rejected = $_.Exception.Message -match
                'exact baseline source bindings'
        }
        $passed = $rejected -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $before
        $currentMutationPassed = $currentMutationPassed -and $passed
        $currentMutationDetails.Add("$($entry.Key)=$passed")
    }
    Add-Result 'current record rejects every unbound provenance family' (
        $currentMutationPassed) ($currentMutationDetails -join '; ')

    $hardLink = New-TestFixture
    $hardLinkPath = $hardLink.Layout.InstallRecord + '.link'
    New-Item -ItemType HardLink -Path $hardLinkPath `
        -Target $hardLink.Layout.InstallRecord | Out-Null
    $hardLinkRejected = $false
    $hardLinkParameters = Get-InvokeParameters $hardLink
    try { & $migrationScript @hardLinkParameters | Out-Null } catch {
        $hardLinkRejected = $true
    }
    Remove-Item -LiteralPath $hardLinkPath -Force
    Add-Result 'hard-linked legacy target is rejected before transaction' (
        $hardLinkRejected -and
        -not (Test-Path -LiteralPath $hardLink.TransactionRoot)) `
        'single-link handle policy fails closed'

    $declaredBoundaries = @([regex]::Matches(
            $source, "Invoke-MigrationBoundary\s+'(?<point>[^']+)'" ) |
        ForEach-Object { $_.Groups['point'].Value } | Sort-Object -Unique)
    $preReplaceBoundaries = @('transaction-after-root',
        'transaction-after-original', 'transaction-after-stage',
        'install-before-replace', 'install-after-final-validation')
    $postReplaceBoundaries = @('install-after-replace')
    $rollbackBoundaries = @('rollback-before-replace',
        'rollback-after-replace')
    $cleanupBoundaries = @('cleanup-before-remove')
    $publishBoundaries = @('publish-before-move', 'publish-after-move')
    $aclBoundaries = @('acl-before-write', 'acl-after-write',
        'acl-before-rollback', 'acl-before-accept')
    $matrixBoundaries = @($preReplaceBoundaries + $postReplaceBoundaries +
        $rollbackBoundaries + $cleanupBoundaries + $publishBoundaries +
        $aclBoundaries |
        Sort-Object -Unique)
    $matrixPassed = @(Compare-Object $declaredBoundaries $matrixBoundaries).
        Count -eq 0
    $matrixDetails = [System.Collections.Generic.List[string]]::new()
    $aclRollbackBoundary = New-TestFixture
    [void](Set-TestKnownLegacyInstallationAcl $aclRollbackBoundary)
    $aclRollbackBoundaryParameters = Get-AclSetterParameters `
        $aclRollbackBoundary
    $aclRollbackBoundaryParameters.InternalTestFaultPoints = @(
        'acl-after-write', 'acl-before-rollback')
    $aclRollbackBoundaryRejected = $false
    try {
        & $aclSetterScript @aclRollbackBoundaryParameters | Out-Null
    } catch {
        $aclRollbackBoundaryRejected = $_.Exception.Message -match
            'rollback was unsafe or failed'
    }
    $aclBoundaryPassed = $beforeWritePassed -and $aclRollbackRejected -and
        $aclRollbackBoundaryRejected -and $lateDaclRejected -and
        (Test-PSOBBProtectedAcl -Path `
            $aclRollbackBoundary.Layout.InstallRecord)
    $matrixPassed = $matrixPassed -and $aclBoundaryPassed
    $matrixDetails.Add("acl-before-write=$beforeWritePassed")
    $matrixDetails.Add("acl-after-write=$aclRollbackRejected")
    $matrixDetails.Add(
        "acl-before-rollback=$aclRollbackBoundaryRejected")
    $matrixDetails.Add("acl-before-accept=$lateDaclRejected")
    foreach ($boundary in $preReplaceBoundaries) {
        $fixture = New-TestFixture
        $beforeHash = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $beforeIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $fixture.Layout.InstallRecord -Root $fixture.Layout.Root `
            -Directory $false -RoleLabel 'Migration matrix original'
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestFaultPoints = @($boundary)
        $observed = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $observed = $_.Exception.Message -match 'Injected'
        }
        $afterIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $fixture.Layout.InstallRecord -Root $fixture.Layout.Root `
            -Directory $false -RoleLabel 'Migration matrix original'
        $passed = $observed -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $beforeHash -and
            $beforeIdentity.VolumeSerialNumber -eq
                $afterIdentity.VolumeSerialNumber -and
            $beforeIdentity.FileId -eq $afterIdentity.FileId -and
            (Test-PSOBBProtectedAcl -Path $fixture.Layout.InstallRecord) -and
            -not (Test-Path -LiteralPath $fixture.TransactionRoot)
        $matrixPassed = $matrixPassed -and $passed
        $matrixDetails.Add("$boundary=$passed")
    }
    foreach ($boundary in $postReplaceBoundaries) {
        $fixture = New-TestFixture
        $beforeHash = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $beforeIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $fixture.Layout.InstallRecord -Root $fixture.Layout.Root `
            -Directory $false -RoleLabel 'Migration matrix original'
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestFaultPoints = @($boundary)
        $observed = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $observed = $_.Exception.Message -match 'Injected'
        }
        $afterIdentity = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $fixture.Layout.InstallRecord -Root $fixture.Layout.Root `
            -Directory $false -RoleLabel 'Migration matrix restored original'
        $passed = $observed -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $beforeHash -and
            $beforeIdentity.VolumeSerialNumber -eq
                $afterIdentity.VolumeSerialNumber -and
            $beforeIdentity.FileId -eq $afterIdentity.FileId -and
            (Test-PSOBBProtectedAcl -Path $fixture.Layout.InstallRecord) -and
            -not (Test-Path -LiteralPath $fixture.TransactionRoot)
        $matrixPassed = $matrixPassed -and $passed
        $matrixDetails.Add("$boundary=$passed")
    }
    foreach ($boundary in $rollbackBoundaries) {
        $fixture = New-TestFixture
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestFaultPoints = @(
            'install-after-replace', $boundary)
        $observed = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $observed = $_.Exception.Message -match
                'conditional recovery did not complete'
        }
        $retained = Test-Path -LiteralPath $fixture.TransactionRoot
        $protected = $false
        if ($retained) {
            $tree = Get-PSOBBOrdinaryTreeSnapshot `
                -Path $fixture.TransactionRoot -Root $fixture.Layout.Stable `
                -Label 'retained migration matrix evidence' -RequireProtectedAcl
            $protected = $tree.Items.Count -ge 5
        }
        $resumeParameters = Get-InvokeParameters $fixture
        $resumed = & $migrationScript @resumeParameters
        $idempotent = & $migrationScript @resumeParameters
        $passed = $observed -and $retained -and $protected -and
            [bool]$resumed.Changed -and
            -not [bool]$idempotent.Changed -and
            (Test-FinalMigrationState $fixture)
        $matrixPassed = $matrixPassed -and $passed
        $matrixDetails.Add("$boundary=$passed")
    }
    foreach ($boundary in $cleanupBoundaries) {
        $fixture = New-TestFixture
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestFaultPoints = @(
            'transaction-after-root', $boundary)
        $observed = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $observed = $_.Exception.Message -match
                'conditional recovery did not complete'
        }
        $retained = Test-Path -LiteralPath $fixture.TransactionRoot
        $resumeParameters = Get-InvokeParameters $fixture
        $resumed = & $migrationScript @resumeParameters
        $idempotent = & $migrationScript @resumeParameters
        $passed = $observed -and $retained -and
            [bool]$resumed.Changed -and -not [bool]$idempotent.Changed -and
            (Test-FinalMigrationState $fixture)
        $matrixPassed = $matrixPassed -and $passed
        $matrixDetails.Add("$boundary=$passed")
    }
    foreach ($boundary in $publishBoundaries) {
        $fixture = New-TestFixture
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestFaultPoints = @($boundary)
        $observed = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $observed = $_.Exception.Message -match 'Injected'
        }
        $resumeParameters = Get-InvokeParameters $fixture
        $resumed = & $migrationScript @resumeParameters
        $passed = $observed -and -not [bool]$resumed.Changed -and
            (Test-FinalMigrationState $fixture)
        $matrixPassed = $matrixPassed -and $passed
        $matrixDetails.Add("$boundary=$passed")
    }
    Add-Result 'all declared transaction boundaries satisfy recovery matrix' (
        $matrixPassed) ($matrixDetails -join '; ')

    $rootRace = New-TestFixture
    $rootSaved = $rootRace.TransactionRoot + '.saved'
    $rootHook = {
        param($Context)
        [System.IO.Directory]::Move($Context.Root, $rootSaved)
        New-Item -ItemType Junction -Path $Context.Root -Target $rootSaved |
            Out-Null
    }
    $rootParameters = Get-InvokeParameters $rootRace
    $rootParameters.InternalTestHookPoint = 'transaction-after-root'
    $rootParameters.InternalTestHook = $rootHook
    $rootRejected = $false
    try { & $migrationScript @rootParameters | Out-Null } catch {
        $rootRejected = $true
    }
    $rootEvidence = Test-Path -LiteralPath $rootRace.TransactionRoot
    if ($rootEvidence) {
        Remove-Item -LiteralPath $rootRace.TransactionRoot -Force
    }
    if (Test-Path -LiteralPath $rootSaved) {
        Remove-Item -LiteralPath $rootSaved -Recurse -Force
    }
    Add-Result 'transaction-root reparse substitution fails closed' (
        $rootRejected -and $rootEvidence -and
        [string](Get-Item -Force -LiteralPath $rootRace.Layout.InstallRecord).
            Attributes -notmatch 'ReparsePoint') `
        'native root creation is revalidated before any transaction artifact'

    $artifactRacePassed = $true
    $artifactRaceDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($artifactName in @('original-installation.json',
            'candidate-installation.json', 'candidate-installation.stage',
            'journal.json')) {
        $fixture = New-TestFixture
        $linkPath = Join-Path $fixture.Layout.Stable (
            '.migration-artifact-link-' + [Guid]::NewGuid().ToString('N'))
        $hook = {
            param($Context)
            New-Item -ItemType HardLink -Path $linkPath `
                -Target (Join-Path $Context.TransactionRoot $artifactName) |
                Out-Null
        }
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestHookPoint = 'install-after-final-validation'
        $parameters.InternalTestHook = $hook
        $rejected = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $rejected = $true
        }
        $retained = Test-Path -LiteralPath $fixture.TransactionRoot
        if (Test-Path -LiteralPath $linkPath) {
            Remove-Item -LiteralPath $linkPath -Force
        }
        $resumeParameters = Get-InvokeParameters $fixture
        $resumed = & $migrationScript @resumeParameters
        $idempotent = & $migrationScript @resumeParameters
        $expectedChanged = $artifactName -ceq 'candidate-installation.stage'
        $passed = $rejected -and $retained -and
            ([bool]$resumed.Changed -eq $expectedChanged) -and
            -not [bool]$idempotent.Changed -and
            (Test-FinalMigrationState $fixture)
        $artifactRacePassed = $artifactRacePassed -and $passed
        $artifactRaceDetails.Add(
            "$artifactName=$passed/rejected=$rejected/retained=$retained/" +
            "changed=$([bool]$resumed.Changed)/expected=$expectedChanged")
    }
    Add-Result 'all transaction artifacts reject hard-link substitution' (
        $artifactRacePassed) ($artifactRaceDetails -join '; ')

    $artifactReparse = New-TestFixture
    $artifactReparsePath = Join-Path $artifactReparse.TransactionRoot `
        'candidate-installation.json'
    $artifactReparseSaved = Join-Path $artifactReparse.Layout.Stable (
        '.migration-artifact-saved-' + [Guid]::NewGuid().ToString('N'))
    $artifactReparseHook = {
        param($Context)
        [System.IO.File]::Move(
            $artifactReparsePath, $artifactReparseSaved, $false)
        [void][System.IO.File]::CreateSymbolicLink(
            $artifactReparsePath, $artifactReparseSaved)
    }
    $artifactReparseParameters = Get-InvokeParameters $artifactReparse
    $artifactReparseParameters.InternalTestHookPoint =
        'install-after-final-validation'
    $artifactReparseParameters.InternalTestHook = $artifactReparseHook
    $artifactReparseRejected = $false
    try { & $migrationScript @artifactReparseParameters | Out-Null } catch {
        $artifactReparseRejected = $true
    }
    $artifactReparseRetained =
        Test-Path -LiteralPath $artifactReparse.TransactionRoot
    $artifactReparseObserved = $false
    if (Test-Path -LiteralPath $artifactReparsePath) {
        $artifactReparseObserved = [bool]((Get-Item -Force `
                    -LiteralPath $artifactReparsePath).Attributes -band
                [System.IO.FileAttributes]::ReparsePoint)
        [System.IO.File]::Delete($artifactReparsePath)
    }
    if (Test-Path -LiteralPath $artifactReparseSaved) {
        [System.IO.File]::Move(
            $artifactReparseSaved, $artifactReparsePath, $false)
    }
    $artifactReparseResumeParameters = Get-InvokeParameters $artifactReparse
    $artifactReparseResumed =
        & $migrationScript @artifactReparseResumeParameters
    $artifactReparseIdempotent =
        & $migrationScript @artifactReparseResumeParameters
    Add-Result 'transaction-artifact reparse substitution fails closed' (
        $artifactReparseRejected -and $artifactReparseRetained -and
        $artifactReparseObserved -and
        -not [bool]$artifactReparseResumed.Changed -and
        -not [bool]$artifactReparseIdempotent.Changed -and
        (Test-FinalMigrationState $artifactReparse)) `
        'clean rerun publishes only the exact identity-bound candidate'

    $markerRacePassed = $true
    $markerRaceDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($markerCase in @('missing', 'extra', 'transaction', 'purpose',
            'root', 'replaced', 'hard-linked')) {
        $fixture = New-TestFixture
        $markerPath = Join-Path $fixture.TransactionRoot `
            '.psobb-combat-canary-transaction.json'
        $savedMarker = Join-Path $fixture.Layout.Stable (
            '.migration-marker-saved-' + [Guid]::NewGuid().ToString('N'))
        $markerLink = Join-Path $fixture.Layout.Stable (
            '.migration-marker-link-' + [Guid]::NewGuid().ToString('N'))
        $targetBefore = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $fixture.Layout.InstallRecord -Root $fixture.Layout.Root `
            -Directory $false -RoleLabel 'Marker-race target'
        $targetHash = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $hook = {
            param($Context)
            if ($markerCase -ceq 'hard-linked') {
                New-Item -ItemType HardLink -Path $markerLink `
                    -Target $markerPath | Out-Null
                return
            }
            [System.IO.File]::Move($markerPath, $savedMarker, $false)
            if ($markerCase -ceq 'missing') { return }
            if ($markerCase -ceq 'replaced') {
                [System.IO.File]::Copy($savedMarker, $markerPath, $false)
                Set-PSOBBProtectedAcl -Path $markerPath
                return
            }
            $value = Get-Content -Raw -LiteralPath $savedMarker |
                ConvertFrom-Json -DateKind String
            switch ($markerCase) {
                'extra' {
                    Add-Member -InputObject $value -NotePropertyName extra `
                        -NotePropertyValue 'rejected'
                }
                'transaction' {
                    $value.transactionId = if (
                        [string]$value.transactionId -clike '0*') {
                        '1' + ([string]$value.transactionId).Substring(1)
                    } else {
                        '0' + ([string]$value.transactionId).Substring(1)
                    }
                }
                'purpose' { $value.purpose = 'invalid-migration-purpose' }
                'root' { $value.rootFileId = '0000000000000000' }
            }
            [void](Write-TestJson $markerPath $value -Protected)
        }
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestHookPoint = 'install-after-final-validation'
        $parameters.InternalTestHook = $hook
        $rejected = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $rejected = $true
        }
        $retained = Test-Path -LiteralPath $fixture.TransactionRoot
        $targetAfter = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $fixture.Layout.InstallRecord -Root $fixture.Layout.Root `
            -Directory $false -RoleLabel 'Marker-race unchanged target'
        $unchanged = $targetBefore.VolumeSerialNumber -eq
                $targetAfter.VolumeSerialNumber -and
            $targetBefore.FileId -eq $targetAfter.FileId -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $targetHash
        if (Test-Path -LiteralPath $markerLink) {
            Remove-Item -LiteralPath $markerLink -Force
        }
        if ($markerCase -cne 'hard-linked') {
            if (Test-Path -LiteralPath $markerPath) {
                [System.IO.File]::Delete($markerPath)
            }
            [System.IO.File]::Move($savedMarker, $markerPath, $false)
        }
        $resumeParameters = Get-InvokeParameters $fixture
        $resumed = & $migrationScript @resumeParameters
        $idempotent = & $migrationScript @resumeParameters
        $passed = $rejected -and $retained -and $unchanged -and
            [bool]$resumed.Changed -and -not [bool]$idempotent.Changed -and
            (Test-FinalMigrationState $fixture)
        $markerRacePassed = $markerRacePassed -and $passed
        $markerRaceDetails.Add("$markerCase=$passed")
    }
    Add-Result 'transaction marker tampering fails closed and resumes exactly' (
        $markerRacePassed) ($markerRaceDetails -join '; ')

    $publicationRacePassed = $true
    $publicationRaceDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($publicationCase in @('journal', 'original', 'displaced',
            'backups')) {
        $fixture = New-TestFixture
        $savedPath = Join-Path $fixture.Layout.Stable (
            '.migration-publication-saved-' +
            [Guid]::NewGuid().ToString('N'))
        $backupSaved = $fixture.Layout.Backups + '.saved'
        $hook = {
            param($Context)
            if ($publicationCase -ceq 'backups') {
                [System.IO.Directory]::Move($Context.BackupPath, $backupSaved)
                New-Item -ItemType Junction -Path $Context.BackupPath `
                    -Target $backupSaved | Out-Null
                return
            }
            $artifactName = switch ($publicationCase) {
                'journal' { 'journal.json' }
                'original' { 'original-installation.json' }
                'displaced' { 'displaced-installation.json' }
            }
            $artifactPath = Join-Path $Context.TransactionRoot $artifactName
            [System.IO.File]::Move($artifactPath, $savedPath, $false)
            [System.IO.File]::Copy($savedPath, $artifactPath, $false)
            Set-PSOBBProtectedAcl -Path $artifactPath
        }
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestHookPoint = 'publish-before-move'
        $parameters.InternalTestHook = $hook
        $rejected = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $rejected = $true
        }
        $retained = Test-Path -LiteralPath $fixture.TransactionRoot
        $published = @(Get-ChildItem -LiteralPath $fixture.Layout.Backups `
                -Directory -Filter 'installation-record-migration-*' `
                -ErrorAction SilentlyContinue).Count -eq 1
        $boundaryDefended = $true
        if ($publicationCase -ceq 'backups') {
            $boundaryStable =
                (Test-Path -LiteralPath $fixture.Layout.Backups) -and
                -not (Test-Path -LiteralPath $backupSaved) -and
                -not [bool]((Get-Item -Force `
                        -LiteralPath $fixture.Layout.Backups).Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint)
            $boundarySubstitutionObserved =
                (Test-Path -LiteralPath $backupSaved) -or
                ((Test-Path -LiteralPath $fixture.Layout.Backups) -and
                 [bool]((Get-Item -Force `
                            -LiteralPath $fixture.Layout.Backups).Attributes -band
                        [System.IO.FileAttributes]::ReparsePoint))
            $boundaryDefended = $boundaryStable -or
                ($boundarySubstitutionObserved -and $retained -and
                    -not $published)
            if (Test-Path -LiteralPath $fixture.Layout.Backups) {
                $backupItem = Get-Item -Force `
                    -LiteralPath $fixture.Layout.Backups
                if ($backupItem.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) {
                    Remove-Item -LiteralPath $fixture.Layout.Backups -Force
                }
            }
            if (Test-Path -LiteralPath $backupSaved) {
                [System.IO.Directory]::Move(
                    $backupSaved, $fixture.Layout.Backups)
            }
        } elseif (Test-Path -LiteralPath $savedPath) {
            $artifactName = switch ($publicationCase) {
                'journal' { 'journal.json' }
                'original' { 'original-installation.json' }
                'displaced' { 'displaced-installation.json' }
            }
            $artifactPath = Join-Path $fixture.TransactionRoot $artifactName
            if (Test-Path -LiteralPath $artifactPath) {
                [System.IO.File]::Delete($artifactPath)
            }
            [System.IO.File]::Move($savedPath, $artifactPath, $false)
        }
        $resumeParameters = Get-InvokeParameters $fixture
        $resumed = & $migrationScript @resumeParameters
        $idempotent = & $migrationScript @resumeParameters
        $passed = $rejected -and ($retained -or $published) -and
            $boundaryDefended -and -not [bool]$resumed.Changed -and
            -not [bool]$idempotent.Changed -and
            (Test-FinalMigrationState $fixture)
        $publicationRacePassed = $publicationRacePassed -and $passed
        $publicationRaceDetails.Add(
            "$publicationCase=$passed/retained=$retained/" +
            "published=$published/defended=$boundaryDefended")
    }
    Add-Result 'final publication seal and backup lease reject substitutions' (
        $publicationRacePassed) ($publicationRaceDetails -join '; ')

    $postMoveJournal = New-TestFixture
    $postMoveJournalSaved = Join-Path $postMoveJournal.Layout.Stable (
        '.migration-post-move-journal-' + [Guid]::NewGuid().ToString('N'))
    $postMoveJournalHook = {
        param($Context)
        $journalPath = Join-Path $Context.DestinationPath 'journal.json'
        [System.IO.File]::Move(
            $journalPath, $postMoveJournalSaved, $false)
        [System.IO.File]::Copy(
            $postMoveJournalSaved, $journalPath, $false)
        Set-PSOBBProtectedAcl -Path $journalPath
    }
    $postMoveJournalParameters = Get-InvokeParameters $postMoveJournal
    $postMoveJournalParameters.InternalTestHookPoint = 'publish-after-move'
    $postMoveJournalParameters.InternalTestHook = $postMoveJournalHook
    $postMoveJournalRejected = $false
    try { & $migrationScript @postMoveJournalParameters | Out-Null } catch {
        $postMoveJournalRejected = $_.Exception.Message -match
            'conditional recovery did not complete'
    }
    $postMovePublished = @(Get-ChildItem `
        -LiteralPath $postMoveJournal.Layout.Backups -Directory `
        -Filter 'installation-record-migration-*')
    $postMoveJournalRetained = $postMovePublished.Count -eq 1 -and
        (Test-Path -LiteralPath $postMoveJournalSaved) -and
        -not (Test-Path -LiteralPath $postMoveJournal.TransactionRoot)
    if ($postMovePublished.Count -eq 1 -and
        (Test-Path -LiteralPath $postMoveJournalSaved)) {
        $journalPath = Join-Path $postMovePublished[0].FullName 'journal.json'
        [System.IO.File]::Delete($journalPath)
        [System.IO.File]::Move(
            $postMoveJournalSaved, $journalPath, $false)
    }
    $postMoveResumeParameters = Get-InvokeParameters $postMoveJournal
    $postMoveResumed = & $migrationScript @postMoveResumeParameters
    $postMoveIdempotent = & $migrationScript @postMoveResumeParameters
    Add-Result 'post-move journal replacement remains fail-closed' (
        $postMoveJournalRejected -and $postMoveJournalRetained -and
        -not [bool]$postMoveResumed.Changed -and
        -not [bool]$postMoveIdempotent.Changed -and
        (Test-FinalMigrationState $postMoveJournal)) `
        'outer recovery requires the original sealed journal identity'

    $bindingRacePassed = $true
    $bindingRaceDetails = [System.Collections.Generic.List[string]]::new()
    foreach ($bindingName in @('marker', 'source', 'policy', 'config',
            'renderer')) {
        $fixture = New-TestFixture
        $bindingPath = switch ($bindingName) {
            'marker' { $fixture.Layout.RuntimeMarker }
            'source' { $fixture.SourceLockPath }
            'policy' { $fixture.PolicyPath }
            'config' { Join-Path $fixture.Layout.Server 'system\config.json' }
            'renderer' { $fixture.RendererConfig.Path }
        }
        $savedPath = $bindingPath + '.swap-attempt'
        $hook = {
            param($Context)
            [System.IO.File]::Move($bindingPath, $savedPath, $false)
            [System.IO.File]::Copy($savedPath, $bindingPath, $false)
            if ($bindingName -cin @('marker', 'source', 'policy')) {
                Set-PSOBBProtectedAcl -Path $bindingPath
            }
        }
        $before = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $fixture.Layout.InstallRecord).Hash
        $parameters = Get-InvokeParameters $fixture
        $parameters.InternalTestHookPoint = 'install-after-final-validation'
        $parameters.InternalTestHook = $hook
        $rejected = $false
        try { & $migrationScript @parameters | Out-Null } catch {
            $rejected = $true
        }
        $passed = $rejected -and
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $fixture.Layout.InstallRecord).Hash -ceq $before -and
            (Test-PSOBBProtectedAcl -Path $fixture.Layout.InstallRecord) -and
            -not (Test-Path -LiteralPath $fixture.TransactionRoot)
        $bindingRacePassed = $bindingRacePassed -and $passed
        $bindingRaceDetails.Add("$bindingName=$passed")
    }
    Add-Result 'marker, source, policy, config, and renderer swaps fail closed' (
        $bindingRacePassed) ($bindingRaceDetails -join '; ')

    $race = New-TestFixture
    $raceSaved = $race.Layout.InstallRecord + '.saved'
    $raceHook = {
        param($Context)
        [System.IO.File]::Move($Context.TargetPath, $raceSaved, $false)
        [System.IO.File]::Copy($raceSaved, $Context.TargetPath, $false)
        Set-PSOBBProtectedAcl -Path $Context.TargetPath
    }
    $raceParameters = Get-InvokeParameters $race
    $raceParameters.InternalTestHookPoint = 'install-after-final-validation'
    $raceParameters.InternalTestHook = $raceHook
    $raceRejected = $false
    try { & $migrationScript @raceParameters | Out-Null } catch {
        $raceRejected = $_.Exception.Message -match
            'conditional recovery did not complete'
    }
    Add-Result 'same-byte target substitution retains evidence' (
        $raceRejected -and
        (Test-Path -LiteralPath $race.TransactionRoot) -and
        (Test-Path -LiteralPath $raceSaved)) `
        'digest equality cannot substitute for the sealed target identity'

    $linkRace = New-TestFixture
    $linkRacePath = $linkRace.Layout.InstallRecord + '.race-link'
    $linkHook = {
        param($Context)
        New-Item -ItemType HardLink -Path $linkRacePath `
            -Target $Context.TargetPath | Out-Null
    }
    $linkParameters = Get-InvokeParameters $linkRace
    $linkParameters.InternalTestHookPoint = 'install-after-final-validation'
    $linkParameters.InternalTestHook = $linkHook
    $linkRejected = $false
    try { & $migrationScript @linkParameters | Out-Null } catch {
        $linkRejected = $true
    }
    $linkEvidence = Test-Path -LiteralPath $linkRace.TransactionRoot
    Remove-Item -LiteralPath $linkRacePath -Force
    $linkResumeParameters = Get-InvokeParameters $linkRace
    $linkResumed = & $migrationScript @linkResumeParameters
    $linkIdempotent = & $migrationScript @linkResumeParameters
    Add-Result 'hard-link race retains evidence and clean rerun converges' (
        $linkRejected -and $linkEvidence -and [bool]$linkResumed.Changed -and
        -not [bool]$linkIdempotent.Changed -and
        (Test-FinalMigrationState $linkRace)) `
        'second handle-bound preflight and retained recovery both fail closed'
} finally {
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    $temporaryRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).TrimEnd('\')
    foreach ($root in $fixtureRoots) {
        $fullRoot = [System.IO.Path]::GetFullPath($root)
        $isExactFixtureRoot =
            [string]::Equals(
                [System.IO.Path]::GetDirectoryName($fullRoot),
                $temporaryRoot,
                [System.StringComparison]::OrdinalIgnoreCase) -and
            [System.IO.Path]::GetFileName($fullRoot) -cmatch
            '^PSOBB-StableInstallationRecordMigrationTests-[a-f0-9]{32}$'
        if (-not $isExactFixtureRoot) {
            $cleanupFailures.Add(
                "Refused to clean an invalid fixture root: $fullRoot")
            continue
        }

        if (Test-Path -LiteralPath $fullRoot) {
            try {
                Remove-Item -LiteralPath $fullRoot -Recurse -Force `
                    -ErrorAction Stop
            } catch {
                $cleanupFailures.Add(
                    "Fixture cleanup failed for $fullRoot`: $($_.Exception.Message)")
            }
        }
        if (Test-Path -LiteralPath $fullRoot) {
            $cleanupFailures.Add(
                "Fixture root remains after cleanup: $fullRoot")
        }
    }
    if ($cleanupFailures.Count -gt 0) {
        throw ($cleanupFailures -join [Environment]::NewLine)
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    $failed | Format-List Name, Detail
    throw "$($failed.Count) Stable installation-record migration test(s) failed"
}
