[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1')
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Invoke-RuntimeAclVerifier([Parameter(Mandatory)][string]$RuntimeRoot) {
    $records = [System.Collections.Generic.List[object]]::new()
    $caught = $null
    try {
        & (Join-Path $repositoryRoot 'scripts\Test-PSOBBRuntimeAcl.ps1') `
            -RuntimeRoot $RuntimeRoot |
            ForEach-Object { [void]$records.Add($_) }
    } catch {
        $caught = $_
    }

    [pscustomobject]@{
        Records = @($records)
        ErrorRecord = $caught
    }
}

function Test-ExactProtectedAcl([Parameter(Mandatory)][string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $expectedSids = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18',
        'S-1-5-32-544'
    ) | Sort-Object -Unique
    $actualRules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]))
    $actualSids = @($actualRules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    $item = Get-Item -Force -LiteralPath $Path
    $expectedInheritance = if ($item.PSIsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }

    $acl.AreAccessRulesProtected -and
        $acl.AreAccessRulesCanonical -and
        ($actualRules.Count -eq 3) -and
        (@(Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids).Count -eq 0) -and
        (@($actualRules | Where-Object {
            $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $_.IsInherited -or
            $_.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $_.InheritanceFlags -ne $expectedInheritance -or
            $_.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
        }).Count -eq 0)
}

function Set-KnownLegacyRuntimeMarkerAcl([Parameter(Mandatory)]$Layout) {
    Set-PSOBBProtectedAcl -Path $Layout.Root
    $marker = Assert-PSOBBOrdinaryContainedPath `
        -Path $Layout.RuntimeMarker -Root $Layout.Root -Kind File `
        -Label 'runtime ownership marker fixture'
    $legacy = [System.Security.AccessControl.FileSecurity]::new()
    $legacy.SetAccessRuleProtection($false, $false)
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $marker),
        $legacy)
    Assert-PSOBBLegacyRuntimeMarkerAclState -Layout $Layout
}

$setterPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1'
$setterTokens = $null
$setterParseErrors = $null
$setterAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $setterPath,
    [ref]$setterTokens,
    [ref]$setterParseErrors)
$setterCommands = @($setterAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
$setterSource = [System.IO.File]::ReadAllText($setterPath)
$usesDaclOnlyWriter =
    $setterParseErrors.Count -eq 0 -and
    'Get-Acl' -notin $setterCommands -and
    'Set-Acl' -notin $setterCommands -and
    $setterSource.Contains('[System.Security.AccessControl.DirectorySecurity]::new()') -and
    $setterSource.Contains('[System.Security.AccessControl.FileSecurity]::new()') -and
    $setterSource.Contains('[System.IO.FileSystemAclExtensions]::SetAccessControl(')
Add-Result 'runtime ACL setter uses a fresh DACL-only writer' `
    $usesDaclOnlyWriter `
    'no full on-disk descriptor is read or persisted and owner, group, and audit sections are not requested'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-RuntimeAclTests-' + [Guid]::NewGuid().ToString('N'))
$outsideRoot = $temporaryRoot + '-outside'
$layout = Get-PSOBBLayout -RuntimeRoot $temporaryRoot
$combatCanary = Get-PSOBBServerEnvironmentLayout `
    -Layout $layout -Environment CombatCanary
try {
    $stableOnlyTargets = @(Get-PSOBBRuntimeAclTargets -Layout $layout)
    Add-Result 'runtime ACL target inventory remains stable before canary materialization' `
        ($stableOnlyTargets.Count -eq 11 -and
         @($stableOnlyTargets.Name | Where-Object {
                $_ -like 'combat-canary-*'
            }).Count -eq 0) `
        'optional combat-canary trees do not change the established stable policy'

    foreach ($directory in @(
        $layout.Root,
        (Join-Path $layout.Server 'system\licenses'),
        (Join-Path $layout.Server 'system\players'),
        (Join-Path $layout.Server 'system\teams'),
        $layout.Secrets,
        $layout.Backups,
        $layout.Logs,
        (Join-Path $layout.Root 'graphics-evidence'),
        (Join-Path $layout.Archives 'graphics-lab\local-assets'),
        (Join-Path $layout.LocalLab 'asset-overlays'),
        (Join-Path $layout.LocalLab 'asset-activations'),
        (Join-Path $layout.LocalLab 'visual-asset-activations'),
        (Join-Path $combatCanary.Server 'system\licenses'),
        (Join-Path $combatCanary.Server 'system\players'),
        (Join-Path $combatCanary.Server 'system\teams'),
        $combatCanary.Secrets,
        $combatCanary.Backups,
        $combatCanary.Logs,
        $combatCanary.Snapshots,
        $combatCanary.ControlDirectory,
        $combatCanary.Builds)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Initialize-PSOBBRuntimeMarker -Layout $layout | Out-Null

    $expectedCanaryTargetPaths = [ordered]@{
        'combat-canary-backups' = $combatCanary.Backups
        'combat-canary-builds' = $combatCanary.Builds
        'combat-canary-control' = $combatCanary.ControlDirectory
        'combat-canary-licenses' = Join-Path $combatCanary.Server 'system\licenses'
        'combat-canary-logs' = $combatCanary.Logs
        'combat-canary-players' = Join-Path $combatCanary.Server 'system\players'
        'combat-canary-secrets' = $combatCanary.Secrets
        'combat-canary-snapshots' = $combatCanary.Snapshots
        'combat-canary-teams' = Join-Path $combatCanary.Server 'system\teams'
    }
    $materializedTargets = @(Get-PSOBBRuntimeAclTargets -Layout $layout)
    $materializedCanaryTargets = @($materializedTargets | Where-Object {
            $_.Name -like 'combat-canary-*'
        })
    $canaryTargetIdentityExact = $materializedCanaryTargets.Count -eq 9
    foreach ($expectedTarget in $expectedCanaryTargetPaths.GetEnumerator()) {
        $matches = @($materializedCanaryTargets | Where-Object {
                $_.Name -ceq $expectedTarget.Key -and
                ([System.IO.Path]::GetFullPath([string]$_.Path)).Equals(
                    [System.IO.Path]::GetFullPath([string]$expectedTarget.Value),
                    [System.StringComparison]::OrdinalIgnoreCase)
            })
        if ($matches.Count -ne 1) {
            $canaryTargetIdentityExact = $false
        }
    }
    Add-Result 'runtime ACL policy declares exact combat-canary target identities' `
        $canaryTargetIdentityExact `
        'only materialized account, evidence, control, build, and secret trees are added'

    $logFile = Join-Path $layout.Logs 'server-fixture.log'
    [System.IO.File]::WriteAllText($logFile, 'fixture')
    $nestedLogDirectory = Join-Path $layout.Logs 'archive'
    New-Item -ItemType Directory -Path $nestedLogDirectory | Out-Null
    $nestedLogFile = Join-Path $nestedLogDirectory 'archived-fixture.log'
    [System.IO.File]::WriteAllText($nestedLogFile, 'nested fixture')
    $licenseFixture = Join-Path $layout.Server 'system\licenses\0000000001.json'
    [System.IO.File]::WriteAllText($licenseFixture, '{"fixture":true}')
    $playerFixture = Join-Path $layout.Server 'system\players\fixture'
    New-Item -ItemType Directory -Path $playerFixture | Out-Null
    $teamFixture = Join-Path $layout.Server 'system\teams\fixture.json'
    [System.IO.File]::WriteAllText($teamFixture, '{"fixture":true}')
    $secretFixture = Join-Path $layout.Secrets 'fixture.key'
    [System.IO.File]::WriteAllText($secretFixture, 'not-a-real-secret')
    $backupFixture = Join-Path $layout.Backups 'state-fixture'
    New-Item -ItemType Directory -Path $backupFixture | Out-Null
    $graphicsFixture = Join-Path $layout.Root 'graphics-evidence\private-frame.png'
    [System.IO.File]::WriteAllText($graphicsFixture, 'private fixture')
    $assetArchiveFixture = Join-Path $layout.Archives 'graphics-lab\local-assets\private-pack.zip'
    [System.IO.File]::WriteAllText($assetArchiveFixture, 'private fixture')
    $overlayFixture = Join-Path $layout.LocalLab 'asset-overlays\foundation.json'
    [System.IO.File]::WriteAllText($overlayFixture, 'private fixture')
    $activationFixture = Join-Path $layout.LocalLab 'asset-activations\activation.json'
    [System.IO.File]::WriteAllText($activationFixture, 'private fixture')
    $supplementalFixture = Join-Path $layout.LocalLab 'visual-asset-activations\activation.json'
    [System.IO.File]::WriteAllText($supplementalFixture, 'private fixture')
    $canaryLicenseFixture = Join-Path $combatCanary.Server 'system\licenses\0000000001.json'
    [System.IO.File]::WriteAllText($canaryLicenseFixture, '{"fixture":true}')
    $canaryPlayerFixture = Join-Path $combatCanary.Server 'system\players\fixture'
    New-Item -ItemType Directory -Path $canaryPlayerFixture | Out-Null
    $canaryTeamFixture = Join-Path $combatCanary.Server 'system\teams\fixture.json'
    [System.IO.File]::WriteAllText($canaryTeamFixture, '{"fixture":true}')
    $canarySecretFixture = Join-Path $combatCanary.Secrets 'fixture.key'
    [System.IO.File]::WriteAllText($canarySecretFixture, 'not-a-real-secret')
    $canaryBackupFixture = Join-Path $combatCanary.Backups 'state-fixture'
    New-Item -ItemType Directory -Path $canaryBackupFixture | Out-Null
    $canaryLogFixture = Join-Path $combatCanary.Logs 'server-fixture.log'
    [System.IO.File]::WriteAllText($canaryLogFixture, 'fixture')
    $canarySnapshotFixture = Join-Path $combatCanary.Snapshots 'twills-snapshot.json'
    [System.IO.File]::WriteAllText($canarySnapshotFixture, '{"fixture":true}')
    $canaryControlFixture = Join-Path $combatCanary.ControlDirectory 'fixture.json'
    [System.IO.File]::WriteAllText($canaryControlFixture, '{"fixture":true}')
    $canaryBuildFixture = Join-Path $combatCanary.Builds 'build-receipt.json'
    [System.IO.File]::WriteAllText($canaryBuildFixture, '{"fixture":true}')

    $markerBefore = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $layout
    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout
    $legacySetterRejected = $false
    try {
        & $setterPath -RuntimeRoot $layout.Root -Confirm:$false | Out-Null
    } catch {
        $legacySetterRejected = $true
    }
    $legacyAfterRejection = Assert-PSOBBLegacyRuntimeMarkerAclState -Layout $layout
    Add-Result 'legacy marker requires the explicit migration switch' `
        ($legacySetterRejected -and
         $legacyAfterRejection.Sha256 -ceq $legacyMarker.Sha256 -and
         $legacyAfterRejection.AccessSddl -ceq $legacyMarker.AccessSddl) `
        'normal recursive ACL maintenance cannot silently migrate the ownership marker'

    $preview = @(& $setterPath `
        -RuntimeRoot $layout.Root -MigrateLegacyRuntimeMarkerAcl -WhatIf)
    $legacyAfterPreview = Assert-PSOBBLegacyRuntimeMarkerAclState -Layout $layout
    Add-Result 'legacy marker migration honors WhatIf without mutation' `
        ($preview.Count -eq 1 -and
         -not $preview[0].Changed -and
         $preview[0].Kind -ceq 'runtime-marker-migration-preview' -and
         $legacyAfterPreview.Sha256 -ceq $legacyMarker.Sha256 -and
         $legacyAfterPreview.AccessSddl -ceq $legacyMarker.AccessSddl) `
        'preview validates the exact legacy marker but does not replace its DACL'

    $everyoneRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $unknownMarkerAcl = Get-Acl -LiteralPath $layout.RuntimeMarker
    [void]$unknownMarkerAcl.AddAccessRule($everyoneRule)
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $layout.RuntimeMarker),
        [System.Security.AccessControl.FileSecurity]$unknownMarkerAcl)
    $unknownMarker = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $layout
    $unknownRejected = $false
    try {
        & $setterPath `
            -RuntimeRoot $layout.Root -MigrateLegacyRuntimeMarkerAcl `
            -Confirm:$false | Out-Null
    } catch {
        $unknownRejected = $true
    }
    $unknownAfter = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $layout
    Add-Result 'runtime-marker migration rejects an unrecognized ACL' `
        ($unknownRejected -and
         $unknownAfter.Sha256 -ceq $unknownMarker.Sha256 -and
         $unknownAfter.AccessSddl -ceq $unknownMarker.AccessSddl) `
        'an extra identity cannot be normalized by the one-time migration path'

    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout
    New-Item -ItemType Directory -Path $layout.ControlDirectory -Force |
        Out-Null
    [System.IO.File]::WriteAllText(
        $layout.ControlState,
        '{"fixture":true}',
        [System.Text.UTF8Encoding]::new($false))
    $lifecycleEvidenceRejected = $false
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl -Layout $layout | Out-Null
    } catch {
        $lifecycleEvidenceRejected = $true
    }
    $markerAfterLifecycleRejection =
        Assert-PSOBBLegacyRuntimeMarkerAclState -Layout $layout
    Remove-Item -LiteralPath $layout.ControlState -Force
    Add-Result 'runtime-marker migration requires a stopped lifecycle boundary' `
        ($lifecycleEvidenceRejected -and
         $markerAfterLifecycleRejection.Sha256 -ceq $legacyMarker.Sha256 -and
         $markerAfterLifecycleRejection.AccessSddl -ceq $legacyMarker.AccessSddl) `
        'even synthetic lifecycle evidence blocks the DACL write before mutation'

    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout
    $forgedAuthorityRejected = $false
    $markerIdentityLease = Open-PSOBBRuntimeMarkerIdentityLease -Layout $layout
    try {
        $forgedMutationState = [pscustomobject]@{
            Attempted = $false
            ProtectedAccessSddl = $null
        }
        try {
            Set-PSOBBRuntimeMarkerProtectedDacl `
                -Layout $layout -IdentityLease $markerIdentityLease `
                -StoppedAuthority ([pscustomobject]@{
                    AuthorityToken = [object]::new()
                }) -ExpectedLegacyState $legacyMarker `
                -MutationState $forgedMutationState
        } catch {
            $forgedAuthorityRejected = $true
        }
    } finally {
        Close-PSOBBRuntimeMarkerIdentityLease `
            -IdentityLease $markerIdentityLease
    }
    $afterForgedAuthority = Assert-PSOBBLegacyRuntimeMarkerAclState `
        -Layout $layout
    Add-Result 'runtime-marker DACL writer rejects missing stopped authority dynamically' `
        ($forgedAuthorityRejected -and
         -not $forgedMutationState.Attempted -and
         $afterForgedAuthority.Sha256 -ceq $legacyMarker.Sha256 -and
         $afterForgedAuthority.AccessSddl -ceq $legacyMarker.AccessSddl) `
        'removing or moving the stopped-runtime authority call cannot reach the exact DACL mutation'

    $callSiteRace = [pscustomobject]@{ Injected = $false }
    $callSiteRaceRejected = $false
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalBeforeWriteAction {
                [System.IO.File]::WriteAllText(
                    $layout.ControlState,
                    '{"fixture":true}',
                    [System.Text.UTF8Encoding]::new($false))
                $callSiteRace.Injected = $true
            } | Out-Null
    } catch {
        $callSiteRaceRejected = $true
    } finally {
        if (Test-Path -LiteralPath $layout.ControlState) {
            Remove-Item -LiteralPath $layout.ControlState -Force
        }
    }
    $afterCallSiteRace = Assert-PSOBBLegacyRuntimeMarkerAclState `
        -Layout $layout
    Add-Result 'runtime-marker write rechecks stopped state at its call site' `
        ($callSiteRace.Injected -and $callSiteRaceRejected -and
         $afterCallSiteRace.Sha256 -ceq $legacyMarker.Sha256 -and
         $afterCallSiteRace.AccessSddl -ceq $legacyMarker.AccessSddl) `
        'lifecycle evidence inserted after the first census still blocks mutation'

    $prewriteTamper = [pscustomobject]@{ AccessSddl = $null }
    $prewriteTamperRejected = $false
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalBeforeWriteAction {
                $tamperedAcl = Get-Acl -LiteralPath $layout.RuntimeMarker
                [void]$tamperedAcl.AddAccessRule($everyoneRule)
                [System.IO.FileSystemAclExtensions]::SetAccessControl(
                    [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                        $layout.RuntimeMarker),
                    [System.Security.AccessControl.FileSecurity]$tamperedAcl)
                $prewriteTamper.AccessSddl = (Get-Acl -LiteralPath `
                    $layout.RuntimeMarker).GetSecurityDescriptorSddlForm(
                        [System.Security.AccessControl.AccessControlSections]::Access)
            } | Out-Null
    } catch {
        $prewriteTamperRejected = $true
    }
    $afterPrewriteTamper = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $layout
    Add-Result 'runtime-marker prewrite rejects live legacy-DACL tampering' `
        ($prewriteTamperRejected -and
         $null -ne $prewriteTamper.AccessSddl -and
         $afterPrewriteTamper.AccessSddl -ceq $prewriteTamper.AccessSddl -and
         $afterPrewriteTamper.Sha256 -ceq $legacyMarker.Sha256) `
        'an unknown DACL inserted after validation is preserved for review and never normalized'
    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout

    $postWriteLifecycle = [pscustomobject]@{ Injected = $false }
    $postWriteLifecycleRejected = $false
    $postWriteLifecycleFailure = $null
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalAfterWriteAction {
                [System.IO.File]::WriteAllText(
                    $layout.ControlState,
                    '{"fixture":true}',
                    [System.Text.UTF8Encoding]::new($false))
                $postWriteLifecycle.Injected = $true
                throw 'injected post-write lifecycle race'
            } | Out-Null
    } catch {
        $postWriteLifecycleRejected = $true
        $postWriteLifecycleFailure = $_.Exception.Message
    } finally {
        if (Test-Path -LiteralPath $layout.ControlState) {
            Remove-Item -LiteralPath $layout.ControlState -Force
        }
    }
    $afterPostWriteLifecycle = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $layout
    Add-Result 'runtime-marker rollback rechecks stopped state after write' `
        ($postWriteLifecycle.Injected -and
         $postWriteLifecycleRejected -and
         $postWriteLifecycleFailure -match 'rollback also failed' -and
         $afterPostWriteLifecycle.Sha256 -ceq $legacyMarker.Sha256 -and
         (Test-ExactProtectedAcl -Path $layout.RuntimeMarker)) `
        'new lifecycle evidence blocks rollback and leaves the exact protected DACL as review evidence'
    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout

    $postWriteDaclTamper = [pscustomobject]@{ AccessSddl = $null }
    $postWriteDaclRejected = $false
    $postWriteDaclFailure = $null
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalAfterWriteAction {
                $tamperedAcl = Get-Acl -LiteralPath $layout.RuntimeMarker
                [void]$tamperedAcl.AddAccessRule($everyoneRule)
                [System.IO.FileSystemAclExtensions]::SetAccessControl(
                    [System.IO.FileInfo](Get-Item -Force -LiteralPath `
                        $layout.RuntimeMarker),
                    [System.Security.AccessControl.FileSecurity]$tamperedAcl)
                $postWriteDaclTamper.AccessSddl = (Get-Acl -LiteralPath `
                    $layout.RuntimeMarker).GetSecurityDescriptorSddlForm(
                        [System.Security.AccessControl.AccessControlSections]::Access)
                throw 'injected post-write DACL substitution'
            } | Out-Null
    } catch {
        $postWriteDaclRejected = $true
        $postWriteDaclFailure = $_.Exception.Message
    }
    $afterPostWriteDaclTamper = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $layout
    Add-Result 'runtime-marker rollback rejects protected-DACL substitution' `
        ($postWriteDaclRejected -and
         $postWriteDaclFailure -match 'rollback also failed' -and
         $afterPostWriteDaclTamper.AccessSddl -ceq
            $postWriteDaclTamper.AccessSddl -and
         $afterPostWriteDaclTamper.Sha256 -ceq $legacyMarker.Sha256 -and
         -not (Test-ExactProtectedAcl -Path $layout.RuntimeMarker)) `
        'a changed post-write DACL is preserved exactly and never rewritten as accepted legacy state'
    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout

    $forgedRollbackAuthority = [pscustomobject]@{ Injected = $false }
    $forgedRollbackRejected = $false
    $forgedRollbackFailure = $null
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalAfterWriteAction {
                param($IdentityLease, $StoppedAuthority)
                $StoppedAuthority.AuthorityToken = [object]::new()
                $forgedRollbackAuthority.Injected = $true
                throw 'injected forged rollback authority'
            } | Out-Null
    } catch {
        $forgedRollbackRejected = $true
        $forgedRollbackFailure = $_.Exception.Message
    }
    $afterForgedRollback = Get-PSOBBRuntimeMarkerMetadataSnapshot `
        -Layout $layout
    Add-Result 'runtime-marker rollback rejects stale or forged authority' `
        ($forgedRollbackAuthority.Injected -and
         $forgedRollbackRejected -and
         $forgedRollbackFailure -match 'rollback also failed' -and
         $afterForgedRollback.Sha256 -ceq $legacyMarker.Sha256 -and
         (Test-ExactProtectedAcl -Path $layout.RuntimeMarker)) `
        'rollback requires the live unforgeable stopped-state authority and preserves protected evidence on rejection'
    $legacyMarker = Set-KnownLegacyRuntimeMarkerAcl -Layout $layout

    $replacementPath = Join-Path $layout.Root `
        '.psobb-runtime-replacement.json'
    [System.IO.File]::WriteAllText(
        $replacementPath,
        '{"replacement":true}',
        [System.Text.UTF8Encoding]::new($false))
    $replacementRaceRejected = $false
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalAfterWriteAction {
                param($IdentityLease)
                [System.IO.File]::Move(
                    $replacementPath, [string]$IdentityLease.Path, $true)
            } | Out-Null
    } catch {
        $replacementRaceRejected = $true
    }
    $afterReplacementRace = Assert-PSOBBLegacyRuntimeMarkerAclState `
        -Layout $layout
    Add-Result 'runtime-marker lease blocks path replacement across rollback' `
        ($replacementRaceRejected -and
         (Test-Path -LiteralPath $replacementPath -PathType Leaf) -and
         $afterReplacementRace.Sha256 -ceq $legacyMarker.Sha256 -and
         $afterReplacementRace.AccessSddl -ceq $legacyMarker.AccessSddl -and
         $afterReplacementRace.FileIndex -eq $legacyMarker.FileIndex) `
        'the canonical path cannot be replaced while the original native file identity is retained'
    Remove-Item -LiteralPath $replacementPath -Force

    $hardLinkPath = Join-Path $layout.Root '.psobb-runtime-hardlink.json'
    $hardLinkRace = [pscustomobject]@{ Created = $false }
    $hardLinkRaceRejected = $false
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalAfterWriteAction {
                param($IdentityLease)
                New-Item -ItemType HardLink -Path $hardLinkPath `
                    -Target $IdentityLease.Path | Out-Null
                $hardLinkRace.Created = $true
            } | Out-Null
    } catch {
        $hardLinkRaceRejected = $true
    } finally {
        if (Test-Path -LiteralPath $hardLinkPath) {
            Remove-Item -LiteralPath $hardLinkPath -Force
        }
    }
    $afterHardLinkRace = Assert-PSOBBLegacyRuntimeMarkerAclState `
        -Layout $layout
    Add-Result 'runtime-marker lease detects a hard-link identity race' `
        ($hardLinkRace.Created -and $hardLinkRaceRejected -and
         $afterHardLinkRace.Sha256 -ceq $legacyMarker.Sha256 -and
         $afterHardLinkRace.AccessSddl -ceq $legacyMarker.AccessSddl -and
         $afterHardLinkRace.FileIndex -eq $legacyMarker.FileIndex -and
         $afterHardLinkRace.NumberOfLinks -eq 1) `
        'link-count drift is rejected and the exact prior DACL is restored through the retained file identity'

    $rollbackRejected = $false
    try {
        Repair-PSOBBLegacyRuntimeMarkerAcl `
            -Layout $layout `
            -InternalAfterWriteAction { throw 'injected marker readback failure' } |
            Out-Null
    } catch {
        $rollbackRejected = $true
    }
    $rolledBackMarker = Assert-PSOBBLegacyRuntimeMarkerAclState -Layout $layout
    Add-Result 'runtime-marker migration rolls back an interrupted DACL write' `
        ($rollbackRejected -and
         $rolledBackMarker.Sha256 -ceq $legacyMarker.Sha256 -and
         $rolledBackMarker.AccessSddl -ceq $legacyMarker.AccessSddl -and
         $rolledBackMarker.OwnerSid -ceq $legacyMarker.OwnerSid -and
         $rolledBackMarker.GroupSid -ceq $legacyMarker.GroupSid) `
        'post-write failure restores the exact prior access SDDL and preserves file identity metadata'

    $nonMarkerAclBefore = Get-Acl -LiteralPath $logFile
    $nonMarkerDaclBefore = $nonMarkerAclBefore.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access)
    $migration = @(& $setterPath `
        -RuntimeRoot $layout.Root -MigrateLegacyRuntimeMarkerAcl `
        -Confirm:$false)
    $migratedMarker = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $layout
    $nonMarkerAclAfter = Get-Acl -LiteralPath $logFile
    $nonMarkerDaclAfter = $nonMarkerAclAfter.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access)
    $markerMigrationRecords = @($migration | Where-Object {
            $_.PSObject.Properties['Kind'] -and
            $_.Kind -ceq 'runtime-marker-migration'
        })
    Add-Result 'known legacy runtime marker migrates exactly once' `
        ($markerMigrationRecords.Count -eq 1 -and
         $markerMigrationRecords[0].Changed -and
         $migratedMarker.Sha256 -ceq $markerBefore.Sha256 -and
         $migratedMarker.OwnerSid -ceq $markerBefore.OwnerSid -and
         $migratedMarker.GroupSid -ceq $markerBefore.GroupSid -and
         $nonMarkerDaclAfter -ceq $nonMarkerDaclBefore -and
         (Test-ExactProtectedAcl -Path $layout.RuntimeMarker)) `
        'exact bytes, owner, group, and every non-marker DACL survive the exact-file migration'
    $migratedAccessSddl = $migratedMarker.AccessSddl
    $idempotentResults = @(& $setterPath `
        -RuntimeRoot $layout.Root -MigrateLegacyRuntimeMarkerAcl `
        -Confirm:$false)
    $markerAfterIdempotence = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $layout
    Add-Result 'runtime-marker migration is idempotent after protection' `
        ($idempotentResults.Count -eq 1 -and
         -not $idempotentResults[0].Changed -and
         $idempotentResults[0].Kind -ceq 'runtime-marker-migration' -and
         $markerAfterIdempotence.Sha256 -ceq $migratedMarker.Sha256 -and
         $markerAfterIdempotence.AccessSddl -ceq $migratedAccessSddl -and
         $markerAfterIdempotence.OwnerSid -ceq $migratedMarker.OwnerSid -and
         $markerAfterIdempotence.GroupSid -ceq $migratedMarker.GroupSid) `
        'a protected exact marker is only read and returned unchanged'

    $logAclBefore = Get-Acl -LiteralPath $layout.Logs
    $logOwnerBefore = $logAclBefore.GetOwner(
        [System.Security.Principal.SecurityIdentifier]).Value
    $logGroupBefore = $logAclBefore.GetGroup(
        [System.Security.Principal.SecurityIdentifier]).Value
    $fileAclBefore = Get-Acl -LiteralPath $nestedLogFile
    $fileOwnerBefore = $fileAclBefore.GetOwner(
        [System.Security.Principal.SecurityIdentifier]).Value
    $fileGroupBefore = $fileAclBefore.GetGroup(
        [System.Security.Principal.SecurityIdentifier]).Value

    $first = @(& $setterPath `
        -RuntimeRoot $layout.Root -Confirm:$false)
    $second = @(& $setterPath `
        -RuntimeRoot $layout.Root -Confirm:$false)

    $logResults = @($first | Where-Object Path -eq $layout.Logs)
    Add-Result 'runtime ACL policy includes the log root' `
        ($logResults.Count -eq 1 -and $logResults[0].Changed) `
        'logs are treated as sensitive runtime state'
    Add-Result 'runtime ACL policy protects the log tree' `
        ((Test-ExactProtectedAcl -Path $layout.Logs) -and
         (Test-ExactProtectedAcl -Path $logFile)) `
        'canonical explicit FullControl rules for current user, SYSTEM, and Administrators only'
    Add-Result 'runtime ACL policy protects combat-canary sensitive trees' `
        ((Test-ExactProtectedAcl -Path $canaryLicenseFixture) -and
         (Test-ExactProtectedAcl -Path $canaryPlayerFixture) -and
         (Test-ExactProtectedAcl -Path $canaryTeamFixture) -and
         (Test-ExactProtectedAcl -Path $canarySecretFixture) -and
         (Test-ExactProtectedAcl -Path $canaryBackupFixture) -and
         (Test-ExactProtectedAcl -Path $canaryLogFixture) -and
         (Test-ExactProtectedAcl -Path $canarySnapshotFixture) -and
         (Test-ExactProtectedAcl -Path $canaryControlFixture) -and
         (Test-ExactProtectedAcl -Path $canaryBuildFixture)) `
        'canary account, evidence, lifecycle, build, and credential state use the exact protected DACL'
    $logAclAfter = Get-Acl -LiteralPath $layout.Logs
    $fileAclAfter = Get-Acl -LiteralPath $nestedLogFile
    Add-Result 'runtime ACL setter preserves owner and group' `
        ($logOwnerBefore -eq $logAclAfter.GetOwner(
                [System.Security.Principal.SecurityIdentifier]).Value -and
         $logGroupBefore -eq $logAclAfter.GetGroup(
                [System.Security.Principal.SecurityIdentifier]).Value -and
         $fileOwnerBefore -eq $fileAclAfter.GetOwner(
                [System.Security.Principal.SecurityIdentifier]).Value -and
         $fileGroupBefore -eq $fileAclAfter.GetGroup(
                [System.Security.Principal.SecurityIdentifier]).Value) `
        'fresh access-only descriptors do not replace ownership metadata'
    Add-Result 'runtime ACL policy is idempotent' `
        (@($second | Where-Object { -not $_.Changed }).Count -eq 0 -and
         (Test-ExactProtectedAcl -Path $layout.Logs) -and
         (Test-ExactProtectedAcl -Path $logFile)) `
        'a second application preserves the exact protected DACL'

    $beforeHash = (Get-FileHash -LiteralPath $nestedLogFile -Algorithm SHA256).Hash
    $beforeDacl = (Get-Acl -LiteralPath $nestedLogFile).GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access)
    $verification = Invoke-RuntimeAclVerifier -RuntimeRoot $layout.Root
    $summary = @($verification.Records | Where-Object RecordType -eq 'Summary')
    $targetSummaries = @($verification.Records | Where-Object RecordType -eq 'TargetSummary')
    $expectedTargets = @(
        'backups',
        'combat-canary-backups',
        'combat-canary-builds',
        'combat-canary-control',
        'combat-canary-licenses',
        'combat-canary-logs',
        'combat-canary-players',
        'combat-canary-secrets',
        'combat-canary-snapshots',
        'combat-canary-teams',
        'graphics-evidence',
        'licenses',
        'local-asset-activations',
        'local-asset-archives',
        'local-asset-overlays',
        'logs',
        'players',
        'secrets',
        'supplemental-asset-activations',
        'teams')
    $actualTargets = @($targetSummaries.Target | Sort-Object -Unique)
    Add-Result 'runtime ACL verifier covers the exact setter target inventory' `
        (-not $verification.ErrorRecord -and
         $summary.Count -eq 1 -and
         $summary[0].Passed -and
         $targetSummaries.Count -eq $expectedTargets.Count -and
         @(Compare-Object $expectedTargets $actualTargets).Count -eq 0 -and
         @($targetSummaries | Where-Object { -not $_.Passed }).Count -eq 0) `
        'account state, logs, private evidence, and local-only asset trees are recursively verified'
    $afterHash = (Get-FileHash -LiteralPath $nestedLogFile -Algorithm SHA256).Hash
    $afterDacl = (Get-Acl -LiteralPath $nestedLogFile).GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access)
    Add-Result 'runtime ACL verifier is read-only' `
        ($beforeHash -eq $afterHash -and $beforeDacl -eq $afterDacl) `
        'verification preserves file bytes and the protected DACL'

    $everyoneSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $unexpectedRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $everyoneSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $tamperedAcl = Get-Acl -LiteralPath $nestedLogFile
    [void]$tamperedAcl.AddAccessRule($unexpectedRule)
    Set-Acl -LiteralPath $nestedLogFile -AclObject $tamperedAcl
    $unexpectedIdentity = Invoke-RuntimeAclVerifier -RuntimeRoot $layout.Root
    $identityFailures = @($unexpectedIdentity.Records | Where-Object {
            $_.RecordType -eq 'Failure' -and
            $_.Path -eq $nestedLogFile -and
            (($_.Issues -join '; ') -match 'unexpected DACL identity SID S-1-1-0')
        })
    Add-Result 'runtime ACL verifier rejects extra identities and rights' `
        ($unexpectedIdentity.ErrorRecord -and $identityFailures.Count -eq 1) `
        'an extra Everyone read rule fails with a path-specific SID diagnostic'

    & (Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1') `
        -RuntimeRoot $layout.Root -Confirm:$false | Out-Null
    $unprotectedAcl = Get-Acl -LiteralPath $nestedLogFile
    $unprotectedAcl.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $nestedLogFile -AclObject $unprotectedAcl
    $unprotected = Invoke-RuntimeAclVerifier -RuntimeRoot $layout.Root
    $protectionFailures = @($unprotected.Records | Where-Object {
            $_.RecordType -eq 'Failure' -and
            $_.Path -eq $nestedLogFile -and
            (($_.Issues -join '; ') -match 'DACL inheritance is enabled')
        })
    Add-Result 'runtime ACL verifier rejects unprotected inheritance' `
        ($unprotected.ErrorRecord -and $protectionFailures.Count -eq 1) `
        'an inheritance regression fails with a path-specific diagnostic'

    & (Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1') `
        -RuntimeRoot $layout.Root -Confirm:$false | Out-Null
    New-Item -ItemType Directory -Path $outsideRoot | Out-Null
    $junction = Join-Path $layout.Logs 'outside-junction'
    New-Item -ItemType Junction -Path $junction -Target $outsideRoot | Out-Null
    $reparseVerification = Invoke-RuntimeAclVerifier -RuntimeRoot $layout.Root
    $reparseFailures = @($reparseVerification.Records | Where-Object {
            $_.RecordType -eq 'Failure' -and
            $_.Target -eq 'logs' -and
            (($_.Issues -join '; ') -match 'reparse point')
        })
    Add-Result 'runtime ACL verifier rejects reparse-point traversal' `
        ($reparseVerification.ErrorRecord -and $reparseFailures.Count -eq 1) `
        'a junction in a protected tree fails before its target is traversed'
    [System.IO.Directory]::Delete($junction)
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $safeRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $safeRoot.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not ([System.IO.Path]::GetFileName($safeRoot)).StartsWith(
                'PSOBB-RuntimeAclTests-', [System.StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected ACL test directory'
        }
        Remove-Item -LiteralPath $safeRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $outsideRoot) {
        $safeOutsideRoot = [System.IO.Path]::GetFullPath($outsideRoot)
        $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $safeOutsideRoot.StartsWith(
                $tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not ([System.IO.Path]::GetFileName($safeOutsideRoot)).StartsWith(
                'PSOBB-RuntimeAclTests-', [System.StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected outside ACL test directory'
        }
        Remove-Item -LiteralPath $safeOutsideRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) runtime ACL policy test(s) failed"
}
[pscustomobject]@{ Suite = 'RuntimeAclPolicy'; Passed = $results.Count; Failed = 0 }
