[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
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
try {
    foreach ($directory in @(
        $layout.Root,
        (Join-Path $layout.Server 'system\licenses'),
        (Join-Path $layout.Server 'system\players'),
        (Join-Path $layout.Server 'system\teams'),
        $layout.Secrets,
        $layout.Backups,
        $layout.Logs)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Initialize-PSOBBRuntimeMarker -Layout $layout | Out-Null

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
    $expectedTargets = @('backups', 'licenses', 'logs', 'players', 'secrets', 'teams')
    $actualTargets = @($targetSummaries.Target | Sort-Object -Unique)
    Add-Result 'runtime ACL verifier covers the exact setter target inventory' `
        (-not $verification.ErrorRecord -and
         $summary.Count -eq 1 -and
         $summary[0].Passed -and
         $targetSummaries.Count -eq 6 -and
         @(Compare-Object $expectedTargets $actualTargets).Count -eq 0 -and
         @($targetSummaries | Where-Object { -not $_.Passed }).Count -eq 0) `
        'licenses, players, teams, secrets, backups, and logs are recursively verified'
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
