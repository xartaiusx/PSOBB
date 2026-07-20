[CmdletBinding()]
param()

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Test-ExpectedFileLockFailure($ErrorRecord) {
    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception -is [System.IO.IOException] -or
            $exception -is [System.UnauthorizedAccessException]) {
            return $true
        }
        $exception = $exception.InnerException
    }
    $false
}

$temporaryBase = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::GetTempPath()).TrimEnd('\')
$testRoot = Join-Path $temporaryBase (
    'PSOBB-RecoveryTrustTests-' + [Guid]::NewGuid().ToString('N'))
$originalPath = [Environment]::GetEnvironmentVariable('PATH', 'Process')
$trusted = $null
$fixtureLease = $null
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $testMarker = Join-Path $testRoot '.recovery-trust-test.json'
    [System.IO.File]::WriteAllText(
        $testMarker, '{"schemaVersion":1}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $testMarker

    $fakeBin = Join-Path $testRoot 'fake-program-files\Git\mingw64\bin'
    New-Item -ItemType Directory -Path $fakeBin | Out-Null
    $fakeGit = Join-Path $fakeBin 'git.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
        -Destination $fakeGit
    [Environment]::SetEnvironmentVariable(
        'PATH', $fakeBin + ';' + $originalPath, 'Process')
    $trusted = Get-PSOBBTrustedGitIdentity
    $expectedGit = Join-Path (
        [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::ProgramFiles)) `
        'Git\mingw64\bin\git.exe'
    $version = Invoke-PSOBBGitBoundaryCommand `
        -RepositoryRoot $repositoryRoot -Arguments @('--version') `
        -GitIdentity $trusted
    Add-Result 'ambient PATH cannot replace trusted Git' (
        $trusted.Path -cne $fakeGit -and
        $trusted.Path -ceq $expectedGit -and
        $version.ExitCode -eq 0 -and
        $version.StandardOutput -match '^git version ') `
        'signed ordinary Program Files identity is used by absolute path'
    Add-Result 'trusted Git bypasses the launcher shim and alternate payloads' (
        $trusted.Path -like '*\Git\mingw64\bin\git.exe' -and
        $trusted.Path -cne $fakeGit) `
        'the signed command payload itself is bound and invoked directly'

    $savedSha256 = [string]$trusted.Sha256
    try {
        $trusted.Sha256 = [string]::new([char]'0', 64)
        $rehashRejected = $false
        try {
            Invoke-PSOBBGitBoundaryCommand `
                -RepositoryRoot $repositoryRoot -Arguments @('--version') `
                -GitIdentity $trusted | Out-Null
        } catch {
            $rehashRejected = $_.Exception.Message -ceq
                'The trusted Git executable changed while leased'
        }
    } finally {
        $trusted.Sha256 = $savedSha256
    }
    Add-Result 'trusted Git identity is rehashed before use' $rehashRejected `
        'same-handle digest drift fails before a process is started'

    $authorityRoot = Join-Path $testRoot 'injected-authority'
    New-Item -ItemType Directory -Path $authorityRoot | Out-Null
    $fixtureGit = Join-Path $authorityRoot 'git.exe'
    Copy-Item -LiteralPath $trusted.Path -Destination $fixtureGit
    $replacementGit = Join-Path $authorityRoot 'replacement.exe'
    Copy-Item -LiteralPath $trusted.Path -Destination $replacementGit
    Set-PSOBBProtectedTreeAcl -Path $authorityRoot -Root $testRoot
    $fixtureLease = Open-PSOBBTrustedExecutableLease `
        -Path $fixtureGit -Root $authorityRoot -MaximumBytes 64MB `
        -Label 'injected trusted executable authority' -RequireProtectedAcl
    $fabricatedAuthority = [pscustomobject]@{
        Path = [string]$fixtureLease.Path
        Root = [string]$fixtureLease.Root
        MaximumBytes = [long]$fixtureLease.MaximumBytes
        Length = [long]$fixtureLease.Length
        Sha256 = [string]$fixtureLease.Sha256
        Lease = $fixtureLease.Lease
        AuthorityToken = [object]::new()
        QuarantineRetained = $false
    }
    $fabricatedRejected = $false
    try {
        Invoke-PSOBBGitBoundaryCommand `
            -RepositoryRoot $repositoryRoot -Arguments @('--version') `
            -GitIdentity $fabricatedAuthority | Out-Null
    } catch {
        $fabricatedRejected = $_.Exception.Message -ceq
            'The trusted Git executable lease identity is invalid'
    }
    Add-Result 'fabricated Git lease authority is rejected' `
        $fabricatedRejected `
        'a generic protected fixture lease cannot become a production authority'
    $fixtureDigest = Get-PSOBBLeasedFileDigest `
        -Lease $fixtureLease.Lease -MaximumBytes 64MB `
        -Label 'injected trusted executable authority pre-start seam'
    $writeBlocked = $false
    try {
        $writeProbe = [System.IO.FileStream]::new(
            $fixtureGit, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $writeProbe.Dispose()
    } catch {
        $writeBlocked = Test-ExpectedFileLockFailure $_
        if (-not $writeBlocked) { throw }
    }
    $deleteBlocked = $false
    try {
        [System.IO.File]::Delete($fixtureGit)
    } catch {
        $deleteBlocked = Test-ExpectedFileLockFailure $_
        if (-not $deleteBlocked) { throw }
    }
    $renamedGit = Join-Path $authorityRoot 'renamed-away.exe'
    $renameBlocked = $false
    try {
        [System.IO.File]::Move($fixtureGit, $renamedGit)
    } catch {
        $renameBlocked = Test-ExpectedFileLockFailure $_
        if (-not $renameBlocked) { throw }
    }
    $replaceBlocked = $false
    try {
        [System.IO.File]::Move($replacementGit, $fixtureGit, $true)
    } catch {
        $replaceBlocked = Test-ExpectedFileLockFailure $_
        if (-not $replaceBlocked) { throw }
    }
    $fixtureDigestAfter = Get-PSOBBLeasedFileDigest `
        -Lease $fixtureLease.Lease -MaximumBytes 64MB `
        -Label 'injected trusted executable authority post-mutation seam'
    Add-Result 'trusted executable lease blocks mutation delete and replacement' (
        $writeBlocked -and $deleteBlocked -and $renameBlocked -and
        $replaceBlocked -and
        (Test-Path -LiteralPath $fixtureGit) -and
        -not (Test-Path -LiteralPath $renamedGit) -and
        (Test-Path -LiteralPath $replacementGit) -and
        $fixtureDigest.Length -eq $fixtureLease.Length -and
        $fixtureDigest.Sha256 -ceq $fixtureLease.Sha256 -and
        $fixtureDigestAfter.Length -eq $fixtureLease.Length -and
        $fixtureDigestAfter.Sha256 -ceq $fixtureLease.Sha256) `
        'write delete rename-away and replacement fail while same-handle bytes remain exact'
    $quarantineEntry = [pscustomobject]@{
        Process = $null
        GitIdentity = $fixtureLease
        RetainedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $script:PSOBBGitBoundaryQuarantine.Add($quarantineEntry)
    Close-PSOBBTrustedExecutableLease -Identity $fixtureLease
    $quarantineRetained =
        $fixtureLease.Lease.CanRead -and
        -not $fixtureLease.Lease.SafeFileHandle.IsClosed
    [void]$script:PSOBBGitBoundaryQuarantine.Remove($quarantineEntry)
    Add-Result 'caller-owned quarantined lease cannot be closed' `
        $quarantineRetained `
        'reference-identity quarantine ownership survives an outer close attempt'
    Close-PSOBBTrustedExecutableLease -Identity $fixtureLease
    Close-PSOBBTrustedExecutableLease -Identity $fixtureLease
    $leaseClosed = Test-PSOBBTrustedExecutableLeaseClosed `
        -Identity $fixtureLease
    [System.IO.File]::Move($replacementGit, $fixtureGit, $true)
    [System.IO.File]::Delete($fixtureGit)
    Add-Result 'trusted executable lease releases deterministically' (
        $leaseClosed -and
        -not (Test-Path -LiteralPath $fixtureGit) -and
        -not (Test-Path -LiteralPath $replacementGit)) `
        'idempotent close releases replacement and delete only after disposal'
    $fixtureLease = $null

    Close-PSOBBTrustedExecutableLease -Identity $trusted
    Add-Result 'trusted Git lease closes explicitly after command use' (
        (Test-PSOBBTrustedExecutableLeaseClosed -Identity $trusted)) `
        'the retained direct-payload handle is closed before later test work'
    $trusted = $null

    $boundaryPassed = $true
    try {
        Assert-PSOBBGitRuntimeBoundary -RepositoryRoot $repositoryRoot
    } catch {
        $boundaryPassed = $false
    }
    Add-Result 'one trusted Git lease spans all runtime-boundary commands' `
        $boundaryPassed `
        'top-level ignore and tracked-path checks complete under one retained lease'

    $commonTokens = $null
    $commonErrors = $null
    $commonAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'),
        [ref]$commonTokens, [ref]$commonErrors)
    $invokeFunction = $commonAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-PSOBBGitBoundaryCommand'
        }, $true)
    $invokeText = if ($invokeFunction) {
        [string]$invokeFunction.Extent.Text
    } else {
        ''
    }
    Add-Result 'Git timeout cleanup is bounded and lease-retaining' (
        $commonErrors.Count -eq 0 -and
        $invokeText -notmatch '\.WaitForExit\(\s*\)' -and
        @([regex]::Matches($invokeText, '\.WaitForExit\(5000\)')).Count -eq 2 -and
        $invokeText -match 'PSOBBGitBoundaryQuarantine') `
        'stop failure uses bounded waits and quarantines the exact live lease'

    $layout = Get-PSOBBLayout -RuntimeRoot $testRoot
    New-Item -ItemType Directory `
        -Path (Split-Path $layout.PidFile -Parent) -Force | Out-Null
    [System.IO.File]::WriteAllText(
        $layout.PidFile, '{}', [System.Text.UTF8Encoding]::new($false))
    $originalReader = (Get-Command Read-PSOBBStrictLifecycleJson).Definition
    try {
        $script:LifecycleReaderCalled = $false
        function script:Read-PSOBBStrictLifecycleJson {
            $script:LifecycleReaderCalled = $true
            throw 'Lifecycle reader should not run for an untrusted ACL'
        }
        $inheritedRejected =
            $null -eq (Get-NewservProcess -Layout $layout) -and
            -not $script:LifecycleReaderCalled
        Add-Result 'inherited lifecycle process record is rejected before parse' `
            $inheritedRejected 'unprotected process identity cannot be consumed'

        $permissive = [System.Security.AccessControl.FileSecurity]::new()
        $permissive.SetAccessRuleProtection($true, $false)
        $permissive.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow))
        $permissive.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                [System.Security.AccessControl.FileSystemRights]::ReadData,
                [System.Security.AccessControl.AccessControlType]::Allow))
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo](Get-Item -Force -LiteralPath $layout.PidFile),
            $permissive)
        $script:LifecycleReaderCalled = $false
        $permissiveRejected =
            $null -eq (Get-NewservProcess -Layout $layout) -and
            -not $script:LifecycleReaderCalled
        Add-Result 'permissive lifecycle process record is rejected before parse' `
            $permissiveRejected 'additional principals cannot control process identity'
    } finally {
        Set-Item -LiteralPath Function:\Read-PSOBBStrictLifecycleJson `
            -Value ([scriptblock]::Create($originalReader))
    }
} finally {
    [Environment]::SetEnvironmentVariable('PATH', $originalPath, 'Process')
    if ($fixtureLease) {
        Close-PSOBBTrustedExecutableLease -Identity $fixtureLease
    }
    if ($trusted) {
        Close-PSOBBTrustedExecutableLease -Identity $trusted
    }
    if (Test-Path -LiteralPath $testRoot) {
        $normalized = [System.IO.Path]::GetFullPath($testRoot).TrimEnd('\')
        $leaf = [System.IO.Path]::GetFileName($normalized)
        if ($leaf -cnotmatch '^PSOBB-RecoveryTrustTests-[a-f0-9]{32}$' -or
            -not $normalized.StartsWith(
                $temporaryBase + '\',
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Recovery trust test cleanup root is invalid'
        }
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $normalized -Root $temporaryBase -Kind Directory `
                -Label 'recovery trust fixture')
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path (Join-Path $normalized '.recovery-trust-test.json') `
                -Root $normalized -Kind File `
                -Label 'recovery trust fixture marker')
        if (-not (Test-PSOBBProtectedAcl `
                -Path (Join-Path $normalized '.recovery-trust-test.json'))) {
            throw 'Recovery trust fixture marker is not protected'
        }
        [void](Get-PSOBBOrdinaryTreeSnapshot `
                -Path $normalized -Root $temporaryBase `
                -Label 'recovery trust fixture tree')
        Remove-PSOBBValidatedRecoveryTree `
            -Path $normalized -Root $temporaryBase `
            -Label 'recovery trust fixture tree'
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) recovery trust-boundary test(s) failed"
}
[pscustomobject]@{
    Suite = 'RecoveryTrustBoundaries'
    Passed = $results.Count
    Failed = 0
}
