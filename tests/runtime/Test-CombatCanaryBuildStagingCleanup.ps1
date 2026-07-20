[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptsRoot = Join-Path $repositoryRoot 'scripts'
$cleanupScript = Join-Path $scriptsRoot `
    'Remove-PSOBBCombatCanaryBuildStaging.ps1'
$canonicalContractPath = Join-Path $repositoryRoot `
    'config\combat-canary-build.json'

. (Join-Path $scriptsRoot 'PSOBB.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
$fixtures = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Write-TestJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [int]$Depth = 100
    )

    [System.IO.Directory]::CreateDirectory(
        [System.IO.Path]::GetDirectoryName($Path)) | Out-Null
    [System.IO.File]::WriteAllText(
        $Path, (($Value | ConvertTo-Json -Depth $Depth) + "`n"),
        [System.Text.UTF8Encoding]::new($false))
}

function Write-TestBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
    )

    [System.IO.Directory]::CreateDirectory(
        [System.IO.Path]::GetDirectoryName($Path)) | Out-Null
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Get-LowerHash {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-TestRelease {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$CanonicalContract
    )

    [System.IO.Directory]::CreateDirectory($Root) | Out-Null
    $payload = [ordered]@{
        'README.md' = [System.Text.Encoding]::UTF8.GetBytes('readme')
        'newserv-windows.exe' = [System.Text.Encoding]::UTF8.GetBytes(
            'synthetic-newserv')
        'system/config.json' = [System.Text.Encoding]::UTF8.GetBytes('{}')
        'system/patch-bb/.metadata-cache.json' =
            [System.Text.Encoding]::UTF8.GetBytes('{"cache":"bb"}')
        'system/patch-pc/.metadata-cache.json' =
            [System.Text.Encoding]::UTF8.GetBytes('{"cache":"pc"}')
        'system/maps/bb-v4/empty.dat' = [byte[]]::new(0)
    }
    $records = [System.Collections.Generic.List[object]]::new()
    [long]$totalBytes = 0
    foreach ($relative in $payload.Keys) {
        $path = Join-Path $Root $relative.Replace('/', '\')
        Write-TestBytes -Path $path -Bytes ([byte[]]$payload[$relative])
        $length = [long](Get-Item -LiteralPath $path).Length
        $totalBytes += $length
        $records.Add([ordered]@{
                path = $relative
                size = $length
                sha256 = Get-LowerHash -Path $path
            })
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        profileId = [string]$CanonicalContract.profileId
        sourceCommit = [string]$CanonicalContract.source.commit
        patchSeriesSha256 = [string]$CanonicalContract.patchSeries.sha256
        files = @($records)
    }
    $manifestPath = Join-Path $Root 'release-manifest.json'
    Write-TestJson -Path $manifestPath -Value $manifest -Depth 8
    $executablePath = Join-Path $Root 'newserv-windows.exe'
    [pscustomobject]@{
        FileCount = [long]$records.Count
        TotalBytes = $totalBytes
        ManifestSize = [long](Get-Item -LiteralPath $manifestPath).Length
        ManifestSha256 = Get-LowerHash -Path $manifestPath
        ExecutableSize = [long](Get-Item -LiteralPath $executablePath).Length
        ExecutableSha256 = Get-LowerHash -Path $executablePath
    }
}

function Copy-TestTree {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    [System.IO.Directory]::CreateDirectory(
        [System.IO.Path]::GetDirectoryName($Destination)) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse
}

function New-CleanupFixture {
    $id = [Guid]::NewGuid()
    $root = Join-Path ([System.IO.Path]::GetTempPath()) (
        'psobb-combat-canary-staging-cleanup-test-' + $id.ToString('N'))
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    Write-TestJson -Path (Join-Path $root `
            '.psobb-combat-canary-staging-cleanup-test.json') -Value ([ordered]@{
            schemaVersion = 1
            testRunId = $id.ToString('D')
            root = [System.IO.Path]::GetFullPath($root)
        }) -Depth 4
    $layout = Get-PSOBBLayout -RuntimeRoot $root
    Write-TestJson -Path $layout.RuntimeMarker -Value ([ordered]@{
            schemaVersion = 1
            installationId = $id.ToString('D')
            runtimeRoot = [System.IO.Path]::GetFullPath($root)
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
        }) -Depth 4
    Set-PSOBBProtectedAcl -Path $layout.RuntimeMarker

    $canonicalContract = Get-Content -Raw -LiteralPath $canonicalContractPath |
        ConvertFrom-Json -Depth 100 -DateKind String
    $combatLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment CombatCanary
    $release = New-TestRelease -Root $combatLayout.ServerBase `
        -CanonicalContract $canonicalContract
    Copy-TestTree -Source $combatLayout.ServerBase -Destination $layout.ServerBase

    $contract = Get-Content -Raw -LiteralPath $canonicalContractPath |
        ConvertFrom-Json -Depth 100 -DateKind String
    $contract.output.fileCount = [long]$release.FileCount
    $contract.output.totalBytes = [long]$release.TotalBytes
    $contract.output.executable.size = [long]$release.ExecutableSize
    $contract.output.executable.sha256 = [string]$release.ExecutableSha256
    $contract.output.releaseManifest.size = [long]$release.ManifestSize
    $contract.output.releaseManifest.sha256 = [string]$release.ManifestSha256
    foreach ($build in @($contract.reproducibility.builds)) {
        $build.size = [long]$release.ExecutableSize
        $build.sha256 = [string]$release.ExecutableSha256
    }
    $contractPath = Join-Path $root 'combat-canary-build.fixture.json'
    Write-TestJson -Path $contractPath -Value $contract
    $fixture = [pscustomobject]@{
        Id = $id
        Root = $root
        Layout = $layout
        CombatLayout = $combatLayout
        ContractPath = $contractPath
        StagingRoot = Join-Path $combatLayout.EnvironmentRoot '.staging'
    }
    $fixtures.Add($fixture)
    $fixture
}

function Remove-CleanupFixture {
    param([Parameter(Mandatory)]$Fixture)

    $full = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath([string]$Fixture.Root))
    $temporary = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()))
    if (-not [string]::Equals(
            [System.IO.Path]::GetDirectoryName($full), $temporary,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($full) -cnotmatch
            '^psobb-combat-canary-staging-cleanup-test-[0-9a-f]{32}$') {
        throw 'Refusing cleanup outside one exact staging-cleanup test fixture'
    }
    if (Test-Path -LiteralPath $full) {
        [System.IO.Directory]::Delete($full, $true)
    }
}

function Add-ValidStagingRelease {
    param(
        [Parameter(Mandatory)]$Fixture,
        [string]$Prefix = 'previous-release'
    )

    [System.IO.Directory]::CreateDirectory($Fixture.StagingRoot) | Out-Null
    $destination = Join-Path $Fixture.StagingRoot (
        $Prefix + '-' + [Guid]::NewGuid().ToString('N'))
    Copy-TestTree -Source $Fixture.CombatLayout.ServerBase `
        -Destination $destination
    $destination
}

function Invoke-FixtureCleanup {
    param(
        [Parameter(Mandatory)]$Fixture,
        [switch]$WhatIf,
        [scriptblock]$BeforeDelete
    )

    $arguments = @{
        RuntimeRoot = $Fixture.Root
        InternalTestFixtureToken = $Fixture.Id.ToString('D')
        InternalTestBuildContractPath = $Fixture.ContractPath
        Confirm = $false
    }
    if ($WhatIf) { $arguments.WhatIf = $true }
    if ($null -ne $BeforeDelete) {
        $arguments.InternalTestBeforeDelete = $BeforeDelete
    }
    & $cleanupScript @arguments
}

function Test-Rejected {
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [Parameter(Mandatory)][string]$Pattern
    )

    try {
        & $Operation | Out-Null
        $false
    } catch {
        $_.Exception.Message -match $Pattern
    }
}

function Get-TreeFingerprint {
    param([Parameter(Mandatory)][string]$Root)

    $lines = @(Get-ChildItem -Force -Recurse -LiteralPath $Root |
        Sort-Object FullName | ForEach-Object {
            $relative = [System.IO.Path]::GetRelativePath($Root, $_.FullName).
                Replace('\', '/')
            if ($_.PSIsContainer) { "D|$relative" }
            else { "F|$relative|$($_.Length)|$(Get-LowerHash $_.FullName)" }
        })
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($lines -join "`n"))
    try {
        ([Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData($bytes))).
            ToLowerInvariant()
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

try {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $cleanupScript, [ref]$tokens, [ref]$parseErrors)
    $source = Get-Content -Raw -LiteralPath $cleanupScript
    Add-Result 'cleanup command parses and exposes a high-impact ShouldProcess gate' (
        $parseErrors.Count -eq 0 -and
        $source -match 'SupportsShouldProcess' -and
        $source -match "ConfirmImpact = 'High'" -and
        $source -notmatch '(?im)^\s*(?:Remove-Item|Set-Acl|icacls|takeown)\b') `
        "parseErrors=$($parseErrors.Count)"
    Add-Result 'cleanup command uses the combat-canary server base and repeats stopped checks' (
        $source -match 'CombatLayout\.ServerBase' -and
        ([regex]::Matches(
                $source, 'Assert-PSOBBCombatCanaryCleanupStopped').Count -ge 3) -and
        $source -match 'MaximumStagingChildren = 64' -and
        $source -match 'MaximumStagingEntries = 32768' -and
        $source -match 'MaximumStagingBytes = 512MB') 'source safety boundaries present'

    $preview = New-CleanupFixture
    $previewRelease = Add-ValidStagingRelease -Fixture $preview
    foreach ($prefix in @('server-base', 'server-base-corrected',
            'phase1-repackage')) {
        [System.IO.Directory]::CreateDirectory((Join-Path $preview.StagingRoot (
                    $prefix + '-' + [Guid]::NewGuid().ToString('N')))) | Out-Null
    }
    $previewBefore = Get-TreeFingerprint -Root $preview.StagingRoot
    $publishedBefore = Get-TreeFingerprint -Root $preview.CombatLayout.ServerBase
    $previewResult = Invoke-FixtureCleanup -Fixture $preview -WhatIf
    $previewAfter = Get-TreeFingerprint -Root $preview.StagingRoot
    $previewJson = $previewResult | ConvertTo-Json -Compress
    Add-Result 'WhatIf is write-free and emits only a sanitized aggregate plan' (
        $previewResult.Outcome -ceq 'Preview' -and
        $previewResult.CandidateCount -eq 4 -and
        $previewBefore -ceq $previewAfter -and
        $publishedBefore -ceq
            (Get-TreeFingerprint -Root $preview.CombatLayout.ServerBase) -and
        $previewJson -notmatch [regex]::Escape($preview.Root) -and
        $previewJson -notmatch $preview.Id.ToString('N')) `
        "outcome=$($previewResult.Outcome); candidates=$($previewResult.CandidateCount)"

    $apply = New-CleanupFixture
    foreach ($prefix in @('previous-release', 'previous-release-phase1',
            'retired-release')) {
        [void](Add-ValidStagingRelease -Fixture $apply -Prefix $prefix)
    }
    $applyPublishedBefore = Get-TreeFingerprint -Root $apply.CombatLayout.ServerBase
    $markerAclBefore = (Get-Acl -LiteralPath $apply.Layout.RuntimeMarker).
        GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All)
    $applyResult = Invoke-FixtureCleanup -Fixture $apply
    Add-Result 'exact legacy dotfiles and a declared zero-byte file survive validation' (
        $applyResult.Outcome -ceq 'Removed' -and
        $applyResult.ReleaseCandidateCount -eq 3 -and
        -not (Test-Path -LiteralPath $apply.StagingRoot) -and
        $applyPublishedBefore -ceq
            (Get-TreeFingerprint -Root $apply.CombatLayout.ServerBase) -and
        $markerAclBefore -ceq (Get-Acl -LiteralPath $apply.Layout.RuntimeMarker).
            GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::All)) `
        "outcome=$($applyResult.Outcome); releases=$($applyResult.ReleaseCandidateCount)"

    $wrongEnvironment = New-CleanupFixture
    [void](Add-ValidStagingRelease -Fixture $wrongEnvironment)
    [System.IO.Directory]::Delete($wrongEnvironment.CombatLayout.ServerBase, $true)
    Add-Result 'missing CombatCanary server base is rejected even when Stable is valid' (
        Test-Rejected -Pattern 'cannot find|does not exist|Could not find' {
            Invoke-FixtureCleanup -Fixture $wrongEnvironment
        }) 'combat-canary release omitted; stable release retained'

    $unknown = New-CleanupFixture
    [System.IO.Directory]::CreateDirectory($unknown.StagingRoot) | Out-Null
    [System.IO.Directory]::CreateDirectory(
        (Join-Path $unknown.StagingRoot 'unknown-evidence')) | Out-Null
    Add-Result 'unknown staging evidence is rejected and retained' (
        (Test-Rejected -Pattern 'unknown child' {
                Invoke-FixtureCleanup -Fixture $unknown
            }) -and
        (Test-Path -LiteralPath (Join-Path $unknown.StagingRoot 'unknown-evidence'))) `
        'unknown evidence retained'

    $topFile = New-CleanupFixture
    [System.IO.Directory]::CreateDirectory($topFile.StagingRoot) | Out-Null
    Write-TestBytes -Path (Join-Path $topFile.StagingRoot 'evidence.bin') `
        -Bytes ([byte[]](1, 2, 3))
    Add-Result 'top-level staging files are rejected and retained' (
        (Test-Rejected -Pattern 'top-level file' {
                Invoke-FixtureCleanup -Fixture $topFile
            }) -and
        (Test-Path -LiteralPath (Join-Path $topFile.StagingRoot 'evidence.bin'))) `
        'top-level evidence retained'

    $failed = New-CleanupFixture
    [System.IO.Directory]::CreateDirectory($failed.StagingRoot) | Out-Null
    $failedPath = Join-Path $failed.StagingRoot (
        'failed-release-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($failedPath) | Out-Null
    Add-Result 'failed publication evidence is rejected and retained' (
        (Test-Rejected -Pattern 'failure or transaction evidence' {
                Invoke-FixtureCleanup -Fixture $failed
            }) -and (Test-Path -LiteralPath $failedPath)) `
        'failed-release evidence retained'

    $nonemptyLegacy = New-CleanupFixture
    [System.IO.Directory]::CreateDirectory($nonemptyLegacy.StagingRoot) | Out-Null
    $nonemptyPath = Join-Path $nonemptyLegacy.StagingRoot (
        'server-base-' + [Guid]::NewGuid().ToString('N'))
    Write-TestBytes -Path (Join-Path $nonemptyPath 'payload.bin') `
        -Bytes ([byte[]](1))
    Add-Result 'empty-only legacy stages reject any data' (
        (Test-Rejected -Pattern 'empty-only build stage contains data' {
                Invoke-FixtureCleanup -Fixture $nonemptyLegacy
            }) -and (Test-Path -LiteralPath $nonemptyPath)) `
        'nonempty legacy stage retained'

    $nearDotfile = New-CleanupFixture
    $nearRoot = Add-ValidStagingRelease -Fixture $nearDotfile
    $exactDotfile = Join-Path $nearRoot 'system\patch-bb\.metadata-cache.json'
    $nearPath = Join-Path $nearRoot 'system\patch-bb\.metadata-cache.json.bak'
    [System.IO.File]::Move($exactDotfile, $nearPath)
    $nearManifestPath = Join-Path $nearRoot 'release-manifest.json'
    $nearManifest = Get-Content -Raw -LiteralPath $nearManifestPath |
        ConvertFrom-Json -Depth 20 -DateKind String
    $nearRecord = @($nearManifest.files | Where-Object {
            $_.path -ceq 'system/patch-bb/.metadata-cache.json'
        })[0]
    $nearRecord.path = 'system/patch-bb/.metadata-cache.json.bak'
    Write-TestJson -Path $nearManifestPath -Value $nearManifest -Depth 8
    Add-Result 'only the two exact legacy metadata dotfiles are permitted' (
        (Test-Rejected -Pattern 'unsafe manifest path' {
                Invoke-FixtureCleanup -Fixture $nearDotfile
            }) -and (Test-Path -LiteralPath $nearRoot)) `
        'near-name dotfile release retained'

    $tooMany = New-CleanupFixture
    [System.IO.Directory]::CreateDirectory($tooMany.StagingRoot) | Out-Null
    for ($index = 0; $index -lt 65; $index++) {
        [System.IO.Directory]::CreateDirectory((Join-Path $tooMany.StagingRoot (
                    'server-base-' + ('{0:x32}' -f $index)))) | Out-Null
    }
    Add-Result 'more than 64 direct staging children fail closed' (
        Test-Rejected -Pattern '64-child bound' {
            Invoke-FixtureCleanup -Fixture $tooMany
        }) '65 recognized empty stages retained'

    $publishedRace = New-CleanupFixture
    $publishedRaceStage = Add-ValidStagingRelease -Fixture $publishedRace
    $publishedPayload = Join-Path $publishedRace.CombatLayout.ServerBase `
        'system\config.json'
    $publishedRaceRejected = Test-Rejected -Pattern 'digest|published' {
        Invoke-FixtureCleanup -Fixture $publishedRace -BeforeDelete {
            param($StagingRoot)
            [System.IO.File]::WriteAllText($publishedPayload, '{"changed":true}')
        }
    }
    Add-Result 'published server-base drift after planning blocks deletion' (
        $publishedRaceRejected -and (Test-Path -LiteralPath $publishedRaceStage)) `
        'staging retained after published-release drift'

    $identityRace = New-CleanupFixture
    $identityStage = Add-ValidStagingRelease -Fixture $identityRace
    $identityRejected = Test-Rejected -Pattern 'empty and cannot be proven|plan changed' {
        Invoke-FixtureCleanup -Fixture $identityRace -BeforeDelete {
            param($StagingRoot)
            [System.IO.Directory]::Delete($identityStage, $true)
            [System.IO.Directory]::CreateDirectory($identityStage) | Out-Null
        }
    }
    Add-Result 'staging identity replacement before deletion fails closed' (
        $identityRejected -and (Test-Path -LiteralPath $identityStage)) `
        'replacement directory retained'
} finally {
    foreach ($fixture in @($fixtures)) {
        try { Remove-CleanupFixture -Fixture $fixture } catch {
            Add-Result 'temporary fixture cleanup' $false $_.Exception.Message
        }
    }
}

$results | Format-Table -AutoSize
$failedResults = @($results | Where-Object { -not $_.Passed })
if ($failedResults.Count -ne 0) {
    throw "$($failedResults.Count) combat-canary staging cleanup test(s) failed"
}
"Combat-canary staging cleanup tests passed: $($results.Count)/$($results.Count)"
