[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [ValidateRange(1, 32)][int]$ShardCount = 1,
    [ValidateRange(0, 31)][int]$ShardIndex = 0,
    [string]$CasePoint,
    [Parameter(DontShow = $true)][switch]$PreserveFixtureOnFailure
)

if ($ShardIndex -ge $ShardCount) {
    throw 'ShardIndex must be less than ShardCount'
}

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$sourceLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Get-SafeRecoveryTestError($ErrorRecord) {
    if (-not $ErrorRecord) {
        return 'none'
    }
    $typeName = $ErrorRecord.Exception.GetType().Name
    $message = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message) -or
        $message -match '[A-Za-z]:[\\/]' -or $message -match '[\\/]') {
        return $typeName
    }
    "$typeName`: $message"
}

function Test-ObservedRecoveryPoint(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$Nonce,
    [Parameter(Mandatory)][ValidateSet('fault', 'hard-exit')][string]$Kind,
    [Parameter(Mandatory)][string]$Point
) {
    try {
        $path = Join-Path $Layout.Root '.recovery-fault-observed.json'
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $path -Root $Layout.Root -Kind File `
                -Label 'recovery fault evidence')
        if (-not (Test-PSOBBProtectedAcl -Path $path)) {
            return $false
        }
        $snapshot = Read-PSOBBStrictJsonSnapshot `
            -Path $path -Root $Layout.Root -MaximumBytes 4KB `
            -MaximumDepth 3 -Label 'recovery fault evidence'
        Assert-PSOBBStrictDataObjectProperties `
            -Value $snapshot.Value -Expected @(
                'schemaVersion', 'installationId', 'nonce', 'kind', 'point') `
            -Label 'recovery fault evidence' | Out-Null
        $snapshot.Value.schemaVersion -is [long] -and
        $snapshot.Value.schemaVersion -eq 1 -and
        $snapshot.Value.installationId -is [string] -and
        [string]$snapshot.Value.installationId -cne '' -and
        [string]$snapshot.Value.installationId -ceq $InstallationId -and
        $snapshot.Value.nonce -is [string] -and
        [string]$snapshot.Value.nonce -ceq $Nonce -and
        $snapshot.Value.kind -is [string] -and
        [string]$snapshot.Value.kind -ceq $Kind -and
        $snapshot.Value.point -is [string] -and
        [string]$snapshot.Value.point -ceq $Point
    } catch {
        $false
    }
}

function Write-TestObservedRecoveryPoint(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Nonce,
    [Parameter(Mandatory)][ValidateSet('fault', 'hard-exit')][string]$Kind,
    [Parameter(Mandatory)][string]$Point
) {
    $path = Join-Path $Layout.Root '.recovery-fault-observed.json'
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        (([ordered]@{
                    schemaVersion = [long]1
                    installationId = $InstallationId
                    nonce = $Nonce
                    kind = $Kind
                    point = $Point
                }) | ConvertTo-Json -Depth 3))
    try {
        [void](Write-PSOBBDurableFileBytes `
                -Path $path -Root $Layout.Root -Bytes $bytes `
                -Overwrite -Label 'stale recovery fault evidence fixture')
        Set-PSOBBProtectedAcl -Path $path
        if (-not (Test-ObservedRecoveryPoint `
                -Layout $Layout -InstallationId $InstallationId `
                -Nonce $Nonce -Kind $Kind -Point $Point)) {
            throw 'Stale recovery fault evidence fixture failed exact publication'
        }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Get-RecoveryGateFixtureFingerprint(
    [Parameter(Mandatory)]$Layout
) {
    $tree = Get-PSOBBOrdinaryTreeSnapshot `
        -Path $Layout.Root -Root ([System.IO.Path]::GetTempPath()) `
        -Label 'recovery fault gate fixture'
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($tree.Items | Sort-Object Path)) {
        $relative = [System.IO.Path]::GetRelativePath(
            $Layout.Root, [string]$entry.Path).Replace('\', '/')
        $acl = (Get-Acl -LiteralPath $entry.Path).Sddl
        if ($entry.IsDirectory) {
            $records.Add("$relative|directory|$acl")
        } else {
            $item = Get-Item -Force -LiteralPath $entry.Path
            $records.Add(
                "$relative|file|$($item.Length)|$(Get-LowerSha256 $entry.Path)|$acl")
        }
    }
    @($records)
}

function Get-RestoreFaultInventory(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidateRange(1, 1000000)][int]$FileCount
) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw 'Restore source does not parse for fault inventory discovery'
    }
    $swapFunction = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-RestoreSwapItems'
        }, $true)
    if (-not $swapFunction) {
        throw 'Restore swap inventory function is absent'
    }
    $swapCount = @($swapFunction.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.HashtableAst]
            }, $true)).Count
    if ($swapCount -lt 1) {
        throw 'Restore swap inventory is empty'
    }

    $commands = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true))
    $prefixes = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($command in $commands) {
        for ($index = 0; $index -lt $command.CommandElements.Count - 1;
            $index++) {
            $element = $command.CommandElements[$index]
            if ($element -is
                    [System.Management.Automation.Language.CommandParameterAst] -and
                $element.ParameterName -ceq 'FaultPrefix') {
                $value = $command.CommandElements[$index + 1]
                if ($value -is
                    [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    [void]$prefixes.Add([string]$value.Value)
                }
            }
        }
    }
    if ($prefixes.Count -lt 1) {
        throw 'Restore journal fault prefixes are absent'
    }

    $cleanupFunction = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Remove-RestoreJournalArtifacts'
        }, $true)
    if (-not $cleanupFunction) {
        throw 'Restore cleanup inventory function is absent'
    }
    $faultNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($match in [regex]::Matches(
            $cleanupFunction.Extent.Text,
            "FaultName\s*=\s*'(?<name>[^']+)'",
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
        [void]$faultNames.Add([string]$match.Groups['name'].Value)
    }
    if ($faultNames.Count -lt 1) {
        throw 'Restore cleanup fault names are absent'
    }

    $points = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $journalSuffixes = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $pointCommands = @($commands | Where-Object {
            $_.GetCommandName() -ceq 'Invoke-RecoveryInternalFault'
        })
    foreach ($command in $pointCommands) {
        $pointExpression = $null
        for ($index = 0; $index -lt $command.CommandElements.Count - 1;
            $index++) {
            $element = $command.CommandElements[$index]
            if ($element -is
                    [System.Management.Automation.Language.CommandParameterAst] -and
                $element.ParameterName -ceq 'Point') {
                $pointExpression = $command.CommandElements[$index + 1]
                break
            }
        }
        if (-not $pointExpression) {
            throw 'Restore fault call is missing its Point argument'
        }
        if ($pointExpression -is
            [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [void]$points.Add([string]$pointExpression.Value)
            continue
        }
        $expression = [string]$pointExpression.Extent.Text
        if ($expression -match '^"\$FaultPrefix-(?<suffix>[a-z-]+)"$') {
            [void]$journalSuffixes.Add([string]$Matches.suffix)
            continue
        }
        if ($expression -match
            '^"cleanup-\$\(\$(?:entry|journalEntry)\.FaultName\)-(?<suffix>[a-z-]+)"$') {
            foreach ($name in $faultNames) {
                [void]$points.Add("cleanup-$name-$($Matches.suffix)")
            }
            continue
        }
        if ($expression -match
            '^"stage-copy-\$copyOrdinal-(?<suffix>[a-z-]+)"$') {
            for ($ordinal = 1; $ordinal -le $FileCount; $ordinal++) {
                [void]$points.Add("stage-copy-$ordinal-$($Matches.suffix)")
            }
            continue
        }
        if ($expression -match
            '^"verify-installed-\$installedOrdinal-(?<suffix>[a-z-]+)"$') {
            for ($ordinal = 1; $ordinal -le $FileCount; $ordinal++) {
                [void]$points.Add("verify-installed-$ordinal-$($Matches.suffix)")
            }
            continue
        }
        if ($expression -match
            '^"(?<family>swap)-\$swapOrdinal-(?<suffix>[a-z-]+)"$') {
            for ($ordinal = 1; $ordinal -le $swapCount; $ordinal++) {
                [void]$points.Add("swap-$ordinal-$($Matches.suffix)")
            }
            continue
        }
        if ($expression -match
            '^"compensate-\$compensationOrdinal-(?<suffix>[a-z-]+)"$') {
            for ($ordinal = 1; $ordinal -le $swapCount; $ordinal++) {
                [void]$points.Add("compensate-$ordinal-$($Matches.suffix)")
            }
            continue
        }
        if ($expression -match
            '^"recover-\$ordinal-(?<suffix>[a-z-]+)"$') {
            for ($ordinal = 1; $ordinal -le $swapCount; $ordinal++) {
                [void]$points.Add("recover-$ordinal-$($Matches.suffix)")
            }
            continue
        }
        throw 'Restore source contains an unsupported fault-point expression'
    }
    foreach ($prefix in $prefixes) {
        foreach ($suffix in $journalSuffixes) {
            [void]$points.Add("$prefix-$suffix")
        }
    }
    $ordered = @($points)
    [Array]::Sort($ordered, [System.StringComparer]::Ordinal)
    $normal = @($ordered | Where-Object {
            -not $_.StartsWith('recover-',
                [System.StringComparison]::Ordinal)
        })
    $recovery = @($ordered | Where-Object {
            $_.StartsWith('recover-',
                [System.StringComparison]::Ordinal)
        })
    [pscustomobject]@{
        All = $ordered
        Normal = $normal
        Recovery = $recovery
        SwapCount = $swapCount
        PointCallCount = $pointCommands.Count
    }
}

function Get-RestoreFaultShardAssignment(
    [Parameter(Mandatory)][string[]]$Points,
    [Parameter(Mandatory)][ValidateRange(1, 32)][int]$Count
) {
    $loads = [long[]]::new($Count)
    $assignment = [System.Collections.Generic.Dictionary[string, int]]::new(
        [System.StringComparer]::Ordinal)
    $highCost = @($Points | Where-Object {
            $_.StartsWith('recover-', [System.StringComparison]::Ordinal) -or
            $_.StartsWith(
                'cleanup-journal-next-',
                [System.StringComparison]::Ordinal)
        })
    $normalCost = @($Points | Where-Object {
            -not $_.StartsWith(
                'recover-', [System.StringComparison]::Ordinal) -and
            -not $_.StartsWith(
                'cleanup-journal-next-',
                [System.StringComparison]::Ordinal)
        })
    foreach ($group in @(
            [pscustomobject]@{ Points = $highCost; Weight = 3L },
            [pscustomobject]@{ Points = $normalCost; Weight = 2L })) {
        foreach ($point in @($group.Points)) {
            $selected = 0
            for ($index = 1; $index -lt $Count; $index++) {
                if ($loads[$index] -lt $loads[$selected]) {
                    $selected = $index
                }
            }
            $assignment.Add([string]$point, $selected)
            $loads[$selected] += [long]$group.Weight
        }
    }
    [pscustomobject]@{
        Assignment = $assignment
        Loads = $loads
    }
}

function Get-RestoreMatrixClosureFingerprint(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$MatrixPath,
    [Parameter(Mandatory)]$GitIdentity
) {
    $paths = @(
        $MatrixPath,
        (Join-Path $RepositoryRoot 'scripts\Restore-PSOBB.ps1'),
        (Join-Path $RepositoryRoot 'scripts\PSOBB.Common.ps1'),
        (Join-Path $RepositoryRoot 'scripts\Backup-PSOBB.ps1'),
        (Join-Path $RepositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1'),
        (Join-Path $RepositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1'),
        (Join-Path $RepositoryRoot 'config\client-patch-profiles.json'),
        (Join-Path $RepositoryRoot 'config\sources.lock.json')
    )
    $relativePaths = @($paths | ForEach-Object {
            [System.IO.Path]::GetRelativePath(
                $RepositoryRoot, [System.IO.Path]::GetFullPath($_)).Replace(
                '\', '/')
        })
    [Array]::Sort($relativePaths, [System.StringComparer]::Ordinal)
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in $relativePaths) {
        $path = Join-Path $RepositoryRoot $relative.Replace('/', '\')
        $snapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
            -Path $path -Root $RepositoryRoot -MaximumBytes 64MB `
            -Label 'restore matrix source closure member'
        $records.Add(
            "$relative|$($snapshot.Length)|$($snapshot.Sha256)")
    }
    [void](Assert-PSOBBTrustedGitLease -Identity $GitIdentity)
    $gitSnapshot = Get-PSOBBLeasedFileDigest `
        -Lease $GitIdentity.Lease -MaximumBytes 64MB `
        -Label 'restore matrix trusted Git member'
    $records.Add(
        "external/trusted-git|$($gitSnapshot.Length)|$($gitSnapshot.Sha256)")
    @($records)
}

function Test-RestoreMatrixClosureUnchanged(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$MatrixPath,
    [Parameter(Mandatory)]$GitIdentity,
    [Parameter(Mandatory)][string[]]$Expected
) {
    try {
        $actual = @(Get-RestoreMatrixClosureFingerprint `
                -RepositoryRoot $RepositoryRoot -MatrixPath $MatrixPath `
                -GitIdentity $GitIdentity)
        @(Compare-Object $Expected $actual).Count -eq 0
    } catch {
        $false
    }
}

function New-FixtureConfig([string]$Name) {
    @"
{
  "BBRequiredPatches": [],
  "AutoPatches": [],
  "fixture": "$Name"
}
"@
}

function New-FixtureInstallationRecord(
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Timestamp
) {
    $hash = [string]::new([char]'0', 64)
    [ordered]@{
        schemaVersion = 2
        installationId = $InstallationId
        initializedAtUtc = $Timestamp
        runtimeRoot = $Root
        serverVersion = 'fixture'
        serverArchiveSha256 = $hash
        serverExecutableSha256 = $hash
        serverBaseManifestSha256 = $hash
        clientVersion = 'fixture'
        clientArchiveSha256 = $hash
        baseClientExecutableSha256 = $hash
        baseClientManifestSha256 = $hash
        clientExecutableSha256 = $hash
        rendererVersion = 'fixture'
        rendererArchiveSha256 = $hash
        rendererWrapperSha256 = $hash
        rendererConfigurationSha256 = $hash
        patchManifestSha256 = $hash
        synchronizedPatchFiles = 0
        clientPatchProfile = 'baseline'
        clientPatchPolicySha256 = Get-LowerSha256 (
            Join-Path $repositoryRoot 'config\client-patch-profiles.json')
        networkScope = 'loopback-only'
    }
}

function Get-StateFingerprint([Parameter(Mandatory)]$Layout) {
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($relativeRoot in @(
            'system\licenses', 'system\players', 'system\teams')) {
        $root = Join-Path $Layout.Server $relativeRoot
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $root -Root $Layout.Root -Kind Directory `
                -Label 'fixture state directory')
        if (-not (Test-PSOBBProtectedAcl -Path $root)) {
            throw 'Fixture state directory ACL is not protected'
        }
        $records.Add(
            ($relativeRoot.Replace('\', '/') + '/|directory|' +
                (Get-Acl -LiteralPath $root).Sddl))
        foreach ($file in @(Get-ChildItem -Force -LiteralPath $root `
                -Recurse -File -ErrorAction Stop | Sort-Object FullName)) {
            [void](Assert-PSOBBOrdinaryContainedPath `
                    -Path $file.FullName -Root $root -Kind File `
                    -Label 'fixture state file')
            if (-not (Test-PSOBBProtectedAcl -Path $file.FullName)) {
                throw 'Fixture state file ACL is not protected'
            }
            $relative = [System.IO.Path]::GetRelativePath(
                $Layout.Server, $file.FullName).Replace('\', '/')
            $records.Add(
                "$relative|$($file.Length)|$(Get-LowerSha256 $file.FullName)|" +
                (Get-Acl -LiteralPath $file.FullName).Sddl)
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{
                Relative = 'system/config.json'
                Path = Join-Path $Layout.Server 'system\config.json'
            },
            [pscustomobject]@{
                Relative = 'stable/installation.json'
                Path = $Layout.InstallRecord
            })) {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $entry.Path -Root $Layout.Root -Kind File `
                -Label 'fixture stable metadata')
        if (-not (Test-PSOBBProtectedAcl -Path $entry.Path)) {
            throw "Fixture stable metadata ACL is not protected: $($entry.Relative)"
        }
        $item = Get-Item -LiteralPath $entry.Path
        $records.Add(
            "$($entry.Relative)|$($item.Length)|$(Get-LowerSha256 $entry.Path)|" +
            (Get-Acl -LiteralPath $entry.Path).Sddl)
    }
    @($records | Sort-Object)
}

function Test-CleanFixtureTarget(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string[]]$TargetFingerprint
) {
    try {
        $state = @(Get-StateFingerprint -Layout $Layout)
        $debris = @(Get-ChildItem -Force -LiteralPath $Layout.Stable `
            -Filter '.psobb-restore-*' -ErrorAction Stop)
        @(Compare-Object $TargetFingerprint $state).Count -eq 0 -and
        $debris.Count -eq 0
    } catch {
        $false
    }
}

function Set-MutatedState(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][int]$Sequence
) {
    [System.IO.File]::WriteAllText(
        (Join-Path $Layout.Server 'system\config.json'),
        (New-FixtureConfig -Name "mutated-$Sequence"),
        [System.Text.UTF8Encoding]::new($false))
    $record = (Read-PSOBBInstallationRecordSnapshot `
        -Path $Layout.InstallRecord -Root $Layout.Root `
        -ExpectedInstallationId $InstallationId `
        -ExpectedRuntimeRoot $Layout.Root).Value
    $record.initializedAtUtc = [DateTimeOffset]::new(
        2026, 7, 19, 0, 0, 0, [TimeSpan]::Zero).AddSeconds(
        $Sequence).ToString('o')
    [System.IO.File]::WriteAllText(
        $Layout.InstallRecord,
        ($record | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
    & (Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1') `
        -RuntimeRoot $Layout.Root -Confirm:$false | Out-Null
}

$script:RestoreFaultFixtureCleanupDisarmed = $false
$script:RestoreHardExitQuarantine = [System.Collections.Generic.List[object]]::new()
function Invoke-HardExitRestore(
    [Parameter(Mandatory)][string]$Script,
    [Parameter(Mandatory)][string]$BackupPath,
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$InstallationId,
    [Parameter(Mandatory)][string]$Nonce,
    [Parameter(Mandatory)][string]$Point
) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Join-Path $PSHOME 'pwsh.exe'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $Script,
            '-BackupPath', $BackupPath, '-RuntimeRoot', $Layout.Root,
            '-Confirm:$false', '-InternalTestHardExitPoint', $Point,
            '-InternalTestFaultToken', $InstallationId,
            '-InternalTestFaultNonce', $Nonce)) {
        $startInfo.ArgumentList.Add([string]$argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $processStarted = $false
    $stdout = $null
    $stderr = $null
    $retainProcess = $false
    try {
        if (-not $process.Start()) {
            throw 'Restore hard-exit fixture did not start'
        }
        $processStarted = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(90000)) {
            try {
                $process.Kill($true)
            } catch {
            }
            if (-not $process.WaitForExit(5000)) {
                $retainProcess = $true
                $script:RestoreFaultFixtureCleanupDisarmed = $true
                throw 'Restore hard-exit fixture did not stop within the bounded termination window; its temporary fixture was preserved'
            }
            [void]$stdout.GetAwaiter().GetResult()
            [void]$stderr.GetAwaiter().GetResult()
            throw 'Restore hard-exit fixture timed out'
        }
        [void]$stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        $process.ExitCode
    } finally {
        if ($processStarted -and -not $process.HasExited -and
            -not $retainProcess) {
            try {
                $process.Kill($true)
            } catch {
            }
            if (-not $process.WaitForExit(5000)) {
                $retainProcess = $true
                $script:RestoreFaultFixtureCleanupDisarmed = $true
            }
        }
        if ($retainProcess) {
            $script:RestoreHardExitQuarantine.Add([pscustomobject]@{
                    Process = $process
                    StandardOutputTask = $stdout
                    StandardErrorTask = $stderr
                    RetainedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
                })
        } else {
            if ($stdout) {
                try {
                    [void]$stdout.GetAwaiter().GetResult()
                } catch {
                }
            }
            if ($stderr) {
                try {
                    [void]$stderr.GetAwaiter().GetResult()
                } catch {
                }
            }
            $process.Dispose()
        }
        if ($retainProcess) {
            throw 'Restore hard-exit fixture did not stop within the bounded termination window; its temporary fixture was preserved'
        }
    }
}

function Remove-RestoreFaultFixture(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$TemporaryBase,
    [Parameter(Mandatory)]$Layout,
    $Marker,
    [Parameter(Mandatory)][bool]$CleanupSentinelArmed
) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $true
    }
    $normalizedRoot = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $normalizedTemp = [System.IO.Path]::GetFullPath(
        $TemporaryBase).TrimEnd('\')
    $fixtureName = [System.IO.Path]::GetFileName($normalizedRoot)
    if ($fixtureName -cnotmatch '^PSOBB-RecoveryTests-[a-f0-9]{32}$' -or
        -not $normalizedRoot.StartsWith(
            $normalizedTemp + '\',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Restore fault fixture cleanup root is not an exact temporary test identity'
    }
    if (-not $CleanupSentinelArmed) {
        Write-Warning 'An unarmed restore fault fixture was preserved for safe inspection'
        return $false
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $normalizedRoot -Root $normalizedTemp -Kind Directory `
            -Label 'restore fault fixture root')
    $fixtureMarker = Join-Path $normalizedRoot '.recovery-test.json'
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $fixtureMarker -Root $normalizedRoot -Kind File `
            -Label 'restore fault fixture marker')
    if (-not (Test-PSOBBProtectedAcl -Path $fixtureMarker)) {
        throw 'Restore fault fixture marker is not protected'
    }
    if ($Marker) {
        $cleanupMarker = Assert-PSOBBRuntimeMarker -Layout $Layout
        if ([string]$cleanupMarker.installationId -cne
            [string]$Marker.installationId) {
            throw 'Restore fault fixture runtime identity changed before cleanup'
        }
    }
    [void](Get-PSOBBOrdinaryTreeSnapshot `
            -Path $normalizedRoot -Root $normalizedTemp `
            -Label 'restore fault fixture cleanup tree')
    Remove-PSOBBValidatedRecoveryTree `
        -Path $normalizedRoot -Root $normalizedTemp `
        -Label 'restore fault fixture cleanup tree'
    -not (Test-Path -LiteralPath $normalizedRoot)
}

$temporaryBase = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::GetTempPath()).TrimEnd('\')
$testRoot = Join-Path $temporaryBase (
    'PSOBB-RecoveryTests-' + [Guid]::NewGuid().ToString('N'))
$layout = Get-PSOBBLayout -RuntimeRoot $testRoot
$restoreScript = Join-Path $repositoryRoot 'scripts\Restore-PSOBB.ps1'
$trustedGit = $null
$marker = $null
$cleanupSentinelArmed = $false
$testRunCompleted = $false

try {
    if ($ShardIndex -eq 0) {
        $setupFaultRoot = Join-Path $temporaryBase (
            'PSOBB-RecoveryTests-' + [Guid]::NewGuid().ToString('N'))
        $setupFaultLayout = Get-PSOBBLayout -RuntimeRoot $setupFaultRoot
        New-Item -ItemType Directory -Path $setupFaultRoot | Out-Null
        $setupFaultMarker = Join-Path $setupFaultRoot '.recovery-test.json'
        [System.IO.File]::WriteAllText(
            $setupFaultMarker, '{"fixture":true}',
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $setupFaultMarker
        $setupFaultCleaned = Remove-RestoreFaultFixture `
            -Path $setupFaultRoot -TemporaryBase $temporaryBase `
            -Layout $setupFaultLayout -Marker $null `
            -CleanupSentinelArmed $true
        Add-Result 'pre-marker setup fault fixture cleans through sentinel gate' `
            $setupFaultCleaned `
            'exact temporary identity and protected early sentinel authorize cleanup'
        if (-not $setupFaultCleaned) {
            throw 'Pre-marker setup fault cleanup test failed'
        }
    }

    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $fixtureMarker = Join-Path $testRoot '.recovery-test.json'
    [System.IO.File]::WriteAllText(
        $fixtureMarker, '{"fixture":true}',
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $fixtureMarker
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $fixtureMarker -Root $testRoot -Kind File `
            -Label 'restore fault fixture marker')
    if (-not (Test-PSOBBProtectedAcl -Path $fixtureMarker)) {
        throw 'Restore fault fixture marker publication failed'
    }
    $cleanupSentinelArmed = $true
    $marker = Initialize-PSOBBRuntimeMarker -Layout $layout
    foreach ($directory in @(
            $layout.Server,
            (Join-Path $layout.Server 'system\licenses'),
            (Join-Path $layout.Server 'system\players'),
            (Join-Path $layout.Server 'system\teams'),
            $layout.Backups,
            $layout.Secrets,
            $layout.Logs,
            (Join-Path $layout.Root 'graphics-evidence'),
            (Join-Path $layout.Archives 'graphics-lab\local-assets'),
            (Join-Path $layout.LocalLab 'asset-overlays'),
            (Join-Path $layout.LocalLab 'asset-activations'),
            (Join-Path $layout.LocalLab 'visual-asset-activations'))) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $sourceLayout.Server 'newserv-windows.exe') `
        -Destination (Join-Path $layout.Server 'newserv-windows.exe')
    [System.IO.File]::WriteAllText(
        (Join-Path $layout.Server 'system\config.json'),
        (New-FixtureConfig -Name 'target'),
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $layout.InstallRecord,
        ((New-FixtureInstallationRecord `
                -InstallationId ([string]$marker.installationId) `
                -Root $layout.Root `
                -Timestamp '2026-07-19T00:00:00.0000000+00:00') |
            ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
    & (Join-Path $repositoryRoot 'scripts\Set-PSOBBRuntimeAcl.ps1') `
        -RuntimeRoot $layout.Root -Confirm:$false | Out-Null
    Set-PSOBBProtectedAcl -Path (
        Join-Path $layout.Server 'system\config.json')
    Set-PSOBBProtectedAcl -Path $layout.InstallRecord
    $backup = & (Join-Path $repositoryRoot 'scripts\Backup-PSOBB.ps1') `
        -RuntimeRoot $layout.Root -Retention 7
    $targetFingerprint = @(Get-StateFingerprint -Layout $layout)
    $manifest = Read-PSOBBRecoveryManifestSnapshot `
        -Path (Join-Path $backup.BackupPath 'manifest.json') `
        -Root $backup.BackupPath
    $fileCount = @($manifest.Value.files).Count

    $inventory = Get-RestoreFaultInventory `
        -Path $restoreScript -FileCount $fileCount
    $expectedPoints = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($point in @(
            'stage-root-after-create-before-acl',
            'stage-tree-before-acl', 'stage-tree-after-acl',
            'installed-tree-before-acl', 'installed-tree-after-acl',
            'installed-tree-after-final-census',
            'compensate-before-acl', 'compensate-after-acl',
            'compensate-after-exact-readback',
            'recover-before-acl', 'recover-after-acl',
            'recover-after-exact-readback')) {
        [void]$expectedPoints.Add($point)
    }
    foreach ($name in @('stage', 'rollback', 'journal-next', 'journal')) {
        foreach ($suffix in @('before-removal', 'after-removal')) {
            [void]$expectedPoints.Add("cleanup-$name-$suffix")
        }
    }
    foreach ($prefix in @(
            'journal-prepared', 'journal-swapping',
            'journal-accepted', 'journal-compensating')) {
        foreach ($suffix in @(
                'before-acl', 'after-acl', 'after-readback', 'after-move',
                'after-destination-acl', 'after-destination-readback')) {
            [void]$expectedPoints.Add("$prefix-$suffix")
        }
    }
    for ($ordinal = 1; $ordinal -le $fileCount; $ordinal++) {
        foreach ($suffix in @('before', 'after-readback')) {
            [void]$expectedPoints.Add("stage-copy-$ordinal-$suffix")
        }
        foreach ($suffix in @('before', 'after')) {
            [void]$expectedPoints.Add("verify-installed-$ordinal-$suffix")
        }
    }
    for ($ordinal = 1; $ordinal -le $inventory.SwapCount; $ordinal++) {
        foreach ($suffix in @(
                'before-original-move', 'before-rollback-acl',
                'after-rollback-acl', 'after-original-move',
                'before-candidate-move', 'after-candidate-move',
                'before-immediate-compensation',
                'after-immediate-compensation')) {
            [void]$expectedPoints.Add("swap-$ordinal-$suffix")
        }
        foreach ($suffix in @(
                'before-candidate-removal', 'after-candidate-removal',
                'before-original-move', 'after-original-move')) {
            [void]$expectedPoints.Add("compensate-$ordinal-$suffix")
        }
        foreach ($suffix in @(
                'before-candidate-removal', 'after-candidate-removal',
                'after-original-move')) {
            [void]$expectedPoints.Add("recover-$ordinal-$suffix")
        }
    }
    $sourcePoints = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($point in @($inventory.All)) {
        [void]$sourcePoints.Add([string]$point)
    }
    $inventoryExact =
        $sourcePoints.SetEquals($expectedPoints) -and
        $expectedPoints.SetEquals($sourcePoints) -and
        $expectedPoints.Count -eq 127 -and
        $sourcePoints.Count -eq 127 -and
        @($inventory.Normal).Count -eq 109 -and
        @($inventory.Recovery).Count -eq 18
    if ($ShardIndex -eq 0) {
        Add-Result 'source-derived fault inventory is exact' $inventoryExact `
            '109 normal plus 18 interrupted-recovery points; ordinal set equality'
    }
    if (-not $inventoryExact) {
        throw 'Restore source fault inventory does not match the exact planned set'
    }
    if (-not [string]::IsNullOrWhiteSpace($CasePoint) -and
        ($ShardCount -ne 1 -or $ShardIndex -ne 0 -or
            -not $sourcePoints.Contains($CasePoint))) {
        throw 'CasePoint requires shard 0 of 1 and one exact source-derived point'
    }
    $trustedGit = Get-PSOBBTrustedGitIdentity
    $sourceClosure = @(Get-RestoreMatrixClosureFingerprint `
            -RepositoryRoot $repositoryRoot -MatrixPath $PSCommandPath `
            -GitIdentity $trustedGit)
    $sourceClosureExact =
        $sourceClosure.Count -eq 9 -and
        @($sourceClosure | Where-Object {
                $_ -notmatch '^[^|]+\|[1-9][0-9]*\|[a-f0-9]{64}$'
            }).Count -eq 0
    $sharding = Get-RestoreFaultShardAssignment `
        -Points ([string[]]$inventory.All) -Count $ShardCount
    $loadMaximum = [long](($sharding.Loads | Measure-Object -Maximum).Maximum)
    $loadMinimum = [long](($sharding.Loads | Measure-Object -Minimum).Minimum)
    $shardingExact =
        $sharding.Assignment.Count -eq $sourcePoints.Count -and
        ($loadMaximum - $loadMinimum) -le 2
    if ($ShardIndex -eq 0) {
        Add-Result 'fault shards use deterministic weighted assignment' `
            $shardingExact 'high-cost recovery cases distributed before ordinal normal cases'
        Add-Result 'restore execution closure is frozen for the matrix run' `
            $sourceClosureExact `
            'nine ordinal file identities are checked before every seam'
    }
    if (-not $shardingExact -or -not $sourceClosureExact) {
        throw 'Restore fault shard assignment is incomplete or imbalanced'
    }

    if ($ShardIndex -eq 0 -and
        [string]::IsNullOrWhiteSpace($CasePoint)) {
        $gateRoot = Join-Path $temporaryBase (
            'PSOBB-RecoveryGateTests-' + [Guid]::NewGuid().ToString('N'))
        $gateLayout = Get-PSOBBLayout -RuntimeRoot $gateRoot
        $gateMarker = $null
        try {
            New-Item -ItemType Directory -Path $gateRoot | Out-Null
            $gateMarker = Initialize-PSOBBRuntimeMarker -Layout $gateLayout
            $gateFixtureMarker = Join-Path $gateRoot '.recovery-test.json'
            [System.IO.File]::WriteAllText(
                $gateFixtureMarker, '{"fixture":true}',
                [System.Text.UTF8Encoding]::new($false))
            Set-PSOBBProtectedAcl -Path $gateFixtureMarker
            $beforeGate = @(Get-RecoveryGateFixtureFingerprint `
                    -Layout $gateLayout)
            $gateEvidence = Join-Path `
                $gateRoot '.recovery-fault-observed.json'
            $gateRejected = $false
            try {
                & $restoreScript `
                    -BackupPath $gateLayout.Backups `
                    -RuntimeRoot $gateRoot -ValidateOnly `
                    -InternalTestFaultPoint ([string]$inventory.Normal[0]) `
                    -InternalTestFaultToken (
                        [string]$gateMarker.installationId) `
                    -InternalTestFaultNonce ([Guid]::NewGuid().ToString('N')) |
                    Out-Null
            } catch {
                $gateRejected = $_.Exception.Message -ceq
                    'Internal recovery fault injection is restricted to an explicit protected temporary fixture'
            }
            $afterGate = @(Get-RecoveryGateFixtureFingerprint `
                    -Layout $gateLayout)
            $canonicalShape = [System.IO.Path]::GetFullPath(
                (Join-Path $repositoryRoot 'PSOBB-Runtime')).TrimEnd('\')
            $canonicalOutsideGate =
                -not $canonicalShape.StartsWith(
                    ($temporaryBase + '\'),
                    [System.StringComparison]::OrdinalIgnoreCase) -and
                [System.IO.Path]::GetFileName($canonicalShape) -cnotmatch
                    '^PSOBB-RecoveryTests-[a-f0-9]{32}$'
            $isolatedGatePassed =
                $gateRejected -and $canonicalOutsideGate -and
                @(Compare-Object $beforeGate $afterGate).Count -eq 0 -and
                -not (Test-Path -LiteralPath $gateEvidence) -and
                -not (Test-Path -LiteralPath ($gateEvidence + '.next'))
            Add-Result 'non-fixture runtime rejects recovery fault injection' `
                $isolatedGatePassed `
                'isolated wrong-name root rejected without evidence or mutation; canonical path was not accessed'
            if (-not $isolatedGatePassed) {
                throw 'Non-fixture runtime recovery fault gate test failed'
            }
        } finally {
            if (Test-Path -LiteralPath $gateRoot) {
                $normalizedGateRoot = [System.IO.Path]::GetFullPath(
                    $gateRoot).TrimEnd('\')
                if ([System.IO.Path]::GetFileName($normalizedGateRoot) -cnotmatch
                        '^PSOBB-RecoveryGateTests-[a-f0-9]{32}$' -or
                    -not $normalizedGateRoot.StartsWith(
                        ($temporaryBase + '\'),
                        [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Recovery fault gate fixture cleanup identity is invalid'
                }
                [void](Assert-PSOBBOrdinaryContainedPath `
                        -Path $normalizedGateRoot -Root $temporaryBase `
                        -Kind Directory -Label 'recovery fault gate fixture')
                if ($gateMarker) {
                    $currentGateMarker = Assert-PSOBBRuntimeMarker `
                        -Layout $gateLayout
                    if ([string]$currentGateMarker.installationId -cne
                        [string]$gateMarker.installationId) {
                        throw 'Recovery fault gate fixture identity changed before cleanup'
                    }
                }
                Remove-PSOBBValidatedRecoveryTree `
                    -Path $normalizedGateRoot -Root $temporaryBase `
                    -Label 'recovery fault gate fixture'
            }
        }

        $evidencePath = Join-Path $layout.Root '.recovery-fault-observed.json'
        [System.IO.File]::WriteAllText(
            $evidencePath, '{}', [System.Text.UTF8Encoding]::new($false))
        $permissive = [System.Security.AccessControl.FileSecurity]::new()
        $permissive.SetAccessRuleProtection($true, $false)
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $permissive.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $currentSid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow))
        $permissive.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
                [System.Security.AccessControl.FileSystemRights]::ReadData,
                [System.Security.AccessControl.AccessControlType]::Allow))
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo](Get-Item -Force -LiteralPath $evidencePath),
            $permissive)
        $permissiveRejected = $false
        try {
            & $restoreScript `
                -BackupPath $backup.BackupPath -RuntimeRoot $layout.Root `
                -ValidateOnly -InternalTestFaultPoint ([string]$inventory.Normal[0]) `
                -InternalTestFaultToken ([string]$marker.installationId) `
                -InternalTestFaultNonce ([Guid]::NewGuid().ToString('N')) |
                Out-Null
        } catch {
            $permissiveRejected =
                $_.Exception.Message -ceq
                'Internal recovery fault evidence has an invalid ACL'
        } finally {
            Set-PSOBBProtectedAcl -Path $evidencePath
            Remove-Item -LiteralPath $evidencePath -Force
        }
        Add-Result 'permissive recovery evidence is rejected' `
            $permissiveRejected 'fault gate failed closed before publication'
        if (-not $permissiveRejected) {
            throw 'Permissive recovery evidence gate test failed'
        }

        $targetPath = Join-Path $layout.Root '.recovery-fault-target.json'
        [System.IO.File]::WriteAllText(
            $targetPath, '{"target":true}',
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $targetPath
        $targetHash = Get-LowerSha256 $targetPath
        $linkCreated = $false
        $reparseRejected = $false
        try {
            $link = New-Item -ItemType SymbolicLink -Path $evidencePath `
                -Target $targetPath -ErrorAction Stop
            $linkCreated =
                ([System.IO.FileAttributes]$link.Attributes).HasFlag(
                    [System.IO.FileAttributes]::ReparsePoint)
            try {
                & $restoreScript `
                    -BackupPath $backup.BackupPath -RuntimeRoot $layout.Root `
                    -ValidateOnly `
                    -InternalTestFaultPoint ([string]$inventory.Normal[0]) `
                    -InternalTestFaultToken ([string]$marker.installationId) `
                    -InternalTestFaultNonce ([Guid]::NewGuid().ToString('N')) |
                    Out-Null
            } catch {
                $reparseRejected = $true
            }
        } finally {
            if (Test-Path -LiteralPath $evidencePath) {
                $linkItem = Get-Item -Force -LiteralPath $evidencePath
                if (([System.IO.FileAttributes]$linkItem.Attributes).HasFlag(
                        [System.IO.FileAttributes]::ReparsePoint)) {
                    Remove-Item -LiteralPath $evidencePath -Force
                } else {
                    throw 'Recovery evidence reparse fixture changed filesystem type'
                }
            }
        }
        $reparseGatePassed =
            $linkCreated -and $reparseRejected -and
            (Get-LowerSha256 $targetPath) -ceq $targetHash
        Set-PSOBBProtectedAcl -Path $targetPath
        Remove-Item -LiteralPath $targetPath -Force
        Add-Result 'reparse recovery evidence is rejected' `
            $reparseGatePassed 'external target remained byte-exact'
        if (-not $reparseGatePassed) {
            throw 'Reparse recovery evidence gate test failed'
        }
    }

    $sequence = 0
    $negativeEvidenceValidated = $false
    $orderedFaultPoints = @($inventory.Normal)
    for ($faultIndex = 0; $faultIndex -lt $orderedFaultPoints.Count; $faultIndex++) {
        $candidatePoint = [string]$orderedFaultPoints[$faultIndex]
        if ((-not [string]::IsNullOrWhiteSpace($CasePoint) -and
                $candidatePoint -cne $CasePoint) -or
            ([string]::IsNullOrWhiteSpace($CasePoint) -and
                $sharding.Assignment[$candidatePoint] -ne $ShardIndex)) {
            continue
        }
        $faultPoint = $candidatePoint
        if (-not (Test-RestoreMatrixClosureUnchanged `
                -RepositoryRoot $repositoryRoot -MatrixPath $PSCommandPath `
                -GitIdentity $trustedGit -Expected $sourceClosure)) {
            throw 'Restore execution closure changed during the fault matrix run'
        }
        if (-not (Test-CleanFixtureTarget `
                -Layout $layout -TargetFingerprint $targetFingerprint)) {
            throw "Restore fixture is not clean before seam $faultPoint"
        }
        $sequence++
        Set-MutatedState `
            -Layout $layout `
            -InstallationId ([string]$marker.installationId) `
            -Sequence $sequence
        $staleEvidenceNonce = $null
        if ($ShardIndex -eq 0 -and -not $negativeEvidenceValidated) {
            $staleEvidenceNonce = [Guid]::NewGuid().ToString('N')
            Write-TestObservedRecoveryPoint `
                -Layout $layout `
                -InstallationId ([string]$marker.installationId) `
                -Nonce $staleEvidenceNonce -Kind 'fault' `
                -Point $faultPoint
        }
        if ($faultPoint.StartsWith(
                'cleanup-journal-next-',
                [System.StringComparison]::Ordinal)) {
            $prepareNonce = [Guid]::NewGuid().ToString('N')
            $preparePoint = 'journal-accepted-after-destination-readback'
            $prepareExit = Invoke-HardExitRestore `
                -Script $restoreScript -BackupPath $backup.BackupPath `
                -Layout $layout `
                -InstallationId ([string]$marker.installationId) `
                -Nonce $prepareNonce -Point $preparePoint
            $prepareObserved = Test-ObservedRecoveryPoint `
                -Layout $layout `
                -InstallationId ([string]$marker.installationId) `
                -Nonce $prepareNonce -Kind 'hard-exit' -Point $preparePoint
            $journalPath = Join-Path `
                $layout.Stable '.psobb-restore-transaction.json'
            $journalNext = Join-Path `
                $layout.Stable '.psobb-restore-transaction.next'
            if ($prepareExit -ne 86 -or -not $prepareObserved -or
                -not (Test-PSOBBProtectedAcl -Path $journalPath) -or
                (Test-Path -LiteralPath $journalNext)) {
                throw 'Accepted journal-next cleanup preparation failed exact proof'
            }
            $journalSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
                -Path $journalPath -Root $layout.Stable `
                -MaximumBytes 64KB -Label 'accepted journal duplicate source' `
                -IncludeBytes
            try {
                [void](Write-PSOBBDurableFileBytes `
                        -Path $journalNext -Root $layout.Stable `
                        -Bytes ([byte[]]$journalSnapshot.Bytes) `
                        -Label 'accepted journal duplicate staging')
                Set-PSOBBProtectedAcl -Path $journalNext
                $nextSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
                    -Path $journalNext -Root $layout.Stable `
                    -MaximumBytes 64KB `
                    -Label 'accepted journal duplicate staging'
                if ($nextSnapshot.Sha256 -cne $journalSnapshot.Sha256 -or
                    -not (Test-PSOBBProtectedAcl -Path $journalNext)) {
                    throw 'Accepted journal duplicate failed exact readback'
                }
            } finally {
                if ($journalSnapshot.Bytes) {
                    [Array]::Clear(
                        $journalSnapshot.Bytes, 0,
                        $journalSnapshot.Bytes.Length)
                }
            }
        }
        $faultObserved = $false
        $faultError = $null
        $faultNonce = [Guid]::NewGuid().ToString('N')
        try {
            & $restoreScript `
                -BackupPath $backup.BackupPath -RuntimeRoot $layout.Root `
                -Confirm:$false -InternalTestFaultPoint $faultPoint `
                -InternalTestFaultToken ([string]$marker.installationId) `
                -InternalTestFaultNonce $faultNonce |
                Out-Null
        } catch {
            $faultObserved = $true
            $faultError = $_
        }
        $pointObserved = Test-ObservedRecoveryPoint `
            -Layout $layout `
            -InstallationId ([string]$marker.installationId) `
            -Nonce $faultNonce -Kind 'fault' -Point $faultPoint
        $recovered = $true
        $recoveryError = $null
        try {
            & $restoreScript `
                -BackupPath $backup.BackupPath -RuntimeRoot $layout.Root `
                -Confirm:$false | Out-Null
            $state = @(Get-StateFingerprint -Layout $layout)
            $debris = @(Get-ChildItem -Force -LiteralPath $layout.Stable `
                -Filter '.psobb-restore-*')
            $recovered =
                @(Compare-Object $targetFingerprint $state).Count -eq 0 -and
                $debris.Count -eq 0
        } catch {
            $recovered = $false
            $recoveryError = $_
        }
        $passed = $faultObserved -and $pointObserved -and $recovered
        $detail = if ($passed) {
            'exact point receipt; exact target state; no transaction debris'
        } else {
            'thrown=' + $faultObserved + '; receipt=' + $pointObserved +
            '; recovered=' + $recovered + '; fault=' +
            (Get-SafeRecoveryTestError $faultError) + '; recovery=' +
            (Get-SafeRecoveryTestError $recoveryError)
        }
        Add-Result "restore fault recovers: $faultPoint" `
            $passed $detail
        if (-not $passed) {
            throw "Restore seam failed: $faultPoint; $detail"
        }
        if ($ShardIndex -eq 0 -and -not $negativeEvidenceValidated) {
            $wrongNonceRejected = -not (Test-ObservedRecoveryPoint `
                    -Layout $layout `
                    -InstallationId ([string]$marker.installationId) `
                    -Nonce ([Guid]::NewGuid().ToString('N')) `
                    -Kind 'fault' -Point $faultPoint)
            $wrongPointRejected = -not (Test-ObservedRecoveryPoint `
                    -Layout $layout `
                    -InstallationId ([string]$marker.installationId) `
                    -Nonce $faultNonce -Kind 'fault' `
                    -Point ($faultPoint + '-wrong'))
            $wrongKindRejected = -not (Test-ObservedRecoveryPoint `
                    -Layout $layout `
                    -InstallationId ([string]$marker.installationId) `
                    -Nonce $faultNonce -Kind 'hard-exit' -Point $faultPoint)
            $staleRejected = -not (Test-ObservedRecoveryPoint `
                    -Layout $layout `
                    -InstallationId ([string]$marker.installationId) `
                    -Nonce $staleEvidenceNonce `
                    -Kind 'fault' -Point $faultPoint)
            foreach ($negative in @(
                    [pscustomobject]@{ Name = 'wrong recovery evidence nonce is rejected'; Passed = $wrongNonceRejected },
                    [pscustomobject]@{ Name = 'wrong recovery evidence point is rejected'; Passed = $wrongPointRejected },
                    [pscustomobject]@{ Name = 'wrong recovery evidence kind is rejected'; Passed = $wrongKindRejected },
                    [pscustomobject]@{ Name = 'stale recovery evidence is rejected'; Passed = $staleRejected })) {
                Add-Result $negative.Name $negative.Passed `
                    'strict point receipt binding failed closed'
                if (-not $negative.Passed) {
                    throw 'Recovery fault evidence negative test failed'
                }
            }
            $negativeEvidenceValidated = $true
        }
    }

    $recoverPoints = @($inventory.Recovery)
    for ($recoverIndex = 0; $recoverIndex -lt $recoverPoints.Count; $recoverIndex++) {
        $candidatePoint = [string]$recoverPoints[$recoverIndex]
        if ((-not [string]::IsNullOrWhiteSpace($CasePoint) -and
                $candidatePoint -cne $CasePoint) -or
            ([string]::IsNullOrWhiteSpace($CasePoint) -and
                $sharding.Assignment[$candidatePoint] -ne $ShardIndex)) {
            continue
        }
        $recoverPoint = $candidatePoint
        if (-not (Test-RestoreMatrixClosureUnchanged `
                -RepositoryRoot $repositoryRoot -MatrixPath $PSCommandPath `
                -GitIdentity $trustedGit -Expected $sourceClosure)) {
            throw 'Restore execution closure changed during the fault matrix run'
        }
        if (-not (Test-CleanFixtureTarget `
                -Layout $layout -TargetFingerprint $targetFingerprint)) {
            throw "Restore fixture is not clean before seam $recoverPoint"
        }
        $sequence++
        Set-MutatedState `
            -Layout $layout `
            -InstallationId ([string]$marker.installationId) `
            -Sequence $sequence
        $hardExitNonce = [Guid]::NewGuid().ToString('N')
        $hardExitPoint = 'swap-5-after-candidate-move'
        $hardExitCode = Invoke-HardExitRestore `
            -Script $restoreScript -BackupPath $backup.BackupPath `
            -Layout $layout `
            -InstallationId ([string]$marker.installationId) `
            -Nonce $hardExitNonce -Point $hardExitPoint
        $hardExitObserved = Test-ObservedRecoveryPoint `
            -Layout $layout `
            -InstallationId ([string]$marker.installationId) `
            -Nonce $hardExitNonce -Kind 'hard-exit' -Point $hardExitPoint
        $faultObserved = $false
        $faultError = $null
        $faultNonce = [Guid]::NewGuid().ToString('N')
        try {
            & $restoreScript `
                -BackupPath $backup.BackupPath -RuntimeRoot $layout.Root `
                -Confirm:$false -InternalTestFaultPoint $recoverPoint `
                -InternalTestFaultToken ([string]$marker.installationId) `
                -InternalTestFaultNonce $faultNonce |
                Out-Null
        } catch {
            $faultObserved = $true
            $faultError = $_
        }
        $pointObserved = Test-ObservedRecoveryPoint `
            -Layout $layout `
            -InstallationId ([string]$marker.installationId) `
            -Nonce $faultNonce -Kind 'fault' -Point $recoverPoint
        $recovered = $true
        $recoveryError = $null
        try {
            & $restoreScript `
                -BackupPath $backup.BackupPath -RuntimeRoot $layout.Root `
                -Confirm:$false | Out-Null
            $state = @(Get-StateFingerprint -Layout $layout)
            $debris = @(Get-ChildItem -Force -LiteralPath $layout.Stable `
                -Filter '.psobb-restore-*')
            $recovered =
                @(Compare-Object $targetFingerprint $state).Count -eq 0 -and
                $debris.Count -eq 0
        } catch {
            $recovered = $false
            $recoveryError = $_
        }
        $passed =
            $hardExitCode -eq 86 -and $hardExitObserved -and
            $faultObserved -and $pointObserved -and $recovered
        $detail = if ($passed) {
            'exact hard-exit and fault receipts; idempotent exact recovery'
        } else {
            'hardExit=' + $hardExitCode + '; hardReceipt=' +
            $hardExitObserved + '; thrown=' + $faultObserved +
            '; receipt=' + $pointObserved + '; recovered=' + $recovered +
            '; fault=' + (Get-SafeRecoveryTestError $faultError) +
            '; recovery=' + (Get-SafeRecoveryTestError $recoveryError)
        }
        Add-Result "interrupted recovery fault resumes: $recoverPoint" `
            $passed $detail
        if (-not $passed) {
            throw "Interrupted recovery seam failed: $recoverPoint; $detail"
        }
    }
    if (-not (Test-RestoreMatrixClosureUnchanged `
            -RepositoryRoot $repositoryRoot -MatrixPath $PSCommandPath `
            -GitIdentity $trustedGit -Expected $sourceClosure)) {
        throw 'Restore execution closure changed before the fault matrix completed'
    }
    $testRunCompleted = $true
} finally {
    try {
        if ($trustedGit) {
            Close-PSOBBTrustedExecutableLease -Identity $trustedGit
            if (-not (Test-PSOBBTrustedExecutableLeaseClosed `
                    -Identity $trustedGit)) {
                throw 'Restore matrix trusted Git lease remained open'
            }
        }
    } finally {
        if (Test-Path -LiteralPath $testRoot) {
            if ($PreserveFixtureOnFailure -and -not $testRunCompleted) {
                Write-Warning (
                    'The failed restore fault fixture was preserved for safe inspection: ' +
                    [System.IO.Path]::GetFileName($testRoot))
            } else {
                [void](Remove-RestoreFaultFixture `
                        -Path $testRoot -TemporaryBase $temporaryBase `
                        -Layout $layout -Marker $marker `
                        -CleanupSentinelArmed (
                            $cleanupSentinelArmed -and
                            -not $script:RestoreFaultFixtureCleanupDisarmed))
            }
        }
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) restore-transaction fault test(s) failed"
}
[pscustomobject]@{
    Suite = 'RestoreTransactionFaults'
    Passed = $results.Count
    Failed = 0
}
