[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$BackupPath,
    [string]$RuntimeRoot,
    [switch]$ValidateOnly
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Get-ApprovedServerExecutable {
    $lockPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config\sources.lock.json'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "Source lock is missing: $lockPath"
    }
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
    $component = @($lock.components | Where-Object id -eq 'newserv-stable-release')
    if ($component.Count -ne 1) {
        throw 'Source lock must contain exactly one newserv-stable-release component'
    }
    $member = @($component[0].members | Where-Object path -eq 'release/newserv-windows.exe')
    if (($member.Count -ne 1) -or ($member[0].sha256 -notmatch '^[0-9a-f]{64}$') -or
        ([long]$member[0].size -le 0)) {
        throw 'Source lock has no valid approved newserv-windows.exe member'
    }
    [pscustomobject]@{
        ComponentId = $component[0].id
        Size = [long]$member[0].size
        Sha256 = $member[0].sha256.ToLowerInvariant()
    }
}

function Get-RunningServerProcesses([Parameter(Mandatory)]$Layout) {
    $expected = [System.IO.Path]::GetFullPath((Join-Path $Layout.Server 'newserv-windows.exe'))
    $matches = [System.Collections.Generic.List[object]]::new()
    if (Get-Command -Name Get-NewservProcessesAtPath -ErrorAction SilentlyContinue) {
        try {
            foreach ($process in @(Get-NewservProcessesAtPath -Layout $Layout)) {
                if ($process) { $matches.Add($process) }
            }
            return @($matches)
        } catch {
            # Fall through to an independent exact executable-path check.
        }
    }
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name = 'newserv-windows.exe'" -ErrorAction Stop)) {
        if ($process.ExecutablePath -and
            [System.IO.Path]::GetFullPath($process.ExecutablePath).Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            $matches.Add($process)
        }
    }
    @($matches)
}

function Assert-ExactProperties($Object, [string[]]$Expected, [string]$Context) {
    if ($null -eq $Object) {
        throw "$Context is null"
    }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expectedSorted -DifferenceObject $actual).Count -ne 0) {
        throw "$Context has an unexpected schema"
    }
}

function Assert-NoReparsePoints([Parameter(Mandatory)][string]$Path) {
    foreach ($item in @(Get-Item -Force -LiteralPath $Path) + @(Get-ChildItem -Force -LiteralPath $Path -Recurse)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Backup contains a reparse point: $($item.FullName)"
        }
    }
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

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
try {
$ownsMutex = $mutex.WaitOne(0)
if (-not $ownsMutex) {
    throw 'Another PSOBB start, stop, backup, restore, or patch-profile operation is already in progress'
}
if (@(Get-RunningServerProcesses -Layout $layout).Count -gt 0) {
    throw 'Stop the exact stable newserv process before validating or restoring state'
}
$resolvedBackup = (Resolve-Path -LiteralPath $BackupPath).Path
Assert-PathWithinRoot -Path $resolvedBackup -Root $layout.Backups | Out-Null
Assert-NoReparsePoints -Path $resolvedBackup
$manifestPath = Join-Path $resolvedBackup 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Backup manifest is missing'
}

try {
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Backup manifest is not valid JSON: $($_.Exception.Message)"
}
if ($manifest.schemaVersion -eq 2) {
    throw 'Unsupported incomplete backup manifest schema 2: stable/installation.json is absent; schema 3 is required'
}
if ($manifest.schemaVersion -ne 3) {
    throw "Unsupported backup manifest schema: $($manifest.schemaVersion); schema 3 is required"
}
Assert-ExactProperties $manifest @(
    'schemaVersion', 'backupId', 'backupKind', 'createdAtUtc', 'serverExecutable',
    'clientPatchState', 'stateRoots', 'files'
) 'Backup manifest'
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

Assert-ExactProperties $manifest.serverExecutable @('path', 'sourceLockComponent', 'size', 'sha256') 'serverExecutable'
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
    Assert-ExactProperties $stateRoot @('path', 'kind') 'stateRoots entry'
    if (-not $expectedStateRoots.Contains([string]$stateRoot.path) -or
        $stateRoot.kind -cne $expectedStateRoots[[string]$stateRoot.path] -or
        -not $seenStateRoots.Add([string]$stateRoot.path)) {
        throw "Backup manifest contains an invalid or duplicate state root: $($stateRoot.path)"
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
foreach ($entry in $manifestFiles) {
    Assert-ExactProperties $entry @('path', 'size', 'sha256') 'files entry'
    $entryPath = [string]$entry.path
    if (-not (Test-AllowedStateFilePath $entryPath)) {
        throw "Backup manifest contains a disallowed path: $entryPath"
    }
    if (-not $seenPaths.Add($entryPath)) {
        throw "Backup manifest contains a duplicate path: $entryPath"
    }
    if (([long]$entry.size -lt 0) -or ([string]$entry.sha256 -notmatch '^[0-9a-f]{64}$')) {
        throw "Backup manifest contains invalid file metadata: $entryPath"
    }
    Add-ExpectedParentDirectories -Set $expectedDirectories -FilePath $entryPath
    $file = Assert-PathWithinRoot -Path (Join-Path $resolvedBackup ($entryPath.Replace('/', '\'))) -Root $resolvedBackup
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Backup file is missing: $entryPath"
    }
    if ((Get-Item -LiteralPath $file).Length -ne [long]$entry.size) {
        throw "Backup size check failed: $entryPath"
    }
    if ((Get-LowerSha256 $file) -cne [string]$entry.sha256) {
        throw "Backup checksum failed: $entryPath"
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

Assert-ExactProperties $manifest.clientPatchState @(
    'profile', 'policySha256', 'configPath', 'configSha256', 'installationPath',
    'installationSha256', 'installationId'
) 'clientPatchState'
$patchState = Assert-PSOBBClientPatchStateCoherent `
    -ConfigPath (Join-Path $resolvedBackup 'system\config.json') `
    -InstallRecordPath (Join-Path $resolvedBackup 'stable\installation.json') `
    -InstallationId ([string]$marker.installationId)
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
    ManifestPath = $manifestPath
    ManifestSha256 = Get-LowerSha256 $manifestPath
    ApprovedServerExecutableSha256 = $approvedServer.Sha256
    ClientPatchProfile = $patchState.Profile
    ClientPatchPolicySha256 = $patchState.PolicySha256
    Manifest = $manifest
}
if ($ValidateOnly) {
    return $validation
}
if (-not $PSCmdlet.ShouldProcess($layout.Root, "Restore exact PSOBB state from $resolvedBackup")) {
    return $validation
}

$systemRoot = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'system') -Root $layout.Server
$stableRoot = Assert-PathWithinRoot -Path $layout.Stable -Root $layout.Root
$transactionId = [Guid]::NewGuid().ToString('N')
$stageRoot = Assert-PathWithinRoot -Path (Join-Path $stableRoot ('.psobb-restore-stage-' + $transactionId)) -Root $stableRoot
$rollbackRoot = Assert-PathWithinRoot -Path (Join-Path $stableRoot ('.psobb-restore-rollback-' + $transactionId)) -Root $stableRoot
$restoreSucceeded = $false
$emergency = $null
try {
    New-Item -ItemType Directory -Path $stageRoot | Out-Null
    foreach ($relative in @('system/licenses', 'system/players', 'system/teams', 'stable')) {
        New-Item -ItemType Directory `
            -Path (Join-Path $stageRoot ($relative.Replace('/', '\'))) `
            -Force | Out-Null
    }
    foreach ($entry in $manifestFiles) {
        $source = Assert-PathWithinRoot -Path (Join-Path $resolvedBackup (([string]$entry.path).Replace('/', '\'))) -Root $resolvedBackup
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $stageRoot (([string]$entry.path).Replace('/', '\'))) `
            -Root $stageRoot
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
        if (((Get-Item -LiteralPath $destination).Length -ne [long]$entry.size) -or
            ((Get-LowerSha256 $destination) -cne [string]$entry.sha256)) {
            throw "Staged restore verification failed: $($entry.path)"
        }
    }
    # Capture the exact pre-mutation state using the same schema and verifier.
    $emergency = & (Join-Path $PSScriptRoot 'Backup-PSOBB.ps1') `
        -RuntimeRoot $layout.Root -BackupKind pre-restore -Retention 7
    if (-not $emergency -or -not (Test-Path -LiteralPath (Join-Path $emergency.BackupPath 'manifest.json') -PathType Leaf)) {
        throw 'The manifested pre-restore emergency backup was not created'
    }
    if (@(Get-RunningServerProcesses -Layout $layout).Count -gt 0) {
        throw 'The stable newserv process started before the restore transaction'
    }

    New-Item -ItemType Directory -Path $rollbackRoot | Out-Null
    $items = @(
        [pscustomobject]@{ Name = 'licenses'; Current = Join-Path $systemRoot 'licenses'; Staged = Join-Path $stageRoot 'system\licenses'; Rollback = Join-Path $rollbackRoot 'licenses' }
        [pscustomobject]@{ Name = 'players'; Current = Join-Path $systemRoot 'players'; Staged = Join-Path $stageRoot 'system\players'; Rollback = Join-Path $rollbackRoot 'players' }
        [pscustomobject]@{ Name = 'teams'; Current = Join-Path $systemRoot 'teams'; Staged = Join-Path $stageRoot 'system\teams'; Rollback = Join-Path $rollbackRoot 'teams' }
        [pscustomobject]@{ Name = 'config.json'; Current = Join-Path $systemRoot 'config.json'; Staged = Join-Path $stageRoot 'system\config.json'; Rollback = Join-Path $rollbackRoot 'config.json' }
        [pscustomobject]@{ Name = 'installation.json'; Current = $layout.InstallRecord; Staged = Join-Path $stageRoot 'stable\installation.json'; Rollback = Join-Path $rollbackRoot 'installation.json' }
    )
    $processed = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($item in $items) {
            Move-Item -LiteralPath $item.Current -Destination $item.Rollback
            try {
                Move-Item -LiteralPath $item.Staged -Destination $item.Current
            } catch {
                $swapFailure = $_
                try {
                    Move-Item -LiteralPath $item.Rollback -Destination $item.Current
                } catch {
                    throw "Swap of $($item.Name) failed and its immediate rollback also failed. Use $($emergency.BackupPath). Swap error: $($swapFailure.Exception.Message). Rollback error: $($_.Exception.Message)"
                }
                throw $swapFailure
            }
            $processed.Add($item)
        }

        # Verify the installed state before deleting rollback material.
        foreach ($entry in $manifestFiles) {
            $installed = Get-LiveStatePath -Layout $layout -RelativePath ([string]$entry.path)
            if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or
                ((Get-Item -LiteralPath $installed).Length -ne [long]$entry.size) -or
                ((Get-LowerSha256 $installed) -cne [string]$entry.sha256)) {
                throw "Installed restore verification failed: $($entry.path)"
            }
        }
        $installedPatchState = Assert-PSOBBClientPatchStateCoherent `
            -ConfigPath (Join-Path $systemRoot 'config.json') `
            -InstallRecordPath $layout.InstallRecord `
            -InstallationId ([string]$marker.installationId)
        if (($installedPatchState.Profile -cne $patchState.Profile) -or
            ($installedPatchState.PolicySha256 -cne $patchState.PolicySha256)) {
            throw 'Installed config and installation metadata do not match the restored client-patch state'
        }
        & (Join-Path $PSScriptRoot 'Set-PSOBBRuntimeAcl.ps1') -RuntimeRoot $layout.Root | Out-Null
        $restoreSucceeded = $true
    } catch {
        $restoreFailure = $_
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        for ($index = $processed.Count - 1; $index -ge 0; $index--) {
            $item = $processed[$index]
            try {
                if (Test-Path -LiteralPath $item.Current) {
                    Remove-Item -LiteralPath $item.Current -Recurse -Force
                }
                Move-Item -LiteralPath $item.Rollback -Destination $item.Current
            } catch {
                $rollbackErrors.Add("$($item.Name): $($_.Exception.Message)")
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "Restore failed and rollback was incomplete. Use $($emergency.BackupPath). Original error: $($restoreFailure.Exception.Message). Rollback errors: $($rollbackErrors -join '; ')"
        }
        throw $restoreFailure
    }
} finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
    if ($restoreSucceeded -and (Test-Path -LiteralPath $rollbackRoot)) {
        Remove-Item -LiteralPath $rollbackRoot -Recurse -Force
    } elseif ((Test-Path -LiteralPath $rollbackRoot) -and
        @(Get-ChildItem -Force -LiteralPath $rollbackRoot).Count -eq 0) {
        Remove-Item -LiteralPath $rollbackRoot -Force
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
}
} finally {
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
