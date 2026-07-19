[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [ValidateRange(1, 100)][int]$Retention = 7,
    [ValidateSet('state', 'pre-restore')][string]$BackupKind = 'state'
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

function Assert-NoReparsePoints([Parameter(Mandatory)][string]$Path) {
    foreach ($item in @(Get-Item -Force -LiteralPath $Path) + @(Get-ChildItem -Force -LiteralPath $Path -Recurse)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Backup source contains a reparse point: $($item.FullName)"
        }
    }
}

function Get-LiveStatePath(
    [Parameter(Mandatory)]$Layout,
    [Parameter(Mandatory)][string]$RelativePath
) {
    if ($RelativePath -eq 'stable/installation.json') {
        return Assert-PathWithinRoot -Path $Layout.InstallRecord -Root $Layout.Root
    }
    if (($RelativePath -eq 'system/config.json') -or
        ($RelativePath -in @('system/licenses', 'system/players', 'system/teams'))) {
        return Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Server ($RelativePath.Replace('/', '\'))) `
            -Root $Layout.Server
    }
    throw "Unsupported backup state path: $RelativePath"
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
$serverExe = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
$approvedServer = Get-ApprovedServerExecutable
if (-not (Test-Path -LiteralPath $serverExe -PathType Leaf)) {
    throw "Server executable is missing: $serverExe"
}
$serverItem = Get-Item -LiteralPath $serverExe
$serverHash = Get-LowerSha256 $serverExe
if (($serverItem.Length -ne $approvedServer.Size) -or ($serverHash -ne $approvedServer.Sha256)) {
    throw 'The installed server executable does not match the approved source-lock member'
}
if (@(Get-RunningServerProcesses -Layout $layout).Count -gt 0) {
    throw 'Stop the exact stable newserv process before creating a consistent backup'
}

$stateRoots = @(
    [ordered]@{ path = 'system/licenses'; kind = 'directory' }
    [ordered]@{ path = 'system/players'; kind = 'directory' }
    [ordered]@{ path = 'system/teams'; kind = 'directory' }
    [ordered]@{ path = 'system/config.json'; kind = 'file' }
    [ordered]@{ path = 'stable/installation.json'; kind = 'file' }
)
foreach ($stateRoot in $stateRoots) {
    $source = Get-LiveStatePath -Layout $layout -RelativePath $stateRoot.path
    $expectedType = if ($stateRoot.kind -eq 'directory') { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $source -PathType $expectedType)) {
        throw "Required $($stateRoot.kind) state root is missing: $($stateRoot.path)"
    }
    Assert-NoReparsePoints -Path $source
}

if (-not (Test-Path -LiteralPath $layout.Backups -PathType Container)) {
    New-Item -ItemType Directory -Path $layout.Backups -Force | Out-Null
}
Assert-PathWithinRoot -Path $layout.Backups -Root $layout.Root | Out-Null
Set-PSOBBProtectedAcl -Path $layout.Backups
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$backup = Join-Path $layout.Backups ($BackupKind + '-' + $stamp)
$partial = $backup + '.partial-' + [Guid]::NewGuid().ToString('N')
Assert-PathWithinRoot -Path $backup -Root $layout.Backups | Out-Null
Assert-PathWithinRoot -Path $partial -Root $layout.Backups | Out-Null

$completed = $false
try {
    New-Item -ItemType Directory -Path $partial | Out-Null
    foreach ($directory in @('system', 'system/licenses', 'system/players', 'system/teams', 'stable')) {
        $destination = Assert-PathWithinRoot -Path (Join-Path $partial ($directory.Replace('/', '\'))) -Root $partial
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
    }

    $manifestFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($rootName in @('licenses', 'players', 'teams')) {
        $sourceRoot = Join-Path $layout.Server ('system\' + $rootName)
        foreach ($sourceFile in @(Get-ChildItem -Force -LiteralPath $sourceRoot -Recurse -File | Sort-Object FullName)) {
            $relativeUnderRoot = [System.IO.Path]::GetRelativePath($sourceRoot, $sourceFile.FullName)
            $relative = ('system/' + $rootName + '/' + $relativeUnderRoot.Replace('\', '/'))
            $destination = Assert-PathWithinRoot -Path (Join-Path $partial ($relative.Replace('/', '\'))) -Root $partial
            New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
            $sourceHash = Get-LowerSha256 $sourceFile.FullName
            Copy-Item -LiteralPath $sourceFile.FullName -Destination $destination
            $destinationItem = Get-Item -LiteralPath $destination
            if (($destinationItem.Length -ne $sourceFile.Length) -or ((Get-LowerSha256 $destination) -ne $sourceHash)) {
                throw "Backup copy verification failed: $relative"
            }
            $manifestFiles.Add([ordered]@{ path = $relative; size = [long]$sourceFile.Length; sha256 = $sourceHash })
        }
    }

    foreach ($relative in @('system/config.json', 'stable/installation.json')) {
        $source = Get-LiveStatePath -Layout $layout -RelativePath $relative
        $destination = Assert-PathWithinRoot `
            -Path (Join-Path $partial ($relative.Replace('/', '\'))) `
            -Root $partial
        $sourceItem = Get-Item -LiteralPath $source
        $sourceHash = Get-LowerSha256 $source
        Copy-Item -LiteralPath $source -Destination $destination
        $destinationItem = Get-Item -LiteralPath $destination
        if (($destinationItem.Length -ne $sourceItem.Length) -or
            ((Get-LowerSha256 $destination) -ne $sourceHash)) {
            throw "Backup copy verification failed: $relative"
        }
        $manifestFiles.Add([ordered]@{
            path = $relative
            size = [long]$destinationItem.Length
            sha256 = $sourceHash
        })
    }

    $patchState = Assert-PSOBBClientPatchStateCoherent `
        -ConfigPath (Join-Path $partial 'system\config.json') `
        -InstallRecordPath (Join-Path $partial 'stable\installation.json') `
        -InstallationId ([string]$marker.installationId)

    # A process that started during the copy invalidates the consistency guarantee.
    if (@(Get-RunningServerProcesses -Layout $layout).Count -gt 0) {
        throw 'The stable newserv process started while the backup was being created'
    }

    $manifest = [ordered]@{
        schemaVersion = 3
        backupId = [Guid]::NewGuid().ToString('D')
        backupKind = $BackupKind
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        serverExecutable = [ordered]@{
            path = 'newserv-windows.exe'
            sourceLockComponent = $approvedServer.ComponentId
            size = [long]$serverItem.Length
            sha256 = $serverHash
        }
        clientPatchState = [ordered]@{
            profile = $patchState.Profile
            policySha256 = $patchState.PolicySha256
            configPath = 'system/config.json'
            configSha256 = $patchState.ConfigSha256
            installationPath = 'stable/installation.json'
            installationSha256 = $patchState.InstallationSha256
            installationId = $patchState.InstallationId
        }
        stateRoots = $stateRoots
        files = @($manifestFiles | Sort-Object { $_.path })
    }
    $manifestPath = Join-Path $partial 'manifest.json'
    [System.IO.File]::WriteAllText(
        $manifestPath,
        ($manifest | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedTreeAcl -Path $partial -Root $layout.Backups
    Move-Item -LiteralPath $partial -Destination $backup
    $completed = $true
} finally {
    if (-not $completed -and (Test-Path -LiteralPath $partial)) {
        Remove-Item -LiteralPath $partial -Recurse -Force
    }
}

Get-ChildItem -LiteralPath $layout.Backups -Directory -Filter ($BackupKind + '-*') |
    Where-Object { $_.Name -notmatch '\.partial-' } |
    Sort-Object Name -Descending |
    Select-Object -Skip $Retention |
    ForEach-Object {
        Assert-PathWithinRoot -Path $_.FullName -Root $layout.Backups | Out-Null
        Remove-Item -LiteralPath $_.FullName -Recurse -Force
    }

$manifestPath = Join-Path $backup 'manifest.json'
[pscustomobject]@{
    BackupPath = $backup
    BackupKind = $BackupKind
    Files = $manifestFiles.Count
    ManifestSha256 = Get-LowerSha256 $manifestPath
    ServerExecutableSha256 = $serverHash
    ClientPatchProfile = $patchState.Profile
    ClientPatchPolicySha256 = $patchState.PolicySha256
    Retention = $Retention
}
} finally {
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
