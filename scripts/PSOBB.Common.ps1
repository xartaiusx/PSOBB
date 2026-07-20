Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:PSOBBRepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:PSOBBCanonicalRuntimeRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $script:PSOBBRepositoryRoot 'PSOBB-Runtime')).TrimEnd('\')
$script:PSOBBTrustedGitAuthorityToken = [object]::new()
$script:PSOBBGitBoundaryQuarantine = [System.Collections.Generic.List[object]]::new()

function Get-PSOBBLeasedFileDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.FileStream]$Lease,
        [Parameter(Mandatory)][ValidateRange(1, 1073741824)]
        [long]$MaximumBytes,
        [string]$Label = 'leased executable'
    )

    if (-not $Lease.CanRead -or -not $Lease.CanSeek) {
        throw "The $Label lease is not readable and seekable"
    }
    $length = [long]$Lease.Length
    if ($length -le 0 -or $length -gt $MaximumBytes) {
        throw "The $Label length is outside its exact bound"
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $null
    try {
        $Lease.Position = 0
        $hash = $sha256.ComputeHash($Lease)
        $Lease.Position = 0
        [pscustomobject]@{
            Length = $length
            Sha256 = [Convert]::ToHexString($hash).ToLowerInvariant()
        }
    } finally {
        if ($hash) {
            [Array]::Clear($hash, 0, $hash.Length)
        }
        $sha256.Dispose()
    }
}

function Open-PSOBBTrustedExecutableLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(1, 1073741824)]
        [long]$MaximumBytes,
        [string]$Label = 'trusted executable',
        [switch]$RequireProtectedAcl
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PSOBBOrdinaryContainedPath `
        -Path $Path -Root $safeRoot -Kind File -Label $Label
    if ($RequireProtectedAcl -and
        -not (Test-PSOBBProtectedAcl -Path $safePath)) {
        throw "The $Label ACL is invalid"
    }
    $lease = $null
    try {
        # FileShare.Read denies write, delete, rename, and replacement while
        # still allowing CreateProcess and signature verification to read.
        $lease = [System.IO.FileStream]::new(
            $safePath, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read,
            65536, [System.IO.FileOptions]::SequentialScan)
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $safePath -Root $safeRoot -Kind File -Label $Label)
        if ($RequireProtectedAcl -and
            -not (Test-PSOBBProtectedAcl -Path $safePath)) {
            throw "The $Label ACL changed while its lease was acquired"
        }
        $digest = Get-PSOBBLeasedFileDigest `
            -Lease $lease -MaximumBytes $MaximumBytes -Label $Label
        [pscustomobject]@{
            Path = $safePath
            Root = $safeRoot
            MaximumBytes = [long]$MaximumBytes
            Length = [long]$digest.Length
            Sha256 = [string]$digest.Sha256
            Lease = $lease
        }
        $lease = $null
    } finally {
        if ($lease) {
            $lease.Dispose()
        }
    }
}

function Test-PSOBBGitLeaseQuarantined {
    [CmdletBinding()]
    param($Identity)

    foreach ($entry in @($script:PSOBBGitBoundaryQuarantine)) {
        if ([object]::ReferenceEquals($entry.GitIdentity, $Identity)) {
            return $true
        }
    }
    $false
}

function Close-PSOBBTrustedExecutableLease {
    [CmdletBinding()]
    param($Identity)

    if ($Identity -and (Test-PSOBBGitLeaseQuarantined -Identity $Identity)) {
        return
    }
    if ($Identity -and $Identity.PSObject.Properties['Lease'] -and
        $Identity.Lease -is [System.IO.FileStream]) {
        $safeHandle = $Identity.Lease.SafeFileHandle
        $Identity.Lease.Dispose()
        if (-not $safeHandle.IsClosed -or $Identity.Lease.CanRead) {
            throw 'The trusted executable lease did not close deterministically'
        }
    }
}

function Test-PSOBBTrustedExecutableLeaseClosed {
    [CmdletBinding()]
    param($Identity)

    if (-not $Identity -or -not $Identity.PSObject.Properties['Lease'] -or
        $Identity.Lease -isnot [System.IO.FileStream]) {
        return $false
    }
    -not $Identity.Lease.CanRead -and
        $Identity.Lease.SafeFileHandle.IsClosed
}

function Get-PSOBBTrustedGitIdentity {
    [CmdletBinding()]
    param()

    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        throw 'The trusted Program Files location is unavailable'
    }
    $trustedRoot = [System.IO.Path]::GetFullPath($programFiles).TrimEnd('\')
    $path = Join-Path $trustedRoot 'Git\mingw64\bin\git.exe'
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $path -Root $trustedRoot -Kind File `
            -Label 'trusted Git executable')
    $identity = Open-PSOBBTrustedExecutableLease `
        -Path $path -Root $trustedRoot -MaximumBytes 64MB `
        -Label 'trusted Git executable'
    try {
        # The lease prevents path replacement while the path-based Windows
        # Authenticode and version-resource APIs inspect the same file whose
        # bytes were hashed through the retained handle.
        $item = Get-Item -Force -LiteralPath $identity.Path
        $version = $item.VersionInfo
        $signature = Get-AuthenticodeSignature -LiteralPath $identity.Path
        $afterIdentity = Get-PSOBBLeasedFileDigest `
            -Lease $identity.Lease -MaximumBytes 64MB `
            -Label 'trusted Git executable identity'
        if ($signature.Status -ne
                [System.Management.Automation.SignatureStatus]::Valid -or
            $version.ProductName -cne 'Git' -or
            $version.FileDescription -cne 'Git for Windows' -or
            $version.OriginalFilename -cne 'git.exe' -or
            $afterIdentity.Length -ne $identity.Length -or
            $afterIdentity.Sha256 -cne $identity.Sha256) {
            throw 'The trusted Git executable identity is invalid'
        }
        $identity | Add-Member -NotePropertyName AuthorityToken `
            -NotePropertyValue $script:PSOBBTrustedGitAuthorityToken
        $identity | Add-Member -NotePropertyName QuarantineRetained `
            -NotePropertyValue $false
        $result = $identity
        $identity = $null
        $result
    } finally {
        if ($identity) {
            Close-PSOBBTrustedExecutableLease -Identity $identity
        }
    }
}

function Assert-PSOBBTrustedGitLease {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Identity)

    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    $expectedRoot = [System.IO.Path]::GetFullPath($programFiles).TrimEnd('\')
    $expectedPath = Join-Path $expectedRoot 'Git\mingw64\bin\git.exe'
    if (-not $Identity.PSObject.Properties['AuthorityToken'] -or
        -not [object]::ReferenceEquals(
            $Identity.AuthorityToken, $script:PSOBBTrustedGitAuthorityToken) -or
        [string]$Identity.Path -cne $expectedPath -or
        [string]$Identity.Root -cne $expectedRoot -or
        $Identity.Lease -isnot [System.IO.FileStream]) {
        throw 'The trusted Git executable lease identity is invalid'
    }
    if (Test-PSOBBGitLeaseQuarantined -Identity $Identity) {
        throw 'The trusted Git executable lease is retained by a quarantined process'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Identity.Path -Root $expectedRoot -Kind File `
            -Label 'trusted Git executable lease')
    $digest = Get-PSOBBLeasedFileDigest `
        -Lease $Identity.Lease -MaximumBytes 64MB `
        -Label 'trusted Git executable lease'
    if ($digest.Length -ne [long]$Identity.Length -or
        $digest.Sha256 -cne [string]$Identity.Sha256) {
        throw 'The trusted Git executable changed while leased'
    }
    $true
}

function Invoke-PSOBBGitBoundaryCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$Arguments,
        $GitIdentity
    )

    $ownsIdentity = $null -eq $GitIdentity
    $git = $null
    $process = $null
    $processStarted = $false
    $stdoutTask = $null
    $stderrTask = $null
    $retainLease = $false
    try {
        $git = if ($ownsIdentity) {
            Get-PSOBBTrustedGitIdentity
        } else {
            $GitIdentity
        }
        [void](Assert-PSOBBTrustedGitLease -Identity $git)
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $git.Path
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @('-C', $RepositoryRoot) + $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        $beforeStart = Get-PSOBBLeasedFileDigest `
            -Lease $git.Lease -MaximumBytes 64MB `
            -Label 'trusted Git executable immediately before process start'
        if ($beforeStart.Length -ne $git.Length -or
            $beforeStart.Sha256 -cne $git.Sha256) {
            throw 'The trusted Git executable changed before process start'
        }
        if (-not $process.Start()) {
            throw 'Windows did not start Git for the runtime boundary check'
        }
        $processStarted = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try {
                $process.Kill($true)
            } catch {
            }
            if (-not $process.WaitForExit(5000)) {
                $retainLease = $true
                throw 'Git did not stop within the bounded termination window; its executable lease remains retained'
            }
            [void]$stdoutTask.GetAwaiter().GetResult()
            [void]$stderrTask.GetAwaiter().GetResult()
            throw 'Git timed out during the runtime boundary check'
        }
        $afterExit = Get-PSOBBLeasedFileDigest `
            -Lease $git.Lease -MaximumBytes 64MB `
            -Label 'trusted Git executable after process exit'
        if ($afterExit.Length -ne $git.Length -or
            $afterExit.Sha256 -cne $git.Sha256) {
            throw 'The trusted Git executable changed during process execution'
        }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $stdoutTask.GetAwaiter().GetResult()
            StandardError = $stderrTask.GetAwaiter().GetResult()
        }
    } finally {
        if ($processStarted -and -not $process.HasExited -and
            -not $retainLease) {
            try {
                $process.Kill($true)
            } catch {
            }
            if (-not $process.WaitForExit(5000)) {
                $retainLease = $true
            }
        }
        if ($retainLease) {
            if (-not $git.PSObject.Properties['QuarantineRetained']) {
                $git | Add-Member -NotePropertyName QuarantineRetained `
                    -NotePropertyValue $true
            } else {
                $git.QuarantineRetained = $true
            }
            $script:PSOBBGitBoundaryQuarantine.Add([pscustomobject]@{
                    Process = $process
                    GitIdentity = $git
                    RetainedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
                })
        } elseif ($stdoutTask) {
            try {
                [void]$stdoutTask.GetAwaiter().GetResult()
            } catch {
            }
        }
        if (-not $retainLease -and $stderrTask) {
            try {
                [void]$stderrTask.GetAwaiter().GetResult()
            } catch {
            }
        }
        if (-not $retainLease -and $process) {
            $process.Dispose()
        }
        if ($ownsIdentity -and $git -and -not $retainLease) {
            Close-PSOBBTrustedExecutableLease -Identity $git
        }
        if ($retainLease) {
            throw 'Git did not stop within the bounded termination window; its executable lease remains retained'
        }
    }
}

function Assert-PSOBBGitRuntimeBoundary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RepositoryRoot)

    $repositoryFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
    $ignorePath = Join-Path $repositoryFull '.gitignore'
    if (-not (Test-Path -LiteralPath $ignorePath -PathType Leaf)) {
        throw 'The canonical nested PSOBB runtime requires the repository .gitignore file'
    }
    $hasAnchoredRuntimeRule = @(Get-Content -LiteralPath $ignorePath | Where-Object {
        $_.Trim().Equals('/PSOBB-Runtime/', [System.StringComparison]::Ordinal)
    }).Count -eq 1
    if (-not $hasAnchoredRuntimeRule) {
        throw 'The repository .gitignore must contain exactly one anchored /PSOBB-Runtime/ rule'
    }

    $trustedGit = Get-PSOBBTrustedGitIdentity
    try {
        $topLevel = Invoke-PSOBBGitBoundaryCommand `
            -RepositoryRoot $repositoryFull `
            -Arguments @('rev-parse', '--show-toplevel') `
            -GitIdentity $trustedGit
        if ($topLevel.ExitCode -ne 0 -or
            [string]::IsNullOrWhiteSpace($topLevel.StandardOutput)) {
            throw 'The canonical nested PSOBB runtime requires a valid Git worktree'
        }
        $reportedTopLevel = [System.IO.Path]::GetFullPath(
            $topLevel.StandardOutput.Trim()).TrimEnd('\')
        if (-not $reportedTopLevel.Equals(
                $repositoryFull,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The PSOBB repository root does not match the effective Git worktree root'
        }

        # Verify the directory boundary itself plus representative paths from
        # each sensitive runtime class while one direct-payload lease remains
        # held across all three Git process exits.
        $ignoreProbePaths = @(
            'PSOBB-Runtime',
            'PSOBB-Runtime/.psobb-runtime.json',
            'PSOBB-Runtime/archives/.psobb-ignore-probe',
            'PSOBB-Runtime/backups/.psobb-ignore-probe',
            'PSOBB-Runtime/graphics-evidence/.psobb-ignore-probe',
            'PSOBB-Runtime/local-lab/runtime/client/Psobb.exe',
            'PSOBB-Runtime/logs/.psobb-ignore-probe',
            'PSOBB-Runtime/secrets/.psobb-ignore-probe',
            'PSOBB-Runtime/stable/runtime/client/Psobb.exe')
        $ignoreProbe = Invoke-PSOBBGitBoundaryCommand `
            -RepositoryRoot $repositoryFull `
            -Arguments (@('check-ignore', '--no-index', '--') +
                $ignoreProbePaths) `
            -GitIdentity $trustedGit
        $ignoredPaths = @(
            $ignoreProbe.StandardOutput -split "`r?`n" | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
        $ignoredPathSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        foreach ($ignoredPath in $ignoredPaths) {
            [void]$ignoredPathSet.Add($ignoredPath)
        }
        $missingIgnoreProbes = @($ignoreProbePaths | Where-Object {
            -not $ignoredPathSet.Contains($_)
        })
        if ($ignoreProbe.ExitCode -ne 0 -or
            $ignoredPaths.Count -ne $ignoreProbePaths.Count -or
            $missingIgnoreProbes.Count -ne 0) {
            throw 'Git does not effectively ignore the complete canonical PSOBB-Runtime boundary'
        }

        $trackedRuntime = Invoke-PSOBBGitBoundaryCommand `
            -RepositoryRoot $repositoryFull `
            -Arguments @('ls-files', '--', 'PSOBB-Runtime') `
            -GitIdentity $trustedGit
        if ($trackedRuntime.ExitCode -ne 0) {
            throw 'Git could not verify whether canonical PSOBB runtime files are tracked'
        }
        $trackedPaths = @(
            $trackedRuntime.StandardOutput -split "`r?`n" | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
        if ($trackedPaths.Count -ne 0) {
            throw "Git already tracks $($trackedPaths.Count) path(s) inside PSOBB-Runtime"
        }
    } finally {
        Close-PSOBBTrustedExecutableLease -Identity $trustedGit
    }
}

function Assert-PSOBBCanonicalRuntimeIgnoreContract {
    [CmdletBinding()]
    param()

    Assert-PSOBBGitRuntimeBoundary -RepositoryRoot $script:PSOBBRepositoryRoot
}

function Test-PSOBBPathWithinCanonicalRuntime {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $runtimePrefix = $script:PSOBBCanonicalRuntimeRoot + '\'
    $fullPath.Equals($script:PSOBBCanonicalRuntimeRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($runtimePrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PSOBBPathOutsideTrackedSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Purpose
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $repositoryPrefix = $script:PSOBBRepositoryRoot.TrimEnd('\') + '\'
    $insideRepository =
        $fullPath.Equals($script:PSOBBRepositoryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($repositoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    if ($insideRepository -and -not (Test-PSOBBPathWithinCanonicalRuntime -Path $fullPath)) {
        throw "$Purpose must remain outside Git-tracked source: $fullPath"
    }
    if (Test-PSOBBPathWithinCanonicalRuntime -Path $fullPath) {
        Assert-PSOBBCanonicalRuntimeIgnoreContract
        return Assert-PathWithinRoot `
            -Path $fullPath `
            -Root $script:PSOBBCanonicalRuntimeRoot
    }
    $fullPath
}

function Get-PSOBBRuntimeRoot {
    [CmdletBinding()]
    param([string]$RuntimeRoot)

    if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
        $RuntimeRoot = $env:PSOBB_RUNTIME_ROOT
    }
    if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
        $RuntimeRoot = $script:PSOBBCanonicalRuntimeRoot
    }
    $fullRoot = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\')
    if ($fullRoot.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        throw 'The PSOBB runtime root must be on a local Windows volume, not a UNC/network path'
    }
    $repoPrefix = $script:PSOBBRepositoryRoot.TrimEnd('\') + '\'
    $insideRepository =
        $fullRoot.Equals($script:PSOBBRepositoryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullRoot.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    if ($insideRepository -and
        -not $fullRoot.Equals($script:PSOBBCanonicalRuntimeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Only the canonical ignored PSOBB-Runtime directory may contain runtime state inside this repository'
    }
    if ($fullRoot.Equals($script:PSOBBCanonicalRuntimeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Assert-PSOBBCanonicalRuntimeIgnoreContract
        Assert-PathWithinRoot `
            -Path $fullRoot `
            -Root $script:PSOBBCanonicalRuntimeRoot | Out-Null
    }
    $fullRoot
}

function Get-PSOBBLayout {
    [CmdletBinding()]
    param([string]$RuntimeRoot)

    $root = Get-PSOBBRuntimeRoot -RuntimeRoot $RuntimeRoot
    [pscustomobject]@{
        Root          = $root
        Archives      = Join-Path $root 'archives'
        Stable        = Join-Path $root 'stable'
        ServerBase    = Join-Path $root 'stable\server-base\release'
        Server        = Join-Path $root 'stable\server\release'
        BaseClient    = Join-Path $root 'stable\client'
        Client        = Join-Path $root 'stable\runtime\client'
        Canary        = Join-Path $root 'canary'
        CombatCanary  = Join-Path $root 'combat-canary'
        LocalLab      = Join-Path $root 'local-lab'
        Backups       = Join-Path $root 'backups'
        Logs          = Join-Path $root 'logs'
        Secrets       = Join-Path $root 'secrets'
        ControlDirectory = Join-Path $root 'stable\control'
        PidFile       = Join-Path $root 'stable\control\newserv.process.json'
        LegacyPidFile = Join-Path $root 'stable\control\newserv.pid'
        HostPidFile   = Join-Path $root 'stable\control\newserv-host.pid'
        ControlState  = Join-Path $root 'stable\control\newserv-control.json'
        ControlRequest = Join-Path $root 'stable\control\newserv-control.request.json'
        InstallRecord = Join-Path $root 'stable\installation.json'
        RuntimeMarker = Join-Path $root '.psobb-runtime.json'
        BaseClientManifest = Join-Path $root 'stable\base-client.manifest.json'
    }
}

function Assert-PathWithinRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rootPrefix = $fullRoot + '\'
    if (-not $fullPath.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside runtime root: $fullPath"
    }

    # A lexical prefix is not sufficient on Windows: a junction or symbolic link
    # beneath the trusted root can redirect a later copy/remove/ACL operation.
    $cursor = $fullPath
    while ($true) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a runtime path that traverses a reparse point: $($item.FullName)"
            }
        }
        if ($cursor.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if (-not $parent -or $parent.FullName.Length -lt $fullRoot.Length) {
            throw "Could not prove path containment beneath runtime root: $fullPath"
        }
        $cursor = $parent.FullName.TrimEnd('\')
    }
    $fullPath
}

function Resolve-PSOBBServerEnvironmentName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Environment
    )

    $normalized = $Environment.Trim() -replace '[\s_-]', ''
    if ($normalized.Equals('stable', [System.StringComparison]::OrdinalIgnoreCase)) {
        return 'Stable'
    }
    if ($normalized.Equals('combatcanary', [System.StringComparison]::OrdinalIgnoreCase)) {
        return 'CombatCanary'
    }
    throw "Unknown PSOBB server environment '$Environment'; expected Stable or CombatCanary"
}

function Get-PSOBBServerEnvironmentLayout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [string]$Environment = 'Stable'
    )

    $environmentName = Resolve-PSOBBServerEnvironmentName -Environment $Environment
    $root = [System.IO.Path]::GetFullPath([string]$Layout.Root).TrimEnd('\')
    if ($root.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        throw 'PSOBB server environments must be on a local Windows volume'
    }

    if ($environmentName -eq 'Stable') {
        $environmentRoot = [string]$Layout.Stable
        $values = [ordered]@{
            Environment        = 'Stable'
            EnvironmentId      = 'stable'
            Root               = $root
            EnvironmentRoot    = $environmentRoot
            ServerBase         = [string]$Layout.ServerBase
            Server             = [string]$Layout.Server
            Client             = [string]$Layout.Client
            ControlDirectory   = [string]$Layout.ControlDirectory
            PidFile            = [string]$Layout.PidFile
            LegacyPidFile      = [string]$Layout.LegacyPidFile
            HostPidFile        = [string]$Layout.HostPidFile
            ControlState       = [string]$Layout.ControlState
            ControlRequest     = [string]$Layout.ControlRequest
            InstallRecord      = [string]$Layout.InstallRecord
            Backups            = [string]$Layout.Backups
            Logs               = [string]$Layout.Logs
            Snapshots          = [string]$Layout.Backups
            Builds             = Split-Path -Parent ([string]$Layout.ServerBase)
            RuntimeMarker      = [string]$Layout.RuntimeMarker
            BaseClient         = [string]$Layout.BaseClient
            BaseClientManifest = [string]$Layout.BaseClientManifest
            Secrets            = [string]$Layout.Secrets
        }
    } else {
        $combatCanaryProperty = $Layout.PSObject.Properties['CombatCanary']
        if ($null -eq $combatCanaryProperty -or
            [string]::IsNullOrWhiteSpace([string]$combatCanaryProperty.Value)) {
            throw 'The runtime layout does not declare a CombatCanary root'
        }
        $environmentRoot = [string]$combatCanaryProperty.Value
        $controlDirectory = Join-Path $environmentRoot 'control'
        $values = [ordered]@{
            Environment        = 'CombatCanary'
            EnvironmentId      = 'combat-canary'
            Root               = $root
            EnvironmentRoot    = $environmentRoot
            ServerBase         = Join-Path $environmentRoot 'server-base\release'
            Server             = Join-Path $environmentRoot 'server\release'
            Client             = Join-Path $environmentRoot 'runtime\client'
            ControlDirectory   = $controlDirectory
            PidFile            = Join-Path $controlDirectory 'newserv.process.json'
            LegacyPidFile      = Join-Path $controlDirectory 'newserv.pid'
            HostPidFile        = Join-Path $controlDirectory 'newserv-host.pid'
            ControlState       = Join-Path $controlDirectory 'newserv-control.json'
            ControlRequest     = Join-Path $controlDirectory 'newserv-control.request.json'
            InstallRecord      = Join-Path $environmentRoot 'installation.json'
            Backups            = Join-Path $environmentRoot 'backups'
            Logs               = Join-Path $environmentRoot 'logs'
            Snapshots          = Join-Path $environmentRoot 'snapshots'
            Builds             = Join-Path $environmentRoot 'builds'
            RuntimeMarker      = [string]$Layout.RuntimeMarker
            BaseClient         = Join-Path $environmentRoot 'client'
            BaseClientManifest = Join-Path $environmentRoot 'base-client.manifest.json'
            Secrets            = Join-Path $environmentRoot 'secrets'
        }
    }

    foreach ($propertyName in @($values.Keys | Where-Object {
                $_ -notin @('Environment', 'EnvironmentId')
            })) {
        $values[$propertyName] = Assert-PathWithinRoot `
            -Path ([string]$values[$propertyName]) -Root $root
    }
    [pscustomobject]$values
}

function Test-PSOBBPathAncestorOverlap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$First,
        [Parameter(Mandatory)][string]$Second
    )

    $firstPath = [System.IO.Path]::GetFullPath($First).TrimEnd('\')
    $secondPath = [System.IO.Path]::GetFullPath($Second).TrimEnd('\')
    $firstPath.Equals($secondPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $firstPath.StartsWith(
            $secondPath + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
        $secondPath.StartsWith(
            $firstPath + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PSOBBServerEnvironmentIsolation {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $stable = Get-PSOBBServerEnvironmentLayout -Layout $Layout -Environment Stable
    $combatCanary = Get-PSOBBServerEnvironmentLayout `
        -Layout $Layout -Environment CombatCanary
    $stablePaths = [ordered]@{
        server    = $stable.Server
        client    = $stable.Client
        control   = $stable.ControlDirectory
        logs      = $stable.Logs
        backups   = $stable.Backups
        licenses  = Join-Path $stable.Server 'system\licenses'
        players   = Join-Path $stable.Server 'system\players'
        teams     = Join-Path $stable.Server 'system\teams'
        snapshots = $stable.Snapshots
    }
    $combatCanaryPaths = [ordered]@{
        server    = $combatCanary.Server
        client    = $combatCanary.Client
        control   = $combatCanary.ControlDirectory
        logs      = $combatCanary.Logs
        backups   = $combatCanary.Backups
        licenses  = Join-Path $combatCanary.Server 'system\licenses'
        players   = Join-Path $combatCanary.Server 'system\players'
        teams     = Join-Path $combatCanary.Server 'system\teams'
        snapshots = $combatCanary.Snapshots
    }

    foreach ($entry in @($stablePaths.GetEnumerator()) +
        @($combatCanaryPaths.GetEnumerator())) {
        Assert-PathWithinRoot -Path ([string]$entry.Value) -Root $stable.Root | Out-Null
    }
    foreach ($stableEntry in $stablePaths.GetEnumerator()) {
        foreach ($combatCanaryEntry in $combatCanaryPaths.GetEnumerator()) {
            if (Test-PSOBBPathAncestorOverlap `
                    -First ([string]$stableEntry.Value) `
                    -Second ([string]$combatCanaryEntry.Value)) {
                throw "PSOBB Stable $($stableEntry.Key) path overlaps CombatCanary $($combatCanaryEntry.Key) path"
            }
        }
    }

    [pscustomobject]@{
        StablePathsChecked       = $stablePaths.Count
        CombatCanaryPathsChecked = $combatCanaryPaths.Count
        PairwiseChecks           = $stablePaths.Count * $combatCanaryPaths.Count
        Passed                   = $true
    }
}

function Get-PSOBBServerComponentId {
    [CmdletBinding()]
    param([string]$ServerEnvironment = 'Stable')

    $environmentName = Resolve-PSOBBServerEnvironmentName `
        -Environment $ServerEnvironment
    if ($environmentName -ceq 'Stable') {
        'newserv-stable-release'
    } else {
        'newserv-combat-canary-build'
    }
}

function Get-PSOBBCombatCanaryServerComponentIdFromBuildContractHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-fA-F0-9]{64}$')]
        [string]$BuildContractSha256
    )

    $expected = $BuildContractSha256.ToLowerInvariant()
    $contracts = @(
        [pscustomobject]@{
            Path = Join-Path $script:PSOBBRepositoryRoot `
                'config\combat-canary-build.json'
            ComponentId = 'newserv-combat-canary-build'
        },
        [pscustomobject]@{
            Path = Join-Path $script:PSOBBRepositoryRoot `
                'config\combat-stable-shadow.json'
            ComponentId = 'newserv-stable-release'
        })
    $matches = @($contracts | Where-Object {
            (Test-Path -LiteralPath $_.Path -PathType Leaf) -and
                (Get-LowerSha256 $_.Path) -ceq $expected
        })
    if ($matches.Count -ne 1) {
        throw 'The combat-canary installation references an unknown build contract'
    }
    [string]$matches[0].ComponentId
}

function Get-PSOBBApprovedNewservExecutableIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [string]$ServerEnvironment = 'Stable',
        [string]$SourcesLockPath = (Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'),
        [string]$CombatCanaryBuildContractPath = (
            Join-Path $script:PSOBBRepositoryRoot 'config\combat-canary-build.json')
    )

    $environmentLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $Layout -Environment $ServerEnvironment
    $componentId = Get-PSOBBServerComponentId `
        -ServerEnvironment $environmentLayout.Environment
    if ($environmentLayout.Environment -ceq 'CombatCanary' -and
        (Test-Path -LiteralPath $environmentLayout.InstallRecord -PathType Leaf)) {
        $expectations = Get-PSOBBCombatCanaryInstallationBindingExpectations `
            -Layout $Layout
        $componentId = [string]$expectations.ServerComponentId
    }
    if (-not (Test-Path -LiteralPath $SourcesLockPath -PathType Leaf)) {
        throw "The source lock is missing: $SourcesLockPath"
    }
    $sourceLock = Get-Content -Raw -LiteralPath $SourcesLockPath |
        ConvertFrom-Json -Depth 30 -DateKind String
    $components = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq $componentId
        })
    $members = if ($components.Count -eq 1) {
        @($components[0].members | Where-Object {
                [string]$_.path -ceq 'release/newserv-windows.exe'
            })
    } else {
        @()
    }
    if ($components.Count -ne 1 -or $members.Count -ne 1 -or
        [long]$members[0].size -le 0 -or
        [string]$members[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "sources.lock.json does not contain one valid $componentId executable member"
    }

    if ($environmentLayout.Environment -ceq 'CombatCanary') {
        $selectedContractPath = if ($componentId -ceq
                'newserv-stable-release') {
            Join-Path $script:PSOBBRepositoryRoot `
                'config\combat-stable-shadow.json'
        } else {
            $CombatCanaryBuildContractPath
        }
        if (-not (Test-Path -LiteralPath $selectedContractPath -PathType Leaf)) {
            throw 'The tracked combat-canary build contract is missing'
        }
        $buildContract = Get-Content -Raw -LiteralPath $selectedContractPath |
            ConvertFrom-Json -Depth 20 -DateKind String
        $contractExecutable = if ($componentId -ceq
                'newserv-stable-release') {
            $buildContract.source.serverExecutable
        } else {
            $buildContract.output.executable
        }
        $contractRoot = [string]$buildContract.output.rootRelative
        if ($contractRoot -cne 'combat-canary/server-base/release' -or
            [string]$contractExecutable.path -cne 'newserv-windows.exe' -or
            [long]$contractExecutable.size -ne [long]$members[0].size -or
            [string]$contractExecutable.sha256 -cne
                [string]$members[0].sha256) {
            throw 'The combat-canary build contract does not match its exact source-lock executable member'
        }
    }

    [pscustomobject]@{
        ServerEnvironment = [string]$environmentLayout.Environment
        EnvironmentId = [string]$environmentLayout.EnvironmentId
        ComponentId = $componentId
        RelativePath = 'newserv-windows.exe'
        ExecutablePath = Join-Path $environmentLayout.Server 'newserv-windows.exe'
        Size = [long]$members[0].size
        Sha256 = [string]$members[0].sha256
        Authenticode = [string]$members[0].authenticode
    }
}

function Get-PSOBBCombatCanaryInstallationBindingExpectations {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $environmentLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $Layout -Environment CombatCanary
    $installRecordPath = Assert-PathWithinRoot `
        -Path $environmentLayout.InstallRecord `
        -Root $environmentLayout.EnvironmentRoot
    $installRecordItem = Get-Item `
        -Force -LiteralPath $installRecordPath -ErrorAction Stop
    if ($installRecordItem.PSIsContainer -or
        ($installRecordItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $installRecordItem.Length -le 0 -or
        $installRecordItem.Length -gt 256KB -or
        -not (Test-PSOBBProtectedAcl -Path $installRecordPath)) {
        throw 'The combat-canary installation binding record is missing, unsafe, or unprotected'
    }

    $snapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $installRecordPath `
        -Root $environmentLayout.EnvironmentRoot `
        -MaximumBytes 256KB `
        -MaximumDepth 8 `
        -Label 'combat-canary installation binding record'
    if (-not (Test-PSOBBProtectedAcl -Path $installRecordPath)) {
        throw 'The combat-canary installation binding record protection changed while it was read'
    }
    $installation = $snapshot.Value
    [void](Assert-PSOBBStrictDataObjectProperties `
            -Value $installation `
            -Label 'combat-canary installation binding record' `
            -Expected @(
                'schemaVersion', 'environment', 'environmentId',
                'initializedAtUtc', 'buildContractSha256',
                'serverReleaseManifestSha256', 'baseClientManifestSha256',
                'clientBindingSha256', 'snapshotDirectoryName', 'snapshotId',
                'snapshotManifestSha256', 'stateBindingSha256',
                'twillsContractSha256', 'signingPublicKeySpkiSha256',
                'configurationSha256'))

    foreach ($propertyName in @(
            'environment', 'environmentId', 'initializedAtUtc',
            'buildContractSha256', 'serverReleaseManifestSha256',
            'baseClientManifestSha256', 'clientBindingSha256',
            'snapshotDirectoryName', 'snapshotId', 'snapshotManifestSha256',
            'stateBindingSha256', 'twillsContractSha256',
            'signingPublicKeySpkiSha256', 'configurationSha256')) {
        if ($installation.$propertyName -isnot [string]) {
            throw "The combat-canary installation binding record contains a non-string $propertyName"
        }
    }
    $initializedAt = [DateTimeOffset]::MinValue
    $snapshotId = [Guid]::Empty
    if ($installation.schemaVersion -isnot [long] -or
        [long]$installation.schemaVersion -ne 1 -or
        [string]$installation.environment -cne 'CombatCanary' -or
        [string]$installation.environmentId -cne 'combat-canary' -or
        -not [DateTimeOffset]::TryParse(
            [string]$installation.initializedAtUtc, [ref]$initializedAt) -or
        [string]$installation.snapshotDirectoryName -cnotmatch
            '^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$' -or
        -not [Guid]::TryParseExact(
            [string]$installation.snapshotId, 'D', [ref]$snapshotId)) {
        throw 'The combat-canary installation binding record has an invalid identity'
    }
    foreach ($propertyName in @(
            'buildContractSha256', 'serverReleaseManifestSha256',
            'baseClientManifestSha256', 'clientBindingSha256',
            'snapshotManifestSha256', 'stateBindingSha256',
            'twillsContractSha256', 'signingPublicKeySpkiSha256',
            'configurationSha256')) {
        if ([string]$installation.$propertyName -cnotmatch '^[a-f0-9]{64}$') {
            throw "The combat-canary installation binding record contains an invalid $propertyName"
        }
    }

    [pscustomobject]@{
        ServerComponentId = Get-PSOBBCombatCanaryServerComponentIdFromBuildContractHash `
            -BuildContractSha256 ([string]$installation.buildContractSha256)
        BuildContractSha256 = [string]$installation.buildContractSha256
        ClientBindingSha256 = [string]$installation.clientBindingSha256
        StateBindingSha256 = [string]$installation.stateBindingSha256
    }
}

function Get-PSOBBCombatCanaryInstalledBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $verificationScript = Join-Path $script:PSOBBRepositoryRoot `
        'scripts\Test-PSOBBCombatCanary.ps1'
    if (-not (Test-Path -LiteralPath $verificationScript -PathType Leaf)) {
        throw 'The combat-canary installation verifier is missing'
    }
    $verification = & $verificationScript `
        -RuntimeRoot $Layout.Root -Target Installed
    if ($null -eq $verification -or -not [bool]$verification.Valid -or
        [string]$verification.Target -cne 'Installed' -or
        [string]$verification.Environment -cne 'CombatCanary') {
        throw 'The combat-canary installation did not pass complete installed-state verification'
    }
    foreach ($propertyName in @(
            'BuildContractSha256',
            'ServerReleaseManifestSha256',
            'BaseClientManifestSha256',
            'ClientBindingSha256',
            'ConfigurationSha256',
            'StateBindingSha256',
            'TwillsContractSha256',
            'SigningPublicKeySpkiSha256')) {
        if ([string]$verification.$propertyName -cnotmatch '^[a-f0-9]{64}$') {
            throw "The combat-canary installed-state verifier returned an invalid $propertyName"
        }
    }
    $expectedComponent =
        Get-PSOBBCombatCanaryServerComponentIdFromBuildContractHash `
            -BuildContractSha256 ([string]$verification.BuildContractSha256)
    $expectedArtifact = if ($expectedComponent -ceq
            'newserv-stable-release') { 'StableShadow' } else {
        'CurrentUpstream'
    }
    if ([string]$verification.ServerComponentId -cne $expectedComponent -or
        [string]$verification.ServerArtifact -cne $expectedArtifact) {
        throw 'The combat-canary installed-state verifier returned an invalid server component'
    }
    $verification
}

function Get-PSOBBCombatCanaryClientLaunchContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $verification = Get-PSOBBCombatCanaryInstalledBinding -Layout $Layout
    $environmentLayout = Get-PSOBBServerEnvironmentLayout `
        -Layout $Layout -Environment CombatCanary
    $bindingPath = Assert-PathWithinRoot `
        -Path (Join-Path $environmentLayout.EnvironmentRoot 'client-binding.json') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $bindingPath -PathType Leaf) -or
        (Get-LowerSha256 $bindingPath) -cne [string]$verification.ClientBindingSha256) {
        throw 'The combat-canary client binding changed after installed-state verification'
    }
    $binding = Get-Content -Raw -LiteralPath $bindingPath |
        ConvertFrom-Json -Depth 10 -DateKind String
    $expectedProperties = @(
        'schemaVersion', 'environment', 'environmentId', 'profile', 'renderer',
        'serverAddress', 'patchPort', 'gamePorts', 'clientExecutablePath',
        'clientExecutableSize', 'clientExecutableSha256', 'clientProfileSha256',
        'baseClientManifestSha256', 'createdAtUtc')
    $actualProperties = @($binding.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object -ReferenceObject @($expectedProperties | Sort-Object) `
            -DifferenceObject $actualProperties) {
        throw 'The combat-canary client binding does not have its exact schema-1 property set'
    }
    $clientExecutable = Join-Path $environmentLayout.Client 'Psobb.exe'
    $profilePath = Join-Path $environmentLayout.Client 'client-profile.json'
    if ([int]$binding.schemaVersion -ne 1 -or
        [string]$binding.environment -cne 'CombatCanary' -or
        [string]$binding.environmentId -cne 'combat-canary' -or
        [string]$binding.profile -cne 'baseline' -or
        [string]$binding.renderer -cne 'Native' -or
        [string]$binding.serverAddress -cne '127.0.0.1' -or
        [int]$binding.patchPort -ne 11000 -or
        @($binding.gamePorts).Count -ne 2 -or
        [int]$binding.gamePorts[0] -ne 12000 -or
        [int]$binding.gamePorts[1] -ne 12001 -or
        [string]$binding.clientExecutablePath -cne 'runtime/client/Psobb.exe' -or
        [string]$binding.clientExecutableSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$binding.clientProfileSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$binding.baseClientManifestSha256 -cne
            [string]$verification.BaseClientManifestSha256 -or
        -not (Test-Path -LiteralPath $clientExecutable -PathType Leaf) -or
        (Get-Item -LiteralPath $clientExecutable).Length -ne
            [long]$binding.clientExecutableSize -or
        (Get-LowerSha256 $clientExecutable) -cne
            [string]$binding.clientExecutableSha256 -or
        -not (Test-Path -LiteralPath $profilePath -PathType Leaf) -or
        (Get-LowerSha256 $profilePath) -cne [string]$binding.clientProfileSha256) {
        throw 'The combat-canary native client binding is invalid or changed after verification'
    }
    $profile = Get-Content -Raw -LiteralPath $profilePath |
        ConvertFrom-Json -Depth 15 -DateKind String
    if ([int]$profile.schemaVersion -ne 5 -or
        [string]$profile.channel -cne 'combat-canary' -or
        [string]$profile.profileId -cne 'safe-native-4x3' -or
        [string]$profile.renderer -cne 'Native' -or
        [string]$profile.graphicsPreset -cne 'Native' -or
        [string]$profile.baseExecutableSha256 -cne
            [string]$binding.clientExecutableSha256 -or
        $null -eq $profile.nativeGraphics) {
        throw 'The combat-canary native client profile is invalid'
    }

    [pscustomobject]@{
        Verification = $verification
        Binding = $binding
        Profile = $profile
        BindingPath = $bindingPath
        ProfilePath = $profilePath
        ClientExecutable = $clientExecutable
    }
}

function Get-PSOBBServerControlIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string]$InstallationId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+$')]
        [string]$EnvironmentId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+$')]
        [string]$ComponentId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')]
        [string]$StartupRequestId,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExecutableSha256
    )

    $canonical = @(
        'psobb-newserv-control-v2',
        $InstallationId.ToLowerInvariant(),
        $EnvironmentId,
        $ComponentId,
        $StartupRequestId,
        $ExecutableSha256
    ) -join "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    try {
        [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Test-PSOBBFixedTimeTextEquals {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][Parameter(Mandatory)][string]$Expected,
        [AllowEmptyString()][Parameter(Mandatory)][string]$Actual
    )

    $expectedBytes = [System.Text.Encoding]::UTF8.GetBytes($Expected)
    $actualBytes = [System.Text.Encoding]::UTF8.GetBytes($Actual)
    try {
        $expectedBytes.Length -eq $actualBytes.Length -and
            [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
                $expectedBytes, $actualBytes)
    } finally {
        [Array]::Clear($expectedBytes, 0, $expectedBytes.Length)
        [Array]::Clear($actualBytes, 0, $actualBytes.Length)
    }
}

function Test-PSOBBStrictJsonPropertyUniqueness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.Json.JsonElement]$Element,
        [string]$Path = '$'
    )

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "Lifecycle JSON contains a duplicate decoded property at $Path.$($property.Name)"
            }
            Test-PSOBBStrictJsonPropertyUniqueness `
                -Element $property.Value -Path "$Path.$($property.Name)"
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Test-PSOBBStrictJsonPropertyUniqueness `
                -Element $item -Path "$Path[$index]"
            $index++
        }
    }
    $true
}

function Assert-PSOBBStrictJsonExactProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
        throw "The $Label lifecycle JSON root is not an object"
    }
    $actual = @($Element.EnumerateObject() | ForEach-Object Name)
    $actualSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($propertyName in $actual) {
        [void]$actualSet.Add($propertyName)
    }
    $expectedSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($propertyName in $Expected) {
        [void]$expectedSet.Add($propertyName)
    }
    if ($actual.Count -ne $Expected.Count -or
        -not $actualSet.SetEquals($expectedSet)) {
        throw "The $Label lifecycle JSON does not have its exact property set"
    }
    $true
}

function ConvertFrom-PSOBBStrictJsonElement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.Json.JsonElement]$Element
    )

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $value = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) {
                $value[$property.Name] = ConvertFrom-PSOBBStrictJsonElement `
                    -Element $property.Value
            }
            return [pscustomobject]$value
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $values = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) {
                $values.Add((ConvertFrom-PSOBBStrictJsonElement -Element $item))
            }
            return ,$values.ToArray()
        }
        ([System.Text.Json.JsonValueKind]::String) {
            return $Element.GetString()
        }
        ([System.Text.Json.JsonValueKind]::Number) {
            [long]$integer = 0
            if ($Element.TryGetInt64([ref]$integer)) {
                return $integer
            }
            return $Element.GetDouble()
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        default { throw 'Lifecycle JSON contains an unsupported value kind' }
    }
}

function Read-PSOBBStrictLifecycleJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]
        [ValidateSet('ServerProcessRecord', 'ServerControlState', 'ServerControlRequest',
            'ClientStartupReceipt')]
        [string]$Contract
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    if (-not (Test-Path -LiteralPath $safePath -PathType Leaf)) {
        throw "The required $Contract lifecycle JSON is missing"
    }
    $item = Get-Item -LiteralPath $safePath -Force -ErrorAction Stop
    $maximumBytes = if ($Contract -ceq 'ServerControlRequest') { 16KB } else { 64KB }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt $maximumBytes) {
        throw "The $Contract lifecycle JSON has an invalid filesystem type or size"
    }

    $bytes = [System.IO.File]::ReadAllBytes($safePath)
    $document = $null
    try {
        if ($bytes.Length -ne $item.Length -or $bytes.Length -gt $maximumBytes) {
            throw "The $Contract lifecycle JSON changed size while it was read"
        }
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($bytes)
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 16
        $document = [System.Text.Json.JsonDocument]::Parse($text, $options)
        $rootElement = $document.RootElement
        Test-PSOBBStrictJsonPropertyUniqueness -Element $rootElement | Out-Null

        $variant = $Contract
        if ($Contract -ceq 'ServerControlState') {
            [System.Text.Json.JsonElement]$stateElement = [System.Text.Json.JsonElement]::new()
            if ($rootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                -not $rootElement.TryGetProperty('state', [ref]$stateElement) -or
                $stateElement.ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
                throw 'The ServerControlState lifecycle JSON has no state discriminator'
            }
            $variant = 'ServerControlState:' + $stateElement.GetString()
        } elseif ($Contract -ceq 'ServerControlRequest') {
            [System.Text.Json.JsonElement]$actionElement = [System.Text.Json.JsonElement]::new()
            if ($rootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                -not $rootElement.TryGetProperty('action', [ref]$actionElement) -or
                $actionElement.ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
                throw 'The ServerControlRequest lifecycle JSON has no action discriminator'
            }
            $variant = 'ServerControlRequest:' + $actionElement.GetString()
        }

        $definition = switch -CaseSensitive ($variant) {
            'ServerProcessRecord' {
                @{
                    Properties = @('schemaVersion', 'serverEnvironment', 'environmentId',
                        'componentId', 'controlIdentity', 'pid', 'executablePath',
                        'executableSha256', 'startTimeUtc', 'startTimeFileTimeUtc',
                        'hostPid', 'hostStartTimeUtc', 'hostStartTimeFileTimeUtc',
                        'hostExecutablePath', 'startupRequestId', 'controlToken',
                        'controlProtocol', 'buildContractSha256', 'clientBindingSha256',
                        'stateBindingSha256', 'stdoutLog', 'stderrLog')
                    Strings = @('serverEnvironment', 'environmentId', 'componentId',
                        'controlIdentity', 'executablePath', 'executableSha256',
                        'startTimeUtc', 'hostStartTimeUtc', 'hostExecutablePath',
                        'startupRequestId', 'controlToken', 'controlProtocol', 'stdoutLog',
                        'stderrLog')
                    Integers = @('schemaVersion', 'pid', 'startTimeFileTimeUtc', 'hostPid',
                        'hostStartTimeFileTimeUtc')
                    NullableStrings = @('buildContractSha256', 'clientBindingSha256',
                        'stateBindingSha256')
                    Booleans = @()
                }
            }
            'ServerControlState:starting' {
                @{
                    Properties = @('schemaVersion', 'state', 'installationId',
                        'serverEnvironment', 'environmentId', 'componentId', 'controlIdentity',
                        'executablePath', 'executableSha256', 'buildContractSha256',
                        'clientBindingSha256', 'stateBindingSha256', 'startupRequestId',
                        'controlToken', 'requestedAtUtc')
                    Strings = @('state', 'installationId', 'serverEnvironment', 'environmentId',
                        'componentId', 'controlIdentity', 'executablePath', 'executableSha256',
                        'startupRequestId', 'controlToken', 'requestedAtUtc')
                    Integers = @('schemaVersion')
                    NullableStrings = @('buildContractSha256', 'clientBindingSha256',
                        'stateBindingSha256')
                    Booleans = @()
                }
            }
            'ServerControlState:child-started' {
                @{
                    Properties = @('schemaVersion', 'state', 'installationId',
                        'serverEnvironment', 'environmentId', 'componentId', 'controlIdentity',
                        'pid', 'startTimeFileTimeUtc', 'hostPid',
                        'hostStartTimeFileTimeUtc', 'startupRequestId', 'startTimeUtc',
                        'updatedAtUtc')
                    Strings = @('state', 'installationId', 'serverEnvironment', 'environmentId',
                        'componentId', 'controlIdentity', 'startupRequestId', 'startTimeUtc',
                        'updatedAtUtc')
                    Integers = @('schemaVersion', 'pid', 'startTimeFileTimeUtc', 'hostPid',
                        'hostStartTimeFileTimeUtc')
                    NullableStrings = @()
                    Booleans = @()
                }
            }
            'ServerControlState:shell-exit-requested' {
                @{
                    Properties = @('schemaVersion', 'state', 'installationId',
                        'serverEnvironment', 'environmentId', 'componentId', 'controlIdentity',
                        'pid', 'startTimeFileTimeUtc', 'hostPid',
                        'hostStartTimeFileTimeUtc', 'updatedAtUtc')
                    Strings = @('state', 'installationId', 'serverEnvironment', 'environmentId',
                        'componentId', 'controlIdentity', 'updatedAtUtc')
                    Integers = @('schemaVersion', 'pid', 'startTimeFileTimeUtc', 'hostPid',
                        'hostStartTimeFileTimeUtc')
                    NullableStrings = @()
                    Booleans = @()
                }
            }
            { $_ -in @('ServerControlState:stopped', 'ServerControlState:exited') } {
                @{
                    Properties = @('schemaVersion', 'state', 'installationId',
                        'serverEnvironment', 'environmentId', 'componentId', 'controlIdentity',
                        'pid', 'startTimeFileTimeUtc', 'exitCode',
                        'gracefulShellExitRequested', 'updatedAtUtc')
                    Strings = @('state', 'installationId', 'serverEnvironment', 'environmentId',
                        'componentId', 'controlIdentity', 'updatedAtUtc')
                    Integers = @('schemaVersion', 'pid', 'startTimeFileTimeUtc', 'exitCode')
                    NullableStrings = @()
                    Booleans = @('gracefulShellExitRequested')
                }
            }
            'ServerControlState:failed' {
                @{
                    Properties = @('schemaVersion', 'state', 'serverEnvironment',
                        'environmentId', 'componentId', 'controlIdentity', 'message',
                        'updatedAtUtc')
                    Strings = @('state', 'serverEnvironment', 'environmentId', 'componentId',
                        'message', 'updatedAtUtc')
                    Integers = @('schemaVersion')
                    NullableStrings = @('controlIdentity')
                    Booleans = @()
                }
            }
            'ServerControlRequest:exit' {
                @{
                    Properties = @('schemaVersion', 'action', 'serverEnvironment',
                        'environmentId', 'componentId', 'controlIdentity', 'startupRequestId',
                        'pid', 'startTimeUtc', 'startTimeFileTimeUtc', 'controlToken',
                        'requestedAtUtc')
                    Strings = @('action', 'serverEnvironment', 'environmentId', 'componentId',
                        'controlIdentity', 'startupRequestId', 'startTimeUtc', 'controlToken',
                        'requestedAtUtc')
                    Integers = @('schemaVersion', 'pid', 'startTimeFileTimeUtc')
                    NullableStrings = @()
                    Booleans = @()
                }
            }
            'ServerControlRequest:cancel-start' {
                @{
                    Properties = @('schemaVersion', 'action', 'serverEnvironment',
                        'environmentId', 'componentId', 'controlIdentity', 'hostPid',
                        'hostStartTimeFileTimeUtc', 'startupRequestId', 'controlToken',
                        'requestedAtUtc')
                    Strings = @('action', 'serverEnvironment', 'environmentId', 'componentId',
                        'controlIdentity', 'startupRequestId', 'controlToken', 'requestedAtUtc')
                    Integers = @('schemaVersion', 'hostPid', 'hostStartTimeFileTimeUtc')
                    NullableStrings = @()
                    Booleans = @()
                }
            }
            'ClientStartupReceipt' {
                @{
                    Properties = @('schemaVersion', 'completedAtUtc', 'serverEnvironment',
                        'environmentId', 'channel', 'profileId', 'materializedProfileSha256',
                        'configurationSha256', 'processId', 'processStartTimeUtc',
                        'processStartTimeFileTimeUtc', 'executableSize', 'executableSha256',
                        'clientBindingSha256', 'startupElapsedMilliseconds',
                        'foregroundPreserved', 'windowMode', 'window',
                        'nativeGraphicsPresetId', 'graphicCtrlSha256')
                    Strings = @('completedAtUtc', 'serverEnvironment', 'environmentId',
                        'channel', 'materializedProfileSha256', 'processStartTimeUtc',
                        'executableSha256', 'windowMode', 'nativeGraphicsPresetId',
                        'graphicCtrlSha256')
                    Integers = @('schemaVersion', 'processId',
                        'processStartTimeFileTimeUtc', 'executableSize')
                    NullableStrings = @('profileId', 'configurationSha256',
                        'clientBindingSha256')
                    Booleans = @('foregroundPreserved')
                    Numbers = @('startupElapsedMilliseconds')
                    Objects = @('window')
                }
            }
            default { throw "The $Contract lifecycle JSON discriminator is unsupported" }
        }

        Assert-PSOBBStrictJsonExactProperties `
            -Element $rootElement -Expected $definition.Properties -Label $variant | Out-Null
        foreach ($propertyName in $definition.Strings) {
            if ($rootElement.GetProperty($propertyName).ValueKind -ne
                [System.Text.Json.JsonValueKind]::String) {
                throw "The $variant lifecycle JSON property '$propertyName' is not a string"
            }
        }
        foreach ($propertyName in $definition.Integers) {
            $propertyValue = $rootElement.GetProperty($propertyName)
            [long]$integer = 0
            if ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or
                -not $propertyValue.TryGetInt64([ref]$integer)) {
                throw "The $variant lifecycle JSON property '$propertyName' is not an Int64"
            }
        }
        foreach ($propertyName in $definition.NullableStrings) {
            $kind = $rootElement.GetProperty($propertyName).ValueKind
            if ($kind -notin @(
                    [System.Text.Json.JsonValueKind]::Null,
                    [System.Text.Json.JsonValueKind]::String)) {
                throw "The $variant lifecycle JSON property '$propertyName' is not nullable text"
            }
        }
        foreach ($propertyName in $definition.Booleans) {
            if ($rootElement.GetProperty($propertyName).ValueKind -notin @(
                    [System.Text.Json.JsonValueKind]::True,
                    [System.Text.Json.JsonValueKind]::False)) {
                throw "The $variant lifecycle JSON property '$propertyName' is not Boolean"
            }
        }
        $numberProperties = if ($definition.ContainsKey('Numbers')) {
            @($definition.Numbers)
        } else { @() }
        foreach ($propertyName in $numberProperties) {
            if ($rootElement.GetProperty($propertyName).ValueKind -ne
                [System.Text.Json.JsonValueKind]::Number) {
                throw "The $variant lifecycle JSON property '$propertyName' is not numeric"
            }
        }
        $objectProperties = if ($definition.ContainsKey('Objects')) {
            @($definition.Objects)
        } else { @() }
        foreach ($propertyName in $objectProperties) {
            if ($rootElement.GetProperty($propertyName).ValueKind -ne
                [System.Text.Json.JsonValueKind]::Object) {
                throw "The $variant lifecycle JSON property '$propertyName' is not an object"
            }
        }
        if ($variant -ceq 'ClientStartupReceipt') {
            $window = $rootElement.GetProperty('window')
            Assert-PSOBBStrictJsonExactProperties `
                -Element $window `
                -Expected @('x', 'y', 'width', 'height', 'clientWidth', 'clientHeight') `
                -Label 'ClientStartupReceipt.window' | Out-Null
            foreach ($property in $window.EnumerateObject()) {
                [long]$integer = 0
                if ($property.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and
                    ($property.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or
                        -not $property.Value.TryGetInt64([ref]$integer))) {
                    throw "The ClientStartupReceipt.window '$($property.Name)' property is not a nullable integer"
                }
            }
        }
        if ($rootElement.GetProperty('schemaVersion').GetInt64() -ne 3) {
            throw "The $variant lifecycle JSON schema version is unsupported"
        }
        ConvertFrom-PSOBBStrictJsonElement -Element $rootElement
    } finally {
        if ($document) { $document.Dispose() }
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
}

function Assert-PSOBBStrictDataObjectProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw "The $Label JSON value is not an object"
    }
    $actual = @($Value.PSObject.Properties.Name)
    $actualSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($name in $actual) { [void]$actualSet.Add($name) }
    $expectedSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($name in $Expected) { [void]$expectedSet.Add($name) }
    if ($actual.Count -ne $Expected.Count -or
        -not $actualSet.SetEquals($expectedSet)) {
        throw "The $Label JSON object does not have its exact property set"
    }
    $true
}

function ConvertFrom-PSOBBStrictDataJsonElement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Text.Json.JsonElement]$Element,
        [string]$Label = 'trusted data'
    )

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $objectValue = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) {
                $objectValue[$property.Name] = ConvertFrom-PSOBBStrictDataJsonElement `
                    -Element $property.Value -Label $Label
            }
            return [pscustomobject]$objectValue
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $arrayValue = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) {
                $arrayValue.Add((ConvertFrom-PSOBBStrictDataJsonElement `
                            -Element $item -Label $Label))
            }
            return ,$arrayValue.ToArray()
        }
        ([System.Text.Json.JsonValueKind]::String) {
            return $Element.GetString()
        }
        ([System.Text.Json.JsonValueKind]::Number) {
            [long]$integerValue = 0
            if (-not $Element.TryGetInt64([ref]$integerValue)) {
                throw "The $Label JSON contains a fractional or out-of-range number"
            }
            return $integerValue
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        default { throw "The $Label JSON contains an unsupported value kind" }
    }
}

function Assert-PSOBBOrdinaryContainedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateSet('File', 'Directory')]
        [string]$Kind,
        [string]$Label = 'trusted path'
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PathWithinRoot -Path $Path -Root $safeRoot
    $relative = [System.IO.Path]::GetRelativePath($safeRoot, $safePath)
    if ($relative -eq '..' -or $relative.StartsWith(
            '..\', [System.StringComparison]::Ordinal)) {
        throw "The $Label is outside its approved root"
    }

    $current = $safeRoot
    $segments = if ($relative -eq '.') { @() } else { @($relative.Split('\')) }
    $paths = @($safeRoot)
    foreach ($segment in $segments) {
        $current = Join-Path $current $segment
        $paths += $current
    }
    for ($index = 0; $index -lt $paths.Count; $index++) {
        $item = Get-Item -Force -LiteralPath $paths[$index] -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The $Label has a reparse point in its contained path"
        }
        $isFinal = $index -eq ($paths.Count - 1)
        if (-not $isFinal -and -not $item.PSIsContainer) {
            throw "The $Label has a non-directory path ancestor"
        }
        if ($isFinal -and
            (($Kind -ceq 'File' -and $item.PSIsContainer) -or
                ($Kind -ceq 'Directory' -and -not $item.PSIsContainer))) {
            throw "The $Label has an unexpected filesystem type"
        }
    }
    $safePath
}

function Read-PSOBBBoundedOrdinaryFileSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(1, 1073741824)]
        [long]$MaximumBytes,
        [string]$Label = 'trusted file',
        [switch]$AllowEmpty,
        [switch]$IncludeBytes
    )

    $safePath = Assert-PSOBBOrdinaryContainedPath `
        -Path $Path -Root $Root -Kind File -Label $Label
    $stream = [System.IO.FileStream]::new(
        $safePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read,
        65536,
        [System.IO.FileOptions]::SequentialScan)
    $bytes = $null
    try {
        if ((-not $AllowEmpty -and $stream.Length -le 0) -or
            $stream.Length -lt 0 -or $stream.Length -gt $MaximumBytes -or
            $stream.Length -gt [int]::MaxValue) {
            throw "The $Label has an invalid bounded size"
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "The $Label changed or ended while its locked bytes were read"
            }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) {
            throw "The $Label grew while its locked bytes were read"
        }
        $digest = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        [pscustomobject]@{
            Path = $safePath
            Length = [long]$bytes.Length
            Sha256 = $digest
            Bytes = if ($IncludeBytes) { $bytes } else { $null }
        }
        if (-not $IncludeBytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
            $bytes = $null
        }
    } finally {
        $stream.Dispose()
        if ($bytes -and -not $IncludeBytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
}

function Read-PSOBBStrictJsonSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(1, 67108864)]
        [long]$MaximumBytes,
        [ValidateRange(1, 64)][int]$MaximumDepth = 32,
        [string]$Label = 'trusted data'
    )

    $fileSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Path -Root $Root -MaximumBytes $MaximumBytes `
        -Label $Label -IncludeBytes
    $document = $null
    try {
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $jsonText = $utf8.GetString([byte[]]$fileSnapshot.Bytes)
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = $MaximumDepth
        $document = [System.Text.Json.JsonDocument]::Parse($jsonText, $options)
        Test-PSOBBStrictJsonPropertyUniqueness `
            -Element $document.RootElement -Path '$' | Out-Null
        $value = ConvertFrom-PSOBBStrictDataJsonElement `
            -Element $document.RootElement -Label $Label
        [pscustomobject]@{
            Value = $value
            Sha256 = [string]$fileSnapshot.Sha256
            Length = [long]$fileSnapshot.Length
            Path = [string]$fileSnapshot.Path
        }
    } catch {
        throw "The $Label is not valid strict bounded UTF-8 JSON: $($_.Exception.Message)"
    } finally {
        if ($document) { $document.Dispose() }
        if ($fileSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$fileSnapshot.Bytes, 0, ([byte[]]$fileSnapshot.Bytes).Length)
        }
    }
}

function Assert-PSOBBStrictStringArray {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value -isnot [System.Array]) {
        throw "The $Label JSON value is not an array"
    }
    foreach ($entry in $Value) {
        if ($entry -isnot [string]) {
            throw "The $Label JSON array contains a non-string value"
        }
    }
    @($Value)
}

function Read-PSOBBClientPatchPolicySnapshot {
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json')
    )

    $snapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $Path -Root $script:PSOBBRepositoryRoot -MaximumBytes 1MB `
        -MaximumDepth 12 -Label 'client-patch policy'
    $policyValue = $snapshot.Value
    Assert-PSOBBStrictDataObjectProperties -Value $policyValue -Expected @(
        'schemaVersion', 'defaultProfile', 'profiles', 'gated') `
        -Label 'client-patch policy root' | Out-Null
    if ($policyValue.schemaVersion -isnot [long] -or
        $policyValue.schemaVersion -ne 1 -or
        $policyValue.defaultProfile -isnot [string] -or
        $policyValue.profiles -isnot [System.Array]) {
        throw 'Client-patch policy header types are invalid'
    }
    foreach ($profileValue in $policyValue.profiles) {
        Assert-PSOBBStrictDataObjectProperties -Value $profileValue -Expected @(
            'id', 'channel', 'description', 'autoPatches', 'bbRequiredPatches') `
            -Label 'client-patch policy profile' | Out-Null
        foreach ($propertyName in @('id', 'channel', 'description')) {
            if ($profileValue.$propertyName -isnot [string]) {
                throw "Client-patch policy profile '$propertyName' has an invalid type"
            }
        }
        [void](Assert-PSOBBStrictStringArray `
                -Value $profileValue.autoPatches `
                -Label 'client-patch profile autoPatches')
        [void](Assert-PSOBBStrictStringArray `
                -Value $profileValue.bbRequiredPatches `
                -Label 'client-patch profile bbRequiredPatches')
    }
    Assert-PSOBBStrictDataObjectProperties -Value $policyValue.gated -Expected @(
        'sourceCanaryOnly', 'protocolRequired', 'migrationRequired') `
        -Label 'client-patch policy gated' | Out-Null
    foreach ($gateName in @('sourceCanaryOnly', 'protocolRequired', 'migrationRequired')) {
        [void](Assert-PSOBBStrictStringArray `
                -Value $policyValue.gated.$gateName `
                -Label "client-patch policy gated.$gateName")
    }
    $snapshot
}

function Read-PSOBBInstallationRecordSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [string]$ExpectedInstallationId,
        [string]$ExpectedRuntimeRoot
    )

    $snapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $Path -Root $Root -MaximumBytes 256KB -MaximumDepth 8 `
        -Label 'Stable installation record'
    $recordValue = $snapshot.Value
    $properties = @(
        'schemaVersion', 'installationId', 'initializedAtUtc', 'runtimeRoot',
        'serverVersion', 'serverArchiveSha256', 'serverExecutableSha256',
        'serverBaseManifestSha256', 'clientVersion', 'clientArchiveSha256',
        'baseClientExecutableSha256', 'baseClientManifestSha256',
        'clientExecutableSha256', 'rendererVersion', 'rendererArchiveSha256',
        'rendererWrapperSha256', 'rendererConfigurationSha256',
        'patchManifestSha256', 'synchronizedPatchFiles', 'clientPatchProfile',
        'clientPatchPolicySha256', 'networkScope')
    Assert-PSOBBStrictDataObjectProperties `
        -Value $recordValue -Expected $properties -Label 'Stable installation record' |
        Out-Null
    foreach ($propertyName in @($properties | Where-Object {
                $_ -notin @('schemaVersion', 'synchronizedPatchFiles')
            })) {
        if ($recordValue.$propertyName -isnot [string]) {
            throw "Stable installation record property '$propertyName' is not text"
        }
    }
    if ($recordValue.schemaVersion -isnot [long] -or
        $recordValue.schemaVersion -ne 2 -or
        $recordValue.synchronizedPatchFiles -isnot [long] -or
        $recordValue.synchronizedPatchFiles -lt 0) {
        throw 'Stable installation record integer fields are invalid'
    }
    foreach ($hashName in @(
            'serverArchiveSha256', 'serverExecutableSha256',
            'serverBaseManifestSha256', 'clientArchiveSha256',
            'baseClientExecutableSha256', 'baseClientManifestSha256',
            'clientExecutableSha256', 'rendererArchiveSha256',
            'rendererWrapperSha256', 'rendererConfigurationSha256',
            'patchManifestSha256', 'clientPatchPolicySha256')) {
        if ([string]$recordValue.$hashName -cnotmatch '^[a-f0-9]{64}$') {
            throw "Stable installation record property '$hashName' is not a lowercase SHA-256"
        }
    }
    $parsedInstallationId = [Guid]::Empty
    $parsedInitializedAt = [DateTimeOffset]::MinValue
    if (-not [Guid]::TryParseExact(
            [string]$recordValue.installationId, 'D', [ref]$parsedInstallationId) -or
        -not [DateTimeOffset]::TryParse(
            [string]$recordValue.initializedAtUtc, [ref]$parsedInitializedAt) -or
        [string]$recordValue.clientPatchProfile -cnotmatch
            '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
        [string]$recordValue.networkScope -cne 'loopback-only') {
        throw 'Stable installation record identity or fixed fields are invalid'
    }
    if ($ExpectedInstallationId -and
        [string]$recordValue.installationId -cne $ExpectedInstallationId) {
        throw 'Stable installation record belongs to another installation'
    }
    if ($ExpectedRuntimeRoot) {
        $recordedRoot = [System.IO.Path]::GetFullPath(
            [string]$recordValue.runtimeRoot).TrimEnd('\')
        $expectedRoot = [System.IO.Path]::GetFullPath(
            $ExpectedRuntimeRoot).TrimEnd('\')
        if (-not $recordedRoot.Equals(
                $expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Stable installation record belongs to another runtime root'
        }
    }
    $snapshot
}

function Get-PSOBBStableServerSourceLockIdentity {
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json')
    )

    $snapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $Path -Root $script:PSOBBRepositoryRoot -MaximumBytes 8MB `
        -MaximumDepth 24 -Label 'source lock'
    $sourceLockValue = $snapshot.Value
    Assert-PSOBBStrictDataObjectProperties -Value $sourceLockValue -Expected @(
        'schemaVersion', 'generatedAtUtc', 'components', 'behaviorReferences') `
        -Label 'source lock root' | Out-Null
    if ($sourceLockValue.schemaVersion -isnot [long] -or
        $sourceLockValue.schemaVersion -ne 1 -or
        $sourceLockValue.generatedAtUtc -isnot [string] -or
        $sourceLockValue.components -isnot [System.Array] -or
        $sourceLockValue.behaviorReferences -isnot [System.Array]) {
        throw 'Source lock root field types are invalid'
    }
    $stableComponents = @($sourceLockValue.components | Where-Object {
            $_ -is [pscustomobject] -and $_.PSObject.Properties['id'] -and
            $_.id -is [string] -and $_.id -ceq 'newserv-stable-release'
        })
    if ($stableComponents.Count -ne 1) {
        throw 'Source lock must contain exactly one Stable release component'
    }
    $componentValue = $stableComponents[0]
    Assert-PSOBBStrictDataObjectProperties -Value $componentValue -Expected @(
        'id', 'role', 'sourceUrl', 'releaseUrl', 'version', 'commit',
        'retrievedAtUtc', 'size', 'sha256', 'signatureState', 'license',
        'redistribution', 'compatibility', 'rollbackTarget', 'members') `
        -Label 'Stable release source-lock component' | Out-Null
    foreach ($propertyName in @(
            'id', 'role', 'sourceUrl', 'releaseUrl', 'version', 'commit',
            'retrievedAtUtc', 'sha256', 'signatureState', 'license',
            'redistribution', 'compatibility', 'rollbackTarget')) {
        if ($componentValue.$propertyName -isnot [string]) {
            throw "Stable release source-lock property '$propertyName' is not text"
        }
    }
    if ($componentValue.size -isnot [long] -or $componentValue.size -le 0 -or
        $componentValue.members -isnot [System.Array] -or
        [string]$componentValue.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Stable release source-lock size, hash, or members are invalid'
    }
    foreach ($memberValue in $componentValue.members) {
        Assert-PSOBBStrictDataObjectProperties -Value $memberValue -Expected @(
            'path', 'size', 'sha256', 'authenticode') `
            -Label 'Stable release source-lock member' | Out-Null
        if ($memberValue.path -isnot [string] -or
            $memberValue.size -isnot [long] -or $memberValue.size -le 0 -or
            $memberValue.sha256 -isnot [string] -or
            [string]$memberValue.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $memberValue.authenticode -isnot [string]) {
            throw 'Stable release source-lock member field types are invalid'
        }
    }
    $serverMembers = @($componentValue.members | Where-Object {
            $_.path -ceq 'release/newserv-windows.exe'
        })
    if ($serverMembers.Count -ne 1) {
        throw 'Source lock has no unique approved Stable server executable member'
    }
    [pscustomobject]@{
        ComponentId = [string]$componentValue.id
        Size = [long]$serverMembers[0].size
        Sha256 = [string]$serverMembers[0].sha256
        Authenticode = [string]$serverMembers[0].authenticode
        Component = $componentValue
        SourceLock = $sourceLockValue
        SourceLockSha256 = [string]$snapshot.Sha256
    }
}

function Read-PSOBBRecoveryManifestSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $snapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $Path -Root $Root -MaximumBytes 16MB -MaximumDepth 16 `
        -Label 'recovery manifest'
    $manifestValue = $snapshot.Value
    Assert-PSOBBStrictDataObjectProperties -Value $manifestValue -Expected @(
        'schemaVersion', 'backupId', 'backupKind', 'createdAtUtc',
        'serverExecutable', 'clientPatchState', 'stateRoots', 'files') `
        -Label 'recovery manifest root' | Out-Null
    if ($manifestValue.schemaVersion -isnot [long] -or
        $manifestValue.backupId -isnot [string] -or
        $manifestValue.backupKind -isnot [string] -or
        $manifestValue.createdAtUtc -isnot [string] -or
        $manifestValue.stateRoots -isnot [System.Array] -or
        $manifestValue.files -isnot [System.Array]) {
        throw 'Recovery manifest root field types are invalid'
    }
    Assert-PSOBBStrictDataObjectProperties `
        -Value $manifestValue.serverExecutable `
        -Expected @('path', 'sourceLockComponent', 'size', 'sha256') `
        -Label 'recovery manifest serverExecutable' | Out-Null
    if ($manifestValue.serverExecutable.path -isnot [string] -or
        $manifestValue.serverExecutable.sourceLockComponent -isnot [string] -or
        $manifestValue.serverExecutable.size -isnot [long] -or
        $manifestValue.serverExecutable.sha256 -isnot [string]) {
        throw 'Recovery manifest serverExecutable field types are invalid'
    }
    Assert-PSOBBStrictDataObjectProperties `
        -Value $manifestValue.clientPatchState -Expected @(
            'profile', 'policySha256', 'configPath', 'configSha256',
            'installationPath', 'installationSha256', 'installationId') `
        -Label 'recovery manifest clientPatchState' | Out-Null
    foreach ($propertyName in @(
            'profile', 'policySha256', 'configPath', 'configSha256',
            'installationPath', 'installationSha256', 'installationId')) {
        if ($manifestValue.clientPatchState.$propertyName -isnot [string]) {
            throw "Recovery manifest clientPatchState '$propertyName' is not text"
        }
    }
    foreach ($stateRootValue in $manifestValue.stateRoots) {
        Assert-PSOBBStrictDataObjectProperties -Value $stateRootValue `
            -Expected @('path', 'kind') -Label 'recovery manifest stateRoots entry' |
            Out-Null
        if ($stateRootValue.path -isnot [string] -or
            $stateRootValue.kind -isnot [string]) {
            throw 'Recovery manifest stateRoots entry field types are invalid'
        }
    }
    foreach ($fileValue in $manifestValue.files) {
        Assert-PSOBBStrictDataObjectProperties -Value $fileValue `
            -Expected @('path', 'size', 'sha256') `
            -Label 'recovery manifest files entry' | Out-Null
        if ($fileValue.path -isnot [string] -or
            $fileValue.size -isnot [long] -or
            $fileValue.sha256 -isnot [string]) {
            throw 'Recovery manifest files entry field types are invalid'
        }
    }
    $snapshot
}

function Get-PSOBBRecordedSupervisorHostState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)

    $expectedHostPath = [System.IO.Path]::GetFullPath(
        (Join-Path $PSHOME 'pwsh.exe'))
    if ([string]$Record.hostPid -cnotmatch '^[1-9][0-9]*$' -or
        [string]$Record.hostStartTimeFileTimeUtc -cnotmatch '^[1-9][0-9]*$' -or
        [string]::IsNullOrWhiteSpace([string]$Record.hostExecutablePath)) {
        return [pscustomobject]@{
            State = 'InvalidRecord'
            Process = $null
            Detail = 'The supervisor host identity fields are incomplete.'
            ExpectedExecutablePath = $expectedHostPath
        }
    }
    try {
        $recordedHostPath = [System.IO.Path]::GetFullPath(
            [string]$Record.hostExecutablePath)
    } catch {
        return [pscustomobject]@{
            State = 'InvalidRecord'
            Process = $null
            Detail = 'The recorded supervisor host executable path is invalid.'
            ExpectedExecutablePath = $expectedHostPath
        }
    }
    if (-not $recordedHostPath.Equals(
            $expectedHostPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{
            State = 'InvalidRecord'
            Process = $null
            Detail = 'The recorded supervisor host executable is not the exact expected pwsh image.'
            ExpectedExecutablePath = $expectedHostPath
        }
    }

    $hostProcess = Get-Process -Id ([int]$Record.hostPid) `
        -ErrorAction SilentlyContinue
    if (-not $hostProcess) {
        return [pscustomobject]@{
            State = 'Absent'
            Process = $null
            Detail = 'The recorded supervisor host PID is absent.'
            ExpectedExecutablePath = $expectedHostPath
        }
    }
    try {
        $actualPath = [System.IO.Path]::GetFullPath($hostProcess.Path)
        $actualStartFileTimeUtc = [long](
            $hostProcess.StartTime.ToUniversalTime().ToFileTimeUtc())
        if (-not $actualPath.Equals(
                $expectedHostPath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            $actualStartFileTimeUtc -ne
                [long]$Record.hostStartTimeFileTimeUtc) {
            $hostProcess.Dispose()
            return [pscustomobject]@{
                State = 'Reused'
                Process = $null
                Detail = 'The recorded supervisor host PID now belongs to a different process identity.'
                ExpectedExecutablePath = $expectedHostPath
            }
        }
        [pscustomobject]@{
            State = 'ExactActive'
            Process = $hostProcess
            Detail = 'The recorded supervisor host PID, image, and creation time match.'
            ExpectedExecutablePath = $expectedHostPath
        }
    } catch {
        $inspectionFailure = $_.Exception.Message
        try {
            $hostProcess.Refresh()
            if ($hostProcess.HasExited) {
                $hostProcess.Dispose()
                return [pscustomobject]@{
                    State = 'Absent'
                    Process = $null
                    Detail = 'The recorded supervisor host exited during identity inspection.'
                    ExpectedExecutablePath = $expectedHostPath
                }
            }
        } catch {
            # Preserve the original inspection failure below.
        }
        $hostProcess.Dispose()
        [pscustomobject]@{
            State = 'Uninspectable'
            Process = $null
            Detail = $inspectionFailure
            ExpectedExecutablePath = $expectedHostPath
        }
    }
}

function Wait-PSOBBRecordedSupervisorHostQuiescence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [ValidateRange(0, 10000)][int]$TimeoutMilliseconds = 5000
    )

    $lifecyclePaths = @(
        $Layout.PidFile,
        $Layout.LegacyPidFile,
        $Layout.HostPidFile,
        $Layout.ControlState,
        $Layout.ControlRequest)
    $presentPaths = @($lifecyclePaths | Where-Object {
            Test-Path -LiteralPath $_
        })
    if ($presentPaths.Count -eq 0) {
        return [pscustomobject]@{
            Quiescent = $true
            InitialState = 'NoLifecycleState'
            HostWasActive = $false
        }
    }
    if (-not (Test-Path -LiteralPath $Layout.PidFile -PathType Leaf)) {
        throw 'Lifecycle state exists without an exact supervisor process record; preserving it instead of racing an unidentified host'
    }

    $safePidFile = Assert-PathWithinRoot `
        -Path $Layout.PidFile -Root $Layout.Root
    try {
        $record = Read-PSOBBStrictLifecycleJson `
            -Path $safePidFile -Root $Layout.Root -Contract ServerProcessRecord
    } catch {
        throw 'The existing supervisor process record cannot prove host quiescence'
    }
    $environmentName = Resolve-PSOBBServerEnvironmentName `
        -Environment ([string]$Layout.Environment)
    $rootLayout = Get-PSOBBLayout -RuntimeRoot ([string]$Layout.Root)
    $approved = Get-PSOBBApprovedNewservExecutableIdentity `
        -Layout $rootLayout -ServerEnvironment $environmentName
    $componentId = [string]$approved.ComponentId
    $marker = Assert-PSOBBRuntimeMarker -Layout $rootLayout
    try {
        $expectedControlIdentity = Get-PSOBBServerControlIdentity `
            -InstallationId ([string]$marker.installationId) `
            -EnvironmentId ([string]$Layout.EnvironmentId) `
            -ComponentId $componentId `
            -StartupRequestId ([string]$record.startupRequestId) `
            -ExecutableSha256 ([string]$record.executableSha256)
    } catch {
        throw 'The existing supervisor process record cannot reconstruct its exact control identity'
    }
    if ([int]$record.schemaVersion -ne 3 -or
        [string]$record.serverEnvironment -cne $environmentName -or
        [string]$record.environmentId -cne [string]$Layout.EnvironmentId -or
        [string]$record.componentId -cne $componentId -or
        [string]$record.executablePath -cne [string]$approved.ExecutablePath -or
        [string]$record.executableSha256 -cne [string]$approved.Sha256 -or
        -not (Test-PSOBBFixedTimeTextEquals `
            -Expected $expectedControlIdentity `
            -Actual ([string]$record.controlIdentity))) {
        throw 'The existing supervisor process record cannot prove an exact environment-bound host identity'
    }

    $hostState = Get-PSOBBRecordedSupervisorHostState -Record $record
    $initialState = [string]$hostState.State
    if ($initialState -in @('InvalidRecord', 'Uninspectable')) {
        throw "The existing supervisor host is $initialState; lifecycle evidence was preserved"
    }
    if ($initialState -eq 'ExactActive') {
        try {
            if (-not $hostState.Process.WaitForExit($TimeoutMilliseconds)) {
                throw 'The exact prior supervisor host is still active; lifecycle evidence was preserved'
            }
        } finally {
            $hostState.Process.Dispose()
        }
        $hostState = Get-PSOBBRecordedSupervisorHostState -Record $record
        if ($hostState.State -eq 'ExactActive') {
            $hostState.Process.Dispose()
            throw 'The exact prior supervisor host remained active after the quiescence wait'
        }
        if ($hostState.State -in @('InvalidRecord', 'Uninspectable')) {
            throw "The prior supervisor host became $($hostState.State) after waiting; lifecycle evidence was preserved"
        }
    }

    [pscustomobject]@{
        Quiescent = $true
        InitialState = $initialState
        HostWasActive = $initialState -eq 'ExactActive'
    }
}

function Get-PSOBBServerLifecycleEvidenceRecords {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $marker = Assert-PSOBBRuntimeMarker -Layout $Layout
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($environmentName in @('Stable', 'CombatCanary')) {
        $environmentLayout = Get-PSOBBServerEnvironmentLayout `
            -Layout $Layout -Environment $environmentName
        $paths = @(
            $environmentLayout.PidFile,
            $environmentLayout.LegacyPidFile,
            $environmentLayout.HostPidFile,
            $environmentLayout.ControlState,
            $environmentLayout.ControlRequest)
        $presentPaths = @($paths | Where-Object {
                Test-Path -LiteralPath $_
            })
        if ($presentPaths.Count -eq 0) {
            continue
        }
        $classification = 'InvalidOrIncomplete'
        $detail = 'Lifecycle files exist without a valid exact process record.'
        try {
            if (-not (Test-Path `
                    -LiteralPath $environmentLayout.PidFile -PathType Leaf)) {
                throw 'The exact process record is missing or not a file.'
            }
            $record = Read-PSOBBStrictLifecycleJson `
                -Path $environmentLayout.PidFile `
                -Root $environmentLayout.Root `
                -Contract ServerProcessRecord
            $approved = Get-PSOBBApprovedNewservExecutableIdentity `
                -Layout $Layout -ServerEnvironment $environmentName
            $expectedControlIdentity = Get-PSOBBServerControlIdentity `
                -InstallationId ([string]$marker.installationId) `
                -EnvironmentId ([string]$environmentLayout.EnvironmentId) `
                -ComponentId ([string]$approved.ComponentId) `
                -StartupRequestId ([string]$record.startupRequestId) `
                -ExecutableSha256 ([string]$record.executableSha256)
            if ([int]$record.schemaVersion -ne 3 -or
                [string]$record.serverEnvironment -cne $environmentName -or
                [string]$record.environmentId -cne
                    [string]$environmentLayout.EnvironmentId -or
                [string]$record.componentId -cne
                    [string]$approved.ComponentId -or
                [string]$record.executablePath -cne
                    [string]$approved.ExecutablePath -or
                [string]$record.executableSha256 -cne
                    [string]$approved.Sha256 -or
                -not (Test-PSOBBFixedTimeTextEquals `
                    -Expected $expectedControlIdentity `
                    -Actual ([string]$record.controlIdentity))) {
                throw 'The process record is not exact and environment-bound.'
            }
            $classification = 'ExactEnvironmentBound'
            $detail = 'The process record exactly identifies this server environment.'
        } catch {
            $detail = $_.Exception.Message
        }
        $records.Add([pscustomobject]@{
            ServerEnvironment = $environmentName
            EnvironmentId = [string]$environmentLayout.EnvironmentId
            Classification = $classification
            PresentPaths = $presentPaths
            Detail = $detail
        })
    }
    @($records)
}

function Remove-PSOBBLifecycleFilesVerified {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    # Preflight every path before deleting anything. The process record is the
    # strongest host/control proof and is deliberately removed last.
    $paths = @(
        $Layout.LegacyPidFile,
        $Layout.HostPidFile,
        $Layout.ControlRequest,
        $Layout.ControlState,
        $Layout.PidFile)
    $normalizedPaths = @($paths | ForEach-Object {
            [System.IO.Path]::GetFullPath([string]$_)
        })
    if (@($normalizedPaths | Sort-Object -Unique).Count -ne $paths.Count) {
        throw 'Lifecycle layout contains duplicate evidence paths'
    }
    $existingPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $paths) {
        $safePath = Assert-PathWithinRoot -Path $path -Root $Layout.Root
        if (-not (Test-Path -LiteralPath $safePath)) {
            continue
        }
        $item = Get-Item -LiteralPath $safePath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Lifecycle path has an unsafe filesystem type: $safePath"
        }
        $existingPaths.Add($safePath)
    }
    $pidPath = [System.IO.Path]::GetFullPath([string]$Layout.PidFile)
    foreach ($preflightPath in $existingPaths) {
        $safePath = Assert-PathWithinRoot `
            -Path $preflightPath -Root $Layout.Root
        $currentItem = Get-Item -LiteralPath $safePath -Force -ErrorAction Stop
        if ($currentItem.PSIsContainer -or
            ($currentItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Lifecycle path changed to an unsafe filesystem type before deletion: $safePath"
        }
        if ($safePath.Equals(
                $pidPath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            $reappearedEvidence = @($paths[0..($paths.Count - 2)] | Where-Object {
                    Test-Path -LiteralPath $_
                })
            if ($reappearedEvidence.Count -gt 0) {
                throw "Lifecycle evidence reappeared before process-record deletion: $($reappearedEvidence -join ', ')"
            }
        }
        Remove-Item -LiteralPath $safePath -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $safePath) {
            throw "Lifecycle file deletion did not reach absence: $safePath"
        }
    }
    $remaining = @($paths | Where-Object {
            Test-Path -LiteralPath $_
        })
    if ($remaining.Count -gt 0) {
        throw "Lifecycle file removal could not be verified: $($remaining -join ', ')"
    }
    $true
}

function Get-PSOBBNamedProcessIdentityCensus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProcessName,
        [AllowEmptyCollection()][Parameter(Mandatory)][object[]]$ApprovedPaths
    )

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($process in @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)) {
        $imagePath = $null
        $classification = 'Uninspectable'
        $matched = $null
        try {
            $native = Get-PSOBBNativeProcessInfo -ProcessId ([int]$process.Id)
            if (-not $native.IsRunning) {
                continue
            }
            $imagePath = [System.IO.Path]::GetFullPath([string]$native.ImagePath)
            $matched = @($ApprovedPaths | Where-Object {
                    $imagePath.Equals(
                        [System.IO.Path]::GetFullPath([string]$_.ExecutablePath),
                        [System.StringComparison]::OrdinalIgnoreCase)
                })
            if ($matched.Count -eq 1) {
                $matched = $matched[0]
                $classification = 'ApprovedExactPath'
            } elseif ($matched.Count -gt 1) {
                $matched = $null
                $classification = 'AmbiguousApprovedPath'
            } else {
                $matched = $null
                $classification = 'UnexpectedPath'
            }
        } catch {
            if (-not (Get-Process -Id ([int]$process.Id) -ErrorAction SilentlyContinue)) {
                continue
            }
        }
        $records.Add([pscustomobject]@{
            Process = $process
            ProcessId = [int]$process.Id
            ExecutablePath = $imagePath
            Classification = $classification
            ApprovedIdentity = $matched
        })
    }
    @($records)
}

function Get-PSOBBServerEnvironmentProcessRecords {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $approvedPaths = [System.Collections.Generic.List[object]]::new()
    foreach ($environmentName in @('Stable', 'CombatCanary')) {
        $environmentLayout = Get-PSOBBServerEnvironmentLayout `
            -Layout $Layout -Environment $environmentName
        $approved = Get-PSOBBApprovedNewservExecutableIdentity `
            -Layout $Layout -ServerEnvironment $environmentName
        $approvedPaths.Add([pscustomobject]@{
            ServerEnvironment = $environmentLayout.Environment
            EnvironmentId = $environmentLayout.EnvironmentId
            ComponentId = [string]$approved.ComponentId
            ExecutablePath = Join-Path $environmentLayout.Server 'newserv-windows.exe'
        })
    }
    @(Get-PSOBBNamedProcessIdentityCensus `
        -ProcessName 'newserv-windows' `
        -ApprovedPaths @($approvedPaths) | ForEach-Object {
        $identity = $_.ApprovedIdentity
        $classification = [string]$_.Classification
        if ($identity -and $classification -ceq 'ApprovedExactPath') {
            try {
                $approved = Get-PSOBBApprovedNewservExecutableIdentity `
                    -Layout $Layout `
                    -ServerEnvironment ([string]$identity.ServerEnvironment)
                if (-not (Test-Path -LiteralPath $approved.ExecutablePath -PathType Leaf) -or
                    (Get-Item -LiteralPath $approved.ExecutablePath).Length -ne
                        $approved.Size -or
                    (Get-LowerSha256 $approved.ExecutablePath) -cne $approved.Sha256) {
                    $classification = 'UnapprovedExecutableIdentity'
                }
            } catch {
                $classification = 'UnapprovedExecutableIdentity'
            }
        }
        $startTimeUtc = $null
        $startTimeFileTimeUtc = $null
        try {
            $startTimeUtc = $_.Process.StartTime.ToUniversalTime()
            $startTimeFileTimeUtc = [long]$startTimeUtc.ToFileTimeUtc()
        } catch {
            $classification = 'Uninspectable'
        }
        [pscustomobject]@{
            ServerEnvironment = if ($identity) {
                [string]$identity.ServerEnvironment
            } else { 'Unknown' }
            EnvironmentId = if ($identity) {
                [string]$identity.EnvironmentId
            } else { $null }
            ComponentId = if ($identity) {
                [string]$identity.ComponentId
            } else { $null }
            Process = $_.Process
            ProcessId = [int]$_.ProcessId
            StartTimeUtc = $startTimeUtc
            StartTimeFileTimeUtc = $startTimeFileTimeUtc
            ExecutablePath = $_.ExecutablePath
            Classification = $classification
        }
    })
}

function Get-PSOBBReservedServerPortListeners {
    [CmdletBinding()]
    param()

    $reservedPorts = @(11000, 12000, 12001)
    @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
            [int]$_.LocalPort -in $reservedPorts
        } | Sort-Object LocalPort, LocalAddress, OwningProcess)
}

function Assert-PSOBBExclusiveServerStartBoundary {
    [CmdletBinding()]
    param(
        [string]$ServerEnvironment = 'Stable',
        [AllowEmptyCollection()][Parameter(Mandatory)][object[]]$ServerProcesses,
        [AllowEmptyCollection()][Parameter(Mandatory)][object[]]$ReservedPortListeners
    )

    $target = Resolve-PSOBBServerEnvironmentName -Environment $ServerEnvironment
    if ($ServerProcesses.Count -gt 0) {
        $identities = @($ServerProcesses | ForEach-Object {
                '{0} PID {1} ({2})' -f $_.ServerEnvironment, $_.ProcessId,
                    $_.Classification
            })
        throw "Cannot start $target while a named newserv process exists ($($identities -join ', '))"
    }
    if ($ReservedPortListeners.Count -gt 0) {
        $identities = @($ReservedPortListeners | ForEach-Object {
                '{0}:{1} PID {2}' -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess
            })
        throw "Cannot start $target because a reserved PSOBB listener is already active ($($identities -join ', '))"
    }
    $true
}

function Test-PSOBBExactLoopbackServerListeners {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$ProcessId,
        [object[]]$ListenerRecords
    )

    if ($null -eq $ListenerRecords) {
        $ListenerRecords = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    }
    $reservedPorts = @(11000, 12000, 12001)
    $reserved = @($ListenerRecords | Where-Object {
            [int]$_.LocalPort -in $reservedPorts
        })
    $owned = @($ListenerRecords | Where-Object {
            [int]$_.OwningProcess -eq $ProcessId
        })
    $actual = @($owned | ForEach-Object {
            '{0}:{1}' -f $_.LocalAddress, $_.LocalPort
        } | Sort-Object -Unique)
    $expected = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
    $actual.Count -eq $expected.Count -and
        -not (Compare-Object -ReferenceObject $expected -DifferenceObject $actual) -and
        $reserved.Count -eq $expected.Count -and
        @($reserved | Where-Object {
                [int]$_.OwningProcess -ne $ProcessId -or
                [string]$_.LocalAddress -cne '127.0.0.1'
            }).Count -eq 0
}

function Test-PSOBBServerListenerSubsetForStop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$ProcessId,
        [AllowEmptyCollection()][Parameter(Mandatory)][object[]]$ReservedPortListeners
    )

    $expectedPorts = @(11000, 12000, 12001)
    $seenPorts = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($listener in $ReservedPortListeners) {
        if ([int]$listener.OwningProcess -ne $ProcessId -or
            [string]$listener.LocalAddress -cne '127.0.0.1' -or
            [int]$listener.LocalPort -notin $expectedPorts -or
            -not $seenPorts.Add([int]$listener.LocalPort)) {
            return $false
        }
    }
    $true
}

function New-PSOBBProtectedSecurityDescriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][bool]$IsContainer)

    $security = if ($IsContainer) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($sid in @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    $security
}

function Set-PSOBBProtectedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -Force -LiteralPath $Path
    # Do not reuse a whole descriptor returned by Get-Acl here. On an audited
    # parent, Set-Acl can attempt to persist its SACL section after applying the
    # DACL, which requires SeSecurityPrivilege. A fresh descriptor contains only
    # the access rules this operation owns. FileSystemAclExtensions then persists
    # only its modified DACL section and leaves owner, group, and SACL untouched.
    $security = New-PSOBBProtectedSecurityDescriptor -IsContainer $item.PSIsContainer
    if ($item.PSIsContainer) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo]$item, [System.Security.AccessControl.DirectorySecurity]$security)
    } else {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo]$item, [System.Security.AccessControl.FileSecurity]$security)
    }
}

function Test-PSOBBProtectedAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $item = Get-Item -Force -LiteralPath $Path
    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$allowed.Add(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    [void]$allowed.Add('S-1-5-32-544')
    [void]$allowed.Add('S-1-5-18')
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        return $false
    }
    $rules = @($acl.GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $allowed.Count) {
        return $false
    }
    $expectedInheritance = if ($item.PSIsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $found = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $rules) {
        if (($rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow) -or
            -not $allowed.Contains($rule.IdentityReference.Value) -or
            $rule.IsInherited -or
            ($rule.FileSystemRights -ne
                [System.Security.AccessControl.FileSystemRights]::FullControl) -or
            ($rule.InheritanceFlags -ne $expectedInheritance) -or
            ($rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None)) {
            return $false
        }
        [void]$found.Add($rule.IdentityReference.Value)
    }
    $found.SetEquals($allowed)
}

function Set-PSOBBProtectedTreeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $safeRoot = Assert-PathWithinRoot -Path $Path -Root $Root
    if (-not (Test-Path -LiteralPath $safeRoot -PathType Container)) {
        throw "Protected runtime tree is missing: $safeRoot"
    }

    # Enumerate one proven directory at a time. A recursive provider walk could
    # enter a substituted junction before the caller has validated that child.
    $paths = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($safeRoot)
    while ($pending.Count -gt 0) {
        $directory = Assert-PathWithinRoot -Path $pending.Dequeue() -Root $Root
        $directoryItem = Get-Item -Force -LiteralPath $directory
        if (-not $directoryItem.PSIsContainer -or
            ($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Protected runtime tree contains an unsafe directory: $directory"
        }
        if ($seen.Add($directoryItem.FullName)) {
            $paths.Add($directoryItem.FullName)
        }

        foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory |
                Sort-Object -Property FullName)) {
            $safeChild = Assert-PathWithinRoot -Path $child.FullName -Root $Root
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Protected runtime tree contains a reparse point: $safeChild"
            }
            if ($child.PSIsContainer) {
                $pending.Enqueue($safeChild)
            } elseif ($seen.Add($safeChild)) {
                $paths.Add($safeChild)
            }
        }
    }

    # Protect children before parents so subsequent parent propagation cannot
    # replace a child's explicit DACL with inherited rules.
    foreach ($itemPath in @($paths | Sort-Object -Property @{
                Expression = { $_.Length }
                Descending = $true
            }, @{
                Expression = { $_ }
                Descending = $false
            })) {
        $safeItem = Assert-PathWithinRoot -Path $itemPath -Root $Root
        $currentItem = Get-Item -Force -LiteralPath $safeItem
        if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Protected runtime tree changed to a reparse point: $safeItem"
        }
        Set-PSOBBProtectedAcl -Path $safeItem
    }
}

function Get-PSOBBOrdinaryTreeSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [string]$Label = 'recovery tree',
        [switch]$RequireProtectedAcl,
        [ValidateRange(1, 2147483647)][int]$MaximumEntries = 2147483647,
        [long]$MaximumBytes = [long]::MaxValue
    )

    if ($MaximumBytes -lt 1) {
        throw "The $Label has an invalid aggregate byte bound"
    }

    $safeTreeRoot = Assert-PSOBBOrdinaryContainedPath `
        -Path $Path -Root $Root -Kind Directory -Label $Label
    $items = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $entryCount = 0
    [long]$aggregateBytes = 0
    $pending.Enqueue($safeTreeRoot)
    while ($pending.Count -gt 0) {
        $directoryPath = Assert-PathWithinRoot `
            -Path $pending.Dequeue() -Root $safeTreeRoot
        $directoryItem = Get-Item -Force -LiteralPath $directoryPath `
            -ErrorAction Stop
        if (-not $directoryItem.PSIsContainer -or
            ($directoryItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($RequireProtectedAcl -and
                -not (Test-PSOBBProtectedAcl -Path $directoryPath))) {
            throw "The $Label contains an unsafe or incorrectly protected directory"
        }
        if (-not $seen.Add($directoryItem.FullName)) {
            throw "The $Label contains a repeated directory identity"
        }
        $items.Add([pscustomobject]@{
                Path = $directoryItem.FullName
                IsDirectory = $true
            })
        foreach ($child in @(Get-ChildItem -Force -LiteralPath $directoryPath |
                Sort-Object -Property FullName)) {
            $entryCount++
            if ($entryCount -gt $MaximumEntries) {
                throw "The $Label exceeds its entry-count bound"
            }
            $safeChild = Assert-PathWithinRoot `
                -Path $child.FullName -Root $safeTreeRoot
            if (($child.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($RequireProtectedAcl -and
                    -not (Test-PSOBBProtectedAcl -Path $safeChild))) {
                throw "The $Label contains an unsafe or incorrectly protected item"
            }
            if ($child.PSIsContainer) {
                $pending.Enqueue($safeChild)
            } else {
                if ($child.Length -lt 0 -or
                    [long]::MaxValue - $aggregateBytes -lt [long]$child.Length) {
                    throw "The $Label aggregate byte count overflowed"
                }
                $aggregateBytes += [long]$child.Length
                if ($aggregateBytes -gt $MaximumBytes) {
                    throw "The $Label exceeds its aggregate byte bound"
                }
                if (-not $seen.Add($child.FullName)) {
                    throw "The $Label contains a repeated file identity"
                }
                $items.Add([pscustomobject]@{
                        Path = $child.FullName
                        IsDirectory = $false
                    })
            }
        }
    }
    [pscustomobject]@{
        Root = $safeTreeRoot
        Items = @($items)
    }
}

function Remove-PSOBBValidatedRecoveryTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [string]$Label = 'recovery tree',
        [switch]$RequireProtectedAcl
    )

    $tree = Get-PSOBBOrdinaryTreeSnapshot `
        -Path $Path -Root $Root -Label $Label `
        -RequireProtectedAcl:$RequireProtectedAcl
    $files = @($tree.Items | Where-Object { -not $_.IsDirectory } |
        Sort-Object { $_.Path.Length } -Descending)
    foreach ($file in $files) {
        $safeFile = Assert-PathWithinRoot -Path $file.Path -Root $tree.Root
        $current = Get-Item -Force -LiteralPath $safeFile -ErrorAction Stop
        if ($current.PSIsContainer -or
            ($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($RequireProtectedAcl -and
                -not (Test-PSOBBProtectedAcl -Path $safeFile))) {
            throw "The $Label changed before constrained file removal"
        }
        Remove-Item -LiteralPath $safeFile -Force -ErrorAction Stop
    }
    $directories = @($tree.Items | Where-Object IsDirectory |
        Sort-Object { $_.Path.Length } -Descending)
    foreach ($directory in $directories) {
        $safeDirectory = Assert-PathWithinRoot `
            -Path $directory.Path -Root $tree.Root
        $current = Get-Item -Force -LiteralPath $safeDirectory -ErrorAction Stop
        if (-not $current.PSIsContainer -or
            ($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($RequireProtectedAcl -and
                -not (Test-PSOBBProtectedAcl -Path $safeDirectory)) -or
            @(Get-ChildItem -Force -LiteralPath $safeDirectory).Count -ne 0) {
            throw "The $Label changed before constrained directory removal"
        }
        Remove-Item -LiteralPath $safeDirectory -Force -ErrorAction Stop
    }
}

function Write-PSOBBDurableFileBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes,
        [switch]$Overwrite,
        [string]$Label = 'transaction file'
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $parent = Split-Path -Parent $safePath
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $parent -Root $Root -Kind Directory -Label "$Label parent")
    $mode = if ($Overwrite) {
        [System.IO.FileMode]::Create
    } else {
        [System.IO.FileMode]::CreateNew
    }
    $stream = [System.IO.FileStream]::new(
        $safePath,
        $mode,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        65536,
        [System.IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    $safePath
}

function Copy-PSOBBVerifiedOrdinaryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][ValidateRange(0, 1073741824)]
        [long]$ExpectedLength,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [string]$Label = 'recovery item'
    )

    $maximumBytes = [Math]::Max(1L, $ExpectedLength)
    $sourceSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
        -Path $Source -Root $SourceRoot -MaximumBytes $maximumBytes `
        -Label $Label -AllowEmpty -IncludeBytes
    try {
        if ($sourceSnapshot.Length -ne $ExpectedLength -or
            $sourceSnapshot.Sha256 -cne $ExpectedSha256) {
            throw "The $Label does not match its sealed length and digest"
        }
        $safeDestination = Write-PSOBBDurableFileBytes `
            -Path $Destination -Root $DestinationRoot `
            -Bytes ([byte[]]$sourceSnapshot.Bytes) -Label $Label
        $destinationSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
            -Path $safeDestination -Root $DestinationRoot `
            -MaximumBytes $maximumBytes -Label $Label -AllowEmpty
        if ($destinationSnapshot.Length -ne $ExpectedLength -or
            $destinationSnapshot.Sha256 -cne $ExpectedSha256) {
            throw "The $Label destination failed exact readback"
        }
        $safeDestination
    } finally {
        if ($sourceSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$sourceSnapshot.Bytes, 0,
                ([byte[]]$sourceSnapshot.Bytes).Length)
        }
    }
}

function Get-PSOBBRedactedRecoveryTreeSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [string]$Label = 'recovery tree',
        [switch]$RequireProtectedAcl
    )

    try {
        Get-PSOBBOrdinaryTreeSnapshot `
            -Path $Path -Root $Root -Label $Label `
            -RequireProtectedAcl:$RequireProtectedAcl
    } catch {
        throw "The $Label failed contained-tree safety validation"
    }
}

function Set-PSOBBRedactedRecoveryTreeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [string]$Label = 'recovery tree'
    )

    try {
        Set-PSOBBProtectedTreeAcl -Path $Path -Root $Root
    } catch {
        throw "The $Label failed protected-tree publication"
    }
}

function Remove-PSOBBRedactedRecoveryTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [string]$Label = 'recovery tree',
        [switch]$RequireProtectedAcl
    )

    try {
        Remove-PSOBBValidatedRecoveryTree `
            -Path $Path -Root $Root -Label $Label `
            -RequireProtectedAcl:$RequireProtectedAcl
    } catch {
        throw "The $Label failed constrained removal"
    }
}

function Read-PSOBBRedactedRecoveryFileSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(1, 1073741824)]
        [long]$MaximumBytes,
        [string]$Label = 'recovery item',
        [switch]$AllowEmpty,
        [switch]$IncludeBytes
    )

    try {
        Read-PSOBBBoundedOrdinaryFileSnapshot `
            -Path $Path -Root $Root -MaximumBytes $MaximumBytes `
            -Label $Label -AllowEmpty:$AllowEmpty -IncludeBytes:$IncludeBytes
    } catch {
        throw "The $Label failed bounded ordinary-file validation"
    }
}

function Read-PSOBBRedactedRecoveryStrictJsonSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(1, 1073741824)]
        [long]$MaximumBytes,
        [ValidateRange(1, 128)][int]$MaximumDepth = 32,
        [string]$Label = 'recovery JSON'
    )

    try {
        Read-PSOBBStrictJsonSnapshot `
            -Path $Path -Root $Root -MaximumBytes $MaximumBytes `
            -MaximumDepth $MaximumDepth -Label $Label
    } catch {
        throw "The $Label failed strict JSON validation"
    }
}

function Test-PSOBBNewservLicenseJsonWhitespaceCharacter {
    [CmdletBinding()]
    param([Parameter(Mandatory)][char]$Character)

    $Character -eq ' ' -or $Character -eq "`t" -or
        $Character -eq "`r" -or $Character -eq "`n"
}

function ConvertTo-PSOBBNewservLicenseStrictJsonText {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][Parameter(Mandatory)][string]$Text,
        [string]$Label = 'licenses item'
    )

    $builder = [System.Text.StringBuilder]::new($Text.Length)
    $insideString = $false
    $escaped = $false
    $stringStart = -1
    $pendingPropertyName = $null
    $requireFormatVersionHex = $false
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($insideString) {
            [void]$builder.Append($character)
            if ($escaped) {
                $escaped = $false
            } elseif ($character -eq '\') {
                $escaped = $true
            } elseif ($character -eq '"') {
                $insideString = $false
                $nextIndex = $index + 1
                while ($nextIndex -lt $Text.Length -and
                    (Test-PSOBBNewservLicenseJsonWhitespaceCharacter `
                            -Character $Text[$nextIndex])) {
                    $nextIndex++
                }
                if ($nextIndex -lt $Text.Length -and
                    $Text[$nextIndex] -eq ':') {
                    $rawPropertyName = $Text.Substring(
                        $stringStart + 1, $index - $stringStart - 1)
                    foreach ($propertyCharacter in $rawPropertyName.ToCharArray()) {
                        if ($propertyCharacter -eq '\' -or
                            [int]$propertyCharacter -lt 0x20 -or
                            [int]$propertyCharacter -gt 0x7E) {
                            throw "The $Label contains a noncanonical property name"
                        }
                    }
                    $pendingPropertyName = $rawPropertyName
                }
            }
            continue
        }

        $isWhitespace = Test-PSOBBNewservLicenseJsonWhitespaceCharacter `
            -Character $character
        $negative = $character -eq '-'
        $prefixIndex = if ($negative) { $index + 1 } else { $index }
        $isHexInteger = ($prefixIndex + 2) -lt $Text.Length -and
            $Text[$prefixIndex] -eq '0' -and
            $Text[$prefixIndex + 1] -ceq 'x' -and
            ((([int]$Text[$prefixIndex + 2]) -ge 0x30 -and
                    ([int]$Text[$prefixIndex + 2]) -le 0x39) -or
                (([int]$Text[$prefixIndex + 2]) -ge 0x41 -and
                    ([int]$Text[$prefixIndex + 2]) -le 0x46))
        if ($requireFormatVersionHex -and -not $isWhitespace -and
            -not $isHexInteger) {
            throw "The $Label FormatVersion is not a saved hexadecimal integer"
        }
        if ($character -eq '"') {
            $insideString = $true
            $stringStart = $index
            [void]$builder.Append($character)
            continue
        }
        if (-not $isHexInteger) {
            if ($character -eq ':' -and $null -ne $pendingPropertyName) {
                $requireFormatVersionHex =
                    $pendingPropertyName -ceq 'FormatVersion'
                $pendingPropertyName = $null
            } elseif (-not $isWhitespace -and $null -ne $pendingPropertyName) {
                $pendingPropertyName = $null
            }
            [void]$builder.Append($character)
            continue
        }
        if ($requireFormatVersionHex) {
            $requireFormatVersionHex = $false
        }

        $previousIndex = $index - 1
        while ($previousIndex -ge 0 -and
            (Test-PSOBBNewservLicenseJsonWhitespaceCharacter `
                    -Character $Text[$previousIndex])) {
            $previousIndex--
        }
        if ($previousIndex -ge 0 -and
            $Text[$previousIndex] -notin @(':', '[', ',')) {
            throw "The $Label contains a non-value hexadecimal token"
        }

        $digitStart = $prefixIndex + 2
        $tokenEnd = $digitStart
        while ($tokenEnd -lt $Text.Length -and
            ((([int]$Text[$tokenEnd]) -ge 0x30 -and
                    ([int]$Text[$tokenEnd]) -le 0x39) -or
                (([int]$Text[$tokenEnd]) -ge 0x41 -and
                    ([int]$Text[$tokenEnd]) -le 0x46))) {
            $tokenEnd++
        }
        $digitCount = $tokenEnd - $digitStart
        if ($digitCount -lt 1 -or $digitCount -gt 16) {
            throw "The $Label contains an out-of-range hexadecimal integer"
        }
        if ($tokenEnd -lt $Text.Length -and
            -not (Test-PSOBBNewservLicenseJsonWhitespaceCharacter `
                    -Character $Text[$tokenEnd]) -and
            $Text[$tokenEnd] -notin @(',', ']', '}')) {
            throw "The $Label contains a malformed hexadecimal integer"
        }

        [uint64]$magnitude = 0
        if (-not [uint64]::TryParse(
                $Text.Substring($digitStart, $digitCount),
                [System.Globalization.NumberStyles]::AllowHexSpecifier,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref]$magnitude) -or
            ((-not $negative) -and
                $magnitude -gt [uint64][long]::MaxValue) -or
            ($negative -and
                $magnitude -gt [uint64]9223372036854775808)) {
            throw "The $Label contains an out-of-range hexadecimal integer"
        }

        $decimal = if ($negative) {
            if ($magnitude -eq [uint64]9223372036854775808) {
                [long]::MinValue.ToString(
                    [System.Globalization.CultureInfo]::InvariantCulture)
            } else {
                (-[long]$magnitude).ToString(
                    [System.Globalization.CultureInfo]::InvariantCulture)
            }
        } else {
            $magnitude.ToString(
                [System.Globalization.CultureInfo]::InvariantCulture)
        }
        [void]$builder.Append($decimal)
        $index = $tokenEnd - 1
    }
    $builder.ToString()
}

function ConvertFrom-PSOBBNewservSavedAsciiJsonStringToken {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][Parameter(Mandatory)][string]$RawToken,
        [string]$Label = 'BBLicense string'
    )

    if ($RawToken.Length -lt 2 -or $RawToken[0] -ne '"' -or
        $RawToken[$RawToken.Length - 1] -ne '"') {
        throw "The $Label is not a JSON string token"
    }
    # Project-provisioned BB usernames and passwords are printable ASCII. The
    # saved account format escapes each non-ASCII byte separately as \u00XX;
    # reject those bytes rather than reinterpret them as Unicode text.
    $bytes = [byte[]]::new(16)
    $byteCount = 0
    try {
        for ($index = 1; $index -lt ($RawToken.Length - 1); $index++) {
            $character = $RawToken[$index]
            [byte]$decodedByte = 0
            if ($character -ne '\') {
                if ([int]$character -lt 0x20 -or [int]$character -gt 0x7E) {
                    throw "The $Label is outside the current ASCII credential contract"
                }
                $decodedByte = [byte][int]$character
            } else {
                $index++
                if ($index -ge ($RawToken.Length - 1)) {
                    throw "The $Label has an incomplete escape"
                }
                $escape = $RawToken[$index]
                $decodedByte = switch -CaseSensitive ($escape) {
                    '"' { [byte]0x22; break }
                    '\' { [byte]0x5C; break }
                    '/' { [byte]0x2F; break }
                    'b' { [byte]0x08; break }
                    'f' { [byte]0x0C; break }
                    'n' { [byte]0x0A; break }
                    'r' { [byte]0x0D; break }
                    't' { [byte]0x09; break }
                    'u' {
                        if (($index + 4) -ge $RawToken.Length) {
                            throw "The $Label has an incomplete Unicode escape"
                        }
                        $digits = $RawToken.Substring($index + 1, 4)
                        if ($digits -cnotmatch '^[0-9A-F]{4}$') {
                            throw "The $Label has a noncanonical Unicode escape"
                        }
                        [uint16]$value = 0
                        if (-not [uint16]::TryParse(
                                $digits,
                                [System.Globalization.NumberStyles]::AllowHexSpecifier,
                                [System.Globalization.CultureInfo]::InvariantCulture,
                                [ref]$value) -or $value -gt 0x7F) {
                            throw "The $Label is outside the current ASCII credential contract"
                        }
                        $index += 4
                        [byte]$value
                        break
                    }
                    default { throw "The $Label has an unsupported escape" }
                }
            }
            if ($decodedByte -lt 0x20 -or $decodedByte -gt 0x7E) {
                throw "The $Label is outside the current printable ASCII credential contract"
            }
            if ($byteCount -ge $bytes.Length) {
                throw "The $Label exceeds the current credential byte limit"
            }
            $bytes[$byteCount] = $decodedByte
            $byteCount++
        }
        [System.Text.Encoding]::ASCII.GetString($bytes, 0, $byteCount)
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Read-PSOBBRedactedRecoveryNewservLicenseJsonSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateRange(1, 67108864)]
        [long]$MaximumBytes,
        [ValidateRange(1, 64)][int]$MaximumDepth = 20,
        [string]$Label = 'licenses item'
    )

    $fileSnapshot = $null
    $document = $null
    try {
        $fileSnapshot = Read-PSOBBBoundedOrdinaryFileSnapshot `
            -Path $Path -Root $Root -MaximumBytes $MaximumBytes `
            -Label $Label -IncludeBytes
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString([byte[]]$fileSnapshot.Bytes)
        $normalized = ConvertTo-PSOBBNewservLicenseStrictJsonText `
            -Text $text -Label $Label
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = $MaximumDepth
        $document = [System.Text.Json.JsonDocument]::Parse($normalized, $options)
        if ($document.RootElement.ValueKind -ne
            [System.Text.Json.JsonValueKind]::Object) {
            throw "The $Label root is not an object"
        }
        Test-PSOBBStrictJsonPropertyUniqueness `
            -Element $document.RootElement -Path '$' | Out-Null
        $formatProperties = @($document.RootElement.EnumerateObject() |
                Where-Object Name -CEQ 'FormatVersion')
        $licenseProperties = @($document.RootElement.EnumerateObject() |
                Where-Object Name -CEQ 'BBLicenses')
        $legacyCredentialProperties = @($document.RootElement.EnumerateObject() |
                Where-Object { $_.Name -ceq 'BBUsername' -or
                    $_.Name -ceq 'BBPassword' })
        [long]$formatVersion = 0
        if ($formatProperties.Count -ne 1 -or
            $formatProperties[0].Value.ValueKind -ne
                [System.Text.Json.JsonValueKind]::Number -or
            -not $formatProperties[0].Value.TryGetInt64([ref]$formatVersion) -or
            $formatVersion -ne 1 -or
            $licenseProperties.Count -ne 1 -or
            $licenseProperties[0].Value.ValueKind -ne
                [System.Text.Json.JsonValueKind]::Array -or
            $legacyCredentialProperties.Count -ne 0) {
            throw "The $Label is not a current-format newserv account"
        }

        $licenses = [System.Collections.Generic.List[object]]::new()
        foreach ($licenseElement in $licenseProperties[0].Value.EnumerateArray()) {
            if ($licenseElement.ValueKind -ne
                [System.Text.Json.JsonValueKind]::Object) {
                throw "The $Label contains a non-object BBLicense"
            }
            $licenseFields = @($licenseElement.EnumerateObject())
            $userFields = @($licenseFields | Where-Object Name -CEQ 'UserName')
            $passwordFields = @($licenseFields | Where-Object Name -CEQ 'Password')
            if ($licenseFields.Count -ne 2 -or $userFields.Count -ne 1 -or
                $passwordFields.Count -ne 1 -or
                $userFields[0].Value.ValueKind -ne
                    [System.Text.Json.JsonValueKind]::String -or
                $passwordFields[0].Value.ValueKind -ne
                    [System.Text.Json.JsonValueKind]::String) {
                throw "The $Label contains an invalid BBLicense property set"
            }
            $userName = ConvertFrom-PSOBBNewservSavedAsciiJsonStringToken `
                -RawToken $userFields[0].Value.GetRawText() `
                -Label 'BBLicense username'
            $password = ConvertFrom-PSOBBNewservSavedAsciiJsonStringToken `
                -RawToken $passwordFields[0].Value.GetRawText() `
                -Label 'BBLicense password'
            if ($userName.Length -lt 1 -or $userName.Length -gt 16 -or
                $password.Length -lt 1 -or $password.Length -gt 16) {
                throw "The $Label contains an out-of-range BBLicense identity"
            }
            $licenses.Add([pscustomobject]@{
                    UserName = $userName
                    Password = $password
                })
        }
        [pscustomobject]@{
            Licenses = $licenses.ToArray()
            Sha256 = [string]$fileSnapshot.Sha256
            Length = [long]$fileSnapshot.Length
            Path = [string]$fileSnapshot.Path
        }
    } catch {
        throw "The $Label failed strict newserv license JSON validation"
    } finally {
        if ($document) { $document.Dispose() }
        if ($fileSnapshot -and $fileSnapshot.Bytes) {
            [Array]::Clear(
                [byte[]]$fileSnapshot.Bytes, 0,
                ([byte[]]$fileSnapshot.Bytes).Length)
        }
    }
}

function Copy-PSOBBRedactedRecoveryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][ValidateRange(0, 1073741824)]
        [long]$ExpectedLength,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [string]$Label = 'recovery item'
    )

    try {
        Copy-PSOBBVerifiedOrdinaryFile `
            -Source $Source -SourceRoot $SourceRoot `
            -Destination $Destination -DestinationRoot $DestinationRoot `
            -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
            -Label $Label
    } catch {
        throw "The $Label failed verified recovery copy"
    }
}

function Add-PSOBBRecoveryBBLicenseRedactionTerms {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, int]]$UserNameCounts,
        [AllowEmptyCollection()][Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Passwords,
        [string]$Label = 'licenses item'
    )

    try {
        $snapshot = Read-PSOBBRedactedRecoveryNewservLicenseJsonSnapshot `
            -Path $Path -Root $Root -MaximumBytes 16MB `
            -MaximumDepth 20 -Label $Label
        $pendingUserNameCounts =
            [System.Collections.Generic.Dictionary[string, int]]::new(
                [System.StringComparer]::Ordinal)
        $pendingPasswords = [System.Collections.Generic.List[string]]::new()
        $count = 0
        foreach ($license in @($snapshot.Licenses)) {
            $userName = [string]$license.UserName
            $password = [string]$license.Password
            if ($pendingUserNameCounts.ContainsKey([string]$userName)) {
                $pendingUserNameCounts[[string]$userName]++
            } else {
                $pendingUserNameCounts.Add([string]$userName, 1)
            }
            $pendingPasswords.Add([string]$password)
            $count++
        }
        foreach ($entry in $pendingUserNameCounts.GetEnumerator()) {
            $existingCount = if ($UserNameCounts.ContainsKey($entry.Key)) {
                [int]$UserNameCounts[$entry.Key]
            } else { 0 }
            if ($existingCount -gt ([int]::MaxValue - [int]$entry.Value)) {
                throw 'BBLicense identity count exceeds its exact bound'
            }
        }
        foreach ($entry in $pendingUserNameCounts.GetEnumerator()) {
            if ($UserNameCounts.ContainsKey($entry.Key)) {
                $UserNameCounts[$entry.Key] += [int]$entry.Value
            } else {
                $UserNameCounts.Add($entry.Key, [int]$entry.Value)
            }
        }
        foreach ($password in $pendingPasswords) {
            $Passwords.Add($password)
        }
        $count
    } catch {
        throw "The $Label cannot be inspected for recovery redaction"
    }
}

function Initialize-PSOBBRuntimeMarker {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    Assert-PathWithinRoot -Path $Layout.RuntimeMarker -Root $Layout.Root | Out-Null
    if (Test-Path -LiteralPath $Layout.RuntimeMarker -PathType Leaf) {
        return Assert-PSOBBRuntimeMarker -Layout $Layout
    }
    $marker = [ordered]@{
        schemaVersion = 1
        installationId = [Guid]::NewGuid().ToString('D')
        runtimeRoot = $Layout.Root
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    $temporary = $Layout.RuntimeMarker + '.new'
    if (Test-Path -LiteralPath $temporary) {
        throw 'PSOBB runtime ownership marker staging is not clean'
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($marker | ConvertTo-Json -Depth 3))
    try {
        [void](Write-PSOBBDurableFileBytes `
                -Path $temporary -Root $Layout.Root -Bytes $bytes `
                -Label 'runtime ownership marker staging')
        Set-PSOBBProtectedAcl -Path $temporary
        $staged = Read-PSOBBStrictJsonSnapshot `
            -Path $temporary -Root $Layout.Root -MaximumBytes 64KB `
            -MaximumDepth 4 -Label 'runtime ownership marker staging'
        [System.IO.File]::Move($temporary, $Layout.RuntimeMarker)
        Set-PSOBBProtectedAcl -Path $Layout.RuntimeMarker
        $published = Read-PSOBBStrictJsonSnapshot `
            -Path $Layout.RuntimeMarker -Root $Layout.Root -MaximumBytes 64KB `
            -MaximumDepth 4 -Label 'runtime ownership marker'
        if ($published.Sha256 -cne $staged.Sha256) {
            throw 'PSOBB runtime ownership marker changed during publication'
        }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    Assert-PSOBBRuntimeMarker -Layout $Layout
}

function Assert-PSOBBRuntimeMarker {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    Assert-PathWithinRoot -Path $Layout.RuntimeMarker -Root $Layout.Root | Out-Null
    if (-not (Test-Path -LiteralPath $Layout.RuntimeMarker -PathType Leaf)) {
        throw 'PSOBB runtime ownership marker is missing'
    }
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Layout.RuntimeMarker -Root $Layout.Root -Kind File `
            -Label 'runtime ownership marker')
    if (-not (Test-PSOBBProtectedAcl -Path $Layout.RuntimeMarker)) {
        throw 'PSOBB runtime ownership marker ACL is invalid'
    }
    $markerSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $Layout.RuntimeMarker -Root $Layout.Root -MaximumBytes 64KB `
        -MaximumDepth 4 -Label 'runtime ownership marker'
    $marker = $markerSnapshot.Value
    [void](Assert-PSOBBOrdinaryContainedPath `
            -Path $Layout.RuntimeMarker -Root $Layout.Root -Kind File `
            -Label 'runtime ownership marker')
    if (-not (Test-PSOBBProtectedAcl -Path $Layout.RuntimeMarker)) {
        throw 'PSOBB runtime ownership marker ACL changed while it was read'
    }
    Assert-PSOBBStrictDataObjectProperties -Value $marker -Expected @(
        'schemaVersion', 'installationId', 'runtimeRoot', 'createdAtUtc') `
        -Label 'runtime ownership marker' | Out-Null
    $parsedInstallationId = [Guid]::Empty
    $parsedCreatedAt = [DateTimeOffset]::MinValue
    if ($marker.schemaVersion -isnot [long] -or $marker.schemaVersion -ne 1 -or
        $marker.installationId -isnot [string] -or
        -not [Guid]::TryParseExact(
            [string]$marker.installationId, 'D', [ref]$parsedInstallationId) -or
        $marker.runtimeRoot -isnot [string] -or
        $marker.createdAtUtc -isnot [string] -or
        -not [DateTimeOffset]::TryParse(
            [string]$marker.createdAtUtc, [ref]$parsedCreatedAt) -or
        -not ([System.IO.Path]::GetFullPath(
                [string]$marker.runtimeRoot).TrimEnd('\')).Equals(
            $Layout.Root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'PSOBB runtime ownership marker is invalid or belongs to another root'
    }
    $marker
}

function Assert-PSOBBZipArchiveSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 1000000)][int]$MaximumEntries = 100000,
        [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = 12GB,
        [ValidateRange(1, [long]::MaxValue)][long]$MaximumEntryBytes = 4GB,
        [switch]$AllowReviewedSourceSymlinks
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -gt $MaximumEntries) {
            throw "Archive contains too many entries: $($archive.Entries.Count)"
        }
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $regularFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $sourceLinks = [System.Collections.Generic.List[object]]::new()
        [long]$expanded = 0
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name)) {
                throw 'Archive contains an empty member name'
            }
            if ([System.IO.Path]::IsPathRooted($name) -or
                $name -match '(^|/)\.\.(/|$)' -or
                $name.Contains(':', [System.StringComparison]::Ordinal) -or
                $name.StartsWith('/', [System.StringComparison]::Ordinal)) {
                throw "Archive contains an unsafe path: $name"
            }
            $segments = @($name.TrimEnd('/').Split('/'))
            foreach ($segment in $segments) {
                if ([string]::IsNullOrEmpty($segment) -or
                    $segment.EndsWith(' ', [System.StringComparison]::Ordinal) -or
                    $segment.EndsWith('.', [System.StringComparison]::Ordinal) -or
                    $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$') {
                    throw "Archive contains a Windows-unsafe path segment: $name"
                }
            }
            $normalizedName = $name.TrimEnd('/')
            if (-not $names.Add($normalizedName)) {
                throw "Archive contains a duplicate or case-colliding path: $name"
            }
            $unixMode = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            $isUnixSymlink = $unixMode -eq 0xA000
            $isWindowsReparsePoint = (($entry.ExternalAttributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)
            if ($isWindowsReparsePoint) {
                throw "Archive contains a link/reparse member: $name"
            }
            if ($isUnixSymlink) {
                if (-not $AllowReviewedSourceSymlinks) {
                    throw "Archive contains a link/reparse member: $name"
                }
                if ($entry.Length -lt 1 -or $entry.Length -gt 4096) {
                    throw "Source symlink target length is invalid: $name"
                }
                $stream = $entry.Open()
                $memory = [System.IO.MemoryStream]::new()
                try {
                    $stream.CopyTo($memory)
                    $target = [System.Text.UTF8Encoding]::new($false, $true).GetString($memory.ToArray())
                } catch {
                    throw "Source symlink target is not strict UTF-8: $name"
                } finally {
                    $memory.Dispose()
                    $stream.Dispose()
                }
                if ([string]::IsNullOrWhiteSpace($target) -or
                    @($target.ToCharArray() | Where-Object { [char]::IsControl($_) }).Count -gt 0) {
                    throw "Source symlink target contains empty or control text: $name"
                }
                $sourceLinks.Add([pscustomobject]@{ Name = $normalizedName; Target = $target })
            } elseif (-not [string]::IsNullOrEmpty($entry.Name)) {
                [void]$regularFiles.Add($normalizedName)
            }
            if ($entry.Length -gt $MaximumEntryBytes) {
                throw "Archive member exceeds the expansion limit: $name"
            }
            if ($entry.Length -gt ([long]::MaxValue - $expanded)) {
                throw 'Archive expanded-size arithmetic overflowed'
            }
            $expanded += $entry.Length
            if ($expanded -gt $MaximumExpandedBytes) {
                throw "Archive exceeds the total expansion limit: $expanded bytes"
            }
        }

        foreach ($link in $sourceLinks) {
            $target = ([string]$link.Target).Replace('\', '/')
            if ([System.IO.Path]::IsPathRooted($target) -or
                $target.StartsWith('/', [System.StringComparison]::Ordinal) -or
                $target.Contains(':', [System.StringComparison]::Ordinal)) {
                throw "Source symlink has a rooted or drive-qualified target: $($link.Name)"
            }
            $parent = [string]$link.Name
            $lastSlash = $parent.LastIndexOf('/')
            if ($lastSlash -ge 0) {
                $parent = $parent.Substring(0, $lastSlash)
            } else {
                $parent = ''
            }
            $combined = if ($parent) { $parent + '/' + $target } else { $target }
            $segments = [System.Collections.Generic.List[string]]::new()
            foreach ($segment in $combined.Split('/')) {
                if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.') {
                    continue
                }
                if ($segment -eq '..') {
                    if ($segments.Count -eq 0) {
                        throw "Source symlink escapes the archive root: $($link.Name)"
                    }
                    $segments.RemoveAt($segments.Count - 1)
                    continue
                }
                if ($segment.EndsWith(' ', [System.StringComparison]::Ordinal) -or
                    $segment.EndsWith('.', [System.StringComparison]::Ordinal) -or
                    $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$') {
                    throw "Source symlink target contains a Windows-unsafe path segment: $($link.Name)"
                }
                $segments.Add($segment)
            }
            $resolvedTarget = $segments -join '/'
            if (-not $regularFiles.Contains($resolvedTarget)) {
                throw "Source symlink does not resolve directly to a regular archive file: $($link.Name)"
            }
        }

        [pscustomobject]@{
            Entries = $archive.Entries.Count
            ExpandedBytes = $expanded
            ReviewedSourceSymlinks = $sourceLinks.Count
        }
    } finally {
        $archive.Dispose()
    }
}

function Expand-PSOBBApprovedArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    Assert-PSOBBZipArchiveSafe -Path $ArchivePath | Out-Null
    Assert-PathWithinRoot -Path $DestinationPath -Root $RuntimeRoot | Out-Null
    if (Test-Path -LiteralPath $DestinationPath) {
        throw "Archive destination already exists: $DestinationPath"
    }
    New-Item -ItemType Directory -Path $DestinationPath | Out-Null
    try {
        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $DestinationPath
        $reparse = Get-ChildItem -LiteralPath $DestinationPath -Force -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($reparse) {
            throw "Extracted archive contains a reparse point: $($reparse.FullName)"
        }
    } catch {
        $safeDestination = Assert-PathWithinRoot -Path $DestinationPath -Root $RuntimeRoot
        Remove-Item -LiteralPath $safeDestination -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Get-PSOBBDirectoryManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

    $resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
    @(Get-ChildItem -LiteralPath $resolvedRoot -File -Force -Recurse | Sort-Object FullName | ForEach-Object {
        $safeFile = Assert-PathWithinRoot -Path $_.FullName -Root $resolvedRoot
        [ordered]@{
            path = [System.IO.Path]::GetRelativePath($resolvedRoot, $safeFile).Replace('\', '/')
            size = $_.Length
            sha256 = Get-LowerSha256 $safeFile
        }
    })
}

function Get-PSOBBZipContentManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    Assert-PSOBBZipArchiveSafe -Path $Path | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) } | Sort-Object FullName | ForEach-Object {
            $stream = $_.Open()
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            try {
                $hash = [Convert]::ToHexString($hasher.ComputeHash($stream)).ToLowerInvariant()
            } finally {
                $hasher.Dispose()
                $stream.Dispose()
            }
            [ordered]@{
                path = $_.FullName.Replace('\', '/').TrimStart('/')
                size = $_.Length
                sha256 = $hash
            }
        })
    } finally {
        $archive.Dispose()
    }
}

function Test-PSOBBDirectoryManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Files
    )

    $actual = @(Get-PSOBBDirectoryManifest -Root $Root)
    $expectedByPath = @{}
    foreach ($entry in @($Files)) {
        $path = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($path) -or $expectedByPath.ContainsKey($path)) {
            return $false
        }
        $expectedByPath[$path] = $entry
    }
    if ($actual.Count -ne $expectedByPath.Count) {
        return $false
    }
    foreach ($entry in $actual) {
        if (-not $expectedByPath.ContainsKey($entry.path)) {
            return $false
        }
        $expected = $expectedByPath[$entry.path]
        if (($entry.size -ne [long]$expected.size) -or ($entry.sha256 -ne [string]$expected.sha256)) {
            return $false
        }
    }
    $true
}

function Test-PSOBBManifestEntriesEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    $leftEntries = @($Left)
    $rightEntries = @($Right)
    if ($leftEntries.Count -ne $rightEntries.Count) {
        return $false
    }
    $rightByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($entry in $rightEntries) {
        $path = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($path) -or $rightByPath.ContainsKey($path)) {
            return $false
        }
        $rightByPath.Add($path, $entry)
    }
    foreach ($entry in $leftEntries) {
        $path = [string]$entry.path
        if (-not $rightByPath.ContainsKey($path)) {
            return $false
        }
        $expected = $rightByPath[$path]
        if (([long]$entry.size -ne [long]$expected.size) -or
            -not ([string]$entry.sha256).Equals(
                [string]$expected.sha256,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    $true
}

function Get-LowerSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Set-ConfigScalar {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$JsonValue
    )

    $pattern = '(?m)^(\s*"' + [regex]::Escape($Key) + '"\s*:\s*)[^,\r\n]+(,\s*)$'
    $regex = [regex]::new($pattern)
    if ($regex.Matches($Text).Count -ne 1) {
        throw "Expected exactly one config key named $Key"
    }
    $regex.Replace($Text, { param($m) $m.Groups[1].Value + $JsonValue + $m.Groups[2].Value }, 1)
}

function Get-PSOBBClientPatchPolicy {
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json')
    )

    $policy = (Read-PSOBBClientPatchPolicySnapshot -Path $Path).Value
    if (($policy.schemaVersion -ne 1) -or
        ([string]$policy.defaultProfile -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$') -or
        (@($policy.profiles).Count -lt 2)) {
        throw 'Client-patch policy header is invalid'
    }

    $profileIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $allClassifiedPatches = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($profile in @($policy.profiles)) {
        if (([string]$profile.id -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$') -or
            -not $profileIds.Add([string]$profile.id) -or
            ([string]$profile.channel -notin @('stable', 'canary'))) {
            throw 'Client-patch policy contains an invalid or duplicate profile'
        }
        foreach ($propertyName in @('autoPatches', 'bbRequiredPatches')) {
            if (-not $profile.PSObject.Properties[$propertyName]) {
                throw "Client-patch profile $($profile.id) is missing $propertyName"
            }
            $profilePatches = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::Ordinal)
            foreach ($patchName in @($profile.$propertyName)) {
                if (([string]$patchName -notmatch '^[A-Za-z][A-Za-z0-9]*$') -or
                    -not $profilePatches.Add([string]$patchName)) {
                    throw "Client-patch profile $($profile.id) contains an invalid or duplicate patch"
                }
                if ([string]$profile.channel -eq 'stable') {
                    [void]$allClassifiedPatches.Add([string]$patchName)
                }
            }
        }
        if (([string]$profile.channel -eq 'stable') -and
            (@($profile.bbRequiredPatches).Count -ne 0)) {
            throw "Stable client-patch profile $($profile.id) cannot enable BBRequiredPatches"
        }
    }
    if (-not $profileIds.Contains([string]$policy.defaultProfile)) {
        throw 'Client-patch policy defaultProfile does not select a declared profile'
    }

    foreach ($gateName in @('sourceCanaryOnly', 'protocolRequired', 'migrationRequired')) {
        if (-not $policy.gated.PSObject.Properties[$gateName]) {
            throw "Client-patch policy is missing the $gateName gate"
        }
        $gatePatches = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        foreach ($patchName in @($policy.gated.$gateName)) {
            if (([string]$patchName -notmatch '^[A-Za-z][A-Za-z0-9]*$') -or
                -not $gatePatches.Add([string]$patchName) -or
                $allClassifiedPatches.Contains([string]$patchName)) {
                throw "Client-patch policy gate $gateName contains an invalid, duplicate, or stable patch"
            }
            [void]$allClassifiedPatches.Add([string]$patchName)
        }
    }
    $policy
}

function Set-ConfigStringArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Key,
        [AllowEmptyCollection()][Parameter(Mandatory)][string[]]$Values
    )

    # Validate the existing array before rewriting it. This prevents a missing
    # closing bracket from making the match consume a later config array.
    Get-ActiveConfigStringArray -Text $Text -Key $Key | Out-Null
    $pattern = '(?m)^(?<indent>[ \t]*)"' + [regex]::Escape($Key) +
        '"[ \t]*:[ \t]*\[(?<body>[^\]]*)\](?<suffix>[ \t]*,)'
    $regex = [regex]::new($pattern)
    $matches = $regex.Matches($Text)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one config array named $Key"
    }
    $match = $matches[0]
    $eol = if ($Text.Contains("`r`n", [System.StringComparison]::Ordinal)) { "`r`n" } else { "`n" }
    $indent = $match.Groups['indent'].Value
    $replacement = $indent + '"' + $Key + '": ['
    if ($Values.Count -gt 0) {
        $entries = for ($index = 0; $index -lt $Values.Count; $index++) {
            $comma = if ($index -lt ($Values.Count - 1)) { ',' } else { '' }
            $indent + '  ' + (ConvertTo-Json -InputObject $Values[$index] -Compress) + $comma
        }
        $replacement += $eol + ($entries -join $eol) + $eol + $indent
    }
    $replacement += ']' + $match.Groups['suffix'].Value
    $Text.Substring(0, $match.Index) + $replacement +
        $Text.Substring($match.Index + $match.Length)
}

function Get-ActiveConfigStringArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Key
    )

    $pattern = '(?m)^[ \t]*"' + [regex]::Escape($Key) +
        '"[ \t]*:[ \t]*\[(?<body>[^\]]*)\][ \t]*,'
    $matches = [regex]::Matches($Text, $pattern)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one config array named $Key"
    }
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($matches[0].Groups['body'].Value -split '\r?\n')) {
        $entry = [regex]::Match($line, '^\s*"(?<value>[A-Za-z][A-Za-z0-9]*)"\s*,?\s*(?://.*)?$')
        if ($entry.Success) {
            $values.Add($entry.Groups['value'].Value)
        } elseif ($line -notmatch '^\s*(?://.*)?$') {
            throw "Config array $Key contains a non-string or malformed active entry"
        }
    }
    @($values)
}

function Test-ExactStringSequence {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][Parameter(Mandatory)][string[]]$Expected,
        [AllowEmptyCollection()][Parameter(Mandatory)][string[]]$Actual
    )

    if ($Expected.Count -ne $Actual.Count) {
        return $false
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Expected[$index] -cne $Actual[$index]) {
            return $false
        }
    }
    $true
}

function Get-NewservClientPatchConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Profile,
        [string]$PolicyPath = (Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json')
    )

    $policy = Get-PSOBBClientPatchPolicy -Path $PolicyPath
    $profiles = @($policy.profiles | Where-Object id -CEQ $Profile)
    if ($profiles.Count -ne 1) {
        throw "Unknown client-patch profile: $Profile"
    }
    $selected = $profiles[0]
    if ([string]$selected.channel -cne 'stable') {
        throw "Client-patch profile $Profile is not approved for the stable runtime"
    }
    $updated = Set-ConfigStringArray -Text $Text -Key 'BBRequiredPatches' `
        -Values @($selected.bbRequiredPatches)
    Set-ConfigStringArray -Text $updated -Key 'AutoPatches' -Values @($selected.autoPatches)
}

function Assert-NewservClientPatchProfileAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServerRoot,
        [Parameter(Mandatory)][string]$Profile,
        [string]$PolicyPath = (Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json'),
        [string]$SourcesLockPath = (Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json')
    )

    $policy = Get-PSOBBClientPatchPolicy -Path $PolicyPath
    $profiles = @($policy.profiles | Where-Object id -CEQ $Profile)
    if ($profiles.Count -ne 1 -or [string]$profiles[0].channel -cne 'stable') {
        throw "Client-patch profile is not approved for stable: $Profile"
    }
    $clientFunctionsRoot = Join-Path $ServerRoot 'system\client-functions'
    if (-not (Test-Path -LiteralPath $clientFunctionsRoot -PathType Container)) {
        throw "newserv client-functions directory is missing: $clientFunctionsRoot"
    }
    $stableIdentity = Get-PSOBBStableServerSourceLockIdentity `
        -Path $SourcesLockPath
    foreach ($patchName in @($profiles[0].autoPatches) + @($profiles[0].bbRequiredPatches)) {
        $patchPath = Join-Path $clientFunctionsRoot (
            $patchName + '\' + $patchName + '.59NL.patch.s')
        $memberPath = 'release/system/client-functions/' + $patchName + '/' +
            $patchName + '.59NL.patch.s'
        $members = @($stableIdentity.Component.members | Where-Object {
                $_.path -ceq $memberPath
            })
        if ($members.Count -ne 1 -or
            [long]$members[0].size -le 0 -or
            [string]$members[0].sha256 -notmatch '^[0-9a-f]{64}$' -or
            -not (Test-Path -LiteralPath $patchPath -PathType Leaf)) {
            throw "The pinned newserv runtime lacks the exact 59NL client patch: $patchName"
        }
        $patchFile = Get-Item -LiteralPath $patchPath
        if (($patchFile.Length -ne [long]$members[0].size) -or
            ((Get-LowerSha256 $patchFile.FullName) -cne [string]$members[0].sha256)) {
            throw "The pinned newserv 59NL client patch failed provenance verification: $patchName"
        }
    }
    $profiles[0]
}

function Assert-PSOBBClientPatchStateCoherent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$InstallRecordPath,
        [Parameter(Mandatory)][string]$InstallationId,
        [string]$RuntimeRoot,
        [string]$PolicyPath = (Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json')
    )

    foreach ($path in @($ConfigPath, $InstallRecordPath, $PolicyPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required client-patch state is missing: $path"
        }
    }

    $installRoot = if ($RuntimeRoot) {
        $RuntimeRoot
    } else {
        Split-Path -Parent $InstallRecordPath
    }
    $installSnapshot = Read-PSOBBInstallationRecordSnapshot `
        -Path $InstallRecordPath -Root $installRoot `
        -ExpectedInstallationId $InstallationId `
        -ExpectedRuntimeRoot $RuntimeRoot
    $installRecord = $installSnapshot.Value

    $profile = [string]$installRecord.clientPatchProfile
    if ($profile -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$') {
        throw 'Runtime installation record has an invalid client-patch profile'
    }
    $policySnapshot = Read-PSOBBClientPatchPolicySnapshot -Path $PolicyPath
    $policySha256 = [string]$policySnapshot.Sha256
    if ([string]$installRecord.clientPatchPolicySha256 -cne $policySha256) {
        throw 'Runtime installation record client-patch policy hash does not match the current pinned policy'
    }

    $policy = $policySnapshot.Value
    $profiles = @($policy.profiles | Where-Object id -CEQ $profile)
    if ($profiles.Count -ne 1 -or [string]$profiles[0].channel -cne 'stable') {
        throw "Runtime installation record selects an unapproved client-patch profile: $profile"
    }
    $configText = Get-Content -Raw -LiteralPath $ConfigPath
    $autoPatches = @(Get-ActiveConfigStringArray -Text $configText -Key 'AutoPatches')
    $requiredPatches = @(Get-ActiveConfigStringArray -Text $configText -Key 'BBRequiredPatches')
    if (-not (Test-ExactStringSequence -Expected @($profiles[0].autoPatches) -Actual $autoPatches) -or
        -not (Test-ExactStringSequence -Expected @($profiles[0].bbRequiredPatches) -Actual $requiredPatches)) {
        throw "Server config does not match client-patch profile metadata: $profile"
    }

    [pscustomobject]@{
        Profile = $profile
        PolicySha256 = $policySha256
        ConfigSha256 = Get-LowerSha256 $ConfigPath
        InstallationSha256 = [string]$installSnapshot.Sha256
        InstallationId = $InstallationId
    }
}

function Set-PSOBBIniValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key,
        [AllowEmptyString()][Parameter(Mandatory)][string]$Value
    )

    $sectionPattern = '(?ms)^\[' + [regex]::Escape($Section) + '\][ \t]*\r?\n(?<body>.*?)(?=^\[|\z)'
    $sectionRegex = [regex]::new($sectionPattern)
    $sectionMatches = $sectionRegex.Matches($Text)
    if ($sectionMatches.Count -ne 1) {
        throw "Expected exactly one dgVoodoo section named [$Section]"
    }

    $sectionMatch = $sectionMatches[0]
    $body = $sectionMatch.Groups['body'].Value
    $keyPattern = '(?m)^(?<prefix>[ \t]*' + [regex]::Escape($Key) +
        '[ \t]*=[ \t]*)(?<value>[^;\r\n]*?)(?<suffix>[ \t]*\r?)$'
    $keyRegex = [regex]::new($keyPattern)
    $keyMatches = $keyRegex.Matches($body)
    if ($keyMatches.Count -ne 1) {
        throw "Expected exactly one active dgVoodoo setting named $Section/$Key"
    }

    $updatedBody = $keyRegex.Replace(
        $body,
        { param($match) $match.Groups['prefix'].Value + $Value + $match.Groups['suffix'].Value },
        1)
    $updatedValueMatches = $keyRegex.Matches($updatedBody)
    if (($updatedValueMatches.Count -ne 1) -or
        -not $updatedValueMatches[0].Groups['value'].Value.Trim().Equals(
            $Value, [System.StringComparison]::Ordinal)) {
        throw "Failed to set the exact dgVoodoo value for $Section/$Key"
    }

    $bodyStart = $sectionMatch.Groups['body'].Index
    $Text.Substring(0, $bodyStart) + $updatedBody +
        $Text.Substring($bodyStart + $sectionMatch.Groups['body'].Length)
}

function Get-PSOBBDgVoodooConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceText,
        [ValidateSet('DgVoodooD3D11', 'DgVoodooD3D12')]
        [string]$Renderer,
        [ValidateSet('Compatibility', 'HighFidelity2560x1600', 'Ultra3840x2880')]
        [string]$GraphicsPreset = 'Ultra3840x2880'
    )

    $outputApi = if ($Renderer -eq 'DgVoodooD3D11') {
        'd3d11_fl11_0'
    } else {
        'd3d12_fl11_0'
    }
    $settings = [System.Collections.Generic.List[object]]::new()
    $settings.Add(@('General', 'OutputAPI', $outputApi))
    $settings.Add(@('DirectX', 'dgVoodooWatermark', 'false'))

    if ($GraphicsPreset -in @('HighFidelity2560x1600', 'Ultra3840x2880')) {
        $forcedResolution = if ($GraphicsPreset -eq 'Ultra3840x2880') {
            '3840x2880'
        } else {
            'max'
        }
        $antialiasing = if ($GraphicsPreset -eq 'Ultra3840x2880') {
            'off'
        } else {
            '8x'
        }
        foreach ($setting in @(
            @('General', 'ScalingMode', 'stretched_ar'),
            @('General', 'FullScreenMode', 'false'),
            @('General', 'KeepWindowAspectRatio', 'true'),
            @('General', 'CenterAppWindow', 'true'),
            @('GeneralExt', 'DesktopResolution', '2560x1600'),
            @('GeneralExt', 'Resampling', 'lanczos-3'),
            @('GeneralExt', 'WindowedAttributes', 'borderless, fullscreensize'),
            @('DirectX', 'Filtering', '16'),
            @('DirectX', 'Mipmapping', 'appdriven'),
            @('DirectX', 'KeepFilterIfPointSampled', 'true'),
            @('DirectX', 'Resolution', $forcedResolution),
            @('DirectX', 'Antialiasing', $antialiasing),
            @('DirectX', 'AppControlledScreenMode', 'false'),
            @('DirectX', 'Bilinear2DOperations', 'false'),
            @('DirectX', 'ForceVerticalSync', 'false')
        )) {
            $settings.Add($setting)
        }
    }

    $configuration = $SourceText
    foreach ($setting in $settings) {
        $configuration = Set-PSOBBIniValue `
            -Text $configuration `
            -Section $setting[0] `
            -Key $setting[1] `
            -Value $setting[2]
    }
    $configuration
}

function Enter-PSOBBClientOperationLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [ValidateRange(0, 300)][int]$TimeoutSeconds = 30
    )

    $marker = Assert-PSOBBRuntimeMarker -Layout $Layout
    $installationId = [string]$marker.installationId
    if ($installationId -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'The runtime installation ID cannot be used for the client-operation lock'
    }
    $mutex = [System.Threading.Mutex]::new(
        $false,
        "Local\PSOBB.Client.$installationId")
    try {
        $acquired = $false
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        } catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            throw 'Another PSOBB client start or rebuild operation is still in progress'
        }
        return $mutex
    } catch {
        $mutex.Dispose()
        throw
    }
}

function Exit-PSOBBClientOperationLock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Threading.Mutex]$Mutex)

    try {
        $Mutex.ReleaseMutex()
    } finally {
        $Mutex.Dispose()
    }
}

function Initialize-PSOBBWindowPresentationType {
    [CmdletBinding()]
    param()

    if ($null -ne ('PSOBBWindowPresentation' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class PSOBBWindowPresentation
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }

    public sealed class State
    {
        public int X { get; init; }
        public int Y { get; init; }
        public int Width { get; init; }
        public int Height { get; init; }
        public int ClientWidth { get; init; }
        public int ClientHeight { get; init; }
        public long Style { get; init; }
    }

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
    private static extern int GetWindowLong32(IntPtr window, int index);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLong64(IntPtr window, int index);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongW", SetLastError = true)]
    private static extern int SetWindowLong32(IntPtr window, int index, int value);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr SetWindowLong64(IntPtr window, int index, IntPtr value);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(
        IntPtr window, IntPtr insertAfter, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    private static extern bool IsWindow(IntPtr window);
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetWindowRect(IntPtr window, out Rect rectangle);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetClientRect(IntPtr window, out Rect rectangle);
    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AdjustWindowRectExForDpi(
        ref Rect rectangle, uint style, bool hasMenu, uint extendedStyle, uint dpi);

    private const int GwlStyle = -16;
    private const int GwlExtendedStyle = -20;
    private const long WsCaption = 0x00C00000L;
    private const long WsThickFrame = 0x00040000L;
    private const long WsMinimizeBox = 0x00020000L;
    private const long WsMaximizeBox = 0x00010000L;
    private const long WsSystemMenu = 0x00080000L;
    private const long WsPopup = unchecked((long)0x80000000);
    private const long WsVisible = 0x10000000L;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpNoActivate = 0x0010;
    private const uint SwpFrameChanged = 0x0020;
    private const uint SwpNoOwnerZOrder = 0x0200;

    private static long GetStyle(IntPtr window) => IntPtr.Size == 8
        ? GetWindowLong64(window, GwlStyle).ToInt64()
        : GetWindowLong32(window, GwlStyle);

    private static long GetExtendedStyle(IntPtr window) => IntPtr.Size == 8
        ? GetWindowLong64(window, GwlExtendedStyle).ToInt64()
        : GetWindowLong32(window, GwlExtendedStyle);

    private static void SetStyle(IntPtr window, long style)
    {
        Marshal.SetLastPInvokeError(0);
        long prior = IntPtr.Size == 8
            ? SetWindowLong64(window, GwlStyle, new IntPtr(style)).ToInt64()
            : SetWindowLong32(window, GwlStyle, unchecked((int)style));
        var error = Marshal.GetLastPInvokeError();
        if (prior == 0 && error != 0)
        {
            throw new Win32Exception(error);
        }
    }

    public static State GetState(IntPtr window)
    {
        if (window == IntPtr.Zero || !GetWindowRect(window, out var rectangle)
            || !GetClientRect(window, out var clientRectangle))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        return new State
        {
            X = rectangle.Left,
            Y = rectangle.Top,
            Width = rectangle.Right - rectangle.Left,
            Height = rectangle.Bottom - rectangle.Top,
            ClientWidth = clientRectangle.Right - clientRectangle.Left,
            ClientHeight = clientRectangle.Bottom - clientRectangle.Top,
            Style = GetStyle(window),
        };
    }

    public static State ApplyBorderless(IntPtr window, int x, int y, int width, int height)
    {
        var oldStyle = GetStyle(window);
        var newStyle = (oldStyle & ~(WsCaption | WsThickFrame | WsMinimizeBox | WsMaximizeBox | WsSystemMenu))
            | WsPopup | WsVisible;
        SetStyle(window, newStyle);
        if (!SetWindowPos(
            window,
            IntPtr.Zero,
            x,
            y,
            width,
            height,
            SwpFrameChanged | SwpNoActivate | SwpNoZOrder | SwpNoOwnerZOrder))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        return GetState(window);
    }

    public static State ApplyResizable(
        IntPtr window,
        int workAreaX,
        int workAreaY,
        int workAreaWidth,
        int workAreaHeight,
        int clientWidth,
        int clientHeight)
    {
        var oldStyle = GetStyle(window);
        var newStyle = (oldStyle & ~WsPopup)
            | WsCaption | WsThickFrame | WsMinimizeBox | WsMaximizeBox | WsSystemMenu | WsVisible;
        SetStyle(window, newStyle);

        var outer = new Rect { Left = 0, Top = 0, Right = clientWidth, Bottom = clientHeight };
        var dpi = GetDpiForWindow(window);
        if (!AdjustWindowRectExForDpi(
            ref outer,
            unchecked((uint)newStyle),
            false,
            unchecked((uint)GetExtendedStyle(window)),
            dpi))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        var outerWidth = outer.Right - outer.Left;
        var outerHeight = outer.Bottom - outer.Top;
        var x = workAreaX + Math.Max(0, (workAreaWidth - outerWidth) / 2);
        var y = workAreaY + Math.Max(0, (workAreaHeight - outerHeight) / 2);
        if (!SetWindowPos(
            window,
            IntPtr.Zero,
            x,
            y,
            outerWidth,
            outerHeight,
            SwpFrameChanged | SwpNoActivate | SwpNoZOrder | SwpNoOwnerZOrder))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        return GetState(window);
    }

    public static IntPtr CaptureForegroundWindow() => GetForegroundWindow();

    public static IntPtr CaptureLatestNonClientForegroundWindow(
        IntPtr priorWindow,
        int clientProcessId)
    {
        var currentWindow = GetForegroundWindow();
        if (currentWindow != IntPtr.Zero && IsWindow(currentWindow))
        {
            GetWindowThreadProcessId(currentWindow, out var currentProcessId);
            if (currentProcessId != 0 &&
                currentProcessId != unchecked((uint)clientProcessId))
            {
                return currentWindow;
            }
        }

        return priorWindow != IntPtr.Zero && IsWindow(priorWindow)
            ? priorWindow
            : IntPtr.Zero;
    }

    public static string RestoreForegroundIfClientActive(
        IntPtr previousWindow,
        IntPtr clientWindow,
        int expectedClientProcessId)
    {
        if (previousWindow == IntPtr.Zero || previousWindow == clientWindow || !IsWindow(previousWindow))
        {
            return "PreviousWindowUnavailable";
        }
        if (clientWindow == IntPtr.Zero || !IsWindow(clientWindow))
        {
            return "ClientWindowUnavailable";
        }

        GetWindowThreadProcessId(clientWindow, out var clientProcessId);
        GetWindowThreadProcessId(previousWindow, out var previousProcessId);
        if (clientProcessId != unchecked((uint)expectedClientProcessId) ||
            previousProcessId == clientProcessId)
        {
            return "WindowOwnershipMismatch";
        }

        var currentWindow = GetForegroundWindow();
        if (currentWindow == previousWindow)
        {
            return "Preserved";
        }
        if (currentWindow != clientWindow)
        {
            return "UserSelectedAnotherWindow";
        }
        if (!SetForegroundWindow(previousWindow))
        {
            return "Denied";
        }
        return GetForegroundWindow() == previousWindow ? "Restored" : "Denied";
    }
}
'@
}

function Get-PSOBBForegroundWindowHandle {
    [CmdletBinding()]
    param()

    Initialize-PSOBBWindowPresentationType
    [PSOBBWindowPresentation]::CaptureForegroundWindow()
}

function Update-PSOBBNonClientForegroundWindowTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$CurrentTarget,
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ClientProcessId
    )

    Initialize-PSOBBWindowPresentationType
    [PSOBBWindowPresentation]::CaptureLatestNonClientForegroundWindow(
        $CurrentTarget,
        $ClientProcessId)
}

function Restore-PSOBBForegroundWindowAfterClientLaunch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][IntPtr]$PreviousWindow
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        throw 'The PSOBB client exited before foreground restoration'
    }
    Initialize-PSOBBWindowPresentationType
    $status = [PSOBBWindowPresentation]::RestoreForegroundIfClientActive(
        $PreviousWindow,
        $Process.MainWindowHandle,
        $Process.Id)
    [pscustomobject]@{
        Status = $status
        Preserved = $status -in @('Preserved', 'Restored', 'UserSelectedAnotherWindow')
    }
}

function Get-PSOBBClientWindowPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)

    $Process.Refresh()
    if ($Process.HasExited -or $Process.MainWindowHandle -eq [IntPtr]::Zero) {
        throw 'The PSOBB client has no live main window to inspect'
    }
    Initialize-PSOBBWindowPresentationType
    [PSOBBWindowPresentation]::GetState($Process.MainWindowHandle)
}

function Set-PSOBBClientBorderlessPresentation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [ValidateRange(640, 16384)][int]$Width,
        [ValidateRange(480, 16384)][int]$Height,
        [int]$X = 0,
        [int]$Y = 0
    )

    $Process.Refresh()
    if ($Process.HasExited -or $Process.MainWindowHandle -eq [IntPtr]::Zero) {
        throw 'The PSOBB client has no live main window to present'
    }
    Initialize-PSOBBWindowPresentationType
    [PSOBBWindowPresentation]::ApplyBorderless(
        $Process.MainWindowHandle, $X, $Y, $Width, $Height) | Out-Null
    Start-Sleep -Milliseconds 750
    $state = [PSOBBWindowPresentation]::GetState($Process.MainWindowHandle)
    if (($state.X -ne $X) -or ($state.Y -ne $Y) -or
        ($state.Width -ne $Width) -or ($state.Height -ne $Height) -or
        (($state.Style -band 0x00C40000L) -ne 0)) {
        throw "The verified PSOBB window did not accept the requested ${Width}x${Height} borderless presentation"
    }
    $state
}

function Set-PSOBBClientResizablePresentation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [ValidateRange(640, 8192)][int]$ClientWidth = 1600,
        [ValidateRange(480, 8192)][int]$ClientHeight = 1200,
        [int]$WorkAreaX = 0,
        [int]$WorkAreaY = 0,
        [ValidateRange(640, 16384)][int]$WorkAreaWidth = 2560,
        [ValidateRange(480, 16384)][int]$WorkAreaHeight = 1542
    )

    $Process.Refresh()
    if ($Process.HasExited -or $Process.MainWindowHandle -eq [IntPtr]::Zero) {
        throw 'The PSOBB client has no live main window to present'
    }
    Initialize-PSOBBWindowPresentationType
    [PSOBBWindowPresentation]::ApplyResizable(
        $Process.MainWindowHandle,
        $WorkAreaX,
        $WorkAreaY,
        $WorkAreaWidth,
        $WorkAreaHeight,
        $ClientWidth,
        $ClientHeight) | Out-Null
    Start-Sleep -Milliseconds 750
    $state = [PSOBBWindowPresentation]::GetState($Process.MainWindowHandle)
    if (($state.ClientWidth -ne $ClientWidth) -or ($state.ClientHeight -ne $ClientHeight) -or
        (($state.Style -band 0x00C40000L) -ne 0x00C40000L)) {
        throw "The verified PSOBB window did not accept the requested movable ${ClientWidth}x${ClientHeight} client area"
    }
    $state
}

function Test-PSOBBLocalReferenceWidescreenProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile)

    $referenceProfileIds = @(
        'lab-widescreen-16x10',
        'lab-widescreen-hd-16x10',
        'lab-widescreen-cas-16x10'
    )
    $enhancementPathProperty =
        $Profile.PSObject.Properties['enhancementConfigurationPath']
    if ([int]$Profile.schemaVersion -lt 7 -or
        [string]$Profile.channel -cne 'local-lab' -or
        [string]$Profile.profileId -cnotin $referenceProfileIds -or
        [string]$Profile.presentationOwner -cne 'client-patch' -or
        [string]$Profile.widescreenConfigurationPath -cne 'widescreen.cfg' -or
        [string]$Profile.widescreenIniPath -cne 'patches/pso_widescreen.ini' -or
        [string]$Profile.widescreenConfigurationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Profile.widescreenIniSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$Profile.aspectPolicy -cne 'expand-horizontal-16x10' -or
        [int]$Profile.resizableClientWidth -ne 1600 -or
        [int]$Profile.resizableClientHeight -ne 1000 -or
        [string]$Profile.redistributionClass -cne 'local-only' -or
        $null -eq $enhancementPathProperty -or
        $null -ne $enhancementPathProperty.Value) {
        return $false
    }

    try {
        $catalog = Get-Content -Raw -LiteralPath (
            Join-Path $script:PSOBBRepositoryRoot 'config\graphics-profiles.json') |
            ConvertFrom-Json -Depth 50 -DateKind String
        $declarations = @($catalog.profiles | Where-Object {
            [string]$_.id -ceq [string]$Profile.profileId -and
            [string]$_.channel -ceq 'local-lab'
        })
        if ($declarations.Count -ne 1 -or
            [string]$declarations[0].display.presentationOwner -cne 'client-patch') {
            return $false
        }
        $declaredModes = @($declarations[0].display.windowModes | ForEach-Object {
            ([string]$_).ToLowerInvariant()
        } | Sort-Object)
        if ([string]::Join(',', $declaredModes) -cne 'borderless,resizable') {
            return $false
        }
        $referenceLayers = @($declarations[0].renderer.secondaryLayers |
            Where-Object {
                [string]$_.componentId -ceq 'psobb-widescreen-local-evaluation' -and
                [string]$_.relativePath -ceq 'plugins/pso_widescreen.asi' -and
                [string]$_.role -ceq 'widescreen-reference' -and
                [int]$_.declaredOrder -eq 30
            })
        $enhancementLayers = @($declarations[0].renderer.secondaryLayers |
            Where-Object {
                [string]$_.componentId -ceq 'project-owned-psobb-enhancement'
            })
        if ($referenceLayers.Count -ne 1 -or $enhancementLayers.Count -ne 0) {
            return $false
        }

        $sources = Get-Content -Raw -LiteralPath (
            Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json') |
            ConvertFrom-Json -Depth 50 -DateKind String
        $components = @($sources.components | Where-Object {
            [string]$_.id -ceq 'psobb-widescreen-local-evaluation' -and
            [string]$_.role -ceq 'widescreen-reference'
        })
        $asiMembers = if ($components.Count -eq 1) {
            @($components[0].members | Where-Object {
                [string]$_.path -ceq 'patches/pso_widescreen.asi' -and
                [string]$_.sha256 -cmatch '^[a-f0-9]{64}$' -and
                [long]$_.size -gt 0
            })
        } else {
            @()
        }
        if ($components.Count -ne 1 -or $asiMembers.Count -ne 1) {
            return $false
        }
    } catch {
        return $false
    }
    $true
}

function Get-PSOBBClientPatchResizablePresentationPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$Presentation
    )

    $hasMovableFrame =
        ([long]$Presentation.Style -band 0x00C40000L) -eq 0x00C40000L
    $hasExactClientArea =
        [int]$Presentation.ClientWidth -eq [int]$Profile.resizableClientWidth -and
        [int]$Presentation.ClientHeight -eq [int]$Profile.resizableClientHeight
    if ($hasMovableFrame -and $hasExactClientArea) {
        return 'Observe'
    }
    if ($hasMovableFrame -and
        (Test-PSOBBLocalReferenceWidescreenProfile -Profile $Profile)) {
        return 'CorrectLocalReference'
    }
    'Reject'
}

function Set-NewservLocalConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$ServerName = 'PSOBB Local',
        [ValidateSet('stable-qol', 'baseline')]
        [string]$ClientPatchProfile = 'baseline'
    )

    if ($ServerName.Length -gt 16) {
        throw 'newserv ServerName must be 16 characters or fewer'
    }

    $text = Get-Content -Raw -LiteralPath $ConfigPath
    $serializedServerName = ConvertTo-Json -InputObject $ServerName -Compress
    $text = Set-ConfigScalar -Text $text -Key 'ServerName' -JsonValue $serializedServerName
    $text = Set-ConfigScalar -Text $text -Key 'LocalAddress' -JsonValue '"127.0.0.1"'
    $text = Set-ConfigScalar -Text $text -Key 'ExternalAddress' -JsonValue '"127.0.0.1"'
    $text = Set-ConfigScalar -Text $text -Key 'DNSServerPort' -JsonValue '0'
    $text = Set-ConfigScalar -Text $text -Key 'IPStackListen' -JsonValue '[]'
    $text = Set-ConfigScalar -Text $text -Key 'PPPStackListen' -JsonValue '[]'
    $text = Set-ConfigScalar -Text $text -Key 'PPPRawListen' -JsonValue '[]'
    $text = Set-ConfigScalar -Text $text -Key 'HTTPListen' -JsonValue '[]'
    if ($text -match '(?m)^\s*"RunInteractiveShell"\s*:') {
        $text = Set-ConfigScalar -Text $text -Key 'RunInteractiveShell' -JsonValue 'true'
    } else {
        $httpPattern = '(?m)^(\s*"HTTPListen"\s*:\s*\[\],\s*)$'
        if ([regex]::Matches($text, $httpPattern).Count -ne 1) {
            throw 'Could not safely insert RunInteractiveShell after HTTPListen'
        }
        $text = [regex]::Replace(
            $text,
            $httpPattern,
            '$1' + [Environment]::NewLine + '  "RunInteractiveShell": true,',
            1)
    }
    $text = Set-ConfigScalar -Text $text -Key 'AllowUnregisteredUsers' -JsonValue 'false'
    $text = Set-ConfigScalar -Text $text -Key 'CheatModeBehavior' -JsonValue '"Off"'
    $text = Set-ConfigScalar -Text $text -Key 'DefaultDropModeV4Normal' -JsonValue '"SERVER_PRIVATE"'
    $text = Set-ConfigScalar -Text $text -Key 'BBEXPShareMultiplier' -JsonValue '0'
    $text = Set-ConfigScalar -Text $text -Key 'EnableSwitchAssistByDefault' -JsonValue 'true'
    $text = Set-ConfigScalar -Text $text -Key 'RareNotificationsEnabledByDefaultV3V4' -JsonValue 'true'
    $text = Set-ConfigScalar -Text $text -Key 'CommandData' -JsonValue '"DISABLED"'
    $text = Get-NewservClientPatchConfiguration -Text $text -Profile $ClientPatchProfile

    $portPattern = '(?ms)(\s*"PortConfiguration"\s*:\s*)\{.*?^\s{2}\},\s*\r?\n\s*// Where to listen for IP'
    $portRegex = [regex]::new($portPattern)
    if ($portRegex.Matches($text).Count -ne 1) {
        throw 'Could not locate the PortConfiguration block safely'
    }
    $ports = @'
{
    "bb-patch": [["127.0.0.1", 11000], "patch", "patch_server_bb"],
    "bb-data1": [["127.0.0.1", 12000], "bb", "game_server"],
    "bb-data2": [["127.0.0.1", 12001], "bb", "game_server"],
  },

  // Where to listen for IP
'@
    $text = $portRegex.Replace($text, { param($m) $m.Groups[1].Value + $ports }, 1)

    [System.IO.File]::WriteAllText($ConfigPath, $text, [System.Text.UTF8Encoding]::new($false))
}

function Get-NewservProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [switch]$PassThruIdentity
    )

    if (-not (Test-Path -LiteralPath $Layout.PidFile)) {
        return $null
    }
    try {
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $Layout.PidFile -Root $Layout.Root -Kind File `
                -Label 'server process record')
        if (-not (Test-PSOBBProtectedAcl -Path $Layout.PidFile)) {
            return $null
        }
        $record = Read-PSOBBStrictLifecycleJson `
            -Path $Layout.PidFile -Root $Layout.Root -Contract ServerProcessRecord
        [void](Assert-PSOBBOrdinaryContainedPath `
                -Path $Layout.PidFile -Root $Layout.Root -Kind File `
                -Label 'server process record')
        if (-not (Test-PSOBBProtectedAcl -Path $Layout.PidFile)) {
            return $null
        }
    } catch {
        return $null
    }
    $environmentName = if ($Layout.PSObject.Properties['Environment']) {
        Resolve-PSOBBServerEnvironmentName `
            -Environment ([string]$Layout.Environment)
    } else {
        'Stable'
    }
    $environmentId = if ($Layout.PSObject.Properties['EnvironmentId']) {
        [string]$Layout.EnvironmentId
    } else {
        'stable'
    }
    try {
        $rootLayout = if ($Layout.PSObject.Properties['Environment']) {
            Get-PSOBBLayout -RuntimeRoot ([string]$Layout.Root)
        } else {
            $Layout
        }
        $approvedIdentity = Get-PSOBBApprovedNewservExecutableIdentity `
            -Layout $rootLayout -ServerEnvironment $environmentName
        $componentId = [string]$approvedIdentity.ComponentId
    } catch {
        return $null
    }
    if (($record.schemaVersion -ne 3) -or
        ([string]$record.pid -notmatch '^\d+$') -or
        ([string]$record.startTimeFileTimeUtc -notmatch '^[1-9][0-9]*$') -or
        [string]$record.serverEnvironment -cne $environmentName -or
        [string]$record.environmentId -cne $environmentId -or
        [string]$record.componentId -cne $componentId -or
        [string]$record.executablePath -cne [string]$approvedIdentity.ExecutablePath -or
        [string]$record.executableSha256 -cne [string]$approvedIdentity.Sha256 -or
        [string]$record.startupRequestId -cnotmatch '^[a-f0-9]{32}$' -or
        [string]$record.executableSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$record.controlIdentity -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$record.controlProtocol -cne 'protected-filesystem-exit-v2') {
        return $null
    }
    try {
        $marker = Assert-PSOBBRuntimeMarker -Layout $Layout
        $expectedControlIdentity = Get-PSOBBServerControlIdentity `
            -InstallationId ([string]$marker.installationId) `
            -EnvironmentId $environmentId `
            -ComponentId $componentId `
            -StartupRequestId ([string]$record.startupRequestId) `
            -ExecutableSha256 ([string]$record.executableSha256)
        if (-not (Test-PSOBBFixedTimeTextEquals `
                -Expected $expectedControlIdentity `
                -Actual ([string]$record.controlIdentity))) {
            return $null
        }
    } catch {
        return $null
    }
    $process = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
    if (-not $process -or $process.ProcessName -notlike 'newserv*') {
        if ($process) { $process.Dispose() }
        return $null
    }
    try {
        $expectedPath = [System.IO.Path]::GetFullPath((Join-Path $Layout.Server 'newserv-windows.exe'))
        if (-not ([System.IO.Path]::GetFullPath($process.Path)).Equals(
            $expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $process.Dispose()
            return $null
        }
        if ((Get-LowerSha256 $expectedPath) -ne [string]$record.executableSha256) {
            $process.Dispose()
            return $null
        }
        [DateTimeOffset]::Parse(
            [string]$record.startTimeUtc,
            [System.Globalization.CultureInfo]::InvariantCulture) | Out-Null
        $actualStartTimeFileTimeUtc = [long](
            $process.StartTime.ToUniversalTime().ToFileTimeUtc())
        if ($actualStartTimeFileTimeUtc -ne [long]$record.startTimeFileTimeUtc) {
            $process.Dispose()
            return $null
        }
        if ($PassThruIdentity) {
            return [pscustomobject]@{
                Process = $process
                Record = $record
                StartTimeFileTimeUtc = $actualStartTimeFileTimeUtc
            }
        }
        return $process
    } catch {
        if ($process) { $process.Dispose() }
        return $null
    }
}

function Initialize-PSOBBNativeProcessQuery {
    [CmdletBinding()]
    param()

    if ('PSOBB.Runtime.NativeProcessQuery' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PSOBB.Runtime
{
    public sealed class NativeProcessInfo
    {
        public int ProcessId { get; private set; }
        public string ImagePath { get; private set; }
        public DateTime CreationTimeUtc { get; private set; }
        public long CreationTimeFileTimeUtc { get; private set; }
        public bool IsRunning { get; private set; }

        public NativeProcessInfo(
            int processId,
            string imagePath,
            DateTime creationTimeUtc,
            long creationTimeFileTimeUtc,
            bool isRunning)
        {
            ProcessId = processId;
            ImagePath = imagePath;
            CreationTimeUtc = creationTimeUtc;
            CreationTimeFileTimeUtc = creationTimeFileTimeUtc;
            IsRunning = isRunning;
        }
    }

    public static class NativeProcessQuery
    {
        private const uint ProcessQueryLimitedInformation = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint LowDateTime;
            public uint HighDateTime;

            public long ToInt64()
            {
                return ((long)HighDateTime << 32) | LowDateTime;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(SafeProcessHandle process);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "QueryFullProcessImageNameW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            uint flags,
            StringBuilder imagePath,
            ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            SafeProcessHandle process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        private static Win32Exception LastError(string operation, int processId)
        {
            return new Win32Exception(
                Marshal.GetLastWin32Error(),
                operation + " failed for PID " + processId + ".");
        }

        public static NativeProcessInfo Query(int processId)
        {
            using (SafeProcessHandle handle = OpenProcess(
                ProcessQueryLimitedInformation,
                false,
                processId))
            {
                if (handle == null || handle.IsInvalid)
                {
                    throw LastError("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)", processId);
                }

                uint handleProcessId = GetProcessId(handle);
                if (handleProcessId == 0)
                {
                    throw LastError("GetProcessId", processId);
                }
                if (handleProcessId != (uint)processId)
                {
                    throw new InvalidOperationException(
                        "The opened process handle does not match PID " + processId + ".");
                }

                FileTime creationTime;
                FileTime exitTime;
                FileTime kernelTime;
                FileTime userTime;
                if (!GetProcessTimes(
                    handle,
                    out creationTime,
                    out exitTime,
                    out kernelTime,
                    out userTime))
                {
                    throw LastError("GetProcessTimes", processId);
                }

                StringBuilder imagePath = new StringBuilder(32768);
                int size = imagePath.Capacity;
                if (!QueryFullProcessImageName(handle, 0, imagePath, ref size))
                {
                    throw LastError("QueryFullProcessImageNameW", processId);
                }

                return new NativeProcessInfo(
                    processId,
                    imagePath.ToString(),
                    DateTime.FromFileTimeUtc(creationTime.ToInt64()),
                    creationTime.ToInt64(),
                    true);
            }
        }
    }
}
'@ -ErrorAction Stop
}

function Get-PSOBBNativeProcessInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$ProcessId)

    Initialize-PSOBBNativeProcessQuery
    [PSOBB.Runtime.NativeProcessQuery]::Query($ProcessId)
}

function Test-PSOBBProcessAtExactPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Process,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedPath,
        [ValidateRange(1, 20)][int]$PathProbeAttempts = 10,
        [ValidateRange(0, 1000)][int]$PathProbeDelayMilliseconds = 100
    )

    $expected = [System.IO.Path]::GetFullPath($ExpectedPath)
    $candidateId = 'unknown'
    $candidateIdNumber = $null
    $candidateStartTimeUtc = $null
    $candidateStartTimeFileTimeUtc = $null
    try {
        $candidateId = [string]$Process.Id
        $candidateIdNumber = [int]$Process.Id
    } catch {
        # Keep the stable fallback; the process identity will be rejected below.
    }
    try {
        $candidateStartTimeUtc = $Process.StartTime.ToUniversalTime()
        $candidateStartTimeFileTimeUtc = [long]$candidateStartTimeUtc.ToFileTimeUtc()
    } catch {
        # Path verification can still succeed, but PID-reacquisition below
        # remains fail-closed if the process identity cannot be compared.
    }

    $pathFailure = 'Windows returned no executable path'
    for ($attempt = 1; $attempt -le $PathProbeAttempts; $attempt++) {
        $current = $Process
        if (($attempt -gt 1) -and ($null -ne $candidateIdNumber) -and
            ($Process -is [System.Diagnostics.Process])) {
            $current = Get-Process -Id $candidateIdNumber -ErrorAction SilentlyContinue
            if (-not $current) {
                return $false
            }
            if ($null -ne $candidateStartTimeFileTimeUtc) {
                try {
                    $currentStartTimeFileTimeUtc = [long](
                        $current.StartTime.ToUniversalTime().ToFileTimeUtc())
                    if ($currentStartTimeFileTimeUtc -ne $candidateStartTimeFileTimeUtc) {
                        return $false
                    }
                } catch {
                    $pathFailure = $_.Exception.Message
                    $current = $null
                }
            }
        }

        if ($current) {
            try {
                if ($current -is [System.Diagnostics.Process]) {
                    $current.Refresh()
                }
                if ([bool]$current.HasExited) {
                    return $false
                }
                if ($current -is [System.Diagnostics.Process]) {
                    try {
                        $nativeInfo = Get-PSOBBNativeProcessInfo -ProcessId $candidateIdNumber
                        if (-not $nativeInfo.IsRunning) {
                            return $false
                        }
                        if ($null -ne $candidateStartTimeFileTimeUtc -and
                            [long]$nativeInfo.CreationTimeFileTimeUtc -ne
                                [long]$candidateStartTimeFileTimeUtc) {
                            return $false
                        }
                        $candidateStartTimeUtc = $nativeInfo.CreationTimeUtc
                        $candidateStartTimeFileTimeUtc =
                            [long]$nativeInfo.CreationTimeFileTimeUtc
                        if (-not [string]::IsNullOrWhiteSpace([string]$nativeInfo.ImagePath)) {
                            return ([System.IO.Path]::GetFullPath([string]$nativeInfo.ImagePath)).Equals(
                                $expected, [System.StringComparison]::OrdinalIgnoreCase)
                        }
                        $pathFailure = 'QueryFullProcessImageNameW returned no executable path'
                    } catch {
                        $pathFailure = $_.Exception.Message
                    }
                }

                $managedPath = [string]$current.Path
                if (-not [string]::IsNullOrWhiteSpace($managedPath)) {
                    return ([System.IO.Path]::GetFullPath($managedPath)).Equals(
                        $expected, [System.StringComparison]::OrdinalIgnoreCase)
                }
            } catch {
                $pathFailure = $_.Exception.Message
            }
        }

        $exitedAfterFailure = $false
        try {
            $exitedAfterFailure = [bool]$Process.HasExited
        } catch {
            # An unverifiable process must not be silently accepted as exited.
        }
        if ($exitedAfterFailure) {
            return $false
        }
        if (($attempt -lt $PathProbeAttempts) -and ($PathProbeDelayMilliseconds -gt 0)) {
            Start-Sleep -Milliseconds $PathProbeDelayMilliseconds
        }
    }

    throw "Cannot verify the executable path for $Name PID $candidateId after $PathProbeAttempts attempts. $pathFailure Close it manually and rerun this command."
}

function Get-PSOBBProcessesAtExactPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedPath
    )

    $expected = [System.IO.Path]::GetFullPath($ExpectedPath)
    $matches = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in @(Get-Process -Name $Name -ErrorAction SilentlyContinue)) {
        if (Test-PSOBBProcessAtExactPath -Process $candidate -Name $Name -ExpectedPath $expected) {
            $matches.Add($candidate)
        }
    }
    @($matches)
}

function Get-NewservProcessesAtPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $expectedPath = [System.IO.Path]::GetFullPath((Join-Path $Layout.Server 'newserv-windows.exe'))
    @(Get-PSOBBProcessesAtExactPath -Name 'newserv-windows' -ExpectedPath $expectedPath)
}

function Get-PSOBBApprovedClientIdentity {
    [CmdletBinding()]
    param()

    $lockPath = Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json -Depth 20
    $components = @($lock.components | Where-Object { $_.id -eq 'tethealla-59nl-english' })
    $members = if ($components.Count -eq 1) {
        @($components[0].members | Where-Object { $_.path -eq 'Psobb.exe' })
    } else {
        @()
    }
    if ($members.Count -ne 1 -or
        [string]$members[0].sha256 -notmatch '^[0-9a-f]{64}$' -or
        [long]$members[0].size -le 0) {
        throw 'sources.lock.json does not contain one valid approved PSOBB client executable member'
    }

    [pscustomobject]@{
        Sha256 = [string]$members[0].sha256
        Size = [long]$members[0].size
    }
}

function Resolve-PSOBBClientChannelForServerEnvironment {
    [CmdletBinding()]
    param(
        [string]$ServerEnvironment = 'Stable',
        [AllowNull()][AllowEmptyString()][string]$Channel,
        [ValidateSet('Stable', 'Canary')][string]$DefaultStableChannel = 'Stable',
        [switch]$AllowAll
    )

    $environmentName = Resolve-PSOBBServerEnvironmentName `
        -Environment $ServerEnvironment
    $resolvedChannel = if ([string]::IsNullOrWhiteSpace($Channel)) {
        if ($environmentName -ceq 'CombatCanary') { 'Native' } else { $DefaultStableChannel }
    } else {
        $Channel
    }
    $allowed = if ($environmentName -ceq 'CombatCanary') {
        if ($AllowAll) { @('Native', 'All') } else { @('Native') }
    } else {
        if ($AllowAll) {
            @('Stable', 'Canary', 'LocalLab', 'All')
        } else {
            @('Stable', 'Canary', 'LocalLab')
        }
    }
    if ($resolvedChannel -notin $allowed) {
        throw "Client channel '$resolvedChannel' is not valid for the $environmentName server environment"
    }
    $resolvedChannel
}

function Get-PSOBBClientExecutablePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]
        [ValidateSet('Stable', 'Canary', 'LocalLab', 'Native')][string]$Channel,
        [string]$ServerEnvironment = 'Stable'
    )

    $environmentName = Resolve-PSOBBServerEnvironmentName `
        -Environment $ServerEnvironment
    $resolvedChannel = Resolve-PSOBBClientChannelForServerEnvironment `
        -ServerEnvironment $environmentName -Channel $Channel
    if ($environmentName -ceq 'CombatCanary') {
        $environmentLayout = Get-PSOBBServerEnvironmentLayout `
            -Layout $Layout -Environment $environmentName
        return Join-Path $environmentLayout.Client 'Psobb.exe'
    }

    $clientRoot = if ($resolvedChannel -eq 'Stable') {
        $Layout.Client
    } elseif ($resolvedChannel -eq 'Canary') {
        Join-Path $Layout.Canary 'runtime\client'
    } else {
        Join-Path $Layout.LocalLab 'runtime\client'
    }
    Assert-PathWithinRoot -Path (Join-Path $clientRoot 'Psobb.exe') -Root $Layout.Root
}

function Assert-PSOBBApprovedClientExecutable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $identity = Get-PSOBBApprovedClientIdentity
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "The approved PSOBB client executable is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $identity.Size -or
        (Get-LowerSha256 -Path $item.FullName) -ne $identity.Sha256) {
        throw "The PSOBB client executable does not match the approved size and SHA-256: $Path"
    }
    $identity
}

function Assert-PSOBBExactJsonProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Label
    )

    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if ($actual.Count -ne $expected.Count -or
        [string]::Join("`n", $actual) -cne [string]::Join("`n", $expected)) {
        throw "$Label contains a missing, duplicate, or undeclared property"
    }
    $true
}

function Get-PSOBBLargeAssetsBuildContract {
    [CmdletBinding()]
    param()

    $manifestPath = Join-Path $script:PSOBBRepositoryRoot `
        'src\PSOBB.LargeAssets\build-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "The PSOBB.LargeAssets build manifest is missing: $manifestPath"
    }
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if ($manifestItem.Length -le 0 -or $manifestItem.Length -gt 256KB) {
        throw 'The PSOBB.LargeAssets build manifest has an invalid size'
    }
    try {
        $manifest = Get-Content -Raw -LiteralPath $manifestPath |
            ConvertFrom-Json -Depth 50
    } catch {
        throw "The PSOBB.LargeAssets build manifest is invalid JSON: $($_.Exception.Message)"
    }

    $identity = Get-PSOBBApprovedClientIdentity
    $artifacts = @($manifest.artifacts)
    $sourceInputs = @($manifest.sourceInputs)
    $verificationTool = $manifest.PSObject.Properties['verificationTool']
    if ([int]$manifest.schemaVersion -ne 1 -or
        [string]$manifest.componentId -cne 'project-owned-psobb-large-assets' -or
        [string]$manifest.version -cne '0.1.0-pinned-59nl' -or
        [string]$manifest.baseClient.relativePath -cne 'Psobb.exe' -or
        [long]$manifest.baseClient.size -ne $identity.Size -or
        [string]$manifest.baseClient.sha256 -cne $identity.Sha256 -or
        [string]$manifest.baseClient.imageBase -cne '0x00400000' -or
        [string]$manifest.baseClient.sizeOfImage -cne '0x00762000' -or
        [int]$manifest.patchContract.upstreamAddressEntries -ne 18 -or
        [int]$manifest.patchContract.uniquePatchSites -ne 17 -or
        [uint32]$manifest.patchContract.replacementUint32 -ne 100000000 -or
        $artifacts.Count -ne 1 -or $sourceInputs.Count -lt 1 -or
        $null -eq $verificationTool) {
        throw 'The PSOBB.LargeAssets build manifest does not match the pinned 59NL capability contract'
    }

    $artifact = $artifacts[0]
    $verifier = $verificationTool.Value
    $expectedVerifierOutput = @(
        'fileSizeMatched=true',
        'sha256Matched=true',
        'peContractMatched=true',
        'patchBytesMatched=true',
        'upstreamAddressEntries=18',
        'uniquePatchSites=17',
        'patchValue=100000000')
    if ([string]$artifact.relativeBuildPath -cne
            'src/PSOBB.LargeAssets/bin/build-x86/Release/PSOBB.LargeAssets.asi' -or
        [string]$artifact.runtimeName -cne 'PSOBB.LargeAssets.asi' -or
        [string]$artifact.machine -cne 'x86' -or
        [long]$artifact.size -ne 230400 -or
        [string]$artifact.sha256 -cne
            'bede4e0a9117a10c0b07a32712a04594604eea586dc779b1f81c34ae8a0b0bcf' -or
        [string]$verifier.relativeBuildPath -cne
            'src/PSOBB.LargeAssets/bin/build-x86/Release/PSOBB.LargeAssets.Verify.exe' -or
        [long]$verifier.size -ne 259584 -or
        [string]$verifier.sha256 -cne
            'e0c0c3dc756e733b3399bbefe1e76114c56bed25818b145d77db123c0a0f266a' -or
        [string]::Join("`n", @($verifier.expectedOutputContract)) -cne
            [string]::Join("`n", $expectedVerifierOutput)) {
        throw 'The PSOBB.LargeAssets artifact or exact-client verifier declaration has changed'
    }

    $sourceNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($source in $sourceInputs) {
        $relativePath = ([string]$source.path).Replace('/', '\')
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [System.IO.Path]::IsPathRooted($relativePath) -or
            $relativePath.Contains(':', [System.StringComparison]::Ordinal) -or
            $relativePath -match '(^|[\\/])\.\.([\\/]|$)' -or
            -not $sourceNames.Add($relativePath) -or
            [long]$source.size -le 0 -or
            [string]$source.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The PSOBB.LargeAssets source-input inventory contains an unsafe or duplicate declaration'
        }
        $sourcePath = Assert-PathWithinRoot `
            -Path (Join-Path $script:PSOBBRepositoryRoot $relativePath) `
            -Root $script:PSOBBRepositoryRoot
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "A PSOBB.LargeAssets source input is missing: $relativePath"
        }
        $sourceItem = Get-Item -LiteralPath $sourcePath -Force
        if ($sourceItem.Length -ne [long]$source.size -or
            (Get-LowerSha256 -Path $sourcePath) -cne [string]$source.sha256) {
            throw "A PSOBB.LargeAssets source input no longer matches the build manifest: $relativePath"
        }
    }

    $artifactPath = Assert-PathWithinRoot `
        -Path (Join-Path $script:PSOBBRepositoryRoot `
            ([string]$artifact.relativeBuildPath).Replace('/', '\')) `
        -Root $script:PSOBBRepositoryRoot
    $verifierPath = Assert-PathWithinRoot `
        -Path (Join-Path $script:PSOBBRepositoryRoot `
            ([string]$verifier.relativeBuildPath).Replace('/', '\')) `
        -Root $script:PSOBBRepositoryRoot
    foreach ($candidate in @(
        [pscustomobject]@{ Path = $artifactPath; Declaration = $artifact; Label = 'ASI' },
        [pscustomobject]@{ Path = $verifierPath; Declaration = $verifier; Label = 'verifier' })) {
        if (-not (Test-Path -LiteralPath $candidate.Path -PathType Leaf)) {
            throw "The PSOBB.LargeAssets $($candidate.Label) build artifact is missing: $($candidate.Path)"
        }
        $item = Get-Item -LiteralPath $candidate.Path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne [long]$candidate.Declaration.size -or
            (Get-LowerSha256 -Path $candidate.Path) -cne
                [string]$candidate.Declaration.sha256) {
            throw "The PSOBB.LargeAssets $($candidate.Label) does not match its exact build manifest"
        }
    }

    [pscustomobject]@{
        ComponentId = [string]$manifest.componentId
        Capability = 'large-assets-59nl'
        MaximumAssetBytes = [uint32]$manifest.patchContract.replacementUint32
        ManifestPath = $manifestPath
        ManifestSha256 = Get-LowerSha256 -Path $manifestPath
        ArtifactPath = $artifactPath
        ArtifactSize = [long]$artifact.size
        ArtifactSha256 = [string]$artifact.sha256
        VerifierPath = $verifierPath
        VerifierSize = [long]$verifier.size
        VerifierSha256 = [string]$verifier.sha256
        VerifierOutputContract = @($verifier.expectedOutputContract)
    }
}

function Assert-PSOBBLargeAssetsVerifierOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StandardOutput,
        [Parameter(Mandatory)][string[]]$ExpectedContract,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )

    if ($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The expected PSOBB executable SHA-256 is invalid'
    }
    $lines = @($StandardOutput -split "`r?`n" | Where-Object { $_.Length -gt 0 })
    foreach ($expectedLine in @($ExpectedContract)) {
        if ($lines -cnotcontains [string]$expectedLine) {
            throw "The PSOBB.LargeAssets exact-client verifier omitted '$expectedLine'"
        }
    }

    $hashPrefix = 'actualSha256='
    $hashLines = @($lines | Where-Object {
        $_.StartsWith($hashPrefix, [System.StringComparison]::Ordinal)
    })
    if ($hashLines.Count -ne 1 -or
        $hashLines[0] -cnotmatch '^actualSha256=[A-Fa-f0-9]{64}$') {
        throw 'The PSOBB.LargeAssets exact-client verifier did not report exactly one valid executable SHA-256'
    }
    $actualSha256 = $hashLines[0].Substring($hashPrefix.Length)
    if (-not $actualSha256.Equals(
        $ExpectedSha256,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The PSOBB.LargeAssets exact-client verifier reported an unexpected executable SHA-256'
    }
    $true
}

function Invoke-PSOBBLargeAssetsExactClientVerifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientExecutablePath,
        [Parameter(Mandatory)]$BuildContract
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [string]$BuildContract.VerifierPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    [void]$startInfo.ArgumentList.Add($ClientExecutablePath)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Windows did not start the PSOBB.LargeAssets exact-client verifier'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($stderr)) {
            throw "The PSOBB.LargeAssets exact-client verifier failed with exit code $($process.ExitCode): $($stderr.Trim())"
        }
        Assert-PSOBBLargeAssetsVerifierOutput `
            -StandardOutput $stdout `
            -ExpectedContract @($BuildContract.VerifierOutputContract) `
            -ExpectedSha256 (Get-LowerSha256 -Path $ClientExecutablePath) | Out-Null
        $true
    } finally {
        $process.Dispose()
    }
}

function Get-PSOBBClientDataManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ClientRoot)

    $dataRoot = Assert-PathWithinRoot -Path (Join-Path $ClientRoot 'data') `
        -Root $ClientRoot
    if (-not (Test-Path -LiteralPath $dataRoot -PathType Container)) {
        throw 'The LocalLab client data directory is missing'
    }
    @(Get-PSOBBDirectoryManifest -Root $dataRoot | ForEach-Object {
        [ordered]@{
            path = 'data/' + [string]$_.path
            size = [long]$_.size
            sha256 = [string]$_.sha256
        }
    })
}

function ConvertFrom-PSOBBActivationManifestJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Json)

    try {
        ConvertFrom-Json -InputObject $Json -Depth 30 -DateKind String `
            -ErrorAction Stop
    } catch {
        throw "The LocalLab asset activation manifest is invalid JSON: $($_.Exception.Message)"
    }
}

function Assert-PSOBBActivationManifestTimestamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Activation)

    $timestampProperty = $Activation.PSObject.Properties['createdAtUtc']
    [DateTimeOffset]$activationCreated = [DateTimeOffset]::MinValue
    if ($null -eq $timestampProperty -or
        $timestampProperty.Value -isnot [string] -or
        -not [DateTimeOffset]::TryParseExact(
            [string]$timestampProperty.Value,
            'o',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$activationCreated)) {
        throw 'The LocalLab asset activation timestamp is invalid'
    }
    $activationCreated
}

function Assert-PSOBBLocalVisualAssetSnapshotContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ComponentId,
        [Parameter(Mandatory)][string]$SnapshotId,
        [AllowEmptyCollection()][Parameter(Mandatory)][object[]]$ActivationFiles,
        [AllowEmptyCollection()][object[]]$PriorEntries = @()
    )

    $componentRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.LocalLab (
            "visual-asset-activations\$ComponentId")) `
        -Root $Layout.LocalLab
    $snapshotRoot = Assert-PathWithinRoot `
        -Path (Join-Path $componentRoot "snapshots\$SnapshotId") `
        -Root $componentRoot
    if (-not (Test-Path -LiteralPath $snapshotRoot -PathType Container)) {
        throw "The LocalLab visual-asset rollback snapshot is missing: $ComponentId"
    }
    $snapshotRootItem = Get-Item -LiteralPath $snapshotRoot -Force
    $reparsePoint = Get-ChildItem -LiteralPath $snapshotRoot -Force -Recurse `
        -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object -First 1
    if (($snapshotRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $reparsePoint) {
        throw "The LocalLab visual-asset rollback snapshot contains a reparse point: $ComponentId"
    }

    $snapshotPath = Join-Path $snapshotRoot 'snapshot.json'
    if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) {
        throw "The LocalLab visual-asset rollback manifest is missing: $ComponentId"
    }
    $snapshotItem = Get-Item -LiteralPath $snapshotPath -Force
    if ($snapshotItem.Length -le 0 -or $snapshotItem.Length -gt 2MB) {
        throw "The LocalLab visual-asset rollback manifest has an invalid size: $ComponentId"
    }
    try {
        $snapshot = Get-Content -Raw -LiteralPath $snapshotPath |
            ConvertFrom-Json -Depth 50 -DateKind String -ErrorAction Stop
    } catch {
        throw "The LocalLab visual-asset rollback manifest is invalid JSON: $ComponentId"
    }
    Assert-PSOBBExactJsonProperties -Object $snapshot `
        -Label 'LocalLab visual-asset rollback manifest' -Names @(
            'schemaVersion', 'componentId', 'snapshotId', 'createdAtUtc',
            'profileBeforeSize', 'profileBeforeSha256', 'files') | Out-Null
    Assert-PSOBBActivationManifestTimestamp -Activation $snapshot | Out-Null

    $expectedFiles = @($ActivationFiles)
    $snapshotFiles = @($snapshot.files)
    if ([int]$snapshot.schemaVersion -ne 1 -or
        [string]$snapshot.componentId -cne $ComponentId -or
        [string]$snapshot.snapshotId -cne $SnapshotId -or
        $snapshotFiles.Count -ne $expectedFiles.Count -or
        [long]$snapshot.profileBeforeSize -le 0 -or
        [string]$snapshot.profileBeforeSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "The LocalLab visual-asset rollback manifest disagrees with its activation: $ComponentId"
    }

    $expectedInventoryPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    [void]$expectedInventoryPaths.Add('snapshot.json')
    [void]$expectedInventoryPaths.Add('client-profile.before.json')
    for ($index = 0; $index -lt $snapshotFiles.Count; $index++) {
        $file = $snapshotFiles[$index]
        Assert-PSOBBExactJsonProperties -Object $file `
            -Label 'LocalLab visual-asset rollback file' -Names @(
                'destinationPath', 'previousExisted', 'previousSize',
                'previousSha256', 'snapshotPath') | Out-Null
        $destinationPath = [string]$file.destinationPath
        if ($destinationPath -cne [string]$expectedFiles[$index].destinationPath -or
            $destinationPath -cnotmatch
                '^data/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:bml|prs|xvm)$' -or
            $file.previousExisted -isnot [bool]) {
            throw "The LocalLab visual-asset rollback file is unsafe or reordered: $destinationPath"
        }
        if ([bool]$file.previousExisted) {
            $expectedSnapshotPath = "previous/$index.bin"
            if ([string]$file.snapshotPath -cne $expectedSnapshotPath -or
                [long]$file.previousSize -le 0 -or
                [string]$file.previousSha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw "The LocalLab visual-asset previous-file declaration is invalid: $destinationPath"
            }
            $previousPath = Assert-PathWithinRoot `
                -Path (Join-Path $snapshotRoot `
                    $expectedSnapshotPath.Replace('/', '\')) `
                -Root $snapshotRoot
            if (-not (Test-Path -LiteralPath $previousPath -PathType Leaf) -or
                (Get-Item -LiteralPath $previousPath -Force).Length -ne
                    [long]$file.previousSize -or
                (Get-LowerSha256 -Path $previousPath) -cne
                    [string]$file.previousSha256) {
                throw "The LocalLab visual-asset previous file has drifted: $destinationPath"
            }
            [void]$expectedInventoryPaths.Add($expectedSnapshotPath)
        } elseif ([long]$file.previousSize -ne 0 -or
            $null -ne $file.previousSha256 -or $null -ne $file.snapshotPath) {
            throw "The LocalLab visual-asset rollback unexpectedly declares a previous file: $destinationPath"
        }
    }

    $profileBeforePath = Join-Path $snapshotRoot 'client-profile.before.json'
    if (-not (Test-Path -LiteralPath $profileBeforePath -PathType Leaf) -or
        (Get-Item -LiteralPath $profileBeforePath -Force).Length -ne
            [long]$snapshot.profileBeforeSize -or
        (Get-LowerSha256 -Path $profileBeforePath) -cne
            [string]$snapshot.profileBeforeSha256) {
        throw "The LocalLab visual-asset rollback profile has drifted: $ComponentId"
    }
    try {
        $profileBefore = Get-Content -Raw -LiteralPath $profileBeforePath |
            ConvertFrom-Json -Depth 50 -DateKind String -ErrorAction Stop
    } catch {
        throw "The LocalLab visual-asset rollback profile is invalid JSON: $ComponentId"
    }
    $priorProperty = $profileBefore.PSObject.Properties['localVisualAssets']
    $expectedPriorEntries = @($PriorEntries)
    if ($expectedPriorEntries.Count -eq 0) {
        if ($null -ne $priorProperty) {
            throw "The LocalLab visual-asset rollback profile contains an unexpected prior stack: $ComponentId"
        }
    } elseif ($null -eq $priorProperty -or $null -eq $priorProperty.Value -or
        @($priorProperty.Value).Count -ne $expectedPriorEntries.Count) {
        throw "The LocalLab visual-asset rollback profile is missing its prior stack: $ComponentId"
    } else {
        $actualPriorEntries = @($priorProperty.Value)
        for ($index = 0; $index -lt $expectedPriorEntries.Count; $index++) {
            $actualJson = $actualPriorEntries[$index] |
                ConvertTo-Json -Depth 20 -Compress
            $expectedJson = $expectedPriorEntries[$index] |
                ConvertTo-Json -Depth 20 -Compress
            if ($actualJson -cne $expectedJson) {
                throw "The LocalLab visual-asset rollback profile has a reordered or changed prior stack: $ComponentId"
            }
        }
    }

    $actualInventory = @(Get-PSOBBDirectoryManifest -Root $snapshotRoot)
    if ($actualInventory.Count -ne $expectedInventoryPaths.Count -or
        @($actualInventory | Where-Object {
            -not $expectedInventoryPaths.Contains([string]$_.path)
        }).Count -gt 0) {
        throw "The LocalLab visual-asset rollback snapshot contains an undeclared file: $ComponentId"
    }

    [pscustomobject]@{
        Snapshot = $snapshot
        SnapshotRoot = $snapshotRoot
        ProfileBefore = $profileBefore
        ProfileBeforePath = $profileBeforePath
    }
}

function Assert-PSOBBLocalVisualAssetCandidateDisposition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComponentId,
        [Parameter(Mandatory)]$SourceComponent,
        [Parameter(Mandatory)]$Evidence
    )

    $candidateMatches = @($Evidence.assetCandidates | Where-Object {
        [string]$_.componentId -ceq $ComponentId
    })
    if ($candidateMatches.Count -ne 1) {
        throw "Graphics evidence must declare exactly one candidate named '$ComponentId'"
    }

    $disposition = [string]$candidateMatches[0].disposition
    $compatibilityState = [string]$SourceComponent.compatibilityState
    if ($disposition -ceq 'rejected' -or
        $compatibilityState.StartsWith(
            'rejected-', [StringComparison]::Ordinal)) {
        if ($disposition -cne 'rejected' -or
            -not $compatibilityState.StartsWith(
                'rejected-', [StringComparison]::Ordinal)) {
            throw "The source lock and graphics evidence disagree about the rejected local visual asset: $ComponentId"
        }
        throw "The local visual-asset candidate is rejected for this exact client stack: $ComponentId"
    }
    if ($disposition -cnotin @('pending', 'accepted')) {
        throw "The local visual-asset candidate has an unsupported disposition: $ComponentId"
    }

    $candidateMatches[0]
}

function Add-PSOBBLocalVisualAssetContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ClientRoot,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$ExpectedData,
        [Parameter(Mandatory)][bool]$HasAshenbubs
    )

    $property = $Profile.PSObject.Properties['localVisualAssets']
    if ($null -eq $property -or $null -eq $property.Value) {
        return @()
    }
    $entries = @($property.Value)
    if ($entries.Count -lt 1 -or $entries.Count -gt 4 -or
        [string]$Profile.profileId -cnotin @(
            'lab-widescreen-16x10', 'lab-widescreen-hd-16x10')) {
        throw 'The LocalLab visual-asset declaration has an invalid count or profile scope'
    }
    if (-not $HasAshenbubs) {
        throw 'Supplemental visual assets require the full AshenbubsHD All foundation'
    }

    $sources = Get-Content -Raw -LiteralPath (
        Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json') |
        ConvertFrom-Json -Depth 100
    $evidence = Get-Content -Raw -LiteralPath (
        Join-Path $script:PSOBBRepositoryRoot 'config\graphics-evidence.json') |
        ConvertFrom-Json -Depth 100
    $identity = Get-PSOBBApprovedClientIdentity
    $componentIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $approvedComponentIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($approvedComponentId in @(
        'luthee-hd-ui-v1.1.6-local-import',
        'higher-resolution-item-box-textures-2025-12-30-local-import',
        'echelon-hd-effects-technics-2019-05-27-local-import',
        'echelon-hd-blood-2018-06-16-local-import')) {
        [void]$approvedComponentIds.Add($approvedComponentId)
    }
    $destinationPaths = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $priorEntries = [Collections.Generic.List[object]]::new()
    $previousSnapshotId = $null

    foreach ($entry in $entries) {
        Assert-PSOBBExactJsonProperties -Object $entry `
            -Label 'LocalLab visual-asset declaration' -Names @(
                'schemaVersion', 'componentId', 'version', 'distributionClass',
                'replacementPolicy', 'activationManifestPath',
                'activationManifestSha256', 'sourceArchiveSha256', 'snapshotId',
                'fileCount', 'totalBytes') | Out-Null

        $componentId = [string]$entry.componentId
        if ([int]$entry.schemaVersion -ne 1 -or
            -not $approvedComponentIds.Contains($componentId) -or
            -not $componentIds.Add($componentId) -or
            [string]$entry.distributionClass -cne 'local-only' -or
            [string]$entry.activationManifestPath -cne
                "visual-asset-activations/$componentId/current/activation.json" -or
            [string]$entry.activationManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$entry.sourceArchiveSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$entry.snapshotId -cnotmatch
                '^activation-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$' -or
            [int]$entry.fileCount -le 0 -or [long]$entry.totalBytes -le 0) {
            throw "The LocalLab visual-asset declaration is invalid: $componentId"
        }
        if ($null -ne $previousSnapshotId -and
            [StringComparer]::Ordinal.Compare(
                [string]$previousSnapshotId,
                [string]$entry.snapshotId) -ge 0) {
            throw 'The LocalLab visual-asset stack is not in activation order'
        }

        $components = @($sources.components | Where-Object {
            [string]$_.id -ceq $componentId
        })
        if ($components.Count -ne 1 -or
            [string]$components[0].distributionClass -cne 'local-only' -or
            [string]$components[0].version -cne [string]$entry.version -or
            [string]$components[0].sha256 -cne
                [string]$entry.sourceArchiveSha256 -or
            @($components[0].members).Count -ne [int]$entry.fileCount) {
            throw "The LocalLab visual asset is not bound to its exact source lock: $componentId"
        }
        $component = $components[0]
        Assert-PSOBBLocalVisualAssetCandidateDisposition `
            -ComponentId $componentId -SourceComponent $component `
            -Evidence $evidence | Out-Null
        $expectedReplacementPolicy = switch ($componentId) {
            'echelon-hd-effects-technics-2019-05-27-local-import' {
                'reject-ashenbubs-collision'
            }
            'echelon-hd-blood-2018-06-16-local-import' {
                'reject-ashenbubs-collision'
            }
            default { 'none' }
        }
        if ([string]$entry.replacementPolicy -cne $expectedReplacementPolicy) {
            throw "The LocalLab visual asset violates its collision policy: $componentId"
        }

        $activationPath = Assert-PathWithinRoot `
            -Path (Join-Path $Layout.LocalLab `
                ([string]$entry.activationManifestPath).Replace('/', '\')) `
            -Root $Layout.LocalLab
        if (-not (Test-Path -LiteralPath $activationPath -PathType Leaf) -or
            (Get-LowerSha256 -Path $activationPath) -cne
                [string]$entry.activationManifestSha256) {
            throw "The LocalLab visual-asset activation record is missing or stale: $componentId"
        }
        $activationRoot = Split-Path -Parent $activationPath
        $activationInventory = @(Get-PSOBBDirectoryManifest -Root $activationRoot)
        if ($activationInventory.Count -ne 1 -or
            [string]$activationInventory[0].path -cne 'activation.json') {
            throw "The LocalLab visual-asset activation directory contains an extra file: $componentId"
        }
        $activation = ConvertFrom-PSOBBActivationManifestJson `
            -Json (Get-Content -Raw -LiteralPath $activationPath)
        Assert-PSOBBExactJsonProperties -Object $activation `
            -Label 'LocalLab visual-asset activation manifest' -Names @(
                'schemaVersion', 'componentId', 'version', 'distributionClass',
                'replacementPolicy', 'profileId', 'baseExecutableSha256',
                'sourceArchiveSha256', 'snapshotId', 'createdAtUtc', 'files') |
            Out-Null
        Assert-PSOBBActivationManifestTimestamp -Activation $activation | Out-Null
        foreach ($field in @(
            'componentId', 'version', 'distributionClass', 'replacementPolicy',
            'sourceArchiveSha256', 'snapshotId')) {
            if ([string]$activation.$field -cne [string]$entry.$field) {
                throw "The visual-asset activation disagrees with profile field '$field'"
            }
        }
        if ([int]$activation.schemaVersion -ne 1 -or
            [string]$activation.profileId -cne [string]$Profile.profileId -or
            [string]$activation.baseExecutableSha256 -cne $identity.Sha256 -or
            @($activation.files).Count -ne [int]$entry.fileCount) {
            throw "The visual-asset activation is not bound to the exact client/profile: $componentId"
        }

        [long]$totalBytes = 0
        foreach ($file in @($activation.files)) {
            Assert-PSOBBExactJsonProperties -Object $file `
                -Label 'LocalLab visual-asset file' -Names @(
                    'archivePath', 'destinationPath', 'size', 'sha256') | Out-Null
            $destinationPath = [string]$file.destinationPath
            $lockedMembers = @($component.members | Where-Object {
                [string]$_.path -ceq [string]$file.archivePath -and
                [string]$_.destinationPath -ceq $destinationPath -and
                [long]$_.size -eq [long]$file.size -and
                [string]$_.sha256 -ceq [string]$file.sha256
            })
            if ($lockedMembers.Count -ne 1 -or
                $destinationPath -cnotmatch
                    '^data/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:bml|prs|xvm)$' -or
                -not $destinationPaths.Add($destinationPath) -or
                [long]$file.size -le 0 -or
                [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$') {
                throw "The LocalLab visual-asset file is unsafe, duplicate, or unlocked: $destinationPath"
            }

            $prior = if ($ExpectedData.ContainsKey($destinationPath)) {
                $ExpectedData[$destinationPath]
            } else { $null }
            $replacesAshenbubs = $HasAshenbubs -and $null -ne $prior -and
                $prior.PSObject.Properties['overlay'] -and [bool]$prior.overlay
            if ($replacesAshenbubs) {
                throw "AshenbubsHD All is the immutable visual foundation; another asset cannot replace $destinationPath"
            }

            $actualPath = Assert-PathWithinRoot `
                -Path (Join-Path $ClientRoot $destinationPath.Replace('/', '\')) `
                -Root $ClientRoot
            if (-not (Test-Path -LiteralPath $actualPath -PathType Leaf) -or
                (Get-Item -LiteralPath $actualPath -Force).Length -ne
                    [long]$file.size -or
                (Get-LowerSha256 -Path $actualPath) -cne [string]$file.sha256) {
                throw "A LocalLab visual asset has drifted: $destinationPath"
            }
            $ExpectedData[$destinationPath] = [pscustomobject]@{
                path = $destinationPath
                size = [long]$file.size
                sha256 = [string]$file.sha256
                overlay = $true
                visualAssetComponentId = $componentId
            }
            $totalBytes += [long]$file.size
        }
        if ($totalBytes -ne [long]$entry.totalBytes) {
            throw "The LocalLab visual-asset byte total has changed: $componentId"
        }
        Assert-PSOBBLocalVisualAssetSnapshotContract `
            -Layout $Layout `
            -ComponentId $componentId `
            -SnapshotId ([string]$entry.snapshotId) `
            -ActivationFiles @($activation.files) `
            -PriorEntries @($priorEntries) | Out-Null
        $priorEntries.Add($entry)
        $previousSnapshotId = [string]$entry.snapshotId
    }
    $entries
}

function Assert-PSOBBLocalAssetOverlayContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ClientRoot,
        [Parameter(Mandatory)][string]$ClientExecutablePath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)]$ExpectedLoadablePaths
    )

    $overlayProperty = $Profile.PSObject.Properties['localAssetOverlay']
    $modulesProperty = $Profile.PSObject.Properties['localModules']
    $largeAssetsIniPath = Join-Path $ClientRoot 'plugins\PSOBB.LargeAssets.ini'
    if ($null -eq $overlayProperty -and $null -eq $modulesProperty) {
        if ([string]$Profile.profileId -ceq 'lab-widescreen-hd-16x10') {
            throw 'The LocalLab HD profile requires its exact asset overlay and large-assets module declarations'
        }
        if (Test-Path -LiteralPath $largeAssetsIniPath) {
            throw 'The LocalLab runtime contains an undeclared PSOBB.LargeAssets configuration'
        }
        $baseManifest = Get-Content -Raw -LiteralPath $Layout.BaseClientManifest |
            ConvertFrom-Json -Depth 30
        if ([int]$baseManifest.schemaVersion -ne 1) {
            throw 'The immutable base-client manifest is invalid during visual-asset verification'
        }
        $expectedData = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($baseFile in @($baseManifest.files | Where-Object {
            ([string]$_.path).StartsWith(
                'data/',
                [StringComparison]::OrdinalIgnoreCase)
        })) {
            $expectedData.Add([string]$baseFile.path, [pscustomobject]@{
                path = [string]$baseFile.path
                size = [long]$baseFile.size
                sha256 = [string]$baseFile.sha256
                overlay = $false
            })
        }
        Add-PSOBBLocalVisualAssetContract `
            -Layout $Layout -ClientRoot $ClientRoot -Profile $Profile `
            -ExpectedData $expectedData -HasAshenbubs:$false | Out-Null
        $actualData = @(Get-PSOBBClientDataManifest -ClientRoot $ClientRoot)
        if ($actualData.Count -ne $expectedData.Count -or
            ($expectedData.Count -gt 0 -and
                -not (Test-PSOBBManifestEntriesEqual `
                    -Left $actualData -Right @($expectedData.Values)))) {
            throw 'The LocalLab client without Ashenbubs does not match its exact base-plus-visual-assets manifest'
        }
        return $null
    }
    if ($null -eq $overlayProperty -or $null -eq $modulesProperty -or
        $null -eq $overlayProperty.Value) {
        throw 'The LocalLab asset overlay and local module declarations must be present together'
    }

    $overlay = $overlayProperty.Value
    Assert-PSOBBExactJsonProperties -Object $overlay -Label 'LocalLab asset overlay declaration' -Names @(
        'schemaVersion', 'componentId', 'version', 'distributionClass', 'selection',
        'baseProfileId',
        'activationManifestPath', 'activationManifestSha256', 'sourceArchiveSha256',
        'stagedManifestSha256', 'snapshotId', 'sourceEntryCount', 'composedFileCount',
        'sourceExpandedAssetBytes', 'composedAssetBytes') | Out-Null
    $modules = @($modulesProperty.Value)
    if ($modules.Count -ne 1) {
        throw 'The LocalLab asset overlay requires exactly one project-owned local module'
    }
    $module = $modules[0]
    Assert-PSOBBExactJsonProperties -Object $module -Label 'LocalLab large-assets module declaration' -Names @(
        'componentId', 'capability', 'relativePath', 'size', 'sha256',
        'configurationPath', 'configurationSha256', 'buildManifestSha256') | Out-Null

    $constantActivationPath =
        'asset-activations/ashenbubs-hd-psobb-v1.02/current/activation.json'
    if ([int]$overlay.schemaVersion -ne 1 -or
        [string]$overlay.componentId -cne 'ashenbubs-hd-psobb-v1.02-local-import' -or
        [string]$overlay.version -cne '1.02' -or
        [string]$overlay.distributionClass -cne 'local-only' -or
        [string]$overlay.selection -cne 'All' -or
        [string]$overlay.baseProfileId -cne 'lab-widescreen-16x10' -or
        [string]$overlay.activationManifestPath -cne $constantActivationPath -or
        [string]$overlay.activationManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$overlay.sourceArchiveSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$overlay.stagedManifestSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$overlay.snapshotId -cnotmatch '^activation-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$' -or
        [int]$overlay.sourceEntryCount -le 0 -or
        [int]$overlay.composedFileCount -le 0 -or
        [int]$overlay.composedFileCount -gt [int]$overlay.sourceEntryCount -or
        [long]$overlay.sourceExpandedAssetBytes -le 0 -or
        [long]$overlay.composedAssetBytes -le 0) {
        throw 'The LocalLab asset overlay declaration is not the approved private AshenbubsHD contract'
    }

    $activationPath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.LocalLab `
            ([string]$overlay.activationManifestPath).Replace('/', '\')) `
        -Root $Layout.LocalLab
    if (-not (Test-Path -LiteralPath $activationPath -PathType Leaf) -or
        (Get-LowerSha256 -Path $activationPath) -cne
            [string]$overlay.activationManifestSha256) {
        throw 'The LocalLab asset activation manifest is missing or hash-mismatched'
    }
    $activationRoot = Split-Path -Parent $activationPath
    $activationInventory = @(Get-PSOBBDirectoryManifest -Root $activationRoot)
    if ($activationInventory.Count -ne 1 -or
        [string]$activationInventory[0].path -cne 'activation.json' -or
        [string]$activationInventory[0].sha256 -cne
            [string]$overlay.activationManifestSha256) {
        throw 'The LocalLab asset activation record contains an undeclared extra file'
    }
    $activationItem = Get-Item -LiteralPath $activationPath -Force
    if ($activationItem.Length -le 0 -or $activationItem.Length -gt 1MB) {
        throw 'The LocalLab asset activation manifest has an invalid size'
    }
    $activation = ConvertFrom-PSOBBActivationManifestJson `
        -Json (Get-Content -Raw -LiteralPath $activationPath)
    Assert-PSOBBExactJsonProperties -Object $activation `
        -Label 'LocalLab asset activation manifest' -Names @(
            'schemaVersion', 'componentId', 'version', 'distributionClass', 'selection',
            'profileId', 'baseProfileId', 'baseExecutableSha256', 'sourceArchiveSha256',
            'stagedManifestSha256', 'snapshotId', 'sourceEntryCount',
            'composedFileCount', 'sourceExpandedAssetBytes', 'composedAssetBytes',
            'createdAtUtc', 'files', 'module') | Out-Null
    Assert-PSOBBExactJsonProperties -Object $activation.module `
        -Label 'LocalLab activation module' -Names @(
            'componentId', 'capability', 'relativePath', 'size', 'sha256',
            'configurationPath', 'configurationSha256', 'buildManifestSha256') | Out-Null

    $identity = Get-PSOBBApprovedClientIdentity
    foreach ($field in @(
        'componentId', 'version', 'distributionClass', 'selection', 'baseProfileId',
        'sourceArchiveSha256', 'stagedManifestSha256', 'snapshotId',
        'sourceEntryCount', 'composedFileCount', 'sourceExpandedAssetBytes',
        'composedAssetBytes')) {
        if ([string]$activation.$field -cne [string]$overlay.$field) {
            throw "The LocalLab asset activation manifest disagrees with profile field '$field'"
        }
    }
    if ([int]$activation.schemaVersion -ne 1 -or
        [string]$activation.profileId -cne 'lab-widescreen-hd-16x10' -or
        [string]$activation.profileId -cne [string]$Profile.profileId -or
        [string]$activation.baseProfileId -cne 'lab-widescreen-16x10' -or
        [string]$Profile.rollbackProfileId -cne 'lab-widescreen-16x10' -or
        [string]$activation.baseExecutableSha256 -cne $identity.Sha256 -or
        @($activation.files).Count -ne [int]$overlay.composedFileCount) {
        throw 'The LocalLab asset activation is not bound to this exact materialized client profile'
    }
    Assert-PSOBBActivationManifestTimestamp -Activation $activation | Out-Null

    $sourcesPath = Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'
    $sources = Get-Content -Raw -LiteralPath $sourcesPath | ConvertFrom-Json -Depth 100
    $assetComponents = @($sources.components | Where-Object {
        [string]$_.id -ceq 'ashenbubs-hd-psobb-v1.02-local-import'
    })
    if ($assetComponents.Count -ne 1 -or
        [string]$assetComponents[0].distributionClass -cne 'local-only' -or
        [string]$assetComponents[0].sha256 -cne
            [string]$overlay.sourceArchiveSha256 -or
        [string]$assetComponents[0].activationRequirements.requiredClientExecutableSha256 -cne
            $identity.Sha256 -or
        [string]$assetComponents[0].activationRequirements.requiredComponentId -cne
            'project-owned-psobb-large-assets' -or
        [string]$assetComponents[0].activationRequirements.requiredCapability -cne
            'large-assets-59nl' -or
        [long]$assetComponents[0].activationRequirements.requiredMaximumAssetBytes -ne
            100000000) {
        throw 'The LocalLab activated assets are not bound to the approved source and activation gate'
    }

    $build = Get-PSOBBLargeAssetsBuildContract
    foreach ($field in @('componentId', 'capability', 'relativePath', 'size', 'sha256',
        'configurationPath', 'configurationSha256', 'buildManifestSha256')) {
        if ([string]$activation.module.$field -cne [string]$module.$field) {
            throw "The LocalLab activation module disagrees with profile field '$field'"
        }
    }
    if ([string]$module.componentId -cne $build.ComponentId -or
        [string]$module.capability -cne $build.Capability -or
        [string]$module.relativePath -cne 'plugins/PSOBB.LargeAssets.asi' -or
        [long]$module.size -ne $build.ArtifactSize -or
        [string]$module.sha256 -cne $build.ArtifactSha256 -or
        [string]$module.configurationPath -cne 'plugins/PSOBB.LargeAssets.ini' -or
        [string]$module.configurationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$module.buildManifestSha256 -cne $build.ManifestSha256) {
        throw 'The LocalLab asset activation does not declare the exact project-owned large-assets build'
    }

    $largeAssetsPath = Assert-PathWithinRoot `
        -Path (Join-Path $ClientRoot ([string]$module.relativePath).Replace('/', '\')) `
        -Root $ClientRoot
    $largeAssetsIniPath = Assert-PathWithinRoot `
        -Path (Join-Path $ClientRoot ([string]$module.configurationPath).Replace('/', '\')) `
        -Root $ClientRoot
    if (-not (Test-Path -LiteralPath $largeAssetsPath -PathType Leaf) -or
        (Get-Item -LiteralPath $largeAssetsPath -Force).Length -ne [long]$module.size -or
        (Get-LowerSha256 -Path $largeAssetsPath) -cne [string]$module.sha256 -or
        -not (Test-Path -LiteralPath $largeAssetsIniPath -PathType Leaf) -or
        (Get-LowerSha256 -Path $largeAssetsIniPath) -cne
            [string]$module.configurationSha256) {
        throw 'The LocalLab large-assets ASI or configuration has drifted'
    }
    $expectedIni = "[LargeAssets]`r`nEnabled=1`r`n"
    if ((Get-Content -Raw -LiteralPath $largeAssetsIniPath) -cne $expectedIni) {
        throw 'The LocalLab large-assets configuration must contain only [LargeAssets] Enabled=1'
    }
    $ExpectedLoadablePaths.Add('plugins\PSOBB.LargeAssets.asi') | Out-Null
    Invoke-PSOBBLargeAssetsExactClientVerifier `
        -ClientExecutablePath $ClientExecutablePath `
        -BuildContract $build | Out-Null

    $baseManifest = Get-Content -Raw -LiteralPath $Layout.BaseClientManifest |
        ConvertFrom-Json -Depth 30
    if ([int]$baseManifest.schemaVersion -ne 1) {
        throw 'The immutable base-client manifest is invalid during asset verification'
    }
    $expectedData = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($baseFile in @($baseManifest.files | Where-Object {
        ([string]$_.path).StartsWith('data/', [System.StringComparison]::OrdinalIgnoreCase)
    })) {
        $expectedData.Add([string]$baseFile.path, [pscustomobject]@{
            path = [string]$baseFile.path
            size = [long]$baseFile.size
            sha256 = [string]$baseFile.sha256
            overlay = $false
        })
    }

    $assetNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [long]$composedBytes = 0
    foreach ($file in @($activation.files)) {
        Assert-PSOBBExactJsonProperties -Object $file `
            -Label 'LocalLab activated asset entry' -Names @('path', 'size', 'sha256') |
            Out-Null
        $relativePath = [string]$file.path
        if ($relativePath -cnotmatch '^data/(?:scene/)?[A-Za-z0-9_.-]+\.(?:afs|bml|xvm)$' -or
            -not $assetNames.Add($relativePath) -or
            [long]$file.size -le 0 -or
            [long]$file.size -gt $build.MaximumAssetBytes -or
            [string]$file.sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw "The LocalLab activation manifest contains an unsafe or duplicate asset: $relativePath"
        }
        $actualPath = Assert-PathWithinRoot `
            -Path (Join-Path $ClientRoot $relativePath.Replace('/', '\')) `
            -Root $ClientRoot
        if (-not (Test-Path -LiteralPath $actualPath -PathType Leaf) -or
            (Get-Item -LiteralPath $actualPath -Force).Length -ne [long]$file.size -or
            (Get-LowerSha256 -Path $actualPath) -cne [string]$file.sha256) {
            throw "A LocalLab AshenbubsHD asset has drifted: $relativePath"
        }
        $expectedData[$relativePath] = [pscustomobject]@{
            path = $relativePath
            size = [long]$file.size
            sha256 = [string]$file.sha256
            overlay = $true
        }
        $composedBytes += [long]$file.size
    }
    if ($assetNames.Count -ne [int]$overlay.composedFileCount -or
        $composedBytes -ne [long]$overlay.composedAssetBytes) {
        throw 'The LocalLab activated asset count or composed byte total has changed'
    }

    Add-PSOBBLocalVisualAssetContract `
        -Layout $Layout -ClientRoot $ClientRoot -Profile $Profile `
        -ExpectedData $expectedData -HasAshenbubs:$true | Out-Null

    if (-not (Test-PSOBBManifestEntriesEqual `
        -Left (Get-PSOBBClientDataManifest -ClientRoot $ClientRoot) `
        -Right @($expectedData.Values))) {
        throw 'The LocalLab data tree contains a missing, changed, or undeclared extra file'
    }
    $overlay
}

function Assert-PSOBBLocalLabClientRuntimeContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $clientExecutable = Get-PSOBBClientExecutablePath -Layout $Layout -Channel LocalLab
    $clientRoot = Split-Path -Parent $clientExecutable
    Assert-PSOBBApprovedClientExecutable -Path $clientExecutable | Out-Null
    $reparsePoint = Get-ChildItem -LiteralPath $clientRoot -Force -Recurse `
        -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($reparsePoint) {
        throw "The LocalLab client runtime contains a reparse point: $($reparsePoint.FullName)"
    }

    $profilePath = Assert-PathWithinRoot `
        -Path (Join-Path $clientRoot 'client-profile.json') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        throw "The LocalLab client profile is not materialized: $profilePath"
    }
    $profileFile = Get-Item -LiteralPath $profilePath -Force
    if ($profileFile.Length -le 0 -or $profileFile.Length -gt 64KB) {
        throw 'The LocalLab client profile has an invalid size'
    }
    try {
        $profile = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -Depth 30
    } catch {
        throw "The LocalLab client profile is not valid JSON: $($_.Exception.Message)"
    }

    $profileId = [string]$profile.profileId
    $identity = Get-PSOBBApprovedClientIdentity
    if ([int]$profile.schemaVersion -lt 7 -or
        [string]$profile.channel -cne 'local-lab' -or
        $profileId -cnotmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
        -not ([string]$profile.baseExecutableSha256).Equals(
            $identity.Sha256,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The LocalLab materialized profile does not match the schema, channel, profile-ID, or immutable-base contract'
    }

    $catalogPath = Join-Path $script:PSOBBRepositoryRoot 'config\graphics-profiles.json'
    $catalog = Get-Content -Raw -LiteralPath $catalogPath | ConvertFrom-Json -Depth 50
    $declaredProfiles = @($catalog.profiles | Where-Object {
        [string]$_.id -ceq $profileId -and [string]$_.channel -ceq 'local-lab'
    })
    if ($catalog.schemaVersion -ne 1 -or
        [string]$catalog.baseClient.executableSha256 -cne $identity.Sha256 -or
        $declaredProfiles.Count -ne 1) {
        throw "The LocalLab profile '$profileId' is not declared exactly once in the approved graphics profile catalog"
    }
    $declared = $declaredProfiles[0]
    $materializedNativeGraphics = Assert-PSOBBNativeGraphicsContract `
        -NativeGraphics $profile.nativeGraphics `
        -Label 'Materialized LocalLab nativeGraphics'
    $declaredNativeGraphics = Assert-PSOBBNativeGraphicsContract `
        -NativeGraphics $declared.nativeGraphics `
        -Label 'Declared LocalLab nativeGraphics'
    if ($materializedNativeGraphics.PresetId -cne
            $declaredNativeGraphics.PresetId -or
        $materializedNativeGraphics.GraphicCtrlSha256 -cne
            $declaredNativeGraphics.GraphicCtrlSha256 -or
        $materializedNativeGraphics.AdvancedEffectsPolicy -cne
            $declaredNativeGraphics.AdvancedEffectsPolicy -or
        $materializedNativeGraphics.PixelFogPolicy -cne
            $declaredNativeGraphics.PixelFogPolicy -or
        $materializedNativeGraphics.LowResolutionTexturesPolicy -cne
            $declaredNativeGraphics.LowResolutionTexturesPolicy -or
        $materializedNativeGraphics.FrameSkipPolicy -cne
            $declaredNativeGraphics.FrameSkipPolicy) {
        throw "The LocalLab materialized profile '$profileId' does not match its declared native graphics contract"
    }

    $renderCandidate = @($declared.display.internalRenderCandidates | Where-Object {
        [int]$_.width -eq [int]$profile.renderWidth -and
        [int]$_.height -eq [int]$profile.renderHeight
    })
    $windowMode = ([string]$profile.defaultWindowMode).ToLowerInvariant()
    $declaredWindowModes = @($declared.display.windowModes | ForEach-Object {
        ([string]$_).ToLowerInvariant()
    })
    if ([string]$profile.outputApi -cne [string]$declared.renderer.outputApi -or
        [int]$profile.desktopWidth -ne [int]$declared.display.output.width -or
        [int]$profile.desktopHeight -ne [int]$declared.display.output.height -or
        [string]$profile.aspectPolicy -cne [string]$declared.display.aspectPolicy -or
        $renderCandidate.Count -ne 1 -or
        [int]$profile.renderWidth -gt [int]$declared.display.renderCeiling.width -or
        [int]$profile.renderHeight -gt [int]$declared.display.renderCeiling.height -or
        $windowMode -notin @('borderless', 'resizable') -or
        $declaredWindowModes -cnotcontains $windowMode -or
        [int]$profile.resizableClientWidth -le 0 -or
        [int]$profile.resizableClientHeight -le 0 -or
        $profile.watermarkEnabled -ne $false) {
        throw "The LocalLab materialized profile '$profileId' does not match its declared renderer, display, window, or watermark contract"
    }

    $sourcesPath = Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'
    $sources = Get-Content -Raw -LiteralPath $sourcesPath | ConvertFrom-Json -Depth 50
    $declaredModules = @($declared.renderer.d3d8Owner) + @($declared.renderer.secondaryLayers)
    $expectedLoadablePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($module in $declaredModules) {
        $relativePath = ([string]$module.relativePath).Replace('/', '\')
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [System.IO.Path]::IsPathRooted($relativePath) -or
            $relativePath.Contains(':', [System.StringComparison]::Ordinal) -or
            $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
            throw "The LocalLab profile declares an unsafe module path: $relativePath"
        }
        $actualPath = Assert-PathWithinRoot -Path (Join-Path $clientRoot $relativePath) -Root $clientRoot
        if (-not (Test-Path -LiteralPath $actualPath -PathType Leaf)) {
            throw "The LocalLab profile module is missing: $relativePath"
        }
        $component = @($sources.components | Where-Object {
            [string]$_.id -ceq [string]$module.componentId
        })
        if ($component.Count -ne 1) {
            throw "The LocalLab module component is not locked exactly once: $($module.componentId)"
        }
        $actualItem = Get-Item -LiteralPath $actualPath -Force
        $actualHash = Get-LowerSha256 -Path $actualPath
        $approvedArtifact = (
            [string]$component[0].sha256 -cmatch '^[a-f0-9]{64}$' -and
            [long]$component[0].size -eq $actualItem.Length -and
            [string]$component[0].sha256 -ceq $actualHash)
        if (-not $approvedArtifact) {
            $componentMembers = if ($component[0].PSObject.Properties.Name -contains 'members') {
                @($component[0].members)
            } else {
                @()
            }
            $componentRuntimeArtifacts = if ($component[0].PSObject.Properties.Name -contains 'runtimeArtifacts') {
                @($component[0].runtimeArtifacts)
            } else {
                @()
            }
            $approvedMembers = @(
                @($componentMembers) + @($componentRuntimeArtifacts) |
                Where-Object {
                [long]$_.size -eq $actualItem.Length -and
                [string]$_.sha256 -ceq $actualHash
                })
            $approvedArtifact = $approvedMembers.Count -eq 1
        }
        if (-not $approvedArtifact) {
            throw "The LocalLab module does not match its locked component: $relativePath"
        }
        if ([System.IO.Path]::GetExtension($relativePath) -ieq '.asi' -or
            [System.IO.Path]::GetFileName($relativePath) -in @(
                'd3d8.dll', 'd3d9.dll', 'ddraw.dll', 'dxgi.dll', 'dinput8.dll')) {
            $expectedLoadablePaths.Add($relativePath) | Out-Null
        }
    }

    Assert-PSOBBLocalAssetOverlayContract `
        -Layout $Layout `
        -ClientRoot $clientRoot `
        -ClientExecutablePath $clientExecutable `
        -Profile $profile `
        -ExpectedLoadablePaths $expectedLoadablePaths | Out-Null

    $actualLoadablePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($proxyName in @('d3d8.dll', 'd3d9.dll', 'ddraw.dll', 'dxgi.dll', 'dinput8.dll')) {
        if (Test-Path -LiteralPath (Join-Path $clientRoot $proxyName) -PathType Leaf) {
            $actualLoadablePaths.Add($proxyName) | Out-Null
        }
    }
    foreach ($loadableExtension in @('*.asi', '*.addon', '*.addon32')) {
        foreach ($loadable in @(Get-ChildItem `
            -LiteralPath $clientRoot `
            -File `
            -Filter $loadableExtension `
            -Recurse `
            -Force)) {
            $actualLoadablePaths.Add(
                [System.IO.Path]::GetRelativePath($clientRoot, $loadable.FullName)) | Out-Null
        }
    }
    if (-not $actualLoadablePaths.SetEquals($expectedLoadablePaths)) {
        throw "The LocalLab runtime loadable-module inventory does not exactly match profile '$profileId'"
    }

    if ([string]$declared.renderer.d3d8Owner.componentId -ceq 'dgvoodoo2-x86-d3d8') {
        $declaredVirtualVram = @(
            $declared.quality.virtualVramMbCandidates | ForEach-Object { [int]$_ })
        $declaredVsyncOwners = @(
            $declared.quality.vsyncOwnerCandidates | ForEach-Object { [string]$_ })
        if ($null -eq $profile.PSObject.Properties['virtualVramMb'] -or
            $null -eq $profile.PSObject.Properties['vsyncOwner'] -or
            [int]$profile.virtualVramMb -notin $declaredVirtualVram -or
            [string]$profile.vsyncOwner -cnotin $declaredVsyncOwners) {
            throw 'The LocalLab materialized profile selects undeclared virtual VRAM or VSync-owner settings'
        }
        $configurationPath = Join-Path $clientRoot 'dgVoodoo.conf'
        if (-not (Test-Path -LiteralPath $configurationPath -PathType Leaf) -or
            [string]$profile.configurationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            (Get-LowerSha256 -Path $configurationPath) -cne [string]$profile.configurationSha256) {
            throw 'The LocalLab dgVoodoo configuration is missing or does not match its materialized hash'
        }
        $configurationText = Get-Content -Raw -LiteralPath $configurationPath
        $getIniValue = {
            param([string]$Section, [string]$Key)
            $sectionMatch = [regex]::Match(
                $configurationText,
                '(?ms)^\[' + [regex]::Escape($Section) + '\][ \t]*\r?\n(?<body>.*?)(?=^\[|\z)')
            if (-not $sectionMatch.Success) {
                return $null
            }
            $keyMatches = [regex]::Matches(
                $sectionMatch.Groups['body'].Value,
                '(?m)^[ \t]*' + [regex]::Escape($Key) +
                '[ \t]*=[ \t]*(?<value>[^;\r\n]*?)[ \t]*\r?$')
            if ($keyMatches.Count -ne 1) {
                return $null
            }
            $keyMatches[0].Groups['value'].Value.Trim()
        }
        $expectedRender = '{0}x{1}' -f [int]$profile.renderWidth, [int]$profile.renderHeight
        $expectedDesktop = '{0}x{1}' -f [int]$profile.desktopWidth, [int]$profile.desktopHeight
        $expectedVsync = if ([string]$profile.vsyncOwner -ceq 'dgvoodoo') {
            'true'
        } else {
            'false'
        }
        if ((& $getIniValue 'General' 'OutputAPI') -cne [string]$profile.outputApi -or
            (& $getIniValue 'GeneralExt' 'DesktopResolution') -cne $expectedDesktop -or
            (& $getIniValue 'DirectX' 'Resolution') -cne $expectedRender -or
            (& $getIniValue 'DirectX' 'VRAM') -cne
                [string][int]$profile.virtualVramMb -or
            (& $getIniValue 'DirectX' 'ForceVerticalSync') -cne $expectedVsync -or
            (& $getIniValue 'DirectX' 'dgVoodooWatermark') -cne 'false') {
            throw 'The LocalLab dgVoodoo configuration does not match its materialized API, render, desktop, VRAM, VSync, or watermark values'
        }
    } elseif ($null -ne $profile.virtualVramMb -or
        [string]$profile.vsyncOwner -cne [string]$declared.quality.vsyncOwner) {
        throw 'The LocalLab non-dgVoodoo profile declares unexpected virtual VRAM or VSync ownership'
    }

    if ($profileId -in @(
        'lab-widescreen-16x10',
        'lab-widescreen-hd-16x10',
        'lab-widescreen-cas-16x10')) {
        if ([string]$profile.presentationOwner -cne 'client-patch' -or
            [string]$profile.widescreenConfigurationPath -cne 'widescreen.cfg' -or
            [string]$profile.widescreenIniPath -cne 'patches/pso_widescreen.ini' -or
            [string]$profile.widescreenConfigurationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$profile.widescreenIniSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The LocalLab widescreen companion-file contract is incomplete'
        }
        $widescreenConfigurationPath = Assert-PathWithinRoot `
            -Path (Join-Path $clientRoot 'widescreen.cfg') `
            -Root $clientRoot
        $widescreenIniPath = Assert-PathWithinRoot `
            -Path (Join-Path $clientRoot 'patches\pso_widescreen.ini') `
            -Root $clientRoot
        if (-not (Test-Path -LiteralPath $widescreenConfigurationPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $widescreenIniPath -PathType Leaf) -or
            (Get-LowerSha256 -Path $widescreenConfigurationPath) -cne
                [string]$profile.widescreenConfigurationSha256 -or
            (Get-LowerSha256 -Path $widescreenIniPath) -cne
                [string]$profile.widescreenIniSha256 -or
            (Test-Path -LiteralPath (Join-Path $clientRoot 'pso_widescreen.ini')) -or
            (Test-Path -LiteralPath (Join-Path $clientRoot 'plugins\pso_widescreen.ini')) -or
            (Test-Path -LiteralPath (Join-Path $clientRoot 'plugins\widescreen.cfg'))) {
            throw 'The LocalLab widescreen companion files are missing, stale, duplicated, or hash-mismatched'
        }

        $widescreenConfiguration = Get-Content -Raw -LiteralPath $widescreenConfigurationPath
        $getFlatValue = {
            param([string]$Text, [string]$Key)
            $matches = [regex]::Matches(
                $Text,
                '(?m)^[ \t]*' + [regex]::Escape($Key) +
                '[ \t]*=[ \t]*(?<value>[^;\r\n]*?)[ \t]*\r?$')
            if ($matches.Count -ne 1) {
                return $null
            }
            $matches[0].Groups['value'].Value.Trim()
        }
        $expectedWindowed = if ($windowMode -ceq 'borderless') { '2' } else { '1' }
        $expectedHudScale = '{0:0.00}' -f [double]$profile.hudScale
        if ((& $getFlatValue $widescreenConfiguration 'Width') -cne [string][int]$profile.renderWidth -or
            (& $getFlatValue $widescreenConfiguration 'Height') -cne [string][int]$profile.renderHeight -or
            (& $getFlatValue $widescreenConfiguration 'HUDScale') -cne $expectedHudScale -or
            (& $getFlatValue $widescreenConfiguration 'Windowed') -cne $expectedWindowed) {
            throw 'The LocalLab widescreen configuration does not match the materialized render, HUD, or window values'
        }

        $widescreenIni = Get-Content -Raw -LiteralPath $widescreenIniPath
        foreach ($sourceFaithfulSetting in @('VideoEnable', 'NoVignette', 'IntegerScale', 'BootPosterEnabled')) {
            if ((& $getFlatValue $widescreenIni $sourceFaithfulSetting) -cne '0') {
                throw "The LocalLab widescreen INI does not preserve source-faithful '$sourceFaithfulSetting=0'"
            }
        }
    }

    if ($profileId -in @('cleanroom-widescreen-canary', 'cas-evaluation-16x10')) {
        if ([string]$profile.presentationOwner -cne 'client-patch' -or
            [string]$profile.enhancementConfigurationPath -cne
                'plugins/PSOBB.Enhancement.ini' -or
            [string]$profile.enhancementConfigurationSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'The LocalLab clean-room enhancement configuration contract is incomplete'
        }
        $enhancementConfigurationPath = Assert-PathWithinRoot `
            -Path (Join-Path $clientRoot 'plugins\PSOBB.Enhancement.ini') `
            -Root $clientRoot
        if (-not (Test-Path -LiteralPath $enhancementConfigurationPath -PathType Leaf) -or
            (Get-LowerSha256 -Path $enhancementConfigurationPath) -cne
                [string]$profile.enhancementConfigurationSha256 -or
            (Test-Path -LiteralPath (Join-Path $clientRoot 'PSOBB.Enhancement.ini'))) {
            throw 'The LocalLab clean-room enhancement configuration is missing, duplicated, or hash-mismatched'
        }

        $enhancementConfiguration = Get-Content -Raw -LiteralPath $enhancementConfigurationPath
        $getEnhancementValue = {
            param([string]$Key)
            $matches = [regex]::Matches(
                $enhancementConfiguration,
                '(?m)^[ \t]*' + [regex]::Escape($Key) +
                '[ \t]*=[ \t]*(?<value>[^;\r\n]*?)[ \t]*\r?$')
            if ($matches.Count -ne 1) {
                return $null
            }
            $matches[0].Groups['value'].Value.Trim()
        }
        $expectedEnhancementWindowMode = if ($windowMode -ceq 'borderless') {
            'Borderless'
        } else {
            'Resizable'
        }
        if ((& $getEnhancementValue 'Enabled') -cne '1' -or
            (& $getEnhancementValue 'Width') -cne [string][int]$profile.renderWidth -or
            (& $getEnhancementValue 'Height') -cne [string][int]$profile.renderHeight -or
            (& $getEnhancementValue 'WindowMode') -cne $expectedEnhancementWindowMode -or
            (& $getEnhancementValue 'HorizontalFov') -cne '1' -or
            (& $getEnhancementValue 'HudMinimap') -cne '0' -or
            (& $getEnhancementValue 'AutomaticDeviceRecreation') -cne '0') {
            throw 'The LocalLab clean-room enhancement configuration does not match its guarded feature contract'
        }
    }

    if ($profileId -ceq 'cleanroom-widescreen-canary') {
        foreach ($unexpectedPostProcessPath in @(
            'ReShade.ini',
            'PSOBB-ReShade-Template.ini',
            'PSOBB-NeutralCAS-Preset.ini',
            'reshade-shaders\Shaders\PSOBB_NeutralCAS.fx')) {
            if (Test-Path -LiteralPath (Join-Path $clientRoot $unexpectedPostProcessPath)) {
                throw 'The clean-room widescreen isolation profile contains an undeclared post-process file'
            }
        }
    }

    if ($profileId -in @('lab-widescreen-cas-16x10', 'cas-evaluation-16x10')) {
        $expectedCasPaths = [ordered]@{
            reshadeConfigurationPath = 'ReShade.ini'
            reshadeTemplatePath = 'PSOBB-ReShade-Template.ini'
            reshadePresetPath = 'PSOBB-NeutralCAS-Preset.ini'
            casShaderPath = 'reshade-shaders/Shaders/PSOBB_NeutralCAS.fx'
        }
        $expectedCasHashes = [ordered]@{
            reshadeTemplateSha256 = 'reshadeTemplatePath'
            reshadePresetSha256 = 'reshadePresetPath'
            casShaderSha256 = 'casShaderPath'
        }
        $resolvedCasPaths = @{}
        foreach ($entry in $expectedCasPaths.GetEnumerator()) {
            if ([string]$profile.($entry.Key) -cne [string]$entry.Value) {
                throw "The CAS evaluation profile declares an unexpected $($entry.Key)"
            }
            $resolvedPath = Assert-PathWithinRoot `
                -Path (Join-Path $clientRoot ([string]$entry.Value).Replace('/', '\')) `
                -Root $clientRoot
            if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
                throw "The CAS evaluation file is missing: $($entry.Value)"
            }
            $resolvedCasPaths[$entry.Key] = $resolvedPath
        }
        foreach ($entry in $expectedCasHashes.GetEnumerator()) {
            $expectedHash = [string]$profile.($entry.Key)
            $resolvedPath = [string]$resolvedCasPaths[[string]$entry.Value]
            if ($expectedHash -cnotmatch '^[a-f0-9]{64}$' -or
                (Get-LowerSha256 -Path $resolvedPath) -cne $expectedHash) {
                throw "The CAS evaluation file does not match $($entry.Key)"
            }
        }
        if ([string]$profile.reshadeConfigurationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]$profile.reshadeConfigurationSha256 -cne
                [string]$profile.reshadeTemplateSha256) {
            throw 'The mutable ReShade runtime configuration is not bound to its immutable template hash'
        }

        $declaredStrengths = @($declared.postProcessing.strengthCandidates | ForEach-Object {
            [double]$_
        })
        if ($null -eq $profile.casStrength -or
            $declaredStrengths -notcontains [double]$profile.casStrength) {
            throw 'The CAS evaluation profile does not select one exact declared strength'
        }

        $expectedReshadeTemplate = (@(
            '[GENERAL]',
            'EffectSearchPaths=.\reshade-shaders\Shaders',
            'IntermediateCachePath=.\reshade-shaders\Cache',
            'NoDebugInfo=1',
            'PerformanceMode=1',
            'PreprocessorDefinitions=',
            'PresetPath=.\PSOBB-NeutralCAS-Preset.ini',
            'SkipLoadingDisabledEffects=1',
            'TextureSearchPaths=.\reshade-shaders\Textures',
            '',
            '[INPUT]',
            'ForceShortcutModifiers=1',
            'KeyScreenshot=121,0,0,0',
            '',
            '[OVERLAY]',
            'TutorialProgress=4',
            '',
            '[SCREENSHOT]',
            'ClearAlpha=1',
            'FileFormat=1',
            'FileNaming=%AppName% %Date% %Time%_%TimeMS%',
            'JPEGQuality=90',
            'PostSaveCommand=',
            'PostSaveCommandArguments="%TargetPath%"',
            'PostSaveCommandHideWindow=0',
            'PostSaveCommandWorkingDirectory=.\',
            'SaveBeforeShot=1',
            'SaveOverlayShot=0',
            'SavePath=.\',
            'SavePresetFile=0',
            'SoundPath='
        ) -join "`r`n") + "`r`n"
        $reshadeTemplate = Get-Content -Raw -LiteralPath `
            $resolvedCasPaths['reshadeTemplatePath']
        if ($reshadeTemplate -cne $expectedReshadeTemplate) {
            throw 'The immutable ReShade template is not the exact project-owned CAS template'
        }

        $reshadeConfigurationPath = [string]$resolvedCasPaths['reshadeConfigurationPath']
        $reshadeConfigurationFile = Get-Item -LiteralPath $reshadeConfigurationPath -Force
        if ($reshadeConfigurationFile.Length -le 0 -or $reshadeConfigurationFile.Length -gt 64KB) {
            throw 'The ReShade runtime configuration has an invalid size'
        }
        $reshadeConfiguration = Get-Content -Raw -LiteralPath $reshadeConfigurationPath
        if ((Get-LowerSha256 -Path $reshadeConfigurationPath) -cne
            [string]$profile.reshadeConfigurationSha256) {
            # ReShade 6.7.3 expands its minimal source template on first launch.
            # Parse that normalized form as a closed schema: no unknown section,
            # key, search path, command, effect-toggle, font path, or shortcut is
            # accepted. Loadable add-ons are rejected by the module inventory.
            $parseNormalizedReshade = {
                param([Parameter(Mandatory)][string]$Text)

                $sections = [System.Collections.Generic.Dictionary[string, object]]::new(
                    [System.StringComparer]::Ordinal)
                $current = $null
                foreach ($rawLine in @($Text -split '\r?\n')) {
                    if ([string]::IsNullOrEmpty($rawLine)) {
                        continue
                    }
                    $sectionMatch = [regex]::Match($rawLine, '^\[(?<name>[A-Z]+)\]$')
                    if ($sectionMatch.Success) {
                        $sectionName = $sectionMatch.Groups['name'].Value
                        if ($sections.ContainsKey($sectionName)) {
                            throw "ReShade normalized configuration repeats section '$sectionName'"
                        }
                        $current = [System.Collections.Generic.Dictionary[string, string]]::new(
                            [System.StringComparer]::Ordinal)
                        $sections.Add($sectionName, $current)
                        continue
                    }
                    $valueMatch = [regex]::Match(
                        $rawLine,
                        '^(?<key>[A-Za-z][A-Za-z0-9]*)=(?<value>.*)$')
                    if (-not $valueMatch.Success -or $null -eq $current) {
                        throw 'ReShade normalized configuration contains an invalid line'
                    }
                    $key = $valueMatch.Groups['key'].Value
                    if ($current.ContainsKey($key)) {
                        throw "ReShade normalized configuration repeats key '$key'"
                    }
                    $current.Add($key, $valueMatch.Groups['value'].Value)
                }
                [pscustomobject]@{ Sections = $sections }
            }

            $normalized = (& $parseNormalizedReshade -Text $reshadeConfiguration).Sections
            $allowedSectionKeys = [ordered]@{
                GENERAL = @(
                    'EffectSearchPaths', 'IntermediateCachePath', 'NoDebugInfo',
                    'NoEffectCache', 'NoReloadOnInit', 'PerformanceMode',
                    'PreprocessorDefinitions', 'PresetPath', 'PresetShortcutKeys',
                    'PresetShortcutPaths', 'PresetTransitionDuration',
                    'SkipLoadingDisabledEffects', 'StartupPresetPath',
                    'TextureSearchPaths')
                INPUT = @(
                    'ForceShortcutModifiers', 'InputProcessing', 'KeyEffects',
                    'KeyFPS', 'KeyFrametime', 'KeyNextPreset', 'KeyOverlay',
                    'KeyPreviousPreset', 'KeyReload', 'KeyScreenshot')
                OVERLAY = @(
                    'AutoSavePreset', 'ClockFormat', 'Docking', 'FPSPosition',
                    'Language', 'ShowClock', 'ShowForceLoadEffectsButton',
                    'ShowFPS', 'ShowFrameTime', 'ShowPresetName',
                    'ShowPresetTransitionMessage', 'ShowScreenshotMessage',
                    'TutorialProgress', 'VariableListHeight', 'VariableListUseTabs')
                SCREENSHOT = @(
                    'ClearAlpha', 'FileFormat', 'FileNaming', 'JPEGQuality',
                    'PostSaveCommand', 'PostSaveCommandArguments',
                    'PostSaveCommandHideWindow', 'PostSaveCommandWorkingDirectory',
                    'SaveBeforeShot', 'SaveOverlayShot', 'SavePath',
                    'SavePresetFile', 'SoundPath')
                STYLE = @(
                    'Alpha', 'ChildRounding', 'ColFPSText', 'EditorFont',
                    'EditorFontSize', 'EditorStyleIndex', 'Font', 'FontScale',
                    'FontSize', 'FPSScale', 'FrameRounding', 'GrabRounding',
                    'HdrOverlayBrightness', 'HdrOverlayOverwriteColorSpaceTo',
                    'LatinFont', 'PopupRounding', 'ScrollbarRounding',
                    'StyleIndex', 'TabRounding', 'WindowRounding')
            }
            if ($normalized.Count -ne $allowedSectionKeys.Count) {
                throw 'ReShade normalized configuration contains an unexpected section set'
            }
            foreach ($section in $allowedSectionKeys.GetEnumerator()) {
                if (-not $normalized.ContainsKey([string]$section.Key)) {
                    throw "ReShade normalized configuration is missing section '$($section.Key)'"
                }
                $actualKeys = $normalized[[string]$section.Key]
                $missingKeys = @($section.Value | Where-Object {
                    -not $actualKeys.ContainsKey([string]$_)
                })
                $unexpectedKeys = @($actualKeys.Keys | Where-Object {
                    @($section.Value) -cnotcontains [string]$_
                })
                if ($missingKeys.Count -gt 0 -or $unexpectedKeys.Count -gt 0) {
                    throw "ReShade normalized section '$($section.Key)' does not match its exact key allowlist"
                }
            }

            $general = $normalized['GENERAL']
            $allowedCachePaths = @('.\reshade-shaders\Cache')
            $localAppData = [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::LocalApplicationData)
            if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
                $allowedCachePaths += Join-Path $localAppData 'Temp\ReShade'
            }
            $requiredGeneral = [ordered]@{
                EffectSearchPaths = '.\reshade-shaders\Shaders'
                NoDebugInfo = '1'
                NoEffectCache = '0'
                NoReloadOnInit = '0'
                PerformanceMode = '1'
                PreprocessorDefinitions = ''
                PresetPath = '.\PSOBB-NeutralCAS-Preset.ini'
                PresetShortcutKeys = ''
                PresetShortcutPaths = ''
                PresetTransitionDuration = '1000'
                SkipLoadingDisabledEffects = '1'
                StartupPresetPath = ''
                TextureSearchPaths = '.\reshade-shaders\Textures'
            }
            foreach ($setting in $requiredGeneral.GetEnumerator()) {
                if ([string]$general[[string]$setting.Key] -cne [string]$setting.Value) {
                    throw "ReShade normalized GENERAL/$($setting.Key) is not approved"
                }
            }
            if ($allowedCachePaths -cnotcontains [string]$general['IntermediateCachePath']) {
                throw 'ReShade normalized cache path is outside the approved project or user-temp location'
            }

            $requiredInput = [ordered]@{
                ForceShortcutModifiers = '1'
                InputProcessing = '2'
                KeyEffects = '0,0,0,0'
                KeyFPS = '0,0,0,0'
                KeyFrametime = '0,0,0,0'
                KeyNextPreset = '0,0,0,0'
                KeyOverlay = '36,0,0,0'
                KeyPreviousPreset = '0,0,0,0'
                KeyReload = '0,0,0,0'
                KeyScreenshot = '121,0,0,0'
            }
            foreach ($setting in $requiredInput.GetEnumerator()) {
                if ([string]$normalized['INPUT'][[string]$setting.Key] -cne
                    [string]$setting.Value) {
                    throw "ReShade normalized INPUT/$($setting.Key) is not approved"
                }
            }

            $screenshot = $normalized['SCREENSHOT']
            $requiredScreenshot = [ordered]@{
                ClearAlpha = '1'
                FileFormat = '1'
                FileNaming = '%AppName% %Date% %Time%_%TimeMS%'
                JPEGQuality = '90'
                PostSaveCommand = ''
                PostSaveCommandArguments = '"%TargetPath%"'
                PostSaveCommandHideWindow = '0'
                PostSaveCommandWorkingDirectory = '.\'
                SaveBeforeShot = '1'
                SaveOverlayShot = '0'
                SavePath = '.\'
                SavePresetFile = '0'
                SoundPath = ''
            }
            foreach ($setting in $requiredScreenshot.GetEnumerator()) {
                if ([string]$screenshot[[string]$setting.Key] -cne [string]$setting.Value) {
                    throw "ReShade normalized SCREENSHOT/$($setting.Key) is not approved"
                }
            }
            if ([string]$normalized['OVERLAY']['AutoSavePreset'] -cne '1' -or
                [string]$normalized['OVERLAY']['TutorialProgress'] -cne '4' -or
                [string]$normalized['STYLE']['FPSScale'] -cne '1.000000' -or
                -not [string]::IsNullOrEmpty([string]$normalized['STYLE']['EditorFont']) -or
                -not [string]::IsNullOrEmpty([string]$normalized['STYLE']['Font']) -or
                -not [string]::IsNullOrEmpty([string]$normalized['STYLE']['LatinFont'])) {
                throw 'ReShade normalized UI fields contain an unapproved preset or font path'
            }
        }

        $reshadePreset = Get-Content -Raw -LiteralPath $resolvedCasPaths['reshadePresetPath']
        $getPresetValue = {
            param([string]$Key)
            $matches = [regex]::Matches(
                $reshadePreset,
                '(?m)^[ \t]*' + [regex]::Escape($Key) +
                '[ \t]*=[ \t]*(?<value>[^\r\n]*?)[ \t]*\r?$')
            if ($matches.Count -ne 1) {
                return $null
            }
            $matches[0].Groups['value'].Value.Trim()
        }
        $expectedTechnique = 'PSOBB_NeutralCAS@PSOBB_NeutralCAS.fx'
        $expectedStrength = '{0:F6}' -f [double]$profile.casStrength
        if ((& $getPresetValue 'PreprocessorDefinitions') -cne '' -or
            (& $getPresetValue 'Techniques') -cne $expectedTechnique -or
            (& $getPresetValue 'TechniqueSorting') -cne $expectedTechnique -or
            (& $getPresetValue 'PSOBB_CAS_Strength') -cne $expectedStrength) {
            throw 'The CAS evaluation preset contains an unexpected technique, definition, or strength'
        }
        $expectedReshadePreset = (@(
            'PreprocessorDefinitions=',
            "Techniques=$expectedTechnique",
            "TechniqueSorting=$expectedTechnique",
            '',
            '[PSOBB_NeutralCAS.fx]',
            "PSOBB_CAS_Strength=$expectedStrength"
        ) -join "`r`n") + "`r`n"
        if ($reshadePreset -cne $expectedReshadePreset) {
            throw 'The CAS evaluation preset contains an undeclared field, section, or line ending'
        }

        $shaderFiles = @(Get-ChildItem `
            -LiteralPath (Join-Path $clientRoot 'reshade-shaders\Shaders') `
            -File `
            -Recurse `
            -Force)
        if ($shaderFiles.Count -ne 1 -or
            [string]$declared.postProcessing.effectComponentId -cne 'psobb-neutral-cas-source') {
            throw 'The CAS evaluation shader inventory is not exactly the single declared project effect'
        }
        $casComponent = @($sources.components | Where-Object {
            [string]$_.id -ceq 'psobb-neutral-cas-source'
        })
        if ($casComponent.Count -ne 1 -or
            [string]$casComponent[0].sha256 -cne [string]$profile.casShaderSha256) {
            throw 'The CAS evaluation shader is not bound to the locked project source'
        }
    }

    $profile
}

function Write-PSOBBAtomicUtf8Text {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )

    if ($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'An atomic text replacement requires one lowercase SHA-256 digest'
    }
    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $parent = Split-Path -Parent $safePath
    $temporaryPath = Join-Path $parent (
        '.psobb-window-mode-' + [Guid]::NewGuid().ToString('N') + '.new')
    Assert-PathWithinRoot -Path $temporaryPath -Root $Root | Out-Null
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $Text,
            [System.Text.UTF8Encoding]::new($false))
        if ((Get-LowerSha256 -Path $temporaryPath) -cne $ExpectedSha256) {
            throw "Atomic text staging produced unexpected bytes: $safePath"
        }
        [System.IO.File]::Move($temporaryPath, $safePath, $true)
        if ((Get-LowerSha256 -Path $safePath) -cne $ExpectedSha256) {
            throw "Atomic text replacement produced unexpected bytes: $safePath"
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Set-PSOBBLocalLabClientWindowMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]
        [ValidateSet('Borderless', 'Resizable')]
        [string]$WindowMode,
        [Parameter(DontShow)][switch]$ClientOperationLockHeld
    )

    $windowModeMutex = if ($ClientOperationLockHeld) {
        $null
    } else {
        Enter-PSOBBClientOperationLock -Layout $Layout
    }
    try {
    # Keep the process check as a second, fail-closed precondition because
    # these two files are read by the presentation-owner ASI at load.
    Assert-PSOBBNoRunningClients -Layout $Layout | Out-Null
    $initialProfile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $Layout
    if ([string]$initialProfile.presentationOwner -cne 'client-patch') {
        throw 'Only a client-patch-owned LocalLab profile can materialize its window mode before launch'
    }
    if ([string]$initialProfile.defaultWindowMode -ieq $WindowMode) {
        return [pscustomobject]@{
            Changed = $false
            WindowMode = $WindowMode
            Profile = $initialProfile
        }
    }

    $supportedProfiles = @(
        'lab-widescreen-16x10',
        'lab-widescreen-hd-16x10',
        'lab-widescreen-cas-16x10'
    )
    if ([string]$initialProfile.profileId -cnotin $supportedProfiles -or
        [string]$initialProfile.widescreenConfigurationPath -cne 'widescreen.cfg') {
        throw "The LocalLab profile '$($initialProfile.profileId)' does not support the guarded widescreen window-mode transaction"
    }

    $catalogPath = Join-Path $script:PSOBBRepositoryRoot 'config\graphics-profiles.json'
    $catalog = Get-Content -Raw -LiteralPath $catalogPath |
        ConvertFrom-Json -Depth 50 -DateKind String
    $declarations = @($catalog.profiles | Where-Object {
        [string]$_.id -ceq [string]$initialProfile.profileId -and
        [string]$_.channel -ceq 'local-lab'
    })
    $requestedMode = $WindowMode.ToLowerInvariant()
    $declaredModes = if ($declarations.Count -eq 1) {
        @($declarations[0].display.windowModes | ForEach-Object {
            ([string]$_).ToLowerInvariant()
        })
    } else {
        @()
    }
    if ($declarations.Count -ne 1 -or $declaredModes -cnotcontains $requestedMode) {
        throw "The LocalLab profile '$($initialProfile.profileId)' does not declare window mode '$WindowMode'"
    }

    $clientExecutable = Get-PSOBBClientExecutablePath -Layout $Layout -Channel LocalLab
    $clientRoot = Split-Path -Parent $clientExecutable
    $profilePath = Assert-PathWithinRoot `
        -Path (Join-Path $clientRoot 'client-profile.json') `
        -Root $clientRoot
    $configurationPath = Assert-PathWithinRoot `
        -Path (Join-Path $clientRoot 'widescreen.cfg') `
        -Root $clientRoot
    $originalProfileText = Get-Content -Raw -LiteralPath $profilePath
    $originalConfigurationText = Get-Content -Raw -LiteralPath $configurationPath
    $originalProfileSha256 = Get-LowerSha256 -Path $profilePath
    $originalConfigurationSha256 = Get-LowerSha256 -Path $configurationPath

    try {
        $profile = ConvertFrom-Json -InputObject $originalProfileText -Depth 30 `
            -DateKind String -ErrorAction Stop
    } catch {
        throw "The LocalLab client profile cannot be safely transformed: $($_.Exception.Message)"
    }
    foreach ($requiredProperty in @(
        'defaultWindowMode', 'widescreenConfigurationSha256')) {
        if ($null -eq $profile.PSObject.Properties[$requiredProperty]) {
            throw "The LocalLab client profile is missing mutable window property '$requiredProperty'"
        }
    }

    $windowedMatches = [regex]::Matches(
        $originalConfigurationText,
        '(?m)^[ \t]*Windowed[ \t]*=[ \t]*(?<value>[^;\r\n]*?)[ \t]*(?:;[^\r\n]*)?\r?$')
    if ($windowedMatches.Count -ne 1 -or
        $windowedMatches[0].Groups['value'].Value.Trim() -cnotin @('1', '2')) {
        throw 'The LocalLab widescreen configuration does not contain exactly one guarded Windowed value'
    }
    $valueGroup = $windowedMatches[0].Groups['value']
    $requestedWindowedValue = if ($WindowMode -ceq 'Borderless') { '2' } else { '1' }
    $updatedConfigurationText = $originalConfigurationText.Remove(
        $valueGroup.Index,
        $valueGroup.Length).Insert($valueGroup.Index, $requestedWindowedValue)

    $transactionRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.LocalLab (
            'transactions\window-mode-' + [Guid]::NewGuid().ToString('N'))) `
        -Root $Layout.Root
    $configurationStagingPath = Join-Path $transactionRoot 'widescreen.cfg'
    $profileStagingPath = Join-Path $transactionRoot 'client-profile.json'
    try {
        New-Item -ItemType Directory -Path $transactionRoot -Force | Out-Null
        [System.IO.File]::WriteAllText(
            $configurationStagingPath,
            $updatedConfigurationText,
            [System.Text.UTF8Encoding]::new($false))
        $updatedConfigurationSha256 = Get-LowerSha256 -Path $configurationStagingPath

        # Treat every field other than these two as protected transaction
        # state. This explicitly includes localAssetOverlay, localModules,
        # activation identity, dgVoodoo configuration, CAS, and rollback data.
        $getProtectedProfileJson = {
            param([Parameter(Mandatory)]$Value)

            $clone = ConvertFrom-Json -InputObject (
                $Value | ConvertTo-Json -Depth 30 -Compress) `
                -Depth 30 -DateKind String
            $clone.defaultWindowMode = '<window-mode>'
            $clone.widescreenConfigurationSha256 = '<widescreen-configuration-sha256>'
            $clone | ConvertTo-Json -Depth 30 -Compress
        }
        $protectedProfileBefore = & $getProtectedProfileJson -Value $profile
        $profile.defaultWindowMode = $WindowMode
        $profile.widescreenConfigurationSha256 = $updatedConfigurationSha256
        $updatedProfileText = $profile | ConvertTo-Json -Depth 30
        [System.IO.File]::WriteAllText(
            $profileStagingPath,
            $updatedProfileText,
            [System.Text.UTF8Encoding]::new($false))
        $stagedProfile = ConvertFrom-Json `
            -InputObject (Get-Content -Raw -LiteralPath $profileStagingPath) `
            -Depth 30 -DateKind String
        $protectedProfileAfter = & $getProtectedProfileJson -Value $stagedProfile
        if ($protectedProfileAfter -cne $protectedProfileBefore -or
            [string]$stagedProfile.defaultWindowMode -cne $WindowMode -or
            [string]$stagedProfile.widescreenConfigurationSha256 -cne
                $updatedConfigurationSha256) {
            throw 'The LocalLab window-mode transaction changed protected profile state'
        }
        $updatedProfileSha256 = Get-LowerSha256 -Path $profileStagingPath

        $replacementStarted = $false
        try {
            # Full HD validation can be intentionally expensive. Recheck the
            # process boundary after staging so a manually launched client
            # cannot make the preflight stale before the first replacement.
            Assert-PSOBBNoRunningClients -Layout $Layout | Out-Null
            # Mark the pair as transactional before the first atomic helper is
            # called. Even a post-replacement verification failure in that
            # helper must restore both original files.
            $replacementStarted = $true
            Write-PSOBBAtomicUtf8Text `
                -Path $configurationPath `
                -Text $updatedConfigurationText `
                -Root $clientRoot `
                -ExpectedSha256 $updatedConfigurationSha256
            Write-PSOBBAtomicUtf8Text `
                -Path $profilePath `
                -Text $updatedProfileText `
                -Root $clientRoot `
                -ExpectedSha256 $updatedProfileSha256
            $validatedProfile = Assert-PSOBBLocalLabClientRuntimeContract -Layout $Layout
        } catch {
            $transactionFailure = $_
            if ($replacementStarted) {
                try {
                    Write-PSOBBAtomicUtf8Text `
                        -Path $configurationPath `
                        -Text $originalConfigurationText `
                        -Root $clientRoot `
                        -ExpectedSha256 $originalConfigurationSha256
                    Write-PSOBBAtomicUtf8Text `
                        -Path $profilePath `
                        -Text $originalProfileText `
                        -Root $clientRoot `
                        -ExpectedSha256 $originalProfileSha256
                    Assert-PSOBBLocalLabClientRuntimeContract -Layout $Layout | Out-Null
                } catch {
                    throw "The LocalLab window-mode transaction failed and its exact rollback also failed: $($_.Exception.Message)"
                }
            }
            throw $transactionFailure
        }

        [pscustomobject]@{
            Changed = $true
            WindowMode = $WindowMode
            Profile = $validatedProfile
        }
    } finally {
        Remove-Item -LiteralPath $transactionRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
    } finally {
        if ($windowModeMutex) {
            Exit-PSOBBClientOperationLock -Mutex $windowModeMutex
        }
    }
}

function Get-PSOBBClientProcessRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [ValidateSet('All', 'Stable', 'Canary', 'LocalLab', 'Native')]
        [string]$Channel = 'All',
        [string]$ServerEnvironment = 'Stable'
    )

    $environmentName = Resolve-PSOBBServerEnvironmentName `
        -Environment $ServerEnvironment
    $resolvedChannel = Resolve-PSOBBClientChannelForServerEnvironment `
        -ServerEnvironment $environmentName -Channel $Channel -AllowAll
    $channels = if ($resolvedChannel -eq 'All') {
        if ($environmentName -ceq 'CombatCanary') {
            @('Native')
        } else {
            @('Stable', 'Canary', 'LocalLab')
        }
    } else {
        @($resolvedChannel)
    }
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($candidateChannel in $channels) {
        $expectedPath = Get-PSOBBClientExecutablePath `
            -Layout $Layout `
            -Channel $candidateChannel `
            -ServerEnvironment $environmentName
        $processes = @(Get-PSOBBProcessesAtExactPath -Name 'Psobb' -ExpectedPath $expectedPath)
        if ($processes.Count -eq 0) {
            continue
        }

        $identity = Assert-PSOBBApprovedClientExecutable -Path $expectedPath
        foreach ($process in $processes) {
            try {
                $startTimeUtc = $process.StartTime.ToUniversalTime()
                $startTimeFileTimeUtc = [long]$startTimeUtc.ToFileTimeUtc()
            } catch {
                throw "Cannot verify the creation time for approved PSOBB client PID $($process.Id)"
            }
            $records.Add([pscustomobject]@{
                ServerEnvironment = $environmentName
                Channel = $candidateChannel
                Process = $process
                ProcessId = [int]$process.Id
                StartTimeUtc = $startTimeUtc
                StartTimeFileTimeUtc = $startTimeFileTimeUtc
                ExecutablePath = $expectedPath
                ExecutableSha256 = $identity.Sha256
            })
        }
    }
    @($records)
}

function Get-PSOBBAllClientProcessRecords {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $approvedPaths = [System.Collections.Generic.List[object]]::new()
    foreach ($channel in @('Stable', 'Canary', 'LocalLab')) {
        $approvedPaths.Add([pscustomobject]@{
            ServerEnvironment = 'Stable'
            Channel = $channel
            ExecutablePath = Get-PSOBBClientExecutablePath `
                -Layout $Layout -ServerEnvironment Stable -Channel $channel
        })
    }
    $approvedPaths.Add([pscustomobject]@{
        ServerEnvironment = 'CombatCanary'
        Channel = 'Native'
        ExecutablePath = Get-PSOBBClientExecutablePath `
            -Layout $Layout -ServerEnvironment CombatCanary -Channel Native
    })

    @(Get-PSOBBNamedProcessIdentityCensus `
        -ProcessName 'Psobb' -ApprovedPaths @($approvedPaths) | ForEach-Object {
        $identity = $_.ApprovedIdentity
        $classification = [string]$_.Classification
        if ($identity -and $classification -ceq 'ApprovedExactPath') {
            try {
                Assert-PSOBBApprovedClientExecutable `
                    -Path ([string]$identity.ExecutablePath) | Out-Null
            } catch {
                $classification = 'UnapprovedExecutableIdentity'
            }
        }
        $startTimeUtc = $null
        $startTimeFileTimeUtc = $null
        try {
            $startTimeUtc = $_.Process.StartTime.ToUniversalTime()
            $startTimeFileTimeUtc = [long]$startTimeUtc.ToFileTimeUtc()
        } catch { }
        [pscustomobject]@{
            ServerEnvironment = if ($identity) {
                [string]$identity.ServerEnvironment
            } else { 'Unknown' }
            Channel = if ($identity) { [string]$identity.Channel } else { 'Unknown' }
            Process = $_.Process
            ProcessId = [int]$_.ProcessId
            StartTimeUtc = $startTimeUtc
            StartTimeFileTimeUtc = $startTimeFileTimeUtc
            ExecutablePath = $_.ExecutablePath
            Classification = $classification
        }
    })
}

function Assert-PSOBBNoRunningClients {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $running = @(Get-PSOBBAllClientProcessRecords -Layout $Layout)
    if ($running.Count -gt 0) {
        $identities = $running | ForEach-Object {
            '{0}/{1} PID {2} ({3})' -f $_.ServerEnvironment, $_.Channel,
                $_.ProcessId, $_.Classification
        }
        throw "Refusing server lifecycle work while a named Psobb process is running ($($identities -join ', ')). Stop the exact approved client first; close an unknown or uninspectable process manually."
    }
    $true
}

function Assert-PSOBBGlobalStoppedRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [string]$Operation = 'Client runtime replacement'
    )

    $lifecycleEvidence = @(Get-PSOBBServerLifecycleEvidenceRecords `
            -Layout $Layout)
    $servers = @(Get-PSOBBServerEnvironmentProcessRecords -Layout $Layout)
    $clients = @(Get-PSOBBAllClientProcessRecords -Layout $Layout)
    $clientHelpers = @(Get-Process -Name 'online', 'option' `
            -ErrorAction SilentlyContinue)
    $listeners = @(Get-PSOBBReservedServerPortListeners)
    if ($lifecycleEvidence.Count -eq 0 -and
        $servers.Count -eq 0 -and
        $clients.Count -eq 0 -and
        $clientHelpers.Count -eq 0 -and
        $listeners.Count -eq 0) {
        return $true
    }

    $evidence = [System.Collections.Generic.List[string]]::new()
    foreach ($record in $lifecycleEvidence) {
        $evidence.Add(('{0} lifecycle evidence ({1})' -f
                [string]$record.ServerEnvironment,
                [string]$record.Classification))
    }
    foreach ($server in $servers) {
        $evidence.Add(('{0} server PID {1} ({2})' -f
                [string]$server.ServerEnvironment,
                [int]$server.ProcessId,
                [string]$server.Classification))
    }
    foreach ($client in $clients) {
        $evidence.Add(('{0}/{1} client PID {2} ({3})' -f
                [string]$client.ServerEnvironment,
                [string]$client.Channel,
                [int]$client.ProcessId,
                [string]$client.Classification))
    }
    foreach ($helper in $clientHelpers) {
        $evidence.Add(('{0} client helper PID {1}' -f
                [string]$helper.ProcessName,
                [int]$helper.Id))
    }
    foreach ($listener in $listeners) {
        $evidence.Add(('{0}:{1} listener PID {2}' -f
                [string]$listener.LocalAddress,
                [int]$listener.LocalPort,
                [int]$listener.OwningProcess))
    }
    throw ("$Operation requires both server environments, " +
        'all named clients/helpers, and all reserved listeners to be stopped ' +
        "($($evidence -join ', '))")
}

function Assert-PSOBBNoNamedClientProcesses {
    [CmdletBinding()]
    param()

    $named = @(Get-Process -Name 'Psobb' -ErrorAction SilentlyContinue)
    if ($named.Count -gt 0) {
        throw ('Refusing to change PSOBB GRAPHICCTRL while a Psobb process is ' +
            "running (PID(s): $($named.Id -join ', '))")
    }
    $true
}

function ConvertTo-PSOBBGraphicCtrlBytes {
    [CmdletBinding()]
    param([AllowEmptyCollection()][Parameter(Mandatory)][object[]]$Dwords)

    if ($Dwords.Count -ne 9) {
        throw 'PSOBB GRAPHICCTRL must contain exactly nine DWORD values'
    }
    $bytes = [byte[]]::new(36)
    for ($index = 0; $index -lt $Dwords.Count; $index++) {
        $text = [string]$Dwords[$index]
        if ($text -cnotmatch '^(?:0|[1-9][0-9]{0,9})$') {
            throw "PSOBB GRAPHICCTRL DWORD $index is not an unsigned 32-bit integer"
        }
        try {
            $value = [uint32]::Parse(
                $text,
                [System.Globalization.NumberStyles]::None,
                [System.Globalization.CultureInfo]::InvariantCulture)
        } catch {
            throw "PSOBB GRAPHICCTRL DWORD $index is outside the unsigned 32-bit range"
        }
        $word = [BitConverter]::GetBytes($value)
        if (-not [BitConverter]::IsLittleEndian) {
            [array]::Reverse($word)
        }
        [Array]::Copy($word, 0, $bytes, $index * 4, 4)
    }
    $bytes
}

function ConvertFrom-PSOBBGraphicCtrlBytes {
    [CmdletBinding()]
    param([AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes)

    if ($Bytes.Count -ne 36) {
        throw 'PSOBB GRAPHICCTRL must be exactly 36 bytes'
    }
    $values = [System.Collections.Generic.List[uint32]]::new()
    for ($index = 0; $index -lt 9; $index++) {
        $word = [byte[]]::new(4)
        [Array]::Copy($Bytes, $index * 4, $word, 0, 4)
        if (-not [BitConverter]::IsLittleEndian) {
            [array]::Reverse($word)
        }
        $values.Add([BitConverter]::ToUInt32($word, 0))
    }
    @($values)
}

function Get-PSOBBGraphicCtrlSha256 {
    [CmdletBinding()]
    param([AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes)

    if ($Bytes.Count -ne 36) {
        throw 'PSOBB GRAPHICCTRL hashing requires exactly 36 bytes'
    }
    [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Assert-PSOBBNativeGraphicsContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$NativeGraphics,
        [string]$Label = 'PSOBB native graphics profile'
    )

    if ($null -eq $NativeGraphics) {
        throw "$Label is missing"
    }
    Assert-PSOBBExactJsonProperties -Object $NativeGraphics -Label $Label -Names @(
        'presetId',
        'graphicCtrlDwords',
        'graphicCtrlSha256',
        'advancedEffectsPolicy',
        'pixelFogPolicy',
        'lowResolutionTexturesPolicy',
        'frameSkipPolicy') | Out-Null

    $presetId = [string]$NativeGraphics.presetId
    $expected = if ($presetId -ceq 'high-end') {
        [pscustomobject]@{
            Dwords = [object[]]@(0, 0, 0, 0, 1, 1, 1, 0, 0)
            Sha256 = '302f04ac1917b0eaecef147a99f7cada007b8bb8cc9ac1d9fd16b1a47d72e8a4'
            AdvancedEffectsPolicy = 'enabled'
        }
    } elseif ($presetId -ceq 'mid-compatibility') {
        [pscustomobject]@{
            Dwords = [object[]]@(1, 0, 0, 0, 1, 1, 1, 0, 0)
            Sha256 = 'a27bceac8141950aa389c1d96c70ebdb3db8a3c8dc88ef070cafffc245fc1917'
            AdvancedEffectsPolicy = 'compatibility'
        }
    } else {
        throw "$Label selects an unsupported preset"
    }

    $declaredDwords = @($NativeGraphics.graphicCtrlDwords)
    $bytes = ConvertTo-PSOBBGraphicCtrlBytes -Dwords $declaredDwords
    $actualHash = Get-PSOBBGraphicCtrlSha256 -Bytes $bytes
    if ([string]$NativeGraphics.graphicCtrlSha256 -cne $expected.Sha256 -or
        $actualHash -cne $expected.Sha256 -or
        [string]::Join(',', $declaredDwords) -cne
            [string]::Join(',', $expected.Dwords) -or
        [string]$NativeGraphics.advancedEffectsPolicy -cne
            $expected.AdvancedEffectsPolicy -or
        [string]$NativeGraphics.pixelFogPolicy -cne 'pixel' -or
        [string]$NativeGraphics.lowResolutionTexturesPolicy -cne 'disabled' -or
        [string]$NativeGraphics.frameSkipPolicy -cne 'disabled') {
        throw "$Label does not match its exact vector, digest, or native-detail policy"
    }

    [pscustomobject]@{
        PresetId = $presetId
        GraphicCtrlDwords = [uint32[]]$declaredDwords
        GraphicCtrlBytes = $bytes
        GraphicCtrlSha256 = $actualHash
        AdvancedEffectsPolicy = [string]$NativeGraphics.advancedEffectsPolicy
        PixelFogPolicy = [string]$NativeGraphics.pixelFogPolicy
        LowResolutionTexturesPolicy =
            [string]$NativeGraphics.lowResolutionTexturesPolicy
        FrameSkipPolicy = [string]$NativeGraphics.frameSkipPolicy
    }
}

function Get-PSOBBClientGraphicCtrlState {
    [CmdletBinding()]
    param([string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB')

    if (-not (Test-Path -LiteralPath $RegistryPath -PathType Container)) {
        throw "PSOBB client registry key is missing: $RegistryPath"
    }
    $registry = Get-Item -LiteralPath $RegistryPath
    if (@($registry.GetValueNames()) -cnotcontains 'GRAPHICCTRL') {
        throw 'PSOBB client GRAPHICCTRL registry value is missing'
    }
    if ($registry.GetValueKind('GRAPHICCTRL') -ne
            [Microsoft.Win32.RegistryValueKind]::Binary) {
        throw 'PSOBB client GRAPHICCTRL registry value is not binary'
    }
    $bytes = $registry.GetValue(
        'GRAPHICCTRL',
        $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($bytes -isnot [byte[]] -or $bytes.Count -ne 36) {
        throw 'PSOBB client GRAPHICCTRL registry value is not exactly 36 bytes'
    }
    $copy = [byte[]]::new(36)
    [Array]::Copy($bytes, $copy, 36)
    [pscustomobject]@{
        Dwords = [uint32[]](ConvertFrom-PSOBBGraphicCtrlBytes -Bytes $copy)
        Bytes = $copy
        Sha256 = Get-PSOBBGraphicCtrlSha256 -Bytes $copy
    }
}

function New-PSOBBClientGraphicCtrlBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$State
    )

    $marker = Assert-PSOBBRuntimeMarker -Layout $Layout
    if ($State.Bytes -isnot [byte[]] -or @($State.Dwords).Count -ne 9 -or
        [string]$State.Sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-PSOBBGraphicCtrlSha256 -Bytes $State.Bytes) -cne
            [string]$State.Sha256) {
        throw 'Cannot back up an invalid PSOBB GRAPHICCTRL state'
    }

    $backupRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Backups 'client-graphics-registry') `
        -Root $Layout.Root
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    Set-PSOBBProtectedAcl -Path $backupRoot
    $backupPath = Assert-PathWithinRoot -Path (Join-Path $backupRoot (
        'graphicctrl-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') +
        '-' + [Guid]::NewGuid().ToString('N') + '.json')) -Root $Layout.Root
    $backup = [ordered]@{
        schemaVersion = 1
        installationId = [string]$marker.installationId
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        registryValueName = 'GRAPHICCTRL'
        registryValueKind = 'Binary'
        graphicCtrlDwords = [uint32[]]$State.Dwords
        graphicCtrlSha256 = [string]$State.Sha256
    }
    $text = $backup | ConvertTo-Json -Depth 4
    $expectedHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.UTF8Encoding]::new($false).GetBytes($text))).ToLowerInvariant()
    Write-PSOBBAtomicUtf8Text `
        -Path $backupPath `
        -Text $text `
        -Root $Layout.Root `
        -ExpectedSha256 $expectedHash
    Set-PSOBBProtectedAcl -Path $backupPath
    $backupPath
}

function Set-PSOBBGraphicCtrlRegistryBytes {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][Parameter(Mandatory)][byte[]]$Bytes,
        [string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB'
    )

    if ($Bytes.Count -ne 36) {
        throw 'Refusing to write GRAPHICCTRL data that is not exactly 36 bytes'
    }
    New-ItemProperty -LiteralPath $RegistryPath -Name 'GRAPHICCTRL' `
        -PropertyType Binary -Value $Bytes -Force | Out-Null
    $verified = Get-PSOBBClientGraphicCtrlState -RegistryPath $RegistryPath
    $expectedHash = Get-PSOBBGraphicCtrlSha256 -Bytes $Bytes
    if ([string]$verified.Sha256 -cne $expectedHash) {
        throw 'PSOBB GRAPHICCTRL registry read-back verification failed'
    }
    $verified
}

function Set-PSOBBClientNativeGraphics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Profile,
        [string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB'
    )

    Assert-PSOBBRuntimeMarker -Layout $Layout | Out-Null
    Assert-PSOBBNoRunningClients -Layout $Layout | Out-Null
    Assert-PSOBBNoNamedClientProcesses | Out-Null
    $contract = Assert-PSOBBNativeGraphicsContract `
        -NativeGraphics $Profile.nativeGraphics `
        -Label 'Materialized client nativeGraphics'
    $prior = Get-PSOBBClientGraphicCtrlState -RegistryPath $RegistryPath
    if ([string]$prior.Sha256 -ceq $contract.GraphicCtrlSha256) {
        return [pscustomobject]@{
            Applied = $false
            PresetId = $contract.PresetId
            GraphicCtrlSha256 = $contract.GraphicCtrlSha256
            BackupPath = $null
        }
    }

    $backupPath = New-PSOBBClientGraphicCtrlBackup -Layout $Layout -State $prior
    try {
        $verified = Set-PSOBBGraphicCtrlRegistryBytes `
            -Bytes $contract.GraphicCtrlBytes `
            -RegistryPath $RegistryPath
        if ([string]$verified.Sha256 -cne $contract.GraphicCtrlSha256) {
            throw 'PSOBB GRAPHICCTRL does not match the selected profile after application'
        }
    } catch {
        $applyError = $_
        try {
            $restored = Set-PSOBBGraphicCtrlRegistryBytes `
                -Bytes $prior.Bytes `
                -RegistryPath $RegistryPath
            if ([string]$restored.Sha256 -cne [string]$prior.Sha256) {
                throw 'Restored GRAPHICCTRL digest does not match the pre-transaction state'
            }
        } catch {
            throw ('PSOBB native graphics application failed and GRAPHICCTRL ' +
                'rollback also failed; close the client and use the protected ' +
                "value-only backup. Apply: $($applyError.Exception.Message) " +
                "Rollback: $($_.Exception.Message)")
        }
        throw $applyError
    }

    [pscustomobject]@{
        Applied = $true
        PresetId = $contract.PresetId
        GraphicCtrlSha256 = $contract.GraphicCtrlSha256
        BackupPath = $backupPath
    }
}

function Restore-PSOBBClientGraphicCtrlBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$BackupPath,
        [string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB'
    )

    $marker = Assert-PSOBBRuntimeMarker -Layout $Layout
    Assert-PSOBBNoRunningClients -Layout $Layout | Out-Null
    Assert-PSOBBNoNamedClientProcesses | Out-Null
    $backupRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Backups 'client-graphics-registry') `
        -Root $Layout.Root
    $safeBackup = Assert-PathWithinRoot -Path $BackupPath -Root $backupRoot
    if (-not (Test-Path -LiteralPath $safeBackup -PathType Leaf)) {
        throw 'The protected GRAPHICCTRL backup is missing'
    }
    $item = Get-Item -LiteralPath $safeBackup -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 8KB) {
        throw 'The protected GRAPHICCTRL backup has an invalid filesystem type or size'
    }
    if (-not (Get-Acl -LiteralPath $safeBackup).AreAccessRulesProtected) {
        throw 'The GRAPHICCTRL backup no longer has a protected DACL'
    }
    try {
        $backup = Get-Content -Raw -LiteralPath $safeBackup |
            ConvertFrom-Json -Depth 5 -DateKind String
    } catch {
        throw 'The protected GRAPHICCTRL backup is not valid JSON'
    }
    Assert-PSOBBExactJsonProperties -Object $backup `
        -Label 'Protected GRAPHICCTRL backup' -Names @(
            'schemaVersion', 'installationId', 'createdAtUtc',
            'registryValueName', 'registryValueKind', 'graphicCtrlDwords',
            'graphicCtrlSha256') | Out-Null
    $bytes = ConvertTo-PSOBBGraphicCtrlBytes -Dwords @($backup.graphicCtrlDwords)
    $expectedHash = Get-PSOBBGraphicCtrlSha256 -Bytes $bytes
    if ([int]$backup.schemaVersion -ne 1 -or
        [string]$backup.installationId -cne [string]$marker.installationId -or
        [string]$backup.registryValueName -cne 'GRAPHICCTRL' -or
        [string]$backup.registryValueKind -cne 'Binary' -or
        [string]$backup.graphicCtrlSha256 -cne $expectedHash) {
        throw 'The protected GRAPHICCTRL backup does not match this runtime or its digest'
    }

    $prior = Get-PSOBBClientGraphicCtrlState -RegistryPath $RegistryPath
    if ([string]$prior.Sha256 -ceq $expectedHash) {
        return [pscustomobject]@{
            Restored = $false
            GraphicCtrlSha256 = $expectedHash
            BackupPath = $safeBackup
        }
    }
    try {
        $verified = Set-PSOBBGraphicCtrlRegistryBytes `
            -Bytes $bytes `
            -RegistryPath $RegistryPath
        if ([string]$verified.Sha256 -cne $expectedHash) {
            throw 'Backup restoration read-back did not match its digest'
        }
    } catch {
        $restoreError = $_
        try {
            Set-PSOBBGraphicCtrlRegistryBytes `
                -Bytes $prior.Bytes `
                -RegistryPath $RegistryPath | Out-Null
        } catch {
            throw ('Protected GRAPHICCTRL restoration failed and its transaction ' +
                "also failed to preserve the current value. Restore: $($restoreError.Exception.Message) " +
                "Preserve: $($_.Exception.Message)")
        }
        throw $restoreError
    }
    [pscustomobject]@{
        Restored = $true
        GraphicCtrlSha256 = $expectedHash
        BackupPath = $safeBackup
    }
}

function Assert-PSOBBClientLoginRegistry {
    [CmdletBinding()]
    param([string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB')

    if (-not (Test-Path -LiteralPath $RegistryPath -PathType Container)) {
        throw "PSOBB client registry key is missing: $RegistryPath"
    }
    $registry = Get-Item -LiteralPath $RegistryPath
    $names = @($registry.GetValueNames())
    foreach ($name in @('ACCOUNT_CHECK', 'ACCOUNT', 'PASSWORD')) {
        if ($names -cnotcontains $name) {
            throw "PSOBB client login registry value is missing: $name"
        }
    }
    $passwordKind = $registry.GetValueKind('PASSWORD')
    if ($registry.GetValueKind('ACCOUNT_CHECK') -ne
            [Microsoft.Win32.RegistryValueKind]::DWord -or
        $registry.GetValueKind('ACCOUNT') -ne
            [Microsoft.Win32.RegistryValueKind]::String -or
        $passwordKind -notin @(
            [Microsoft.Win32.RegistryValueKind]::String,
            [Microsoft.Win32.RegistryValueKind]::Binary)) {
        throw 'PSOBB client login registry values have unexpected types'
    }
    $accountCheck = [int]$registry.GetValue(
        'ACCOUNT_CHECK',
        -1,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($accountCheck -notin @(0, 1)) {
        throw 'PSOBB client ACCOUNT_CHECK must be 0 or 1'
    }

    [pscustomobject]@{
        RegistryPath = $RegistryPath
        RememberLoginEnabled = ($accountCheck -eq 1)
    }
}

function Set-PSOBBClientRememberedLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$Enabled,
        [switch]$ClearCredentials,
        [string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB'
    )

    if (-not (Test-Path -LiteralPath $RegistryPath -PathType Container)) {
        throw "PSOBB client registry key is missing: $RegistryPath"
    }
    $registry = Get-Item -LiteralPath $RegistryPath
    $names = @($registry.GetValueNames())
    if ($names -cnotcontains 'ACCOUNT') {
        New-ItemProperty -LiteralPath $RegistryPath -Name 'ACCOUNT' `
            -PropertyType String -Value '' -Force | Out-Null
    } elseif ($registry.GetValueKind('ACCOUNT') -ne
            [Microsoft.Win32.RegistryValueKind]::String) {
        throw 'PSOBB client login registry value has an unexpected type: ACCOUNT'
    }
    if ($names -cnotcontains 'PASSWORD') {
        New-ItemProperty -LiteralPath $RegistryPath -Name 'PASSWORD' `
            -PropertyType String -Value '' -Force | Out-Null
    } elseif ($registry.GetValueKind('PASSWORD') -notin @(
            [Microsoft.Win32.RegistryValueKind]::String,
            [Microsoft.Win32.RegistryValueKind]::Binary)) {
        throw 'PSOBB client login registry value has an unexpected type: PASSWORD'
    }
    if ($ClearCredentials) {
        New-ItemProperty -LiteralPath $RegistryPath -Name 'ACCOUNT' `
            -PropertyType String -Value '' -Force | Out-Null
        New-ItemProperty -LiteralPath $RegistryPath -Name 'PASSWORD' `
            -PropertyType String -Value '' -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $RegistryPath -Name 'ACCOUNT_CHECK' `
        -PropertyType DWord -Value $(if ($Enabled) { 1 } else { 0 }) `
        -Force | Out-Null
    Assert-PSOBBClientLoginRegistry -RegistryPath $RegistryPath
}

function Clear-PSOBBClientSavedCredentials {
    [CmdletBinding()]
    param([string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB')

    $policy = Assert-PSOBBClientLoginRegistry -RegistryPath $RegistryPath
    Set-PSOBBClientRememberedLogin `
        -Enabled ([bool]$policy.RememberLoginEnabled) `
        -ClearCredentials `
        -RegistryPath $RegistryPath
}

function Set-PSOBBClientManualLogin {
    [CmdletBinding()]
    param([string]$RegistryPath = 'HKCU:\Software\SonicTeam\PSOBB')

    Set-PSOBBClientRememberedLogin `
        -Enabled $false `
        -ClearCredentials `
        -RegistryPath $RegistryPath | Out-Null
}

function Test-PSOBBGamePasswordLength {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Password)

    ($Password.Length -ge 1) -and ($Password.Length -le 16)
}

function New-CrockfordSecret {
    [CmdletBinding()]
    param([ValidateRange(1, 128)][int]$Length = 16)

    $alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    $buffer = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    -join ($buffer | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}
