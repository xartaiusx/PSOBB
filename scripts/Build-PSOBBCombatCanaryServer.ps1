[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Verify', 'Build')]
    [string]$Action = 'Verify',

    [string]$RuntimeRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'PSOBB-Runtime'),

    [string]$BuildContractPath = (Join-Path (Split-Path -Parent $PSScriptRoot) `
        'config\combat-canary-build.json'),

    [string]$PatchSeriesPath = (Join-Path (Split-Path -Parent $PSScriptRoot) `
        'patches\newserv\series.json'),

    [ValidateRange(1, 32)]
    [int]$Parallel = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$script:CanonicalRuntimeRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
    [System.IO.Path]::GetFullPath((Join-Path $script:RepositoryRoot 'PSOBB-Runtime')))
$script:RuntimeRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
    [System.IO.Path]::GetFullPath($RuntimeRoot))
$script:ContractPath = [System.IO.Path]::GetFullPath($BuildContractPath)
$script:SeriesPath = [System.IO.Path]::GetFullPath($PatchSeriesPath)
$script:SourceLockPath = Join-Path $script:RepositoryRoot 'config\sources.lock.json'
$script:ContractSchemaPath = Join-Path $script:RepositoryRoot `
    'config\schemas\combat-canary-build.schema.json'
$script:SeriesSchemaPath = Join-Path $script:RepositoryRoot `
    'config\schemas\newserv-patch-series.schema.json'
$script:SourceCommit = 'd754a34e271a4fb387be63db34ef0c303e49dcf2'
$script:SourceDateEpoch = 1783778777
$script:BuildRevision = 'd754a34'
$script:ToolRecords = $null
$script:NativeExecutionManifest = $null
$script:BuildBoundaryDepth = 0

function Assert-CanonicalRuntimeRoot {
    if (-not [string]::Equals(
            [System.IO.Path]::TrimEndingDirectorySeparator(
                [System.IO.Path]::GetFullPath($script:RuntimeRoot)),
            $script:CanonicalRuntimeRoot,
            [System.StringComparison]::Ordinal)) {
        throw "RuntimeRoot must be the exact canonical path: $($script:CanonicalRuntimeRoot)"
    }
    $script:CanonicalRuntimeRoot
}

function Assert-ReparseFreePathHierarchy {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'path'
    )
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "Unable to resolve the root for ${Label}: $Path"
    }
    $candidates = [System.Collections.Generic.List[string]]::new()
    $candidates.Add($root)
    $current = $root
    $relative = $full.Substring($root.Length).Trim(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
    if (-not [string]::IsNullOrEmpty($relative)) {
        foreach ($part in @($relative -split '[\\/]' | Where-Object {
                    -not [string]::IsNullOrEmpty($_)
                })) {
            $current = Join-Path $current $part
            $candidates.Add($current)
        }
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [string]$item.LinkType -in @('SymbolicLink', 'Junction')) {
            throw "Reparse point in ${Label} hierarchy: $candidate"
        }
    }
    $full
}

function Assert-ReparseFreeDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'directory'
    )
    $full = Assert-ReparseFreePathHierarchy -Path $Path -Label $Label
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "Required ${Label} is missing or is not a directory: $full"
    }
    $full
}

function New-ReparseFreeDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'directory'
    )
    $full = Assert-ReparseFreePathHierarchy -Path $Path -Label $Label
    New-Item -ItemType Directory -Path $full -Force | Out-Null
    Assert-ReparseFreeDirectory -Path $full -Label $Label
}

function Get-LowerSha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile {
    param([Parameter(Mandatory)][string]$Path)
    $full = Assert-ReparseFreePathHierarchy -Path $Path -Label 'file'
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Required file is missing: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse points are forbidden for this file: $full"
    }
    $item
}

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )
    $fullPath = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath($Path))
    $fullRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath($Root))
    if ([string]::Equals(
            $fullPath, $fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-OrdinalRelativeFiles {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string]$Label = 'file tree'
    )
    $rootPath = Assert-ReparseFreeDirectory -Path $Root -Label $Label
    $byPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $caseInsensitivePaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force)) {
        $file = Assert-RegularFile -Path $item.FullName
        $relative = [System.IO.Path]::GetRelativePath($rootPath, $file.FullName).
            Replace('\', '/')
        if (-not $byPath.TryAdd($relative, $file) -or
            -not $caseInsensitivePaths.Add($relative)) {
            throw "$Label contains a duplicate or case-colliding path: $relative"
        }
    }
    $paths = [string[]]@($byPath.Keys)
    [Array]::Sort($paths, [System.StringComparer]::Ordinal)
    foreach ($relative in $paths) {
        [pscustomobject]@{
            RelativePath = $relative
            File = $byPath[$relative]
        }
    }
}

function Assert-FileRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Record
    )
    $item = Assert-RegularFile -Path $Path
    if ($item.Length -ne [long]$Record.size) {
        throw "File size mismatch: $Path"
    }
    if ((Get-LowerSha256 -Path $item.FullName) -cne [string]$Record.sha256) {
        throw "File SHA-256 mismatch: $Path"
    }
    $item
}

function Resolve-ContractRelativePath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [System.IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath.Contains(':', [System.StringComparison]::Ordinal) -or
        $RelativePath.Contains('..', [System.StringComparison]::Ordinal)) {
        throw "Unsafe contract-relative path: $RelativePath"
    }
    $canonicalRoot = Assert-ReparseFreePathHierarchy -Path $Root -Label 'contract root'
    $full = [System.IO.Path]::GetFullPath(
        (Join-Path $canonicalRoot ($RelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar))))
    $prefix = $canonicalRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Contract path escaped its root: $RelativePath"
    }
    Assert-ReparseFreePathHierarchy -Path $full -Label 'contract path'
}

function Get-VerifiedToolRecord {
    param([Parameter(Mandatory)][string]$Id)
    if ($null -eq $script:ToolRecords -or -not $script:ToolRecords.ContainsKey($Id)) {
        throw "Tool was not verified before use: $Id"
    }
    $verified = $script:ToolRecords[$Id]
    $item = Assert-RegularFile -Path ([string]$verified.Path)
    if ($item.Length -ne [long]$verified.Record.executableSize -or
        (Get-LowerSha256 -Path $item.FullName) -cne [string]$verified.Record.sha256) {
        throw "Toolchain binary changed before invocation: $Id"
    }
    [pscustomobject]@{
        Id = $Id
        Path = $item.FullName
        Record = $verified.Record
    }
}

function Convert-NativeTextToLines {
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    @([regex]::Split($Text.TrimEnd("`r", "`n"), '\r?\n'))
}

function Invoke-PinnedNative {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$Label = $Id,
        [string]$WorkingDirectory,
        [hashtable]$Environment = @{},
        [string[]]$PathDirectories = @()
    )
    $tool = Get-VerifiedToolRecord -Id $Id
    $systemRoot = Split-Path -Parent ([Environment]::SystemDirectory)
    $system32 = [Environment]::SystemDirectory
    $temporary = Assert-ReparseFreeDirectory -Path ([System.IO.Path]::GetTempPath()) `
        -Label 'native temporary root'
    $pathEntries = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($system32) + @($PathDirectories)) {
        if ([string]::IsNullOrWhiteSpace([string]$entry)) { continue }
        $safeEntry = Assert-ReparseFreeDirectory -Path ([string]$entry) `
            -Label 'native PATH directory'
        if (-not $pathEntries.Contains($safeEntry)) { $pathEntries.Add($safeEntry) }
    }
    Assert-NativeToolPayloadBoundary -Id $Id -ToolPath $tool.Path `
        -PathDirectories @($pathEntries)
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $tool.Path
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $startInfo.WorkingDirectory = Assert-ReparseFreeDirectory `
            -Path $WorkingDirectory -Label 'native working directory'
    }
    $startInfo.Environment.Clear()
    $startInfo.Environment['SystemRoot'] = $systemRoot
    $startInfo.Environment['WINDIR'] = $systemRoot
    $startInfo.Environment['ComSpec'] = (Get-VerifiedToolRecord -Id 'cmd').Path
    $startInfo.Environment['TEMP'] = $temporary
    $startInfo.Environment['TMP'] = $temporary
    $startInfo.Environment['PATH'] = ($pathEntries -join ';')
    $startInfo.Environment['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    $startInfo.Environment['LANG'] = 'C'
    $startInfo.Environment['LC_ALL'] = 'C'
    $startInfo.Environment['PROCESSOR_ARCHITECTURE'] = 'AMD64'
    foreach ($name in @($Environment.Keys)) {
        if ([string]::IsNullOrWhiteSpace([string]$name) -or
            [string]$name -match '=') {
            throw 'Invalid hermetic native environment name'
        }
        $startInfo.Environment[[string]$name] = [string]$Environment[$name]
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "$Label did not start" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "$Label failed with exit code $($process.ExitCode)"
        }
        [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            StdOut = [string]$stdout
            StdErr = [string]$stderr
            StdOutLines = @(Convert-NativeTextToLines -Text ([string]$stdout))
            StdErrLines = @(Convert-NativeTextToLines -Text ([string]$stderr))
        }
    } finally {
        $process.Dispose()
    }
}

function Get-ToolPath {
    param([Parameter(Mandatory)][string]$Id)
    (Get-VerifiedToolRecord -Id $Id).Path
}

function Assert-GitMetadataPolicy {
    param(
        [Parameter(Mandatory)][string]$GitDirectory,
        [string]$Label = 'Git repository',
        [string]$AllowedAlternateObjectRoot
    )
    $metadataRoot = Assert-ReparseFreeDirectory -Path $GitDirectory `
        -Label "$Label metadata"
    $items = @(Get-ChildItem -LiteralPath $metadataRoot -Recurse -Force `
            -ErrorAction Stop)
    $reparse = @($items | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [string]::IsNullOrWhiteSpace([string]$_.LinkType)
        })
    if ($reparse.Count -ne 0) {
        throw "$Label metadata contains a reparse point: $($reparse[0].FullName)"
    }
    $forbidden = @(
        'refs/replace',
        'logs/refs/replace',
        'info/grafts',
        'info/attributes',
        'objects/info/http-alternates',
        'commondir',
        'config.worktree',
        'shallow'
    )
    foreach ($item in $items) {
        $relative = [System.IO.Path]::GetRelativePath($metadataRoot, $item.FullName).
            Replace('\', '/')
        foreach ($blocked in $forbidden) {
            if ([string]::Equals($relative, $blocked,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                $relative.StartsWith($blocked + '/',
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                ($blocked -ceq 'shallow' -and $relative.StartsWith(
                        'shallow.', [System.StringComparison]::OrdinalIgnoreCase))) {
                throw "$Label metadata contains a forbidden replace, graft, shallow, or attributes mechanism: $relative"
            }
        }
    }
    $packedRefsPath = Join-Path $metadataRoot 'packed-refs'
    if (Test-Path -LiteralPath $packedRefsPath -PathType Leaf) {
        Assert-RegularFile -Path $packedRefsPath | Out-Null
        if ([System.IO.File]::ReadAllText($packedRefsPath) -match
            '(?im)^[0-9a-f]{40,64}\s+refs/replace(?:/|$)') {
            throw "$Label packed refs contain a forbidden replacement reference"
        }
    }
    $alternatesPath = Join-Path $metadataRoot 'objects\info\alternates'
    if (Test-Path -LiteralPath $alternatesPath) {
        Assert-RegularFile -Path $alternatesPath | Out-Null
        if ([string]::IsNullOrWhiteSpace($AllowedAlternateObjectRoot)) {
            throw "$Label object store contains an unapproved alternate"
        }
        $allowed = Assert-ReparseFreeDirectory -Path $AllowedAlternateObjectRoot `
            -Label "$Label alternate object root"
        $alternateReparse = @(Get-ChildItem -LiteralPath $allowed -Recurse -Force `
                -ErrorAction Stop | Where-Object {
                ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not [string]::IsNullOrWhiteSpace([string]$_.LinkType)
            })
        if ($alternateReparse.Count -ne 0) {
            throw "$Label alternate object root contains a reparse point"
        }
        $lines = @(Get-Content -LiteralPath $alternatesPath | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            })
        if ($lines.Count -ne 1 -or -not [string]::Equals(
                [System.IO.Path]::TrimEndingDirectorySeparator(
                    [System.IO.Path]::GetFullPath([string]$lines[0])),
                [System.IO.Path]::TrimEndingDirectorySeparator($allowed),
                [System.StringComparison]::Ordinal)) {
            throw "$Label object store alternate is not the exact approved local root"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($AllowedAlternateObjectRoot)) {
        throw "$Label is missing its approved local object-store alternate"
    }
}

function Assert-GitRepositoryConfig {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'Git repository',
        [string]$AllowedAlternateObjectRoot
    )
    $repository = Assert-ReparseFreeDirectory -Path $Path -Label $Label
    $gitDirectory = Assert-ReparseFreeDirectory -Path (Join-Path $repository '.git') `
        -Label "$Label metadata"
    Assert-GitMetadataPolicy -GitDirectory $gitDirectory -Label $Label `
        -AllowedAlternateObjectRoot $AllowedAlternateObjectRoot
    $configPath = Join-Path $gitDirectory 'config'
    Assert-RegularFile -Path $configPath | Out-Null
    $section = $null
    $entries = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($line in @(Get-Content -LiteralPath $configPath)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
        if ([string]$line -match '^\s*\[(?<section>[^\]]+)\]\s*$') {
            $section = [string]$Matches.section
            if ($section -cne 'core') {
                throw "$Label local config contains a disallowed section: $section"
            }
            continue
        }
        if ($null -eq $section -or
            [string]$line -notmatch '^\s*(?<key>[A-Za-z][A-Za-z0-9]*)\s*=\s*(?<value>\S+)\s*$') {
            throw "$Label local config contains unsupported syntax"
        }
        $key = $section + '.' + [string]$Matches.key
        if (-not $entries.TryAdd($key, [string]$Matches.value)) {
            throw "$Label local config contains a duplicate key: $key"
        }
    }
    $expectedValues = [ordered]@{
        'core.repositoryformatversion' = @('0')
        'core.filemode' = @('false')
        'core.bare' = @('false')
        'core.logallrefupdates' = @('true')
        'core.symlinks' = @('false', 'true')
        'core.ignorecase' = @('true')
    }
    if ($entries.Count -ne $expectedValues.Count) {
        throw "$Label local config is not the minimal exact allowlist"
    }
    foreach ($key in @($entries.Keys)) {
        if (-not $expectedValues.Contains($key) -or
            [string]$entries[$key] -cnotin @($expectedValues[$key])) {
            throw "$Label local config contains a disallowed key or value: $key"
        }
    }
    $repository
}

function Get-VerifiedGitWorkingDirectory {
    $path = Join-Path $script:CanonicalRuntimeRoot 'trust\git-empty-workdir'
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        New-ReparseFreeDirectory -Path $path -Label 'Git empty working directory' | Out-Null
    }
    $path = Assert-ReparseFreeDirectory -Path $path -Label 'Git empty working directory'
    if (@(Get-ChildItem -LiteralPath $path -Force).Count -ne 0) {
        throw 'The verified Git working directory is not empty'
    }
    $path
}

function Invoke-HermeticGit {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$Label = 'git',
        [string]$RepositoryPath,
        [string]$AllowedAlternateObjectRoot
    )
    $git = Get-ToolPath -Id 'git'
    $emptyWorkingDirectory = Get-VerifiedGitWorkingDirectory
    $emptyExecDirectory = Join-Path $script:CanonicalRuntimeRoot 'trust\git-empty-exec-path'
    if (-not (Test-Path -LiteralPath $emptyExecDirectory -PathType Container)) {
        New-ReparseFreeDirectory -Path $emptyExecDirectory `
            -Label 'Git empty execution path' | Out-Null
    }
    $emptyExecDirectory = Assert-ReparseFreeDirectory -Path $emptyExecDirectory `
        -Label 'Git empty execution path'
    if (@(Get-ChildItem -LiteralPath $emptyExecDirectory -Force).Count -ne 0) {
        throw 'The verified Git execution path is not empty'
    }
    $environment = @{
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_SYSTEM = 'NUL'
        GIT_CONFIG_GLOBAL = 'NUL'
        GIT_TERMINAL_PROMPT = '0'
        GCM_INTERACTIVE = 'never'
        GIT_ALLOW_PROTOCOL = 'file'
        GIT_PROTOCOL_FROM_USER = '0'
        GIT_NO_REPLACE_OBJECTS = '1'
        GIT_EXEC_PATH = $emptyExecDirectory
        GIT_OPTIONAL_LOCKS = '0'
        GIT_CEILING_DIRECTORIES = $emptyWorkingDirectory
    }
    $baseArguments = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($RepositoryPath)) {
        $repository = Assert-GitRepositoryConfig -Path $RepositoryPath -Label $Label `
            -AllowedAlternateObjectRoot $AllowedAlternateObjectRoot
        $baseArguments.Add('--git-dir=' + (Join-Path $repository '.git'))
        $baseArguments.Add('--work-tree=' + $repository)
    }
    $baseArguments.AddRange([string[]]@(
        '--no-optional-locks',
        '-c', 'core.autocrlf=true',
        '-c', 'core.fsmonitor=false',
        '-c', 'core.hooksPath=NUL',
        '-c', 'credential.helper=',
        '-c', 'core.askPass=',
        '-c', 'protocol.allow=never',
        '-c', 'protocol.file.allow=always'
    ))
    Invoke-PinnedNative -Id 'git' -Arguments (@($baseArguments) + @($Arguments)) `
        -Label $Label -Environment $environment -WorkingDirectory $emptyWorkingDirectory
    if (@(Get-ChildItem -LiteralPath $emptyWorkingDirectory -Force).Count -ne 0) {
        throw 'Git wrote state to its verified empty working directory'
    }
}

function Write-MinimalGitRepositoryConfig {
    param(
        [Parameter(Mandatory)][string]$Path,
        [bool]$Symlinks = $false
    )
    $repository = Assert-ReparseFreeDirectory -Path $Path -Label 'Git destination repository'
    $gitDirectory = Assert-ReparseFreeDirectory -Path (Join-Path $repository '.git') `
        -Label 'Git destination metadata'
    $configPath = Join-Path $gitDirectory 'config'
    Assert-RegularFile -Path $configPath | Out-Null
    $temporaryPath = Join-Path $gitDirectory ('config.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $text = "[core]`n" +
        "`trepositoryformatversion = 0`n" +
        "`tfilemode = false`n" +
        "`tbare = false`n" +
        "`tlogallrefupdates = true`n" +
        ("`tsymlinks = " + $Symlinks.ToString().ToLowerInvariant() + "`n") +
        "`tignorecase = true`n"
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath, $text, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($temporaryPath, $configPath, $true)
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
    Assert-GitRepositoryConfig -Path $repository -Label 'Git destination repository' | Out-Null
}

function New-LocalObjectGitCheckout {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][string]$Commit,
        [Parameter(Mandatory)][string]$Label
    )
    $source = Assert-GitRepositoryConfig -Path $SourcePath -Label "$Label source"
    $sourceObjects = Assert-ReparseFreeDirectory -Path (Join-Path $source '.git\objects') `
        -Label "$Label source objects"
    $destination = [System.IO.Path]::GetFullPath($DestinationPath)
    Assert-ReparseFreePathHierarchy -Path $destination -Label "$Label destination" | Out-Null
    if (Test-Path -LiteralPath $destination) {
        throw "$Label destination already exists"
    }
    Invoke-HermeticGit -Arguments @('init', '--quiet', $destination) `
        -Label "$Label destination init" | Out-Null
    Assert-ReparseFreeDirectory -Path $destination -Label "$Label destination" | Out-Null
    Write-MinimalGitRepositoryConfig -Path $destination
    $infoRoot = Join-Path $destination '.git\objects\info'
    if (-not (Test-Path -LiteralPath $infoRoot -PathType Container)) {
        New-ReparseFreeDirectory -Path $infoRoot -Label "$Label object info" | Out-Null
    }
    $alternatesPath = Join-Path $infoRoot 'alternates'
    [System.IO.File]::WriteAllText(
        $alternatesPath,
        ([System.IO.Path]::TrimEndingDirectorySeparator($sourceObjects) + "`n"),
        [System.Text.UTF8Encoding]::new($false))
    Invoke-HermeticGit -RepositoryPath $destination `
        -AllowedAlternateObjectRoot $sourceObjects `
        -Arguments @('checkout', '--quiet', '--detach', $Commit) `
        -Label "$Label destination checkout" | Out-Null
    $head = Invoke-HermeticGit -RepositoryPath $destination `
        -AllowedAlternateObjectRoot $sourceObjects `
        -Arguments @('rev-parse', 'HEAD') -Label "$Label destination revision"
    $lines = @($head.StdOutLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        })
    if ($lines.Count -ne 1 -or [string]$lines[0] -cne $Commit) {
        throw "$Label destination did not materialize the locked commit"
    }
    [pscustomobject]@{
        Repository = $destination
        AlternateObjectRoot = $sourceObjects
    }
}

function ConvertFrom-GitTrackedFileInventoryText {
    param(
        [AllowEmptyString()][string]$Text,
        [string]$Label = 'Git tracked-file inventory'
    )
    $records = [System.Collections.Generic.List[object]]::new()
    $byPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $normalizedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrEmpty($Text)) {
        return [pscustomobject]@{ Records = @(); ByPath = $byPath }
    }
    if ($Text[$Text.Length - 1] -ne [char]0) {
        throw "$Label is not NUL-terminated"
    }
    foreach ($entry in $Text.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $match = [regex]::Match(
            $entry,
            '^(?<mode>[0-9]{6}) (?<oid>[0-9a-f]{40}) 0\t(?<path>.+)$',
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if (-not $match.Success) { throw "$Label contains an invalid index record" }
        $mode = $match.Groups['mode'].Value
        if ($mode -cnotin @('100644', '100755', '120000')) {
            throw "$Label contains an unsupported Git mode: $mode"
        }
        $path = $match.Groups['path'].Value
        if ($path -match '[\x00-\x1F\x7F]' -or
            $path.Contains('\', [System.StringComparison]::Ordinal) -or
            $path.Contains(':', [System.StringComparison]::Ordinal) -or
            [System.IO.Path]::IsPathRooted($path) -or
            $path.Normalize([System.Text.NormalizationForm]::FormC) -cne $path) {
            throw "$Label contains an unsafe or non-normalized path"
        }
        $parts = @($path.Split('/'))
        if ($parts.Count -eq 0 -or @($parts | Where-Object {
                    [string]::IsNullOrEmpty($_) -or $_ -cin @('.', '..') -or
                    $_.EndsWith(' ', [System.StringComparison]::Ordinal) -or
                    $_.EndsWith('.', [System.StringComparison]::Ordinal)
                }).Count -ne 0) {
            throw "$Label contains an unsafe path: $path"
        }
        $record = [pscustomobject]@{
            Mode = $mode
            ObjectId = $match.Groups['oid'].Value
            Path = $path
        }
        if (-not $byPath.TryAdd($path, $record) -or
            -not $normalizedPaths.Add($path)) {
            throw "$Label contains a duplicate or case-colliding normalized path: $path"
        }
        $records.Add($record)
    }
    $orderedPaths = [string[]]@($byPath.Keys)
    [Array]::Sort($orderedPaths, [System.StringComparer]::Ordinal)
    $orderedRecords = @($orderedPaths | ForEach-Object { $byPath[$_] })
    [pscustomobject]@{ Records = $orderedRecords; ByPath = $byPath }
}

function Get-GitTrackedFileInventory {
    param(
        [Parameter(Mandatory)][string]$RepositoryPath,
        [Parameter(Mandatory)][string]$AllowedAlternateObjectRoot,
        [string]$Label = 'Git tracked-file inventory'
    )
    $result = Invoke-HermeticGit -RepositoryPath $RepositoryPath `
        -AllowedAlternateObjectRoot $AllowedAlternateObjectRoot `
        -Arguments @('ls-files', '-s', '-z') -Label $Label
    ConvertFrom-GitTrackedFileInventoryText -Text ([string]$result.StdOut) -Label $Label
}

function Resolve-GitTrackedWorktreeSource {
    param(
        [Parameter(Mandatory)][string]$RepositoryPath,
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][string]$TrackedPath
    )
    $repository = Assert-ReparseFreeDirectory -Path $RepositoryPath `
        -Label 'tracked package checkout'
    $currentPath = $TrackedPath
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($depth in 0..31) {
        if (-not $Inventory.ByPath.ContainsKey($currentPath)) {
            throw "Tracked package path is absent from the index: $currentPath"
        }
        if (-not $visited.Add($currentPath)) {
            throw "Tracked package link cycle detected: $TrackedPath"
        }
        $record = $Inventory.ByPath[$currentPath]
        $worktreePath = Resolve-ContractRelativePath -Root $repository `
            -RelativePath $currentPath
        $item = Assert-RegularFile -Path $worktreePath
        if ([string]$record.Mode -cne '120000') {
            return [pscustomobject]@{
                TrackedPath = $TrackedPath
                ResolvedTrackedPath = $currentPath
                Mode = [string]$record.Mode
                SourcePath = $item.FullName
            }
        }
        $linkTarget = [System.IO.File]::ReadAllText($item.FullName)
        if ([string]::IsNullOrWhiteSpace($linkTarget) -or
            $linkTarget -match '[\x00\r\n]' -or
            $linkTarget.Contains('\', [System.StringComparison]::Ordinal) -or
            $linkTarget.Contains(':', [System.StringComparison]::Ordinal) -or
            [System.IO.Path]::IsPathRooted($linkTarget)) {
            throw "Tracked package link has an unsafe target: $currentPath"
        }
        $targetPath = [System.IO.Path]::GetFullPath((Join-Path (
                    Split-Path -Parent $item.FullName) $linkTarget.Replace('/', '\')))
        if (-not (Test-PathWithinRoot -Path $targetPath -Root $repository)) {
            throw "Tracked package link escapes the checkout: $currentPath"
        }
        $currentPath = [System.IO.Path]::GetRelativePath($repository, $targetPath).
            Replace('\', '/')
    }
    throw "Tracked package link depth exceeded: $TrackedPath"
}

function Get-NewservPackageSystemPlan {
    param(
        [Parameter(Mandatory)][string]$RepositoryPath,
        [Parameter(Mandatory)]$Inventory
    )
    $planned = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $caseInsensitiveDestinations = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($record in @($Inventory.Records)) {
        $trackedPath = [string]$record.Path
        if (-not $trackedPath.StartsWith('system/', [System.StringComparison]::Ordinal)) {
            continue
        }
        $tail = $trackedPath.Substring('system/'.Length)
        $parts = @($tail.Split('/'))
        $name = $parts[-1]
        $include = $name -cne '.DS_Store' -and
            -not $name.EndsWith('.WIP-s', [System.StringComparison]::Ordinal)
        if ($parts.Count -eq 1 -and
            $name.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase) -and
            $name -cne 'config.example.json') { $include = $false }
        if ($parts[0] -ceq 'ep3' -and $parts.Count -ge 2 -and
            -not $parts[1].StartsWith('cardtex', [System.StringComparison]::Ordinal)) {
            $include = $false
        }
        if ($parts[0] -ceq 'client-functions' -and
            ($parts.Count -ne 2 -or $parts[1] -cnotin @(
                    'AccurateKillCount.s',
                    'FastTekker.s',
                    'HungryMagSound.s',
                    'NoRareSelling.s',
                    'PaletteBB.s',
                    'notes.txt'
                ))) {
            $include = $false
        }
        if ($parts[0] -cin @('dol', 'licenses', 'players')) { $include = $false }
        if ($parts[0] -ceq 'quests' -and $parts.Count -ge 2 -and
            $parts[1] -notin @('private', 'includes')) { $include = $false }
        if ($parts[0] -ceq 'teams' -and
            ($parts.Count -ne 2 -or $parts[1] -cne 'base.json')) { $include = $false }
        if (-not $include) { continue }
        $destinationPath = if ($trackedPath -ceq 'system/config.example.json') {
            'system/config.json'
        } else { $trackedPath }
        $source = Resolve-GitTrackedWorktreeSource -RepositoryPath $RepositoryPath `
            -Inventory $Inventory -TrackedPath $trackedPath
        $plan = [pscustomobject]@{
            TrackedPath = $trackedPath
            ResolvedTrackedPath = $source.ResolvedTrackedPath
            Mode = [string]$record.Mode
            SourcePath = $source.SourcePath
            DestinationPath = $destinationPath
        }
        if (-not $planned.TryAdd($destinationPath, $plan) -or
            -not $caseInsensitiveDestinations.Add($destinationPath)) {
            throw "Package plan contains a duplicate or case-colliding path: $destinationPath"
        }
    }
    $paths = [string[]]@($planned.Keys)
    [Array]::Sort($paths, [System.StringComparer]::Ordinal)
    foreach ($path in $paths) { $planned[$path] }
}

function Remove-NewservGeneratedRevisionFiles {
    param([Parameter(Mandatory)]$Checkout)
    $repository = Assert-ReparseFreeDirectory -Path $Checkout.Repository `
        -Label 'newserv generated-revision checkout'
    $revisionPath = Resolve-ContractRelativePath -Root $repository `
        -RelativePath 'src/Revision.cc'
    $placeholderPath = Resolve-ContractRelativePath -Root $repository `
        -RelativePath 'src/__Revision__.cc'
    $revision = Assert-RegularFile -Path $revisionPath
    $placeholder = Assert-RegularFile -Path $placeholderPath
    $expectedText = "#include `"Revision.hh`"`n`n" +
        "const char* GIT_REVISION_HASH = `"$($script:BuildRevision)`";`n" +
        'const uint64_t BUILD_TIMESTAMP = static_cast<uint64_t>(' +
        "$($script:SourceDateEpoch)) * 1000000;`n"
    $expectedBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($expectedText)
    $expectedHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($expectedBytes)).ToLowerInvariant()
    if ($revision.Length -ne $expectedBytes.Length -or
        (Get-LowerSha256 -Path $revision.FullName) -cne $expectedHash) {
        throw 'newserv generated Revision.cc is not the exact deterministic output'
    }
    if ($placeholder.Length -ne 0 -or
        (Get-LowerSha256 -Path $placeholder.FullName) -cne
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
        throw 'newserv generated __Revision__.cc is not the exact empty placeholder'
    }
    [System.IO.File]::Delete($revision.FullName)
    [System.IO.File]::Delete($placeholder.FullName)
    if (Test-Path -LiteralPath $revision.FullName) {
        throw 'newserv generated Revision.cc could not be removed'
    }
    if (Test-Path -LiteralPath $placeholder.FullName) {
        throw 'newserv generated __Revision__.cc could not be removed'
    }
}

function Assert-NewservPatchedCheckoutStatus {
    param(
        [Parameter(Mandatory)]$Checkout,
        [Parameter(Mandatory)][int]$Run
    )
    $status = Invoke-HermeticGit -RepositoryPath $Checkout.Repository `
        -AllowedAlternateObjectRoot $Checkout.AlternateObjectRoot `
        -Arguments @('status', '--porcelain=v1', '--untracked-files=all') `
        -Label "newserv patched status run $Run"
    $lines = @($status.StdOutLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        })
    if (($lines -join "`n") -cne
        "M  CMakeLists.txt`nM  src/Revision-generate.sh") {
        throw "newserv patch changed an unexpected path in run $Run"
    }
}

function Assert-GitCheckout {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Commit,
        [Parameter(Mandatory)][string]$Label
    )
    $checkout = Assert-GitRepositoryConfig -Path $Path -Label "$Label checkout"
    $headResult = Invoke-HermeticGit -RepositoryPath $checkout -Arguments @(
        'rev-parse', 'HEAD') -Label "$Label revision"
    $head = @($headResult.StdOutLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Select-Object -First 1)
    if ($head.Count -ne 1 -or [string]$head[0] -cne $Commit) {
        throw "$Label checkout is not at the locked commit"
    }
    $treeResult = Invoke-HermeticGit -RepositoryPath $checkout -Arguments @(
        'rev-parse', 'HEAD^{tree}', "$Commit^{tree}") -Label "$Label tree identity"
    $trees = @($treeResult.StdOutLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        })
    if ($trees.Count -ne 2 -or [string]$trees[0] -cne [string]$trees[1]) {
        throw "$Label checkout tree is not the locked commit tree"
    }
    $objectResult = Invoke-HermeticGit -RepositoryPath $checkout -Arguments @(
        'rev-list', '--objects', '--missing=print', '--max-count=1', $Commit) `
        -Label "$Label object completeness"
    if (@($objectResult.StdOutLines | Where-Object { [string]$_ -match '^\?' }).Count -ne 0) {
        throw "$Label locked commit tree has a missing object"
    }
    $statusResult = Invoke-HermeticGit -RepositoryPath $checkout -Arguments @(
        'status', '--porcelain=v1', '--untracked-files=all') `
        -Label "$Label cleanliness"
    $status = @($statusResult.StdOutLines | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        })
    if ($status.Count -ne 0) {
        throw "$Label checkout is not clean"
    }
}

function Assert-PatchSeries {
    param([Parameter(Mandatory)]$Contract)
    $seriesItem = Assert-RegularFile -Path $script:SeriesPath
    if ((Get-LowerSha256 -Path $seriesItem.FullName) -cne
        [string]$Contract.patchSeries.sha256) {
        throw 'The ordered newserv patch-series hash changed'
    }
    $seriesSchema = Assert-RegularFile -Path $script:SeriesSchemaPath
    $seriesText = Get-Content -Raw -LiteralPath $seriesItem.FullName
    if (-not ($seriesText | Test-Json -SchemaFile $seriesSchema.FullName `
                -ErrorAction SilentlyContinue)) {
        throw 'The ordered newserv patch series does not match its tracked schema'
    }
    $series = $seriesText | ConvertFrom-Json -Depth 20
    if ([string]$series.sourceCommit -cne $script:SourceCommit -or
        [string]$series.buildEnvironment.NEWSERV_BUILD_REVISION -cne $script:BuildRevision -or
        [string]$series.buildEnvironment.SOURCE_DATE_EPOCH -cne ([string]$script:SourceDateEpoch)) {
        throw 'The patch series build identity is not exact'
    }
    $patches = @($series.patches)
    if ($patches.Count -ne 1 -or [int]$patches[0].order -ne 1 -or
        [string]$patches[0].path -cne '0001-deterministic-revision-metadata.patch' -or
        [string]$patches[0].scope -cne 'build-metadata' -or
        [bool]$patches[0].runtimeBehaviorChanged) {
        throw 'The combat-canary series must contain only the ordered metadata patch'
    }
    $patchRoot = Split-Path -Parent $script:SeriesPath
    $patchFiles = @(Get-ChildItem -LiteralPath $patchRoot -File -Filter '*.patch' -Force)
    if ($patchFiles.Count -ne 1 -or $patchFiles[0].Name -cne [string]$patches[0].path) {
        throw 'An unlisted newserv patch is present'
    }
    $patchItem = Assert-RegularFile -Path $patchFiles[0].FullName
    if ((Get-LowerSha256 -Path $patchItem.FullName) -cne [string]$patches[0].sha256) {
        throw 'The ordered newserv metadata patch hash changed'
    }
    $sourcePath = Join-Path $script:RuntimeRoot 'sources\newserv-git-d754a34e'
    Invoke-HermeticGit -RepositoryPath $sourcePath -Arguments @(
        'apply', '--check', '--cached', '--whitespace=error-all', $patchFiles[0].FullName
    ) -Label 'newserv metadata patch check'
    $series
}

function Assert-Dependencies {
    param([Parameter(Mandatory)]$Contract)
    $dependencies = @($Contract.dependencies)
    $expectedIds = @('asio', 'phosg', 'resource_dasm', 'libiconv', 'zlib')
    if ($dependencies.Count -ne $expectedIds.Count) {
        throw 'The dependency contract must contain exactly five locked dependencies'
    }
    for ($index = 0; $index -lt $expectedIds.Count; $index++) {
        if ([string]$dependencies[$index].id -cne $expectedIds[$index]) {
            throw 'The dependency contract IDs or order changed'
        }
    }
    foreach ($dependency in $dependencies) {
        $path = Resolve-ContractRelativePath -Root $script:RuntimeRoot -RelativePath ([string]$dependency.source)
        if ([string]$dependency.kind -ceq 'git') {
            Assert-GitCheckout -Path $path -Commit ([string]$dependency.commit) `
                -Label ([string]$dependency.id)
            continue
        }
        Assert-FileRecord -Path $path -Record $dependency | Out-Null
        if ($null -eq $dependency.signature) {
            throw "Archive dependency lacks a signature contract: $($dependency.id)"
        }
        $signaturePath = Resolve-ContractRelativePath -Root $script:RuntimeRoot `
            -RelativePath ([string]$dependency.signature.path)
        Assert-FileRecord -Path $signaturePath -Record $dependency.signature | Out-Null
        $verification = $Contract.signatureVerification
        if ([string]$verification.toolId -cne 'gpgv') {
            throw 'The detached-signature verifier must be the pinned gpgv tool'
        }
        $keyringPath = Resolve-ContractRelativePath -Root $script:RuntimeRoot `
            -RelativePath ([string]$verification.keyring.source)
        $keyringItem = Assert-FileRecord -Path $keyringPath `
            -Record $verification.keyring
        if (-not [bool]$verification.keyring.readOnly -or -not $keyringItem.IsReadOnly) {
            throw 'The trusted public build keyring must be read-only'
        }
        $verificationHome = Join-Path $script:RuntimeRoot 'trust\gpgv-empty-home'
        if (-not (Test-Path -LiteralPath $verificationHome -PathType Container)) {
            New-ReparseFreeDirectory -Path $verificationHome `
                -Label 'gpgv empty home' | Out-Null
        }
        Assert-ReparseFreeDirectory -Path $verificationHome `
            -Label 'gpgv empty home' | Out-Null
        if (@(Get-ChildItem -LiteralPath $verificationHome -Force).Count -ne 0) {
            throw 'The isolated gpgv home is not empty'
        }
        $gpgvResult = Invoke-PinnedNative -Id 'gpgv' -Arguments @(
            '--homedir', $verificationHome,
            '--keyring', $keyringPath,
            '--status-fd', '1',
            $signaturePath,
            $path
        ) -Label "detached signature verification for $($dependency.id)" `
            -PathDirectories @((Split-Path -Parent (Get-ToolPath -Id 'gpgv')))
        if (@(Get-ChildItem -LiteralPath $verificationHome -Force).Count -ne 0) {
            throw 'gpgv wrote unexpected state to its isolated home'
        }
        $fingerprint = [string]$dependency.signature.signerFingerprint
        if (-not (([string]$gpgvResult.StdOut) -match (
                    '\[GNUPG:\] VALIDSIG ' + [regex]::Escape($fingerprint) + '\b'))) {
            throw "Detached signature signer mismatch: $($dependency.id)"
        }
    }
}

function Resolve-NativeExecutionRoot {
    param(
        [Parameter(Mandatory)][string]$PathRoot,
        [Parameter(Mandatory)][string]$RelativeRoot,
        [Parameter(Mandatory)][string]$Label
    )
    $base = switch ($PathRoot) {
        'LOCALAPPDATA' {
            [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::LocalApplicationData)
            break
        }
        'PROGRAMFILES' {
            [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::ProgramFiles)
            break
        }
        default { throw "Unknown native execution path root: $Label" }
    }
    Resolve-ContractRelativePath -Root $base -RelativePath $RelativeRoot
}

function Get-ReparseFreeTreeFiles {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )
    $rootPath = Assert-ReparseFreeDirectory -Path $Root -Label $Label
    $items = @(Get-ChildItem -LiteralPath $rootPath -Recurse -Force `
            -ErrorAction Stop)
    $reparse = @($items | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        })
    if ($reparse.Count -ne 0) {
        throw "Reparse point in ${Label}: $($reparse[0].FullName)"
    }
    @($items | Where-Object { -not $_.PSIsContainer })
}

function Assert-NativeExecutionPayloadFiles {
    param(
        [Parameter(Mandatory)]$Payload,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$Extensions
    )
    $rootPath = Assert-ReparseFreeDirectory -Path $Root `
        -Label "$($Payload.id) native execution root"
    $actualFiles = @(Get-ReparseFreeTreeFiles -Root $rootPath `
            -Label "$($Payload.id) native execution tree" | Where-Object {
            $_.Extension.ToLowerInvariant() -cin $Extensions
        })
    $actualByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($item in $actualFiles) {
        $relative = [System.IO.Path]::GetRelativePath($rootPath, $item.FullName).
            Replace('\', '/')
        if (-not $actualByPath.TryAdd($relative, $item)) {
            throw "Duplicate native execution payload path: $relative"
        }
    }
    $records = @($Payload.files)
    if ($records.Count -ne [int]$Payload.fileCount -or
        $actualByPath.Count -ne [int]$Payload.fileCount) {
        throw "Native execution payload file count changed: $($Payload.id)"
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    [long]$totalBytes = 0
    $previous = $null
    foreach ($record in $records) {
        $relative = [string]$record.path
        if ([string]::IsNullOrWhiteSpace($relative) -or
            $relative.Contains('\', [System.StringComparison]::Ordinal) -or
            $relative.Contains(':', [System.StringComparison]::Ordinal) -or
            $relative.Contains('..', [System.StringComparison]::Ordinal) -or
            [System.IO.Path]::IsPathRooted($relative) -or
            -not $seen.Add($relative)) {
            throw "Unsafe or duplicate native execution payload path: $relative"
        }
        if ($null -ne $previous -and
            [string]::Compare($previous, $relative, [System.StringComparison]::Ordinal) -ge 0) {
            throw "Native execution payload records are not ordinally sorted: $($Payload.id)"
        }
        $previous = $relative
        $extension = [System.IO.Path]::GetExtension($relative).ToLowerInvariant()
        if ($extension -cnotin $Extensions -or -not $actualByPath.ContainsKey($relative)) {
            throw "Missing or unallowlisted native execution payload: $relative"
        }
        $item = $actualByPath[$relative]
        if ($item.Length -ne [long]$record.size -or
            (Get-LowerSha256 -Path $item.FullName) -cne [string]$record.sha256) {
            throw "Native execution payload hash or size changed: $relative"
        }
        $totalBytes += [long]$record.size
    }
    if ($totalBytes -ne [long]$Payload.totalBytes) {
        throw "Native execution payload byte total changed: $($Payload.id)"
    }
}

function Get-OrdinaryFileTreeState {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )
    $rootPath = Assert-ReparseFreeDirectory -Path $Root -Label $Label
    $files = @(Get-ReparseFreeTreeFiles -Root $rootPath -Label $Label)
    $byPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($item in $files) {
        $relative = [System.IO.Path]::GetRelativePath($rootPath, $item.FullName).
            Replace('\', '/')
        if (-not $byPath.TryAdd($relative, $item)) {
            throw "Duplicate ordinary-file tree path: $relative"
        }
    }
    $paths = [string[]]@($byPath.Keys)
    [Array]::Sort($paths, [System.StringComparer]::Ordinal)
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $digest = [System.Security.Cryptography.IncrementalHash]::CreateHash(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    [long]$totalBytes = 0
    try {
        foreach ($relative in $paths) {
            $item = $byPath[$relative]
            $fileHash = Get-LowerSha256 -Path $item.FullName
            $line = $relative + "`0" +
                $item.Length.ToString([System.Globalization.CultureInfo]::InvariantCulture) +
                "`0" + $fileHash + "`n"
            $digest.AppendData($utf8.GetBytes($line))
            $totalBytes += [long]$item.Length
        }
        $rootSha256 = [Convert]::ToHexString($digest.GetHashAndReset()).ToLowerInvariant()
    } finally {
        $digest.Dispose()
    }
    [pscustomobject]@{
        FileCount = $paths.Count
        TotalBytes = $totalBytes
        RootSha256 = $rootSha256
    }
}

function Assert-OrdinaryFileTree {
    param(
        [Parameter(Mandatory)]$Tree,
        [Parameter(Mandatory)][string]$Root
    )
    $state = Get-OrdinaryFileTreeState -Root $Root `
        -Label "$($Tree.id) ordinary-file execution tree"
    if ($state.FileCount -ne [int]$Tree.fileCount -or
        $state.TotalBytes -ne [long]$Tree.totalBytes -or
        $state.RootSha256 -cne [string]$Tree.rootSha256) {
        throw "Ordinary-file execution tree changed: $($Tree.id)"
    }
}

function Assert-OrdinaryExecutionTrees {
    param([Parameter(Mandatory)]$Manifest)
    $expectedIds = @('cmake', 'git-for-windows', 'gnupg', 'ninja', 'winlibs')
    $trees = @($Manifest.ordinaryFileTrees)
    if ($trees.Count -ne $expectedIds.Count) {
        throw 'The ordinary-file execution tree set changed'
    }
    for ($index = 0; $index -lt $expectedIds.Count; $index++) {
        $tree = $trees[$index]
        if ([string]$tree.id -cne $expectedIds[$index]) {
            throw 'The ordinary-file execution tree order or identity changed'
        }
        $root = Resolve-NativeExecutionRoot -PathRoot ([string]$tree.pathRoot) `
            -RelativeRoot ([string]$tree.relativeRoot) -Label ([string]$tree.id)
        Assert-OrdinaryFileTree -Tree $tree -Root $root
    }
}

function Assert-NativeExecutionManifest {
    param([Parameter(Mandatory)]$Contract)
    $record = $Contract.toolchain.nativeExecutionManifest
    $manifestPath = Resolve-ContractRelativePath -Root $script:RepositoryRoot `
        -RelativePath ([string]$record.path)
    Assert-FileRecord -Path $manifestPath -Record $record | Out-Null
    $schemaPath = Resolve-ContractRelativePath -Root $script:RepositoryRoot `
        -RelativePath ([string]$record.schemaPath)
    Assert-FileRecord -Path $schemaPath -Record ([pscustomobject]@{
            size = [long]$record.schemaSize
            sha256 = [string]$record.schemaSha256
        }) | Out-Null
    $manifestText = Get-Content -Raw -LiteralPath $manifestPath
    if (-not ($manifestText | Test-Json -SchemaFile $schemaPath `
                -ErrorAction SilentlyContinue)) {
        throw 'The native execution payload manifest does not match its tracked schema'
    }
    $manifest = $manifestText | ConvertFrom-Json -Depth 20
    $expectedExtensions = @('.bat', '.cmd', '.com', '.dll', '.exe', '.pyd')
    $extensions = @($manifest.extensions | ForEach-Object { [string]$_ })
    if ($extensions.Count -ne $expectedExtensions.Count) {
        throw 'The native execution extension allowlist changed'
    }
    for ($index = 0; $index -lt $expectedExtensions.Count; $index++) {
        if ($extensions[$index] -cne $expectedExtensions[$index]) {
            throw 'The native execution extension allowlist changed'
        }
    }
    $expectedPayloadIds = @('cmake', 'git-for-windows', 'gnupg', 'ninja', 'winlibs')
    $payloads = @($manifest.payloads)
    if ($payloads.Count -ne $expectedPayloadIds.Count) {
        throw 'The native execution payload set changed'
    }
    for ($index = 0; $index -lt $expectedPayloadIds.Count; $index++) {
        $payload = $payloads[$index]
        if ([string]$payload.id -cne $expectedPayloadIds[$index]) {
            throw 'The native execution payload order or identity changed'
        }
        $root = Resolve-NativeExecutionRoot -PathRoot ([string]$payload.pathRoot) `
            -RelativeRoot ([string]$payload.relativeRoot) -Label ([string]$payload.id)
        Assert-NativeExecutionPayloadFiles -Payload $payload -Root $root `
            -Extensions $extensions
    }
    $script:NativeExecutionManifest = $manifest
    $manifest
}

function Get-NativePayloadsForInvocation {
    param(
        [Parameter(Mandatory)][string]$ToolPath,
        [string[]]$PathDirectories = @(),
        [Parameter(Mandatory)]$Manifest
    )
    $systemDirectory = [Environment]::SystemDirectory
    $inputs = [System.Collections.Generic.List[object]]::new()
    $inputs.Add([pscustomobject]@{ Kind = 'tool'; Path = $ToolPath })
    foreach ($directory in @($PathDirectories)) {
        if ([string]::IsNullOrWhiteSpace([string]$directory)) { continue }
        $inputs.Add([pscustomobject]@{ Kind = 'PATH'; Path = [string]$directory })
    }
    $payloadRoots = [System.Collections.Generic.List[object]]::new()
    foreach ($payload in @($Manifest.payloads)) {
        $root = Resolve-NativeExecutionRoot -PathRoot ([string]$payload.pathRoot) `
            -RelativeRoot ([string]$payload.relativeRoot) -Label ([string]$payload.id)
        $payloadRoots.Add([pscustomobject]@{ Payload = $payload; Root = $root })
    }
    $selected = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($input in $inputs) {
        $fullInput = [System.IO.Path]::GetFullPath([string]$input.Path)
        if (Test-PathWithinRoot -Path $fullInput -Root $systemDirectory) { continue }
        $matches = @($payloadRoots | Where-Object {
                Test-PathWithinRoot -Path $fullInput -Root ([string]$_.Root)
            })
        if ($matches.Count -ne 1) {
            throw "Native $($input.Kind) path is not covered by exactly one payload: $fullInput"
        }
        $match = $matches[0]
        $id = [string]$match.Payload.id
        if (-not $selected.ContainsKey($id)) { $selected.Add($id, $match) }
    }
    foreach ($payload in @($Manifest.payloads)) {
        $id = [string]$payload.id
        if ($selected.ContainsKey($id)) { $selected[$id] }
    }
}

function Assert-NativeToolPayloadBoundary {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$ToolPath,
        [string[]]$PathDirectories = @()
    )
    if ($null -eq $script:NativeExecutionManifest) { return }
    $payloads = @(Get-NativePayloadsForInvocation -ToolPath $ToolPath `
            -PathDirectories $PathDirectories -Manifest $script:NativeExecutionManifest)
    $extensions = @($script:NativeExecutionManifest.extensions | ForEach-Object {
            [string]$_
        })
    foreach ($record in $payloads) {
        Assert-NativeExecutionPayloadFiles -Payload $record.Payload -Root $record.Root `
            -Extensions $extensions
    }
}

function Assert-OrdinaryBuildInputBoundary {
    param([Parameter(Mandatory)]$Contract)
    $manifest = Assert-NativeExecutionManifest -Contract $Contract
    Assert-OrdinaryExecutionTrees -Manifest $manifest
}

function Assert-Toolchain {
    param([Parameter(Mandatory)]$Contract)
    $expectedIds = @(
        'cmd',
        'gcc',
        'g++',
        'objdump',
        'cmake',
        'ctest',
        'ninja',
        'mingw32-make',
        'git',
        'gpgv',
        'tar',
        'bash',
        'sh',
        'subst'
    )
    $tools = @($Contract.toolchain.tools)
    $actualIds = @($tools | ForEach-Object { [string]$_.id })
    $idSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $duplicateIds = @($actualIds | Where-Object { -not $idSet.Add($_) })
    $orderChanged = $tools.Count -ne $expectedIds.Count
    if (-not $orderChanged) {
        for ($index = 0; $index -lt $expectedIds.Count; $index++) {
            if ($actualIds[$index] -cne $expectedIds[$index]) {
                $orderChanged = $true
                break
            }
        }
    }
    if ($orderChanged -or $duplicateIds.Count -ne 0) {
        throw 'The toolchain must contain each exact tool ID once'
    }
    $verifiedRecords = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    $script:ToolRecords = $verifiedRecords
    foreach ($tool in $tools) {
        $pathRoot = switch ([string]$tool.pathRoot) {
            'LOCALAPPDATA' {
                [Environment]::GetFolderPath(
                    [Environment+SpecialFolder]::LocalApplicationData)
                break
            }
            'PROGRAMFILES' {
                [Environment]::GetFolderPath(
                    [Environment+SpecialFolder]::ProgramFiles)
                break
            }
            'SYSTEMROOT' {
                Split-Path -Parent ([Environment]::SystemDirectory)
                break
            }
            default { throw "Unknown toolchain path root: $($tool.id)" }
        }
        if ([string]::IsNullOrWhiteSpace($pathRoot)) {
            throw "Toolchain path root is unavailable: $($tool.id)"
        }
        $expectedPath = Resolve-ContractRelativePath -Root $pathRoot `
            -RelativePath ([string]$tool.relativePath)
        if ([System.IO.Path]::GetFileNameWithoutExtension($expectedPath) -cne
            [string]$tool.command) {
            throw "Toolchain command does not match its exact path: $($tool.id)"
        }
        Assert-ReparseFreePathHierarchy -Path $expectedPath `
            -Label "$($tool.id) tool" | Out-Null
        $commands = @(Get-Command -Name $expectedPath -CommandType Application `
            -All -ErrorAction Stop)
        if ($commands.Count -ne 1 -or
            -not [string]::Equals(
                [System.IO.Path]::GetFullPath([string]$commands[0].Source),
                $expectedPath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Tool did not resolve to the exact Application path: $($tool.id)"
        }
        $item = Assert-RegularFile -Path $expectedPath
        if ($item.Length -ne [long]$tool.executableSize -or
            (Get-LowerSha256 -Path $item.FullName) -cne [string]$tool.sha256) {
            throw "Toolchain binary mismatch: $($tool.id)"
        }
        $verifiedRecords.Add([string]$tool.id, [pscustomobject]@{
                Path = $item.FullName
                Record = $tool
            })
        if ([string]$tool.versionMode -ceq 'command') {
            $versionResult = Invoke-PinnedNative -Id ([string]$tool.id) `
                -Arguments @($tool.versionArguments) `
                -Label "$($tool.id) version verification" `
                -PathDirectories @((Split-Path -Parent $item.FullName))
            $version = [string]($versionResult.StdOutLines | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_)
                } | Select-Object -First 1)
            if ($version.TrimEnd() -cne [string]$tool.version) {
                throw "Toolchain version mismatch: $($tool.id)"
            }
        } elseif ([string]$tool.versionMode -ceq 'file') {
            if ([string]$item.VersionInfo.FileVersion -cne [string]$tool.version) {
                throw "Toolchain file version mismatch: $($tool.id)"
            }
        } else {
            throw "Unknown toolchain version mode: $($tool.id)"
        }
    }
    $script:ToolRecords = $verifiedRecords
}

function Get-ReleaseVersionOutput {
    param([Parameter(Mandatory)][string]$ExecutablePath)
    $executable = Assert-RegularFile -Path $ExecutablePath
    $workingDirectory = Join-Path $script:CanonicalRuntimeRoot 'trust\newserv-help-empty'
    if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) {
        New-ReparseFreeDirectory -Path $workingDirectory `
            -Label 'newserv help working directory' | Out-Null
    }
    $workingDirectory = Assert-ReparseFreeDirectory -Path $workingDirectory `
        -Label 'newserv help working directory'
    if (@(Get-ChildItem -LiteralPath $workingDirectory -Force).Count -ne 0) {
        throw 'The newserv help working directory is not empty'
    }
    $systemRoot = Split-Path -Parent ([Environment]::SystemDirectory)
    $temporary = Assert-ReparseFreeDirectory -Path ([System.IO.Path]::GetTempPath()) `
        -Label 'newserv help temporary root'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executable.FullName
    $startInfo.ArgumentList.Add('--help')
    $startInfo.WorkingDirectory = $workingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment.Clear()
    $startInfo.Environment['SystemRoot'] = $systemRoot
    $startInfo.Environment['WINDIR'] = $systemRoot
    $startInfo.Environment['ComSpec'] = (Get-VerifiedToolRecord -Id 'cmd').Path
    $startInfo.Environment['TEMP'] = $temporary
    $startInfo.Environment['TMP'] = $temporary
    $startInfo.Environment['PATH'] = [Environment]::SystemDirectory
    $startInfo.Environment['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    $startInfo.Environment['LANG'] = 'C'
    $startInfo.Environment['LC_ALL'] = 'C'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'newserv help probe did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'newserv help probe timed out'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or
            -not [string]::IsNullOrWhiteSpace([string]$stdout)) {
            throw 'newserv help probe did not exit through its read-only help path'
        }
        $lines = @(Convert-NativeTextToLines -Text ([string]$stderr) | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            })
        if ($lines.Count -lt 2 -or
            [string]$lines[0] -notmatch '^newserv-[0-9a-f]{7} built .+ UTC$' -or
            @($lines | Where-Object { [string]$_ -ceq 'Usage:' }).Count -ne 1) {
            throw 'newserv help output does not contain one exact version header and usage marker'
        }
        if (@(Get-ChildItem -LiteralPath $workingDirectory -Force).Count -ne 0) {
            throw 'newserv help probe wrote unexpected state'
        }
        [string]$lines[0]
    } finally {
        $process.Dispose()
    }
}

function Get-PeRuntimeImports {
    param([Parameter(Mandatory)][string]$ExecutablePath)
    $executable = Assert-RegularFile -Path $ExecutablePath
    $objdump = Get-ToolPath -Id 'objdump'
    $result = Invoke-PinnedNative -Id 'objdump' -Arguments @('-p', $executable.FullName) `
        -Label 'PE import-table inspection' `
        -PathDirectories @((Split-Path -Parent $objdump))
    if ([string]$result.StdOut -notmatch '(?m)^.+file format pei-x86-64\r?$') {
        throw 'The release executable is not the expected x86-64 PE format'
    }
    $imports = @($result.StdOutLines | ForEach-Object {
            if ([string]$_ -match '^\s*DLL Name:\s*(?<name>\S+)\s*$') {
                [string]$Matches.name
            }
        })
    $unique = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    if ($imports.Count -eq 0 -or
        @($imports | Where-Object { -not $unique.Add([string]$_) }).Count -ne 0) {
        throw 'The PE import table is empty or contains a duplicate DLL record'
    }
    $imports
}

function Test-FileContainsByteNeedle {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Needle
    )
    if ($Needle.Count -eq 0) { throw 'A byte needle must not be empty' }
    $needleText = [System.Text.Encoding]::Latin1.GetString($Needle)
    $overlapLength = $Needle.Count - 1
    $buffer = [byte[]]::new(65536 + $overlapLength)
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $carry = 0
        while (($read = $stream.Read($buffer, $carry, 65536)) -gt 0) {
            $count = $carry + $read
            $text = [System.Text.Encoding]::Latin1.GetString($buffer, 0, $count)
            if ($text.IndexOf($needleText, [System.StringComparison]::Ordinal) -ge 0) {
                return $true
            }
            $carry = [Math]::Min($overlapLength, $count)
            if ($carry -gt 0) {
                [System.Buffer]::BlockCopy($buffer, $count - $carry, $buffer, 0, $carry)
            }
        }
        $false
    } finally {
        $stream.Dispose()
    }
}

function Assert-NoDeterministicBuildPathNeedles {
    param([Parameter(Mandatory)][string]$Root)
    $rootPath = Assert-ReparseFreeDirectory -Path $Root -Label 'release path-scan root'
    $needles = @(
        @{ Name = 'ASCII P:\'; Bytes = [System.Text.Encoding]::ASCII.GetBytes('P:\') },
        @{ Name = 'ASCII P:/'; Bytes = [System.Text.Encoding]::ASCII.GetBytes('P:/') },
        @{ Name = 'UTF-16LE P:\'; Bytes = [System.Text.Encoding]::Unicode.GetBytes('P:\') },
        @{ Name = 'UTF-16LE P:/'; Bytes = [System.Text.Encoding]::Unicode.GetBytes('P:/') }
    )
    foreach ($entry in @(Get-OrdinalRelativeFiles -Root $rootPath `
            -Label 'release path-scan root')) {
        $file = $entry.File
        foreach ($needle in $needles) {
            if (Test-FileContainsByteNeedle -Path $file.FullName -Needle $needle.Bytes) {
                $relative = [string]$entry.RelativePath
                throw "Release file contains deterministic build path needle $($needle.Name): $relative"
            }
        }
    }
}

function Assert-ReleaseOutputClaims {
    param(
        [Parameter(Mandatory)]$Contract,
        [Parameter(Mandatory)][string]$ReleaseRoot
    )
    $executablePath = Resolve-ContractRelativePath -Root $ReleaseRoot `
        -RelativePath ([string]$Contract.output.executable.path)
    Assert-FileRecord -Path $executablePath -Record $Contract.output.executable | Out-Null
    $version = Get-ReleaseVersionOutput -ExecutablePath $executablePath
    if ($version -cne [string]$Contract.output.versionOutput) {
        throw 'The executable version output does not match the exact contract'
    }
    $imports = @(Get-PeRuntimeImports -ExecutablePath $executablePath)
    $expectedImports = @($Contract.output.runtimeImports | ForEach-Object { [string]$_ })
    if ($imports.Count -ne $expectedImports.Count) {
        throw 'The PE runtime import count does not match the exact contract'
    }
    for ($index = 0; $index -lt $imports.Count; $index++) {
        if ([string]$imports[$index] -cne [string]$expectedImports[$index]) {
            throw "The PE runtime import order changed at index $index"
        }
    }
    Assert-NoDeterministicBuildPathNeedles -Root $ReleaseRoot
}

function Assert-CTestSummary {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Expected
    )
    $name = [string]$Expected.name
    $summaryPattern = '(?m)^100% tests passed out of (?<total>[0-9]+)\r?$'
    $matches = [regex]::Matches([string]$Result.StdOut, $summaryPattern)
    if ($matches.Count -eq 0) {
        throw "$name did not emit one parseable CTest total"
    }
    if ($matches.Count -ne 1) {
        throw "$name emitted an ambiguous CTest total"
    }
    $match = $matches[0]
    $failed = 0
    $total = [int]$match.Groups['total'].Value
    $passed = $total - $failed
    if ($failed -ne [int]$Expected.failed -or
        $passed -ne [int]$Expected.passed -or
        $total -ne ([int]$Expected.passed + [int]$Expected.failed)) {
        throw "$name CTest totals do not match the exact contract"
    }
}

function Assert-Release {
    param([Parameter(Mandatory)]$Contract)
    $releaseRoot = Resolve-ContractRelativePath -Root $script:RuntimeRoot `
        -RelativePath ([string]$Contract.output.rootRelative)
    if (-not (Test-Path -LiteralPath $releaseRoot -PathType Container)) {
        throw "Combat-canary release is missing: $releaseRoot"
    }
    $reparse = @(Get-ChildItem -LiteralPath $releaseRoot -Recurse -Force | Where-Object {
            $_.LinkType -or
            (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
        })
    if ($reparse.Count -ne 0) {
        throw 'The combat-canary release contains a reparse point'
    }
    $manifestPath = Resolve-ContractRelativePath -Root $releaseRoot `
        -RelativePath ([string]$Contract.output.releaseManifest.path)
    Assert-FileRecord -Path $manifestPath -Record $Contract.output.releaseManifest | Out-Null
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -Depth 20
    if ([string]$manifest.profileId -cne [string]$Contract.profileId -or
        [string]$manifest.sourceCommit -cne [string]$Contract.source.commit -or
        [string]$manifest.patchSeriesSha256 -cne [string]$Contract.patchSeries.sha256) {
        throw 'The release manifest identity is not exact'
    }
    $records = @($manifest.files)
    if ($records.Count -ne [int]$Contract.output.fileCount) {
        throw 'The release manifest file count is not exact'
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $totalBytes = [long]0
    foreach ($record in $records) {
        if (-not $seen.Add([string]$record.path)) {
            throw "Duplicate release manifest path: $($record.path)"
        }
        $path = Resolve-ContractRelativePath -Root $releaseRoot -RelativePath ([string]$record.path)
        Assert-FileRecord -Path $path -Record $record | Out-Null
        $totalBytes += [long]$record.size
    }
    if ($totalBytes -ne [long]$Contract.output.totalBytes) {
        throw 'The release manifest byte total is not exact'
    }
    $actualFiles = @(Get-ChildItem -LiteralPath $releaseRoot -Recurse -File -Force | Where-Object {
            $_.FullName -cne $manifestPath
        })
    if ($actualFiles.Count -ne $records.Count) {
        throw 'The release contains an unlisted or missing file'
    }
    $executablePath = Resolve-ContractRelativePath -Root $releaseRoot `
        -RelativePath ([string]$Contract.output.executable.path)
    Assert-FileRecord -Path $executablePath -Record $Contract.output.executable | Out-Null
    if ([string](Get-AuthenticodeSignature -LiteralPath $executablePath).Status -cne
        [string]$Contract.output.executable.authenticode) {
        throw 'The combat-canary executable signature state changed'
    }
    Assert-ReleaseOutputClaims -Contract $Contract -ReleaseRoot $releaseRoot
    $releaseRoot
}

function Assert-SourceLockInputs {
    param([Parameter(Mandatory)]$Contract)
    $lockItem = Assert-RegularFile -Path $script:SourceLockPath
    $lock = Get-Content -Raw -LiteralPath $lockItem.FullName | ConvertFrom-Json -Depth 50
    $component = @($lock.components | Where-Object id -ceq 'newserv-combat-canary-build')
    if ($component.Count -ne 1 -or
        [string]$component[0].commit -cne [string]$Contract.source.commit) {
        throw 'The combat-canary source-lock component is missing or ambiguous'
    }
    $members = @($component[0].members)
    $expectedMembers = @(
        'config/combat-canary-build.json',
        'config/schemas/combat-canary-build.schema.json',
        'config/native-execution-payloads.json',
        'config/schemas/native-execution-payloads.schema.json',
        'patches/newserv/series.json',
        'config/schemas/newserv-patch-series.schema.json',
        'release/release-manifest.json',
        'release/newserv-windows.exe'
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if ($members.Count -ne $expectedMembers.Count) {
        throw 'The combat-canary source-lock must contain exactly eight critical members'
    }
    foreach ($member in $members) {
        $memberPath = [string]$member.path
        if ($memberPath -cnotin $expectedMembers -or -not $seen.Add($memberPath)) {
            throw "Unexpected or ambiguous combat-canary source-lock member: $memberPath"
        }
    }
    if ([long]$component[0].size -ne [long]$Contract.output.executable.size -or
        [string]$component[0].sha256 -cne [string]$Contract.output.executable.sha256) {
        throw 'The combat-canary source-lock executable identity does not match the contract'
    }
    $checks = @(
        @{ Path = $script:ContractPath; Member = 'config/combat-canary-build.json' },
        @{ Path = $script:ContractSchemaPath; Member = 'config/schemas/combat-canary-build.schema.json' },
        @{
            Path = Resolve-ContractRelativePath -Root $script:RepositoryRoot `
                -RelativePath ([string]$Contract.toolchain.nativeExecutionManifest.path)
            Member = 'config/native-execution-payloads.json'
        },
        @{
            Path = Resolve-ContractRelativePath -Root $script:RepositoryRoot `
                -RelativePath ([string]$Contract.toolchain.nativeExecutionManifest.schemaPath)
            Member = 'config/schemas/native-execution-payloads.schema.json'
        },
        @{ Path = $script:SeriesPath; Member = 'patches/newserv/series.json' },
        @{ Path = $script:SeriesSchemaPath; Member = 'config/schemas/newserv-patch-series.schema.json' }
    )
    foreach ($check in $checks) {
        $member = @($members | Where-Object path -ceq $check.Member)
        if ($member.Count -ne 1) {
            throw "Source-lock member is missing: $($check.Member)"
        }
        Assert-FileRecord -Path $check.Path -Record $member[0] | Out-Null
    }
    foreach ($check in @(
            @{
                Member = 'release/release-manifest.json'
                Record = $Contract.output.releaseManifest
            },
            @{
                Member = 'release/newserv-windows.exe'
                Record = $Contract.output.executable
            }
        )) {
        $member = @($members | Where-Object path -ceq $check.Member)[0]
        if ([long]$member.size -ne [long]$check.Record.size -or
            [string]$member.sha256 -cne [string]$check.Record.sha256 -or
            [string]$member.authenticode -cne [string]$check.Record.authenticode) {
            throw "Source-lock member does not match the build contract: $($check.Member)"
        }
    }
    $component[0]
}

function Assert-SourceLock {
    param(
        [Parameter(Mandatory)]$Contract,
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)]$Component
    )
    $members = @($Component.members)
    $checks = @(
        @{
            Path = Join-Path $ReleaseRoot 'release-manifest.json'
            Member = 'release/release-manifest.json'
        },
        @{
            Path = Join-Path $ReleaseRoot 'newserv-windows.exe'
            Member = 'release/newserv-windows.exe'
        }
    )
    foreach ($check in $checks) {
        $member = @($members | Where-Object path -ceq $check.Member)
        if ($member.Count -ne 1) {
            throw "Source-lock member is missing: $($check.Member)"
        }
        Assert-FileRecord -Path $check.Path -Record $member[0] | Out-Null
    }
}

function Invoke-CombatCanaryPreflight {
    Assert-CanonicalRuntimeRoot | Out-Null
    $script:RuntimeRoot = Assert-ReparseFreeDirectory -Path $script:RuntimeRoot `
        -Label 'runtime root'
    $contractItem = Assert-RegularFile -Path $script:ContractPath
    $contractSchema = Assert-RegularFile -Path $script:ContractSchemaPath
    $contractText = Get-Content -Raw -LiteralPath $contractItem.FullName
    if (-not ($contractText | Test-Json -SchemaFile $contractSchema.FullName `
                -ErrorAction SilentlyContinue)) {
        throw 'The combat-canary build contract does not match its tracked schema'
    }
    $contract = $contractText | ConvertFrom-Json -Depth 50
    $recordedBuilds = @($contract.reproducibility.builds)
    if ([string]$contract.profileId -cne 'newserv-combat-canary-build' -or
        [string]$contract.source.commit -cne $script:SourceCommit -or
        [int64]$contract.reproducibility.sourceDateEpoch -ne $script:SourceDateEpoch -or
        [int]$contract.reproducibility.cleanBuildCount -ne 2 -or
        $recordedBuilds.Count -ne 2 -or
        [int]$recordedBuilds[0].run -ne 1 -or
        [int]$recordedBuilds[1].run -ne 2 -or
        [long]$recordedBuilds[0].size -ne [long]$recordedBuilds[1].size -or
        [string]$recordedBuilds[0].sha256 -cne [string]$recordedBuilds[1].sha256 -or
        [long]$recordedBuilds[0].size -ne [long]$contract.output.executable.size -or
        [string]$recordedBuilds[0].sha256 -cne [string]$contract.output.executable.sha256) {
        throw 'The combat-canary build contract identity is not exact'
    }
    $nativeExecutionManifest = Assert-NativeExecutionManifest -Contract $contract
    Assert-Toolchain -Contract $contract
    $sourcePath = Join-Path $script:RuntimeRoot 'sources\newserv-git-d754a34e'
    Assert-GitCheckout -Path $sourcePath -Commit $script:SourceCommit -Label 'newserv'
    Assert-PatchSeries -Contract $contract | Out-Null
    Assert-Dependencies -Contract $contract
    $sourceLockComponent = Assert-SourceLockInputs -Contract $contract
    Assert-OrdinaryExecutionTrees -Manifest $nativeExecutionManifest
    [pscustomobject]@{
        Contract = $contract
        SourceLockComponent = $sourceLockComponent
    }
}

function Invoke-CombatCanaryVerify {
    $preflight = Invoke-CombatCanaryPreflight
    $contract = $preflight.Contract
    $releaseRoot = Assert-Release -Contract $contract
    Assert-SourceLock -Contract $contract -ReleaseRoot $releaseRoot `
        -Component $preflight.SourceLockComponent
    [pscustomobject]@{
        ProfileId = [string]$contract.profileId
        SourceCommit = [string]$contract.source.commit
        ExecutableSha256 = [string]$contract.output.executable.sha256
        ExecutableSize = [long]$contract.output.executable.size
        FileCount = [int]$contract.output.fileCount
        TotalBytes = [long]$contract.output.totalBytes
        VersionOutput = [string]$contract.output.versionOutput
        RuntimeImportCount = @($contract.output.runtimeImports).Count
        ReleaseRoot = $releaseRoot
        Verified = $true
    }
}

function Assert-SafeTarArchive {
    param([Parameter(Mandatory)][string]$Path)
    $archive = Assert-RegularFile -Path $Path
    $tarDirectory = Split-Path -Parent (Get-ToolPath -Id 'tar')
    $listResult = Invoke-PinnedNative -Id 'tar' -Arguments @(
        '-tzf', $archive.FullName) -Label 'list source archive' `
        -PathDirectories @($tarDirectory)
    $entries = @($listResult.StdOutLines)
    if ($entries.Count -eq 0) {
        throw "Unable to list source archive: $Path"
    }
    foreach ($entry in $entries) {
        $normalized = ([string]$entry).Replace('\', '/')
        if ($normalized.StartsWith('/', [System.StringComparison]::Ordinal) -or
            $normalized.Contains(':', [System.StringComparison]::Ordinal) -or
            @($normalized.Split('/') | Where-Object { $_ -ceq '..' }).Count -gt 0) {
            throw "Unsafe source archive entry: $entry"
        }
    }
    $verboseResult = Invoke-PinnedNative -Id 'tar' -Arguments @(
        '-tvzf', $archive.FullName) -Label 'inspect source archive' `
        -PathDirectories @($tarDirectory)
    $verbose = @($verboseResult.StdOutLines)
    if (@($verbose | Where-Object { $_ -match '^[lh]' }).Count -ne 0) {
        throw "Source archive contains a link or cannot be inspected: $Path"
    }
}

function Convert-ToMsysPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Unable to convert path to an MSYS path: $Path"
    }
    '/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2].Replace('\', '/')
}

function Assert-PSOBBBuildStoppedBoundary {
    $namedProcesses = @(
        Get-Process -Name @('newserv-windows', 'Psobb') -ErrorAction SilentlyContinue)
    if ($namedProcesses.Count -ne 0) {
        throw 'Combat-canary build requires every PSOBB client and server process to be stopped'
    }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
            [int]$_.LocalPort -in @(11000, 12000, 12001)
        })
    if ($listeners.Count -ne 0) {
        throw 'Combat-canary build requires every reserved PSOBB server port to be unbound'
    }
}

function Enter-CombatCanaryBuildBoundary {
    $markerPath = Join-Path $script:RuntimeRoot '.psobb-runtime.json'
    $markerItem = Assert-RegularFile -Path $markerPath
    $marker = Get-Content -Raw -LiteralPath $markerItem.FullName | ConvertFrom-Json -Depth 10
    $runtimeIdentity = [System.IO.Path]::GetFullPath([string]$marker.runtimeRoot).TrimEnd('\')
    if ([int]$marker.schemaVersion -ne 1 -or
        [string]$marker.installationId -notmatch `
            '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
        -not $runtimeIdentity.Equals(
            $script:RuntimeRoot.TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The PSOBB runtime ownership marker is invalid'
    }
    $identityToken = ([string]$marker.installationId).Replace('-', '').ToLowerInvariant()
    $buildMutex = [System.Threading.Mutex]::new(
        $false, "Local\PSOBB.CombatCanary.Build.$identityToken")
    $lifecycleMutex = $null
    $ownsBuild = $false
    $ownsLifecycle = $false
    try {
        try {
            $ownsBuild = $buildMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsBuild = $true
        }
        if (-not $ownsBuild) {
            throw 'Another combat-canary build or publication operation is active'
        }
        $lifecycleMutex = [System.Threading.Mutex]::new(
            $false, "Local\PSOBB.Newserv.Start.$identityToken")
        try {
            $ownsLifecycle = $lifecycleMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsLifecycle = $true
        }
        if (-not $ownsLifecycle) {
            throw 'The PSOBB lifecycle is changing; combat-canary build is blocked'
        }
        Assert-PSOBBBuildStoppedBoundary
        $script:BuildBoundaryDepth++
        [pscustomobject]@{
            BuildMutex = $buildMutex
            LifecycleMutex = $lifecycleMutex
            OwnsBuild = $ownsBuild
            OwnsLifecycle = $ownsLifecycle
        }
    } catch {
        if ($ownsLifecycle -and $lifecycleMutex) {
            $lifecycleMutex.ReleaseMutex()
        }
        if ($lifecycleMutex) { $lifecycleMutex.Dispose() }
        if ($ownsBuild) { $buildMutex.ReleaseMutex() }
        $buildMutex.Dispose()
        throw
    }
}

function Exit-CombatCanaryBuildBoundary {
    param([Parameter(Mandatory)]$Boundary)
    try {
        if ([bool]$Boundary.OwnsLifecycle) {
            $Boundary.LifecycleMutex.ReleaseMutex()
        }
    } finally {
        if ($Boundary.LifecycleMutex) { $Boundary.LifecycleMutex.Dispose() }
        try {
            if ([bool]$Boundary.OwnsBuild) { $Boundary.BuildMutex.ReleaseMutex() }
        } finally {
            if ($Boundary.BuildMutex) { $Boundary.BuildMutex.Dispose() }
            if ($script:BuildBoundaryDepth -gt 0) { $script:BuildBoundaryDepth-- }
        }
    }
}

function Publish-CombatCanaryRelease {
    param(
        [Parameter(Mandatory)][string]$StageRelease,
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)][string]$StagingRoot,
        [Parameter(Mandatory)][scriptblock]$VerifyAction
    )
    if ($script:BuildBoundaryDepth -ne 1) {
        throw 'Publication requires the exclusive combat-canary build and lifecycle boundary'
    }
    $staging = Assert-ReparseFreePathHierarchy -Path $StagingRoot `
        -Label 'publication staging root'
    $stage = Assert-ReparseFreeDirectory -Path $StageRelease `
        -Label 'staged publication release'
    $release = Assert-ReparseFreePathHierarchy -Path $ReleaseRoot `
        -Label 'publication release root'
    $stagingPrefix = $staging.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $stage.StartsWith(
            $stagingPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The staged release is outside the publication staging root'
    }
    $staging = New-ReparseFreeDirectory -Path $staging `
        -Label 'publication staging root'
    New-ReparseFreeDirectory -Path (Split-Path -Parent $release) `
        -Label 'publication release parent' | Out-Null

    $hadPreviousRelease = Test-Path -LiteralPath $release
    $retired = $null
    if ($hadPreviousRelease) {
        Assert-ReparseFreePathHierarchy -Path $release `
            -Label 'existing publication release' | Out-Null
        $retired = Join-Path $staging (
            'previous-release-' + [Guid]::NewGuid().ToString('N'))
        Assert-ReparseFreePathHierarchy -Path $retired `
            -Label 'retired publication release' | Out-Null
        Move-Item -LiteralPath $release -Destination $retired
        Assert-ReparseFreePathHierarchy -Path $retired `
            -Label 'retired publication release' | Out-Null
    }

    try {
        Move-Item -LiteralPath $stage -Destination $release
        Assert-ReparseFreeDirectory -Path $release `
            -Label 'published release' | Out-Null
        & $VerifyAction
    } catch {
        if (Test-Path -LiteralPath $release) {
            $failed = Join-Path $staging (
                'failed-release-' + [Guid]::NewGuid().ToString('N'))
            Assert-ReparseFreePathHierarchy -Path $failed `
                -Label 'failed publication release' | Out-Null
            Move-Item -LiteralPath $release -Destination $failed
        }
        if ($hadPreviousRelease) {
            Move-Item -LiteralPath $retired -Destination $release
            Assert-ReparseFreePathHierarchy -Path $release `
                -Label 'restored publication release' | Out-Null
        }
        throw
    }
}

function Invoke-CombatCanaryBuild {
    $canonicalContract = Join-Path $script:RepositoryRoot 'config\combat-canary-build.json'
    $canonicalSeries = Join-Path $script:RepositoryRoot 'patches\newserv\series.json'
    if ($script:ContractPath -cne $canonicalContract -or
        $script:SeriesPath -cne $canonicalSeries) {
        throw 'Build requires the canonical tracked contract and patch series'
    }
    $preflight = Invoke-CombatCanaryPreflight
    $contract = $preflight.Contract
    $buildsRoot = Join-Path $script:RuntimeRoot 'combat-canary\builds'
    Assert-ReparseFreePathHierarchy -Path $buildsRoot -Label 'builds root' | Out-Null
    if (-not $PSCmdlet.ShouldProcess($buildsRoot,
            'Create two clean dependency-locked newserv builds and atomically publish server-base')) {
        return
    }
    $boundary = Enter-CombatCanaryBuildBoundary
    try {
        if (Test-Path -LiteralPath 'P:\') {
            throw 'The fixed deterministic build drive P: is already in use'
        }
        $buildRoot = Join-Path $buildsRoot (
            'build-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' +
            [Guid]::NewGuid().ToString('N'))
        $buildRoot = New-ReparseFreeDirectory -Path $buildRoot -Label 'build root'
        $tar = Get-ToolPath -Id 'tar'
        $cmake = Get-ToolPath -Id 'cmake'
        $ctest = Get-ToolPath -Id 'ctest'
        $ninja = Get-ToolPath -Id 'ninja'
        $gcc = Get-ToolPath -Id 'gcc'
        $gxx = Get-ToolPath -Id 'g++'
        $make = Get-ToolPath -Id 'mingw32-make'
        $bash = Get-ToolPath -Id 'bash'
        $sh = Get-ToolPath -Id 'sh'
        $subst = Get-ToolPath -Id 'subst'
        try {
            Invoke-PinnedNative -Id 'subst' -Arguments @('P:', $buildRoot) `
                -Label 'create deterministic P: build drive' `
                -PathDirectories @((Split-Path -Parent $subst)) | Out-Null
        Assert-ReparseFreeDirectory -Path 'P:\' `
            -Label 'deterministic build drive' | Out-Null
        foreach ($dependency in @($contract.dependencies | Where-Object kind -ceq 'archive')) {
            $archive = Resolve-ContractRelativePath -Root $script:RuntimeRoot `
                -RelativePath ([string]$dependency.source)
            Assert-SafeTarArchive -Path $archive
            Invoke-PinnedNative -Id 'tar' `
                -Arguments @('-xzf', $archive, '-C', 'P:\') `
                -Label "extract $($dependency.id)" `
                -PathDirectories @((Split-Path -Parent $tar)) | Out-Null
        }
        foreach ($dependency in @($contract.dependencies | Where-Object kind -ceq 'git')) {
            $origin = Resolve-ContractRelativePath -Root $script:RuntimeRoot `
                -RelativePath ([string]$dependency.source)
            $destination = 'P:\' + [string]$dependency.id
            New-LocalObjectGitCheckout -SourcePath $origin -DestinationPath $destination `
                -Commit ([string]$dependency.commit) -Label ([string]$dependency.id) | Out-Null
        }
        # The complete dependency recipe is deliberately encoded here rather than
        # modifying any installed MinGW directory. All outputs stay below P:\prefix.
        $prefix = 'P:/prefix'
        $releaseC = '-O2 -DNDEBUG -ffile-prefix-map=P:=. -fmacro-prefix-map=P:=. -fdebug-prefix-map=P:=.'
        $releaseCxx = $releaseC + ' -Wno-free-nonheap-object'
        New-ReparseFreeDirectory -Path 'P:\home' -Label 'hermetic build home' | Out-Null
        New-ReparseFreeDirectory -Path 'P:\tmp' -Label 'hermetic build temporary root' | Out-Null
        $buildEnvironment = @{
            HOME = 'P:\home'
            USERPROFILE = 'P:\home'
            TEMP = 'P:\tmp'
            TMP = 'P:\tmp'
        }
        $buildNativePaths = @(
            (Split-Path -Parent $cmake),
            (Split-Path -Parent $ninja),
            (Split-Path -Parent $gcc),
            (Split-Path -Parent $sh),
            (Split-Path -Parent $tar)
        )
        Invoke-PinnedNative -Id 'cmake' -Arguments @(
            '-S', 'P:\zlib-1.3.2', '-B', 'P:\build-zlib', '-G', 'Ninja',
            "-DCMAKE_MAKE_PROGRAM=$ninja", "-DCMAKE_C_COMPILER=$gcc",
            "-DCMAKE_INSTALL_PREFIX=$prefix", '-DCMAKE_BUILD_TYPE=Release',
            '-DZLIB_BUILD_TESTING=ON', "-DCMAKE_C_FLAGS_RELEASE=$releaseC"
        ) -Label 'zlib configure' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        Invoke-PinnedNative -Id 'cmake' -Arguments @(
            '--build', 'P:\build-zlib', '--parallel', "$Parallel") `
            -Label 'zlib build' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        $zlibCTest = Invoke-PinnedNative -Id 'ctest' -Arguments @(
            '--test-dir', 'P:\build-zlib', '--output-on-failure') `
            -Label 'zlib CTest' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths
        Assert-CTestSummary -Result $zlibCTest `
            -Expected @($contract.validation.dependencyTests)[0]
        Invoke-PinnedNative -Id 'cmake' -Arguments @('--install', 'P:\build-zlib') `
            -Label 'zlib install' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        Copy-Item -LiteralPath 'P:\prefix\lib\libzs.a' -Destination 'P:\prefix\lib\libz.a' -Force
        foreach ($unneeded in @('P:\prefix\lib\libz.dll.a', 'P:\prefix\bin\libz.dll')) {
            if (Test-Path -LiteralPath $unneeded -PathType Leaf) {
                [System.IO.File]::Delete($unneeded)
            }
        }
        New-ReparseFreeDirectory -Path 'P:\tools' -Label 'build tools root' | Out-Null
        New-ReparseFreeDirectory -Path 'P:\build-iconv' -Label 'libiconv build root' | Out-Null
        $makeTool = Get-VerifiedToolRecord -Id 'mingw32-make'
        Copy-Item -LiteralPath $makeTool.Path `
            -Destination 'P:\tools\make.exe' -Force
        Assert-FileRecord -Path 'P:\tools\make.exe' -Record ([pscustomobject]@{
                size = [long]$makeTool.Record.executableSize
                sha256 = [string]$makeTool.Record.sha256
            }) | Out-Null
        $mingwBin = Split-Path -Parent $gcc
        $mingwUnix = Convert-ToMsysPath -Path $mingwBin
        $gccUnix = Convert-ToMsysPath -Path $gcc
        $iconvScript = "export PATH='/p/tools:${mingwUnix}:/usr/bin'; " +
            'cd /p/build-iconv; ../libiconv-1.19/configure ' +
            '--host=x86_64-w64-mingw32 --disable-shared --enable-static --disable-nls ' +
            "--prefix=/p/prefix CC='$gccUnix' CFLAGS='$releaseC' " +
            "LDFLAGS='-static -Wl,--no-insert-timestamp'; " +
            "/p/tools/make.exe -j$Parallel OBJECTS_RES_yes="
        Invoke-PinnedNative -Id 'bash' -Arguments @(
            '--noprofile', '--norc', '-c', $iconvScript) `
            -Label 'libiconv build' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        Copy-Item 'P:\build-iconv\lib\.libs\libiconv.a' 'P:\prefix\lib\libiconv.a' -Force
        Copy-Item 'P:\build-iconv\include\iconv.h' 'P:\prefix\include\iconv.h' -Force
        Invoke-PinnedNative -Id 'cmake' -Arguments @(
            '-S', 'P:\phosg', '-B', 'P:\build-phosg', '-G', 'Ninja',
            "-DCMAKE_MAKE_PROGRAM=$ninja", "-DCMAKE_C_COMPILER=$gcc",
            "-DCMAKE_CXX_COMPILER=$gxx", "-DCMAKE_INSTALL_PREFIX=$prefix",
            "-DCMAKE_PREFIX_PATH=$prefix", '-DCMAKE_BUILD_TYPE=Release',
            "-DCMAKE_C_FLAGS_RELEASE=$releaseC", "-DCMAKE_CXX_FLAGS_RELEASE=$releaseCxx",
            '-DCMAKE_EXE_LINKER_FLAGS=-static -Wl,--no-insert-timestamp',
            '-DPHOSG_SKIP_PROCESS_TEST=1'
        ) -Label 'phosg configure' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        Invoke-PinnedNative -Id 'cmake' -Arguments @(
            '--build', 'P:\build-phosg', '--parallel', "$Parallel") `
            -Label 'phosg build' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        $phosgCTest = Invoke-PinnedNative -Id 'ctest' -Arguments @(
            '--test-dir', 'P:\build-phosg', '--output-on-failure') `
            -Label 'phosg CTest' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths
        Assert-CTestSummary -Result $phosgCTest `
            -Expected @($contract.validation.dependencyTests)[1]
        Invoke-PinnedNative -Id 'cmake' -Arguments @('--install', 'P:\build-phosg') `
            -Label 'phosg install' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        Invoke-PinnedNative -Id 'cmake' -Arguments @(
            '-S', 'P:\resource_dasm', '-B', 'P:\build-resource', '-G', 'Ninja',
            "-DCMAKE_MAKE_PROGRAM=$ninja", "-DCMAKE_C_COMPILER=$gcc",
            "-DCMAKE_CXX_COMPILER=$gxx", "-DCMAKE_INSTALL_PREFIX=$prefix",
            "-DCMAKE_PREFIX_PATH=$prefix", '-DCMAKE_BUILD_TYPE=Release',
            "-DCMAKE_C_FLAGS_RELEASE=$releaseC", "-DCMAKE_CXX_FLAGS_RELEASE=$releaseCxx"
        ) -Label 'resource_file configure' -Environment $buildEnvironment `
            -PathDirectories $buildNativePaths | Out-Null
        Invoke-PinnedNative -Id 'cmake' -Arguments @(
            '--build', 'P:\build-resource', '--target', 'resource_file',
            '--parallel', "$Parallel") -Label 'resource_file build' `
            -Environment $buildEnvironment -PathDirectories $buildNativePaths | Out-Null
        Copy-Item -LiteralPath 'P:\build-resource\libresource_file.a' `
            -Destination 'P:\prefix\lib\libresource_file.a' -Force
        $resourceInclude = 'P:\prefix\include\resource_file'
        New-Item -ItemType Directory -Path $resourceInclude -Force | Out-Null
        foreach ($relativeDirectory in @('', 'Audio', 'Decompressors', 'IndexFormats',
                'ExecutableFormats', 'Emulators')) {
            $sourceDirectory = if ($relativeDirectory) {
                Join-Path 'P:\resource_dasm\src' $relativeDirectory
            } else {
                'P:\resource_dasm\src'
            }
            if (-not (Test-Path -LiteralPath $sourceDirectory -PathType Container)) {
                continue
            }
            $destinationDirectory = if ($relativeDirectory) {
                Join-Path $resourceInclude $relativeDirectory
            } else {
                $resourceInclude
            }
            New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
            foreach ($header in @(Get-ChildItem -LiteralPath $sourceDirectory -File `
                    -Filter '*.hh' -Force)) {
                Copy-Item -LiteralPath $header.FullName -Destination (
                    Join-Path $destinationDirectory $header.Name) -Force
            }
        }
        $resourceConfigDirectory = 'P:\prefix\lib\cmake\resource_file'
        New-Item -ItemType Directory -Path $resourceConfigDirectory -Force | Out-Null
        $resourceConfig = @'
if(NOT TARGET resource_file::resource_file)
  add_library(resource_file::resource_file STATIC IMPORTED)
  set_target_properties(resource_file::resource_file PROPERTIES
    IMPORTED_LOCATION "P:/prefix/lib/libresource_file.a"
    INTERFACE_INCLUDE_DIRECTORIES "P:/prefix/include"
    INTERFACE_LINK_LIBRARIES "phosg::phosg;z")
endif()
'@
        [System.IO.File]::WriteAllText(
            (Join-Path $resourceConfigDirectory 'resource_fileConfig.cmake'),
            $resourceConfig,
            [System.Text.UTF8Encoding]::new($false))
        Copy-Item -LiteralPath 'P:\asio\include\asio.hpp' `
            -Destination 'P:\prefix\include\asio.hpp' -Force
        Copy-Item -LiteralPath 'P:\asio\include\asio' `
            -Destination 'P:\prefix\include\asio' -Recurse -Force

        $sourceOrigin = Join-Path $script:RuntimeRoot 'sources\newserv-git-d754a34e'
        $patchPath = Join-Path $script:RepositoryRoot `
            'patches\newserv\0001-deterministic-revision-metadata.patch'
        $newservEnvironment = @{
            HOME = 'P:\home'
            USERPROFILE = 'P:\home'
            TEMP = 'P:\tmp'
            TMP = 'P:\tmp'
            NEWSERV_BUILD_REVISION = $script:BuildRevision
            SOURCE_DATE_EPOCH = [string]$script:SourceDateEpoch
        }
        $buildResults = [System.Collections.Generic.List[object]]::new()
        foreach ($run in 1..2) {
            $newservCheckout = New-LocalObjectGitCheckout -SourcePath $sourceOrigin `
                -DestinationPath 'P:\newserv' -Commit $script:SourceCommit `
                -Label "newserv run $run"
            Invoke-HermeticGit -RepositoryPath $newservCheckout.Repository `
                -AllowedAlternateObjectRoot $newservCheckout.AlternateObjectRoot `
                -Arguments @('apply', '--cached', '--whitespace=error-all', $patchPath) `
                -Label "newserv patch run $run" | Out-Null
            $checkoutPrefix = [System.IO.Path]::TrimEndingDirectorySeparator(
                [string]$newservCheckout.Repository) + [System.IO.Path]::DirectorySeparatorChar
            Invoke-HermeticGit -RepositoryPath $newservCheckout.Repository `
                -AllowedAlternateObjectRoot $newservCheckout.AlternateObjectRoot `
                -Arguments @('checkout-index', '--all', '--force',
                    ('--prefix=' + $checkoutPrefix)) `
                -Label "newserv patched worktree run $run" | Out-Null
            Assert-NewservPatchedCheckoutStatus -Checkout $newservCheckout -Run $run
            Assert-OrdinaryBuildInputBoundary -Contract $contract
            Invoke-PinnedNative -Id 'cmake' -Arguments @(
                '-S', 'P:\newserv', '-B', 'P:\build-newserv', '-G', 'Ninja',
                "-DCMAKE_MAKE_PROGRAM=$ninja", "-DCMAKE_C_COMPILER=$gcc",
                "-DCMAKE_CXX_COMPILER=$gxx", "-DCMAKE_PREFIX_PATH=$prefix",
                "-DSH_EXECUTABLE=$sh",
                "-DWINDOWS_ENV=$prefix", '-DCMAKE_BUILD_TYPE=Release',
                "-DCMAKE_C_FLAGS_RELEASE=$releaseC",
                "-DCMAKE_CXX_FLAGS_RELEASE=$releaseCxx",
                '-DCMAKE_EXE_LINKER_FLAGS=-static -Wl,--no-insert-timestamp'
            ) -Label "newserv configure run $run" `
                -Environment $newservEnvironment `
                -PathDirectories $buildNativePaths | Out-Null
            Assert-ReparseFreeDirectory -Path 'P:\build-newserv' `
                -Label "newserv build output run $run" | Out-Null
            Invoke-PinnedNative -Id 'cmake' -Arguments @(
                '--build', 'P:\build-newserv', '--parallel', "$Parallel") `
                -Label "newserv build run $run" -Environment $newservEnvironment `
                -PathDirectories $buildNativePaths | Out-Null
            $executable = Assert-RegularFile -Path 'P:\build-newserv\newserv.exe'
            $buildResults.Add([pscustomobject]@{
                    Run = $run
                    Size = [long]$executable.Length
                    Sha256 = Get-LowerSha256 -Path $executable.FullName
                    Path = $executable.FullName
                })
            Remove-NewservGeneratedRevisionFiles -Checkout $newservCheckout
            Assert-NewservPatchedCheckoutStatus -Checkout $newservCheckout -Run $run
            if ($run -eq 1) {
                New-Item -ItemType Directory -Path 'P:\results' -Force | Out-Null
                Copy-Item -LiteralPath $executable.FullName `
                    -Destination 'P:\results\newserv-run1.exe' -Force
                Move-Item -LiteralPath 'P:\newserv' -Destination 'P:\newserv-run1'
                Move-Item -LiteralPath 'P:\build-newserv' `
                    -Destination 'P:\build-newserv-run1'
            }
        }
        $first = $buildResults[0]
        $second = $buildResults[1]
        if ($first.Size -ne $second.Size -or $first.Sha256 -cne $second.Sha256 -or
            $second.Size -ne [long]$contract.output.executable.size -or
            $second.Sha256 -cne [string]$contract.output.executable.sha256) {
            throw 'The two clean newserv builds are not byte-identical to the contract'
        }
        Assert-NewservPatchedCheckoutStatus -Checkout $newservCheckout -Run 2
        $trackedInventory = Get-GitTrackedFileInventory `
            -RepositoryPath $newservCheckout.Repository `
            -AllowedAlternateObjectRoot $newservCheckout.AlternateObjectRoot `
            -Label 'newserv run 2 tracked package inventory'
        $readmeSource = Resolve-GitTrackedWorktreeSource `
            -RepositoryPath $newservCheckout.Repository -Inventory $trackedInventory `
            -TrackedPath 'README.md'
        $licenseSource = Resolve-GitTrackedWorktreeSource `
            -RepositoryPath $newservCheckout.Repository -Inventory $trackedInventory `
            -TrackedPath 'LICENSE'
        $systemPackagePlan = @(Get-NewservPackageSystemPlan `
                -RepositoryPath $newservCheckout.Repository -Inventory $trackedInventory)

        $stageRelease = Join-Path $script:RuntimeRoot (
            'combat-canary\.staging\server-base-' + [Guid]::NewGuid().ToString('N'))
        New-ReparseFreeDirectory -Path $stageRelease `
            -Label 'publication stage release' | Out-Null
        function Copy-PackageFile {
            param([string]$Source, [string]$RelativePath)
            $destination = Resolve-ContractRelativePath -Root $stageRelease `
                -RelativePath $RelativePath
            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                New-ReparseFreeDirectory -Path $parent `
                    -Label 'publication package directory' | Out-Null
            }
            $sourceItem = Assert-RegularFile -Path $Source
            Copy-Item -LiteralPath $sourceItem.FullName -Destination $destination -Force
        }
        Copy-PackageFile -Source 'P:\build-newserv\newserv.exe' `
            -RelativePath 'newserv-windows.exe'
        Copy-PackageFile -Source $readmeSource.SourcePath `
            -RelativePath 'README.md'
        foreach ($notice in @(
                @{ Source = $licenseSource.SourcePath; Path = 'notices/newserv-MIT.txt' },
                @{ Source = 'P:\phosg\README.md'; Path = 'notices/phosg-README.txt' },
                @{ Source = 'P:\resource_dasm\LICENSE'; Path = 'notices/resource_dasm-MIT.txt' },
                @{ Source = 'P:\asio\LICENSE_1_0.txt'; Path = 'notices/asio-Boost-1.0.txt' },
                @{ Source = 'P:\libiconv-1.19\COPYING.LIB'; Path = 'notices/libiconv-LGPL-2.1.txt' },
                @{ Source = 'P:\zlib-1.3.2\LICENSE'; Path = 'notices/zlib-license.txt' }
            )) {
            Copy-PackageFile -Source $notice.Source -RelativePath $notice.Path
        }
        foreach ($plannedFile in $systemPackagePlan) {
            Copy-PackageFile -Source $plannedFile.SourcePath `
                -RelativePath $plannedFile.DestinationPath
        }
        $releaseFiles = [System.Collections.Generic.List[object]]::new()
        $payloadBytes = [long]0
        foreach ($entry in @(Get-OrdinalRelativeFiles -Root $stageRelease `
                -Label 'publication stage release')) {
            $file = $entry.File
            $payloadBytes += [long]$file.Length
            $releaseFiles.Add([ordered]@{
                    path = [string]$entry.RelativePath
                    size = [long]$file.Length
                    sha256 = Get-LowerSha256 -Path $file.FullName
                })
        }
        $manifest = [ordered]@{
            schemaVersion = 1
            profileId = [string]$contract.profileId
            sourceCommit = [string]$contract.source.commit
            patchSeriesSha256 = [string]$contract.patchSeries.sha256
            files = @($releaseFiles)
        }
        $manifestPath = Join-Path $stageRelease 'release-manifest.json'
        [System.IO.File]::WriteAllText(
            $manifestPath,
            (($manifest | ConvertTo-Json -Depth 8) + "`n"),
            [System.Text.UTF8Encoding]::new($false))
        if ($releaseFiles.Count -ne [int]$contract.output.fileCount -or
            $payloadBytes -ne [long]$contract.output.totalBytes) {
            throw 'The rebuilt release payload does not match the contract'
        }
        Assert-FileRecord -Path $manifestPath -Record $contract.output.releaseManifest | Out-Null
        Assert-ReleaseOutputClaims -Contract $contract -ReleaseRoot $stageRelease
        } finally {
            if (Test-Path -LiteralPath 'P:\') {
                Invoke-PinnedNative -Id 'subst' -Arguments @('P:', '/D') `
                    -Label 'remove deterministic P: build drive' `
                    -PathDirectories @((Split-Path -Parent $subst)) | Out-Null
                if (Test-Path -LiteralPath 'P:\') {
                    throw 'Unable to remove the deterministic P: build drive'
                }
            }
        }
        Assert-PSOBBBuildStoppedBoundary
        $releaseRoot = Resolve-ContractRelativePath -Root $script:RuntimeRoot `
            -RelativePath ([string]$contract.output.rootRelative)
        Publish-CombatCanaryRelease -StageRelease $stageRelease `
            -ReleaseRoot $releaseRoot `
            -StagingRoot (Join-Path $script:RuntimeRoot 'combat-canary\.staging') `
            -VerifyAction { Invoke-CombatCanaryVerify }
    } finally {
        Exit-CombatCanaryBuildBoundary -Boundary $boundary
    }
}

if ($MyInvocation.InvocationName -cne '.') {
    Assert-CanonicalRuntimeRoot | Out-Null
    if ($Action -ceq 'Verify') {
        Invoke-CombatCanaryVerify
    } else {
        Invoke-CombatCanaryBuild
    }
}
