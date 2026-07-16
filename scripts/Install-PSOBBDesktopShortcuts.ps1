[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RuntimeRoot,
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$PlayChannel = 'Canary',
    [ValidateSet(
        'safe-native-4x3',
        'clarity-dgvoodoo-4x3',
        'lab-widescreen-16x10',
        'lab-widescreen-hd-16x10',
        'fidelity-modern-16x10',
        'dxvk-canary',
        'd3d8to9-canary')]
    [string]$PlayProfile,
    [ValidateSet('Borderless', 'Resizable')]
    [string]$PlayWindowMode = 'Borderless',
    [switch]$PlayPreserveForeground,
    [Parameter(DontShow)][string]$ShortcutDirectory
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Assert-PSOBBSafeLauncherPayloadPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$LauncherRoot
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path -cne $Path.Trim() -or
        $Path.Contains('\') -or
        $Path.StartsWith('/', [System.StringComparison]::Ordinal) -or
        [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw "The launcher payload contains an unsafe non-canonical path: $Path"
    }

    $segments = @($Path.Split('/'))
    $invalidNameCharacters = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or
            $segment -ceq '.' -or
            $segment -ceq '..' -or
            $segment -cne $segment.Trim() -or
            $segment.EndsWith('.', [System.StringComparison]::Ordinal) -or
            $segment.IndexOfAny($invalidNameCharacters) -ge 0) {
            throw "The launcher payload contains an unsafe non-canonical path: $Path"
        }
        $deviceName = $segment.Split('.')[0]
        if ($deviceName -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])$') {
            throw "The launcher payload contains a reserved Windows path: $Path"
        }
    }

    $platformPath = $Path.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    Assert-PathWithinRoot `
        -Path (Join-Path $LauncherRoot $platformPath) `
        -Root $LauncherRoot
}

function Get-PSOBBLauncherPayloadSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Entries)

    # This is intentionally byte-for-byte identical to Publish-PSOBBLauncher.ps1.
    $payloadIndex = ($Entries | ForEach-Object {
        "$($_.path)`0$($_.size)`0$($_.sha256)"
    }) -join "`n"
    [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.Encoding]::UTF8.GetBytes($payloadIndex))).ToLowerInvariant()
}

function Assert-PSOBBLauncherPayloadInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LauncherRoot,
        [Parameter(Mandatory)]$Record
    )

    $launcherRootFull = [System.IO.Path]::GetFullPath($LauncherRoot).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $launcherRootFull -PathType Container)) {
        throw "The published launcher package directory does not exist: $launcherRootFull"
    }
    Assert-PathWithinRoot -Path $launcherRootFull -Root $launcherRootFull | Out-Null
    $reparseItems = @(Get-ChildItem -LiteralPath $launcherRootFull -Force -Recurse |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        })
    if ($reparseItems.Count -gt 0) {
        throw "The launcher payload contains a reparse point: $($reparseItems[0].FullName)"
    }
    if ($Record.schemaVersion -ne 2) {
        throw 'The published launcher build record has an unsupported schema version'
    }

    $requiredExclusions = @('launcher-build.json', 'launcher-build.json.sig')
    $recordExclusions = @($Record.payloadIndexExcludes)
    if ($recordExclusions.Count -ne $requiredExclusions.Count) {
        throw 'The launcher payload-index exclusion list is not exact'
    }
    for ($index = 0; $index -lt $requiredExclusions.Count; $index++) {
        if ([string]$recordExclusions[$index] -cne $requiredExclusions[$index]) {
            throw 'The launcher payload-index exclusion list is not exact'
        }
    }

    $recordEntries = @($Record.files)
    if ($recordEntries.Count -eq 0) {
        throw 'The signed launcher payload inventory is empty'
    }
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $validatedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $recordEntries) {
        if ($null -eq $entry -or
            $null -eq $entry.PSObject.Properties['path'] -or
            $null -eq $entry.PSObject.Properties['size'] -or
            $null -eq $entry.PSObject.Properties['sha256']) {
            throw 'The signed launcher payload contains an incomplete file entry'
        }
        $relativePath = [string]$entry.path
        $entryPath = Assert-PSOBBSafeLauncherPayloadPath `
            -Path $relativePath `
            -LauncherRoot $launcherRootFull
        if ($requiredExclusions -ccontains $relativePath) {
            throw "The launcher payload inventory includes an excluded file: $relativePath"
        }
        if (-not $seenPaths.Add($relativePath)) {
            throw "The launcher payload contains a duplicate path: $relativePath"
        }

        $sizeText = [Convert]::ToString(
            $entry.size,
            [System.Globalization.CultureInfo]::InvariantCulture)
        if ($sizeText -notmatch '^(0|[1-9][0-9]*)$') {
            throw "The launcher payload contains an invalid size for $relativePath"
        }
        $entrySize = 0L
        if (-not [long]::TryParse(
            $sizeText,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$entrySize)) {
            throw "The launcher payload contains an invalid size for $relativePath"
        }
        $entryHash = [string]$entry.sha256
        if ($entryHash -cnotmatch '^[0-9a-f]{64}$') {
            throw "The launcher payload contains an invalid SHA-256 for $relativePath"
        }
        $validatedEntries.Add([pscustomobject]@{
            path = $relativePath
            size = $entrySize
            sha256 = $entryHash
            fullPath = $entryPath
        })
    }

    $excludedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($excludedPath in $requiredExclusions) {
        $excludedPaths.Add($excludedPath) | Out-Null
    }
    $actualEntries = @(Get-ChildItem -LiteralPath $launcherRootFull -File -Recurse -Force |
        Sort-Object FullName |
        ForEach-Object {
            $fullPath = Assert-PathWithinRoot -Path $_.FullName -Root $launcherRootFull
            $relativePath = [System.IO.Path]::GetRelativePath(
                $launcherRootFull,
                $fullPath).Replace('\', '/')
            if (-not $excludedPaths.Contains($relativePath)) {
                Assert-PSOBBSafeLauncherPayloadPath `
                    -Path $relativePath `
                    -LauncherRoot $launcherRootFull | Out-Null
                [pscustomobject]@{
                    path = $relativePath
                    item = $_
                }
            }
        })

    if ($actualEntries.Count -ne $validatedEntries.Count) {
        throw "The launcher payload inventory does not exactly match the signed build record ($($actualEntries.Count) actual, $($validatedEntries.Count) signed)"
    }

    $canonicalEntries = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $actualEntries.Count; $index++) {
        $actualEntry = $actualEntries[$index]
        $signedEntry = $validatedEntries[$index]
        if ([string]$actualEntry.path -cne [string]$signedEntry.path) {
            throw "The launcher payload inventory or canonical order differs at entry $index"
        }
        if ([long]$actualEntry.item.Length -ne [long]$signedEntry.size) {
            throw "The launcher payload size does not match the signed build record: $($signedEntry.path)"
        }
        $actualHash = Get-LowerSha256 -Path $actualEntry.item.FullName
        if ($actualHash -cne [string]$signedEntry.sha256) {
            throw "The launcher payload SHA-256 does not match the signed build record: $($signedEntry.path)"
        }
        $canonicalEntries.Add([pscustomobject]@{
            path = [string]$actualEntry.path
            size = [long]$actualEntry.item.Length
            sha256 = $actualHash
        })
    }

    $recordPayloadHash = [string]$Record.payloadSha256
    if ($recordPayloadHash -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The launcher build record contains an invalid payload SHA-256'
    }
    $actualPayloadHash = Get-PSOBBLauncherPayloadSha256 -Entries $canonicalEntries.ToArray()
    if ($actualPayloadHash -cne $recordPayloadHash) {
        throw 'The launcher payload index does not match payloadSha256 in the signed build record'
    }

    [pscustomobject]@{
        Entries = $canonicalEntries.ToArray()
        PayloadSha256 = $actualPayloadHash
    }
}

function Assert-PSOBBPublishedLauncher {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $launcherRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Stable 'launcher') `
        -Root $Layout.Root
    $launcherPath = Join-Path $launcherRoot 'PSOBB.Launcher.exe'
    $buildRecordPath = Join-Path $launcherRoot 'launcher-build.json'
    $signaturePath = $buildRecordPath + '.sig'
    $publicKeyPath = Join-Path $launcherRoot 'release-public-key.pem'
    foreach ($path in @($launcherPath, $buildRecordPath, $signaturePath, $publicKeyPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "The signed published launcher package is incomplete: $path"
        }
    }

    $trustPath = Join-Path $script:PSOBBRepositoryRoot 'config\release-trust.json'
    $trust = Get-Content -Raw -LiteralPath $trustPath | ConvertFrom-Json -Depth 10
    $activeKeys = @($trust.keys | Where-Object { $_.id -eq $trust.activeKeyId })
    if ($trust.schemaVersion -ne 1 -or $activeKeys.Count -ne 1 -or
        [string]$activeKeys[0].spkiSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'release-trust.json does not contain one valid active launcher trust anchor'
    }

    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportFromPem([System.IO.File]::ReadAllText($publicKeyPath))
        $spki = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData(
                $verifier.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
        if ($spki -ne [string]$activeKeys[0].spkiSha256) {
            throw 'The published launcher public key does not match the repository trust anchor'
        }
        $signature = [Convert]::FromBase64String(
            [System.IO.File]::ReadAllText($signaturePath).Trim())
        $signatureValid = $verifier.VerifyData(
            [System.IO.File]::ReadAllBytes($buildRecordPath),
            $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        [Array]::Clear($signature, 0, $signature.Length)
        if (-not $signatureValid) {
            throw 'The published launcher build-record signature is invalid'
        }
    } finally {
        $verifier.Dispose()
    }

    $record = Get-Content -Raw -LiteralPath $buildRecordPath | ConvertFrom-Json -Depth 10
    Assert-PSOBBLauncherPayloadInventory `
        -LauncherRoot $launcherRoot `
        -Record $record | Out-Null
    $launcherFile = Get-Item -LiteralPath $launcherPath
    $launcherEntries = @($record.files | Where-Object { $_.path -eq 'PSOBB.Launcher.exe' })
    $actualHash = Get-LowerSha256 -Path $launcherPath
    if ($record.schemaVersion -ne 2 -or
        [string]$record.launcherSha256 -ne $actualHash -or
        $launcherEntries.Count -ne 1 -or
        [long]$launcherEntries[0].size -ne $launcherFile.Length -or
        [string]$launcherEntries[0].sha256 -ne $actualHash) {
        throw 'The published launcher executable does not match its signed build record'
    }

    [pscustomobject]@{
        Path = $launcherPath
        Root = $launcherRoot
        Sha256 = $actualHash
    }
}

function Get-PSOBBShortcutDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$TargetPath,
        [AllowEmptyString()][string]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$Description
    )

    [pscustomobject]@{
        Name = $Name
        TargetPath = [System.IO.Path]::GetFullPath($TargetPath)
        Arguments = [string]$Arguments
        WorkingDirectory = [System.IO.Path]::GetFullPath($WorkingDirectory)
        Description = $Description
        IconLocation = ([System.IO.Path]::GetFullPath($TargetPath) + ',0')
    }
}

function Test-PSOBBShortcutDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Shell,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Definition
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $shortcut = $Shell.CreateShortcut($Path)
    ([System.IO.Path]::GetFullPath([string]$shortcut.TargetPath)).Equals(
        $Definition.TargetPath,
        [System.StringComparison]::OrdinalIgnoreCase) -and
        ([string]$shortcut.Arguments -ceq [string]$Definition.Arguments) -and
        ([System.IO.Path]::GetFullPath([string]$shortcut.WorkingDirectory)).Equals(
            $Definition.WorkingDirectory,
            [System.StringComparison]::OrdinalIgnoreCase) -and
        ([string]$shortcut.Description -ceq [string]$Definition.Description) -and
        ([string]$shortcut.IconLocation).Equals(
            $Definition.IconLocation,
            [System.StringComparison]::OrdinalIgnoreCase)
}

function Write-PSOBBShortcutDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Shell,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Definition
    )

    $shortcut = $Shell.CreateShortcut($Path)
    $shortcut.TargetPath = $Definition.TargetPath
    $shortcut.Arguments = $Definition.Arguments
    $shortcut.WorkingDirectory = $Definition.WorkingDirectory
    $shortcut.Description = $Definition.Description
    $shortcut.IconLocation = $Definition.IconLocation
    $shortcut.WindowStyle = 1
    $shortcut.Save()
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$launcher = Assert-PSOBBPublishedLauncher -Layout $layout
if ([string]::IsNullOrWhiteSpace($ShortcutDirectory)) {
    $ShortcutDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::DesktopDirectory,
        [Environment+SpecialFolderOption]::DoNotVerify)
}
if ([string]::IsNullOrWhiteSpace($ShortcutDirectory)) {
    throw 'Windows did not return the current user Desktop known-folder path'
}
$shortcutRoot = [System.IO.Path]::GetFullPath($ShortcutDirectory).TrimEnd('\')
if ($shortcutRoot.StartsWith('\\', [System.StringComparison]::Ordinal)) {
    throw 'The PSOBB shortcuts must be installed on a local per-user Desktop, not a network path'
}
if (-not (Test-Path -LiteralPath $shortcutRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $shortcutRoot -Force | Out-Null
}

$profileChannels = [ordered]@{
    'safe-native-4x3' = 'Stable'
    'clarity-dgvoodoo-4x3' = 'Canary'
    'lab-widescreen-16x10' = 'LocalLab'
    'lab-widescreen-hd-16x10' = 'LocalLab'
    'fidelity-modern-16x10' = 'Canary'
    'dxvk-canary' = 'LocalLab'
    'd3d8to9-canary' = 'LocalLab'
}
if ([string]::IsNullOrWhiteSpace($PlayProfile)) {
    $PlayProfile = switch ($PlayChannel) {
        'Stable' { 'safe-native-4x3' }
        'Canary' { 'clarity-dgvoodoo-4x3' }
        'LocalLab' { 'lab-widescreen-16x10' }
    }
}
if (-not $profileChannels.Contains($PlayProfile) -or
    [string]$profileChannels[$PlayProfile] -cne $PlayChannel) {
    throw "Play profile '$PlayProfile' is not valid for the $PlayChannel channel"
}

$playChannelArgument = if ($PlayChannel -eq 'LocalLab') { 'local-lab' } else { $PlayChannel.ToLowerInvariant() }
$runtimeArgument = '--runtime-root "{0}"' -f $layout.Root.Replace('"', '\"')
$startServerArguments = '--start-server {0}' -f $runtimeArgument
$stopServerArguments = '--stop-all {0}' -f $runtimeArgument
$playArguments = '--play --channel {0} --profile {1} --window-mode {2} --runtime-root "{3}"' -f `
    $playChannelArgument,
    $PlayProfile,
    $PlayWindowMode.ToLowerInvariant(),
    $layout.Root.Replace('"', '\"')
if ($PlayPreserveForeground) {
    $playArguments += ' --preserve-foreground'
}
if (($startServerArguments, $stopServerArguments, $playArguments) -match
    '(?i)(password|credential|username|identity|secret)') {
    throw 'A desktop shortcut must never contain an account name or credential'
}
$startServerDefinition = Get-PSOBBShortcutDefinition `
    -Name 'PSOBB Start Server' `
    -TargetPath $launcher.Path `
    -Arguments $startServerArguments `
    -WorkingDirectory $launcher.Root `
    -Description 'Start the local PSOBB server'
$stopServerDefinition = Get-PSOBBShortcutDefinition `
    -Name 'PSOBB Stop Server' `
    -TargetPath $launcher.Path `
    -Arguments $stopServerArguments `
    -WorkingDirectory $launcher.Root `
    -Description 'Close the PSOBB client if needed, then stop the local server safely'
$playDefinition = Get-PSOBBShortcutDefinition `
    -Name 'PSOBB Play' `
    -TargetPath $launcher.Path `
    -Arguments $playArguments `
    -WorkingDirectory $launcher.Root `
    -Description $(if ($PlayPreserveForeground) {
        'Start PSOBB and try to keep the current application focused'
    } else {
        'Start the local server if needed and launch the PSOBB client in borderless mode'
    })
$definitions = @($startServerDefinition, $stopServerDefinition, $playDefinition)
$obsoleteShortcutPaths = @(
    (Join-Path $shortcutRoot 'PSOBB Control Center.lnk')
)

$shell = New-Object -ComObject WScript.Shell
$temporaryPaths = [System.Collections.Generic.List[string]]::new()
$backupPaths = @{}
$modifiedFinals = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
try {
    $alreadyCurrent = $true
    foreach ($definition in $definitions) {
        $path = Join-Path $shortcutRoot ($definition.Name + '.lnk')
        if (-not (Test-PSOBBShortcutDefinition -Shell $shell -Path $path -Definition $definition)) {
            $alreadyCurrent = $false
        }
    }
    foreach ($obsoletePath in $obsoleteShortcutPaths) {
        if (Test-Path -LiteralPath $obsoletePath -PathType Leaf) {
            $alreadyCurrent = $false
        }
    }
    if ($alreadyCurrent) {
        return [pscustomobject]@{
            Installed = $true
            Changed = $false
            Directory = $shortcutRoot
            StartServer = Join-Path $shortcutRoot 'PSOBB Start Server.lnk'
            StopServer = Join-Path $shortcutRoot 'PSOBB Stop Server.lnk'
            Play = Join-Path $shortcutRoot 'PSOBB Play.lnk'
            LauncherSha256 = $launcher.Sha256
        }
    }

    if (-not $PSCmdlet.ShouldProcess(
        $shortcutRoot,
        'install or repair the PSOBB Start Server, Stop Server, and Play shortcuts')) {
        return
    }

    foreach ($definition in $definitions) {
        $temporary = Join-Path $shortcutRoot (
            '.' + $definition.Name + '.' + [Guid]::NewGuid().ToString('N') + '.lnk')
        Write-PSOBBShortcutDefinition -Shell $shell -Path $temporary -Definition $definition
        if (-not (Test-PSOBBShortcutDefinition -Shell $shell -Path $temporary -Definition $definition)) {
            throw "The staged shortcut did not match its exact definition: $($definition.Name)"
        }
        $temporaryPaths.Add($temporary)
    }

    for ($index = 0; $index -lt $definitions.Count; $index++) {
        $definition = $definitions[$index]
        $final = Join-Path $shortcutRoot ($definition.Name + '.lnk')
        if (Test-Path -LiteralPath $final -PathType Leaf) {
            $backup = $final + '.' + [Guid]::NewGuid().ToString('N') + '.backup'
            [System.IO.File]::Copy($final, $backup, $false)
            $backupPaths[$final] = $backup
        }
        [System.IO.File]::Move($temporaryPaths[$index], $final, $true)
        $modifiedFinals.Add($final) | Out-Null
    }

    foreach ($definition in $definitions) {
        $final = Join-Path $shortcutRoot ($definition.Name + '.lnk')
        if (-not (Test-PSOBBShortcutDefinition -Shell $shell -Path $final -Definition $definition)) {
            throw "The installed shortcut did not match its exact definition: $($definition.Name)"
        }
    }

    foreach ($obsoletePath in $obsoleteShortcutPaths) {
        if (Test-Path -LiteralPath $obsoletePath -PathType Leaf) {
            $backup = $obsoletePath + '.' + [Guid]::NewGuid().ToString('N') + '.backup'
            [System.IO.File]::Copy($obsoletePath, $backup, $false)
            $backupPaths[$obsoletePath] = $backup
            Remove-Item -LiteralPath $obsoletePath -Force
        }
    }

    [pscustomobject]@{
        Installed = $true
        Changed = $true
        Directory = $shortcutRoot
        StartServer = Join-Path $shortcutRoot 'PSOBB Start Server.lnk'
        StopServer = Join-Path $shortcutRoot 'PSOBB Stop Server.lnk'
        Play = Join-Path $shortcutRoot 'PSOBB Play.lnk'
        LauncherSha256 = $launcher.Sha256
    }
} catch {
    foreach ($definition in $definitions) {
        $final = Join-Path $shortcutRoot ($definition.Name + '.lnk')
        if ($backupPaths.ContainsKey($final)) {
            [System.IO.File]::Copy([string]$backupPaths[$final], $final, $true)
        } elseif ($modifiedFinals.Contains($final) -and
            (Test-Path -LiteralPath $final -PathType Leaf)) {
            Remove-Item -LiteralPath $final -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($obsoletePath in $obsoleteShortcutPaths) {
        if ($backupPaths.ContainsKey($obsoletePath)) {
            [System.IO.File]::Copy([string]$backupPaths[$obsoletePath], $obsoletePath, $true)
        }
    }
    throw
} finally {
    foreach ($temporary in $temporaryPaths) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    foreach ($backup in $backupPaths.Values) {
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
    if ($shell) {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
}
