[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptPath = Join-Path $repositoryRoot 'scripts\Set-PSOBBAshenbubsHDOverlay.ps1'
$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
. $commonPath

$sevenZipPath = 'C:\Program Files\7-Zip\7z.exe'
$sevenZipDllPath = 'C:\Program Files\7-Zip\7z.dll'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('psobb-ashenbubs-test-' + [Guid]::NewGuid().ToString('N'))
$runtimeRoot = Join-Path $temporaryRoot 'runtime'
$fixtureRoot = Join-Path $temporaryRoot 'fixtures'
$sourcesPath = Join-Path $temporaryRoot 'sources.lock.json'
$passed = 0

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Label)
    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
    $script:passed++
}

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][string]$Label)
    $threw = $false
    try {
        & $Action
    } catch {
        $threw = $true
    }
    Assert-True -Condition $threw -Label $Label
}

function New-TestZip {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Entries
    )

    Add-Type -AssemblyName System.IO.Compression
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    $archive = [System.IO.Compression.ZipArchive]::new(
        $stream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        foreach ($source in @($Entries)) {
            $entry = $archive.CreateEntry([string]$source.Path)
            $writer = [System.IO.StreamWriter]::new(
                $entry.Open(),
                [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write([string]$source.Content)
            } finally {
                $writer.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function New-OuterArchive {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$MonsterArchive,
        [Parameter(Mandatory)][string]$ObjectArchive,
        [Parameter(Mandatory)][string]$CharacterArchive,
        [Parameter(Mandatory)][string]$MapArchive
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    $archive = [System.IO.Compression.ZipArchive]::new(
        $stream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        foreach ($source in @(
            @{ Path = 'root/monster.rar'; Source = $MonsterArchive },
            @{ Path = 'root/object.rar'; Source = $ObjectArchive },
            @{ Path = 'root/character.rar'; Source = $CharacterArchive },
            @{ Path = 'root/map.rar'; Source = $MapArchive }
        )) {
            $entry = $archive.CreateEntry([string]$source.Path)
            $input = [System.IO.File]::OpenRead([string]$source.Source)
            $output = $entry.Open()
            try {
                $input.CopyTo($output)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
        $readme = $archive.CreateEntry('root/Read Me.txt')
        $writer = [System.IO.StreamWriter]::new($readme.Open())
        try { $writer.Write('fixture only') } finally { $writer.Dispose() }
    } finally {
        $archive.Dispose()
    }
}

function Get-ZipEntryStats {
    param([Parameter(Mandatory)][string]$Path)

    $result = & $sevenZipPath l -slt -ba -sccUTF-8 -- $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Fixture listing failed: $Path"
    }
    $entries = @()
    $record = @{}
    foreach ($line in @($result)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($record.ContainsKey('Path')) { $entries += [pscustomobject]$record }
            $record = @{}
            continue
        }
        if ($line -match '^([^=]+) = (.*)$') {
            $record[$matches[1].Trim()] = $matches[2]
        }
    }
    if ($record.ContainsKey('Path')) { $entries += [pscustomobject]$record }
    $files = @($entries | Where-Object { [string]$_.Folder -eq '-' })
    [pscustomobject]@{
        Count = $files.Count
        Bytes = [long](($files | Measure-Object -Property Size -Sum).Sum)
        MaximumBytes = [long](($files | Sort-Object { [long]$_.Size } -Descending |
            Select-Object -First 1).Size)
    }
}

function Write-TestSourcesLock {
    param(
        [Parameter(Mandatory)][string]$OuterArchive,
        [Parameter(Mandatory)]$PackDeclarations,
        [string[]]$AllowedCollisions = @()
    )

    $outer = Get-Item -LiteralPath $OuterArchive
    [long]$expandedAssetBytes = 0
    foreach ($pack in @($PackDeclarations)) {
        $expandedAssetBytes += [long]$pack.expandedBytes
    }
    $members = @(Get-PSOBBZipContentManifest -Path $outer.FullName | ForEach-Object {
        [ordered]@{
            path = [string]$_.path
            size = [long]$_.size
            sha256 = [string]$_.sha256
            authenticode = 'NotApplicable'
        }
    })
    $lock = [ordered]@{
        schemaVersion = 1
        components = @(
            [ordered]@{
                id = 'sevenzip-local-extraction-tool'
                version = [string](Get-Item $sevenZipPath).VersionInfo.FileVersion
                size = (Get-Item $sevenZipPath).Length
                sha256 = Get-LowerSha256 $sevenZipPath
                members = @(
                    [ordered]@{
                        path = '7z.dll'
                        size = (Get-Item $sevenZipDllPath).Length
                        sha256 = Get-LowerSha256 $sevenZipDllPath
                    }
                )
            },
            [ordered]@{
                id = 'ashenbubs-hd-psobb-v1.02-local-import'
                version = '1.02'
                distributionClass = 'local-only'
                compatibilityState = 'ephinea-only-upstream-warning'
                size = $outer.Length
                sha256 = Get-LowerSha256 $outer.FullName
                maximumAssetBytes = 100000000
                expandedAssetBytes = $expandedAssetBytes
                activationRequirements = [ordered]@{
                    requiredClientExecutableSha256 = ('a' * 64)
                    requiredComponentId = 'project-owned-psobb-large-assets'
                    requiredCapability = 'large-assets-59nl'
                    requiredMaximumAssetBytes = 100000000
                    integrationState = 'not-attached-by-this-asset-materializer'
                }
                members = @($members)
                packArchives = @($PackDeclarations)
                allowedIdenticalCollisions = @($AllowedCollisions)
            }
        )
    }
    [System.IO.File]::WriteAllText(
        $sourcesPath,
        ($lock | ConvertTo-Json -Depth 30),
        [System.Text.UTF8Encoding]::new($false))
}

function New-ValidFixture {
    param([Parameter(Mandatory)][string]$Name)

    $root = Join-Path $fixtureRoot $Name
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $monster = Join-Path $root 'monster.rar'
    $object = Join-Path $root 'object.rar'
    $character = Join-Path $root 'character.rar'
    $map = Join-Path $root 'map.rar'
    New-TestZip -Path $monster -Entries @(
        @{ Path = 'monster.bml'; Content = 'monster' },
        @{ Path = 'shared.bml'; Content = 'shared' })
    New-TestZip -Path $object -Entries @(
        @{ Path = 'object.bml'; Content = 'object' },
        @{ Path = 'shared.bml'; Content = 'shared' })
    New-TestZip -Path $character -Entries @(
        @{ Path = 'character.afs'; Content = 'character' })
    New-TestZip -Path $map -Entries @(
        @{ Path = 'map.xvm'; Content = 'map' })
    $outer = Join-Path $root 'outer.zip'
    New-OuterArchive -Path $outer -MonsterArchive $monster -ObjectArchive $object `
        -CharacterArchive $character -MapArchive $map
    $archives = @{
        monster = $monster
        'object-npc' = $object
        character = $character
        map = $map
    }
    $metadata = @(
        @{ Id = 'monster'; Member = 'root/monster.rar'; Destination = 'data'; Extension = '.bml' },
        @{ Id = 'object-npc'; Member = 'root/object.rar'; Destination = 'data'; Extension = '.bml' },
        @{ Id = 'character'; Member = 'root/character.rar'; Destination = 'data'; Extension = '.afs' },
        @{ Id = 'map'; Member = 'root/map.rar'; Destination = 'data/scene'; Extension = '.xvm' }
    )
    $declarations = @($metadata | ForEach-Object {
        $stats = Get-ZipEntryStats -Path $archives[$_.Id]
        [ordered]@{
            id = $_.Id
            memberPath = $_.Member
            destinationRoot = $_.Destination
            extension = $_.Extension
            entryCount = $stats.Count
            expandedBytes = $stats.Bytes
            maximumEntryBytes = $stats.MaximumBytes
        }
    })
    [pscustomobject]@{ Outer = $outer; Declarations = $declarations }
}

try {
    foreach ($path in @($runtimeRoot, $fixtureRoot)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    $runtimeMarker = [ordered]@{
        schemaVersion = 1
        installationId = [Guid]::NewGuid().ToString('D')
        runtimeRoot = [System.IO.Path]::GetFullPath($runtimeRoot).TrimEnd('\')
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $runtimeRoot '.psobb-runtime.json'),
        ($runtimeMarker | ConvertTo-Json),
        [System.Text.UTF8Encoding]::new($false))

    Assert-True -Condition (Test-Path -LiteralPath $sevenZipPath -PathType Leaf) `
        -Label 'locked 7-Zip fixture dependency exists'
    Assert-True -Condition (Test-Path -LiteralPath $sevenZipDllPath -PathType Leaf) `
        -Label 'locked 7-Zip engine exists'

    $productionSources = Get-Content -Raw `
        -LiteralPath (Join-Path $repositoryRoot 'config\sources.lock.json') |
        ConvertFrom-Json -Depth 100
    $productionComponents = @($productionSources.components | Where-Object {
        [string]$_.id -ceq 'ashenbubs-hd-psobb-v1.02-local-import'
    })
    Assert-True -Condition ($productionComponents.Count -eq 1) `
        -Label 'production lock has one AshenbubsHD v1.02 component'
    $production = $productionComponents[0]
    Assert-True -Condition ([string]$production.sourceUrl -ceq
        'https://www.nexusmods.com/phantasystaronline/mods/3' -and
        [string]$production.distributionClass -ceq 'local-only' -and
        [string]$production.compatibilityState -ceq 'ephinea-only-upstream-warning') `
        -Label 'production provenance preserves official source and local-only boundary'
    Assert-True -Condition ([long]$production.size -eq 1147485243 -and
        [string]$production.sha256 -ceq
            'cfe0fd182485e34d05f5d93b08580453a351ad7ba8ad35056d9167a412b2efea' -and
        @($production.members).Count -eq 5) `
        -Label 'production outer archive and complete member inventory are pinned'
    Assert-True -Condition (@($production.packArchives.entryCount |
        Measure-Object -Sum).Sum -eq 484 -and
        @($production.packArchives.expandedBytes | Measure-Object -Sum).Sum -eq 3449734004 -and
        [long]$production.maximumObservedAssetBytes -eq 85533184 -and
        [long]$production.maximumAssetBytes -eq 100000000) `
        -Label 'production pack counts, sizes, observed maximum, and ceiling are exact'
    Assert-True -Condition (@($production.allowedIdenticalCollisions).Count -eq 3 -and
        [string]$production.activationRequirements.requiredComponentId -ceq
            'project-owned-psobb-large-assets' -and
        [string]$production.activationRequirements.integrationState -ceq
            'not-attached-by-this-asset-materializer') `
        -Label 'production duplicate allowlist and fail-closed large-assets hook are exact'

    $fixture = New-ValidFixture -Name 'valid'
    Write-TestSourcesLock -OuterArchive $fixture.Outer `
        -PackDeclarations $fixture.Declarations `
        -AllowedCollisions @('data/shared.bml')

    $characterResult = & $scriptPath -Action Install -Pack Characters `
        -ArchivePath $fixture.Outer -SevenZipPath $sevenZipPath `
        -SourcesLockPath $sourcesPath -RuntimeRoot $runtimeRoot -Confirm:$false
    Assert-True -Condition ($characterResult.Changed -eq $true -and
        $characterResult.Selection -ceq 'Characters' -and $characterResult.AssetFiles -eq 1) `
        -Label 'character-only overlay materializes exactly one AFS'

    $verifyCharacter = & $scriptPath -Action Verify -SevenZipPath $sevenZipPath `
        -SourcesLockPath $sourcesPath -RuntimeRoot $runtimeRoot
    Assert-True -Condition ($verifyCharacter.Valid -and
        $verifyCharacter.Selection -ceq 'Characters' -and $verifyCharacter.AssetFiles -eq 1) `
        -Label 'character-only overlay verifies complete SHA-256 inventory'

    $idempotent = & $scriptPath -Action Install -Pack Characters `
        -ArchivePath $fixture.Outer -SevenZipPath $sevenZipPath `
        -SourcesLockPath $sourcesPath -RuntimeRoot $runtimeRoot -Confirm:$false
    Assert-True -Condition ($idempotent.Changed -eq $false) `
        -Label 'identical archive and selection are idempotent'

    $allResult = & $scriptPath -Action Install -Pack All `
        -ArchivePath $fixture.Outer -SevenZipPath $sevenZipPath `
        -SourcesLockPath $sourcesPath -RuntimeRoot $runtimeRoot -Confirm:$false
    Assert-True -Condition ($allResult.Changed -eq $true -and
        $allResult.AssetFiles -eq 6 -and $allResult.IdenticalCollisions -eq 1) `
        -Label 'All keeps four packs isolated and accepts only locked identical collision'

    $overlayRoot = Join-Path $runtimeRoot `
        'local-lab\asset-overlays\ashenbubs-hd-psobb-v1.02'
    $current = Join-Path $overlayRoot 'current'
    $forbidden = @(Get-ChildItem -LiteralPath $current -Recurse -File | Where-Object {
        $_.Extension -in @('.rar', '.zip', '.exe', '.dll') -or $_.Name -eq 'Read Me.txt'
    })
    Assert-True -Condition ($forbidden.Count -eq 0) `
        -Label 'overlay contains only assets and its generated manifest'

    $snapshot = Get-ChildItem -LiteralPath (Join-Path $overlayRoot 'snapshots') -Directory |
        Select-Object -First 1
    Assert-True -Condition ($null -ne $snapshot) `
        -Label 'selection replacement snapshots the prior isolated overlay'
    $rollback = & $scriptPath -Action Rollback -SnapshotId $snapshot.Name `
        -SevenZipPath $sevenZipPath -SourcesLockPath $sourcesPath `
        -RuntimeRoot $runtimeRoot -Confirm:$false
    $postRollback = & $scriptPath -Action Verify -SevenZipPath $sevenZipPath `
        -SourcesLockPath $sourcesPath -RuntimeRoot $runtimeRoot
    Assert-True -Condition ($rollback.Changed -and
        $postRollback.Selection -ceq 'Characters' -and $postRollback.AssetFiles -eq 1) `
        -Label 'explicit snapshot rollback restores the exact prior selection'

    $wrongHash = Join-Path $fixtureRoot 'wrong-hash.zip'
    Copy-Item -LiteralPath $fixture.Outer -Destination $wrongHash
    [System.IO.File]::AppendAllText($wrongHash, 'changed')
    Assert-Throws {
        & $scriptPath -Action Install -Pack All -ArchivePath $wrongHash `
            -SevenZipPath $sevenZipPath -SourcesLockPath $sourcesPath `
            -RuntimeRoot $runtimeRoot -Confirm:$false | Out-Null
    } 'outer archive SHA-256 mismatch fails closed'

    $malicious = New-ValidFixture -Name 'executable'
    $maliciousRoot = Split-Path -Parent $malicious.Outer
    Remove-Item -LiteralPath (Join-Path $maliciousRoot 'monster.rar') -Force
    New-TestZip -Path (Join-Path $maliciousRoot 'monster.rar') -Entries @(
        @{ Path = 'payload.exe'; Content = 'not executable' })
    Remove-Item -LiteralPath $malicious.Outer -Force
    New-OuterArchive -Path $malicious.Outer `
        -MonsterArchive (Join-Path $maliciousRoot 'monster.rar') `
        -ObjectArchive (Join-Path $maliciousRoot 'object.rar') `
        -CharacterArchive (Join-Path $maliciousRoot 'character.rar') `
        -MapArchive (Join-Path $maliciousRoot 'map.rar')
    $monsterDeclaration = @($malicious.Declarations | Where-Object id -eq 'monster')[0]
    $stats = Get-ZipEntryStats -Path (Join-Path $maliciousRoot 'monster.rar')
    $monsterDeclaration.entryCount = $stats.Count
    $monsterDeclaration.expandedBytes = $stats.Bytes
    $monsterDeclaration.maximumEntryBytes = $stats.MaximumBytes
    Write-TestSourcesLock -OuterArchive $malicious.Outer `
        -PackDeclarations $malicious.Declarations
    Assert-Throws {
        & $scriptPath -Action Install -Pack Monsters -ArchivePath $malicious.Outer `
            -SevenZipPath $sevenZipPath -SourcesLockPath $sourcesPath `
            -RuntimeRoot $runtimeRoot -Confirm:$false | Out-Null
    } 'inner executable member fails closed even when the outer hash is locked'

    $traversal = New-ValidFixture -Name 'traversal'
    $traversalRoot = Split-Path -Parent $traversal.Outer
    Remove-Item -LiteralPath (Join-Path $traversalRoot 'monster.rar') -Force
    New-TestZip -Path (Join-Path $traversalRoot 'monster.rar') -Entries @(
        @{ Path = '../escape.bml'; Content = 'escape attempt' })
    Remove-Item -LiteralPath $traversal.Outer -Force
    New-OuterArchive -Path $traversal.Outer `
        -MonsterArchive (Join-Path $traversalRoot 'monster.rar') `
        -ObjectArchive (Join-Path $traversalRoot 'object.rar') `
        -CharacterArchive (Join-Path $traversalRoot 'character.rar') `
        -MapArchive (Join-Path $traversalRoot 'map.rar')
    $traversalMonster = @($traversal.Declarations | Where-Object id -eq 'monster')[0]
    $stats = Get-ZipEntryStats -Path (Join-Path $traversalRoot 'monster.rar')
    $traversalMonster.entryCount = $stats.Count
    $traversalMonster.expandedBytes = $stats.Bytes
    $traversalMonster.maximumEntryBytes = $stats.MaximumBytes
    Write-TestSourcesLock -OuterArchive $traversal.Outer `
        -PackDeclarations $traversal.Declarations
    Assert-Throws {
        & $scriptPath -Action Install -Pack Monsters -ArchivePath $traversal.Outer `
            -SevenZipPath $sevenZipPath -SourcesLockPath $sourcesPath `
            -RuntimeRoot $runtimeRoot -Confirm:$false | Out-Null
    } 'inner path traversal fails closed before extraction'

    $extra = New-ValidFixture -Name 'extra-entry'
    $extraMonster = @($extra.Declarations | Where-Object id -eq 'monster')[0]
    $extraMonster.entryCount = [int]$extraMonster.entryCount - 1
    Write-TestSourcesLock -OuterArchive $extra.Outer `
        -PackDeclarations $extra.Declarations `
        -AllowedCollisions @('data/shared.bml')
    Assert-Throws {
        & $scriptPath -Action Install -Pack Monsters -ArchivePath $extra.Outer `
            -SevenZipPath $sevenZipPath -SourcesLockPath $sourcesPath `
            -RuntimeRoot $runtimeRoot -Confirm:$false | Out-Null
    } 'extra inner asset fails closed against the locked entry count'

    [pscustomobject]@{ Suite = 'AshenbubsHDOverlay'; Passed = $passed; Failed = 0 }
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
