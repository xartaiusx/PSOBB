[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Parent $PSScriptRoot) '..\scripts\PSOBB.Common.ps1')

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('psobb-archive-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

function New-TestArchive {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Target,
        [switch]$IncludeTarget,
        [switch]$TargetIsLink
    )

    Add-Type -AssemblyName System.IO.Compression
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    $archive = [System.IO.Compression.ZipArchive]::new(
        $stream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false)
    try {
        if ($IncludeTarget) {
            $file = $archive.CreateEntry('root/files/target.txt')
            $writer = [System.IO.StreamWriter]::new($file.Open())
            try { $writer.Write('target') } finally { $writer.Dispose() }
        }
        $link = $archive.CreateEntry('root/links/link.txt')
        $link.ExternalAttributes = [int]0xA1FF0000
        $writer = [System.IO.StreamWriter]::new(
            $link.Open(),
            [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($Target) } finally { $writer.Dispose() }
        if ($TargetIsLink) {
            $second = $archive.CreateEntry('root/files/target.txt')
            $second.ExternalAttributes = [int]0xA1FF0000
            $writer = [System.IO.StreamWriter]::new(
                $second.Open(),
                [System.Text.UTF8Encoding]::new($false))
            try { $writer.Write('real.txt') } finally { $writer.Dispose() }
            $real = $archive.CreateEntry('root/files/real.txt')
            $writer = [System.IO.StreamWriter]::new($real.Open())
            try { $writer.Write('real') } finally { $writer.Dispose() }
        }
    } finally {
        $archive.Dispose()
    }
}

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][string]$Label)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    if (-not $threw) { throw "Expected rejection: $Label" }
}

try {
    $safe = Join-Path $temporaryRoot 'safe.zip'
    New-TestArchive -Path $safe -Target '../files/target.txt' -IncludeTarget
    Assert-Throws { Assert-PSOBBZipArchiveSafe -Path $safe | Out-Null } 'default extraction policy rejects symlinks'
    $result = Assert-PSOBBZipArchiveSafe -Path $safe -AllowReviewedSourceSymlinks
    if ($result.ReviewedSourceSymlinks -ne 1) { throw 'Reviewed source symlink count was not exact' }

    $dangling = Join-Path $temporaryRoot 'dangling.zip'
    New-TestArchive -Path $dangling -Target '../files/missing.txt'
    Assert-Throws { Assert-PSOBBZipArchiveSafe -Path $dangling -AllowReviewedSourceSymlinks | Out-Null } 'dangling source symlink'

    $escape = Join-Path $temporaryRoot 'escape.zip'
    New-TestArchive -Path $escape -Target '../../../outside.txt'
    Assert-Throws { Assert-PSOBBZipArchiveSafe -Path $escape -AllowReviewedSourceSymlinks | Out-Null } 'root-escaping source symlink'

    $chain = Join-Path $temporaryRoot 'chain.zip'
    New-TestArchive -Path $chain -Target '../files/target.txt' -TargetIsLink
    Assert-Throws { Assert-PSOBBZipArchiveSafe -Path $chain -AllowReviewedSourceSymlinks | Out-Null } 'source symlink chain'

    [pscustomobject]@{ Passed = 5; Failed = 0 }
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
