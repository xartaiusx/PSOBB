[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$BuildPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedBuildSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$canonicalBuildPath = Join-Path $repositoryRoot 'config\twills-fonewearl-build.json'
if ([string]::IsNullOrWhiteSpace($BuildPath)) {
    $BuildPath = $canonicalBuildPath
}
$resolvedBuildPath = [System.IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $BuildPath).Path)
if (-not $resolvedBuildPath.Equals(
        [System.IO.Path]::GetFullPath($canonicalBuildPath),
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Only the canonical Twills FOnewearl contract may verify a bank: $canonicalBuildPath"
}
$buildItem = Get-Item -LiteralPath $resolvedBuildPath -Force
if (($buildItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $buildItem.Length -le 0 -or $buildItem.Length -gt 128KB) {
    throw 'The Twills FOnewearl build contract has an invalid size or filesystem type'
}
$buildBytes = [System.IO.File]::ReadAllBytes($resolvedBuildPath)
$buildHash = ([Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($buildBytes))).ToLowerInvariant()
if ($buildHash -cne $ExpectedBuildSha256.ToLowerInvariant()) {
    throw 'The Twills FOnewearl build contract does not match its explicit SHA-256 pin'
}
try {
    $build = [System.Text.Encoding]::UTF8.GetString($buildBytes) |
        ConvertFrom-Json -Depth 30
} catch {
    throw 'The Twills FOnewearl build contract is not valid JSON'
}
if ([int]$build.schemaVersion -ne 2 -or
    [string]$build.character.name -cne 'Twills' -or
    [int]$build.character.classId -ne 8 -or
    [string]$build.character.className -cne 'FOnewearl' -or
    [int]$build.character.slotIndex -ne 0) {
    throw 'The bank verifier is restricted to the slot-0 Twills FOnewearl contract'
}

$resolvedPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
$bankItem = Get-Item -LiteralPath $resolvedPath -Force
if ($bankItem.Name -cnotmatch '^player_.+_0\.psobank$' -or
    $bankItem.PSIsContainer -or
    ($bankItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $bankItem.Length -lt 8 -or $bankItem.Length -gt (8 + (200 * 0x18))) {
    throw 'Bank verification is restricted to one ordinary slot-0 PSOBANK file'
}
$bytes = [System.IO.File]::ReadAllBytes($resolvedPath)

function Read-UInt16LE {
    param([byte[]]$Data, [int]$Offset)

    [uint16]([uint16]$Data[$Offset] -bor
        ([uint16]$Data[$Offset + 1] -shl 8))
}

function Read-UInt32LE {
    param([byte[]]$Data, [int]$Offset)

    [uint32](
        [uint32]$Data[$Offset] -bor
        ([uint32]$Data[$Offset + 1] -shl 8) -bor
        ([uint32]$Data[$Offset + 2] -shl 16) -bor
        ([uint32]$Data[$Offset + 3] -shl 24))
}

function Get-Hex {
    param([byte[]]$Data, [int]$Offset, [int]$Count)

    -join @($Data[$Offset..($Offset + $Count - 1)] | ForEach-Object {
            $_.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
        })
}

$count = Read-UInt32LE -Data $bytes -Offset 0
$meseta = Read-UInt32LE -Data $bytes -Offset 4
if ($count -gt 200 -or $bytes.Length -ne (8 + ([int]$count * 0x18))) {
    throw 'The slot-0 PSOBANK count and exact serialized length are inconsistent'
}
if ($meseta -gt 999999) {
    throw 'The slot-0 PSOBANK Meseta value exceeds the BB limit'
}
$expectedItems = @($build.items | Where-Object {
        [string]$_.location -ceq 'Bank'
    } | Sort-Object { [int]$_.slot })
if ($count -ne $expectedItems.Count) {
    throw "The slot-0 PSOBANK item count is not exact: expected $($expectedItems.Count), found $count"
}

$ids = [System.Collections.Generic.HashSet[uint32]]::new()
$items = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $expectedItems.Count; $index++) {
    $offset = 8 + ($index * 0x18)
    $descriptor = (Get-Hex -Data $bytes -Offset $offset -Count 12) +
        (Get-Hex -Data $bytes -Offset ($offset + 16) -Count 4)
    $id = Read-UInt32LE -Data $bytes -Offset ($offset + 12)
    $amount = Read-UInt16LE -Data $bytes -Offset ($offset + 20)
    $present = Read-UInt16LE -Data $bytes -Offset ($offset + 22)
    $expected = $expectedItems[$index]
    if ([int]$expected.slot -ne ($index + 1) -or
        [string]$expected.equippedSlot -cne 'None' -or
        $descriptor -cne [string]$expected.descriptorHex -or
        $amount -ne 1 -or $present -ne 1 -or
        $id -eq 0 -or $id -eq [uint32]::MaxValue -or -not $ids.Add($id)) {
        throw "The slot-0 PSOBANK item at position $($index + 1) is not exact"
    }
    $items.Add([pscustomobject]@{
            Slot = $index + 1
            Name = [string]$expected.name
            DescriptorHex = $descriptor
            ItemId = $id
            Amount = $amount
            Present = $present
        })
}

$buildHashAfter = (Get-FileHash -LiteralPath $resolvedBuildPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
$bankHashAfter = (Get-FileHash -LiteralPath $resolvedPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ($buildHashAfter -cne $buildHash -or
    $bankHashAfter -cne ([Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()) {
    throw 'The bank or pinned build changed during verification'
}

[pscustomobject]@{
    Valid = $true
    Character = 'Twills'
    Class = 'FOnewearl'
    SlotIndex = 0
    Path = $resolvedPath
    Sha256 = $bankHashAfter
    BuildSha256 = $buildHashAfter
    Count = [int]$count
    Meseta = [uint32]$meseta
    UniqueItemIds = $ids.Count
    Items = @($items)
}
