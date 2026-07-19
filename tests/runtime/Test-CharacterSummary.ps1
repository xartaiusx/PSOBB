[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$summaryScript = Join-Path $repositoryRoot 'scripts\Get-PSOBBCharacterSummary.ps1'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Detail
    )
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Set-UInt16LE {
    param([byte[]]$Data, [int]$Offset, [uint16]$Value)

    $Data[$Offset] = [byte]($Value -band 0xFF)
    $Data[$Offset + 1] = [byte](($Value -shr 8) -band 0xFF)
}

function Set-UInt32LE {
    param([byte[]]$Data, [int]$Offset, [uint32]$Value)

    for ($index = 0; $index -lt 4; $index++) {
        $Data[$Offset + $index] = [byte](($Value -shr ($index * 8)) -band 0xFF)
    }
}

function Set-Utf16LE {
    param([byte[]]$Data, [int]$Offset, [int]$ByteCount, [string]$Value)

    $encoded = [System.Text.Encoding]::Unicode.GetBytes($Value)
    if ($encoded.Length -gt $ByteCount) {
        throw "Fixture text is too long for $ByteCount bytes"
    }
    [System.Array]::Copy($encoded, 0, $Data, $Offset, $encoded.Length)
}

function Set-ItemData {
    param(
        [byte[]]$Data,
        [int]$Offset,
        [byte[]]$Data1,
        [uint32]$Id,
        [byte[]]$Data2
    )

    if ($Data1.Length -ne 12 -or $Data2.Length -ne 4) {
        throw 'Item data fixtures require 12 data1 bytes and 4 data2 bytes'
    }
    [System.Array]::Copy($Data1, 0, $Data, $Offset, 12)
    Set-UInt32LE -Data $Data -Offset ($Offset + 12) -Value $Id
    [System.Array]::Copy($Data2, 0, $Data, ($Offset + 16), 4)
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('PSOBB-CharacterSummaryTests-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $fixturePath = Join-Path $temporaryRoot 'player_fixture_1.psochar'
    $bytes = [byte[]]::new(0x399C)
    $header = [byte[]](0x9C, 0x39, 0xE7, 0, 0, 0, 0, 0)
    [System.Array]::Copy($header, $bytes, $header.Length)

    $bytes[0x08] = 5
    $bytes[0x09] = 250
    $bytes[0x0A] = 248
    $bytes[0x3A8] = 2
    $bytes[0x3A9] = 8
    $bytes[0x3AA] = 5
    $bytes[0x3AB] = 3
    Set-UInt32LE -Data $bytes -Offset 0x3AC -Value 0x8A
    Set-Utf16LE -Data $bytes -Offset 0x3C8 -ByteCount 0x20 -Value "`tETwills"
    Set-UInt32LE -Data $bytes -Offset 0x4E4 -Value 0x11223344
    Set-UInt32LE -Data $bytes -Offset 0x4EC `
        -Value ([Convert]::ToUInt32('C87ED5B1', 16))
    Set-UInt32LE -Data $bytes -Offset 0x36C -Value 199
    Set-UInt32LE -Data $bytes -Offset 0x370 -Value 83227800
    Set-UInt32LE -Data $bytes -Offset 0x374 -Value 999999

    $statValues = [uint16[]](1234, 1456, 678, 1500, 456, 180, 100)
    for ($index = 0; $index -lt $statValues.Count; $index++) {
        Set-UInt16LE -Data $bytes -Offset (0x354 + ($index * 2)) -Value $statValues[$index]
    }

    $bytes[0x0EF] = 1
    $bytes[0x10B] = 140
    $bytes[0x127] = 2
    $bytes[0x143] = 3
    $bytes[0x15F] = 4

    for ($index = 0; $index -lt 19; $index++) {
        $bytes[0x4D0 + $index] = 0xFF
    }
    $bytes[0x4D0] = 0x0E
    $bytes[0x0E] = 0x0F
    $bytes[0x4D0 + 14] = 0
    $bytes[0x0E + (14 * 0x1C)] = 0
    $bytes[0x4D0 + 16] = 6
    $bytes[0x0E + (16 * 0x1C)] = 0
    $bytes[0x0E + (18 * 0x1C)] = 9

    $weaponOffset = 0x0C
    $bytes[$weaponOffset] = 1
    Set-UInt32LE -Data $bytes -Offset ($weaponOffset + 4) -Value 8
    Set-ItemData -Data $bytes -Offset ($weaponOffset + 8) `
        -Data1 ([byte[]](0x00, 0x33, 0x01, 0x04, 0, 0, 0, 0, 0, 0, 0, 0)) `
        -Id ([System.Convert]::ToUInt32('AABBCCDD', 16)) `
        -Data2 ([byte[]](0x11, 0x22, 0x33, 0x44))

    $magOffset = 0x0C + 0x1C
    $bytes[$magOffset] = 1
    Set-ItemData -Data $bytes -Offset ($magOffset + 8) `
        -Data1 ([byte[]](0x02, 0x41, 0xC8, 0xD9, 0xF4, 0x01, 0x60, 0x22, 0xD4, 0x17, 0xF8, 0x11)) `
        -Id 0x01020304 -Data2 ([byte[]](0x78, 0xC8, 0x07, 0x04))

    $techDiskOffset = 0x0C + (2 * 0x1C)
    $bytes[$techDiskOffset] = 1
    Set-ItemData -Data $bytes -Offset ($techDiskOffset + 8) `
        -Data1 ([byte[]](0x03, 0x02, 0x1D, 0, 0x12, 0, 0, 0, 0, 0, 0, 0)) `
        -Id 0x05060708 -Data2 ([byte[]](0, 0, 0, 0))

    $sRankOffset = 0x0C + (3 * 0x1C)
    $bytes[$sRankOffset] = 1
    Set-ItemData -Data $bytes -Offset ($sRankOffset + 8) `
        -Data1 ([byte[]](0x00, 0x70, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0)) `
        -Id 0x090A0B0C -Data2 ([byte[]](0, 0, 0, 0))

    $unitOffset = 0x0C + (4 * 0x1C)
    $bytes[$unitOffset] = 1
    Set-UInt32LE -Data $bytes -Offset ($unitOffset + 4) -Value 8
    Set-ItemData -Data $bytes -Offset ($unitOffset + 8) `
        -Data1 ([byte[]](0x01, 0x03, 0x4C, 0, 0x02, 0, 0, 0, 0, 0, 0, 0)) `
        -Id 0x0A0B0C0D -Data2 ([byte[]](0, 0, 0, 0))

    Set-UInt32LE -Data $bytes -Offset 0x700 -Value 1
    Set-UInt32LE -Data $bytes -Offset 0x704 -Value 54321
    Set-ItemData -Data $bytes -Offset 0x708 `
        -Data1 ([byte[]](0x04, 0xAB, 0xCD, 0, 0, 0, 0, 0, 0, 0, 0, 0)) `
        -Id 0x0D0E0F10 -Data2 ([byte[]](0x39, 0x30, 0, 0))
    Set-UInt16LE -Data $bytes -Offset 0x71C -Value 12345
    Set-UInt16LE -Data $bytes -Offset 0x71E -Value 1

    Set-Utf16LE -Data $bytes -Offset 0x19CC -ByteCount 0x30 -Value "`tETwills"
    $bytes[0x1ACC] = 1
    $bytes[0x1ACE] = 2
    $bytes[0x1ACF] = 8

    [System.IO.File]::WriteAllBytes($fixturePath, $bytes)
    $hashBefore = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $summary = & $summaryScript -Path $fixturePath
    $hashAfter = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()

    Add-Result 'valid fixture identity and validation fields parse exactly' (
        $summary.Length -eq 0x399C -and
        $summary.Header -ceq '9C39E70000000000' -and
        $summary.Name -ceq 'Twills' -and
        $summary.ClassId -eq 8 -and $summary.ClassName -ceq 'FOnewearl' -and
        $summary.SectionId -eq 2 -and $summary.SectionName -ceq 'Skyly' -and
        $summary.VisualValidationFlags -eq 5 -and
        $summary.CharacterValidationFlags -eq 0x11223344) `
        'header, marked UTF-16 name, class, section, and validation flags'

    Add-Result 'visual signature and Guild Card identity parse exactly' (
        $summary.VisualVersion -eq 3 -and
        $summary.VisualClassFlags -eq 0x8A -and
        $summary.SignatureHex -ceq 'C87ED5B1' -and
        $summary.GuildCard.Name -ceq 'Twills' -and
        $summary.GuildCard.Present -eq 1 -and
        $summary.GuildCard.SectionId -eq 2 -and
        $summary.GuildCard.ClassId -eq 8) `
        'redundant slot-0 FOnewearl identity and structural signature'

    Add-Result 'level, experience, meseta, and stats parse exactly' (
        $summary.StoredLevel -eq 199 -and $summary.DisplayedLevel -eq 200 -and
        $summary.Experience -eq 83227800 -and $summary.Meseta -eq 999999 -and
        $summary.Stats.ATP -eq 1234 -and $summary.Stats.MST -eq 1456 -and
        $summary.Stats.EVP -eq 678 -and $summary.Stats.HP -eq 1500 -and
        $summary.Stats.DFP -eq 456 -and $summary.Stats.ATA -eq 180 -and
        $summary.Stats.LCK -eq 100) 'stored/displayed levels and seven character stats'

    Add-Result 'all material counters use the pinned BB offsets' (
        $summary.Materials.Power -eq 1 -and $summary.Materials.Mind -eq 140 -and
        $summary.Materials.Evade -eq 2 -and $summary.Materials.Def -eq 3 -and
        $summary.Materials.Luck -eq 4 -and $summary.Materials.HP -eq 125 -and
        $summary.Materials.TP -eq 124) 'five extension counters plus encoded HP and TP usage'

    $foie = $summary.Techniques | Where-Object Id -eq 0
    $ryuker = $summary.Techniques | Where-Object Id -eq 14
    $anti = $summary.Techniques | Where-Object Id -eq 16
    $megid = $summary.Techniques | Where-Object Id -eq 18
    Add-Result 'technique base and extension levels parse exactly' (
        $summary.Techniques.Count -eq 19 -and
        $foie.StoredLevel -eq 29 -and $foie.DisplayedLevel -eq 30 -and
        $ryuker.StoredLevel -eq 0 -and $ryuker.DisplayedLevel -eq 1 -and
        $anti.StoredLevel -eq 6 -and $anti.DisplayedLevel -eq 7 -and
        $null -eq $megid.StoredLevel -and $null -eq $megid.DisplayedLevel) `
        'Lv30 extension, special-tech levels, and unlearned sentinel'

    Add-Result 'inventory primary identifiers match newserv semantics' (
        $summary.InventoryCount -eq 5 -and $summary.InventoryItems.Count -eq 5 -and
        $summary.InventoryItems[0].Present -eq 1 -and
        $summary.InventoryItems[0].UnknownA1 -eq 0 -and
        $summary.InventoryItems[0].Flags -eq 8 -and
        $summary.InventoryItems[0].PrimaryId -ceq '00330100' -and
        $summary.InventoryItems[0].Equipped -and
        $summary.InventoryItems[0].EquippedSlot -ceq 'Weapon' -and
        $summary.InventoryItems[0].CanonicalDescriptorHex -ceq
            $summary.InventoryItems[0].DescriptorHex -and
        $summary.InventoryItems[1].PrimaryId -ceq '02410000' -and
        $summary.InventoryItems[1].DescriptorHex -ceq '0241C8D9F4016022D417F81178C80704' -and
        $summary.InventoryItems[2].PrimaryId -ceq '0302121D' -and
        $summary.InventoryItems[3].PrimaryId -ceq '00700000') `
        'ordinary weapon, canonical Mag, technique disk, and S-rank weapon'

    Add-Result 'unit runtime slot is separated from its canonical descriptor' (
        $summary.InventoryItems[4].PrimaryId -ceq '01034C00' -and
        $summary.InventoryItems[4].DescriptorHex -ceq '01034C00020000000000000000000000' -and
        $summary.InventoryItems[4].CanonicalDescriptorHex -ceq '01034C00000000000000000000000000' -and
        $summary.InventoryItems[4].Equipped -and
        $summary.InventoryItems[4].EquippedSlot -ceq 'Unit3' -and
        $summary.InventoryItems[4].UnitSlotIndex -eq 2) `
        'flags, equipped slot, and canonical unit bytes remain distinct'

    Add-Result 'bank count, presence, amount, and Meseta identifier parse exactly' (
        $summary.BankCount -eq 1 -and $summary.BankItems.Count -eq 1 -and
        $summary.BankItems[0].Present -eq 1 -and
        $summary.BankItems[0].Amount -eq 12345 -and
        $summary.BankItems[0].PrimaryId -ceq '04000000') `
        'first bank entry follows PlayerBank200 layout'

    Add-Result 'summary is read-only and hashes the parsed bytes' (
        $hashBefore -ceq $hashAfter -and $summary.Sha256 -ceq $hashBefore) `
        $hashAfter

    $cMarkerPath = Join-Path $temporaryRoot 'player_c_marker.psochar'
    $cMarkerBytes = [byte[]]$bytes.Clone()
    [System.Array]::Clear($cMarkerBytes, 0x3C8, 0x20)
    Set-Utf16LE -Data $cMarkerBytes -Offset 0x3C8 -ByteCount 0x20 -Value "`tCTwills"
    [System.IO.File]::WriteAllBytes($cMarkerPath, $cMarkerBytes)
    $cMarkerSummary = & $summaryScript -Path $cMarkerPath
    Add-Result 'literal C marker is preserved like UTF16_ALWAYS_MARKED' (
        $cMarkerSummary.Name -ceq "`tCTwills") 'upstream only strips tab markers whose second character is not C'

    $badInventoryPath = Join-Path $temporaryRoot 'bad_inventory.psochar'
    $badInventoryBytes = [byte[]]$bytes.Clone()
    $badInventoryBytes[0x08] = 31
    [System.IO.File]::WriteAllBytes($badInventoryPath, $badInventoryBytes)
    $badInventoryRejected = $false
    try {
        & $summaryScript -Path $badInventoryPath | Out-Null
    } catch {
        $badInventoryRejected = $_.Exception.Message -match 'Inventory item count is invalid: 31'
    }
    Add-Result 'inventory counts above 30 fail closed' $badInventoryRejected `
        'invalid active-slot range is rejected'

    $badBankPath = Join-Path $temporaryRoot 'bad_bank.psochar'
    $badBankBytes = [byte[]]$bytes.Clone()
    Set-UInt32LE -Data $badBankBytes -Offset 0x700 -Value 201
    [System.IO.File]::WriteAllBytes($badBankPath, $badBankBytes)
    $badBankRejected = $false
    try {
        & $summaryScript -Path $badBankPath | Out-Null
    } catch {
        $badBankRejected = $_.Exception.Message -match 'Bank item count is invalid: 201'
    }
    Add-Result 'bank counts above 200 fail closed' $badBankRejected `
        'invalid active-bank range is rejected'

    $badHeaderPath = Join-Path $temporaryRoot 'bad_header.psochar'
    $badHeaderBytes = [byte[]]$bytes.Clone()
    $badHeaderBytes[2] = 0
    [System.IO.File]::WriteAllBytes($badHeaderPath, $badHeaderBytes)
    $badHeaderRejected = $false
    try {
        & $summaryScript -Path $badHeaderPath | Out-Null
    } catch {
        $badHeaderRejected = $_.Exception.Message -match 'PSOCHAR header is invalid'
    }
    Add-Result 'invalid PSOCHAR headers fail closed' $badHeaderRejected `
        'size, command, and flag header must match newserv'

    $badLengthPath = Join-Path $temporaryRoot 'bad_length.psochar'
    [System.IO.File]::WriteAllBytes($badLengthPath, [byte[]]::new(0x399B))
    $badLengthRejected = $false
    try {
        & $summaryScript -Path $badLengthPath | Out-Null
    } catch {
        $badLengthRejected = $_.Exception.Message -match 'PSOCHAR length is invalid'
    }
    Add-Result 'invalid PSOCHAR lengths fail closed' $badLengthRejected `
        'the full file must be exactly 0x399C bytes'

    $oversizedPath = Join-Path $temporaryRoot 'oversized.psochar'
    [System.IO.File]::WriteAllBytes($oversizedPath, [byte[]]::new(0x399D))
    $oversizedRejected = $false
    try {
        & $summaryScript -Path $oversizedPath | Out-Null
    } catch {
        $oversizedRejected = $_.Exception.Message -match 'PSOCHAR length is invalid'
    }
    Add-Result 'oversized PSOCHAR files fail before parsing' $oversizedRejected `
        'the reader validates the bounded file length before allocating its parse buffer'

    $reparseTargetPath = Join-Path $temporaryRoot 'reparse-target.psochar'
    $reparsePath = Join-Path $temporaryRoot 'reparse-input.psochar'
    [System.IO.File]::WriteAllBytes($reparseTargetPath, $bytes)
    New-Item -ItemType SymbolicLink -Path $reparsePath -Target $reparseTargetPath `
        -ErrorAction Stop | Out-Null
    $reparseRejected = $false
    try {
        & $summaryScript -Path $reparsePath | Out-Null
    } catch {
        $reparseRejected = $_.Exception.Message -match 'ordinary non-reparse file'
    }
    Add-Result 'reparse PSOCHAR inputs fail before content reads' $reparseRejected `
        'standalone verification accepts only an ordinary file'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) character-summary test(s) failed"
}
[pscustomobject]@{
    Suite = 'CharacterSummary'
    Passed = $results.Count
    Failed = 0
}
