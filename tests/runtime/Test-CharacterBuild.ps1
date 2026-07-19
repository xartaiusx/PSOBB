[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$verifierScript = Join-Path $repositoryRoot 'scripts\Test-PSOBBCharacterBuild.ps1'
$buildPath = Join-Path $repositoryRoot 'config\twills-fonewearl-build.json'
$build = Get-Content -Raw -LiteralPath $buildPath | ConvertFrom-Json -Depth 30
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Detail
    )

    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Set-UInt32LE {
    param([byte[]]$Data, [int]$Offset, [uint32]$Value)

    for ($index = 0; $index -lt 4; $index++) {
        $Data[$Offset + $index] = [byte](($Value -shr ($index * 8)) -band 0xFF)
    }
}

function Set-UInt16LE {
    param([byte[]]$Data, [int]$Offset, [uint16]$Value)

    for ($index = 0; $index -lt 2; $index++) {
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

function Swap-ByteRanges {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$LeftOffset,
        [Parameter(Mandatory)][int]$RightOffset,
        [Parameter(Mandatory)][int]$Count
    )

    $temporary = [byte[]]::new($Count)
    [System.Array]::Copy($Data, $LeftOffset, $temporary, 0, $Count)
    [System.Array]::Copy($Data, $RightOffset, $Data, $LeftOffset, $Count)
    [System.Array]::Copy($temporary, 0, $Data, $RightOffset, $Count)
}

function Convert-HexToBytes {
    param([Parameter(Mandatory)][string]$Hex)

    if ($Hex -cnotmatch '^(?:[0-9A-F]{2})+$') {
        throw "Fixture descriptor is not uppercase hexadecimal: $Hex"
    }
    $value = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $value.Length; $index++) {
        $value[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $value
}

function Write-ContractVariant {
    param(
        [Parameter(Mandatory)]$Contract,
        [Parameter(Mandatory)][string]$Path
    )

    $Contract | ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath $Path -Encoding utf8
}

function Read-ContractCopy {
    return Get-Content -Raw -LiteralPath $buildPath | ConvertFrom-Json -Depth 30
}

function Invoke-RejectionCheck {
    param(
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)][string]$ContractPath,
        [Parameter(Mandatory)][string]$Pattern
    )

    try {
        & $verifierScript -Path $CharacterPath -BuildPath $ContractPath *> $null
        return $false
    } catch {
        return $_.Exception.Message -match $Pattern
    }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('PSOBB-CharacterBuildTests-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $fixturePath = Join-Path $temporaryRoot 'player_twills_0.psochar'
    $bytes = [byte[]]::new(0x399C)
    [System.Array]::Copy(
        [byte[]](0x9C, 0x39, 0xE7, 0, 0, 0, 0, 0), $bytes, 8)

    $inventoryItems = @($build.items | Where-Object { $_.location -ceq 'Inventory' })
    $bankItems = @($build.items | Where-Object { $_.location -ceq 'Bank' })
    $bytes[0x08] = [byte]$inventoryItems.Count
    $bytes[0x09] = [byte]([int]$build.materials.HP * 2)
    $bytes[0x0A] = [byte]([int]$build.materials.TP * 2)
    $bytes[0x0EF] = [byte]$build.materials.Power
    $bytes[0x10B] = [byte]$build.materials.Mind
    $bytes[0x127] = [byte]$build.materials.Evade
    $bytes[0x143] = [byte]$build.materials.Def
    $bytes[0x15F] = [byte]$build.materials.Luck
    foreach ($entry in @(
            @{ Name = 'ATP'; Offset = 0x354 },
            @{ Name = 'MST'; Offset = 0x356 },
            @{ Name = 'EVP'; Offset = 0x358 },
            @{ Name = 'HP'; Offset = 0x35A },
            @{ Name = 'DFP'; Offset = 0x35C },
            @{ Name = 'ATA'; Offset = 0x35E },
            @{ Name = 'LCK'; Offset = 0x360 })) {
        Set-UInt16LE -Data $bytes -Offset $entry.Offset `
            -Value ([uint16]$build.stats.($entry.Name))
    }
    Set-UInt32LE -Data $bytes -Offset 0x36C -Value ([uint32]$build.character.storedLevel)
    Set-UInt32LE -Data $bytes -Offset 0x370 -Value ([uint32]$build.character.experience)
    Set-UInt32LE -Data $bytes -Offset 0x374 -Value ([uint32]$build.character.meseta)
    $bytes[0x3A8] = [byte]$build.character.sectionId
    $bytes[0x3A9] = [byte]$build.character.classId
    $bytes[0x3AA] = [byte]$build.integrity.visualValidationFlags
    $bytes[0x3AB] = [byte]$build.integrity.visualVersion
    Set-UInt32LE -Data $bytes -Offset 0x3AC -Value ([uint32]$build.integrity.visualClassFlags)
    Set-Utf16LE -Data $bytes -Offset 0x3C8 -ByteCount 0x20 `
        -Value ("`tE" + [string]$build.character.name)
    Set-UInt32LE -Data $bytes -Offset 0x4E4 `
        -Value ([uint32]$build.integrity.characterValidationFlags)
    Set-UInt32LE -Data $bytes -Offset 0x4EC `
        -Value ([Convert]::ToUInt32([string]$build.integrity.signatureHex, 16))
    Set-Utf16LE -Data $bytes -Offset 0x19CC -ByteCount 0x30 `
        -Value ("`tE" + [string]$build.integrity.guildCardName)
    $bytes[0x1ACC] = [byte]$build.integrity.guildCardPresent
    $bytes[0x1ACE] = [byte]$build.integrity.guildCardSectionId
    $bytes[0x1ACF] = [byte]$build.integrity.guildCardClassId

    foreach ($technique in @($build.techniques)) {
        $id = [int]$technique.id
        $bytes[0x4D0 + $id] = [byte]([int]$technique.displayedLevel - 1)
        $bytes[0x0E + ($id * 0x1C)] = 0
    }

    $nextItemId = [uint32]1
    foreach ($item in $inventoryItems) {
        $descriptor = Convert-HexToBytes -Hex ([string]$item.descriptorHex)
        if ($descriptor[0] -eq 0x01 -and $descriptor[1] -eq 0x03 -and
            [string]$item.equippedSlot -cmatch '^Unit([1-4])$') {
            $descriptor[4] = [byte]([int]$Matches[1] - 1)
        }
        $itemOffset = 0x0C + (([int]$item.slot - 1) * 0x1C)
        $dataOffset = $itemOffset + 8
        $bytes[$itemOffset] = 1
        $flags = if ([string]$item.equippedSlot -ceq 'None') { 0 } else { 8 }
        Set-UInt32LE -Data $bytes -Offset ($itemOffset + 4) -Value $flags
        [System.Array]::Copy($descriptor, 0, $bytes, $dataOffset, 12)
        Set-UInt32LE -Data $bytes -Offset ($dataOffset + 12) -Value $nextItemId
        [System.Array]::Copy($descriptor, 12, $bytes, ($dataOffset + 16), 4)
        $nextItemId++
    }

    Set-UInt32LE -Data $bytes -Offset 0x700 -Value ([uint32]$bankItems.Count)
    Set-UInt32LE -Data $bytes -Offset 0x704 -Value 999999
    foreach ($item in $bankItems) {
        $descriptor = Convert-HexToBytes -Hex ([string]$item.descriptorHex)
        $itemOffset = 0x708 + (([int]$item.slot - 1) * 0x18)
        [System.Array]::Copy($descriptor, 0, $bytes, $itemOffset, 12)
        Set-UInt32LE -Data $bytes -Offset ($itemOffset + 12) -Value $nextItemId
        [System.Array]::Copy($descriptor, 12, $bytes, ($itemOffset + 16), 4)
        Set-UInt16LE -Data $bytes -Offset ($itemOffset + 0x14) -Value 1
        Set-UInt16LE -Data $bytes -Offset ($itemOffset + 0x16) -Value 1
        $nextItemId++
    }

    [System.IO.File]::WriteAllBytes($fixturePath, $bytes)
    $hashBefore = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $buildHashBefore = (Get-FileHash -LiteralPath $buildPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $verificationOutput = @(& $verifierScript -Path $fixturePath -BuildPath $buildPath)
    $verification = @($verificationOutput | Where-Object {
            $_.PSObject.Properties.Name -contains 'Valid'
        })[-1]
    $hashAfter = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()

    Add-Result 'exact slot-0 Twills FOnewearl build fixture passes' (
        $verification.Valid -and
        $verification.ProfileId -ceq [string]$build.profileId -and
        $verification.ActiveLoadoutId -ceq 'general-dps' -and
        $verification.SlotIndex -eq 0 -and
        $verification.DisplayedLevel -eq 200 -and
        $verification.ExactOwnedItems -eq 57 -and
        $verification.InventoryItems -eq 28 -and
        $verification.BankItems -eq 29 -and
        $verification.ChecksPassed -eq 11 -and
        $verification.BuildPath -ceq (Resolve-Path -LiteralPath $buildPath).Path -and
        $verification.BuildSha256 -ceq $buildHashBefore) `
        'identity, progression, stats, integrity, inventory, bank, equipment, and profiles'
    Add-Result 'successful verification is byte-for-byte read-only' (
        $hashBefore -ceq $hashAfter -and
        $verification.CharacterSha256 -ceq $hashBefore) $hashAfter

    $reorderedBankPath = Join-Path $temporaryRoot 'player_reordered_bank_0.psochar'
    $reorderedBankBytes = [byte[]]$bytes.Clone()
    Swap-ByteRanges -Data $reorderedBankBytes -LeftOffset 0x708 `
        -RightOffset (0x708 + (($bankItems.Count - 1) * 0x18)) -Count 0x18
    [System.IO.File]::WriteAllBytes($reorderedBankPath, $reorderedBankBytes)
    $reorderedBankHashBefore = (Get-FileHash -LiteralPath $reorderedBankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $reorderedBankOutput = @(& $verifierScript -Path $reorderedBankPath `
            -BuildPath $buildPath)
    $reorderedBankVerification = @($reorderedBankOutput | Where-Object {
            $_.PSObject.Properties.Name -contains 'Valid'
        })[-1]
    $reorderedBankHashAfter = (Get-FileHash -LiteralPath $reorderedBankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Result 'complete embedded-bank record reordering is accepted read-only' (
        $reorderedBankVerification.Valid -and
        $reorderedBankVerification.BankItems -eq $bankItems.Count -and
        $reorderedBankHashBefore -ceq $reorderedBankHashAfter -and
        $reorderedBankVerification.CharacterSha256 -ceq $reorderedBankHashBefore) `
        'bank identity is the exact descriptor multiset, not serialized position'

    $reorderedInventoryPath = Join-Path $temporaryRoot `
        'player_reordered_inventory_0.psochar'
    $reorderedInventoryBytes = [byte[]]$bytes.Clone()
    Swap-ByteRanges -Data $reorderedInventoryBytes -LeftOffset 0x0C `
        -RightOffset (0x0C + (($inventoryItems.Count - 1) * 0x1C)) -Count 0x1C
    [System.IO.File]::WriteAllBytes($reorderedInventoryPath, $reorderedInventoryBytes)
    Add-Result 'inventory record reordering remains rejected' (
        Invoke-RejectionCheck -CharacterPath $reorderedInventoryPath `
            -ContractPath $buildPath -Pattern 'character-build verification check') `
        'inventory slots and equipped state remain position-bound'

    $defaultOutput = @(& $verifierScript -Path $fixturePath)
    $defaultVerification = @($defaultOutput | Where-Object {
            $_.PSObject.Properties.Name -contains 'Valid'
        })[-1]
    Add-Result 'default contract resolves to the FOnewearl schema v2 file' (
        $defaultVerification.Valid -and
        $defaultVerification.BuildPath -ceq (Resolve-Path -LiteralPath $buildPath).Path) `
        $defaultVerification.BuildPath

    foreach ($entry in @(
            @{ Name = 'ATP'; Offset = 0x354 },
            @{ Name = 'MST'; Offset = 0x356 },
            @{ Name = 'EVP'; Offset = 0x358 },
            @{ Name = 'HP'; Offset = 0x35A },
            @{ Name = 'DFP'; Offset = 0x35C },
            @{ Name = 'ATA'; Offset = 0x35E },
            @{ Name = 'LCK'; Offset = 0x360 })) {
        $driftPath = Join-Path $temporaryRoot ("player_wrong_stat_$($entry.Name)_0.psochar")
        $driftBytes = [byte[]]$bytes.Clone()
        $driftBytes[$entry.Offset] = $driftBytes[$entry.Offset] -bxor 1
        [System.IO.File]::WriteAllBytes($driftPath, $driftBytes)
        Add-Result "$($entry.Name) stat drift fails closed" (
            Invoke-RejectionCheck -CharacterPath $driftPath -ContractPath $buildPath `
                -Pattern 'character-build verification check') `
            'every saved stat is contract-bound'
    }

    foreach ($entry in @(
            @{ Name = 'visual validation flags'; Offset = 0x3AA },
            @{ Name = 'visual version'; Offset = 0x3AB },
            @{ Name = 'visual class flags'; Offset = 0x3AC },
            @{ Name = 'character validation flags'; Offset = 0x4E4 },
            @{ Name = 'character signature'; Offset = 0x4EC },
            @{ Name = 'Guild Card name'; Offset = 0x19D0 },
            @{ Name = 'Guild Card present flag'; Offset = 0x1ACC },
            @{ Name = 'Guild Card section'; Offset = 0x1ACE },
            @{ Name = 'Guild Card class'; Offset = 0x1ACF },
            @{ Name = 'HP material raw encoding'; Offset = 0x09 },
            @{ Name = 'TP material raw encoding'; Offset = 0x0A })) {
        $safeName = $entry.Name -replace '[^A-Za-z0-9]+', '_'
        $driftPath = Join-Path $temporaryRoot ("player_wrong_integrity_$safeName`_0.psochar")
        $driftBytes = [byte[]]$bytes.Clone()
        $driftBytes[$entry.Offset] = $driftBytes[$entry.Offset] -bxor 1
        [System.IO.File]::WriteAllBytes($driftPath, $driftBytes)
        Add-Result "$($entry.Name) drift fails closed" (
            Invoke-RejectionCheck -CharacterPath $driftPath -ContractPath $buildPath `
                -Pattern 'character-build verification check') `
            'redundant identity and canonical encodings are contract-bound'
    }

    $wrongClassPath = Join-Path $temporaryRoot 'player_wrong_class_0.psochar'
    $wrongClassBytes = [byte[]]$bytes.Clone()
    $wrongClassBytes[0x3A9] = 7
    [System.IO.File]::WriteAllBytes($wrongClassPath, $wrongClassBytes)
    Add-Result 'FOnewm cannot satisfy the FOnewearl contract' (
        Invoke-RejectionCheck -CharacterPath $wrongClassPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'only existing Twills FOnewearl is in scope'

    $wrongSlotPath = Join-Path $temporaryRoot 'player_twills_1.psochar'
    [System.IO.File]::WriteAllBytes($wrongSlotPath, $bytes)
    Add-Result 'nonzero character slot path fails closed' (
        Invoke-RejectionCheck -CharacterPath $wrongSlotPath -ContractPath $buildPath `
            -Pattern 'restricted to existing slot 0') `
        'the verifier cannot be redirected to slot 1'

    $missingItemPath = Join-Path $temporaryRoot 'player_missing_item_0.psochar'
    $missingItemBytes = [byte[]]$bytes.Clone()
    $missingItemBytes[0x0C] = 0
    [System.IO.File]::WriteAllBytes($missingItemPath, $missingItemBytes)
    Add-Result 'absent required item fails closed' (
        Invoke-RejectionCheck -CharacterPath $missingItemPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'present flag is required at every pinned item position'

    $driftedItemPath = Join-Path $temporaryRoot 'player_drifted_item_0.psochar'
    $driftedItemBytes = [byte[]]$bytes.Clone()
    $driftedItemBytes[0x0C + 8 + 16] = $driftedItemBytes[0x0C + 8 + 16] -bxor 1
    [System.IO.File]::WriteAllBytes($driftedItemPath, $driftedItemBytes)
    Add-Result 'descriptor byte drift fails closed' (
        Invoke-RejectionCheck -CharacterPath $driftedItemPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'primary ID alone is insufficient when canonical descriptor bytes differ'

    $flagsPath = Join-Path $temporaryRoot 'player_flags_0.psochar'
    $flagsBytes = [byte[]]$bytes.Clone()
    $flagsItemOffset = 0x0C + ((21 - 1) * 0x1C)
    Set-UInt32LE -Data $flagsBytes -Offset ($flagsItemOffset + 4) -Value 9
    [System.IO.File]::WriteAllBytes($flagsPath, $flagsBytes)
    Add-Result 'inventory flags other than exact zero or eight fail closed' (
        Invoke-RejectionCheck -CharacterPath $flagsPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'unrelated flag bits cannot be hidden behind the equipped mask'

    $unknownA1Path = Join-Path $temporaryRoot 'player_unknown_a1_0.psochar'
    $unknownA1Bytes = [byte[]]$bytes.Clone()
    $unknownA1Bytes[$flagsItemOffset + 1] = 1
    [System.IO.File]::WriteAllBytes($unknownA1Path, $unknownA1Bytes)
    Add-Result 'nonzero inventory UnknownA1 fails closed' (
        Invoke-RejectionCheck -CharacterPath $unknownA1Path -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'inventory extension state is exact'

    $extraEquippedPath = Join-Path $temporaryRoot 'player_extra_equipped_0.psochar'
    $extraEquippedBytes = [byte[]]$bytes.Clone()
    $magicalPieceOffset = 0x0C + ((8 - 1) * 0x1C)
    Set-UInt32LE -Data $extraEquippedBytes -Offset ($magicalPieceOffset + 4) -Value 8
    [System.IO.File]::WriteAllBytes($extraEquippedPath, $extraEquippedBytes)
    Add-Result 'extra equipped item fails closed' (
        Invoke-RejectionCheck -CharacterPath $extraEquippedPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'only the active profile may be equipped'

    $wrongUnitSlotPath = Join-Path $temporaryRoot 'player_wrong_unit_slot_0.psochar'
    $wrongUnitSlotBytes = [byte[]]$bytes.Clone()
    $v801DataOffset = 0x0C + ((3 - 1) * 0x1C) + 8
    $wrongUnitSlotBytes[$v801DataOffset + 4] = 3
    [System.IO.File]::WriteAllBytes($wrongUnitSlotPath, $wrongUnitSlotBytes)
    Add-Result 'wrong unit runtime slot fails closed while descriptor stays canonical' (
        Invoke-RejectionCheck -CharacterPath $wrongUnitSlotPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'unit data1[4] is verified separately from the canonical descriptor'

    $missingBankPath = Join-Path $temporaryRoot 'player_bank_missing_0.psochar'
    $missingBankBytes = [byte[]]$bytes.Clone()
    Set-UInt32LE -Data $missingBankBytes -Offset 0x700 `
        -Value ([uint32]($bankItems.Count - 1))
    [System.IO.File]::WriteAllBytes($missingBankPath, $missingBankBytes)
    Add-Result 'missing embedded-bank multiplicity fails closed' (
        Invoke-RejectionCheck -CharacterPath $missingBankPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'the exact bank item count remains contract-bound'

    $duplicateBankPath = Join-Path $temporaryRoot 'player_bank_duplicate_0.psochar'
    $duplicateBankBytes = [byte[]]$bytes.Clone()
    [System.Array]::Copy($duplicateBankBytes, 0x708, $duplicateBankBytes,
        (0x708 + 0x18), 12)
    [System.Array]::Copy($duplicateBankBytes, (0x708 + 16), $duplicateBankBytes,
        (0x708 + 0x18 + 16), 4)
    [System.IO.File]::WriteAllBytes($duplicateBankPath, $duplicateBankBytes)
    Add-Result 'duplicate embedded-bank descriptor multiplicity fails closed' (
        Invoke-RejectionCheck -CharacterPath $duplicateBankPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'matching uses complete 16-byte descriptor multiplicity'

    $alteredBankPath = Join-Path $temporaryRoot 'player_bank_altered_0.psochar'
    $alteredBankBytes = [byte[]]$bytes.Clone()
    $alteredBankBytes[0x708 + 16] = $alteredBankBytes[0x708 + 16] -bxor 1
    [System.IO.File]::WriteAllBytes($alteredBankPath, $alteredBankBytes)
    Add-Result 'altered embedded-bank descriptor fails closed' (
        Invoke-RejectionCheck -CharacterPath $alteredBankPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'all 16 canonical descriptor bytes are identity-bearing'

    $bankAmountPath = Join-Path $temporaryRoot 'player_bank_amount_0.psochar'
    $bankAmountBytes = [byte[]]$bytes.Clone()
    Set-UInt16LE -Data $bankAmountBytes -Offset (0x708 + 0x14) -Value 2
    [System.IO.File]::WriteAllBytes($bankAmountPath, $bankAmountBytes)
    Add-Result 'bank equipment amount other than one fails closed' (
        Invoke-RejectionCheck -CharacterPath $bankAmountPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'bank gear uses one exact non-stack entry'

    $bankPresentPath = Join-Path $temporaryRoot 'player_bank_present_0.psochar'
    $bankPresentBytes = [byte[]]$bytes.Clone()
    Set-UInt16LE -Data $bankPresentBytes -Offset (0x708 + 0x16) -Value 0
    [System.IO.File]::WriteAllBytes($bankPresentPath, $bankPresentBytes)
    Add-Result 'absent embedded-bank record fails closed' (
        Invoke-RejectionCheck -CharacterPath $bankPresentPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'every active bank record must be present exactly once'

    $zeroBankIdPath = Join-Path $temporaryRoot 'player_bank_zero_id_0.psochar'
    $zeroBankIdBytes = [byte[]]$bytes.Clone()
    Set-UInt32LE -Data $zeroBankIdBytes -Offset (0x708 + 12) -Value 0
    [System.IO.File]::WriteAllBytes($zeroBankIdPath, $zeroBankIdBytes)
    Add-Result 'zero embedded-bank item ID fails closed' (
        Invoke-RejectionCheck -CharacterPath $zeroBankIdPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'runtime item IDs must be valid even though prior values are transient'

    $maximumBankIdPath = Join-Path $temporaryRoot 'player_bank_max_id_0.psochar'
    $maximumBankIdBytes = [byte[]]$bytes.Clone()
    Set-UInt32LE -Data $maximumBankIdBytes -Offset (0x708 + 12) `
        -Value ([uint32]::MaxValue)
    [System.IO.File]::WriteAllBytes($maximumBankIdPath, $maximumBankIdBytes)
    Add-Result 'maximum embedded-bank item ID fails closed' (
        Invoke-RejectionCheck -CharacterPath $maximumBankIdPath -ContractPath $buildPath `
            -Pattern 'character-build verification check') `
        'the reserved maximum runtime ID remains invalid'

    $duplicateBankIdPath = Join-Path $temporaryRoot 'player_bank_duplicate_id_0.psochar'
    $duplicateBankIdBytes = [byte[]]$bytes.Clone()
    [System.Array]::Copy($duplicateBankIdBytes, (0x708 + 12), $duplicateBankIdBytes,
        (0x708 + 0x18 + 12), 4)
    [System.IO.File]::WriteAllBytes($duplicateBankIdPath, $duplicateBankIdBytes)
    Add-Result 'duplicate embedded-bank item ID fails closed' (
        Invoke-RejectionCheck -CharacterPath $duplicateBankIdPath `
            -ContractPath $buildPath -Pattern 'character-build verification check') `
        'inventory and embedded-bank runtime IDs remain globally unique'

    $unknownPropertyPath = Join-Path $temporaryRoot 'unknown_property.json'
    $variant = Read-ContractCopy
    $variant | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Write-ContractVariant -Contract $variant -Path $unknownPropertyPath
    Add-Result 'unknown contract properties fail closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $unknownPropertyPath `
            -Pattern 'exact closed property set') `
        'top-level contract schema is closed'

    $stringIntegerPath = Join-Path $temporaryRoot 'string_integer.json'
    $variant = Read-ContractCopy
    $variant.character.classId = '8'
    Write-ContractVariant -Contract $variant -Path $stringIntegerPath
    Add-Result 'numeric strings in the contract fail closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $stringIntegerPath `
            -Pattern 'invalid JSON scalar types') `
        'numeric casts cannot normalize a string into an integer'

    $fractionalIntegerPath = Join-Path $temporaryRoot 'fractional_integer.json'
    $variant = Read-ContractCopy
    $variant.character.classId = 8.4
    Write-ContractVariant -Contract $variant -Path $fractionalIntegerPath
    Add-Result 'fractional integers in the contract fail closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $fractionalIntegerPath `
            -Pattern 'invalid JSON scalar types') `
        'numeric casts cannot truncate a fractional value'

    $nullIntegerPath = Join-Path $temporaryRoot 'null_integer.json'
    $variant = Read-ContractCopy
    $variant.materials.Mind = $null
    Write-ContractVariant -Contract $variant -Path $nullIntegerPath
    Add-Result 'null integers in the contract fail closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $nullIntegerPath `
            -Pattern 'invalid JSON scalar types') `
        'null cannot normalize to zero'

    $wrongContractSlotPath = Join-Path $temporaryRoot 'wrong_contract_slot.json'
    $variant = Read-ContractCopy
    $variant.character.slotIndex = 1
    Write-ContractVariant -Contract $variant -Path $wrongContractSlotPath
    Add-Result 'contract target other than slot zero fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $wrongContractSlotPath `
            -Pattern 'only existing slot-0 Twills FOnewearl') `
        'slot scope cannot be widened by editing the contract'

    $wrongMaterialPath = Join-Path $temporaryRoot 'wrong_material.json'
    $variant = Read-ContractCopy
    $variant.materials.Mind = 149
    Write-ContractVariant -Contract $variant -Path $wrongMaterialPath
    Add-Result 'non-max Mind material contract fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $wrongMaterialPath `
            -Pattern 'unexpected FOnewearl material count') `
        'the exact 150-Mind plan is schema-bound'

    $techniqueOverflowPath = Join-Path $temporaryRoot 'technique_overflow.json'
    $variant = Read-ContractCopy
    $variant.techniques[14].displayedLevel = 2
    Write-ContractVariant -Contract $variant -Path $techniqueOverflowPath
    Add-Result 'technique-specific limits in the contract fail closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $techniqueOverflowPath `
            -Pattern 'Technique contract is invalid') `
        'Ryuker and Reverser remain displayed level 1'

    $duplicateItemPath = Join-Path $temporaryRoot 'duplicate_item.json'
    $variant = Read-ContractCopy
    $variant.items[1].name = $variant.items[0].name
    Write-ContractVariant -Contract $variant -Path $duplicateItemPath
    Add-Result 'duplicate item names in the contract fail closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $duplicateItemPath `
            -Pattern 'invalid or duplicate') `
        'same-primary-ID Mag and weapon variants remain unambiguous by name and descriptor'

    $canonicalUnitPath = Join-Path $temporaryRoot 'noncanonical_unit.json'
    $variant = Read-ContractCopy
    $v801 = @($variant.items | Where-Object { $_.name -ceq 'V801' })[0]
    $v801.descriptorHex = $v801.descriptorHex.Substring(0, 8) + '01' +
        $v801.descriptorHex.Substring(10)
    Write-ContractVariant -Contract $variant -Path $canonicalUnitPath
    Add-Result 'unit contract with embedded runtime slot fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $canonicalUnitPath `
            -Pattern 'not canonical') `
        'canonical unit descriptors always zero data1[4]'

    $unpinnedSourcePath = Join-Path $temporaryRoot 'unpinned_source.json'
    $variant = Read-ContractCopy
    $variant.sources[0] = 'https://wiki.pioneer2.net/w/FOnewearl/Guide'
    Write-ContractVariant -Contract $variant -Path $unpinnedSourcePath
    Add-Result 'unpinned source URL fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $unpinnedSourcePath `
            -Pattern 'revision-pinned') `
        'recommendation evidence cannot silently drift'

    $wrongOrderPath = Join-Path $temporaryRoot 'wrong_order.json'
    $variant = Read-ContractCopy
    $adept = @($variant.items | Where-Object { $_.name -ceq 'Adept' })[0]
    $wand = @($variant.items | Where-Object { $_.name -ceq 'Psycho Wand' })[0]
    $adept.slot = 7
    $wand.slot = 4
    Write-ContractVariant -Contract $variant -Path $wrongOrderPath
    Add-Result 'Psycho Wand before Adept in the contract fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $wrongOrderPath `
            -Pattern 'Adept must physically precede Psycho Wand') `
        'inventory modifier evaluation order is explicit'

    $freeSlotPolicyPath = Join-Path $temporaryRoot 'free_slot_policy.json'
    $variant = Read-ContractCopy
    $variant.inventoryPolicy.minimumFreeSlots = 1
    Write-ContractVariant -Contract $variant -Path $freeSlotPolicyPath
    Add-Result 'weakened minimum-free-slot policy fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $freeSlotPolicyPath `
            -Pattern 'preserve two free slots') `
        'two inventory positions remain available'

    $profileReferencePath = Join-Path $temporaryRoot 'profile_reference.json'
    $variant = Read-ContractCopy
    $variant.loadoutProfiles[0].weapon = 'Unknown Weapon'
    Write-ContractVariant -Contract $variant -Path $profileReferencePath
    Add-Result 'unknown profile item reference fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $profileReferencePath `
            -Pattern 'references an unknown item') `
        'profiles reference only exact owned items'

    $profileTypePath = Join-Path $temporaryRoot 'profile_type.json'
    $variant = Read-ContractCopy
    $variant.loadoutProfiles[0].weapon = 'Ignition Cloak'
    Write-ContractVariant -Contract $variant -Path $profileTypePath
    Add-Result 'profile weapon-to-armor type confusion fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $profileTypePath `
            -Pattern 'item type is invalid for Weapon') `
        'loadout slot types are descriptor-bound'

    $profileUnitTypePath = Join-Path $temporaryRoot 'profile_unit_type.json'
    $variant = Read-ContractCopy
    $variant.loadoutProfiles[0].units[0] = 'Psycho Wand'
    Write-ContractVariant -Contract $variant -Path $profileUnitTypePath
    Add-Result 'profile unit-to-weapon type confusion fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $profileUnitTypePath `
            -Pattern 'unit type is invalid') `
        'all four unit references must be canonical units'

    $missingProfilePath = Join-Path $temporaryRoot 'missing_profile.json'
    $variant = Read-ContractCopy
    $variant.loadoutProfiles = @($variant.loadoutProfiles | Where-Object {
            $_.id -cne 'dark-falz'
        })
    Write-ContractVariant -Contract $variant -Path $missingProfilePath
    Add-Result 'missing boss profile fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $missingProfilePath `
            -Pattern 'missing required loadout profile: dark-falz') `
        'the full elemental and boss profile matrix is required'

    $selectCloakPath = Join-Path $temporaryRoot 'nonmaximum_select_cloak.json'
    $variant = Read-ContractCopy
    $selectCloak = @($variant.items | Where-Object { $_.name -ceq 'Select Cloak' })[0]
    $selectCloak.descriptorHex = '01014A00000407000800000000000000'
    Write-ContractVariant -Contract $variant -Path $selectCloakPath
    Add-Result 'nonmaximum Select Cloak fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $selectCloakPath `
            -Pattern 'Select Cloak must be the exact') `
        'the Grants armor remains four-slot maximum DFP and EVP'

    $lightArmorPath = Join-Path $temporaryRoot 'wrong_light_armor.json'
    $variant = Read-ContractCopy
    $lightProfile = @($variant.loadoutProfiles | Where-Object { $_.id -ceq 'light-grants' })[0]
    $lightProfile.armor = 'Brightness Circle'
    Write-ContractVariant -Contract $variant -Path $lightArmorPath
    Add-Result 'Light Grants without Select Cloak fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $lightArmorPath `
            -Pattern 'Light Grants profile must combine') `
        'the dedicated light profile retains the Grants armor boost'

    $healerUnitPath = Join-Path $temporaryRoot 'healer_smartlink.json'
    $variant = Read-ContractCopy
    $healerProfile = @($variant.loadoutProfiles | Where-Object { $_.id -ceq 'healer-support' })[0]
    $healerProfile.units[3] = 'Smartlink'
    Write-ContractVariant -Contract $variant -Path $healerUnitPath
    Add-Result 'healer Smartlink regression fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $healerUnitPath `
            -Pattern 'must use Heavenly/HP instead of Smartlink') `
        'the casting-only healer profile retains its survivability unit'

    $forbiddenItemPath = Join-Path $temporaryRoot 'forbidden_item.json'
    $variant = Read-ContractCopy
    $scape = @($variant.items | Where-Object { $_.name -ceq 'Scape Doll' })[0]
    $scape.name = 'Excalibur'
    Write-ContractVariant -Contract $variant -Path $forbiddenItemPath
    Add-Result 'FOnewearl-incompatible item name fails closed' (
        Invoke-RejectionCheck -CharacterPath $fixturePath -ContractPath $forbiddenItemPath `
            -Pattern 'outside the FOnewearl contract') `
        'retired FOnewm and class-incompatible recommendations stay excluded'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) character-build test(s) failed"
}
[pscustomobject]@{
    Suite = 'CharacterBuild'
    Passed = $results.Count
    Failed = 0
}
