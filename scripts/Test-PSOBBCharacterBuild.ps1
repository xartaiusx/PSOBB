[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [string]$BuildPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($BuildPath)) {
    $BuildPath = Join-Path $repositoryRoot 'config\twills-fonewearl-build.json'
}
$resolvedBuildPath = [System.IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $BuildPath).Path)
$buildFile = Get-Item -LiteralPath $resolvedBuildPath -Force
if (($buildFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $buildFile.Length -le 0 -or $buildFile.Length -gt 64KB) {
    throw "Character build contract has an invalid size or filesystem type: $resolvedBuildPath"
}
$buildHashBefore = (Get-FileHash -LiteralPath $resolvedBuildPath -Algorithm SHA256).Hash.ToLowerInvariant()
try {
    $build = Get-Content -Raw -LiteralPath $resolvedBuildPath |
        ConvertFrom-Json -Depth 30
} catch {
    throw "Character build contract is not valid JSON: $($_.Exception.Message)"
}

function Test-JsonObject {
    param($Value)
    return $null -ne $Value -and
        $Value.GetType() -eq [System.Management.Automation.PSCustomObject]
}

function Test-JsonArray {
    param($Value)
    return $null -ne $Value -and $Value.GetType().IsArray
}

function Test-JsonInteger {
    param($Value)
    return $null -ne $Value -and (
        $Value -is [sbyte] -or $Value -is [byte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64])
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string[]]$Names
    )

    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if ([string]::Join("`n", $actual) -cne [string]::Join("`n", $expected)) {
        throw "$Label does not use its exact closed property set"
    }
}

function Convert-HexToBytes {
    param([Parameter(Mandatory)][string]$Hex)

    if ($Hex -cnotmatch '^(?:[0-9A-F]{2})+$') {
        throw "Descriptor is not uppercase hexadecimal: $Hex"
    }
    $value = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $value.Length; $index++) {
        $value[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $value
}

function Get-DescriptorPrimaryId {
    param([Parameter(Mandatory)][byte[]]$Descriptor)

    $itemClass = [int]$Descriptor[0]
    $itemType = [int]$Descriptor[1]
    $itemSubtype = [int]$Descriptor[2]
    if ($itemClass -eq 0x04) {
        return '04000000'
    }
    if ($itemClass -eq 0x03 -and $itemType -eq 0x02) {
        return '0302{0:X2}{1:X2}' -f $Descriptor[4], $itemSubtype
    }
    if ($itemClass -eq 0x02) {
        return '02{0:X2}0000' -f $itemType
    }
    if ($itemClass -eq 0x00 -and
        (($itemType -gt 0x6F -and $itemType -lt 0x89) -or
            ($itemType -gt 0xA4 -and $itemType -lt 0xAA))) {
        return '00{0:X2}0000' -f $itemType
    }
    return '{0:X2}{1:X2}{2:X2}00' -f $itemClass, $itemType, $itemSubtype
}

function Get-DescriptorEquipmentKind {
    param([Parameter(Mandatory)][byte[]]$Descriptor)

    if ($Descriptor[0] -eq 0x00) { return 'Weapon' }
    if ($Descriptor[0] -eq 0x02) { return 'Mag' }
    if ($Descriptor[0] -eq 0x01) {
        switch ([int]$Descriptor[1]) {
            0x01 { return 'Armor' }
            0x02 { return 'Shield' }
            0x03 { return 'Unit' }
        }
    }
    return 'Tool'
}

function Test-PinnedSourceUrl {
    param([Parameter(Mandatory)][string]$Value)

    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'https') {
        return $false
    }
    return $Value -cmatch '(?:[?&]oldid=[0-9]+(?:&|$)|/releases/tag/[A-Za-z0-9._-]+$|/commit/[0-9a-f]{40}$)'
}

if (-not (Test-JsonObject $build) -or
    -not (Test-JsonObject $build.character) -or
    -not (Test-JsonObject $build.stats) -or
    -not (Test-JsonObject $build.integrity) -or
    -not (Test-JsonObject $build.materials) -or
    -not (Test-JsonObject $build.inventoryPolicy) -or
    -not (Test-JsonArray $build.sources) -or
    -not (Test-JsonArray $build.techniques) -or
    -not (Test-JsonArray $build.items) -or
    -not (Test-JsonArray $build.loadoutProfiles)) {
    throw 'Character build contract uses invalid JSON container types'
}

Assert-ExactProperties -Object $build -Label 'Character build contract' -Names @(
    'schemaVersion', 'profileId', 'sources', 'character', 'materials', 'stats',
    'integrity', 'techniques', 'inventoryPolicy', 'items', 'activeLoadoutId',
    'loadoutProfiles')
Assert-ExactProperties -Object $build.character -Label 'Character identity contract' -Names @(
    'slotIndex', 'name', 'classId', 'className', 'sectionId', 'sectionName',
    'storedLevel', 'displayedLevel', 'experience', 'meseta')
Assert-ExactProperties -Object $build.materials -Label 'Character material contract' -Names @(
    'Power', 'Mind', 'Evade', 'Def', 'Luck', 'HP', 'TP')
Assert-ExactProperties -Object $build.stats -Label 'Character stats contract' -Names @(
    'ATP', 'MST', 'EVP', 'HP', 'DFP', 'ATA', 'LCK')
Assert-ExactProperties -Object $build.integrity -Label 'Character integrity contract' -Names @(
    'characterValidationFlags', 'signatureHex', 'visualValidationFlags',
    'visualVersion', 'visualClassFlags', 'guildCardName', 'guildCardPresent',
    'guildCardSectionId', 'guildCardClassId', 'hpMaterialRaw', 'tpMaterialRaw')
Assert-ExactProperties -Object $build.inventoryPolicy -Label 'Inventory policy contract' -Names @(
    'capacity', 'minimumFreeSlots', 'requiredInventoryOrder')

$classNames = @(
    'HUmar', 'HUnewearl', 'HUcast', 'RAmar', 'RAcast', 'RAcaseal',
    'FOmarl', 'FOnewm', 'FOnewearl', 'HUcaseal', 'FOmar', 'RAmarl')
$sectionNames = @(
    'Viridia', 'Greennill', 'Skyly', 'Bluefull', 'Purplenum',
    'Pinkal', 'Redria', 'Oran', 'Yellowboze', 'Whitill')
$techniqueNames = @(
    'Foie', 'Gifoie', 'Rafoie', 'Barta', 'Gibarta', 'Rabarta',
    'Zonde', 'Gizonde', 'Razonde', 'Grants', 'Deband', 'Jellen',
    'Zalure', 'Shifta', 'Ryuker', 'Resta', 'Anti', 'Reverser', 'Megid')

if (-not (Test-JsonInteger $build.schemaVersion) -or
    $build.profileId -isnot [string] -or
    $build.activeLoadoutId -isnot [string] -or
    $build.character.name -isnot [string] -or
    $build.character.className -isnot [string] -or
    $build.character.sectionName -isnot [string] -or
    @($build.sources | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
    @('slotIndex', 'classId', 'sectionId', 'storedLevel', 'displayedLevel',
        'experience', 'meseta' | Where-Object {
            -not (Test-JsonInteger $build.character.$_)
        }).Count -ne 0 -or
    @('Power', 'Mind', 'Evade', 'Def', 'Luck', 'HP', 'TP' | Where-Object {
            -not (Test-JsonInteger $build.materials.$_)
        }).Count -ne 0 -or
    @('ATP', 'MST', 'EVP', 'HP', 'DFP', 'ATA', 'LCK' | Where-Object {
            -not (Test-JsonInteger $build.stats.$_)
        }).Count -ne 0 -or
    @('characterValidationFlags', 'visualValidationFlags', 'visualVersion',
        'visualClassFlags', 'guildCardPresent', 'guildCardSectionId',
        'guildCardClassId', 'hpMaterialRaw', 'tpMaterialRaw' | Where-Object {
            -not (Test-JsonInteger $build.integrity.$_)
        }).Count -ne 0 -or
    @('capacity', 'minimumFreeSlots' | Where-Object {
            -not (Test-JsonInteger $build.inventoryPolicy.$_)
        }).Count -ne 0 -or
    $build.integrity.signatureHex -isnot [string] -or
    $build.integrity.guildCardName -isnot [string] -or
    -not (Test-JsonArray $build.inventoryPolicy.requiredInventoryOrder) -or
    @($build.inventoryPolicy.requiredInventoryOrder | Where-Object {
            $_ -isnot [string]
        }).Count -ne 0) {
    throw 'Character build contract uses invalid JSON scalar types'
}

$sourceSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($source in @($build.sources)) {
    if (-not (Test-PinnedSourceUrl -Value ([string]$source)) -or
        -not $sourceSet.Add([string]$source)) {
        throw "Character build source is not uniquely revision-pinned: $source"
    }
}
if (@($build.sources).Count -lt 5 -or
    @($build.sources | Where-Object {
            [string]$_ -cmatch '^https://github\.com/fuzziqersoftware/newserv/releases/tag/'
        }).Count -ne 1 -or
    @($build.sources | Where-Object {
            [string]$_ -cmatch '^https://github\.com/fuzziqersoftware/newserv/commit/[0-9a-f]{40}$'
        }).Count -ne 1) {
    throw 'Character build sources must include unique pinned wiki and newserv release/commit evidence'
}

if ([int]$build.schemaVersion -ne 2 -or
    [string]$build.profileId -cne 'twills-fonewearl-level-200' -or
    [string]$build.activeLoadoutId -cne 'general-dps' -or
    [string]$build.character.name -cne 'Twills' -or
    [int]$build.character.slotIndex -ne 0 -or
    [int]$build.character.classId -ne 8 -or
    [string]$build.character.className -cne 'FOnewearl' -or
    [int]$build.character.sectionId -ne 2 -or
    [string]$build.character.sectionName -cne 'Skyly' -or
    [int]$build.character.classId -notin 0..11 -or
    [string]$build.character.className -cne $classNames[[int]$build.character.classId] -or
    [int]$build.character.sectionId -notin 0..9 -or
    [string]$build.character.sectionName -cne $sectionNames[[int]$build.character.sectionId] -or
    [int]$build.character.storedLevel -ne 199 -or
    [int]$build.character.displayedLevel -ne 200 -or
    [long]$build.character.experience -ne 83227800 -or
    [long]$build.character.meseta -ne 999999) {
    throw 'Character build contract does not target only existing slot-0 Twills FOnewearl'
}

$expectedStats = [ordered]@{
    ATP = 480; MST = 1500; EVP = 735; HP = 593; DFP = 334; ATA = 736; LCK = 10
}
foreach ($name in $expectedStats.Keys) {
    if ([long]$build.stats.$name -ne [long]$expectedStats[$name]) {
        throw "Character build contract has an unexpected FOnewearl saved stat: $name"
    }
}

$expectedMaterials = [ordered]@{
    Power = 0; Mind = 150; Evade = 0; Def = 0; Luck = 0; HP = 125; TP = 125
}
foreach ($name in $expectedMaterials.Keys) {
    if ([long]$build.materials.$name -ne [long]$expectedMaterials[$name]) {
        throw "Character build contract has an unexpected FOnewearl material count: $name"
    }
}

if ([int]$build.integrity.characterValidationFlags -ne 0 -or
    [string]$build.integrity.signatureHex -cne 'C87ED5B1' -or
    [int]$build.integrity.visualValidationFlags -ne 0 -or
    [int]$build.integrity.visualVersion -ne 3 -or
    [int]$build.integrity.visualClassFlags -ne 0x8A -or
    [string]$build.integrity.guildCardName -cne 'Twills' -or
    [int]$build.integrity.guildCardPresent -ne 1 -or
    [int]$build.integrity.guildCardSectionId -ne 2 -or
    [int]$build.integrity.guildCardClassId -ne 8 -or
    [int]$build.integrity.hpMaterialRaw -ne 250 -or
    [int]$build.integrity.tpMaterialRaw -ne 250) {
    throw 'Character build contract integrity values are internally inconsistent'
}

$techniqueIds = [System.Collections.Generic.HashSet[int]]::new()
foreach ($technique in @($build.techniques)) {
    if (-not (Test-JsonObject $technique)) {
        throw 'Technique contract entries must be JSON objects'
    }
    Assert-ExactProperties -Object $technique -Label 'Technique contract' -Names @(
        'id', 'name', 'displayedLevel')
    if (-not (Test-JsonInteger $technique.id) -or
        -not (Test-JsonInteger $technique.displayedLevel) -or
        $technique.name -isnot [string]) {
        throw 'Technique contract uses invalid JSON scalar types'
    }
    $techniqueId = [int]$technique.id
    $expectedDisplayedLevel = if ($techniqueId -in @(14, 17)) {
        1
    } elseif ($techniqueId -eq 16) {
        7
    } else {
        30
    }
    if ($techniqueId -notin 0..18 -or
        -not $techniqueIds.Add($techniqueId) -or
        [string]$technique.name -cne $techniqueNames[$techniqueId] -or
        [int]$technique.displayedLevel -ne $expectedDisplayedLevel) {
        throw "Technique contract is invalid or not maxed: $($technique.name)"
    }
}
if ($techniqueIds.Count -ne 19) {
    throw 'Character build contract must declare all 19 techniques exactly once'
}

if ([int]$build.inventoryPolicy.capacity -ne 30 -or
    [int]$build.inventoryPolicy.minimumFreeSlots -ne 2 -or
    @($build.inventoryPolicy.requiredInventoryOrder).Count -ne 2 -or
    [string]$build.inventoryPolicy.requiredInventoryOrder[0] -cne 'Adept' -or
    [string]$build.inventoryPolicy.requiredInventoryOrder[1] -cne 'Psycho Wand') {
    throw 'Inventory policy must preserve two free slots and Adept-before-Psycho-Wand order'
}

$itemNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$descriptors = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$locationSlots = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$itemByName = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::Ordinal)
$allowedEquippedSlots = @('None', 'Weapon', 'Armor', 'Shield', 'Mag',
    'Unit1', 'Unit2', 'Unit3', 'Unit4')

foreach ($item in @($build.items)) {
    if (-not (Test-JsonObject $item)) {
        throw 'Item contract entries must be JSON objects'
    }
    Assert-ExactProperties -Object $item -Label 'Item contract' -Names @(
        'name', 'description', 'primaryId', 'descriptorHex', 'count',
        'location', 'slot', 'equippedSlot')
    if ($item.name -isnot [string] -or
        $item.description -isnot [string] -or
        $item.primaryId -isnot [string] -or
        $item.descriptorHex -isnot [string] -or
        $item.location -isnot [string] -or
        $item.equippedSlot -isnot [string] -or
        -not (Test-JsonInteger $item.count) -or
        -not (Test-JsonInteger $item.slot) -or
        [string]$item.name -cnotmatch '^.{1,64}$' -or
        [string]$item.description -cnotmatch '^[ -~]{1,160}$' -or
        [string]$item.primaryId -cnotmatch '^[0-9A-F]{8}$' -or
        [string]$item.descriptorHex -cnotmatch '^[0-9A-F]{32}$' -or
        [int]$item.count -ne 1 -or
        [string]$item.location -notin @('Inventory', 'Bank') -or
        [string]$item.equippedSlot -notin $allowedEquippedSlots -or
        -not $itemNames.Add([string]$item.name) -or
        -not $descriptors.Add([string]$item.descriptorHex) -or
        -not $locationSlots.Add("$($item.location):$($item.slot)")) {
        throw "Item contract is invalid or duplicate: $($item.name)"
    }
    if ([string]$item.name -cmatch '^(?:Mother Garb\+|Excalibur|Dark Bridge|Demonic Fork)$') {
        throw "Item is outside the FOnewearl contract: $($item.name)"
    }

    $descriptor = Convert-HexToBytes -Hex ([string]$item.descriptorHex)
    $kind = Get-DescriptorEquipmentKind -Descriptor $descriptor
    if ((Get-DescriptorPrimaryId -Descriptor $descriptor) -cne [string]$item.primaryId -or
        ($kind -eq 'Unit' -and $descriptor[4] -ne 0)) {
        throw "Item descriptor is not canonical for its primary ID: $($item.name)"
    }
    if ([string]$item.location -ceq 'Inventory') {
        if ([int]$item.slot -lt 1 -or [int]$item.slot -gt 30) {
            throw "Inventory item slot is outside 1..30: $($item.name)"
        }
    } else {
        if ([int]$item.slot -lt 1 -or [int]$item.slot -gt 200 -or
            [string]$item.equippedSlot -cne 'None') {
            throw "Bank item slot or equipped state is invalid: $($item.name)"
        }
    }
    if ([string]$item.equippedSlot -cne 'None') {
        $expectedKind = if ([string]$item.equippedSlot -cmatch '^Unit[1-4]$') {
            'Unit'
        } else {
            [string]$item.equippedSlot
        }
        if ($kind -cne $expectedKind) {
            throw "Equipped slot is incompatible with item descriptor: $($item.name)"
        }
    }
    $itemByName.Add([string]$item.name, $item)
}

$inventoryItems = @($build.items | Where-Object { [string]$_.location -ceq 'Inventory' })
$bankItems = @($build.items | Where-Object { [string]$_.location -ceq 'Bank' })
if ($inventoryItems.Count -ne 28 -or $bankItems.Count -ne 29) {
    throw 'Character build contract must declare the pinned 28-item inventory and 29-item bank kit'
}
for ($slot = 1; $slot -le 28; $slot++) {
    if (@($inventoryItems | Where-Object { [int]$_.slot -eq $slot }).Count -ne 1) {
        throw "Character build contract inventory slots are not contiguous at slot $slot"
    }
}
for ($slot = 1; $slot -le 29; $slot++) {
    if (@($bankItems | Where-Object { [int]$_.slot -eq $slot }).Count -ne 1) {
        throw "Character build contract bank slots are not contiguous at slot $slot"
    }
}
$selectCloak = $itemByName['Select Cloak']
if ([string]$selectCloak.location -cne 'Bank' -or
    [int]$selectCloak.slot -ne 29 -or
    [string]$selectCloak.primaryId -cne '01014A00' -or
    [string]$selectCloak.descriptorHex -cne '01014A00000408000800000000000000') {
    throw 'Select Cloak must be the exact four-slot maximum-DFP/EVP bank item'
}
$adept = $itemByName['Adept']
$psychoWand = $itemByName['Psycho Wand']
if ([string]$adept.location -cne 'Inventory' -or
    [string]$psychoWand.location -cne 'Inventory' -or
    [int]$adept.slot -ge [int]$psychoWand.slot) {
    throw 'Adept must physically precede Psycho Wand in inventory order'
}

$profileIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$profileById = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::Ordinal)
foreach ($profile in @($build.loadoutProfiles)) {
    if (-not (Test-JsonObject $profile)) {
        throw 'Loadout profile entries must be JSON objects'
    }
    Assert-ExactProperties -Object $profile -Label 'Loadout profile' -Names @(
        'id', 'name', 'purpose', 'weapon', 'armor', 'shield', 'mag', 'units',
        'swapItems')
    if ($profile.id -isnot [string] -or
        $profile.name -isnot [string] -or
        $profile.purpose -isnot [string] -or
        $profile.weapon -isnot [string] -or
        $profile.armor -isnot [string] -or
        $profile.shield -isnot [string] -or
        $profile.mag -isnot [string] -or
        -not (Test-JsonArray $profile.units) -or
        -not (Test-JsonArray $profile.swapItems) -or
        [string]$profile.id -cnotmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$' -or
        [string]$profile.name -cnotmatch '^[ -~]{1,80}$' -or
        [string]$profile.purpose -cnotmatch '^[ -~]{1,240}$' -or
        @($profile.units).Count -ne 4 -or
        @($profile.units | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        @($profile.swapItems | Where-Object { $_ -isnot [string] }).Count -ne 0 -or
        -not $profileIds.Add([string]$profile.id)) {
        throw "Loadout profile is invalid or duplicate: $($profile.id)"
    }

    foreach ($entry in @(
            @{ Name = [string]$profile.weapon; Kind = 'Weapon' },
            @{ Name = [string]$profile.armor; Kind = 'Armor' },
            @{ Name = [string]$profile.shield; Kind = 'Shield' },
            @{ Name = [string]$profile.mag; Kind = 'Mag' })) {
        if (-not $itemByName.ContainsKey($entry.Name)) {
            throw "Loadout profile references an unknown item: $($entry.Name)"
        }
        $descriptor = Convert-HexToBytes -Hex ([string]$itemByName[$entry.Name].descriptorHex)
        if ((Get-DescriptorEquipmentKind -Descriptor $descriptor) -cne $entry.Kind) {
            throw "Loadout profile item type is invalid for $($entry.Kind): $($entry.Name)"
        }
    }

    $profileUnitNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($unitName in @($profile.units)) {
        if (-not $itemByName.ContainsKey([string]$unitName) -or
            -not $profileUnitNames.Add([string]$unitName)) {
            throw "Loadout profile references an unknown or duplicate unit: $unitName"
        }
        $descriptor = Convert-HexToBytes -Hex ([string]$itemByName[[string]$unitName].descriptorHex)
        if ((Get-DescriptorEquipmentKind -Descriptor $descriptor) -cne 'Unit') {
            throw "Loadout profile unit type is invalid: $unitName"
        }
    }
    $swapNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($swapName in @($profile.swapItems)) {
        if (-not $itemByName.ContainsKey([string]$swapName) -or
            -not $swapNames.Add([string]$swapName)) {
            throw "Loadout profile references an unknown or duplicate swap item: $swapName"
        }
    }
    $profileById.Add([string]$profile.id, $profile)
}

$requiredProfileIds = @(
    'general-dps', 'healer-support',
    'fire-simple', 'fire-gi', 'fire-ra',
    'ice-simple', 'ice-gi', 'ice-ra',
    'lightning-simple', 'lightning-gi', 'lightning-ra',
    'light-grants', 'dark-megid', 'dark-falz', 'vol-opt',
    'saint-milion-kondrieu', 'shambertin', 'olga-flow-ep2-physical')
foreach ($profileId in $requiredProfileIds) {
    if (-not $profileById.ContainsKey($profileId)) {
        throw "Character build contract is missing required loadout profile: $profileId"
    }
}
$lightGrantsProfile = $profileById['light-grants']
if ([string]$lightGrantsProfile.weapon -cne 'Mercurius Rod' -or
    [string]$lightGrantsProfile.armor -cne 'Select Cloak') {
    throw 'Light Grants profile must combine Mercurius Rod with Select Cloak'
}
$healerProfile = $profileById['healer-support']
if ([string]$healerProfile.units[3] -cne 'Heavenly/HP' -or
    @($healerProfile.units | Where-Object { [string]$_ -ceq 'Smartlink' }).Count -ne 0) {
    throw 'Healer and Support profile must use Heavenly/HP instead of Smartlink'
}
if (-not $profileById.ContainsKey([string]$build.activeLoadoutId)) {
    throw 'Active loadout ID does not resolve to exactly one loadout profile'
}

$activeProfile = $profileById[[string]$build.activeLoadoutId]
$activeSlots = [ordered]@{
    Weapon = [string]$activeProfile.weapon
    Armor = [string]$activeProfile.armor
    Shield = [string]$activeProfile.shield
    Mag = [string]$activeProfile.mag
    Unit1 = [string]$activeProfile.units[0]
    Unit2 = [string]$activeProfile.units[1]
    Unit3 = [string]$activeProfile.units[2]
    Unit4 = [string]$activeProfile.units[3]
}
$activeNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($slotName in $activeSlots.Keys) {
    $itemName = $activeSlots[$slotName]
    $item = $itemByName[$itemName]
    if (-not $activeNames.Add($itemName) -or
        [string]$item.location -cne 'Inventory' -or
        [string]$item.equippedSlot -cne $slotName) {
        throw "Active loadout does not match the equipped item contract: $slotName"
    }
}
foreach ($item in @($build.items)) {
    if ([string]$item.equippedSlot -cne 'None' -and
        -not $activeNames.Contains([string]$item.name)) {
        throw "Item is equipped outside the active loadout: $($item.name)"
    }
}

$resolvedCharacterPath = [System.IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $Path).Path)
$characterLeafName = [System.IO.Path]::GetFileName($resolvedCharacterPath)
if ($characterLeafName -cnotmatch '^player_[A-Za-z0-9._-]+_0\.psochar$') {
    throw "Character build verification is restricted to existing slot 0: $characterLeafName"
}
$characterFile = Get-Item -LiteralPath $resolvedCharacterPath -Force
if (($characterFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Character build verification refuses a reparse point: $resolvedCharacterPath"
}
$hashBefore = (Get-FileHash -LiteralPath $resolvedCharacterPath -Algorithm SHA256).Hash.ToLowerInvariant()
$summary = & (Join-Path $PSScriptRoot 'Get-PSOBBCharacterSummary.ps1') `
    -Path $resolvedCharacterPath

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

Add-Result -Name 'slot-0 character target' -Passed (
    $characterLeafName -cmatch '_0\.psochar$' -and
    [int]$build.character.slotIndex -eq 0) -Detail $characterLeafName

Add-Result -Name 'character identity' -Passed (
    [string]$summary.Name -ceq [string]$build.character.name -and
    [int]$summary.ClassId -eq [int]$build.character.classId -and
    [string]$summary.ClassName -ceq [string]$build.character.className -and
    [int]$summary.SectionId -eq [int]$build.character.sectionId -and
    [string]$summary.SectionName -ceq [string]$build.character.sectionName) `
    -Detail "$($summary.Name) / $($summary.ClassName) / $($summary.SectionName)"

Add-Result -Name 'level experience and meseta' -Passed (
    [int]$summary.StoredLevel -eq [int]$build.character.storedLevel -and
    [int]$summary.DisplayedLevel -eq [int]$build.character.displayedLevel -and
    [long]$summary.Experience -eq [long]$build.character.experience -and
    [long]$summary.Meseta -eq [long]$build.character.meseta) `
    -Detail "level=$($summary.DisplayedLevel) exp=$($summary.Experience) meseta=$($summary.Meseta)"

$statsMatch = $true
foreach ($name in $expectedStats.Keys) {
    if ([int]$summary.Stats.$name -ne [int]$build.stats.$name) {
        $statsMatch = $false
    }
}
Add-Result -Name 'exact saved stats' -Passed $statsMatch `
    -Detail ($summary.Stats | ConvertTo-Json -Compress)

$integrityMatch = [int]$summary.CharacterValidationFlags -eq [int]$build.integrity.characterValidationFlags -and
    [string]$summary.SignatureHex -ceq [string]$build.integrity.signatureHex -and
    [int]$summary.VisualValidationFlags -eq [int]$build.integrity.visualValidationFlags -and
    [int]$summary.VisualVersion -eq [int]$build.integrity.visualVersion -and
    [long]$summary.VisualClassFlags -eq [long]$build.integrity.visualClassFlags -and
    [string]$summary.GuildCard.Name -ceq [string]$build.integrity.guildCardName -and
    [int]$summary.GuildCard.Present -eq [int]$build.integrity.guildCardPresent -and
    [int]$summary.GuildCard.SectionId -eq [int]$build.integrity.guildCardSectionId -and
    [int]$summary.GuildCard.ClassId -eq [int]$build.integrity.guildCardClassId -and
    [int]$summary.MaterialEncoding.HPRaw -eq [int]$build.integrity.hpMaterialRaw -and
    [int]$summary.MaterialEncoding.TPRaw -eq [int]$build.integrity.tpMaterialRaw -and
    [bool]$summary.MaterialEncoding.HPCanonical -and
    [bool]$summary.MaterialEncoding.TPCanonical
Add-Result -Name 'structural integrity and redundant identity' -Passed $integrityMatch `
    -Detail "visual=$($summary.VisualVersion)/$($summary.VisualClassFlags) guild=$($summary.GuildCard.Name)/$($summary.GuildCard.SectionId)/$($summary.GuildCard.ClassId) raw-materials=$($summary.MaterialEncoding.HPRaw)/$($summary.MaterialEncoding.TPRaw)"

$materialMatch = $true
foreach ($name in $expectedMaterials.Keys) {
    if ([int]$summary.Materials.$name -ne [int]$build.materials.$name) {
        $materialMatch = $false
    }
}
Add-Result -Name 'material plan' -Passed $materialMatch `
    -Detail ($summary.Materials | ConvertTo-Json -Compress)

$techniqueMatch = @($summary.Techniques).Count -eq 19
foreach ($expected in @($build.techniques)) {
    $matches = @($summary.Techniques | Where-Object {
            [int]$_.Id -eq [int]$expected.id -and
            [string]$_.Name -ceq [string]$expected.name -and
            [int]$_.DisplayedLevel -eq [int]$expected.displayedLevel
        })
    if ($matches.Count -ne 1) {
        $techniqueMatch = $false
    }
}
Add-Result -Name 'technique plan' -Passed $techniqueMatch `
    -Detail '19 exact maxed technique IDs, names, and displayed levels'

$inventoryStateMatch = [int]$summary.InventoryCount -eq $inventoryItems.Count -and
    ([int]$build.inventoryPolicy.capacity - [int]$summary.InventoryCount) -ge
        [int]$build.inventoryPolicy.minimumFreeSlots -and
    @($summary.InventoryItems | Where-Object {
            [int]$_.Present -ne 1 -or [int]$_.UnknownA1 -ne 0 -or
            [long]$_.Flags -notin @(0, 8)
        }).Count -eq 0
Add-Result -Name 'inventory capacity and exact flags' -Passed $inventoryStateMatch `
    -Detail "used=$($summary.InventoryCount) free=$([int]$build.inventoryPolicy.capacity - [int]$summary.InventoryCount)"

$itemMatch = $true
$itemDetails = [System.Collections.Generic.List[string]]::new()
foreach ($expected in @($build.items)) {
    $actual = if ([string]$expected.location -ceq 'Inventory') {
        @($summary.InventoryItems | Where-Object { [int]$_.Slot -eq [int]$expected.slot })
    } else {
        @($summary.BankItems | Where-Object { [int]$_.Slot -eq [int]$expected.slot })
    }
    $passed = $actual.Count -eq 1
    if ($passed) {
        $entry = $actual[0]
        $passed = [int]$entry.Present -eq 1 -and
            [string]$entry.PrimaryId -ceq [string]$expected.primaryId -and
            [string]$entry.CanonicalDescriptorHex -ceq [string]$expected.descriptorHex -and
            [string]$entry.Location -ceq [string]$expected.location
        if ([string]$expected.location -ceq 'Inventory') {
            $expectedFlags = if ([string]$expected.equippedSlot -ceq 'None') { 0 } else { 8 }
            $expectedUnitIndex = if ([string]$expected.equippedSlot -cmatch '^Unit([1-4])$') {
                [int]$Matches[1] - 1
            } else {
                $null
            }
            $passed = $passed -and
                [int]$entry.UnknownA1 -eq 0 -and
                [long]$entry.Flags -eq $expectedFlags -and
                [string]$entry.EquippedSlot -ceq [string]$expected.equippedSlot -and
                (($null -eq $expectedUnitIndex -and $null -eq $entry.UnitSlotIndex) -or
                    ($null -ne $expectedUnitIndex -and
                        [int]$entry.UnitSlotIndex -eq $expectedUnitIndex))
        } else {
            $passed = $passed -and [int]$entry.Amount -eq 1 -and
                -not [bool]$entry.Equipped -and
                [string]$entry.EquippedSlot -ceq 'None'
        }
    }
    if (-not $passed) {
        $itemMatch = $false
    }
    $itemDetails.Add("$($expected.location)#$($expected.slot):$($expected.name)=$passed")
}
Add-Result -Name 'exact owned item layout and canonical descriptors' -Passed $itemMatch `
    -Detail ([string]::Join('; ', $itemDetails))

$equippedItems = @($summary.InventoryItems | Where-Object { [bool]$_.Equipped })
$activeEquipmentMatch = $equippedItems.Count -eq 8
foreach ($slotName in $activeSlots.Keys) {
    $expectedItem = $itemByName[$activeSlots[$slotName]]
    $matches = @($equippedItems | Where-Object {
            [int]$_.Slot -eq [int]$expectedItem.slot -and
            [string]$_.EquippedSlot -ceq $slotName -and
            [string]$_.CanonicalDescriptorHex -ceq [string]$expectedItem.descriptorHex
        })
    if ($matches.Count -ne 1) {
        $activeEquipmentMatch = $false
    }
}
Add-Result -Name 'active loadout and no extra equipped items' -Passed $activeEquipmentMatch `
    -Detail "$($build.activeLoadoutId): $($equippedItems.Count) equipped slots"

$hashAfter = (Get-FileHash -LiteralPath $resolvedCharacterPath -Algorithm SHA256).Hash.ToLowerInvariant()
$buildHashAfter = (Get-FileHash -LiteralPath $resolvedBuildPath -Algorithm SHA256).Hash.ToLowerInvariant()
Add-Result -Name 'verification is read-only' -Passed (
    $hashBefore -ceq $hashAfter -and
    [string]$summary.Sha256 -ceq $hashBefore -and
    $buildHashBefore -ceq $buildHashAfter) `
    -Detail "character=$hashAfter contract=$buildHashAfter"

$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    throw "$($failed.Count) character-build verification check(s) failed"
}

[pscustomobject]@{
    Valid = $true
    ProfileId = [string]$build.profileId
    ActiveLoadoutId = [string]$build.activeLoadoutId
    SlotIndex = [int]$build.character.slotIndex
    CharacterPath = $resolvedCharacterPath
    CharacterSha256 = $hashAfter
    BuildPath = $resolvedBuildPath
    BuildSha256 = $buildHashAfter
    DisplayedLevel = [int]$summary.DisplayedLevel
    ExactOwnedItems = @($build.items).Count
    InventoryItems = $inventoryItems.Count
    BankItems = $bankItems.Count
    ChecksPassed = $results.Count
}
