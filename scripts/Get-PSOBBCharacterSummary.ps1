[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedLength = 0x399C
$expectedHeader = '9C39E70000000000'
$pathItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
if ($pathItem.PSProvider.Name -cne 'FileSystem' -or
    $pathItem.PSIsContainer -or
    $pathItem -isnot [System.IO.FileInfo] -or
    ($pathItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'PSOCHAR path must identify one ordinary non-reparse file'
}
$resolvedPath = [System.IO.Path]::GetFullPath($pathItem.FullName)
if ($pathItem.Length -ne $expectedLength) {
    throw "PSOCHAR length is invalid: expected $expectedLength bytes, found $($pathItem.Length)"
}

$stream = [System.IO.FileStream]::new(
    $resolvedPath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read)
try {
    if ($stream.Length -ne $expectedLength) {
        throw "PSOCHAR length changed during validation: expected $expectedLength bytes, found $($stream.Length)"
    }
    $bytes = [byte[]]::new($expectedLength)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -eq 0) {
            throw 'PSOCHAR length changed during validation: the file ended early'
        }
        $offset += $read
    }
    if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $expectedLength) {
        throw 'PSOCHAR length changed during validation: the file grew while being read'
    }
} finally {
    $stream.Dispose()
}

function Get-HexSlice {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$Count
    )

    if ($Offset -lt 0 -or $Count -lt 0 -or ($Offset + $Count) -gt $Data.Length) {
        throw "Hex slice is outside the character file: offset=$Offset count=$Count"
    }
    return -join @($Data[$Offset..($Offset + $Count - 1)] | ForEach-Object {
            $_.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
        })
}

function Read-UInt16LE {
    param([Parameter(Mandatory)][byte[]]$Data, [Parameter(Mandatory)][int]$Offset)

    if ($Offset -lt 0 -or ($Offset + 2) -gt $Data.Length) {
        throw "UInt16 read is outside the character file: offset=$Offset"
    }
    return [uint16]([uint16]$Data[$Offset] -bor
        ([uint16]$Data[$Offset + 1] -shl 8))
}

function Read-UInt32LE {
    param([Parameter(Mandatory)][byte[]]$Data, [Parameter(Mandatory)][int]$Offset)

    if ($Offset -lt 0 -or ($Offset + 4) -gt $Data.Length) {
        throw "UInt32 read is outside the character file: offset=$Offset"
    }
    return [uint32](
        [uint32]$Data[$Offset] -bor
        ([uint32]$Data[$Offset + 1] -shl 8) -bor
        ([uint32]$Data[$Offset + 2] -shl 16) -bor
        ([uint32]$Data[$Offset + 3] -shl 24))
}

function Read-MarkedUtf16Name {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$ByteCount
    )

    if ($Offset -lt 0 -or $ByteCount -lt 2 -or ($Offset + $ByteCount) -gt $Data.Length) {
        throw "Marked UTF-16 read is outside the character file: offset=$Offset count=$ByteCount"
    }
    $markedName = [System.Text.Encoding]::Unicode.GetString(
        $Data, $Offset, $ByteCount).TrimEnd([char]0)
    if ($markedName.Length -ge 2 -and $markedName[0] -eq "`t" -and
        $markedName[1] -ne 'C') {
        return $markedName.Substring(2)
    }
    return $markedName
}

function Get-PrimaryIdentifier {
    param([Parameter(Mandatory)][byte[]]$Data, [Parameter(Mandatory)][int]$Offset)

    $itemClass = [int]$Data[$Offset]
    $itemType = [int]$Data[$Offset + 1]
    $itemSubtype = [int]$Data[$Offset + 2]

    if ($itemClass -eq 0x04) {
        return '04000000'
    }
    if ($itemClass -eq 0x03 -and $itemType -eq 0x02) {
        return '0302{0:X2}{1:X2}' -f $Data[$Offset + 4], $itemSubtype
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

function Get-DescriptorHex {
    param([Parameter(Mandatory)][byte[]]$Data, [Parameter(Mandatory)][int]$Offset)

    return (Get-HexSlice -Data $Data -Offset $Offset -Count 12) +
        (Get-HexSlice -Data $Data -Offset ($Offset + 16) -Count 4)
}

function Get-CanonicalDescriptorHex {
    param([Parameter(Mandatory)][byte[]]$Data, [Parameter(Mandatory)][int]$Offset)

    $descriptor = [byte[]]::new(16)
    [System.Array]::Copy($Data, $Offset, $descriptor, 0, 12)
    [System.Array]::Copy($Data, $Offset + 16, $descriptor, 12, 4)
    if ($descriptor[0] -eq 0x01 -and $descriptor[1] -eq 0x03) {
        # Units encode their equipped armor slot in data1[4]. It is runtime
        # state, not part of the item's canonical descriptor.
        $descriptor[4] = 0
    }
    return -join @($descriptor | ForEach-Object {
            $_.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
        })
}

function Get-EquippedSlot {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint32]$Flags
    )

    if (($Flags -band 8) -eq 0) {
        return 'None'
    }

    $itemClass = [int]$Data[$Offset]
    $itemType = [int]$Data[$Offset + 1]
    if ($itemClass -eq 0x00) {
        return 'Weapon'
    }
    if ($itemClass -eq 0x02) {
        return 'Mag'
    }
    if ($itemClass -eq 0x01) {
        switch ($itemType) {
            0x01 { return 'Armor' }
            0x02 { return 'Shield' }
            0x03 {
                $unitIndex = [int]$Data[$Offset + 4]
                if ($unitIndex -ge 0 -and $unitIndex -le 3) {
                    return 'Unit{0}' -f ($unitIndex + 1)
                }
                return 'InvalidUnit'
            }
        }
    }
    return 'Invalid'
}

$header = Get-HexSlice -Data $bytes -Offset 0 -Count 8
if ($header -cne $expectedHeader) {
    throw "PSOCHAR header is invalid: expected $expectedHeader, found $header"
}

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

$classId = [int]$bytes[0x3A9]
$sectionId = [int]$bytes[0x3A8]
$className = if ($classId -lt $classNames.Count) { $classNames[$classId] } else { 'Unknown' }
$sectionName = if ($sectionId -lt $sectionNames.Count) { $sectionNames[$sectionId] } else { 'Unknown' }

$name = Read-MarkedUtf16Name -Data $bytes -Offset 0x3C8 -ByteCount 0x20
$guildCardName = Read-MarkedUtf16Name -Data $bytes -Offset 0x19CC -ByteCount 0x30

$techniques = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $techniqueNames.Count; $index++) {
    $baseLevel = [int]$bytes[0x4D0 + $index]
    $extensionLevel = [int]$bytes[0x0E + ($index * 0x1C)]
    $storedLevel = if ($baseLevel -eq 0xFF) { $null } else { $baseLevel + $extensionLevel }
    $techniques.Add([pscustomobject]@{
            Id = $index
            Name = $techniqueNames[$index]
            StoredLevel = $storedLevel
            DisplayedLevel = if ($null -eq $storedLevel) { $null } else { $storedLevel + 1 }
        })
}

$inventoryItems = [System.Collections.Generic.List[object]]::new()
$inventoryCount = [int]$bytes[0x08]
if ($inventoryCount -gt 30) {
    throw "Inventory item count is invalid: $inventoryCount"
}
for ($index = 0; $index -lt $inventoryCount; $index++) {
    $itemOffset = 0x0C + ($index * 0x1C)
    $dataOffset = $itemOffset + 8
    $flags = Read-UInt32LE -Data $bytes -Offset ($itemOffset + 4)
    $isUnit = $bytes[$dataOffset] -eq 0x01 -and $bytes[$dataOffset + 1] -eq 0x03
    $inventoryItems.Add([pscustomobject]@{
            Location = 'Inventory'
            Slot = $index + 1
            Present = [int]$bytes[$itemOffset]
            UnknownA1 = [int]$bytes[$itemOffset + 1]
            ExtensionData1 = [int]$bytes[$itemOffset + 2]
            ExtensionData2 = [int]$bytes[$itemOffset + 3]
            Flags = $flags
            PrimaryId = Get-PrimaryIdentifier -Data $bytes -Offset $dataOffset
            DescriptorHex = Get-DescriptorHex -Data $bytes -Offset $dataOffset
            CanonicalDescriptorHex = Get-CanonicalDescriptorHex -Data $bytes -Offset $dataOffset
            Equipped = ($flags -band 8) -ne 0
            EquippedSlot = Get-EquippedSlot -Data $bytes -Offset $dataOffset -Flags $flags
            UnitSlotIndex = if ($isUnit) { [int]$bytes[$dataOffset + 4] } else { $null }
            Amount = $null
        })
}

$bankItems = [System.Collections.Generic.List[object]]::new()
$bankCount = Read-UInt32LE -Data $bytes -Offset 0x700
if ($bankCount -gt 200) {
    throw "Bank item count is invalid: $bankCount"
}
for ($index = 0; $index -lt $bankCount; $index++) {
    $itemOffset = 0x708 + ($index * 0x18)
    $present = Read-UInt16LE -Data $bytes -Offset ($itemOffset + 0x16)
    $bankItems.Add([pscustomobject]@{
            Location = 'Bank'
            Slot = $index + 1
            Present = [int]$present
            UnknownA1 = $null
            ExtensionData1 = $null
            ExtensionData2 = $null
            Flags = $null
            PrimaryId = Get-PrimaryIdentifier -Data $bytes -Offset $itemOffset
            DescriptorHex = Get-DescriptorHex -Data $bytes -Offset $itemOffset
            CanonicalDescriptorHex = Get-CanonicalDescriptorHex -Data $bytes -Offset $itemOffset
            Equipped = $false
            EquippedSlot = 'None'
            UnitSlotIndex = $null
            Amount = Read-UInt16LE -Data $bytes -Offset ($itemOffset + 0x14)
        })
}

$materials = [ordered]@{
    Power = [int]$bytes[0x0EF]
    Mind = [int]$bytes[0x10B]
    Evade = [int]$bytes[0x127]
    Def = [int]$bytes[0x143]
    Luck = [int]$bytes[0x15F]
    HP = [int]($bytes[0x09] -shr 1)
    TP = [int]($bytes[0x0A] -shr 1)
}
$rawHpMaterials = [int]$bytes[0x09]
$rawTpMaterials = [int]$bytes[0x0A]

$allItems = @($inventoryItems) + @($bankItems)
[pscustomobject]@{
    Path = $resolvedPath
    Length = $bytes.Length
    Sha256 = ([System.Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
    Header = $header
    Name = $name
    ClassId = $classId
    ClassName = $className
    SectionId = $sectionId
    SectionName = $sectionName
    VisualValidationFlags = [int]$bytes[0x3AA]
    VisualVersion = [int]$bytes[0x3AB]
    VisualClassFlags = Read-UInt32LE -Data $bytes -Offset 0x3AC
    CharacterValidationFlags = Read-UInt32LE -Data $bytes -Offset 0x4E4
    SignatureHex = '{0:X8}' -f (Read-UInt32LE -Data $bytes -Offset 0x4EC)
    StoredLevel = Read-UInt32LE -Data $bytes -Offset 0x36C
    DisplayedLevel = (Read-UInt32LE -Data $bytes -Offset 0x36C) + 1
    Experience = Read-UInt32LE -Data $bytes -Offset 0x370
    Meseta = Read-UInt32LE -Data $bytes -Offset 0x374
    Stats = [pscustomobject]@{
        ATP = Read-UInt16LE -Data $bytes -Offset 0x354
        MST = Read-UInt16LE -Data $bytes -Offset 0x356
        EVP = Read-UInt16LE -Data $bytes -Offset 0x358
        HP = Read-UInt16LE -Data $bytes -Offset 0x35A
        DFP = Read-UInt16LE -Data $bytes -Offset 0x35C
        ATA = Read-UInt16LE -Data $bytes -Offset 0x35E
        LCK = Read-UInt16LE -Data $bytes -Offset 0x360
    }
    Materials = [pscustomobject]$materials
    MaterialEncoding = [pscustomobject]@{
        HPRaw = $rawHpMaterials
        TPRaw = $rawTpMaterials
        HPCanonical = (($rawHpMaterials -band 1) -eq 0)
        TPCanonical = (($rawTpMaterials -band 1) -eq 0)
    }
    GuildCard = [pscustomobject]@{
        Name = $guildCardName
        Present = [int]$bytes[0x1ACC]
        SectionId = [int]$bytes[0x1ACE]
        ClassId = [int]$bytes[0x1ACF]
    }
    Techniques = @($techniques)
    InventoryCount = $inventoryCount
    InventoryItems = @($inventoryItems)
    BankCount = $bankCount
    BankItems = @($bankItems)
    Items = $allItems
}
