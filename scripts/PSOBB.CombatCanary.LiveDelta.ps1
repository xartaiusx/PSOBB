Set-StrictMode -Version Latest

$script:PSOBBCharacterFileLength = 0x399C
$script:PSOBBInventoryCountOffset = 0x08
$script:PSOBBInventoryItemIdOffset = 0x20
$script:PSOBBInventoryItemStride = 0x1C
$script:PSOBBPlayTimeOffset = 0x4F0
$script:PSOBBMaximumInventoryItems = 30

function Get-PSOBBCombatCanaryUInt32LittleEndian {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidateRange(0, 67108860)][int]$Offset
    )

    if ($Offset -gt ($Bytes.Length - 4)) {
        throw 'The bounded character field is incomplete'
    }

    [uint32](
        [uint64]$Bytes[$Offset] +
        ([uint64]$Bytes[$Offset + 1] * 0x100) +
        ([uint64]$Bytes[$Offset + 2] * 0x10000) +
        ([uint64]$Bytes[$Offset + 3] * 0x1000000))
}

function Get-PSOBBCombatCanaryItemIdNamespace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$ItemId,
        [Parameter(Mandatory)]
        [ValidateRange(0, 29)]
        [int]$InventoryIndex
    )

    if ($ItemId -eq [uint32](0x00010000 + $InventoryIndex)) {
        return 'Game'
    }
    if ($ItemId -eq [uint32](0x10010000 + $InventoryIndex)) {
        return 'Lobby'
    }
    throw 'An active inventory item ID is outside the exact native client-slot-0 namespace'
}

function Compare-PSOBBCombatCanaryCharacterLiveDelta {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$ReferenceBytes,
        [Parameter(Mandatory)][byte[]]$CandidateBytes,
        [Parameter(Mandatory)]
        [ValidateRange(0, 3600)]
        [uint32]$MaximumPlayTimeDeltaSeconds
    )

    if ($ReferenceBytes.Length -ne $script:PSOBBCharacterFileLength -or
        $CandidateBytes.Length -ne $script:PSOBBCharacterFileLength) {
        throw 'The live character pair is not the exact PSOBB character-file size'
    }

    $referenceItemCount = [int]$ReferenceBytes[$script:PSOBBInventoryCountOffset]
    $candidateItemCount = [int]$CandidateBytes[$script:PSOBBInventoryCountOffset]
    if ($referenceItemCount -lt 1 -or
        $referenceItemCount -gt $script:PSOBBMaximumInventoryItems -or
        $candidateItemCount -ne $referenceItemCount) {
        throw 'The live character pair has an invalid or changed active inventory count'
    }

    $referenceNamespace = $null
    $candidateNamespace = $null
    for ($inventoryIndex = 0;
        $inventoryIndex -lt $referenceItemCount;
        $inventoryIndex++) {
        $itemIdOffset = $script:PSOBBInventoryItemIdOffset +
            ($inventoryIndex * $script:PSOBBInventoryItemStride)
        $referenceItemId = Get-PSOBBCombatCanaryUInt32LittleEndian `
            -Bytes $ReferenceBytes -Offset $itemIdOffset
        $candidateItemId = Get-PSOBBCombatCanaryUInt32LittleEndian `
            -Bytes $CandidateBytes -Offset $itemIdOffset
        $currentReferenceNamespace = Get-PSOBBCombatCanaryItemIdNamespace `
            -ItemId $referenceItemId -InventoryIndex $inventoryIndex
        $currentCandidateNamespace = Get-PSOBBCombatCanaryItemIdNamespace `
            -ItemId $candidateItemId -InventoryIndex $inventoryIndex

        if ($null -eq $referenceNamespace) {
            $referenceNamespace = $currentReferenceNamespace
            $candidateNamespace = $currentCandidateNamespace
        } elseif ($referenceNamespace -cne $currentReferenceNamespace -or
            $candidateNamespace -cne $currentCandidateNamespace) {
            throw 'The live character pair contains mixed inventory item-ID namespaces'
        }
    }

    $referencePlayTime = Get-PSOBBCombatCanaryUInt32LittleEndian `
        -Bytes $ReferenceBytes -Offset $script:PSOBBPlayTimeOffset
    $candidatePlayTime = Get-PSOBBCombatCanaryUInt32LittleEndian `
        -Bytes $CandidateBytes -Offset $script:PSOBBPlayTimeOffset
    if ($candidatePlayTime -lt $referencePlayTime) {
        throw 'The live character play time moved backward'
    }
    [uint64]$playTimeDelta = [uint64]$candidatePlayTime -
        [uint64]$referencePlayTime
    if ($playTimeDelta -gt [uint64]$MaximumPlayTimeDeltaSeconds) {
        throw 'The live character play-time delta exceeds its explicit bound'
    }

    $changedBytes = 0
    $inventoryItemIdChangedBytes = 0
    $playTimeChangedBytes = 0
    for ($offset = 0; $offset -lt $ReferenceBytes.Length; $offset++) {
        if ($ReferenceBytes[$offset] -eq $CandidateBytes[$offset]) {
            continue
        }

        $changedBytes++
        $relativeItemOffset = $offset - $script:PSOBBInventoryItemIdOffset
        $isActiveItemIdByte = $relativeItemOffset -ge 0 -and
            $relativeItemOffset -lt (
                $referenceItemCount * $script:PSOBBInventoryItemStride) -and
            ($relativeItemOffset % $script:PSOBBInventoryItemStride) -lt 4
        if ($isActiveItemIdByte) {
            $inventoryItemIdChangedBytes++
            continue
        }
        if ($offset -ge $script:PSOBBPlayTimeOffset -and
            $offset -lt ($script:PSOBBPlayTimeOffset + 4)) {
            $playTimeChangedBytes++
            continue
        }
        throw 'The live character changed outside the exact allowlist'
    }

    [pscustomobject]@{
        InventoryItems = $referenceItemCount
        ChangedBytes = $changedBytes
        InventoryItemIdChangedBytes = $inventoryItemIdChangedBytes
        PlayTimeChangedBytes = $playTimeChangedBytes
        PlayTimeDeltaSeconds = [uint32]$playTimeDelta
        MaximumPlayTimeDeltaSeconds = $MaximumPlayTimeDeltaSeconds
    }
}
