[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.RuntimeAclPolicy.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.Common.ps1')
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.LiveDelta.ps1')
$wrapperPath = Join-Path $repositoryRoot `
    'scripts\Test-PSOBBCombatCanaryLiveDelta.ps1'

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed
    )

    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed })
}

function Set-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][uint32]$Value
    )

    $Bytes[$Offset] = [byte]($Value -band 0xFF)
    $Bytes[$Offset + 1] = [byte](($Value -shr 8) -band 0xFF)
    $Bytes[$Offset + 2] = [byte](($Value -shr 16) -band 0xFF)
    $Bytes[$Offset + 3] = [byte](($Value -shr 24) -band 0xFF)
}

function New-CharacterBytes {
    param(
        [ValidateRange(1, 30)][int]$InventoryItems = 3,
        [ValidateSet('Game', 'Lobby')][string]$Namespace = 'Game',
        [uint32]$PlayTime = 100
    )

    $bytes = [byte[]]::new(0x399C)
    $bytes[0x08] = [byte]$InventoryItems
    $baseId = if ($Namespace -ceq 'Game') { 0x00010000 } else { 0x10010000 }
    for ($index = 0; $index -lt $InventoryItems; $index++) {
        Set-UInt32LittleEndian -Bytes $bytes `
            -Offset (0x20 + ($index * 0x1C)) `
            -Value ([uint32]($baseId + $index))
    }
    Set-UInt32LittleEndian -Bytes $bytes -Offset 0x4F0 -Value $PlayTime
    $bytes
}

function Test-Rejected {
    param(
        [Parameter(Mandatory)][byte[]]$Reference,
        [Parameter(Mandatory)][byte[]]$Candidate,
        [uint32]$MaximumPlayTimeDeltaSeconds = 600
    )

    try {
        [void](Compare-PSOBBCombatCanaryCharacterLiveDelta `
                -ReferenceBytes $Reference -CandidateBytes $Candidate `
                -MaximumPlayTimeDeltaSeconds $MaximumPlayTimeDeltaSeconds)
        $false
    } catch {
        $true
    }
}

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $wrapperPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
Add-Result 'canonical live-delta wrapper parses cleanly' (
    $parseErrors.Count -eq 0)

$alternateRuntimeError = $null
try {
    & $wrapperPath -RuntimeRoot $repositoryRoot -SnapshotPath 'not-used' `
        -MaximumPlayTimeDeltaSeconds 0 | Out-Null
} catch {
    $alternateRuntimeError = $_.Exception.Message
}
Add-Result 'alternate runtime fails closed with a redacted error' (
    $alternateRuntimeError -ceq
        'The live-delta verifier accepts only the canonical PSOBB runtime')

$aclFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('psobb-live-delta-acl-' + [Guid]::NewGuid().ToString('N'))
$aclFixturePath = Join-Path $aclFixtureRoot 'state.bin'
try {
    [void][System.IO.Directory]::CreateDirectory($aclFixtureRoot)
    [System.IO.File]::WriteAllBytes($aclFixturePath, [byte[]](1, 2, 3, 4))
    $ordinarySnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $aclFixturePath -Root $aclFixtureRoot -MaximumBytes 4 `
        -ExpectedLength 4 -RoleLabel 'synthetic live state' `
        -Consumer { param([byte[]]$Bytes) $Bytes.Length }
    Add-Result 'ordinary bounded snapshot remains available' (
        $ordinarySnapshot.Value -eq 4)

    $unprotectedRejected = $false
    try {
        [void](Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
                -LiteralPath $aclFixturePath -Root $aclFixtureRoot `
                -MaximumBytes 4 -ExpectedLength 4 `
                -RoleLabel 'synthetic live state' -RequireProtectedAcl `
                -Consumer { param([byte[]]$Bytes) $Bytes.Length })
    } catch {
        $unprotectedRejected = $_.Exception.Message -ceq
            'The synthetic live state does not have its protected file ACL'
    }
    Add-Result 'leased snapshot rejects an unprotected exact identity' (
        $unprotectedRejected)
} finally {
    if (Test-Path -LiteralPath $aclFixturePath) {
        Remove-Item -Force -LiteralPath $aclFixturePath
    }
    if (Test-Path -LiteralPath $aclFixtureRoot) {
        Remove-Item -Force -LiteralPath $aclFixtureRoot
    }
}

$reference = New-CharacterBytes
$identical = [byte[]]$reference.Clone()
$exact = Compare-PSOBBCombatCanaryCharacterLiveDelta `
    -ReferenceBytes $reference -CandidateBytes $identical `
    -MaximumPlayTimeDeltaSeconds 0
Add-Result 'identical exact character passes' (
    $exact.ChangedBytes -eq 0 -and $exact.InventoryItems -eq 3 -and
    $exact.PlayTimeDeltaSeconds -eq 0)

$lobby = New-CharacterBytes -Namespace Lobby
$namespaceDelta = Compare-PSOBBCombatCanaryCharacterLiveDelta `
    -ReferenceBytes $reference -CandidateBytes $lobby `
    -MaximumPlayTimeDeltaSeconds 0
Add-Result 'uniform game-to-lobby item-ID transition passes' (
    $namespaceDelta.ChangedBytes -eq 3 -and
    $namespaceDelta.InventoryItemIdChangedBytes -eq 3 -and
    $namespaceDelta.PlayTimeChangedBytes -eq 0)

$reverseNamespaceDelta = Compare-PSOBBCombatCanaryCharacterLiveDelta `
    -ReferenceBytes $lobby -CandidateBytes $reference `
    -MaximumPlayTimeDeltaSeconds 0
Add-Result 'uniform lobby-to-game item-ID transition passes' (
    $reverseNamespaceDelta.ChangedBytes -eq 3 -and
    $reverseNamespaceDelta.InventoryItemIdChangedBytes -eq 3)

$combined = New-CharacterBytes -Namespace Lobby -PlayTime 700
$combinedDelta = Compare-PSOBBCombatCanaryCharacterLiveDelta `
    -ReferenceBytes $reference -CandidateBytes $combined `
    -MaximumPlayTimeDeltaSeconds 600
Add-Result 'namespace plus maximum play-time delta passes' (
    $combinedDelta.PlayTimeDeltaSeconds -eq 600 -and
    $combinedDelta.InventoryItemIdChangedBytes -eq 3 -and
    $combinedDelta.PlayTimeChangedBytes -gt 0 -and
    $combinedDelta.ChangedBytes -eq (
        $combinedDelta.InventoryItemIdChangedBytes +
        $combinedDelta.PlayTimeChangedBytes))

$thirty = New-CharacterBytes -InventoryItems 30
Add-Result 'maximum exact inventory count passes' (-not (Test-Rejected `
        -Reference $thirty -Candidate ([byte[]]$thirty.Clone()) `
        -MaximumPlayTimeDeltaSeconds 0))

Add-Result 'short character rejected' (Test-Rejected `
    -Reference ([byte[]]::new(0x399B)) -Candidate $identical)
Add-Result 'long character rejected' (Test-Rejected `
    -Reference $reference -Candidate ([byte[]]::new(0x399D)))

$zeroCount = [byte[]]$reference.Clone()
$zeroCount[0x08] = 0
Add-Result 'zero inventory count rejected' (Test-Rejected `
    -Reference $zeroCount -Candidate ([byte[]]$zeroCount.Clone()))
$excessCount = [byte[]]$reference.Clone()
$excessCount[0x08] = 31
Add-Result 'excess inventory count rejected' (Test-Rejected `
    -Reference $excessCount -Candidate ([byte[]]$excessCount.Clone()))
$changedCount = [byte[]]$reference.Clone()
$changedCount[0x08] = 2
Add-Result 'changed inventory count rejected' (Test-Rejected `
    -Reference $reference -Candidate $changedCount)

$descriptorChange = [byte[]]$reference.Clone()
$descriptorChange[0x0C] = 1
Add-Result 'active item descriptor change rejected' (Test-Rejected `
    -Reference $reference -Candidate $descriptorChange)
$inactiveIdChange = [byte[]]$reference.Clone()
Set-UInt32LittleEndian -Bytes $inactiveIdChange -Offset (0x20 + (3 * 0x1C)) `
    -Value 0x00010003
Add-Result 'inactive item-ID change rejected' (Test-Rejected `
    -Reference $reference -Candidate $inactiveIdChange)
$choiceSearchChange = [byte[]]$reference.Clone()
$choiceSearchChange[0x2E28] = 1
Add-Result 'Choice Search change rejected' (Test-Rejected `
    -Reference $reference -Candidate $choiceSearchChange)
$saveCountChange = [byte[]]$reference.Clone()
$saveCountChange[0x4F8] = 1
Add-Result 'save-count change rejected' (Test-Rejected `
    -Reference $reference -Candidate $saveCountChange)

$badReferenceId = [byte[]]$reference.Clone()
Set-UInt32LittleEndian -Bytes $badReferenceId -Offset 0x20 -Value 3735928559
Add-Result 'invalid reference item ID rejected' (Test-Rejected `
    -Reference $badReferenceId -Candidate $identical)
$wrongCandidateIndex = [byte[]]$reference.Clone()
Set-UInt32LittleEndian -Bytes $wrongCandidateIndex -Offset (0x20 + 0x1C) `
    -Value 0x00010002
Add-Result 'wrong candidate item index rejected' (Test-Rejected `
    -Reference $reference -Candidate $wrongCandidateIndex)
$nonzeroClientId = [byte[]]$reference.Clone()
Set-UInt32LittleEndian -Bytes $nonzeroClientId -Offset 0x20 -Value 0x10210000
Add-Result 'nonzero lobby-client namespace rejected' (Test-Rejected `
    -Reference $reference -Candidate $nonzeroClientId)
$mixedNamespace = [byte[]]$reference.Clone()
Set-UInt32LittleEndian -Bytes $mixedNamespace -Offset 0x20 -Value 0x10010000
Add-Result 'mixed item-ID namespace rejected' (Test-Rejected `
    -Reference $reference -Candidate $mixedNamespace)

$playTimeRollback = New-CharacterBytes -PlayTime 99
Add-Result 'play-time rollback rejected' (Test-Rejected `
    -Reference $reference -Candidate $playTimeRollback)
$playTimeExcess = New-CharacterBytes -PlayTime 701
Add-Result 'play-time excess rejected' (Test-Rejected `
    -Reference $reference -Candidate $playTimeExcess `
    -MaximumPlayTimeDeltaSeconds 600)

$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
if ($failed.Count -ne 0) {
    throw "CombatCanary live-delta tests failed: $($failed.Name -join ', ')"
}

[pscustomobject]@{
    Suite = 'CombatCanaryLiveDelta'
    Passed = $results.Count
    Failed = 0
}
