[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Apply', 'Verify', 'Rollback')]
    [string]$Action,

    [string]$RuntimeRoot,

    [string]$BuildPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedBuildSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSourceSha256,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSourceBankSha256,

    [string]$TransactionPath,

    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSigningPublicKeySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$script:ExpectedCharacterLength = 0x399C
$script:ExpectedCharacterHeader = '9C39E70000000000'
$script:ExpectedNewservCommit = 'a649a4a146d04dba320bb579ac291527db0febb5'
$script:ExpectedNewservSourceArchiveSha256 =
    'c721731193a0cb5544871d810cdf29d9cd391d4233df032d8cc680520e7f287a'
$script:BuildFileName = 'twills-fonewearl-build.json'
$script:SummaryScript = Join-Path $PSScriptRoot 'Get-PSOBBCharacterSummary.ps1'
$script:BuildVerifierScript = Join-Path $PSScriptRoot 'Test-PSOBBCharacterBuild.ps1'
$script:BankVerifierScript = Join-Path $PSScriptRoot 'Test-PSOBBTwillsBank.ps1'
$script:RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Get-PSOBBProvisioningSha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    ([System.Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Read-PSOBBProvisioningBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 64MB)][long]$MaximumLength = 64MB
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt $MaximumLength) {
        throw "Provisioning input has an invalid size or filesystem type: $($item.FullName)"
    }
    [System.IO.File]::ReadAllBytes($item.FullName)
}

function ConvertFrom-PSOBBProvisioningHex {
    param(
        [Parameter(Mandatory)][string]$Hex,
        [Parameter(Mandatory)][ValidateRange(1, 1024)][int]$ExpectedBytes,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Hex -cnotmatch ('^(?:[0-9A-F]{2}){' + $ExpectedBytes + '}$')) {
        throw "$Label must be exactly $ExpectedBytes bytes of uppercase hexadecimal"
    }
    $bytes = [byte[]]::new($ExpectedBytes)
    for ($index = 0; $index -lt $ExpectedBytes; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    $bytes
}

function Set-PSOBBProvisioningUInt16LE {
    param([byte[]]$Data, [int]$Offset, [uint16]$Value)

    $Data[$Offset] = [byte]($Value -band 0xFF)
    $Data[$Offset + 1] = [byte](($Value -shr 8) -band 0xFF)
}

function Set-PSOBBProvisioningUInt32LE {
    param([byte[]]$Data, [int]$Offset, [uint32]$Value)

    for ($index = 0; $index -lt 4; $index++) {
        $Data[$Offset + $index] = [byte](($Value -shr ($index * 8)) -band 0xFF)
    }
}

function Get-PSOBBProvisioningUInt32LE {
    param([byte[]]$Data, [int]$Offset)

    if ($Offset -lt 0 -or ($Offset + 4) -gt $Data.Length) {
        throw "UInt32 read is outside provisioning data: offset=$Offset"
    }
    [uint32](
        [uint32]$Data[$Offset] -bor
        ([uint32]$Data[$Offset + 1] -shl 8) -bor
        ([uint32]$Data[$Offset + 2] -shl 16) -bor
        ([uint32]$Data[$Offset + 3] -shl 24))
}

function Get-PSOBBProvisioningHexSlice {
    param([byte[]]$Data, [int]$Offset, [int]$Count)

    -join @($Data[$Offset..($Offset + $Count - 1)] | ForEach-Object {
            $_.ToString('X2', [System.Globalization.CultureInfo]::InvariantCulture)
        })
}

function Assert-PSOBBProvisioningProtectedAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][bool]$IsContainer
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne $IsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Protected provisioning path has an invalid filesystem type: $($item.FullName)"
    }
    $acl = Get-Acl -LiteralPath $item.FullName
    if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) {
        throw "Provisioning path does not have a canonical protected DACL: $($item.FullName)"
    }
    $expectedSids = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-32-544',
        'S-1-5-18') | Sort-Object -Unique
    $rules = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]))
    $actualSids = @($rules | ForEach-Object {
            $_.IdentityReference.Value
        } | Sort-Object -Unique)
    if ($rules.Count -ne $expectedSids.Count -or
        $actualSids.Count -ne $expectedSids.Count -or
        @(Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids).Count -ne 0) {
        throw "Provisioning path DACL identities are not exact: $($item.FullName)"
    }
    $expectedInheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            [int64]$rule.FileSystemRights -ne
                [int64][System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None) {
            throw "Provisioning path DACL rule is not exact: $($item.FullName)"
        }
    }
    $item.FullName
}

function Assert-PSOBBProvisioningProcessesStopped {
    $running = @(Get-Process -ErrorAction Stop | Where-Object {
            $_.ProcessName -like 'newserv*' -or $_.ProcessName -ieq 'Psobb'
        })
    if ($running.Count -gt 0) {
        $identities = @($running | Sort-Object ProcessName, Id | ForEach-Object {
                '{0} PID {1}' -f $_.ProcessName, $_.Id
            })
        throw ('Twills provisioning requires every newserv and PSOBB client process ' +
            "to be stopped. Running: $($identities -join ', ')")
    }
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { [int]$_.LocalPort -in @(11000, 12000, 12001) })
    } catch {
        throw ('Cannot verify that the PSOBB TCP listeners are stopped: ' +
            $_.Exception.Message)
    }
    if ($listeners.Count -gt 0) {
        $listenerEvidence = @($listeners |
            Sort-Object LocalPort, LocalAddress, OwningProcess |
            ForEach-Object {
                '{0}:{1} PID {2}' -f $_.LocalAddress, $_.LocalPort,
                    $_.OwningProcess
            })
        throw ('Twills provisioning requires TCP ports 11000, 12000, and ' +
            "12001 to have no listeners. Listening: $($listenerEvidence -join ', ')")
    }
    $true
}

function Enter-PSOBBProvisioningLocks {
    param([Parameter(Mandatory)]$Layout)

    $marker = Assert-PSOBBRuntimeMarker -Layout $Layout
    $installationId = ([string]$marker.installationId).Replace('-', '')
    $serverMutex = [System.Threading.Mutex]::new(
        $false,
        ('Local\PSOBB.Newserv.Start.' + $installationId))
    $ownsServerMutex = $false
    $clientMutex = $null
    try {
        try {
            $ownsServerMutex = $serverMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsServerMutex = $true
        }
        if (-not $ownsServerMutex) {
            throw 'Another PSOBB server lifecycle operation is in progress'
        }
        $clientMutex = Enter-PSOBBClientOperationLock -Layout $Layout -TimeoutSeconds 0
        [pscustomobject]@{
            ServerMutex = $serverMutex
            OwnsServerMutex = $true
            ClientMutex = $clientMutex
        }
    } catch {
        if ($clientMutex) {
            Exit-PSOBBClientOperationLock -Mutex $clientMutex
        }
        if ($ownsServerMutex) {
            $serverMutex.ReleaseMutex()
        }
        $serverMutex.Dispose()
        throw
    }
}

function Exit-PSOBBProvisioningLocks {
    param([Parameter(Mandatory)]$Locks)

    if ($Locks.ClientMutex) {
        Exit-PSOBBClientOperationLock -Mutex $Locks.ClientMutex
    }
    if ($Locks.OwnsServerMutex) {
        $Locks.ServerMutex.ReleaseMutex()
    }
    $Locks.ServerMutex.Dispose()
}

function Get-PSOBBProvisioningBuild {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )

    $canonicalPath = [System.IO.Path]::GetFullPath(
        (Join-Path $script:RepositoryRoot ('config\' + $script:BuildFileName)))
    $resolvedPath = [System.IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $Path).Path)
    if (-not $resolvedPath.Equals(
            $canonicalPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Only the canonical Twills FOnewearl contract may be used: $canonicalPath"
    }
    $bytes = Read-PSOBBProvisioningBytes -Path $resolvedPath -MaximumLength 128KB
    $hash = Get-PSOBBProvisioningSha256Bytes -Bytes $bytes
    if ($hash -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'The Twills FOnewearl contract does not match the explicitly pinned SHA-256'
    }
    try {
        $build = [System.Text.Encoding]::UTF8.GetString($bytes) |
            ConvertFrom-Json -Depth 30
    } catch {
        throw "The Twills FOnewearl contract is not valid JSON: $($_.Exception.Message)"
    }
    if ([int]$build.schemaVersion -ne 2 -or
        [string]$build.character.name -cne 'Twills' -or
        [int]$build.character.classId -ne 8 -or
        [string]$build.character.className -cne 'FOnewearl' -or
        [int]$build.character.slotIndex -ne 0 -or
        [string]$build.integrity.guildCardName -cne 'Twills' -or
        [int]$build.integrity.guildCardClassId -ne 8 -or
        [int]$build.character.displayedLevel -ne 200 -or
        [int]$build.character.storedLevel -ne 199) {
        throw 'The pinned build is not the exact slot-0 Twills FOnewearl level-200 contract'
    }

    $sourceLockPath = Join-Path $script:RepositoryRoot 'config\sources.lock.json'
    $sourceLockBytes = Read-PSOBBProvisioningBytes -Path $sourceLockPath -MaximumLength 1MB
    try {
        $sourceLock = [System.Text.Encoding]::UTF8.GetString($sourceLockBytes) |
            ConvertFrom-Json -Depth 30
    } catch {
        throw 'The source lock is not valid JSON'
    }
    $sourceComponents = @($sourceLock.components | Where-Object {
            [string]$_.id -ceq 'newserv-stable-source'
        })
    if ($sourceComponents.Count -ne 1 -or
        [string]$sourceComponents[0].commit -cne $script:ExpectedNewservCommit -or
        [string]$sourceComponents[0].sha256 -cne
            $script:ExpectedNewservSourceArchiveSha256) {
        throw 'The PSOCHAR writer layout is not bound to the approved newserv source lock'
    }

    [pscustomobject]@{
        Path = $resolvedPath
        Bytes = $bytes
        Sha256 = $hash
        Value = $build
    }
}

function Assert-PSOBBProvisioningBuildStillPinned {
    param([Parameter(Mandatory)]$BuildRecord)

    $currentBytes = Read-PSOBBProvisioningBytes `
        -Path $BuildRecord.Path -MaximumLength 128KB
    if ((Get-PSOBBProvisioningSha256Bytes -Bytes $currentBytes) -cne
        [string]$BuildRecord.Sha256) {
        throw 'The pinned Twills contract changed during the provisioning operation'
    }
    $true
}

function Get-PSOBBProvisioningCharacterPath {
    param([Parameter(Mandatory)]$Layout)

    $playersRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Server 'system\players') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $playersRoot -PathType Container)) {
        throw "The protected players directory is missing: $playersRoot"
    }
    Assert-PSOBBProvisioningProtectedAcl -Path $playersRoot -IsContainer $true |
        Out-Null
    $slotZero = @(Get-ChildItem -LiteralPath $playersRoot -Force -File |
        Where-Object { $_.Name -cmatch '^player_.+_0\.psochar$' })
    if ($slotZero.Count -ne 1) {
        throw "Expected exactly one slot-0 PSOCHAR file, found $($slotZero.Count)"
    }
    $safePath = Assert-PathWithinRoot -Path $slotZero[0].FullName -Root $playersRoot
    Assert-PSOBBProvisioningProtectedAcl -Path $safePath -IsContainer $false |
        Out-Null
    $safePath
}

function Get-PSOBBProvisioningBankPath {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$CharacterPath
    )

    $playersRoot = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Server 'system\players') `
        -Root $Layout.Root
    $characterLeaf = Split-Path -Leaf $CharacterPath
    if ($characterLeaf -cnotmatch '^(player_.+_0)\.psochar$') {
        throw 'The Twills character filename cannot identify its slot-0 bank'
    }
    $bankPath = Assert-PathWithinRoot `
        -Path (Join-Path $playersRoot ($Matches[1] + '.psobank')) `
        -Root $playersRoot
    if (-not (Test-Path -LiteralPath $bankPath -PathType Leaf)) {
        throw "The authoritative slot-0 Twills PSOBANK file is missing: $bankPath"
    }
    Assert-PSOBBProvisioningProtectedAcl -Path $bankPath -IsContainer $false |
        Out-Null
    $bankPath
}

function Assert-PSOBBProvisioningIdentity {
    param(
        [Parameter(Mandatory)]$Summary,
        [Parameter(Mandatory)]$Build,
        [Parameter(Mandatory)][string]$Path
    )

    $leaf = Split-Path -Leaf $Path
    if ($leaf -cnotmatch '^player_.+_0\.psochar$' -or
        [string]$Summary.Name -cne 'Twills' -or
        [int]$Summary.ClassId -ne 8 -or
        [string]$Summary.ClassName -cne 'FOnewearl' -or
        [int]$Summary.SectionId -ne [int]$Build.character.sectionId -or
        [string]$Summary.SectionName -cne [string]$Build.character.sectionName -or
        [string]$Summary.GuildCard.Name -cne 'Twills' -or
        [int]$Summary.GuildCard.Present -ne 1 -or
        [int]$Summary.GuildCard.ClassId -ne 8 -or
        [int]$Summary.GuildCard.SectionId -ne [int]$Build.character.sectionId -or
        [int]$Summary.VisualValidationFlags -ne
            [int]$Build.integrity.visualValidationFlags -or
        [int]$Summary.VisualVersion -ne [int]$Build.integrity.visualVersion -or
        [uint32]$Summary.VisualClassFlags -ne
            [uint32]$Build.integrity.visualClassFlags -or
        [uint32]$Summary.CharacterValidationFlags -ne
            [uint32]$Build.integrity.characterValidationFlags -or
        [string]$Summary.SignatureHex -cne [string]$Build.integrity.signatureHex) {
        throw 'The target is not the exact existing slot-0 Twills FOnewearl identity'
    }
    $true
}

function Assert-PSOBBProvisioningDescriptorSlot {
    param(
        [Parameter(Mandatory)][byte[]]$Descriptor,
        [Parameter(Mandatory)][string]$EquippedSlot,
        [Parameter(Mandatory)][string]$ItemName
    )

    $expectedSlot = switch ($EquippedSlot) {
        'None' { $null }
        'Weapon' { @(0x00) }
        'Armor' { @(0x01, 0x01) }
        'Shield' { @(0x01, 0x02) }
        'Mag' { @(0x02) }
        { $_ -cmatch '^Unit[1-4]$' } { @(0x01, 0x03) }
        default { throw "Unsupported equipped slot for $ItemName`: $EquippedSlot" }
    }
    if ($EquippedSlot -cne 'None') {
        $expectedBytes = @($expectedSlot)
        for ($index = 0; $index -lt $expectedBytes.Count; $index++) {
            if ($Descriptor[$index] -ne $expectedBytes[$index]) {
                throw "$ItemName cannot be equipped in $EquippedSlot"
            }
        }
    }
    if ($Descriptor[0] -eq 0x01 -and $Descriptor[1] -eq 0x03 -and
        $Descriptor[4] -ne 0) {
        throw "$ItemName does not use a canonical zeroed unit-slot descriptor"
    }
}

function Add-PSOBBProvisioningAllowedRange {
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[int]]$Allowed,
        [int]$Offset,
        [int]$Count
    )

    for ($index = 0; $index -lt $Count; $index++) {
        [void]$Allowed.Add($Offset + $index)
    }
}

function New-PSOBBProvisionedCharacterBytes {
    param(
        [Parameter(Mandatory)][byte[]]$SourceBytes,
        [Parameter(Mandatory)]$Build,
        [Parameter(Mandatory)]
        [ValidateRange(0, 999999)]
        [uint32]$AuthoritativeBankMeseta
    )

    if ($SourceBytes.Length -ne $script:ExpectedCharacterLength -or
        (Get-PSOBBProvisioningHexSlice -Data $SourceBytes -Offset 0 -Count 8) -cne
            $script:ExpectedCharacterHeader) {
        throw 'The source PSOCHAR length or command header is invalid'
    }
    $target = [byte[]]$SourceBytes.Clone()
    $allowed = [System.Collections.Generic.HashSet[int]]::new()

    $inventoryItems = @($Build.items | Where-Object {
            [string]$_.location -ceq 'Inventory'
        } | Sort-Object { [int]$_.slot })
    $bankItems = @($Build.items | Where-Object {
            [string]$_.location -ceq 'Bank'
        } | Sort-Object { [int]$_.slot })
    if ($inventoryItems.Count -gt 30 -or $bankItems.Count -gt 200 -or
        $inventoryItems.Count -gt
            ([int]$Build.inventoryPolicy.capacity -
                [int]$Build.inventoryPolicy.minimumFreeSlots)) {
        throw 'The pinned build exceeds the PSOBB inventory or bank capacity policy'
    }
    for ($index = 0; $index -lt $inventoryItems.Count; $index++) {
        if ([int]$inventoryItems[$index].slot -ne ($index + 1)) {
            throw 'The pinned inventory contract must use consecutive one-based slots'
        }
    }
    for ($index = 0; $index -lt $bankItems.Count; $index++) {
        if ([int]$bankItems[$index].slot -ne ($index + 1)) {
            throw 'The pinned bank contract must use consecutive one-based slots'
        }
    }

    $target[0x08] = [byte]$inventoryItems.Count
    $target[0x09] = [byte]$Build.integrity.hpMaterialRaw
    $target[0x0A] = [byte]$Build.integrity.tpMaterialRaw
    Add-PSOBBProvisioningAllowedRange -Allowed $allowed -Offset 0x08 -Count 3

    $materialNames = @('Power', 'Mind', 'Evade', 'Def', 'Luck')
    for ($index = 0; $index -lt $materialNames.Count; $index++) {
        $offset = 0x0C + ((8 + $index) * 0x1C) + 3
        $target[$offset] = [byte]$Build.materials.($materialNames[$index])
        [void]$allowed.Add($offset)
    }

    foreach ($technique in @($Build.techniques)) {
        $id = [int]$technique.id
        if ($id -lt 0 -or $id -gt 18) {
            throw "The provisioning writer does not own technique stripe $id"
        }
        $storedLevel = [int]$technique.displayedLevel - 1
        $baseLevel = [Math]::Min($storedLevel, 0x0E)
        $extensionLevel = [Math]::Max(0, $storedLevel - 0x0E)
        $baseOffset = 0x4D0 + $id
        $extensionOffset = 0x0E + ($id * 0x1C)
        $target[$baseOffset] = [byte]$baseLevel
        $target[$extensionOffset] = [byte]$extensionLevel
        [void]$allowed.Add($baseOffset)
        [void]$allowed.Add($extensionOffset)
    }

    foreach ($entry in @(
            @{ Name = 'ATP'; Offset = 0x354 },
            @{ Name = 'MST'; Offset = 0x356 },
            @{ Name = 'EVP'; Offset = 0x358 },
            @{ Name = 'HP'; Offset = 0x35A },
            @{ Name = 'DFP'; Offset = 0x35C },
            @{ Name = 'ATA'; Offset = 0x35E },
            @{ Name = 'LCK'; Offset = 0x360 })) {
        Set-PSOBBProvisioningUInt16LE -Data $target -Offset $entry.Offset `
            -Value ([uint16]$Build.stats.($entry.Name))
        Add-PSOBBProvisioningAllowedRange -Allowed $allowed `
            -Offset $entry.Offset -Count 2
    }
    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 0x36C `
        -Value ([uint32]$Build.character.storedLevel)
    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 0x370 `
        -Value ([uint32]$Build.character.experience)
    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 0x374 `
        -Value ([uint32]$Build.character.meseta)
    Add-PSOBBProvisioningAllowedRange -Allowed $allowed -Offset 0x36C -Count 12

    $usedIds = [System.Collections.Generic.HashSet[uint32]]::new()
    for ($index = 0; $index -lt $inventoryItems.Count; $index++) {
        $item = $inventoryItems[$index]
        $descriptor = ConvertFrom-PSOBBProvisioningHex `
            -Hex ([string]$item.descriptorHex) -ExpectedBytes 16 `
            -Label ([string]$item.name)
        $equippedSlot = [string]$item.equippedSlot
        Assert-PSOBBProvisioningDescriptorSlot -Descriptor $descriptor `
            -EquippedSlot $equippedSlot -ItemName ([string]$item.name)
        if ($equippedSlot -cmatch '^Unit([1-4])$') {
            $descriptor[4] = [byte]([int]$Matches[1] - 1)
        }
        $itemOffset = 0x0C + ($index * 0x1C)
        $dataOffset = $itemOffset + 8
        if ($SourceBytes[$itemOffset + 1] -ne 0) {
            throw ('The target inventory slot has nonzero unknown_a1 state that ' +
                "cannot be changed safely: slot $($index + 1)")
        }
        $target[$itemOffset] = 1
        Set-PSOBBProvisioningUInt32LE -Data $target -Offset ($itemOffset + 4) `
            -Value ([uint32]($(if ($equippedSlot -ceq 'None') { 0 } else { 8 })))
        [System.Array]::Copy($descriptor, 0, $target, $dataOffset, 12)
        $itemId = [uint32](0x71000000 + $index + 1)
        if (-not $usedIds.Add($itemId)) {
            throw 'The deterministic inventory item-ID allocation collided'
        }
        Set-PSOBBProvisioningUInt32LE -Data $target `
            -Offset ($dataOffset + 12) -Value $itemId
        [System.Array]::Copy($descriptor, 12, $target, $dataOffset + 16, 4)
        [void]$allowed.Add($itemOffset)
        Add-PSOBBProvisioningAllowedRange -Allowed $allowed `
            -Offset ($itemOffset + 4) -Count 24
    }

    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 0x700 `
        -Value ([uint32]$bankItems.Count)
    Add-PSOBBProvisioningAllowedRange -Allowed $allowed -Offset 0x700 -Count 4
    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 0x704 `
        -Value $AuthoritativeBankMeseta
    Add-PSOBBProvisioningAllowedRange -Allowed $allowed -Offset 0x704 -Count 4
    for ($index = 0; $index -lt $bankItems.Count; $index++) {
        $item = $bankItems[$index]
        if ([string]$item.equippedSlot -cne 'None') {
            throw "Bank item $($item.name) cannot be equipped"
        }
        $descriptor = ConvertFrom-PSOBBProvisioningHex `
            -Hex ([string]$item.descriptorHex) -ExpectedBytes 16 `
            -Label ([string]$item.name)
        Assert-PSOBBProvisioningDescriptorSlot -Descriptor $descriptor `
            -EquippedSlot 'None' -ItemName ([string]$item.name)
        $itemOffset = 0x708 + ($index * 0x18)
        [System.Array]::Copy($descriptor, 0, $target, $itemOffset, 12)
        $itemId = [uint32](0x72000000 + $index + 1)
        if (-not $usedIds.Add($itemId)) {
            throw 'The deterministic bank item-ID allocation collided'
        }
        Set-PSOBBProvisioningUInt32LE -Data $target `
            -Offset ($itemOffset + 12) -Value $itemId
        [System.Array]::Copy($descriptor, 12, $target, $itemOffset + 16, 4)
        $amount = if ($descriptor[0] -eq 0x03 -and
            $descriptor[1] -ne 0x02 -and $descriptor[5] -gt 0) {
            [uint16]$descriptor[5]
        } else {
            [uint16]1
        }
        Set-PSOBBProvisioningUInt16LE -Data $target `
            -Offset ($itemOffset + 20) -Value $amount
        Set-PSOBBProvisioningUInt16LE -Data $target `
            -Offset ($itemOffset + 22) -Value 1
        Add-PSOBBProvisioningAllowedRange -Allowed $allowed `
            -Offset $itemOffset -Count 24
    }

    for ($index = 0; $index -lt $SourceBytes.Length; $index++) {
        if ($SourceBytes[$index] -ne $target[$index] -and
            -not $allowed.Contains($index)) {
            throw ('The staged Twills save changed a byte outside the authoritative ' +
                ('PSOCHAR write map at offset 0x{0:X}' -f $index))
        }
    }
    if ((Get-PSOBBProvisioningHexSlice -Data $target -Offset 0 -Count 8) -cne
            $script:ExpectedCharacterHeader -or
        $target.Length -ne $SourceBytes.Length) {
        throw 'The staged Twills save changed its length or command header'
    }

    [pscustomobject]@{
        Bytes = $target
        Sha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $target
        InventoryCount = $inventoryItems.Count
        BankCount = $bankItems.Count
        ChangedByteCount = @($allowed | Where-Object {
                $SourceBytes[$_] -ne $target[$_]
            }).Count
        UniqueItemIds = $usedIds.Count
    }
}

function New-PSOBBProvisionedBankBytes {
    param(
        [Parameter(Mandatory)][byte[]]$SourceBytes,
        [Parameter(Mandatory)]$Build
    )

    if ($SourceBytes.Length -lt 8 -or $SourceBytes.Length -gt (8 + (200 * 0x18))) {
        throw 'The source slot-0 PSOBANK length is invalid'
    }
    $sourceCount = Get-PSOBBProvisioningUInt32LE -Data $SourceBytes -Offset 0
    $sourceMeseta = Get-PSOBBProvisioningUInt32LE -Data $SourceBytes -Offset 4
    if ($sourceCount -gt 200 -or
        $SourceBytes.Length -ne (8 + ([int]$sourceCount * 0x18)) -or
        $sourceMeseta -gt 999999) {
        throw 'The source slot-0 PSOBANK count, length, or Meseta is invalid'
    }
    $bankItems = @($Build.items | Where-Object {
            [string]$_.location -ceq 'Bank'
        } | Sort-Object { [int]$_.slot })
    if ($bankItems.Count -gt 200) {
        throw 'The pinned build exceeds the PSOBANK item capacity'
    }
    $target = [byte[]]::new(8 + ($bankItems.Count * 0x18))
    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 0 `
        -Value ([uint32]$bankItems.Count)
    Set-PSOBBProvisioningUInt32LE -Data $target -Offset 4 `
        -Value $sourceMeseta
    $usedIds = [System.Collections.Generic.HashSet[uint32]]::new()
    for ($index = 0; $index -lt $bankItems.Count; $index++) {
        $item = $bankItems[$index]
        if ([int]$item.slot -ne ($index + 1) -or
            [string]$item.equippedSlot -cne 'None') {
            throw 'The pinned bank contract must use consecutive unequipped slots'
        }
        $descriptor = ConvertFrom-PSOBBProvisioningHex `
            -Hex ([string]$item.descriptorHex) -ExpectedBytes 16 `
            -Label ([string]$item.name)
        Assert-PSOBBProvisioningDescriptorSlot -Descriptor $descriptor `
            -EquippedSlot 'None' -ItemName ([string]$item.name)
        $offset = 8 + ($index * 0x18)
        [System.Array]::Copy($descriptor, 0, $target, $offset, 12)
        $itemId = [uint32](0x72000000 + $index + 1)
        if (-not $usedIds.Add($itemId)) {
            throw 'The deterministic PSOBANK item-ID allocation collided'
        }
        Set-PSOBBProvisioningUInt32LE -Data $target `
            -Offset ($offset + 12) -Value $itemId
        [System.Array]::Copy($descriptor, 12, $target, $offset + 16, 4)
        Set-PSOBBProvisioningUInt16LE -Data $target `
            -Offset ($offset + 20) -Value 1
        Set-PSOBBProvisioningUInt16LE -Data $target `
            -Offset ($offset + 22) -Value 1
    }
    [pscustomobject]@{
        Bytes = $target
        Sha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $target
        SourceMeseta = $sourceMeseta
        BankCount = $bankItems.Count
        UniqueItemIds = $usedIds.Count
    }
}

function Test-PSOBBProvisioningCharacterBuild {
    param(
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)]$BuildRecord
    )

    $output = @(& $script:BuildVerifierScript `
            -Path $CharacterPath -BuildPath $BuildRecord.Path)
    $result = @($output | Where-Object {
            $_.PSObject.Properties.Name -contains 'Valid'
        })
    if ($result.Count -ne 1 -or -not [bool]$result[0].Valid -or
        [string]$result[0].BuildSha256 -cne $BuildRecord.Sha256) {
        throw 'Independent Twills character-build verification did not return one exact valid result'
    }
    $characterBytes = Read-PSOBBProvisioningBytes `
        -Path $CharacterPath -MaximumLength $script:ExpectedCharacterLength
    $characterHash = Get-PSOBBProvisioningSha256Bytes -Bytes $characterBytes
    if ([string]$result[0].CharacterSha256 -cne $characterHash) {
        throw 'Independent Twills character-build verification did not bind the staged bytes'
    }
    if ((Get-PSOBBProvisioningSha256Bytes `
                -Bytes (Read-PSOBBProvisioningBytes -Path $BuildRecord.Path `
                    -MaximumLength 128KB)) -cne $BuildRecord.Sha256) {
        throw 'The pinned Twills contract changed during independent verification'
    }
    $result[0]
}

function Test-PSOBBProvisioningBankBuild {
    param(
        [Parameter(Mandatory)][string]$BankPath,
        [Parameter(Mandatory)]$BuildRecord
    )

    $result = & $script:BankVerifierScript -Path $BankPath `
        -BuildPath $BuildRecord.Path `
        -ExpectedBuildSha256 $BuildRecord.Sha256
    if ($null -eq $result -or -not [bool]$result.Valid -or
        [string]$result.BuildSha256 -cne $BuildRecord.Sha256) {
        throw 'Independent slot-0 Twills bank verification did not return one exact valid result'
    }
    $result
}

function Get-PSOBBProvisioningTrustFingerprint {
    param([string]$ExplicitFingerprint)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitFingerprint)) {
        return $ExplicitFingerprint.ToLowerInvariant()
    }
    $trustPath = Join-Path $script:RepositoryRoot 'config\release-trust.json'
    $trustBytes = Read-PSOBBProvisioningBytes -Path $trustPath -MaximumLength 64KB
    try {
        $trust = [System.Text.Encoding]::UTF8.GetString($trustBytes) |
            ConvertFrom-Json -Depth 10
    } catch {
        throw 'The release trust policy is not valid JSON'
    }
    $keys = @($trust.keys | Where-Object {
            [string]$_.id -ceq [string]$trust.activeKeyId
        })
    if ($keys.Count -ne 1 -or
        [string]$keys[0].spkiSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The release trust policy does not identify one active signing key'
    }
    [string]$keys[0].spkiSha256
}

function Get-PSOBBProvisioningPublicKey {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$ExpectedFingerprint
    )

    $publicKeyPath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Stable 'release-public-key.pem') `
        -Root $Layout.Root
    $publicBytes = Read-PSOBBProvisioningBytes -Path $publicKeyPath -MaximumLength 16KB
    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportFromPem([System.Text.Encoding]::UTF8.GetString($publicBytes))
        $fingerprint = Get-PSOBBProvisioningSha256Bytes `
            -Bytes $verifier.ExportSubjectPublicKeyInfo()
        if ($fingerprint -cne $ExpectedFingerprint) {
            throw 'The runtime signing public key does not match its explicit trust pin'
        }
        [pscustomobject]@{
            Path = $publicKeyPath
            Fingerprint = $fingerprint
            PemBytes = $publicBytes
        }
    } finally {
        $verifier.Dispose()
    }
}

function New-PSOBBProvisioningSignature {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][byte[]]$ManifestBytes,
        [Parameter(Mandatory)]$PublicKey
    )

    $privateKeyPath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Secrets 'local-acceptance-signing-private.pem') `
        -Root $Layout.Root
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $privateKeyPath -IsContainer $false | Out-Null
    $privateBytes = Read-PSOBBProvisioningBytes -Path $privateKeyPath -MaximumLength 16KB
    $signer = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $signer.ImportFromPem([System.Text.Encoding]::UTF8.GetString($privateBytes))
        $fingerprint = Get-PSOBBProvisioningSha256Bytes `
            -Bytes $signer.ExportSubjectPublicKeyInfo()
        if ($fingerprint -cne $PublicKey.Fingerprint) {
            throw 'The protected transaction signing key does not match the trusted public key'
        }
        $signature = $signer.SignData(
            $ManifestBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
        if ($signature.Length -ne 64) {
            throw 'The transaction manifest signature is not an ECDSA P-256 P1363 signature'
        }
        $signature
    } finally {
        $signer.Dispose()
    }
}

function Test-PSOBBProvisioningSignature {
    param(
        [Parameter(Mandatory)][byte[]]$ManifestBytes,
        [Parameter(Mandatory)][byte[]]$Signature,
        [Parameter(Mandatory)]$PublicKey
    )

    if ($Signature.Length -ne 64) {
        return $false
    }
    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportFromPem(
            [System.Text.Encoding]::UTF8.GetString($PublicKey.PemBytes))
        $verifier.VerifyData(
            $ManifestBytes,
            $Signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    } finally {
        $verifier.Dispose()
    }
}

function Write-PSOBBProvisioningCreateOnlyBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Root
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    if (Test-Path -LiteralPath $safePath) {
        throw "Refusing to overwrite create-only provisioning evidence: $safePath"
    }
    $parent = Split-Path -Parent $safePath
    $temporary = Assert-PathWithinRoot `
        -Path (Join-Path $parent ('.twills-' + [Guid]::NewGuid().ToString('N') + '.new')) `
        -Root $Root
    try {
        [System.IO.File]::WriteAllBytes($temporary, $Bytes)
        Set-PSOBBProtectedAcl -Path $temporary
        Assert-PSOBBProvisioningProtectedAcl -Path $temporary -IsContainer $false |
            Out-Null
        if ((Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $temporary)) -cne
                (Get-PSOBBProvisioningSha256Bytes -Bytes $Bytes)) {
            throw "Provisioning evidence staging changed bytes: $safePath"
        }
        [System.IO.File]::Move($temporary, $safePath)
        Assert-PSOBBProvisioningProtectedAcl -Path $safePath -IsContainer $false |
            Out-Null
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Write-PSOBBProvisioningJournalEntry {
    param(
        [Parameter(Mandatory)][string]$TransactionRoot,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$TransactionId,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$ManifestSha256,
        [Parameter(Mandatory)][string]$CharacterSha256,
        [Parameter(Mandatory)][string]$BankSha256
    )

    $entry = [ordered]@{
        schemaVersion = 1
        transactionId = $TransactionId
        state = $State
        recordedAtUtc = [DateTime]::UtcNow.ToString('o')
        manifestSha256 = $ManifestSha256
        characterSha256 = $CharacterSha256
        bankSha256 = $BankSha256
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($entry | ConvertTo-Json -Depth 5))
    Write-PSOBBProvisioningCreateOnlyBytes `
        -Path (Join-Path $TransactionRoot ('journal\' + $FileName)) `
        -Bytes $bytes -Root $TransactionRoot
}

function Test-PSOBBProvisioningJournalEntry {
    param(
        [Parameter(Mandatory)][string]$TransactionRoot,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$TransactionId,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$ManifestSha256,
        [Parameter(Mandatory)][string]$CharacterSha256,
        [Parameter(Mandatory)][string]$BankSha256
    )

    $path = Assert-PathWithinRoot `
        -Path (Join-Path $TransactionRoot ('journal\' + $FileName)) `
        -Root $TransactionRoot
    if (-not (Test-Path -LiteralPath $path)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Provisioning journal evidence is not an ordinary file: $path"
    }
    Assert-PSOBBProvisioningProtectedAcl -Path $path -IsContainer $false |
        Out-Null
    try {
        $entry = [System.Text.Encoding]::UTF8.GetString(
            (Read-PSOBBProvisioningBytes -Path $path -MaximumLength 16KB)) |
            ConvertFrom-Json -Depth 5
    } catch {
        throw "Provisioning journal evidence is invalid JSON: $path"
    }
    if ([int]$entry.schemaVersion -ne 1 -or
        [string]$entry.transactionId -cne $TransactionId -or
        [string]$entry.state -cne $State -or
        [string]$entry.manifestSha256 -cne $ManifestSha256 -or
        [string]$entry.characterSha256 -cne $CharacterSha256 -or
        [string]$entry.bankSha256 -cne $BankSha256 -or
        [string]::IsNullOrWhiteSpace([string]$entry.recordedAtUtc)) {
        throw "Provisioning journal evidence does not match the sealed transaction: $path"
    }
    $true
}

function Get-PSOBBProvisioningRollbackJournalState {
    param([Parameter(Mandatory)]$Transaction)

    $common = @{
        TransactionRoot = $Transaction.Path
        TransactionId = [string]$Transaction.Manifest.transactionId
        ManifestSha256 = $Transaction.ManifestSha256
    }
    [pscustomobject]@{
        Prepared = Test-PSOBBProvisioningJournalEntry @common `
            -FileName '000-prepared.json' -State 'prepared' `
            -CharacterSha256 ([string]$Transaction.Manifest.sourceSha256) `
            -BankSha256 ([string]$Transaction.Manifest.sourceBankSha256)
        Applied = Test-PSOBBProvisioningJournalEntry @common `
            -FileName '001-applied.json' -State 'applied' `
            -CharacterSha256 ([string]$Transaction.Manifest.provisionedSha256) `
            -BankSha256 ([string]$Transaction.Manifest.provisionedBankSha256)
        ApplyFailedRolledBack = Test-PSOBBProvisioningJournalEntry @common `
            -FileName '001-apply-failed-rolled-back.json' `
            -State 'apply-failed-rolled-back' `
            -CharacterSha256 ([string]$Transaction.Manifest.sourceSha256) `
            -BankSha256 ([string]$Transaction.Manifest.sourceBankSha256)
        RollbackIntent = Test-PSOBBProvisioningJournalEntry @common `
            -FileName '001-rollback-intent.json' `
            -State 'rollback-intent' `
            -CharacterSha256 ([string]$Transaction.Manifest.provisionedSha256) `
            -BankSha256 ([string]$Transaction.Manifest.provisionedBankSha256)
        RolledBack = Test-PSOBBProvisioningJournalEntry @common `
            -FileName '002-rolled-back.json' -State 'rolled-back' `
            -CharacterSha256 ([string]$Transaction.Manifest.sourceSha256) `
            -BankSha256 ([string]$Transaction.Manifest.sourceBankSha256)
    }
}

function Assert-PSOBBProvisioningRollbackJournalState {
    param(
        [Parameter(Mandatory)]$Transaction,
        [Parameter(Mandatory)]$JournalState,
        [Parameter(Mandatory)][string]$CharacterSha256,
        [Parameter(Mandatory)][string]$BankSha256
    )

    if (-not $JournalState.Prepared) {
        throw 'Rollback requires the exact create-only prepared journal entry'
    }
    $predecessors = @(
        if ($JournalState.Applied) { 'Applied' }
        if ($JournalState.ApplyFailedRolledBack) { 'ApplyFailedRolledBack' }
        if ($JournalState.RollbackIntent) { 'RollbackIntent' })
    if ($predecessors.Count -gt 1) {
        throw ('Rollback refuses conflicting validated 001 journal states: ' +
            ($predecessors -join ', '))
    }
    if ($JournalState.RolledBack -and $predecessors.Count -ne 1) {
        throw 'Rollback refuses a final 002 journal entry without one exact 001 predecessor'
    }
    $isSourcePair =
        $CharacterSha256 -ceq [string]$Transaction.Manifest.sourceSha256 -and
        $BankSha256 -ceq [string]$Transaction.Manifest.sourceBankSha256
    $isProvisionedPair =
        $CharacterSha256 -ceq [string]$Transaction.Manifest.provisionedSha256 -and
        $BankSha256 -ceq [string]$Transaction.Manifest.provisionedBankSha256
    $isMixedPair =
        ($CharacterSha256 -ceq [string]$Transaction.Manifest.sourceSha256 -and
            $BankSha256 -ceq [string]$Transaction.Manifest.provisionedBankSha256) -or
        ($CharacterSha256 -ceq [string]$Transaction.Manifest.provisionedSha256 -and
            $BankSha256 -ceq [string]$Transaction.Manifest.sourceBankSha256)
    if (-not $isSourcePair -and -not $isProvisionedPair -and -not $isMixedPair) {
        throw 'Rollback refuses a Twills pair outside the exact signed source/after matrix'
    }
    if (($JournalState.ApplyFailedRolledBack -or $JournalState.RolledBack) -and
        -not $isSourcePair) {
        throw 'Rollback journal state is incompatible with the current Twills pair hashes'
    }
    [pscustomobject]@{
        IsSourcePair = $isSourcePair
        IsProvisionedPair = $isProvisionedPair
        IsMixedPair = $isMixedPair
        Predecessor = if ($predecessors.Count -eq 1) {
            $predecessors[0]
        } else {
            'None'
        }
    }
}

function New-PSOBBProvisioningTransaction {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)][string]$BankPath,
        [Parameter(Mandatory)][byte[]]$SourceBytes,
        [Parameter(Mandatory)][byte[]]$SourceBankBytes,
        [Parameter(Mandatory)]$Provisioned,
        [Parameter(Mandatory)]$ProvisionedBank,
        [Parameter(Mandatory)]$BuildRecord,
        [Parameter(Mandatory)]$PublicKey
    )

    $transactionParent = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Backups 'twills-provisioning') `
        -Root $Layout.Backups
    if (-not (Test-Path -LiteralPath $transactionParent)) {
        New-Item -ItemType Directory -Path $transactionParent | Out-Null
        Set-PSOBBProtectedAcl -Path $transactionParent
    }
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $transactionParent -IsContainer $true | Out-Null

    $transactionId = [Guid]::NewGuid().ToString('D')
    $name = 'twills-slot0-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') +
        '-' + $transactionId.Substring(0, 8)
    $finalRoot = Assert-PathWithinRoot `
        -Path (Join-Path $transactionParent $name) -Root $transactionParent
    $partialRoot = Assert-PathWithinRoot `
        -Path ($finalRoot + '.partial') -Root $transactionParent
    if ((Test-Path -LiteralPath $finalRoot) -or
        (Test-Path -LiteralPath $partialRoot)) {
        throw 'The unique Twills transaction path already exists'
    }
    $complete = $false
    try {
        New-Item -ItemType Directory -Path $partialRoot | Out-Null
        Set-PSOBBProtectedAcl -Path $partialRoot
        foreach ($directoryName in @('before', 'after', 'contract', 'journal', 'trust')) {
            $directoryPath = Join-Path $partialRoot $directoryName
            New-Item -ItemType Directory -Path $directoryPath | Out-Null
            Set-PSOBBProtectedAcl -Path $directoryPath
        }
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'before\player_twills_0.psochar') `
            -Bytes $SourceBytes -Root $partialRoot
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'before\player_twills_0.psobank') `
            -Bytes $SourceBankBytes -Root $partialRoot
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'after\player_twills_0.psochar') `
            -Bytes $Provisioned.Bytes -Root $partialRoot
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'after\player_twills_0.psobank') `
            -Bytes $ProvisionedBank.Bytes -Root $partialRoot
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot ('contract\' + $script:BuildFileName)) `
            -Bytes $BuildRecord.Bytes -Root $partialRoot
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'trust\signing-public-key.pem') `
            -Bytes $PublicKey.PemBytes -Root $partialRoot

        $relativeTarget = [System.IO.Path]::GetRelativePath(
            $Layout.Root,
            $CharacterPath).Replace('\', '/')
        $relativeBankTarget = [System.IO.Path]::GetRelativePath(
            $Layout.Root,
            $BankPath).Replace('\', '/')
        $manifest = [ordered]@{
            schemaVersion = 2
            transactionId = $transactionId
            createdAtUtc = [DateTime]::UtcNow.ToString('o')
            operation = 'ProvisionTwillsSlot0FOnewearl'
            character = [ordered]@{
                name = 'Twills'
                classId = 8
                className = 'FOnewearl'
                slotIndex = 0
            }
            targetRelativePath = $relativeTarget
            bankTargetRelativePath = $relativeBankTarget
            sourceSha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $SourceBytes
            sourceBankSha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $SourceBankBytes
            provisionedSha256 = $Provisioned.Sha256
            provisionedBankSha256 = $ProvisionedBank.Sha256
            build = [ordered]@{
                fileName = $script:BuildFileName
                archivedPath = 'contract/' + $script:BuildFileName
                size = $BuildRecord.Bytes.Length
                schemaVersion = [int]$BuildRecord.Value.schemaVersion
                profileId = [string]$BuildRecord.Value.profileId
                sha256 = $BuildRecord.Sha256
            }
            newservSource = [ordered]@{
                commit = $script:ExpectedNewservCommit
                archiveSha256 = $script:ExpectedNewservSourceArchiveSha256
            }
            format = [ordered]@{
                length = $script:ExpectedCharacterLength
                headerHex = $script:ExpectedCharacterHeader
                changedByteCount = [int]$Provisioned.ChangedByteCount
                inventoryCount = [int]$Provisioned.InventoryCount
                bankCount = [int]$Provisioned.BankCount
                uniqueItemIds = [int]$Provisioned.UniqueItemIds
                bankFileLength = [int]$ProvisionedBank.Bytes.Length
                bankMeseta = [uint32]$ProvisionedBank.SourceMeseta
            }
            evidence = @(
                [ordered]@{
                    path = 'before/player_twills_0.psochar'
                    size = $script:ExpectedCharacterLength
                    sha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $SourceBytes
                },
                [ordered]@{
                    path = 'before/player_twills_0.psobank'
                    size = $SourceBankBytes.Length
                    sha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $SourceBankBytes
                },
                [ordered]@{
                    path = 'after/player_twills_0.psochar'
                    size = $script:ExpectedCharacterLength
                    sha256 = $Provisioned.Sha256
                },
                [ordered]@{
                    path = 'after/player_twills_0.psobank'
                    size = $ProvisionedBank.Bytes.Length
                    sha256 = $ProvisionedBank.Sha256
                },
                [ordered]@{
                    path = 'contract/' + $script:BuildFileName
                    size = $BuildRecord.Bytes.Length
                    sha256 = $BuildRecord.Sha256
                },
                [ordered]@{
                    path = 'trust/signing-public-key.pem'
                    size = $PublicKey.PemBytes.Length
                    sha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $PublicKey.PemBytes
                })
            signing = [ordered]@{
                archivedPublicKeyPath = 'trust/signing-public-key.pem'
                archivedPublicKeySize = $PublicKey.PemBytes.Length
                algorithm = 'ECDSA-P256-SHA256-P1363'
                publicKeySha256 = $PublicKey.Fingerprint
            }
        }
        $manifestBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            ($manifest | ConvertTo-Json -Depth 10))
        $manifestSha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $manifestBytes
        $signature = New-PSOBBProvisioningSignature `
            -Layout $Layout -ManifestBytes $manifestBytes -PublicKey $PublicKey
        if (-not (Test-PSOBBProvisioningSignature `
                -ManifestBytes $manifestBytes -Signature $signature `
                -PublicKey $PublicKey)) {
            throw 'The sealed transaction manifest signature did not self-verify'
        }
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'manifest.json') `
            -Bytes $manifestBytes -Root $partialRoot
        Write-PSOBBProvisioningCreateOnlyBytes `
            -Path (Join-Path $partialRoot 'manifest.sig') `
            -Bytes ([System.Text.Encoding]::ASCII.GetBytes(
                    [Convert]::ToBase64String($signature))) `
            -Root $partialRoot
        Write-PSOBBProvisioningJournalEntry `
            -TransactionRoot $partialRoot -FileName '000-prepared.json' `
            -TransactionId $transactionId -State 'prepared' `
            -ManifestSha256 $manifestSha256 `
            -CharacterSha256 ([string]$manifest.sourceSha256) `
            -BankSha256 ([string]$manifest.sourceBankSha256)

        [System.IO.Directory]::Move($partialRoot, $finalRoot)
        $complete = $true
        [pscustomobject]@{
            Path = $finalRoot
            Id = $transactionId
            Manifest = $manifest
            ManifestSha256 = $manifestSha256
        }
    } finally {
        if (-not $complete -and (Test-Path -LiteralPath $partialRoot)) {
            Remove-Item -LiteralPath $partialRoot -Recurse -Force
        }
    }
}

function Invoke-PSOBBProvisioningAtomicReplacement {
    param(
        [Parameter(Mandatory)][string]$CharacterPath,
        [Parameter(Mandatory)][byte[]]$ReplacementBytes,
        [Parameter(Mandatory)][string]$ExpectedCurrentSha256,
        [Parameter(Mandatory)][string]$ExpectedReplacementSha256,
        [Parameter(Mandatory)][string]$PlayersRoot
    )

    $safeCharacterPath = Assert-PathWithinRoot `
        -Path $CharacterPath -Root $PlayersRoot
    if (-not $safeCharacterPath.Equals(
            [System.IO.Path]::GetFullPath($CharacterPath),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The slot-0 Twills replacement target changed path identity'
    }
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $safeCharacterPath -IsContainer $false | Out-Null
    $currentBytes = Read-PSOBBProvisioningBytes `
        -Path $safeCharacterPath -MaximumLength $script:ExpectedCharacterLength
    if ((Get-PSOBBProvisioningSha256Bytes -Bytes $currentBytes) -cne
            $ExpectedCurrentSha256) {
        throw 'The slot-0 Twills save changed immediately before atomic replacement'
    }
    $stagingPath = Assert-PathWithinRoot `
        -Path (Join-Path $PlayersRoot (
                '.twills-slot0-' + [Guid]::NewGuid().ToString('N') + '.new')) `
        -Root $PlayersRoot
    $emergencyPath = Assert-PathWithinRoot `
        -Path (Join-Path $PlayersRoot (
                '.twills-slot0-' + [Guid]::NewGuid().ToString('N') + '.rollback')) `
        -Root $PlayersRoot
    $replacementCommitted = $false
    try {
        [System.IO.File]::WriteAllBytes($stagingPath, $ReplacementBytes)
        Set-PSOBBProtectedAcl -Path $stagingPath
        Assert-PSOBBProvisioningProtectedAcl -Path $stagingPath -IsContainer $false |
            Out-Null
        if ((Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $stagingPath)) -cne
                $ExpectedReplacementSha256) {
            throw 'The adjacent Twills replacement staging file changed bytes'
        }
        $lastMomentPath = Assert-PathWithinRoot `
            -Path $CharacterPath -Root $PlayersRoot
        if (-not $lastMomentPath.Equals(
                $safeCharacterPath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The slot-0 Twills replacement target changed during staging'
        }
        Assert-PSOBBProvisioningProtectedAcl `
            -Path $lastMomentPath -IsContainer $false | Out-Null
        $lastMomentHash = Get-PSOBBProvisioningSha256Bytes `
            -Bytes (Read-PSOBBProvisioningBytes `
                -Path $lastMomentPath -MaximumLength $script:ExpectedCharacterLength)
        if ($lastMomentHash -cne $ExpectedCurrentSha256) {
            throw 'The slot-0 Twills save changed during replacement staging'
        }
        Assert-PSOBBProvisioningProcessesStopped | Out-Null
        [System.IO.File]::Replace(
            $stagingPath,
            $lastMomentPath,
            $emergencyPath,
            $true)
        $replacementCommitted = $true
        $replacedHash = Get-PSOBBProvisioningSha256Bytes `
            -Bytes (Read-PSOBBProvisioningBytes -Path $safeCharacterPath `
                -MaximumLength $script:ExpectedCharacterLength)
        $emergencyHash = Get-PSOBBProvisioningSha256Bytes `
            -Bytes (Read-PSOBBProvisioningBytes -Path $emergencyPath `
                -MaximumLength $script:ExpectedCharacterLength)
        if ($replacedHash -cne $ExpectedReplacementSha256 -or
            $emergencyHash -cne $ExpectedCurrentSha256) {
            throw 'Atomic Twills replacement did not produce the exact before/after byte pair'
        }
        Assert-PSOBBProvisioningProtectedAcl `
            -Path $safeCharacterPath -IsContainer $false | Out-Null
        [pscustomobject]@{
            EmergencyPath = $emergencyPath
            CurrentSha256 = $replacedHash
        }
    } catch {
        $replacementError = $_
        if ($replacementCommitted) {
            try {
                if (-not (Test-Path -LiteralPath $emergencyPath -PathType Leaf)) {
                    throw 'Atomic replacement recovery file is missing'
                }
                $currentHash = Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $safeCharacterPath)
                $emergencyHash = Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $emergencyPath)
                if ($currentHash -cne $ExpectedReplacementSha256 -or
                    $emergencyHash -cne $ExpectedCurrentSha256) {
                    throw 'Atomic replacement recovery bytes are not the expected pair'
                }
                $recoveryTargetPath = Assert-PathWithinRoot `
                    -Path $CharacterPath -Root $PlayersRoot
                if (-not $recoveryTargetPath.Equals(
                        $safeCharacterPath,
                        [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw 'The slot-0 Twills recovery target changed path identity'
                }
                Assert-PSOBBProvisioningProtectedAcl `
                    -Path $recoveryTargetPath -IsContainer $false | Out-Null
                $recoveryCurrentHash = Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $recoveryTargetPath)
                $recoveryEmergencyHash = Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $emergencyPath)
                if ($recoveryCurrentHash -cne $ExpectedReplacementSha256 -or
                    $recoveryEmergencyHash -cne $ExpectedCurrentSha256) {
                    throw 'Atomic replacement recovery bytes changed before restoration'
                }
                Assert-PSOBBProvisioningProcessesStopped | Out-Null
                $failedPath = Assert-PathWithinRoot `
                    -Path (Join-Path $PlayersRoot (
                            '.twills-slot0-' + [Guid]::NewGuid().ToString('N') + '.failed')) `
                    -Root $PlayersRoot
                [System.IO.File]::Replace(
                    $emergencyPath,
                    $recoveryTargetPath,
                    $failedPath,
                    $true)
                $restoredHash = Get-PSOBBProvisioningSha256Bytes `
                    -Bytes (Read-PSOBBProvisioningBytes -Path $safeCharacterPath)
                if ($restoredHash -cne $ExpectedCurrentSha256) {
                    throw 'Atomic replacement recovery did not restore the original hash'
                }
                Remove-Item -LiteralPath $failedPath -Force `
                    -ErrorAction SilentlyContinue
            } catch {
                throw ('Atomic replacement failed after commit and exact recovery also ' +
                    "failed. Replacement error: $($replacementError.Exception.Message) " +
                    "Recovery error: $($_.Exception.Message) Recovery path: $emergencyPath")
            }
        }
        throw $replacementError
    } finally {
        Remove-Item -LiteralPath $stagingPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PSOBBProvisioningPairedReplacement {
    param(
        [Parameter(Mandatory)][object[]]$Files,
        [Parameter(Mandatory)][string]$PlayersRoot
    )

    $completed = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($file in $Files) {
            $replacement = Invoke-PSOBBProvisioningAtomicReplacement `
                -CharacterPath ([string]$file.Path) `
                -ReplacementBytes ([byte[]]$file.ReplacementBytes) `
                -ExpectedCurrentSha256 ([string]$file.CurrentSha256) `
                -ExpectedReplacementSha256 ([string]$file.ReplacementSha256) `
                -PlayersRoot $PlayersRoot
            $completed.Add([pscustomobject]@{
                    Name = [string]$file.Name
                    Path = [string]$file.Path
                    OriginalBytes = [byte[]]$file.OriginalBytes
                    OriginalSha256 = [string]$file.CurrentSha256
                    ReplacementSha256 = [string]$file.ReplacementSha256
                    EmergencyPath = [string]$replacement.EmergencyPath
                })
        }
        [pscustomobject]@{
            Completed = @($completed)
        }
    } catch {
        $pairError = $_
        $compensationErrors = [System.Collections.Generic.List[string]]::new()
        for ($index = $completed.Count - 1; $index -ge 0; $index--) {
            $entry = $completed[$index]
            try {
                $compensation = Invoke-PSOBBProvisioningAtomicReplacement `
                    -CharacterPath $entry.Path `
                    -ReplacementBytes $entry.OriginalBytes `
                    -ExpectedCurrentSha256 $entry.ReplacementSha256 `
                    -ExpectedReplacementSha256 $entry.OriginalSha256 `
                    -PlayersRoot $PlayersRoot
                Remove-Item -LiteralPath $compensation.EmergencyPath -Force `
                    -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $entry.EmergencyPath -Force `
                    -ErrorAction SilentlyContinue
            } catch {
                $compensationErrors.Add(
                    "$($entry.Name): $($_.Exception.Message)")
            }
        }
        if ($compensationErrors.Count -gt 0) {
            throw ('The paired Twills character/bank replacement failed, and exact ' +
                "compensation was incomplete. Pair error: $($pairError.Exception.Message) " +
                "Compensation errors: $($compensationErrors -join '; ')")
        }
        $pairError.Exception.Data['PSOBBPairCompletedBeforeFailure'] = $completed.Count
        $pairError.Exception.Data['PSOBBPairCompensated'] = $true
        throw $pairError
    }
}

function Remove-PSOBBProvisioningPairEmergencyFiles {
    param([Parameter(Mandatory)]$Pair)

    foreach ($entry in @($Pair.Completed)) {
        Remove-Item -LiteralPath ([string]$entry.EmergencyPath) -Force
    }
}

function Assert-PSOBBProvisioningExactProperties {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if ($actual.Count -ne $expectedSorted.Count -or
        @(Compare-Object -ReferenceObject $expectedSorted `
            -DifferenceObject $actual).Count -ne 0) {
        throw "$Label does not have the exact sealed schema"
    }
    $true
}

function Read-PSOBBProvisioningTransaction {
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedBuildHash,
        [Parameter(Mandatory)][string]$ExpectedPublicKeyFingerprint
    )

    $transactionParent = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Backups 'twills-provisioning') `
        -Root $Layout.Backups
    $safeRoot = Assert-PathWithinRoot -Path $Path -Root $transactionParent
    $rootItem = Get-Item -LiteralPath $safeRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $rootItem.Name -cnotmatch '^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$') {
        throw 'The rollback path is not an exact sealed Twills slot-0 transaction'
    }
    Assert-PSOBBProvisioningProtectedAcl -Path $safeRoot -IsContainer $true |
        Out-Null
    foreach ($directoryName in @('before', 'after', 'contract', 'journal', 'trust')) {
        $directoryPath = Assert-PathWithinRoot `
            -Path (Join-Path $safeRoot $directoryName) -Root $safeRoot
        Assert-PSOBBProvisioningProtectedAcl `
            -Path $directoryPath -IsContainer $true | Out-Null
    }
    $archivedPublicKeyPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'trust\signing-public-key.pem') -Root $safeRoot
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $archivedPublicKeyPath -IsContainer $false | Out-Null
    $archivedPublicKeyBytes = Read-PSOBBProvisioningBytes `
        -Path $archivedPublicKeyPath -MaximumLength 16KB
    $keyVerifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $keyVerifier.ImportFromPem(
            [System.Text.Encoding]::UTF8.GetString($archivedPublicKeyBytes))
        $archivedPublicKeyFingerprint = Get-PSOBBProvisioningSha256Bytes `
            -Bytes $keyVerifier.ExportSubjectPublicKeyInfo()
    } catch {
        throw 'The archived Twills transaction public key is not valid ECDSA PEM'
    } finally {
        $keyVerifier.Dispose()
    }
    if ($archivedPublicKeyFingerprint -cne
        $ExpectedPublicKeyFingerprint.ToLowerInvariant()) {
        throw 'The archived Twills transaction public key does not match its explicit caller pin'
    }
    $publicKey = [pscustomobject]@{
        Path = $archivedPublicKeyPath
        Fingerprint = $archivedPublicKeyFingerprint
        PemBytes = $archivedPublicKeyBytes
    }

    $manifestPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'manifest.json') -Root $safeRoot
    $signaturePath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'manifest.sig') -Root $safeRoot
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $manifestPath -IsContainer $false | Out-Null
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $signaturePath -IsContainer $false | Out-Null
    $manifestBytes = Read-PSOBBProvisioningBytes `
        -Path $manifestPath -MaximumLength 128KB
    $signatureText = [System.Text.Encoding]::ASCII.GetString(
        (Read-PSOBBProvisioningBytes -Path $signaturePath -MaximumLength 1KB))
    try {
        $signature = [Convert]::FromBase64String($signatureText)
    } catch {
        throw 'The sealed Twills transaction signature is not valid Base64'
    }
    if (-not (Test-PSOBBProvisioningSignature `
            -ManifestBytes $manifestBytes -Signature $signature `
            -PublicKey $PublicKey)) {
        throw 'The sealed Twills transaction signature is invalid'
    }
    try {
        $manifest = [System.Text.Encoding]::UTF8.GetString($manifestBytes) |
            ConvertFrom-Json -Depth 20
    } catch {
        throw 'The sealed Twills transaction manifest is not valid JSON'
    }
    Assert-PSOBBProvisioningExactProperties -Value $manifest -Label 'Transaction manifest' `
        -Expected @('schemaVersion', 'transactionId', 'createdAtUtc', 'operation',
            'character', 'targetRelativePath', 'bankTargetRelativePath',
            'sourceSha256', 'sourceBankSha256', 'provisionedSha256',
            'provisionedBankSha256', 'build', 'newservSource', 'format',
            'evidence', 'signing') | Out-Null
    Assert-PSOBBProvisioningExactProperties -Value $manifest.character `
        -Label 'Transaction character' `
        -Expected @('name', 'classId', 'className', 'slotIndex') | Out-Null
    Assert-PSOBBProvisioningExactProperties -Value $manifest.build `
        -Label 'Transaction build' `
        -Expected @('fileName', 'archivedPath', 'size', 'schemaVersion',
            'profileId', 'sha256') | Out-Null
    Assert-PSOBBProvisioningExactProperties -Value $manifest.newservSource `
        -Label 'Transaction source metadata' `
        -Expected @('commit', 'archiveSha256') | Out-Null
    Assert-PSOBBProvisioningExactProperties -Value $manifest.format `
        -Label 'Transaction format metadata' `
        -Expected @('length', 'headerHex', 'changedByteCount', 'inventoryCount',
            'bankCount', 'uniqueItemIds', 'bankFileLength', 'bankMeseta') | Out-Null
    Assert-PSOBBProvisioningExactProperties -Value $manifest.signing `
        -Label 'Transaction signing metadata' `
        -Expected @('archivedPublicKeyPath', 'archivedPublicKeySize',
            'algorithm', 'publicKeySha256') | Out-Null
    if ([int]$manifest.schemaVersion -ne 2 -or
        [string]$manifest.operation -cne 'ProvisionTwillsSlot0FOnewearl' -or
        [string]$manifest.character.name -cne 'Twills' -or
        [int]$manifest.character.classId -ne 8 -or
        [string]$manifest.character.className -cne 'FOnewearl' -or
        [int]$manifest.character.slotIndex -ne 0 -or
        [string]$manifest.build.fileName -cne $script:BuildFileName -or
        [string]$manifest.build.archivedPath -cne
            ('contract/' + $script:BuildFileName) -or
        [int64]$manifest.build.size -le 0 -or
        [int64]$manifest.build.size -gt 128KB -or
        [int]$manifest.build.schemaVersion -ne 2 -or
        [string]::IsNullOrWhiteSpace([string]$manifest.build.profileId) -or
        [string]$manifest.build.sha256 -cne $ExpectedBuildHash -or
        [string]$manifest.newservSource.commit -cnotmatch '^[a-f0-9]{40}$' -or
        [string]$manifest.newservSource.archiveSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.signing.archivedPublicKeyPath -cne
            'trust/signing-public-key.pem' -or
        [int64]$manifest.signing.archivedPublicKeySize -ne
            $archivedPublicKeyBytes.Length -or
        [string]$manifest.signing.algorithm -cne 'ECDSA-P256-SHA256-P1363' -or
        [string]$manifest.signing.publicKeySha256 -cne $PublicKey.Fingerprint -or
        [int64]$manifest.format.length -ne $script:ExpectedCharacterLength -or
        [string]$manifest.format.headerHex -cne $script:ExpectedCharacterHeader -or
        [int64]$manifest.format.bankFileLength -lt 8 -or
        [int64]$manifest.format.bankFileLength -gt (8 + (200 * 0x18)) -or
        [string]$manifest.targetRelativePath -cnotmatch
            '^stable/server/release/system/players/player_.+_0\.psochar$' -or
        [string]$manifest.bankTargetRelativePath -cnotmatch
            '^stable/server/release/system/players/player_.+_0\.psobank$' -or
        [string]$manifest.sourceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.sourceBankSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.provisionedSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]$manifest.provisionedBankSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The sealed Twills transaction manifest is not internally exact'
    }
    $archivedBuildPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot ('contract\' + $script:BuildFileName)) `
        -Root $safeRoot
    Assert-PSOBBProvisioningProtectedAcl `
        -Path $archivedBuildPath -IsContainer $false | Out-Null
    $archivedBuildBytes = Read-PSOBBProvisioningBytes `
        -Path $archivedBuildPath -MaximumLength 128KB
    $archivedBuildHash = Get-PSOBBProvisioningSha256Bytes -Bytes $archivedBuildBytes
    if ($archivedBuildHash -cne $ExpectedBuildHash -or
        $archivedBuildHash -cne [string]$manifest.build.sha256 -or
        $archivedBuildBytes.Length -ne [int64]$manifest.build.size) {
        throw 'The archived Twills build does not match the caller pin and signed manifest'
    }
    try {
        $archivedBuild = [System.Text.Encoding]::UTF8.GetString($archivedBuildBytes) |
            ConvertFrom-Json -Depth 30
    } catch {
        throw 'The archived Twills build is not valid JSON'
    }
    if ([int]$archivedBuild.schemaVersion -ne 2 -or
        [string]$archivedBuild.character.name -cne 'Twills' -or
        [int]$archivedBuild.character.classId -ne 8 -or
        [string]$archivedBuild.character.className -cne 'FOnewearl' -or
        [int]$archivedBuild.character.slotIndex -ne 0 -or
        [string]$archivedBuild.integrity.guildCardName -cne 'Twills' -or
        [int]$archivedBuild.integrity.guildCardClassId -ne 8) {
        throw 'The archived build is not the exact slot-0 Twills FOnewearl contract'
    }
    $beforePath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'before\player_twills_0.psochar') -Root $safeRoot
    $afterPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'after\player_twills_0.psochar') -Root $safeRoot
    $beforeBankPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'before\player_twills_0.psobank') -Root $safeRoot
    $afterBankPath = Assert-PathWithinRoot `
        -Path (Join-Path $safeRoot 'after\player_twills_0.psobank') -Root $safeRoot
    foreach ($evidencePath in @(
            $beforePath,
            $afterPath,
            $beforeBankPath,
            $afterBankPath)) {
        Assert-PSOBBProvisioningProtectedAcl `
            -Path $evidencePath -IsContainer $false | Out-Null
    }
    $beforeBytes = Read-PSOBBProvisioningBytes `
        -Path $beforePath -MaximumLength $script:ExpectedCharacterLength
    $afterBytes = Read-PSOBBProvisioningBytes `
        -Path $afterPath -MaximumLength $script:ExpectedCharacterLength
    $beforeBankBytes = Read-PSOBBProvisioningBytes `
        -Path $beforeBankPath -MaximumLength (8 + (200 * 0x18))
    $afterBankBytes = Read-PSOBBProvisioningBytes `
        -Path $afterBankPath -MaximumLength (8 + (200 * 0x18))
    if ($beforeBytes.Length -ne $script:ExpectedCharacterLength -or
        $afterBytes.Length -ne $script:ExpectedCharacterLength -or
        (Get-PSOBBProvisioningSha256Bytes -Bytes $beforeBytes) -cne
            [string]$manifest.sourceSha256 -or
        (Get-PSOBBProvisioningSha256Bytes -Bytes $afterBytes) -cne
            [string]$manifest.provisionedSha256 -or
        (Get-PSOBBProvisioningSha256Bytes -Bytes $beforeBankBytes) -cne
            [string]$manifest.sourceBankSha256 -or
        (Get-PSOBBProvisioningSha256Bytes -Bytes $afterBankBytes) -cne
            [string]$manifest.provisionedBankSha256) {
        throw 'The sealed Twills transaction evidence no longer matches its manifest'
    }
    $expectedEvidence = @(
        [pscustomobject]@{
            Path = 'before/player_twills_0.psochar'
            Size = $beforeBytes.Length
            Sha256 = [string]$manifest.sourceSha256
        },
        [pscustomobject]@{
            Path = 'before/player_twills_0.psobank'
            Size = $beforeBankBytes.Length
            Sha256 = [string]$manifest.sourceBankSha256
        },
        [pscustomobject]@{
            Path = 'after/player_twills_0.psochar'
            Size = $afterBytes.Length
            Sha256 = [string]$manifest.provisionedSha256
        },
        [pscustomobject]@{
            Path = 'after/player_twills_0.psobank'
            Size = $afterBankBytes.Length
            Sha256 = [string]$manifest.provisionedBankSha256
        },
        [pscustomobject]@{
            Path = 'contract/' + $script:BuildFileName
            Size = $archivedBuildBytes.Length
            Sha256 = $archivedBuildHash
        },
        [pscustomobject]@{
            Path = 'trust/signing-public-key.pem'
            Size = $archivedPublicKeyBytes.Length
            Sha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $archivedPublicKeyBytes
        })
    if (@($manifest.evidence).Count -ne $expectedEvidence.Count) {
        throw 'The sealed Twills transaction evidence index is not exact'
    }
    foreach ($entry in @($manifest.evidence)) {
        Assert-PSOBBProvisioningExactProperties -Value $entry `
            -Label 'Transaction evidence entry' `
            -Expected @('path', 'size', 'sha256') | Out-Null
    }
    foreach ($expected in $expectedEvidence) {
        $matches = @($manifest.evidence | Where-Object {
                [string]$_.path -ceq $expected.Path -and
                [int64]$_.size -eq $expected.Size -and
                [string]$_.sha256 -ceq $expected.Sha256
            })
        if ($matches.Count -ne 1) {
            throw "The sealed Twills evidence index does not match $($expected.Path)"
        }
    }
    $targetPath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Root (
                ([string]$manifest.targetRelativePath).Replace('/', '\'))) `
        -Root (Join-Path $Layout.Server 'system\players')
    $bankTargetPath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Root (
                ([string]$manifest.bankTargetRelativePath).Replace('/', '\'))) `
        -Root (Join-Path $Layout.Server 'system\players')
    if ([System.IO.Path]::GetFileNameWithoutExtension($targetPath) -cne
        [System.IO.Path]::GetFileNameWithoutExtension($bankTargetPath)) {
        throw 'The sealed character and bank targets do not have the same slot-0 identity'
    }
    [pscustomobject]@{
        Path = $safeRoot
        Id = [string]$manifest.transactionId
        Manifest = $manifest
        ManifestBytes = $manifestBytes
        ManifestSha256 = Get-PSOBBProvisioningSha256Bytes -Bytes $manifestBytes
        BeforeBytes = $beforeBytes
        AfterBytes = $afterBytes
        BeforeBankBytes = $beforeBankBytes
        AfterBankBytes = $afterBankBytes
        TargetPath = $targetPath
        BankTargetPath = $bankTargetPath
        BuildRecord = [pscustomobject]@{
            Path = $archivedBuildPath
            Bytes = $archivedBuildBytes
            Sha256 = $archivedBuildHash
            Value = $archivedBuild
        }
        PublicKey = $publicKey
    }
}

$ExpectedBuildSha256 = $ExpectedBuildSha256.ToLowerInvariant()
$buildRecord = $null
if ($Action -cne 'Rollback') {
    if ([string]::IsNullOrWhiteSpace($BuildPath)) {
        $BuildPath = Join-Path $script:RepositoryRoot ('config\' + $script:BuildFileName)
    }
    $buildRecord = Get-PSOBBProvisioningBuild `
        -Path $BuildPath -ExpectedSha256 $ExpectedBuildSha256
}
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$locks = Enter-PSOBBProvisioningLocks -Layout $layout
try {
    Assert-PSOBBProvisioningProcessesStopped | Out-Null
    $characterPath = Get-PSOBBProvisioningCharacterPath -Layout $layout
    $bankPath = Get-PSOBBProvisioningBankPath `
        -Layout $layout -CharacterPath $characterPath
    $sourceBytes = Read-PSOBBProvisioningBytes `
        -Path $characterPath -MaximumLength $script:ExpectedCharacterLength
    $sourceBankBytes = Read-PSOBBProvisioningBytes `
        -Path $bankPath -MaximumLength (8 + (200 * 0x18))
    if ($sourceBytes.Length -ne $script:ExpectedCharacterLength) {
        throw "PSOCHAR length is invalid: $($sourceBytes.Length)"
    }
    $sourceHash = Get-PSOBBProvisioningSha256Bytes -Bytes $sourceBytes
    $sourceBankHash = Get-PSOBBProvisioningSha256Bytes -Bytes $sourceBankBytes
    $sourceSummary = & $script:SummaryScript -Path $characterPath
    if ($Action -cne 'Rollback') {
        Assert-PSOBBProvisioningIdentity -Summary $sourceSummary `
            -Build $buildRecord.Value -Path $characterPath | Out-Null
    }

    if ($Action -ceq 'Verify') {
        $verification = Test-PSOBBProvisioningCharacterBuild `
            -CharacterPath $characterPath -BuildRecord $buildRecord
        $bankVerification = Test-PSOBBProvisioningBankBuild `
            -BankPath $bankPath -BuildRecord $buildRecord
        [pscustomobject]@{
            Action = 'Verify'
            Valid = $true
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
            CharacterPath = $characterPath
            BankPath = $bankPath
            CharacterSha256 = $sourceHash
            BankSha256 = $sourceBankHash
            BuildSha256 = $buildRecord.Sha256
            ProfileId = [string]$verification.ProfileId
            BankCount = [int]$bankVerification.Count
        }
        return
    }

    if ($Action -ceq 'Apply') {
        $trustFingerprint = Get-PSOBBProvisioningTrustFingerprint `
            -ExplicitFingerprint $ExpectedSigningPublicKeySha256
        $publicKey = Get-PSOBBProvisioningPublicKey `
            -Layout $layout -ExpectedFingerprint $trustFingerprint
        if ([string]::IsNullOrWhiteSpace($ExpectedSourceSha256) -or
            [string]::IsNullOrWhiteSpace($ExpectedSourceBankSha256)) {
            throw ('Apply requires exact independently recorded source SHA-256 ' +
                'values for both PSOCHAR and the authoritative PSOBANK')
        }
        $ExpectedSourceSha256 = $ExpectedSourceSha256.ToLowerInvariant()
        $ExpectedSourceBankSha256 = $ExpectedSourceBankSha256.ToLowerInvariant()
        if ($sourceHash -cne $ExpectedSourceSha256 -or
            $sourceBankHash -cne $ExpectedSourceBankSha256) {
            throw ('The existing slot-0 Twills PSOCHAR or authoritative PSOBANK ' +
                'does not match its explicit source SHA-256')
        }
        $provisionedBank = New-PSOBBProvisionedBankBytes `
            -SourceBytes $sourceBankBytes -Build $buildRecord.Value
        $provisioned = New-PSOBBProvisionedCharacterBytes `
            -SourceBytes $sourceBytes -Build $buildRecord.Value `
            -AuthoritativeBankMeseta $provisionedBank.SourceMeseta
        if (-not $PSCmdlet.ShouldProcess(
                "$characterPath and $bankPath",
                ('Provision only slot-0 Twills FOnewearl and her authoritative ' +
                    'character bank from the pinned build'))) {
            [pscustomobject]@{
                Action = 'Apply'
                Changed = $false
                WhatIf = $true
                CharacterPath = $characterPath
                BankPath = $bankPath
                SourceSha256 = $sourceHash
                SourceBankSha256 = $sourceBankHash
                ProvisionedSha256 = $provisioned.Sha256
                ProvisionedBankSha256 = $provisionedBank.Sha256
                BuildSha256 = $buildRecord.Sha256
            }
            return
        }

        $transaction = New-PSOBBProvisioningTransaction `
            -Layout $layout -CharacterPath $characterPath -BankPath $bankPath `
            -SourceBytes $sourceBytes -SourceBankBytes $sourceBankBytes `
            -Provisioned $provisioned -ProvisionedBank $provisionedBank `
            -BuildRecord $buildRecord -PublicKey $publicKey
        $afterPath = Join-Path $transaction.Path 'after\player_twills_0.psochar'
        $afterBankPath = Join-Path $transaction.Path 'after\player_twills_0.psobank'
        [void](Test-PSOBBProvisioningCharacterBuild `
                -CharacterPath $afterPath -BuildRecord $buildRecord)
        [void](Test-PSOBBProvisioningBankBuild `
                -BankPath $afterBankPath -BuildRecord $buildRecord)
        Assert-PSOBBProvisioningBuildStillPinned -BuildRecord $buildRecord |
            Out-Null
        Assert-PSOBBProvisioningProcessesStopped | Out-Null
        $transaction = Read-PSOBBProvisioningTransaction `
            -Layout $layout -Path $transaction.Path `
            -ExpectedBuildHash $buildRecord.Sha256 `
            -ExpectedPublicKeyFingerprint $trustFingerprint
        $preparedState = Get-PSOBBProvisioningRollbackJournalState `
            -Transaction $transaction
        $preparedValidation = Assert-PSOBBProvisioningRollbackJournalState `
            -Transaction $transaction -JournalState $preparedState `
            -CharacterSha256 $sourceHash -BankSha256 $sourceBankHash
        if ($preparedValidation.Predecessor -cne 'None' -or
            $preparedState.RolledBack -or
            -not $transaction.TargetPath.Equals(
                $characterPath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            -not $transaction.BankTargetPath.Equals(
                $bankPath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$transaction.Manifest.sourceSha256 -cne $sourceHash -or
            [string]$transaction.Manifest.sourceBankSha256 -cne $sourceBankHash -or
            [string]$transaction.Manifest.provisionedSha256 -cne $provisioned.Sha256 -or
            [string]$transaction.Manifest.provisionedBankSha256 -cne
                $provisionedBank.Sha256) {
            throw 'The finalized Twills transaction is not the exact prepared save pair'
        }

        $playersRoot = Split-Path -Parent $characterPath
        $pair = $null
        try {
            $pair = Invoke-PSOBBProvisioningPairedReplacement -Files @(
                [pscustomobject]@{
                    Name = 'PSOBANK'
                    Path = $bankPath
                    OriginalBytes = $transaction.BeforeBankBytes
                    CurrentSha256 = [string]$transaction.Manifest.sourceBankSha256
                    ReplacementBytes = $transaction.AfterBankBytes
                    ReplacementSha256 = [string]$transaction.Manifest.provisionedBankSha256
                },
                [pscustomobject]@{
                    Name = 'PSOCHAR'
                    Path = $characterPath
                    OriginalBytes = $transaction.BeforeBytes
                    CurrentSha256 = [string]$transaction.Manifest.sourceSha256
                    ReplacementBytes = $transaction.AfterBytes
                    ReplacementSha256 = [string]$transaction.Manifest.provisionedSha256
                }) `
                -PlayersRoot $playersRoot
            Assert-PSOBBProvisioningProcessesStopped | Out-Null
            Assert-PSOBBProvisioningBuildStillPinned -BuildRecord $buildRecord |
                Out-Null
            [void](Test-PSOBBProvisioningCharacterBuild `
                    -CharacterPath $characterPath -BuildRecord $buildRecord)
            [void](Test-PSOBBProvisioningBankBuild `
                    -BankPath $bankPath -BuildRecord $buildRecord)
            Remove-PSOBBProvisioningPairEmergencyFiles -Pair $pair
            Write-PSOBBProvisioningJournalEntry `
                -TransactionRoot $transaction.Path `
                -FileName '001-applied.json' `
                -TransactionId $transaction.Id -State 'applied' `
                -ManifestSha256 $transaction.ManifestSha256 `
                -CharacterSha256 $provisioned.Sha256 `
                -BankSha256 $provisionedBank.Sha256
        } catch {
            $applyError = $_
            if ($pair) {
                try {
                    Assert-PSOBBProvisioningProcessesStopped | Out-Null
                    $compensation = Invoke-PSOBBProvisioningPairedReplacement -Files @(
                        [pscustomobject]@{
                            Name = 'PSOBANK'
                            Path = $bankPath
                            OriginalBytes = $provisionedBank.Bytes
                            CurrentSha256 = $provisionedBank.Sha256
                            ReplacementBytes = $sourceBankBytes
                            ReplacementSha256 = $sourceBankHash
                        },
                        [pscustomobject]@{
                            Name = 'PSOCHAR'
                            Path = $characterPath
                            OriginalBytes = $provisioned.Bytes
                            CurrentSha256 = $provisioned.Sha256
                            ReplacementBytes = $sourceBytes
                            ReplacementSha256 = $sourceHash
                        }) -PlayersRoot $playersRoot
                    Remove-PSOBBProvisioningPairEmergencyFiles -Pair $compensation
                    foreach ($entry in @($pair.Completed)) {
                        Remove-Item -LiteralPath $entry.EmergencyPath -Force `
                            -ErrorAction SilentlyContinue
                    }
                    Write-PSOBBProvisioningJournalEntry `
                        -TransactionRoot $transaction.Path `
                        -FileName '001-apply-failed-rolled-back.json' `
                        -TransactionId $transaction.Id `
                        -State 'apply-failed-rolled-back' `
                        -ManifestSha256 $transaction.ManifestSha256 `
                        -CharacterSha256 $sourceHash `
                        -BankSha256 $sourceBankHash
                } catch {
                    throw ('Twills provisioning failed, and exact automatic rollback ' +
                        "also failed. Apply error: $($applyError.Exception.Message) " +
                        "Rollback error: $($_.Exception.Message) Transaction: $($transaction.Path)")
                }
            } elseif (
                [bool]$applyError.Exception.Data['PSOBBPairCompensated'] -and
                [int]$applyError.Exception.Data['PSOBBPairCompletedBeforeFailure'] -gt 0) {
                try {
                    Assert-PSOBBProvisioningProcessesStopped | Out-Null
                    $compensatedCharacterHash = Get-PSOBBProvisioningSha256Bytes `
                        -Bytes (Read-PSOBBProvisioningBytes `
                            -Path $characterPath `
                            -MaximumLength $script:ExpectedCharacterLength)
                    $compensatedBankHash = Get-PSOBBProvisioningSha256Bytes `
                        -Bytes (Read-PSOBBProvisioningBytes `
                            -Path $bankPath -MaximumLength (8 + (200 * 0x18)))
                    if ($compensatedCharacterHash -cne $sourceHash -or
                        $compensatedBankHash -cne $sourceBankHash) {
                        throw 'Paired replacement compensation did not restore both source hashes'
                    }
                    Write-PSOBBProvisioningJournalEntry `
                        -TransactionRoot $transaction.Path `
                        -FileName '001-apply-failed-rolled-back.json' `
                        -TransactionId $transaction.Id `
                        -State 'apply-failed-rolled-back' `
                        -ManifestSha256 $transaction.ManifestSha256 `
                        -CharacterSha256 $sourceHash `
                        -BankSha256 $sourceBankHash
                } catch {
                    throw ('Twills paired replacement failed, and compensation evidence ' +
                        "could not be finalized. Apply error: $($applyError.Exception.Message) " +
                        "Evidence error: $($_.Exception.Message) Transaction: $($transaction.Path)")
                }
            }
            throw $applyError
        }

        [pscustomobject]@{
            Action = 'Apply'
            Changed = $true
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
            CharacterPath = $characterPath
            BankPath = $bankPath
            SourceSha256 = $sourceHash
            SourceBankSha256 = $sourceBankHash
            ProvisionedSha256 = $provisioned.Sha256
            ProvisionedBankSha256 = $provisionedBank.Sha256
            BuildSha256 = $buildRecord.Sha256
            TransactionPath = $transaction.Path
            ManifestSha256 = $transaction.ManifestSha256
            InventoryCount = $provisioned.InventoryCount
            BankCount = $provisioned.BankCount
            UniqueItemIds = $provisioned.UniqueItemIds
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($TransactionPath)) {
        throw 'Rollback requires one explicit sealed Twills transaction path'
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedSigningPublicKeySha256)) {
        throw 'Rollback requires the explicit historical transaction public-key SHA-256 pin'
    }
    $rollbackPublicKeyFingerprint = $ExpectedSigningPublicKeySha256.ToLowerInvariant()
    $transaction = Read-PSOBBProvisioningTransaction `
        -Layout $layout -Path $TransactionPath `
        -ExpectedBuildHash $ExpectedBuildSha256 `
        -ExpectedPublicKeyFingerprint $rollbackPublicKeyFingerprint
    $buildRecord = $transaction.BuildRecord
    Assert-PSOBBProvisioningIdentity -Summary $sourceSummary `
        -Build $buildRecord.Value -Path $characterPath | Out-Null
    if (-not $transaction.TargetPath.Equals(
            $characterPath,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $transaction.BankTargetPath.Equals(
            $bankPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('The sealed rollback transaction does not target the only slot-0 ' +
            'Twills character/bank pair')
    }
    $currentHash = Get-PSOBBProvisioningSha256Bytes `
        -Bytes (Read-PSOBBProvisioningBytes -Path $characterPath `
            -MaximumLength $script:ExpectedCharacterLength)
    $currentBankHash = Get-PSOBBProvisioningSha256Bytes `
        -Bytes (Read-PSOBBProvisioningBytes -Path $bankPath `
            -MaximumLength (8 + (200 * 0x18)))
    $journalState = Get-PSOBBProvisioningRollbackJournalState `
        -Transaction $transaction
    $journalValidation = Assert-PSOBBProvisioningRollbackJournalState `
        -Transaction $transaction -JournalState $journalState `
        -CharacterSha256 $currentHash -BankSha256 $currentBankHash
    $journalFileName = '002-rolled-back.json'
    $rolledBackEvidence = $journalState.RolledBack
    $isSourcePair = $journalValidation.IsSourcePair
    if ($isSourcePair) {
        if ($journalValidation.Predecessor -ceq 'None' -and
            -not $rolledBackEvidence) {
            throw ('Rollback refuses to label a prepared-only source pair as rolled back; ' +
                'no validated applied or automatically compensated journal entry exists')
        }
        $evidenceRecorded = $false
        if (-not $rolledBackEvidence) {
            if (-not $PSCmdlet.ShouldProcess(
                    $transaction.Path,
                    'Record missing rollback evidence for the already-restored Twills pair')) {
                [pscustomobject]@{
                    Action = 'Rollback'
                    Changed = $false
                    AlreadyRolledBack = $true
                    WhatIf = $true
                    EvidenceMissing = $true
                    CharacterPath = $characterPath
                    BankPath = $bankPath
                    CharacterSha256 = $currentHash
                    BankSha256 = $currentBankHash
                    TransactionPath = $transaction.Path
                }
                return
            }
            Assert-PSOBBProvisioningProcessesStopped | Out-Null
            $transaction = Read-PSOBBProvisioningTransaction `
                -Layout $layout -Path $TransactionPath `
                -ExpectedBuildHash $ExpectedBuildSha256 `
                -ExpectedPublicKeyFingerprint $rollbackPublicKeyFingerprint
            $journalState = Get-PSOBBProvisioningRollbackJournalState `
                -Transaction $transaction
            $repairCharacterHash = Get-PSOBBProvisioningSha256Bytes `
                -Bytes (Read-PSOBBProvisioningBytes -Path $characterPath `
                    -MaximumLength $script:ExpectedCharacterLength)
            $repairBankHash = Get-PSOBBProvisioningSha256Bytes `
                -Bytes (Read-PSOBBProvisioningBytes -Path $bankPath `
                    -MaximumLength (8 + (200 * 0x18)))
            if ($repairCharacterHash -cne
                    [string]$transaction.Manifest.sourceSha256 -or
                $repairBankHash -cne
                    [string]$transaction.Manifest.sourceBankSha256) {
                throw 'The Twills source pair changed before rollback evidence repair'
            }
            $repairValidation = Assert-PSOBBProvisioningRollbackJournalState `
                -Transaction $transaction -JournalState $journalState `
                -CharacterSha256 $repairCharacterHash `
                -BankSha256 $repairBankHash
            if (-not $repairValidation.IsSourcePair -or
                $repairValidation.Predecessor -ceq 'None' -or
                $journalState.RolledBack) {
                throw 'Rollback journal state changed before evidence repair'
            }
            Write-PSOBBProvisioningJournalEntry `
                -TransactionRoot $transaction.Path `
                -FileName $journalFileName `
                -TransactionId ([string]$transaction.Manifest.transactionId) `
                -State 'rolled-back' `
                -ManifestSha256 $transaction.ManifestSha256 `
                -CharacterSha256 ([string]$transaction.Manifest.sourceSha256) `
                -BankSha256 ([string]$transaction.Manifest.sourceBankSha256)
            $evidenceRecorded = $true
        }
        [pscustomobject]@{
            Action = 'Rollback'
            Changed = $false
            AlreadyRolledBack = $true
            EvidenceRecorded = $evidenceRecorded
            JournalComplete = $true
            Character = 'Twills'
            Class = 'FOnewearl'
            SlotIndex = 0
            CharacterPath = $characterPath
            BankPath = $bankPath
            CharacterSha256 = $currentHash
            BankSha256 = $currentBankHash
            TransactionPath = $transaction.Path
        }
        return
    }
    if ($currentHash -cnotin @(
            [string]$transaction.Manifest.sourceSha256,
            [string]$transaction.Manifest.provisionedSha256) -or
        $currentBankHash -cnotin @(
            [string]$transaction.Manifest.sourceBankSha256,
            [string]$transaction.Manifest.provisionedBankSha256)) {
        throw ('Rollback refuses a slot-0 Twills character or bank that drifted ' +
            'after provisioning')
    }
    if (-not $PSCmdlet.ShouldProcess(
            "$characterPath and $bankPath",
            ('Rollback only slot-0 Twills FOnewearl and her authoritative bank ' +
                'to their sealed source bytes'))) {
        [pscustomobject]@{
            Action = 'Rollback'
            Changed = $false
            WhatIf = $true
            CharacterPath = $characterPath
            BankPath = $bankPath
            CurrentSha256 = $currentHash
            CurrentBankSha256 = $currentBankHash
            RollbackSha256 = [string]$transaction.Manifest.sourceSha256
            RollbackBankSha256 = [string]$transaction.Manifest.sourceBankSha256
            TransactionPath = $transaction.Path
        }
        return
    }
    Assert-PSOBBProvisioningProcessesStopped | Out-Null
    $transaction = Read-PSOBBProvisioningTransaction `
        -Layout $layout -Path $TransactionPath `
        -ExpectedBuildHash $ExpectedBuildSha256 `
        -ExpectedPublicKeyFingerprint $rollbackPublicKeyFingerprint
    if (-not $transaction.TargetPath.Equals(
            $characterPath,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $transaction.BankTargetPath.Equals(
            $bankPath,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The sealed rollback targets changed before mutation'
    }
    $journalState = Get-PSOBBProvisioningRollbackJournalState `
        -Transaction $transaction
    $currentHash = Get-PSOBBProvisioningSha256Bytes `
        -Bytes (Read-PSOBBProvisioningBytes -Path $characterPath `
            -MaximumLength $script:ExpectedCharacterLength)
    $currentBankHash = Get-PSOBBProvisioningSha256Bytes `
        -Bytes (Read-PSOBBProvisioningBytes -Path $bankPath `
            -MaximumLength (8 + (200 * 0x18)))
    if ($currentHash -cnotin @(
            [string]$transaction.Manifest.sourceSha256,
            [string]$transaction.Manifest.provisionedSha256) -or
        $currentBankHash -cnotin @(
            [string]$transaction.Manifest.sourceBankSha256,
            [string]$transaction.Manifest.provisionedBankSha256) -or
        ($currentHash -ceq [string]$transaction.Manifest.sourceSha256 -and
            $currentBankHash -ceq [string]$transaction.Manifest.sourceBankSha256)) {
        throw 'The Twills pair changed before rollback mutation'
    }
    $journalValidation = Assert-PSOBBProvisioningRollbackJournalState `
        -Transaction $transaction -JournalState $journalState `
        -CharacterSha256 $currentHash -BankSha256 $currentBankHash
    if ($journalValidation.IsSourcePair) {
        throw 'The Twills pair returned to source state before rollback mutation'
    }
    if ($journalValidation.Predecessor -ceq 'None') {
        Write-PSOBBProvisioningJournalEntry `
            -TransactionRoot $transaction.Path `
            -FileName '001-rollback-intent.json' `
            -TransactionId ([string]$transaction.Manifest.transactionId) `
            -State 'rollback-intent' `
            -ManifestSha256 $transaction.ManifestSha256 `
            -CharacterSha256 ([string]$transaction.Manifest.provisionedSha256) `
            -BankSha256 ([string]$transaction.Manifest.provisionedBankSha256)
        $transaction = Read-PSOBBProvisioningTransaction `
            -Layout $layout -Path $TransactionPath `
            -ExpectedBuildHash $ExpectedBuildSha256 `
            -ExpectedPublicKeyFingerprint $rollbackPublicKeyFingerprint
        $journalState = Get-PSOBBProvisioningRollbackJournalState `
            -Transaction $transaction
    }
    $currentHash = Get-PSOBBProvisioningSha256Bytes `
        -Bytes (Read-PSOBBProvisioningBytes -Path $characterPath `
            -MaximumLength $script:ExpectedCharacterLength)
    $currentBankHash = Get-PSOBBProvisioningSha256Bytes `
        -Bytes (Read-PSOBBProvisioningBytes -Path $bankPath `
            -MaximumLength (8 + (200 * 0x18)))
    if ($currentHash -cnotin @(
            [string]$transaction.Manifest.sourceSha256,
            [string]$transaction.Manifest.provisionedSha256) -or
        $currentBankHash -cnotin @(
            [string]$transaction.Manifest.sourceBankSha256,
            [string]$transaction.Manifest.provisionedBankSha256) -or
        ($currentHash -ceq [string]$transaction.Manifest.sourceSha256 -and
            $currentBankHash -ceq [string]$transaction.Manifest.sourceBankSha256)) {
        throw 'The Twills pair changed after rollback intent was sealed'
    }
    $journalValidation = Assert-PSOBBProvisioningRollbackJournalState `
        -Transaction $transaction -JournalState $journalState `
        -CharacterSha256 $currentHash -BankSha256 $currentBankHash
    if ($journalValidation.IsSourcePair -or
        $journalValidation.Predecessor -cnotin @('Applied', 'RollbackIntent')) {
        throw 'Rollback journal state is not an exact mutation predecessor'
    }
    $buildRecord = $transaction.BuildRecord
    $playersRoot = Split-Path -Parent $characterPath
    $rollbackFiles = [System.Collections.Generic.List[object]]::new()
    if ($currentBankHash -ceq [string]$transaction.Manifest.provisionedBankSha256) {
        $rollbackFiles.Add([pscustomobject]@{
                Name = 'PSOBANK'
                Path = $bankPath
                OriginalBytes = $transaction.AfterBankBytes
                CurrentSha256 = [string]$transaction.Manifest.provisionedBankSha256
                ReplacementBytes = $transaction.BeforeBankBytes
                ReplacementSha256 = [string]$transaction.Manifest.sourceBankSha256
            })
    }
    if ($currentHash -ceq [string]$transaction.Manifest.provisionedSha256) {
        $rollbackFiles.Add([pscustomobject]@{
                Name = 'PSOCHAR'
                Path = $characterPath
                OriginalBytes = $transaction.AfterBytes
                CurrentSha256 = [string]$transaction.Manifest.provisionedSha256
                ReplacementBytes = $transaction.BeforeBytes
                ReplacementSha256 = [string]$transaction.Manifest.sourceSha256
            })
    }
    $replacement = Invoke-PSOBBProvisioningPairedReplacement `
        -Files @($rollbackFiles) -PlayersRoot $playersRoot
    try {
        Assert-PSOBBProvisioningProcessesStopped | Out-Null
        $transaction = Read-PSOBBProvisioningTransaction `
            -Layout $layout -Path $TransactionPath `
            -ExpectedBuildHash $ExpectedBuildSha256 `
            -ExpectedPublicKeyFingerprint $rollbackPublicKeyFingerprint
        $journalState = Get-PSOBBProvisioningRollbackJournalState `
            -Transaction $transaction
        $restoredCharacterHash = Get-PSOBBProvisioningSha256Bytes `
            -Bytes (Read-PSOBBProvisioningBytes -Path $characterPath `
                -MaximumLength $script:ExpectedCharacterLength)
        $restoredBankHash = Get-PSOBBProvisioningSha256Bytes `
            -Bytes (Read-PSOBBProvisioningBytes -Path $bankPath `
                -MaximumLength (8 + (200 * 0x18)))
        $restoredValidation = Assert-PSOBBProvisioningRollbackJournalState `
            -Transaction $transaction -JournalState $journalState `
            -CharacterSha256 $restoredCharacterHash `
            -BankSha256 $restoredBankHash
        if (-not $restoredValidation.IsSourcePair -or
            $restoredValidation.Predecessor -cnotin @('Applied', 'RollbackIntent') -or
            $journalState.RolledBack) {
            throw 'Rollback journal state changed during save restoration'
        }
        $buildRecord = $transaction.BuildRecord
        $rolledBackSummary = & $script:SummaryScript -Path $characterPath
        Assert-PSOBBProvisioningIdentity -Summary $rolledBackSummary `
            -Build $buildRecord.Value -Path $characterPath | Out-Null
        Write-PSOBBProvisioningJournalEntry `
            -TransactionRoot $transaction.Path `
            -FileName '002-rolled-back.json' `
            -TransactionId ([string]$transaction.Manifest.transactionId) `
            -State 'rolled-back' `
            -ManifestSha256 $transaction.ManifestSha256 `
            -CharacterSha256 ([string]$transaction.Manifest.sourceSha256) `
            -BankSha256 ([string]$transaction.Manifest.sourceBankSha256)
        Remove-PSOBBProvisioningPairEmergencyFiles -Pair $replacement
    } catch {
        throw ('The exact source bytes were restored, but rollback evidence finalization ' +
            "failed: $($_.Exception.Message) Transaction: $($transaction.Path)")
    }
    [pscustomobject]@{
        Action = 'Rollback'
        Changed = $true
        Character = 'Twills'
        Class = 'FOnewearl'
        SlotIndex = 0
        CharacterPath = $characterPath
        BankPath = $bankPath
        CharacterSha256 = [string]$transaction.Manifest.sourceSha256
        BankSha256 = [string]$transaction.Manifest.sourceBankSha256
        TransactionPath = $transaction.Path
        ManifestSha256 = $transaction.ManifestSha256
    }
} finally {
    Exit-PSOBBProvisioningLocks -Locks $locks
}
