[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$provisioningScript = Join-Path $repositoryRoot 'scripts\Set-PSOBBTwillsProvisioning.ps1'
$summaryScript = Join-Path $repositoryRoot 'scripts\Get-PSOBBCharacterSummary.ps1'
$verifierScript = Join-Path $repositoryRoot 'scripts\Test-PSOBBCharacterBuild.ps1'
$bankVerifierScript = Join-Path $repositoryRoot 'scripts\Test-PSOBBTwillsBank.ps1'
$buildPath = Join-Path $repositoryRoot 'config\twills-fonewearl-build.json'
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

if (-not (Test-Path -LiteralPath $buildPath -PathType Leaf)) {
    throw "The canonical Twills FOnewearl contract is missing: $buildPath"
}
$build = Get-Content -Raw -LiteralPath $buildPath | ConvertFrom-Json -Depth 30
$buildHash = (Get-FileHash -LiteralPath $buildPath -Algorithm SHA256).Hash.ToLowerInvariant()
$inventoryContract = @($build.items | Where-Object location -CEQ 'Inventory' |
    Sort-Object { [int]$_.slot })
$bankContract = @($build.items | Where-Object location -CEQ 'Bank' |
    Sort-Object { [int]$_.slot })
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][string]$Detail
    )

    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Set-TestUInt16LE {
    param([byte[]]$Data, [int]$Offset, [uint16]$Value)

    $Data[$Offset] = [byte]($Value -band 0xFF)
    $Data[$Offset + 1] = [byte](($Value -shr 8) -band 0xFF)
}

function Set-TestUInt32LE {
    param([byte[]]$Data, [int]$Offset, [uint32]$Value)

    for ($index = 0; $index -lt 4; $index++) {
        $Data[$Offset + $index] = [byte](($Value -shr ($index * 8)) -band 0xFF)
    }
}

function Get-TestUInt32LE {
    param([byte[]]$Data, [int]$Offset)

    [uint32](
        [uint32]$Data[$Offset] -bor
        ([uint32]$Data[$Offset + 1] -shl 8) -bor
        ([uint32]$Data[$Offset + 2] -shl 16) -bor
        ([uint32]$Data[$Offset + 3] -shl 24))
}

function Set-TestUtf16LE {
    param(
        [byte[]]$Data,
        [int]$Offset,
        [int]$ByteCount,
        [string]$Value
    )

    [System.Array]::Clear($Data, $Offset, $ByteCount)
    $encoded = [System.Text.Encoding]::Unicode.GetBytes($Value)
    if ($encoded.Length -gt $ByteCount) {
        throw 'Fixture UTF-16 value is too long'
    }
    [System.Array]::Copy($encoded, 0, $Data, $Offset, $encoded.Length)
}

function Get-TestSha256Bytes {
    param([byte[]]$Bytes)

    ([Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function New-TestCharacterBytes {
    $bytes = [byte[]]::new(0x399C)
    [System.Array]::Copy(
        [byte[]](0x9C, 0x39, 0xE7, 0, 0, 0, 0, 0),
        $bytes,
        8)

    $bytes[0x08] = 6
    $bytes[0x09] = 2
    $bytes[0x0A] = 4
    $bytes[0x0B] = 4
    for ($index = 0; $index -lt 30; $index++) {
        $itemOffset = 0x0C + ($index * 0x1C)
        $bytes[$itemOffset] = [byte]($(if ($index -lt 6) { 1 } else { 0 }))
        $bytes[$itemOffset + 1] = [byte]($(if ($index -lt $inventoryContract.Count) {
                    0
                } else {
                    0x80 + $index
                }))
        $bytes[$itemOffset + 2] = [byte](0x40 + $index)
        $bytes[$itemOffset + 3] = [byte](0x20 + $index)
        if ($index -lt 6) {
            $bytes[$itemOffset + 8] = 0x03
            $bytes[$itemOffset + 9] = 0x00
            $bytes[$itemOffset + 13] = 1
            Set-TestUInt32LE -Data $bytes -Offset ($itemOffset + 20) `
                -Value ([uint32](0x50000000 + $index + 1))
        }
    }
    for ($index = 0; $index -lt 20; $index++) {
        $bytes[0x4D0 + $index] = 0xFF
    }

    Set-TestUInt16LE -Data $bytes -Offset 0x354 -Value 35
    Set-TestUInt16LE -Data $bytes -Offset 0x356 -Value 65
    Set-TestUInt16LE -Data $bytes -Offset 0x358 -Value 45
    Set-TestUInt16LE -Data $bytes -Offset 0x35A -Value 20
    Set-TestUInt16LE -Data $bytes -Offset 0x35C -Value 15
    Set-TestUInt16LE -Data $bytes -Offset 0x35E -Value 25
    Set-TestUInt16LE -Data $bytes -Offset 0x360 -Value 10
    Set-TestUInt32LE -Data $bytes -Offset 0x36C -Value 1
    Set-TestUInt32LE -Data $bytes -Offset 0x370 -Value 79
    Set-TestUInt32LE -Data $bytes -Offset 0x374 -Value 42

    $bytes[0x3A8] = [byte]$build.character.sectionId
    $bytes[0x3A9] = 8
    $bytes[0x3AA] = [byte]$build.integrity.visualValidationFlags
    $bytes[0x3AB] = [byte]$build.integrity.visualVersion
    Set-TestUInt32LE -Data $bytes -Offset 0x3AC `
        -Value ([uint32]$build.integrity.visualClassFlags)
    Set-TestUtf16LE -Data $bytes -Offset 0x3C8 -ByteCount 0x20 `
        -Value "`tETwills"
    Set-TestUInt32LE -Data $bytes -Offset 0x4E4 `
        -Value ([uint32]$build.integrity.characterValidationFlags)
    Set-TestUInt32LE -Data $bytes -Offset 0x4EC `
        -Value ([Convert]::ToUInt32([string]$build.integrity.signatureHex, 16))

    Set-TestUInt32LE -Data $bytes -Offset 0x700 -Value 1
    Set-TestUInt32LE -Data $bytes -Offset 0x704 -Value 12345
    for ($index = 0; $index -lt 200; $index++) {
        $itemOffset = 0x708 + ($index * 0x18)
        for ($byteIndex = 0; $byteIndex -lt 0x18; $byteIndex++) {
            $bytes[$itemOffset + $byteIndex] = [byte](
                (0xA0 + $index + $byteIndex) -band 0xFF)
        }
    }
    $bytes[0x708] = 0x03
    $bytes[0x709] = 0x00
    $bytes[0x70D] = 1
    Set-TestUInt32LE -Data $bytes -Offset 0x714 -Value 0x60000001
    Set-TestUInt16LE -Data $bytes -Offset 0x71C -Value 1
    Set-TestUInt16LE -Data $bytes -Offset 0x71E -Value 1

    Set-TestUtf16LE -Data $bytes -Offset 0x19CC -ByteCount 0x30 `
        -Value "`tETwills"
    $bytes[0x1ACC] = [byte]$build.integrity.guildCardPresent
    $bytes[0x1ACE] = [byte]$build.integrity.guildCardSectionId
    $bytes[0x1ACF] = 8

    for ($index = 0x2EAC; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [byte](($index * 17) -band 0xFF)
    }
    $bytes
}

function New-TestRuntime {
    param(
        [Parameter(Mandatory)][string]$Parent,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet(0, 1)][int]$SlotIndex = 0,
        [ValidateRange(0, 11)][int]$ClassId = 8
    )

    $root = Join-Path $Parent $Name
    $players = Join-Path $root 'stable\server\release\system\players'
    $backups = Join-Path $root 'backups'
    $secrets = Join-Path $root 'secrets'
    $stable = Join-Path $root 'stable'
    foreach ($directory in @($players, $backups, $secrets)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    foreach ($directory in @($players, $backups, $secrets)) {
        Set-PSOBBProtectedAcl -Path $directory
    }

    $marker = [ordered]@{
        schemaVersion = 1
        installationId = [Guid]::NewGuid().ToString('D')
        runtimeRoot = [System.IO.Path]::GetFullPath($root)
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $root '.psobb-runtime.json'),
        ($marker | ConvertTo-Json -Depth 3),
        [System.Text.UTF8Encoding]::new($false))

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create(
        [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $privatePath = Join-Path $secrets 'local-acceptance-signing-private.pem'
        $publicPath = Join-Path $stable 'release-public-key.pem'
        [System.IO.File]::WriteAllText(
            $privatePath,
            $ecdsa.ExportPkcs8PrivateKeyPem(),
            [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText(
            $publicPath,
            $ecdsa.ExportSubjectPublicKeyInfoPem(),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $privatePath
        Set-PSOBBProtectedAcl -Path $publicPath
        $fingerprint = Get-TestSha256Bytes `
            -Bytes $ecdsa.ExportSubjectPublicKeyInfo()
    } finally {
        $ecdsa.Dispose()
    }

    $characterPath = Join-Path $players ("player_fixture_$SlotIndex.psochar")
    $characterBytes = New-TestCharacterBytes
    $characterBytes[0x3A9] = [byte]$ClassId
    $characterBytes[0x1ACF] = [byte]$ClassId
    [System.IO.File]::WriteAllBytes($characterPath, $characterBytes)
    Set-PSOBBProtectedAcl -Path $characterPath

    $bankPath = Join-Path $players ("player_fixture_$SlotIndex.psobank")
    $bankBytes = [byte[]]::new(8)
    Set-TestUInt32LE -Data $bankBytes -Offset 0 -Value 0
    Set-TestUInt32LE -Data $bankBytes -Offset 4 -Value 54321
    [System.IO.File]::WriteAllBytes($bankPath, $bankBytes)
    Set-PSOBBProtectedAcl -Path $bankPath
    [pscustomobject]@{
        Root = $root
        Players = $players
        Backups = $backups
        CharacterPath = $characterPath
        BankPath = $bankPath
        SourceBytes = $characterBytes
        SourceBankBytes = $bankBytes
        SourceSha256 = Get-TestSha256Bytes -Bytes $characterBytes
        SourceBankSha256 = Get-TestSha256Bytes -Bytes $bankBytes
        SigningPublicKeySha256 = $fingerprint
    }
}

function Get-ActionResult {
    param([object[]]$Output, [string]$Action)

    @($Output | Where-Object {
            $_.PSObject.Properties.Name -contains 'Action' -and
            [string]$_.Action -ceq $Action
        })[-1]
}

function Test-Rejected {
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [Parameter(Mandatory)][string]$Pattern
    )

    try {
        & $Operation *> $null
        $false
    } catch {
        $_.Exception.Message -match $Pattern
    }
}

function Test-ByteRangeEqual {
    param(
        [byte[]]$Left,
        [byte[]]$Right,
        [int]$Offset,
        [int]$Count
    )

    for ($index = 0; $index -lt $Count; $index++) {
        if ($Left[$Offset + $index] -ne $Right[$Offset + $index]) {
            return $false
        }
    }
    $true
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('PSOBB-TwillsProvisioningTests-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

    $primary = New-TestRuntime -Parent $temporaryRoot -Name 'primary'
    $applyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $primary.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $primary.SourceSha256 `
            -ExpectedSourceBankSha256 $primary.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $primary.SigningPublicKeySha256 `
            -Confirm:$false)
    $apply = Get-ActionResult -Output $applyOutput -Action 'Apply'
    $afterBytes = [System.IO.File]::ReadAllBytes($primary.CharacterPath)
    $afterHash = Get-TestSha256Bytes -Bytes $afterBytes
    $afterBankBytes = [System.IO.File]::ReadAllBytes($primary.BankPath)
    $afterBankHash = Get-TestSha256Bytes -Bytes $afterBankBytes
    Add-Result 'apply provisions only the exact slot-0 Twills FOnewearl save pair' (
        $apply.Changed -and $apply.Character -ceq 'Twills' -and
        $apply.Class -ceq 'FOnewearl' -and $apply.SlotIndex -eq 0 -and
        $apply.SourceSha256 -ceq $primary.SourceSha256 -and
        $apply.SourceBankSha256 -ceq $primary.SourceBankSha256 -and
        $apply.ProvisionedSha256 -ceq $afterHash -and
        $apply.ProvisionedBankSha256 -ceq $afterBankHash -and
        $apply.BankPath -ceq $primary.BankPath -and
        -not (Test-Path -LiteralPath (
                Join-Path $primary.Players 'player_fixture_1.psochar'))) `
        "character=$afterHash; bank=$afterBankHash"

    $summary = & $summaryScript -Path $primary.CharacterPath
    $verifyOutput = @(& $verifierScript -Path $primary.CharacterPath `
            -BuildPath $buildPath)
    $buildVerification = @($verifyOutput | Where-Object {
            $_.PSObject.Properties.Name -contains 'Valid'
        })[-1]
    $bankVerification = & $bankVerifierScript -Path $primary.BankPath `
        -BuildPath $buildPath -ExpectedBuildSha256 $buildHash
    Add-Result 'independent character and authoritative-bank verification accept the result' (
        $buildVerification.Valid -and
        $buildVerification.CharacterSha256 -ceq $afterHash -and
        $bankVerification.Valid -and
        $bankVerification.Sha256 -ceq $afterBankHash -and
        $bankVerification.Count -eq $bankContract.Count -and
        $bankVerification.Meseta -eq 54321 -and
        (Get-TestUInt32LE -Data $afterBytes -Offset 0x704) -eq
            $bankVerification.Meseta -and
        $summary.Name -ceq 'Twills' -and $summary.ClassId -eq 8 -and
        $summary.ClassName -ceq 'FOnewearl' -and
        $summary.DisplayedLevel -eq 200 -and
        $summary.InventoryCount -eq $inventoryContract.Count -and
        $summary.BankCount -eq $bankContract.Count) `
        "inventory=$($summary.InventoryCount); embeddedBank=$($summary.BankCount); authoritativeBank=$($bankVerification.Count)"

    $orderExact = $true
    for ($index = 0; $index -lt $inventoryContract.Count; $index++) {
        $actual = $summary.InventoryItems[$index]
        $expected = $inventoryContract[$index]
        if ($actual.Slot -ne [int]$expected.slot -or
            $actual.CanonicalDescriptorHex -cne [string]$expected.descriptorHex -or
            $actual.EquippedSlot -cne [string]$expected.equippedSlot) {
            $orderExact = $false
            break
        }
    }
    if ($orderExact) {
        for ($index = 0; $index -lt $bankContract.Count; $index++) {
            if ($summary.BankItems[$index].Slot -ne [int]$bankContract[$index].slot -or
                $summary.BankItems[$index].CanonicalDescriptorHex -cne
                    [string]$bankContract[$index].descriptorHex -or
                $bankVerification.Items[$index].Slot -ne
                    [int]$bankContract[$index].slot -or
                $bankVerification.Items[$index].DescriptorHex -cne
                    [string]$bankContract[$index].descriptorHex) {
                $orderExact = $false
                break
            }
        }
    }
    Add-Result 'inventory, both banks, order, and equipped-slot semantics are exact' `
        $orderExact 'all contract slots and canonical descriptors match in both bank forms'

    $unknownsPreserved = $afterBytes[0x0B] -eq $primary.SourceBytes[0x0B]
    for ($index = 0; $index -lt 30; $index++) {
        $itemOffset = 0x0C + ($index * 0x1C)
        if ($afterBytes[$itemOffset + 1] -ne
            $primary.SourceBytes[$itemOffset + 1]) {
            $unknownsPreserved = $false
        }
        if ($index -ge 19 -and $afterBytes[$itemOffset + 2] -ne
            $primary.SourceBytes[$itemOffset + 2]) {
            $unknownsPreserved = $false
        }
        if (($index -lt 8 -or $index -ge 13) -and
            $afterBytes[$itemOffset + 3] -ne
                $primary.SourceBytes[$itemOffset + 3]) {
            $unknownsPreserved = $false
        }
    }
    Add-Result 'inventory language and unknown extension stripes are preserved' `
        $unknownsPreserved 'only technique and material stripe bytes owned by newserv changed'

    $largeRegionsPreserved =
        (Test-ByteRangeEqual -Left $primary.SourceBytes -Right $afterBytes `
            -Offset 0 -Count 8) -and
        (Test-ByteRangeEqual -Left $primary.SourceBytes -Right $afterBytes `
            -Offset 0x378 -Count 0x70) -and
        (Test-ByteRangeEqual -Left $primary.SourceBytes -Right $afterBytes `
            -Offset 0x19C8 -Count 0x108) -and
        (Test-ByteRangeEqual -Left $primary.SourceBytes -Right $afterBytes `
            -Offset 0x2EAC -Count (0x399C - 0x2EAC)) -and
        (Test-ByteRangeEqual -Left $primary.SourceBytes -Right $afterBytes `
            -Offset (0x0C + ($inventoryContract.Count * 0x1C)) `
            -Count ((30 - $inventoryContract.Count) * 0x1C)) -and
        (Test-ByteRangeEqual -Left $primary.SourceBytes -Right $afterBytes `
            -Offset (0x708 + ($bankContract.Count * 0x18)) `
            -Count ((200 - $bankContract.Count) * 0x18))
    Add-Result 'header, visual, identity, Guild Card, trailing slots, and system/team bytes remain exact' `
        $largeRegionsPreserved 'all non-owned structural regions match the source fixture'

    $ids = [System.Collections.Generic.HashSet[uint32]]::new()
    $uniqueIds = $true
    for ($index = 0; $index -lt $summary.InventoryCount; $index++) {
        if (-not $ids.Add((Get-TestUInt32LE -Data $afterBytes `
                    -Offset (0x0C + ($index * 0x1C) + 20)))) {
            $uniqueIds = $false
        }
    }
    for ($index = 0; $index -lt $summary.BankCount; $index++) {
        $embeddedId = Get-TestUInt32LE -Data $afterBytes `
            -Offset (0x708 + ($index * 0x18) + 12)
        $externalId = Get-TestUInt32LE -Data $afterBankBytes `
            -Offset (8 + ($index * 0x18) + 12)
        if (-not $ids.Add($embeddedId) -or $externalId -ne $embeddedId) {
            $uniqueIds = $false
        }
    }
    Add-Result 'inventory and bank IDs are unique and both bank forms agree' (
        $uniqueIds -and $ids.Count -eq
            ($summary.InventoryCount + $summary.BankCount)) `
        "uniqueIds=$($ids.Count)"

    $transactionRoot = [string]$apply.TransactionPath
    $manifestPath = Join-Path $transactionRoot 'manifest.json'
    $signaturePath = Join-Path $transactionRoot 'manifest.sig'
    $beforeBackup = Join-Path $transactionRoot 'before\player_twills_0.psochar'
    $afterBackup = Join-Path $transactionRoot 'after\player_twills_0.psochar'
    $beforeBankBackup = Join-Path $transactionRoot 'before\player_twills_0.psobank'
    $afterBankBackup = Join-Path $transactionRoot 'after\player_twills_0.psobank'
    $sealedBeforeHash = (Get-FileHash -LiteralPath $beforeBackup `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $sealedAfterHash = (Get-FileHash -LiteralPath $afterBackup `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $sealedBeforeBankHash = (Get-FileHash -LiteralPath $beforeBankBackup `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $sealedAfterBankHash = (Get-FileHash -LiteralPath $afterBankBackup `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $sealedManifestHash = (Get-FileHash -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Result 'signed manifest seals both backup pairs and journal entries are create-only' (
        $sealedBeforeHash -ceq $primary.SourceSha256 -and
        $sealedAfterHash -ceq $afterHash -and
        $sealedBeforeBankHash -ceq $primary.SourceBankSha256 -and
        $sealedAfterBankHash -ceq $afterBankHash -and
        $sealedManifestHash -ceq [string]$apply.ManifestSha256 -and
        (Test-Path -LiteralPath $signaturePath -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $transactionRoot `
                'journal\000-prepared.json') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $transactionRoot `
                'journal\001-applied.json') -PathType Leaf)) `
        $transactionRoot

    $transactionCountBeforeVerify = @(Get-ChildItem -LiteralPath (
            Join-Path $primary.Backups 'twills-provisioning') -Directory).Count
    $hashBeforeVerify = (Get-FileHash -LiteralPath $primary.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $bankHashBeforeVerify = (Get-FileHash -LiteralPath $primary.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $verifyActionOutput = @(& $provisioningScript -Action Verify `
            -RuntimeRoot $primary.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash)
    $verifyAction = Get-ActionResult -Output $verifyActionOutput -Action 'Verify'
    $hashAfterVerify = (Get-FileHash -LiteralPath $primary.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $bankHashAfterVerify = (Get-FileHash -LiteralPath $primary.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $transactionCountAfterVerify = @(Get-ChildItem -LiteralPath (
            Join-Path $primary.Backups 'twills-provisioning') -Directory).Count
    Add-Result 'Verify is byte-for-byte read-only and creates no transaction' (
        $verifyAction.Valid -and
        $verifyAction.CharacterSha256 -ceq $hashAfterVerify -and
        $verifyAction.BankSha256 -ceq $bankHashAfterVerify -and
        $hashBeforeVerify -ceq $hashAfterVerify -and
        $bankHashBeforeVerify -ceq $bankHashAfterVerify -and
        $transactionCountBeforeVerify -eq $transactionCountAfterVerify) `
        "character=$hashAfterVerify; bank=$bankHashAfterVerify"

    $wrongHash = New-TestRuntime -Parent $temporaryRoot -Name 'wrong-hash'
    $wrongHashBefore = (Get-FileHash -LiteralPath $wrongHash.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongHashRejected = Test-Rejected -Pattern 'explicit source SHA-256' -Operation {
        & $provisioningScript -Action Apply -RuntimeRoot $wrongHash.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 ('0' * 64) `
            -ExpectedSourceBankSha256 $wrongHash.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $wrongHash.SigningPublicKeySha256 `
            -Confirm:$false
    }
    Add-Result 'Apply rejects a source-hash mismatch before backup or mutation' (
        $wrongHashRejected -and
        $wrongHashBefore -ceq (Get-FileHash -LiteralPath $wrongHash.CharacterPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -and
        -not (Test-Path -LiteralPath (Join-Path $wrongHash.Backups `
                'twills-provisioning'))) `
        'explicit source pin is mandatory'

    $wrongBankHash = New-TestRuntime -Parent $temporaryRoot -Name 'wrong-bank-hash'
    $wrongBankCharacterBefore = (Get-FileHash `
        -LiteralPath $wrongBankHash.CharacterPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongBankBefore = (Get-FileHash -LiteralPath $wrongBankHash.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongBankRejected = Test-Rejected -Pattern 'explicit source SHA-256' -Operation {
        & $provisioningScript -Action Apply -RuntimeRoot $wrongBankHash.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $wrongBankHash.SourceSha256 `
            -ExpectedSourceBankSha256 ('0' * 64) `
            -ExpectedSigningPublicKeySha256 $wrongBankHash.SigningPublicKeySha256 `
            -Confirm:$false
    }
    Add-Result 'Apply rejects a bank source-hash mismatch before backup or mutation' (
        $wrongBankRejected -and
        $wrongBankCharacterBefore -ceq (Get-FileHash `
            -LiteralPath $wrongBankHash.CharacterPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -and
        $wrongBankBefore -ceq (Get-FileHash -LiteralPath $wrongBankHash.BankPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -and
        -not (Test-Path -LiteralPath (Join-Path $wrongBankHash.Backups `
                'twills-provisioning'))) `
        'both member hashes of the source pair are mandatory'

    $pairFailure = New-TestRuntime -Parent $temporaryRoot -Name 'pair-failure'
    $characterLock = [System.IO.FileStream]::new(
        $pairFailure.CharacterPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $pairFailureRejected = Test-Rejected -Pattern '.' -Operation {
            & $provisioningScript -Action Apply -RuntimeRoot $pairFailure.Root `
                -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
                -ExpectedSourceSha256 $pairFailure.SourceSha256 `
                -ExpectedSourceBankSha256 $pairFailure.SourceBankSha256 `
                -ExpectedSigningPublicKeySha256 $pairFailure.SigningPublicKeySha256 `
                -Confirm:$false
        }
    } finally {
        $characterLock.Dispose()
    }
    $pairFailureTransactions = @(Get-ChildItem -LiteralPath (
            Join-Path $pairFailure.Backups 'twills-provisioning') -Directory)
    $pairFailureJournal = if ($pairFailureTransactions.Count -eq 1) {
        Join-Path $pairFailureTransactions[0].FullName `
            'journal\001-apply-failed-rolled-back.json'
    } else {
        ''
    }
    Add-Result 'second-file replacement failure exactly compensates the first file' (
        $pairFailureRejected -and $pairFailureTransactions.Count -eq 1 -and
        (Get-FileHash -LiteralPath $pairFailure.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $pairFailure.SourceSha256 -and
        (Get-FileHash -LiteralPath $pairFailure.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $pairFailure.SourceBankSha256 -and
        (Test-Path -LiteralPath $pairFailureJournal -PathType Leaf) -and
        @(Get-ChildItem -LiteralPath $pairFailure.Players -Force -File |
            Where-Object Name -like '.twills-slot0-*').Count -eq 0) `
        'a locked PSOCHAR forces failure after bank-first replacement and records compensation'

    $failedIntentRejected = $false
    $failedIntentHasNoFinal = $false
    if ($pairFailureTransactions.Count -eq 1) {
        $pairFailureTransaction = $pairFailureTransactions[0].FullName
        $pairFailureManifestPath = Join-Path $pairFailureTransaction 'manifest.json'
        $pairFailureManifest = Get-Content -Raw -LiteralPath $pairFailureManifestPath |
            ConvertFrom-Json -Depth 20
        $failedIntent = [ordered]@{
            schemaVersion = 1
            transactionId = [string]$pairFailureManifest.transactionId
            state = 'rollback-intent'
            recordedAtUtc = [DateTime]::UtcNow.ToString('o')
            manifestSha256 = (Get-FileHash -LiteralPath $pairFailureManifestPath `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            characterSha256 = [string]$pairFailureManifest.provisionedSha256
            bankSha256 = [string]$pairFailureManifest.provisionedBankSha256
        }
        $failedIntentPath = Join-Path $pairFailureTransaction `
            'journal\001-rollback-intent.json'
        [System.IO.File]::WriteAllText(
            $failedIntentPath,
            ($failedIntent | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false))
        Set-PSOBBProtectedAcl -Path $failedIntentPath
        $failedIntentRejected = Test-Rejected `
            -Pattern 'conflicting validated 001' -Operation {
            & $provisioningScript -Action Rollback -RuntimeRoot $pairFailure.Root `
                -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
                -ExpectedSigningPublicKeySha256 $pairFailure.SigningPublicKeySha256 `
                -TransactionPath $pairFailureTransaction -Confirm:$false
        }
        $failedIntentHasNoFinal = -not (Test-Path -LiteralPath (
                Join-Path $pairFailureTransaction 'journal\002-rolled-back.json'))
    }
    Add-Result 'conflicting ApplyFailed and RollbackIntent entries fail closed' (
        $failedIntentRejected -and $failedIntentHasNoFinal -and
        (Get-FileHash -LiteralPath $pairFailure.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $pairFailure.SourceSha256 -and
        (Get-FileHash -LiteralPath $pairFailure.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $pairFailure.SourceBankSha256) `
        'compensated failure cannot also claim an independent rollback intent'

    $preparedOnly = New-TestRuntime -Parent $temporaryRoot -Name 'prepared-only'
    $bankLock = [System.IO.FileStream]::new(
        $preparedOnly.BankPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $preparedApplyRejected = Test-Rejected -Pattern '.' -Operation {
            & $provisioningScript -Action Apply -RuntimeRoot $preparedOnly.Root `
                -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
                -ExpectedSourceSha256 $preparedOnly.SourceSha256 `
                -ExpectedSourceBankSha256 $preparedOnly.SourceBankSha256 `
                -ExpectedSigningPublicKeySha256 $preparedOnly.SigningPublicKeySha256 `
                -Confirm:$false
        }
    } finally {
        $bankLock.Dispose()
    }
    $preparedTransactions = @(Get-ChildItem -LiteralPath (
            Join-Path $preparedOnly.Backups 'twills-provisioning') -Directory)
    $preparedRollbackRejected = if ($preparedTransactions.Count -eq 1) {
        Test-Rejected -Pattern 'prepared-only' -Operation {
            & $provisioningScript -Action Rollback -RuntimeRoot $preparedOnly.Root `
                -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
                -ExpectedSigningPublicKeySha256 $preparedOnly.SigningPublicKeySha256 `
                -TransactionPath $preparedTransactions[0].FullName `
                -Confirm:$false
        }
    } else {
        $false
    }
    $preparedRollbackJournal = if ($preparedTransactions.Count -eq 1) {
        Join-Path $preparedTransactions[0].FullName 'journal\002-rolled-back.json'
    } else {
        ''
    }
    Add-Result 'prepared-only source state cannot be mislabeled as a rollback' (
        $preparedApplyRejected -and $preparedTransactions.Count -eq 1 -and
        $preparedRollbackRejected -and
        -not (Test-Path -LiteralPath $preparedRollbackJournal) -and
        (Get-FileHash -LiteralPath $preparedOnly.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $preparedOnly.SourceSha256 -and
        (Get-FileHash -LiteralPath $preparedOnly.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $preparedOnly.SourceBankSha256) `
        'a bank-first failure leaves only prepared evidence and rollback refuses to relabel it'

    $crashProvisioned = New-TestRuntime -Parent $temporaryRoot -Name 'crash-provisioned'
    $crashProvisionedApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $crashProvisioned.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $crashProvisioned.SourceSha256 `
            -ExpectedSourceBankSha256 $crashProvisioned.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $crashProvisioned.SigningPublicKeySha256 `
            -Confirm:$false)
    $crashProvisionedApply = Get-ActionResult `
        -Output $crashProvisionedApplyOutput -Action 'Apply'
    Remove-Item -LiteralPath (Join-Path `
        ([string]$crashProvisionedApply.TransactionPath) `
        'journal\001-applied.json') -Force
    $crashProvisionedRollbackOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $crashProvisioned.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $crashProvisioned.SigningPublicKeySha256 `
            -TransactionPath ([string]$crashProvisionedApply.TransactionPath) `
            -Confirm:$false)
    $crashProvisionedRollback = Get-ActionResult `
        -Output $crashProvisionedRollbackOutput -Action 'Rollback'
    $crashProvisionedRepeatOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $crashProvisioned.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $crashProvisioned.SigningPublicKeySha256 `
            -TransactionPath ([string]$crashProvisionedApply.TransactionPath) `
            -Confirm:$false)
    $crashProvisionedRepeat = Get-ActionResult `
        -Output $crashProvisionedRepeatOutput -Action 'Rollback'
    Add-Result 'prepared-only provisioned pair remains exactly crash-recoverable' (
        $crashProvisionedRollback.Changed -and
        -not $crashProvisionedRepeat.Changed -and
        $crashProvisionedRepeat.AlreadyRolledBack -and
        (Get-FileHash -LiteralPath $crashProvisioned.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $crashProvisioned.SourceSha256 -and
        (Get-FileHash -LiteralPath $crashProvisioned.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $crashProvisioned.SourceBankSha256) `
        'valid 000 plus both exact signed after hashes can restore both source files'

    $crashMixed = New-TestRuntime -Parent $temporaryRoot -Name 'crash-mixed'
    $crashMixedApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $crashMixed.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $crashMixed.SourceSha256 `
            -ExpectedSourceBankSha256 $crashMixed.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $crashMixed.SigningPublicKeySha256 `
            -Confirm:$false)
    $crashMixedApply = Get-ActionResult `
        -Output $crashMixedApplyOutput -Action 'Apply'
    Remove-Item -LiteralPath (Join-Path `
        ([string]$crashMixedApply.TransactionPath) 'journal\001-applied.json') -Force
    [System.IO.File]::WriteAllBytes($crashMixed.CharacterPath, $crashMixed.SourceBytes)
    Set-PSOBBProtectedAcl -Path $crashMixed.CharacterPath
    $crashMixedRollbackOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $crashMixed.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $crashMixed.SigningPublicKeySha256 `
            -TransactionPath ([string]$crashMixedApply.TransactionPath) `
            -Confirm:$false)
    $crashMixedRollback = Get-ActionResult `
        -Output $crashMixedRollbackOutput -Action 'Rollback'
    $crashMixedRepeatOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $crashMixed.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $crashMixed.SigningPublicKeySha256 `
            -TransactionPath ([string]$crashMixedApply.TransactionPath) `
            -Confirm:$false)
    $crashMixedRepeat = Get-ActionResult `
        -Output $crashMixedRepeatOutput -Action 'Rollback'
    Add-Result 'prepared-only mixed pair remains exactly crash-recoverable' (
        $crashMixedRollback.Changed -and
        -not $crashMixedRepeat.Changed -and $crashMixedRepeat.AlreadyRolledBack -and
        (Get-FileHash -LiteralPath $crashMixed.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $crashMixed.SourceSha256 -and
        (Get-FileHash -LiteralPath $crashMixed.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $crashMixed.SourceBankSha256) `
        'valid 000 plus one source and one after hash restores only the remaining after file'

    $crashMixedCharacter = New-TestRuntime `
        -Parent $temporaryRoot -Name 'crash-mixed-character'
    $crashMixedCharacterApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $crashMixedCharacter.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $crashMixedCharacter.SourceSha256 `
            -ExpectedSourceBankSha256 $crashMixedCharacter.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 `
                $crashMixedCharacter.SigningPublicKeySha256 `
            -Confirm:$false)
    $crashMixedCharacterApply = Get-ActionResult `
        -Output $crashMixedCharacterApplyOutput -Action 'Apply'
    Remove-Item -LiteralPath (Join-Path `
        ([string]$crashMixedCharacterApply.TransactionPath) `
        'journal\001-applied.json') -Force
    [System.IO.File]::WriteAllBytes(
        $crashMixedCharacter.BankPath,
        $crashMixedCharacter.SourceBankBytes)
    Set-PSOBBProtectedAcl -Path $crashMixedCharacter.BankPath
    $crashMixedCharacterRollbackOutput = @(& $provisioningScript `
            -Action Rollback -RuntimeRoot $crashMixedCharacter.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 `
                $crashMixedCharacter.SigningPublicKeySha256 `
            -TransactionPath ([string]$crashMixedCharacterApply.TransactionPath) `
            -Confirm:$false)
    $crashMixedCharacterRollback = Get-ActionResult `
        -Output $crashMixedCharacterRollbackOutput -Action 'Rollback'
    Add-Result 'prepared-only opposite mixed pair is exactly crash-recoverable' (
        $crashMixedCharacterRollback.Changed -and
        (Get-FileHash -LiteralPath $crashMixedCharacter.CharacterPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
                $crashMixedCharacter.SourceSha256 -and
        (Get-FileHash -LiteralPath $crashMixedCharacter.BankPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
                $crashMixedCharacter.SourceBankSha256) `
        'valid 000 also covers the character-after and bank-source interruption order'

    $wrongSlot = New-TestRuntime -Parent $temporaryRoot -Name 'wrong-slot' `
        -SlotIndex 1
    $wrongSlotBefore = (Get-FileHash -LiteralPath $wrongSlot.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongSlotRejected = Test-Rejected -Pattern 'exactly one slot-0' -Operation {
        & $provisioningScript -Action Apply -RuntimeRoot $wrongSlot.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $wrongSlot.SourceSha256 `
            -ExpectedSourceBankSha256 $wrongSlot.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $wrongSlot.SigningPublicKeySha256 `
            -Confirm:$false
    }
    Add-Result 'slot 1 is never accepted or modified' (
        $wrongSlotRejected -and
        $wrongSlotBefore -ceq (Get-FileHash -LiteralPath $wrongSlot.CharacterPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()) `
        'only a player_*_0.psochar target is discoverable'

    $wrongClass = New-TestRuntime -Parent $temporaryRoot -Name 'wrong-class' `
        -ClassId 7
    $wrongClassBefore = (Get-FileHash -LiteralPath $wrongClass.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrongClassRejected = Test-Rejected -Pattern 'exact existing slot-0' -Operation {
        & $provisioningScript -Action Apply -RuntimeRoot $wrongClass.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $wrongClass.SourceSha256 `
            -ExpectedSourceBankSha256 $wrongClass.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $wrongClass.SigningPublicKeySha256 `
            -Confirm:$false
    }
    Add-Result 'non-FOnewearl identity fails before backup or mutation' (
        $wrongClassRejected -and
        $wrongClassBefore -ceq (Get-FileHash -LiteralPath $wrongClass.CharacterPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -and
        -not (Test-Path -LiteralPath (Join-Path $wrongClass.Backups `
                'twills-provisioning'))) `
        'class and redundant Guild Card class must both be 8'

    $wrongBuildPin = New-TestRuntime -Parent $temporaryRoot -Name 'wrong-build-pin'
    $wrongBuildRejected = Test-Rejected -Pattern 'explicitly pinned SHA-256' -Operation {
        & $provisioningScript -Action Verify -RuntimeRoot $wrongBuildPin.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 ('0' * 64)
    }
    Add-Result 'contract hash mismatch fails before runtime mutation' (
        $wrongBuildRejected -and
        -not (Test-Path -LiteralPath (Join-Path $wrongBuildPin.Backups `
                'twills-provisioning'))) `
        'the canonical config path and exact bytes are both pinned'

    $manifestHashBeforeRollback = (Get-FileHash -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $signatureHashBeforeRollback = (Get-FileHash -LiteralPath $signaturePath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $rollbackOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $primary.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $primary.SigningPublicKeySha256 `
            -TransactionPath $transactionRoot -Confirm:$false)
    $rollback = Get-ActionResult -Output $rollbackOutput -Action 'Rollback'
    $rolledBackHash = (Get-FileHash -LiteralPath $primary.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $rolledBackBankHash = (Get-FileHash -LiteralPath $primary.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Result 'Rollback restores both exact sealed source files' (
        $rollback.Changed -and
        $rolledBackHash -ceq $primary.SourceSha256 -and
        $rolledBackBankHash -ceq $primary.SourceBankSha256 -and
        (Test-ByteRangeEqual -Left $primary.SourceBytes `
            -Right ([System.IO.File]::ReadAllBytes($primary.CharacterPath)) `
            -Offset 0 -Count $primary.SourceBytes.Length) -and
        (Test-ByteRangeEqual -Left $primary.SourceBankBytes `
            -Right ([System.IO.File]::ReadAllBytes($primary.BankPath)) `
            -Offset 0 -Count $primary.SourceBankBytes.Length) -and
        (Test-Path -LiteralPath (Join-Path $transactionRoot `
                'journal\002-rolled-back.json') -PathType Leaf) -and
        $manifestHashBeforeRollback -ceq (Get-FileHash -LiteralPath $manifestPath `
            -Algorithm SHA256).Hash.ToLowerInvariant() -and
        $signatureHashBeforeRollback -ceq (Get-FileHash -LiteralPath $signaturePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()) `
        "character=$rolledBackHash; bank=$rolledBackBankHash"

    $secondRollbackOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $primary.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $primary.SigningPublicKeySha256 `
            -TransactionPath $transactionRoot -Confirm:$false)
    $secondRollback = Get-ActionResult -Output $secondRollbackOutput `
        -Action 'Rollback'
    Add-Result 'repeated Rollback is an exact read-only no-op' (
        -not $secondRollback.Changed -and $secondRollback.AlreadyRolledBack -and
        (Get-FileHash -LiteralPath $primary.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $primary.SourceSha256 -and
        (Get-FileHash -LiteralPath $primary.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $primary.SourceBankSha256) `
        'already-rolled-back state is recognized only for the full sealed pair'

    $journalRecovery = New-TestRuntime -Parent $temporaryRoot -Name 'journal-recovery'
    $journalRecoveryApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $journalRecovery.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $journalRecovery.SourceSha256 `
            -ExpectedSourceBankSha256 $journalRecovery.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $journalRecovery.SigningPublicKeySha256 `
            -Confirm:$false)
    $journalRecoveryApply = Get-ActionResult `
        -Output $journalRecoveryApplyOutput -Action 'Apply'
    [System.IO.File]::WriteAllBytes(
        $journalRecovery.CharacterPath,
        $journalRecovery.SourceBytes)
    [System.IO.File]::WriteAllBytes(
        $journalRecovery.BankPath,
        $journalRecovery.SourceBankBytes)
    Set-PSOBBProtectedAcl -Path $journalRecovery.CharacterPath
    Set-PSOBBProtectedAcl -Path $journalRecovery.BankPath
    $recoveredJournalPath = Join-Path ([string]$journalRecoveryApply.TransactionPath) `
        'journal\002-rolled-back.json'
    $journalRecoveryOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $journalRecovery.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $journalRecovery.SigningPublicKeySha256 `
            -TransactionPath ([string]$journalRecoveryApply.TransactionPath) `
            -Confirm:$false)
    $journalRecoveryResult = Get-ActionResult `
        -Output $journalRecoveryOutput -Action 'Rollback'
    Add-Result 'already-restored bytes recover missing create-only rollback evidence' (
        -not $journalRecoveryResult.Changed -and
        $journalRecoveryResult.AlreadyRolledBack -and
        $journalRecoveryResult.EvidenceRecorded -and
        $journalRecoveryResult.JournalComplete -and
        (Test-Path -LiteralPath $recoveredJournalPath -PathType Leaf)) `
        'rerun records the missing 002 journal entry without rewriting either save file'

    $intentRecovery = New-TestRuntime -Parent $temporaryRoot -Name 'intent-recovery'
    $intentRecoveryApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $intentRecovery.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $intentRecovery.SourceSha256 `
            -ExpectedSourceBankSha256 $intentRecovery.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $intentRecovery.SigningPublicKeySha256 `
            -Confirm:$false)
    $intentRecoveryApply = Get-ActionResult `
        -Output $intentRecoveryApplyOutput -Action 'Apply'
    $intentRecoveryTransaction = [string]$intentRecoveryApply.TransactionPath
    Remove-Item -LiteralPath (Join-Path $intentRecoveryTransaction `
        'journal\001-applied.json') -Force
    $intentRecoveryManifestPath = Join-Path $intentRecoveryTransaction 'manifest.json'
    $intentRecoveryManifest = Get-Content -Raw `
        -LiteralPath $intentRecoveryManifestPath | ConvertFrom-Json -Depth 20
    $intentRecoveryEntry = [ordered]@{
        schemaVersion = 1
        transactionId = [string]$intentRecoveryManifest.transactionId
        state = 'rollback-intent'
        recordedAtUtc = [DateTime]::UtcNow.ToString('o')
        manifestSha256 = (Get-FileHash -LiteralPath $intentRecoveryManifestPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        characterSha256 = [string]$intentRecoveryManifest.provisionedSha256
        bankSha256 = [string]$intentRecoveryManifest.provisionedBankSha256
    }
    $intentRecoveryPath = Join-Path $intentRecoveryTransaction `
        'journal\001-rollback-intent.json'
    [System.IO.File]::WriteAllText(
        $intentRecoveryPath,
        ($intentRecoveryEntry | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $intentRecoveryPath
    [System.IO.File]::WriteAllBytes(
        $intentRecovery.CharacterPath,
        $intentRecovery.SourceBytes)
    [System.IO.File]::WriteAllBytes(
        $intentRecovery.BankPath,
        $intentRecovery.SourceBankBytes)
    Set-PSOBBProtectedAcl -Path $intentRecovery.CharacterPath
    Set-PSOBBProtectedAcl -Path $intentRecovery.BankPath
    $intentRecoveryOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $intentRecovery.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $intentRecovery.SigningPublicKeySha256 `
            -TransactionPath $intentRecoveryTransaction -Confirm:$false)
    $intentRecoveryResult = Get-ActionResult `
        -Output $intentRecoveryOutput -Action 'Rollback'
    $intentRecoveryRepeatOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $intentRecovery.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $intentRecovery.SigningPublicKeySha256 `
            -TransactionPath $intentRecoveryTransaction -Confirm:$false)
    $intentRecoveryRepeat = Get-ActionResult `
        -Output $intentRecoveryRepeatOutput -Action 'Rollback'
    Add-Result 'source pair with durable rollback intent repairs missing final evidence' (
        -not $intentRecoveryResult.Changed -and
        $intentRecoveryResult.AlreadyRolledBack -and
        $intentRecoveryResult.EvidenceRecorded -and
        -not $intentRecoveryRepeat.Changed -and
        $intentRecoveryRepeat.AlreadyRolledBack -and
        (Test-Path -LiteralPath (Join-Path $intentRecoveryTransaction `
                'journal\002-rolled-back.json') -PathType Leaf)) `
        'a retry after restoration but before 002 creation completes evidence only'

    $mixedBank = New-TestRuntime -Parent $temporaryRoot -Name 'mixed-bank'
    $mixedBankApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $mixedBank.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $mixedBank.SourceSha256 `
            -ExpectedSourceBankSha256 $mixedBank.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $mixedBank.SigningPublicKeySha256 `
            -Confirm:$false)
    $mixedBankApply = Get-ActionResult -Output $mixedBankApplyOutput -Action 'Apply'
    [System.IO.File]::WriteAllBytes($mixedBank.CharacterPath, $mixedBank.SourceBytes)
    Set-PSOBBProtectedAcl -Path $mixedBank.CharacterPath
    $mixedBankRollbackOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $mixedBank.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $mixedBank.SigningPublicKeySha256 `
            -TransactionPath ([string]$mixedBankApply.TransactionPath) `
            -Confirm:$false)
    $mixedBankRollback = Get-ActionResult -Output $mixedBankRollbackOutput `
        -Action 'Rollback'
    Add-Result 'Rollback safely completes a source-character/provisioned-bank mixed pair' (
        $mixedBankRollback.Changed -and
        (Get-FileHash -LiteralPath $mixedBank.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $mixedBank.SourceSha256 -and
        (Get-FileHash -LiteralPath $mixedBank.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $mixedBank.SourceBankSha256) `
        'only the still-provisioned authoritative bank is restored'

    $mixedCharacter = New-TestRuntime -Parent $temporaryRoot -Name 'mixed-character'
    $mixedCharacterApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $mixedCharacter.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $mixedCharacter.SourceSha256 `
            -ExpectedSourceBankSha256 $mixedCharacter.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $mixedCharacter.SigningPublicKeySha256 `
            -Confirm:$false)
    $mixedCharacterApply = Get-ActionResult -Output $mixedCharacterApplyOutput `
        -Action 'Apply'
    [System.IO.File]::WriteAllBytes(
        $mixedCharacter.BankPath,
        $mixedCharacter.SourceBankBytes)
    Set-PSOBBProtectedAcl -Path $mixedCharacter.BankPath
    $mixedCharacterRollbackOutput = @(& $provisioningScript -Action Rollback `
            -RuntimeRoot $mixedCharacter.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $mixedCharacter.SigningPublicKeySha256 `
            -TransactionPath ([string]$mixedCharacterApply.TransactionPath) `
            -Confirm:$false)
    $mixedCharacterRollback = Get-ActionResult `
        -Output $mixedCharacterRollbackOutput -Action 'Rollback'
    Add-Result 'Rollback safely completes a provisioned-character/source-bank mixed pair' (
        $mixedCharacterRollback.Changed -and
        (Get-FileHash -LiteralPath $mixedCharacter.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $mixedCharacter.SourceSha256 -and
        (Get-FileHash -LiteralPath $mixedCharacter.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $mixedCharacter.SourceBankSha256) `
        'only the still-provisioned character file is restored'

    $drift = New-TestRuntime -Parent $temporaryRoot -Name 'drift'
    $driftApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $drift.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $drift.SourceSha256 `
            -ExpectedSourceBankSha256 $drift.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $drift.SigningPublicKeySha256 `
            -Confirm:$false)
    $driftApply = Get-ActionResult -Output $driftApplyOutput -Action 'Apply'
    $driftBytes = [System.IO.File]::ReadAllBytes($drift.CharacterPath)
    $driftBytes[0x500] = $driftBytes[0x500] -bxor 1
    [System.IO.File]::WriteAllBytes($drift.CharacterPath, $driftBytes)
    Set-PSOBBProtectedAcl -Path $drift.CharacterPath
    $driftHash = Get-TestSha256Bytes -Bytes $driftBytes
    $driftRejected = Test-Rejected `
        -Pattern 'outside the exact signed source/after matrix' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $drift.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $drift.SigningPublicKeySha256 `
            -TransactionPath ([string]$driftApply.TransactionPath) `
            -Confirm:$false
    }
    Add-Result 'Rollback rejects post-provisioning character drift' (
        $driftRejected -and
        (Get-FileHash -LiteralPath $drift.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $driftHash) `
        'rollback cannot overwrite intervening character changes'

    $bankDrift = New-TestRuntime -Parent $temporaryRoot -Name 'bank-drift'
    $bankDriftApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $bankDrift.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $bankDrift.SourceSha256 `
            -ExpectedSourceBankSha256 $bankDrift.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $bankDrift.SigningPublicKeySha256 `
            -Confirm:$false)
    $bankDriftApply = Get-ActionResult -Output $bankDriftApplyOutput -Action 'Apply'
    $bankDriftBytes = [System.IO.File]::ReadAllBytes($bankDrift.BankPath)
    $bankDriftBytes[16] = $bankDriftBytes[16] -bxor 1
    [System.IO.File]::WriteAllBytes($bankDrift.BankPath, $bankDriftBytes)
    Set-PSOBBProtectedAcl -Path $bankDrift.BankPath
    $bankDriftHash = Get-TestSha256Bytes -Bytes $bankDriftBytes
    $bankDriftCharacterHash = (Get-FileHash `
        -LiteralPath $bankDrift.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $bankDriftRejected = Test-Rejected `
        -Pattern 'outside the exact signed source/after matrix' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $bankDrift.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $bankDrift.SigningPublicKeySha256 `
            -TransactionPath ([string]$bankDriftApply.TransactionPath) `
            -Confirm:$false
    }
    Add-Result 'Rollback rejects post-provisioning authoritative-bank drift' (
        $bankDriftRejected -and
        (Get-FileHash -LiteralPath $bankDrift.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $bankDriftHash -and
        (Get-FileHash -LiteralPath $bankDrift.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $bankDriftCharacterHash) `
        'rollback cannot overwrite intervening bank changes or touch the paired character'

    $preparedTamper = New-TestRuntime -Parent $temporaryRoot -Name 'prepared-tamper'
    $preparedTamperApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $preparedTamper.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $preparedTamper.SourceSha256 `
            -ExpectedSourceBankSha256 $preparedTamper.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $preparedTamper.SigningPublicKeySha256 `
            -Confirm:$false)
    $preparedTamperApply = Get-ActionResult `
        -Output $preparedTamperApplyOutput -Action 'Apply'
    $preparedTamperCharacterHash = (Get-FileHash `
        -LiteralPath $preparedTamper.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $preparedTamperBankHash = (Get-FileHash `
        -LiteralPath $preparedTamper.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $preparedJournalPath = Join-Path ([string]$preparedTamperApply.TransactionPath) `
        'journal\000-prepared.json'
    $preparedJournal = Get-Content -Raw -LiteralPath $preparedJournalPath |
        ConvertFrom-Json -Depth 5
    $preparedJournal.state = 'tampered'
    [System.IO.File]::WriteAllText(
        $preparedJournalPath,
        ($preparedJournal | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $preparedJournalPath
    $preparedTamperRejected = Test-Rejected -Pattern 'journal evidence' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $preparedTamper.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $preparedTamper.SigningPublicKeySha256 `
            -TransactionPath ([string]$preparedTamperApply.TransactionPath) `
            -Confirm:$false
    }
    Add-Result 'corrupt prepared evidence blocks provisioned-pair rollback before mutation' (
        $preparedTamperRejected -and
        (Get-FileHash -LiteralPath $preparedTamper.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $preparedTamperCharacterHash -and
        (Get-FileHash -LiteralPath $preparedTamper.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $preparedTamperBankHash) `
        '000-prepared is preflighted while both files still have provisioned hashes'

    $staleRollback = New-TestRuntime -Parent $temporaryRoot -Name 'stale-rollback'
    $staleRollbackApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $staleRollback.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $staleRollback.SourceSha256 `
            -ExpectedSourceBankSha256 $staleRollback.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $staleRollback.SigningPublicKeySha256 `
            -Confirm:$false)
    $staleRollbackApply = Get-ActionResult `
        -Output $staleRollbackApplyOutput -Action 'Apply'
    $staleProvisionedBankHash = (Get-FileHash `
        -LiteralPath $staleRollback.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllBytes(
        $staleRollback.CharacterPath,
        $staleRollback.SourceBytes)
    Set-PSOBBProtectedAcl -Path $staleRollback.CharacterPath
    $staleManifestPath = Join-Path ([string]$staleRollbackApply.TransactionPath) `
        'manifest.json'
    $staleManifest = Get-Content -Raw -LiteralPath $staleManifestPath |
        ConvertFrom-Json -Depth 20
    $staleEntry = [ordered]@{
        schemaVersion = 1
        transactionId = [string]$staleManifest.transactionId
        state = 'rolled-back'
        recordedAtUtc = [DateTime]::UtcNow.ToString('o')
        manifestSha256 = (Get-FileHash -LiteralPath $staleManifestPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        characterSha256 = [string]$staleManifest.sourceSha256
        bankSha256 = [string]$staleManifest.sourceBankSha256
    }
    $staleJournalPath = Join-Path ([string]$staleRollbackApply.TransactionPath) `
        'journal\002-rolled-back.json'
    [System.IO.File]::WriteAllText(
        $staleJournalPath,
        ($staleEntry | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $staleJournalPath
    $staleRollbackRejected = Test-Rejected `
        -Pattern 'journal state is incompatible' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $staleRollback.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $staleRollback.SigningPublicKeySha256 `
            -TransactionPath ([string]$staleRollbackApply.TransactionPath) `
            -Confirm:$false
    }
    Add-Result 'stale valid rolled-back evidence blocks mixed-pair rollback before mutation' (
        $staleRollbackRejected -and
        (Get-FileHash -LiteralPath $staleRollback.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $staleRollback.SourceSha256 -and
        (Get-FileHash -LiteralPath $staleRollback.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $staleProvisionedBankHash) `
        'a valid-looking 002 entry cannot authorize mutation of a mixed pair'

    $journalConflict = New-TestRuntime -Parent $temporaryRoot -Name 'journal-conflict'
    $journalConflictApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $journalConflict.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $journalConflict.SourceSha256 `
            -ExpectedSourceBankSha256 $journalConflict.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $journalConflict.SigningPublicKeySha256 `
            -Confirm:$false)
    $journalConflictApply = Get-ActionResult `
        -Output $journalConflictApplyOutput -Action 'Apply'
    $journalConflictTransaction = [string]$journalConflictApply.TransactionPath
    $journalConflictManifestPath = Join-Path $journalConflictTransaction 'manifest.json'
    $journalConflictManifest = Get-Content -Raw `
        -LiteralPath $journalConflictManifestPath | ConvertFrom-Json -Depth 20
    $journalConflictManifestHash = (Get-FileHash `
        -LiteralPath $journalConflictManifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $journalConflictCharacterHash = (Get-FileHash `
        -LiteralPath $journalConflict.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $journalConflictBankHash = (Get-FileHash `
        -LiteralPath $journalConflict.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $conflictIntentPath = Join-Path $journalConflictTransaction `
        'journal\001-rollback-intent.json'
    $conflictIntent = [ordered]@{
        schemaVersion = 1
        transactionId = [string]$journalConflictManifest.transactionId
        state = 'rollback-intent'
        recordedAtUtc = [DateTime]::UtcNow.ToString('o')
        manifestSha256 = $journalConflictManifestHash
        characterSha256 = [string]$journalConflictManifest.provisionedSha256
        bankSha256 = [string]$journalConflictManifest.provisionedBankSha256
    }
    [System.IO.File]::WriteAllText(
        $conflictIntentPath,
        ($conflictIntent | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $conflictIntentPath
    $appliedIntentRejected = Test-Rejected `
        -Pattern 'conflicting validated 001' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $journalConflict.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $journalConflict.SigningPublicKeySha256 `
            -TransactionPath $journalConflictTransaction -Confirm:$false
    }
    Add-Result 'conflicting Applied and RollbackIntent entries fail before mutation' (
        $appliedIntentRejected -and
        (Get-FileHash -LiteralPath $journalConflict.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $journalConflictCharacterHash -and
        (Get-FileHash -LiteralPath $journalConflict.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $journalConflictBankHash) `
        'exact individual entries cannot form an unrecognized dual-predecessor state'
    Remove-Item -LiteralPath $conflictIntentPath -Force
    $conflictFailedPath = Join-Path $journalConflictTransaction `
        'journal\001-apply-failed-rolled-back.json'
    $conflictFailed = [ordered]@{
        schemaVersion = 1
        transactionId = [string]$journalConflictManifest.transactionId
        state = 'apply-failed-rolled-back'
        recordedAtUtc = [DateTime]::UtcNow.ToString('o')
        manifestSha256 = $journalConflictManifestHash
        characterSha256 = [string]$journalConflictManifest.sourceSha256
        bankSha256 = [string]$journalConflictManifest.sourceBankSha256
    }
    [System.IO.File]::WriteAllText(
        $conflictFailedPath,
        ($conflictFailed | ConvertTo-Json -Depth 5),
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $conflictFailedPath
    $appliedFailedRejected = Test-Rejected `
        -Pattern 'conflicting validated 001' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $journalConflict.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $journalConflict.SigningPublicKeySha256 `
            -TransactionPath $journalConflictTransaction -Confirm:$false
    }
    Add-Result 'conflicting Applied and ApplyFailed entries fail before mutation' (
        $appliedFailedRejected -and
        (Get-FileHash -LiteralPath $journalConflict.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $journalConflictCharacterHash -and
        (Get-FileHash -LiteralPath $journalConflict.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $journalConflictBankHash) `
        'successful and compensated failure predecessors are mutually exclusive'

    $tamper = New-TestRuntime -Parent $temporaryRoot -Name 'tamper'
    $tamperApplyOutput = @(& $provisioningScript -Action Apply `
            -RuntimeRoot $tamper.Root -BuildPath $buildPath `
            -ExpectedBuildSha256 $buildHash `
            -ExpectedSourceSha256 $tamper.SourceSha256 `
            -ExpectedSourceBankSha256 $tamper.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $tamper.SigningPublicKeySha256 `
            -Confirm:$false)
    $tamperApply = Get-ActionResult -Output $tamperApplyOutput -Action 'Apply'
    $tamperCurrentHash = (Get-FileHash -LiteralPath $tamper.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $tamperCurrentBankHash = (Get-FileHash -LiteralPath $tamper.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $tamperManifestPath = Join-Path ([string]$tamperApply.TransactionPath) `
        'manifest.json'
    $tamperManifestBytes = [System.IO.File]::ReadAllBytes($tamperManifestPath)
    $tamperManifestBytes[10] = $tamperManifestBytes[10] -bxor 1
    [System.IO.File]::WriteAllBytes($tamperManifestPath, $tamperManifestBytes)
    Set-PSOBBProtectedAcl -Path $tamperManifestPath
    $tamperRejected = Test-Rejected -Pattern 'signature is invalid' -Operation {
        & $provisioningScript -Action Rollback -RuntimeRoot $tamper.Root `
            -BuildPath $buildPath -ExpectedBuildSha256 $buildHash `
            -ExpectedSigningPublicKeySha256 $tamper.SigningPublicKeySha256 `
            -TransactionPath ([string]$tamperApply.TransactionPath) `
            -Confirm:$false
    }
    Add-Result 'Rollback rejects a tampered sealed manifest' (
        $tamperRejected -and
        (Get-FileHash -LiteralPath $tamper.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $tamperCurrentHash -and
        (Get-FileHash -LiteralPath $tamper.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $tamperCurrentBankHash) `
        'ECDSA P-256 signature binds the transaction manifest'

    $historicalRepo = Join-Path $temporaryRoot 'historical-repo'
    $historicalScripts = Join-Path $historicalRepo 'scripts'
    $historicalConfig = Join-Path $historicalRepo 'config'
    New-Item -ItemType Directory -Path $historicalScripts | Out-Null
    New-Item -ItemType Directory -Path $historicalConfig | Out-Null
    foreach ($scriptName in @(
            'Set-PSOBBTwillsProvisioning.ps1',
            'PSOBB.Common.ps1',
            'Get-PSOBBCharacterSummary.ps1',
            'Test-PSOBBCharacterBuild.ps1',
            'Test-PSOBBTwillsBank.ps1')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot ('scripts\' + $scriptName)) `
            -Destination (Join-Path $historicalScripts $scriptName)
    }
    foreach ($configName in @(
            'twills-fonewearl-build.json',
            'sources.lock.json',
            'release-trust.json')) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot ('config\' + $configName)) `
            -Destination (Join-Path $historicalConfig $configName)
    }
    $historicalScript = Join-Path $historicalScripts `
        'Set-PSOBBTwillsProvisioning.ps1'
    $historicalBuildPath = Join-Path $historicalConfig `
        'twills-fonewearl-build.json'
    $historicalSourceLockPath = Join-Path $historicalConfig 'sources.lock.json'
    $historicalBuildHash = (Get-FileHash -LiteralPath $historicalBuildPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $historical = New-TestRuntime -Parent $temporaryRoot -Name 'historical-runtime'
    $historicalApplyOutput = @(& $historicalScript -Action Apply `
            -RuntimeRoot $historical.Root -BuildPath $historicalBuildPath `
            -ExpectedBuildSha256 $historicalBuildHash `
            -ExpectedSourceSha256 $historical.SourceSha256 `
            -ExpectedSourceBankSha256 $historical.SourceBankSha256 `
            -ExpectedSigningPublicKeySha256 $historical.SigningPublicKeySha256 `
            -Confirm:$false)
    $historicalApply = Get-ActionResult `
        -Output $historicalApplyOutput -Action 'Apply'
    $historicalProvisionedCharacterHash = (Get-FileHash `
        -LiteralPath $historical.CharacterPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $historicalProvisionedBankHash = (Get-FileHash `
        -LiteralPath $historical.BankPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $historicalTransaction = [string]$historicalApply.TransactionPath
    $archivedBuildPath = Join-Path $historicalTransaction `
        'contract\twills-fonewearl-build.json'
    $archivedPublicKeyPath = Join-Path $historicalTransaction `
        'trust\signing-public-key.pem'
    [System.IO.File]::WriteAllText(
        $historicalBuildPath,
        '{"schemaVersion":999}',
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $historicalSourceLockPath,
        '{}',
        [System.Text.UTF8Encoding]::new($false))
    Remove-Item -LiteralPath (Join-Path $historical.Root `
        'stable\release-public-key.pem') -Force
    $historicalWrongBuildRejected = Test-Rejected `
        -Pattern 'manifest|build' -Operation {
        & $historicalScript -Action Rollback -RuntimeRoot $historical.Root `
            -BuildPath $historicalBuildPath -ExpectedBuildSha256 ('0' * 64) `
            -ExpectedSigningPublicKeySha256 $historical.SigningPublicKeySha256 `
            -TransactionPath $historicalTransaction -Confirm:$false
    }
    $historicalWrongKeyRejected = Test-Rejected `
        -Pattern 'explicit caller pin' -Operation {
        & $historicalScript -Action Rollback -RuntimeRoot $historical.Root `
            -BuildPath $historicalBuildPath `
            -ExpectedBuildSha256 $historicalBuildHash `
            -ExpectedSigningPublicKeySha256 ('0' * 64) `
            -TransactionPath $historicalTransaction -Confirm:$false
    }
    $historicalPinsLeaveStateExact =
        (Get-FileHash -LiteralPath $historical.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $historicalProvisionedCharacterHash -and
        (Get-FileHash -LiteralPath $historical.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $historicalProvisionedBankHash
    $historicalRollbackOutput = @(& $historicalScript -Action Rollback `
            -RuntimeRoot $historical.Root -BuildPath $historicalBuildPath `
            -ExpectedBuildSha256 $historicalBuildHash `
            -ExpectedSigningPublicKeySha256 $historical.SigningPublicKeySha256 `
            -TransactionPath $historicalTransaction -Confirm:$false)
    $historicalRollback = Get-ActionResult `
        -Output $historicalRollbackOutput -Action 'Rollback'
    Add-Result 'historical rollback rejects wrong pins before touching either save' (
        $historicalWrongBuildRejected -and $historicalWrongKeyRejected -and
        $historicalPinsLeaveStateExact) `
        'archived build bytes and archived public-key SPKI both require caller-known hashes'
    Add-Result 'historical rollback survives canonical contract, source-lock, and key rotation' (
        $historicalRollback.Changed -and
        (Test-Path -LiteralPath $archivedBuildPath -PathType Leaf) -and
        (Test-Path -LiteralPath $archivedPublicKeyPath -PathType Leaf) -and
        (Get-FileHash -LiteralPath $historical.CharacterPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $historical.SourceSha256 -and
        (Get-FileHash -LiteralPath $historical.BankPath -Algorithm SHA256).
            Hash.ToLowerInvariant() -ceq $historical.SourceBankSha256) `
        'rollback uses only the signed transaction archives after current files are changed or absent'

    $sourceText = Get-Content -Raw -LiteralPath $provisioningScript
    $atomicStart = $sourceText.IndexOf(
        'function Invoke-PSOBBProvisioningAtomicReplacement',
        [System.StringComparison]::Ordinal)
    $pairStart = $sourceText.IndexOf(
        'function Invoke-PSOBBProvisioningPairedReplacement',
        [System.StringComparison]::Ordinal)
    $atomicBody = $sourceText.Substring($atomicStart, $pairStart - $atomicStart)
    $firstReplace = $atomicBody.IndexOf(
        '[System.IO.File]::Replace(',
        [System.StringComparison]::Ordinal)
    $beforeFirstReplace = $atomicBody.Substring(0, $firstReplace)
    $stagingWrite = $beforeFirstReplace.IndexOf(
        '[System.IO.File]::WriteAllBytes($stagingPath',
        [System.StringComparison]::Ordinal)
    $lastPathGuard = $beforeFirstReplace.LastIndexOf(
        '$lastMomentPath = Assert-PathWithinRoot',
        [System.StringComparison]::Ordinal)
    $lastAclGuard = $beforeFirstReplace.LastIndexOf(
        '-Path $lastMomentPath -IsContainer $false',
        [System.StringComparison]::Ordinal)
    $lastHashGuard = $beforeFirstReplace.LastIndexOf(
        '$lastMomentHash = Get-PSOBBProvisioningSha256Bytes',
        [System.StringComparison]::Ordinal)
    $lastProcessGate = $beforeFirstReplace.LastIndexOf(
        'Assert-PSOBBProvisioningProcessesStopped',
        [System.StringComparison]::Ordinal)
    Add-Result 'process and listener gates cover the full local server surface' (
        $atomicStart -ge 0 -and $pairStart -gt $atomicStart -and
        $firstReplace -gt 0 -and
        $sourceText -match "ProcessName -like 'newserv\*'" -and
        $sourceText -match "ProcessName -ieq 'Psobb'" -and
        $sourceText -match 'Get-NetTCPConnection -State Listen' -and
        $sourceText -match '11000, 12000, 12001' -and
        $sourceText -match 'OwningProcess' -and
        $stagingWrite -ge 0 -and
        $lastPathGuard -gt $stagingWrite -and
        $lastAclGuard -gt $lastPathGuard -and
        $lastHashGuard -gt $lastAclGuard -and
        $lastProcessGate -gt $lastHashGuard -and
        $firstReplace -gt $lastProcessGate) `
        'target path, ACL, hash, processes, and listeners are ordered immediately before replacement'
    $applyStart = $sourceText.IndexOf(
        "if (`$Action -ceq 'Apply')",
        [System.StringComparison]::Ordinal)
    $rollbackStart = $sourceText.IndexOf(
        "if ([string]::IsNullOrWhiteSpace(`$TransactionPath))",
        [System.StringComparison]::Ordinal)
    $applyBody = $sourceText.Substring($applyStart, $rollbackStart - $applyStart)
    $emergencyCleanup = $applyBody.IndexOf(
        'Remove-PSOBBProvisioningPairEmergencyFiles -Pair $pair',
        [System.StringComparison]::Ordinal)
    $appliedJournal = $applyBody.IndexOf(
        "-FileName '001-applied.json'",
        [System.StringComparison]::Ordinal)
    Add-Result 'successful Apply cleanup precedes the exclusive Applied journal state' (
        $applyStart -ge 0 -and $rollbackStart -gt $applyStart -and
        $emergencyCleanup -ge 0 -and $appliedJournal -gt $emergencyCleanup) `
        'cleanup failure compensates to source before any Applied predecessor can exist'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) Twills-provisioning test(s) failed"
}
[pscustomobject]@{
    Suite = 'TwillsProvisioning'
    Passed = $results.Count
    Failed = 0
}
