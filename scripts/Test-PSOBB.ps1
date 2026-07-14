[CmdletBinding()]
param(
    [ValidateSet('Baseline', 'Recovery', 'PublicReadiness')][string]$Suite = 'Baseline',
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$lock = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'config\sources.lock.json') | ConvertFrom-Json -Depth 20
$trust = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'config\release-trust.json') | ConvertFrom-Json -Depth 10
$clientPatchPolicyPath = Join-Path $repositoryRoot 'config\client-patch-profiles.json'
$clientPatchPolicy = Get-PSOBBClientPatchPolicy -Path $clientPatchPolicyPath
$clientPatchPolicySha256 = Get-LowerSha256 $clientPatchPolicyPath
$serverLock = @($lock.components | Where-Object id -eq 'newserv-stable-release')
$clientLock = @($lock.components | Where-Object id -eq 'tethealla-59nl-english')
$serverMember = @($serverLock.members | Where-Object path -eq 'release/newserv-windows.exe')
$clientMember = @($clientLock.members | Where-Object path -eq 'Psobb.exe')
$results = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}
function Test-ExactFile([string]$Path, $Member) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or $null -eq $Member) {
        return $false
    }
    $file = Get-Item -LiteralPath $Path
    ($file.Length -eq [long]$Member.size) -and ((Get-LowerSha256 $file.FullName) -eq [string]$Member.sha256)
}
function Get-ActiveConfigScalar([string]$Text, [string]$Key) {
    $pattern = '(?m)^\s*"' + [regex]::Escape($Key) + '"\s*:\s*(?<value>[^,\r\n]+),\s*(?://.*)?$'
    $matches = [regex]::Matches($Text, $pattern)
    if ($matches.Count -ne 1) {
        return $null
    }
    $matches[0].Groups['value'].Value.Trim()
}
function Test-ProtectedAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $allowed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$allowed.Add([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    [void]$allowed.Add('S-1-5-32-544')
    [void]$allowed.Add('S-1-5-18')
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        return $false
    }
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if (($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) -or
            -not $allowed.Contains($rule.IdentityReference.Value)) {
            return $false
        }
        [void]$found.Add($rule.IdentityReference.Value)
    }
    $found.SetEquals($allowed)
}

$serverExe = Join-Path $layout.Server 'newserv-windows.exe'
$baseClientExe = Join-Path $layout.BaseClient 'Psobb.exe'
$clientExe = Join-Path $layout.Client 'Psobb.exe'
$configPath = Join-Path $layout.Server 'system\config.json'
$patchData = Join-Path $layout.Server 'system\patch-bb\data'

$markerValid = $false
try {
    $marker = Assert-PSOBBRuntimeMarker -Layout $layout
    $markerValid = $true
} catch {
    $marker = $null
}
Add-Check 'runtime ownership marker' $markerValid $layout.RuntimeMarker
Add-Check 'approved server executable' (($serverMember.Count -eq 1) -and (Test-ExactFile $serverExe $serverMember[0])) $serverExe
Add-Check 'approved immutable client executable' (($clientMember.Count -eq 1) -and (Test-ExactFile $baseClientExe $clientMember[0])) $baseClientExe
Add-Check 'approved disposable client executable' (($clientMember.Count -eq 1) -and (Test-ExactFile $clientExe $clientMember[0])) $clientExe

$installValid = $false
$install = $null
if ((Test-Path -LiteralPath $layout.InstallRecord -PathType Leaf) -and $markerValid) {
    try {
        $install = Get-Content -Raw -LiteralPath $layout.InstallRecord | ConvertFrom-Json
        $installValid = ($install.schemaVersion -eq 2) -and
            ([string]$install.installationId -eq [string]$marker.installationId) -and
            ([string]$install.serverArchiveSha256 -eq [string]$serverLock[0].sha256) -and
            ([string]$install.serverExecutableSha256 -eq [string]$serverMember[0].sha256) -and
            ([string]$install.clientArchiveSha256 -eq [string]$clientLock[0].sha256) -and
            ([string]$install.baseClientExecutableSha256 -eq [string]$clientMember[0].sha256) -and
            ([string]$install.clientExecutableSha256 -eq [string]$clientMember[0].sha256) -and
            ([string]$install.networkScope -eq 'loopback-only')
    } catch {
        $installValid = $false
    }
}
Add-Check 'installation record provenance' $installValid $layout.InstallRecord

$patchManifestPath = Join-Path $layout.Stable 'patch-bb-data.manifest.json'
$patchParityValid = $false
if ((Test-Path -LiteralPath $patchData -PathType Container) -and
    (Test-Path -LiteralPath $patchManifestPath -PathType Leaf)) {
    try {
        $patchManifest = Get-Content -Raw -LiteralPath $patchManifestPath | ConvertFrom-Json -Depth 10
        $patchParityValid = ($patchManifest.schemaVersion -eq 1) -and
            ([string]$patchManifest.sourceClientArchiveSha256 -eq [string]$clientLock[0].sha256) -and
            (Test-PSOBBDirectoryManifest -Root $patchData -Files $patchManifest.files)
    } catch {
        $patchParityValid = $false
    }
}
Add-Check 'exact BB patch-data inventory' $patchParityValid $patchManifestPath
$unitxtJ = Join-Path $patchData 'unitxt_j.prs'
$unitxtE = Join-Path $patchData 'unitxt_e.prs'
$englishTextParity = (Test-Path -LiteralPath $unitxtJ -PathType Leaf) -and
    (Test-Path -LiteralPath $unitxtE -PathType Leaf) -and
    ((Get-LowerSha256 $unitxtJ) -eq (Get-LowerSha256 $unitxtE))
Add-Check 'English text parity copy' $englishTextParity 'unitxt_j.prs == unitxt_e.prs'

$configText = if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    Get-Content -Raw -LiteralPath $configPath
} else { '' }
Add-Check 'configuration present' (-not [string]::IsNullOrEmpty($configText)) $configPath
$installedPatchProfile = 'baseline'
$patchProfileProvenance = $true
$patchProfileProvenanceDetail = 'legacy installation record; baseline rollback profile expected'
if ($install -and ($install.PSObject.Properties['clientPatchProfile'] -or
        $install.PSObject.Properties['clientPatchPolicySha256'])) {
    $installedPatchProfile = [string]$install.clientPatchProfile
    $patchProfileProvenance =
        ($installedPatchProfile -match '^[a-z0-9]+(?:-[a-z0-9]+)*$') -and
        ([string]$install.clientPatchPolicySha256 -ceq $clientPatchPolicySha256)
    $patchProfileProvenanceDetail =
        "profile=$installedPatchProfile; policy=$([string]$install.clientPatchPolicySha256)"
}
$selectedPatchProfiles = @($clientPatchPolicy.profiles | Where-Object id -CEQ $installedPatchProfile)
$patchProfileProvenance = $patchProfileProvenance -and
    ($selectedPatchProfiles.Count -eq 1) -and
    ([string]$selectedPatchProfiles[0].channel -ceq 'stable')
Add-Check 'client-patch profile provenance' $patchProfileProvenance $patchProfileProvenanceDetail
$autoPatchesValid = $false
$requiredPatchesValid = $false
$patchSourcesAvailable = $false
try {
    if ($selectedPatchProfiles.Count -ne 1) {
        throw 'selected client-patch profile is not declared'
    }
    $observedAutoPatches = @(Get-ActiveConfigStringArray -Text $configText -Key 'AutoPatches')
    $observedRequiredPatches = @(Get-ActiveConfigStringArray -Text $configText -Key 'BBRequiredPatches')
    $autoPatchesValid = Test-ExactStringSequence `
        -Expected @($selectedPatchProfiles[0].autoPatches) `
        -Actual $observedAutoPatches
    $requiredPatchesValid = Test-ExactStringSequence `
        -Expected @($selectedPatchProfiles[0].bbRequiredPatches) `
        -Actual $observedRequiredPatches
    Assert-NewservClientPatchProfileAvailable `
        -ServerRoot $layout.Server `
        -Profile $installedPatchProfile `
        -PolicyPath $clientPatchPolicyPath | Out-Null
    $patchSourcesAvailable = $true
} catch {
    $observedAutoPatches = @()
    $observedRequiredPatches = @()
}
Add-Check 'exact stable AutoPatches profile' $autoPatchesValid (
    "profile=$installedPatchProfile; active=$($observedAutoPatches -join ',')")
Add-Check 'no protocol-required BBRequiredPatches' $requiredPatchesValid (
    "profile=$installedPatchProfile; active=$($observedRequiredPatches -join ',')")
Add-Check 'exact 59NL patch sources available' $patchSourcesAvailable $installedPatchProfile
$scalarExpectations = [ordered]@{
    ServerName = '"PSOBB Local"'
    LocalAddress = '"127.0.0.1"'
    ExternalAddress = '"127.0.0.1"'
    DNSServerPort = '0'
    IPStackListen = '[]'
    PPPStackListen = '[]'
    PPPRawListen = '[]'
    HTTPListen = '[]'
    RunInteractiveShell = 'true'
    AllowUnregisteredUsers = 'false'
    CheatModeBehavior = '"Off"'
    DefaultDropModeV4Normal = '"SERVER_PRIVATE"'
    BBEXPShareMultiplier = '0'
    EnableSwitchAssistByDefault = 'true'
    RareNotificationsEnabledByDefaultV3V4 = 'true'
    CommandData = '"DISABLED"'
}
foreach ($entry in $scalarExpectations.GetEnumerator()) {
    $actual = Get-ActiveConfigScalar -Text $configText -Key $entry.Key
    Add-Check "config $($entry.Key)" ($actual -ceq $entry.Value) "$($entry.Key)=$actual"
}
$portBlock = [regex]::Match(
    $configText,
    '(?ms)^\s*"PortConfiguration"\s*:\s*\{(?<body>.*?)^\s*\},\s*\r?\n\s*// Where to listen for IP')
$observedConfigPorts = @{}
if ($portBlock.Success) {
    foreach ($match in [regex]::Matches(
        $portBlock.Groups['body'].Value,
        '(?m)^\s*"(?<name>[^"]+)"\s*:\s*\[\["(?<address>[^"]+)",\s*(?<port>\d+)\]')) {
        $observedConfigPorts[$match.Groups['name'].Value] =
            "$($match.Groups['address'].Value):$($match.Groups['port'].Value)"
    }
}
$expectedConfigPorts = [ordered]@{
    'bb-patch' = '127.0.0.1:11000'
    'bb-data1' = '127.0.0.1:12000'
    'bb-data2' = '127.0.0.1:12001'
}
$portConfigValid = ($observedConfigPorts.Count -eq $expectedConfigPorts.Count)
foreach ($entry in $expectedConfigPorts.GetEnumerator()) {
    if (-not $observedConfigPorts.ContainsKey($entry.Key) -or $observedConfigPorts[$entry.Key] -ne $entry.Value) {
        $portConfigValid = $false
    }
}
Add-Check 'exact loopback-only BB port configuration' $portConfigValid (($observedConfigPorts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')

$process = Get-NewservProcess -Layout $layout
Add-Check 'managed exact-path newserv process running' ($null -ne $process) $(if ($process) { "PID $($process.Id)" } else { 'not running' })
if ($process) {
    $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $process.Id -ErrorAction SilentlyContinue)
    $unexpected = @($listeners | Where-Object { $_.LocalAddress -ne '127.0.0.1' })
    $observedPorts = @($listeners.LocalPort | Sort-Object -Unique)
    $portDiff = @(Compare-Object -ReferenceObject @(11000, 12000, 12001) -DifferenceObject $observedPorts)
    Add-Check 'newserv loopback listeners only' ($unexpected.Count -eq 0) (($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ', ')
    Add-Check 'exact live BB listeners' ($portDiff.Count -eq 0) (($observedPorts | ForEach-Object { $_.ToString() }) -join '/')
} else {
    Add-Check 'newserv loopback listeners only' $false 'managed process unavailable'
    Add-Check 'exact live BB listeners' $false 'managed process unavailable'
}

$accountChecksPassed = $true
foreach ($role in @('admin', 'player')) {
    $metadataPath = Join-Path $layout.Secrets ($role + '.account.json')
    $credentialPath = Join-Path $layout.Secrets ($role + '.credential.clixml')
    try {
        if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
            throw 'account metadata or credential missing'
        }
        $metadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
        $credential = Import-Clixml -LiteralPath $credentialPath
        if ($credential.UserName -cne [string]$metadata.username) {
            throw 'credential username mismatch'
        }
        $accountNumber = [Convert]::ToUInt32([string]$metadata.accountId, 16)
        $licensePath = Join-Path $layout.Server ('system\licenses\' + $accountNumber.ToString('D10') + '.json')
        $licenseText = Get-Content -Raw -LiteralPath $licensePath
        $savedId = [regex]::Match($licenseText, '(?m)^\s*"AccountID"\s*:\s*0x([0-9A-Fa-f]+),').Groups[1].Value
        $flags = [regex]::Match($licenseText, '(?m)^\s*"Flags"\s*:\s*([^,]+),').Groups[1].Value.Trim()
        $licenseMatches = [regex]::Matches(
            $licenseText,
            '\{"UserName"\s*:\s*"(?<username>[^"]+)",\s*"Password"\s*:\s*"(?<password>[^"]+)"\}')
        $matching = @($licenseMatches | Where-Object { $_.Groups['username'].Value -ceq [string]$metadata.username })
        $expectedFlags = if ($role -eq 'admin') { '0x7FFFFFFF' } else { '0x0' }
        if (($savedId.ToUpperInvariant() -ne ([string]$metadata.accountId).ToUpperInvariant()) -or
            ($flags -ne $expectedFlags) -or ($matching.Count -ne 1) -or
            -not (Test-PSOBBGamePasswordLength -Password $matching[0].Groups['password'].Value) -or
            -not (Test-ProtectedAcl $credentialPath) -or
            -not (Test-ProtectedAcl $metadataPath) -or
            -not (Test-ProtectedAcl $licensePath)) {
            throw 'account ID, role, license, password length, or ACL mismatch'
        }
    } catch {
        $accountChecksPassed = $false
    } finally {
        $credential = $null
    }
}
Add-Check 'admin and player account role/ACL contract' $accountChecksPassed 'admin=root; player=none; protected 1-16-character BB licenses'

$manifestPath = Join-Path $layout.Stable 'release-manifest.json'
$signaturePath = $manifestPath + '.sig'
$publicKeyPath = Join-Path $layout.Stable 'release-public-key.pem'
$manifestContractValid = $false
$signatureVerified = $false
$artifactGraphValid = $false
try {
    $release = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -Depth 20
    $activeKeys = @($trust.keys | Where-Object id -eq $trust.activeKeyId)
    if (($trust.schemaVersion -ne 1) -or ($activeKeys.Count -ne 1)) {
        throw 'invalid repository trust configuration'
    }
    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportFromPem([System.IO.File]::ReadAllText($publicKeyPath))
        $spki = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($verifier.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
        if ($spki -ne [string]$activeKeys[0].spkiSha256) {
            throw 'release key does not match repository trust anchor'
        }
        $signatureVerified = $verifier.VerifyData(
            [System.IO.File]::ReadAllBytes($manifestPath),
            [Convert]::FromBase64String([System.IO.File]::ReadAllText($signaturePath).Trim()),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    } finally {
        $verifier.Dispose()
    }
    $manifestContractValid = ($release.schemaVersion -eq 1) -and
        ([string]$release.channel -in @('stable', 'canary')) -and
        ([int]$release.protocolRevision -gt 0) -and
        (@($release.artifacts).Count -ge 1) -and
        (@($release.artifacts).Count -le 256)
    $artifactGraphValid = $manifestContractValid
    $destinations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($artifact in @($release.artifacts)) {
        $sourceUrl = if ($artifact.PSObject.Properties['sourceUrl']) { [string]$artifact.sourceUrl } else { '' }
        $requiredBase = if ($artifact.PSObject.Properties['requiredBase']) { $artifact.requiredBase } else { $null }
        $destination = Assert-PathWithinRoot -Path (Join-Path $layout.Stable ([string]$artifact.destination).Replace('/', '\')) -Root $layout.Stable
        if (-not $destinations.Add([string]$artifact.destination) -or
            ([string]$artifact.channel -ne [string]$release.channel) -or
            ([int]$artifact.protocolRevision -ne [int]$release.protocolRevision) -or
            ([string]$artifact.sha256 -notmatch '^[0-9a-f]{64}$') -or
            ([long]$artifact.byteSize -le 0) -or
            [string]::IsNullOrWhiteSpace([string]$artifact.license) -or
            [string]::IsNullOrWhiteSpace([string]$artifact.redistribution) -or
            [string]::IsNullOrWhiteSpace([string]$artifact.rollback.target) -or
            -not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            $artifactGraphValid = $false
            continue
        }
        $file = Get-Item -LiteralPath $destination
        if (($file.Length -ne [long]$artifact.byteSize) -or
            ((Get-LowerSha256 $file.FullName) -ne [string]$artifact.sha256)) {
            $artifactGraphValid = $false
        }
        if ([string]$artifact.sourceKind -eq 'remote') {
            $sourceUri = $null
            if (-not [Uri]::TryCreate($sourceUrl, [UriKind]::Absolute, [ref]$sourceUri) -or
                $sourceUri.Scheme -ne 'https' -or -not [string]::IsNullOrEmpty($sourceUri.UserInfo)) {
                $artifactGraphValid = $false
            }
        } elseif ([string]$artifact.sourceKind -ne 'localImport' -or -not [string]::IsNullOrWhiteSpace($sourceUrl)) {
            $artifactGraphValid = $false
        }
        if ($requiredBase) {
            $basePath = Assert-PathWithinRoot -Path (Join-Path $layout.Stable ([string]$requiredBase.path).Replace('/', '\')) -Root $layout.Stable
            if (-not (Test-Path -LiteralPath $basePath -PathType Leaf)) {
                $artifactGraphValid = $false
            } else {
                $baseFile = Get-Item -LiteralPath $basePath
                if (($baseFile.Length -ne [long]$requiredBase.byteSize) -or
                    ((Get-LowerSha256 $baseFile.FullName) -ne [string]$requiredBase.sha256)) {
                    $artifactGraphValid = $false
                }
            }
        }
    }
    if ([string]$release.launch.serverExecutable -notin @($release.artifacts.destination) -or
        [string]$release.launch.clientExecutable -notin @($release.artifacts.destination) -or
        (@(Compare-Object @(11000, 12000, 12001) @($release.launch.healthPorts))).Count -ne 0) {
        $artifactGraphValid = $false
    }
} catch {
    $manifestContractValid = $false
    $signatureVerified = $false
    $artifactGraphValid = $false
}
Add-Check 'release manifest pinned signature' $signatureVerified 'compiled/repository-pinned ECDSA P-256 SHA-256 trust anchor'
Add-Check 'release manifest schema contract' $manifestContractValid $manifestPath
Add-Check 'release artifact graph exact hashes/sizes' $artifactGraphValid 'destinations, base import, protocol, rollback, and launch graph'

if ($Suite -in @('Recovery', 'PublicReadiness')) {
    $latestBackup = Get-ChildItem -LiteralPath $layout.Backups -Directory -Filter 'state-*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    $backupValid = $false
    if ($latestBackup) {
        try {
            $backupManifestPath = Join-Path $latestBackup.FullName 'manifest.json'
            $backupManifest = Get-Content -Raw -LiteralPath $backupManifestPath | ConvertFrom-Json -Depth 10
            $backupValid = ($backupManifest.schemaVersion -eq 3) -and
                (@($backupManifest.stateRoots).Count -eq 5) -and
                (@($backupManifest.stateRoots | Where-Object path -CEQ 'stable/installation.json').Count -eq 1) -and
                (@($backupManifest.files | Where-Object path -CEQ 'system/config.json').Count -eq 1) -and
                (@($backupManifest.files | Where-Object path -CEQ 'stable/installation.json').Count -eq 1) -and
                ([string]$backupManifest.clientPatchState.configSha256 -match '^[0-9a-f]{64}$') -and
                ([string]$backupManifest.clientPatchState.installationSha256 -match '^[0-9a-f]{64}$') -and
                ((Get-Item -LiteralPath $backupManifestPath).Length -gt 0)
        } catch {
            $backupValid = $false
        }
    }
    Add-Check 'latest state backup schema-v3 patch state exists' $backupValid $(if ($latestBackup) { $latestBackup.FullName } else { 'none' })

    $latestDrill = Get-ChildItem -LiteralPath $layout.Backups -Directory -Filter 'restore-drill-*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    $drillPassed = $false
    if ($latestDrill) {
        try {
            $drillResult = Get-Content -Raw -LiteralPath (Join-Path $latestDrill.FullName 'drill-result.json') | ConvertFrom-Json
            $completed = [DateTimeOffset]::Parse([string]$drillResult.completedAtUtc)
            $drillBackup = Join-Path $layout.Backups ([string]$drillResult.backup)
            $drillManifestPath = Join-Path $drillBackup 'manifest.json'
            $drillManifest = Get-Content -Raw -LiteralPath $drillManifestPath | ConvertFrom-Json
            $drillPassed = ($drillResult.schemaVersion -eq 3) -and
                ($drillManifest.schemaVersion -eq 3) -and
                ($drillResult.passed -eq $true) -and
                ($completed -gt [DateTimeOffset]::UtcNow.AddDays(-7)) -and
                (Test-Path -LiteralPath $drillManifestPath -PathType Leaf) -and
                ([string]$drillResult.backupManifestSha256 -eq (Get-LowerSha256 $drillManifestPath)) -and
                ([string]$drillResult.serverExecutableSha256 -eq [string]$serverMember[0].sha256) -and
                ([string]$drillResult.clientPatchProfile -ceq [string]$drillManifest.clientPatchState.profile) -and
                ([string]$drillResult.clientPatchPolicySha256 -ceq [string]$drillManifest.clientPatchState.policySha256) -and
                ([string]$drillResult.clientPatchConfigSha256 -ceq [string]$drillManifest.clientPatchState.configSha256) -and
                ([string]$drillResult.installationRecordSha256 -ceq [string]$drillManifest.clientPatchState.installationSha256)
        } catch {
            $drillPassed = $false
        }
    }
    Add-Check 'fresh latest restore drill is bound to backup/server' $drillPassed $(if ($latestDrill) { $latestDrill.FullName } else { 'none' })
}
if ($Suite -eq 'PublicReadiness') {
    Add-Check 'public deployment intentionally gated' $false 'Dedicated provider/host/domain/firewall/TLS/off-host backup/alerts/code-signing approvals remain required'
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) $Suite check(s) failed"
}
[pscustomobject]@{ Suite = $Suite; Passed = $results.Count; Failed = 0 }
