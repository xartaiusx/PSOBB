[CmdletBinding()]
param(
    [switch]$ScanWithDefender,
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $repositoryRoot 'config\sources.lock.json'
$lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json -Depth 20
$results = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
}

function Test-PathCoveredByDefenderExclusion {
    param(
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][string]$ExclusionPath
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($ExclusionPath).Trim()
    if ([string]::IsNullOrWhiteSpace($expanded)) {
        return $false
    }
    if ($expanded.IndexOfAny([char[]]'*?[') -ge 0) {
        return ($TargetPath -like $expanded) -or
            (($TargetPath + '\probe') -like ($expanded.TrimEnd('\') + '\*'))
    }

    $target = [System.IO.Path]::GetFullPath($TargetPath)
    $excluded = [System.IO.Path]::GetFullPath($expanded)
    $excludedRoot = [System.IO.Path]::GetPathRoot($excluded)
    if (-not $excluded.Equals($excludedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $excluded = $excluded.TrimEnd('\')
    }
    if ($target.Equals($excluded, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = if ($excluded.EndsWith('\', [System.StringComparison]::Ordinal)) {
        $excluded
    } else {
        $excluded + '\'
    }
    $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

$artifacts = @(
    @{ Id = 'newserv-stable-release'; Path = Join-Path $layout.Archives 'newserv-v2026-02-27-release.zip' },
    @{ Id = 'newserv-stable-source'; Path = Join-Path $layout.Archives 'newserv-v2026-02-27-source.zip' },
    @{ Id = 'tethealla-59nl-english'; Path = Join-Path $layout.Archives 'TethVer12513_English.zip' },
    @{ Id = 'dgvoodoo2-x86-d3d8'; Path = Join-Path $layout.Archives 'dgVoodoo2_87_3.zip' }
)

$defenderTargets = [System.Collections.Generic.List[string]]::new()
foreach ($artifact in $artifacts) {
    $component = @($lock.components | Where-Object id -eq $artifact.Id)
    if ($component.Count -ne 1) {
        Add-Check "lock entry $($artifact.Id)" $false 'expected exactly one component'
        continue
    }
    if (-not (Test-Path -LiteralPath $artifact.Path -PathType Leaf)) {
        Add-Check "artifact $($artifact.Id)" $false 'file missing'
        continue
    }
    $file = Get-Item -LiteralPath $artifact.Path
    $hashMatches = (Get-LowerSha256 $file.FullName) -eq [string]$component[0].sha256
    $sizeMatches = $file.Length -eq [long]$component[0].size
    Add-Check "artifact $($artifact.Id)" ($hashMatches -and $sizeMatches) "size=$($file.Length); SHA-256 locked"
    try {
        if ($artifact.Id -eq 'newserv-stable-source') {
            $archiveInfo = Assert-PSOBBZipArchiveSafe -Path $file.FullName -AllowReviewedSourceSymlinks
            $detail = "entries=$($archiveInfo.Entries); expanded=$($archiveInfo.ExpandedBytes); reviewedSourceSymlinks=$($archiveInfo.ReviewedSourceSymlinks); extractionForbidden=true"
        } else {
            $archiveInfo = Assert-PSOBBZipArchiveSafe -Path $file.FullName
            $detail = "entries=$($archiveInfo.Entries); expanded=$($archiveInfo.ExpandedBytes); reviewedSourceSymlinks=0"
        }
        Add-Check "archive safety $($artifact.Id)" $true $detail
    } catch {
        Add-Check "archive safety $($artifact.Id)" $false $_.Exception.Message
    }
    $defenderTargets.Add($file.FullName)
}

$extractedMembers = @(
    @{ Component = 'newserv-stable-release'; Member = 'release/newserv-windows.exe'; Path = Join-Path $layout.Server 'newserv-windows.exe' },
    @{ Component = 'tethealla-59nl-english'; Member = 'Psobb.exe'; Path = Join-Path $layout.BaseClient 'Psobb.exe' },
    @{ Component = 'dgvoodoo2-x86-d3d8'; Member = 'MS/x86/D3D8.dll'; Path = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\MS\x86\D3D8.dll' },
    @{ Component = 'dgvoodoo2-x86-d3d8'; Member = 'dgVoodoo.conf'; Path = Join-Path $layout.Stable 'overlays\dgvoodoo-2.87.3\dgVoodoo.conf' }
)
foreach ($target in $extractedMembers) {
    $component = @($lock.components | Where-Object id -eq $target.Component)
    $member = @($component.members | Where-Object path -eq $target.Member)
    $passed = $false
    $detail = 'lock member or extracted file missing'
    if (($component.Count -eq 1) -and ($member.Count -eq 1) -and
        (Test-Path -LiteralPath $target.Path -PathType Leaf)) {
        $file = Get-Item -LiteralPath $target.Path
        $passed = ($file.Length -eq [long]$member[0].size) -and
            ((Get-LowerSha256 $file.FullName) -eq [string]$member[0].sha256)
        $detail = "size=$($file.Length); member SHA-256 locked"
        $defenderTargets.Add($file.FullName)
    }
    Add-Check "extracted member $($target.Component)" $passed $detail
}

$baseManifestValid = $false
if ((Test-Path -LiteralPath $layout.BaseClientManifest -PathType Leaf) -and
    (Test-Path -LiteralPath $layout.BaseClient -PathType Container)) {
    $baseManifest = Get-Content -Raw -LiteralPath $layout.BaseClientManifest | ConvertFrom-Json -Depth 10
    $clientLock = @($lock.components | Where-Object id -eq 'tethealla-59nl-english')
    $baseManifestValid = ($baseManifest.schemaVersion -eq 1) -and
        ($clientLock.Count -eq 1) -and
        ([string]$baseManifest.sourceArchiveSha256 -eq [string]$clientLock[0].sha256) -and
        (Test-PSOBBDirectoryManifest -Root $layout.BaseClient -Files $baseManifest.files)
}
Add-Check 'immutable client complete inventory' $baseManifestValid $layout.BaseClientManifest

$defender = Get-MpComputerStatus
Add-Check 'Microsoft Defender enabled' ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) 'antivirus and real-time protection'
$exclusions = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue)
$runtimeExcluded = $false
foreach ($exclusion in $exclusions) {
    if ([string]::IsNullOrWhiteSpace($exclusion)) {
        continue
    }
    try {
        if (Test-PathCoveredByDefenderExclusion `
            -TargetPath $layout.Root `
            -ExclusionPath ([string]$exclusion)) {
            $runtimeExcluded = $true
        }
    } catch {
        $runtimeExcluded = $true
    }
}
Add-Check 'runtime has no parent/wildcard Defender exclusion' (-not $runtimeExcluded) $layout.Root
$volumeRoot = [System.IO.Path]::GetPathRoot($layout.Root)
Add-Check 'volume-root Defender exclusion is recognized' (
    Test-PathCoveredByDefenderExclusion -TargetPath $layout.Root -ExclusionPath $volumeRoot) $volumeRoot

if ($ScanWithDefender) {
    $scanStartedAt = [DateTime]::UtcNow.AddMinutes(-1)
    foreach ($target in @($defenderTargets | Sort-Object -Unique)) {
        Start-MpScan -ScanType CustomScan -ScanPath $target
    }
    $newDetections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
        $_.InitialDetectionTime.ToUniversalTime() -ge $scanStartedAt -and
        @($_.Resources | Where-Object {
            $resource = [string]$_
            @($defenderTargets | Where-Object { $resource.Contains($_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        }).Count -gt 0
    })
    Add-Check 'Defender custom scans completed without detections' ($newDetections.Count -eq 0) "targets=$($defenderTargets.Count); newDetections=$($newDetections.Count)"
}

$signatureStates = foreach ($target in $extractedMembers) {
    if (-not (Test-Path -LiteralPath $target.Path -PathType Leaf)) {
        'Missing'
    } elseif ([System.IO.Path]::GetExtension($target.Path) -notin @('.exe', '.dll')) {
        'NotApplicable'
    } else {
        (Get-AuthenticodeSignature -LiteralPath $target.Path).Status.ToString()
    }
}
Add-Check 'signature state recorded for loadable binaries' (@($signatureStates | Where-Object {
    $_ -notin @('NotSigned', 'NotApplicable')
}).Count -eq 0) ($signatureStates -join ', ')

$candidateFiles = @(& git -C $repositoryRoot ls-files --cached --others --exclude-standard)
$gitSucceeded = $LASTEXITCODE -eq 0
Add-Check 'Git candidate enumeration succeeded' $gitSucceeded "exit=$LASTEXITCODE"
$proprietaryCandidates = @($candidateFiles | Where-Object {
    $_ -match '(?i)^(runtime|archives|client|server|licenses|players|teams|secrets)/' -or
    $_ -match '(?i)\.(exe|dll|zip|7z|rar|dat|prs|gsl|psochar|psosys|psocard|clixml)$' -or
    $_ -match '(?i)\.account\.json$'
})
Add-Check 'Git candidate set has no runtime assets' ($gitSucceeded -and $proprietaryCandidates.Count -eq 0) "candidates=$($candidateFiles.Count); prohibited=$($proprietaryCandidates.Count)"

$knownSecrets = foreach ($role in @('admin', 'player')) {
    $credentialPath = Join-Path $layout.Secrets ($role + '.credential.clixml')
    if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
        (Import-Clixml -LiteralPath $credentialPath).GetNetworkCredential().Password
    }
}
$secretMatches = 0
foreach ($relativePath in $candidateFiles) {
    $path = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    try {
        $text = [System.IO.File]::ReadAllText($path)
    } catch {
        continue
    }
    if ($text -match '-----BEGIN (EC |RSA |ENCRYPTED )?PRIVATE KEY-----') {
        $secretMatches++
    }
    foreach ($secret in $knownSecrets) {
        if (-not [string]::IsNullOrEmpty($secret) -and $text.Contains($secret, [System.StringComparison]::Ordinal)) {
            $secretMatches++
        }
    }
}
$knownSecrets = $null
Add-Check 'Git candidate set has no known secrets' ($secretMatches -eq 0) "matches=$secretMatches"

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) supply-chain check(s) failed"
}
[pscustomobject]@{ Suite = 'SupplyChain'; Passed = $results.Count; Failed = 0; DefenderScanned = $ScanWithDefender.IsPresent }
