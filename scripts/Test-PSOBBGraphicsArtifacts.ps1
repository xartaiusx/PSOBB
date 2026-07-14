[CmdletBinding()]
param(
    [switch]$ScanWithDefender,
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$lock = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'config\sources.lock.json') |
    ConvertFrom-Json -Depth 50
$graphicsArchiveRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Archives 'graphics-lab') `
    -Root $layout.Root
$localOverlayRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Root 'local-lab\overlays') `
    -Root $layout.Root
$results = [System.Collections.Generic.List[object]]::new()

function Add-GraphicsArtifactCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Detail
    )

    $results.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    })
}

function Test-TarPathSafety {
    param([Parameter(Mandatory)][string]$Path)

    $entries = @(& tar -tf $Path)
    if ($LASTEXITCODE -ne 0 -or $entries.Count -eq 0) {
        throw "Could not enumerate tar archive: $Path"
    }
    $verbose = @(& tar -tvf $Path)
    if ($LASTEXITCODE -ne 0 -or @($verbose | Where-Object {
        ([string]$_).StartsWith('l', [System.StringComparison]::Ordinal) -or
        ([string]$_).StartsWith('h', [System.StringComparison]::Ordinal)
    }).Count -gt 0) {
        throw "Tar archive contains a link or could not be inspected: $Path"
    }

    $names = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $name = ([string]$entry).Replace('\', '/').TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($name) -or
            [System.IO.Path]::IsPathRooted($name) -or
            $name.StartsWith('/', [System.StringComparison]::Ordinal) -or
            $name.Contains(':', [System.StringComparison]::Ordinal) -or
            $name -match '(^|/)\.\.(/|$)' -or
            -not $names.Add($name)) {
            throw "Tar archive contains an unsafe or colliding path: $entry"
        }
        foreach ($segment in @($name.Split('/'))) {
            if ([string]::IsNullOrWhiteSpace($segment) -or
                $segment.EndsWith(' ', [System.StringComparison]::Ordinal) -or
                $segment.EndsWith('.', [System.StringComparison]::Ordinal) -or
                $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$') {
                throw "Tar archive contains a Windows-unsafe path: $entry"
            }
        }
    }
    [pscustomobject]@{ Entries = $entries.Count }
}

function Test-LockedMember {
    param(
        [Parameter(Mandatory)][string]$ComponentId,
        [Parameter(Mandatory)][string]$MemberPath,
        [Parameter(Mandatory)][string]$ActualPath,
        [string]$ActualRoot = $layout.Root
    )

    $component = @($lock.components | Where-Object id -ceq $ComponentId)
    $member = if ($component.Count -eq 1) {
        @($component[0].members | Where-Object path -ceq $MemberPath)
    } else {
        @()
    }
    $passed = $false
    $detail = 'component/member or extracted file missing'
    if (($member.Count -eq 1) -and (Test-Path -LiteralPath $ActualPath -PathType Leaf)) {
        Assert-PathWithinRoot -Path $ActualPath -Root $ActualRoot | Out-Null
        $item = Get-Item -LiteralPath $ActualPath -Force
        $passed = ($item.Length -eq [long]$member[0].size) -and
            ((Get-LowerSha256 $item.FullName) -ceq [string]$member[0].sha256)
        $detail = "size=$($item.Length); sha256=$(Get-LowerSha256 $item.FullName)"
        if ([System.IO.Path]::GetFullPath($ActualRoot).TrimEnd('\').Equals(
            [System.IO.Path]::GetFullPath($layout.Root).TrimEnd('\'),
            [System.StringComparison]::OrdinalIgnoreCase)) {
            $defenderTargets.Add($item.FullName)
        }
    }
    Add-GraphicsArtifactCheck "member $ComponentId/$MemberPath" $passed $detail
}

function Test-LockedRuntimeArtifact {
    param(
        [Parameter(Mandatory)][string]$ComponentId,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][string]$ActualPath,
        [Parameter(Mandatory)][string]$ActualRoot
    )

    $component = @($lock.components | Where-Object id -ceq $ComponentId)
    $artifact = if (($component.Count -eq 1) -and
        ($component[0].PSObject.Properties.Name -contains 'runtimeArtifacts')) {
        @($component[0].runtimeArtifacts | Where-Object path -ceq $ArtifactPath)
    } else {
        @()
    }
    $passed = $false
    $detail = 'component/runtime artifact or build output missing'
    if (($artifact.Count -eq 1) -and (Test-Path -LiteralPath $ActualPath -PathType Leaf)) {
        Assert-PathWithinRoot -Path $ActualPath -Root $ActualRoot | Out-Null
        $item = Get-Item -LiteralPath $ActualPath -Force
        $hash = Get-LowerSha256 $item.FullName
        $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
        $passed = ($item.Length -eq [long]$artifact[0].size) -and
            ($hash -ceq [string]$artifact[0].sha256) -and
            ([string]$signature.Status -ceq [string]$artifact[0].authenticode)
        $detail = "size=$($item.Length); sha256=$hash; signature=$($signature.Status)"
    }
    Add-GraphicsArtifactCheck "runtime artifact $ComponentId/$ArtifactPath" $passed $detail
}

$artifacts = @(
    @{ Id = 'newserv-canary-source'; File = 'newserv-d754a34e-source.zip'; Kind = 'source-zip' },
    @{ Id = 'blue-burst-patch-project'; File = 'blue-burst-patch-project-dc123c5-source.zip'; Kind = 'zip' },
    @{ Id = 'ultimate-asi-loader-x86'; File = 'Ultimate-ASI-Loader-v9.7.2-x86.zip'; Kind = 'zip' },
    @{ Id = 'psobb-widescreen-local-evaluation'; File = 'pso-widescreen-1.0.2-asi-only.zip'; Kind = 'zip' },
    @{ Id = 'reshade-6.7.3-local-import'; File = 'ReShade_Setup_6.7.3.exe'; Kind = 'binary' },
    @{ Id = 'dxvk-x86-d3d8-d3d9'; File = 'dxvk-3.0.1.tar.gz'; Kind = 'tar' },
    @{ Id = 'd3d8to9-x86'; File = 'd3d8to9-v1.15.1-x86.dll'; Kind = 'binary' },
    @{ Id = 'presentmon-portable'; File = 'PresentMon-2.5.1-x64.exe'; Kind = 'binary' },
    @{ Id = 'renderdoc-diagnostic'; File = 'RenderDoc_1.45_64.zip'; Kind = 'zip' }
)
$defenderTargets = [System.Collections.Generic.List[string]]::new()
foreach ($artifact in $artifacts) {
    $component = @($lock.components | Where-Object id -ceq $artifact.Id)
    $path = Join-Path $graphicsArchiveRoot $artifact.File
    $passed = $false
    $detail = 'lock entry or file missing'
    if (($component.Count -eq 1) -and
        (Test-Path -LiteralPath $path -PathType Leaf)) {
        Assert-PathWithinRoot -Path $path -Root $layout.Root | Out-Null
        $item = Get-Item -LiteralPath $path -Force
        $passed = ($item.Length -eq [long]$component[0].size) -and
            ((Get-LowerSha256 $item.FullName) -ceq [string]$component[0].sha256)
        $detail = "size=$($item.Length); sha256=$(Get-LowerSha256 $item.FullName)"
        $defenderTargets.Add($item.FullName)
    }
    Add-GraphicsArtifactCheck "artifact $($artifact.Id)" $passed $detail

    if (-not $passed) {
        continue
    }
    try {
        if ($artifact.Kind -eq 'source-zip') {
            $archive = Assert-PSOBBZipArchiveSafe -Path $path -AllowReviewedSourceSymlinks
            $archiveDetail = "entries=$($archive.Entries); reviewedSourceSymlinks=$($archive.ReviewedSourceSymlinks)"
        } elseif ($artifact.Kind -eq 'zip') {
            $archive = Assert-PSOBBZipArchiveSafe -Path $path
            $archiveDetail = "entries=$($archive.Entries); reviewedSourceSymlinks=0"
        } elseif ($artifact.Kind -eq 'tar') {
            $archive = Test-TarPathSafety -Path $path
            $archiveDetail = "entries=$($archive.Entries); links=0"
        } else {
            continue
        }
        Add-GraphicsArtifactCheck "archive safety $($artifact.Id)" $true $archiveDetail
    } catch {
        Add-GraphicsArtifactCheck "archive safety $($artifact.Id)" $false $_.Exception.Message
    }
}

Test-LockedMember `
    -ComponentId 'ultimate-asi-loader-x86' `
    -MemberPath 'dinput8.dll' `
    -ActualPath (Join-Path $localOverlayRoot 'ultimate-asi-loader-9.7.2\dinput8.dll')
Test-LockedMember `
    -ComponentId 'psobb-widescreen-local-evaluation' `
    -MemberPath 'patches/pso_widescreen.asi' `
    -ActualPath (Join-Path $localOverlayRoot 'psobb-widescreen-1.0.2\patches\pso_widescreen.asi')
Test-LockedMember `
    -ComponentId 'reshade-6.7.3-local-import' `
    -MemberPath 'ReShade32.dll' `
    -ActualPath (Join-Path $localOverlayRoot 'reshade-6.7.3-standard\dxgi.dll')
Test-LockedMember `
    -ComponentId 'renderdoc-diagnostic' `
    -MemberPath 'qrenderdoc.exe' `
    -ActualPath (Join-Path $layout.Root 'tools\renderdoc-1.45\RenderDoc_1.45_64\qrenderdoc.exe')
Test-LockedMember `
    -ComponentId 'renderdoc-diagnostic' `
    -MemberPath 'x86/renderdoc.dll' `
    -ActualPath (Join-Path $layout.Root 'tools\renderdoc-1.45\RenderDoc_1.45_64\x86\renderdoc.dll')
Test-LockedRuntimeArtifact `
    -ComponentId 'project-owned-psobb-enhancement' `
    -ArtifactPath 'PSOBB.Enhancement.asi' `
    -ActualPath (Join-Path $repositoryRoot 'src\PSOBB.Enhancement\bin\build-x86\Release\PSOBB.Enhancement.asi') `
    -ActualRoot $repositoryRoot

$dxvkTemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-dxvk-member-check-' + [Guid]::NewGuid().ToString('N'))
try {
    [void][System.IO.Directory]::CreateDirectory($dxvkTemporaryRoot)
    $dxvkArchive = Join-Path $graphicsArchiveRoot 'dxvk-3.0.1.tar.gz'
    & tar -xf $dxvkArchive -C $dxvkTemporaryRoot `
        'dxvk-3.0.1/x32/d3d8.dll' `
        'dxvk-3.0.1/x32/d3d9.dll'
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not extract the two locked DXVK x32 members for verification'
    }
    Test-LockedMember `
        -ComponentId 'dxvk-x86-d3d8-d3d9' `
        -MemberPath 'x32/d3d8.dll' `
        -ActualPath (Join-Path $dxvkTemporaryRoot 'dxvk-3.0.1\x32\d3d8.dll') `
        -ActualRoot $dxvkTemporaryRoot
    Test-LockedMember `
        -ComponentId 'dxvk-x86-d3d8-d3d9' `
        -MemberPath 'x32/d3d9.dll' `
        -ActualPath (Join-Path $dxvkTemporaryRoot 'dxvk-3.0.1\x32\d3d9.dll') `
        -ActualRoot $dxvkTemporaryRoot
} finally {
    if (Test-Path -LiteralPath $dxvkTemporaryRoot) {
        Remove-Item -LiteralPath $dxvkTemporaryRoot -Recurse -Force
    }
}

$signatureTargets = @(
    @{
        Name = 'Ultimate ASI Loader x86'
        Path = Join-Path $localOverlayRoot 'ultimate-asi-loader-9.7.2\dinput8.dll'
        Status = 'UnknownError'
        Signer = 'CN=FusionFix'
    },
    @{
        Name = 'widescreen reference ASI'
        Path = Join-Path $localOverlayRoot 'psobb-widescreen-1.0.2\patches\pso_widescreen.asi'
        Status = 'NotSigned'
        Signer = ''
    },
    @{
        Name = 'ReShade x86'
        Path = Join-Path $localOverlayRoot 'reshade-6.7.3-standard\dxgi.dll'
        Status = 'UnknownError'
        Signer = 'CN=ReShade'
    },
    @{
        Name = 'd3d8to9 x86'
        Path = Join-Path $graphicsArchiveRoot 'd3d8to9-v1.15.1-x86.dll'
        Status = 'NotSigned'
        Signer = ''
    },
    @{
        Name = 'PresentMon portable'
        Path = Join-Path $graphicsArchiveRoot 'PresentMon-2.5.1-x64.exe'
        Status = 'Valid'
        Signer = 'CN=Intel Corporation'
    },
    @{
        Name = 'RenderDoc UI'
        Path = Join-Path $layout.Root 'tools\renderdoc-1.45\RenderDoc_1.45_64\qrenderdoc.exe'
        Status = 'Valid'
        Signer = 'CN=Baldur Scott Karlsson'
    }
)
foreach ($target in $signatureTargets) {
    $signaturePassed = $false
    $signatureDetail = 'file missing'
    if (Test-Path -LiteralPath $target.Path -PathType Leaf) {
        Assert-PathWithinRoot -Path $target.Path -Root $layout.Root | Out-Null
        $signature = Get-AuthenticodeSignature -LiteralPath $target.Path
        $subject = if ($signature.SignerCertificate) {
            [string]$signature.SignerCertificate.Subject
        } else {
            ''
        }
        $signaturePassed = ([string]$signature.Status -ceq [string]$target.Status) -and
            ([string]::IsNullOrEmpty([string]$target.Signer) -or
             $subject.StartsWith([string]$target.Signer, [System.StringComparison]::Ordinal))
        $signatureDetail = "status=$($signature.Status); signer=$subject"
        $defenderTargets.Add($target.Path)
    }
    Add-GraphicsArtifactCheck "signature $($target.Name)" $signaturePassed $signatureDetail
}

$defender = Get-MpComputerStatus
Add-GraphicsArtifactCheck 'Microsoft Defender enabled' (
    $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) (
    'antivirus and real-time protection')
if ($ScanWithDefender) {
    $scanStartedAt = [DateTime]::UtcNow.AddMinutes(-1)
    foreach ($target in @($defenderTargets | Sort-Object -Unique)) {
        Start-MpScan -ScanType CustomScan -ScanPath $target
    }
    $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
        $_.InitialDetectionTime.ToUniversalTime() -ge $scanStartedAt -and
        @($_.Resources | Where-Object {
            $resource = [string]$_
            @($defenderTargets | Where-Object {
                $resource.Contains($_, [System.StringComparison]::OrdinalIgnoreCase)
            }).Count -gt 0
        }).Count -gt 0
    })
    Add-GraphicsArtifactCheck 'Defender custom scans have no new detections' (
        $detections.Count -eq 0) "targets=$($defenderTargets.Count); detections=$($detections.Count)"
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) graphics-artifact check(s) failed"
}
[pscustomobject]@{
    Suite = 'GraphicsArtifacts'
    Passed = $results.Count
    Failed = 0
    DefenderScanned = $ScanWithDefender.IsPresent
}
