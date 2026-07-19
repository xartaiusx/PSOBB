[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]+(?:-[a-z0-9]+)*$')]
    [string]$ProfileId,

    [ValidateRange(15, 180)]
    [int]$WindowWaitSeconds = 90,

    [string]$RuntimeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')

function Assert-PSOBBPrivateRenderDocPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RuntimeEvidenceRoot,
        [Parameter(Mandatory)][string]$Purpose
    )

    $fullPath = Assert-PathWithinRoot -Path $Path -Root $RuntimeEvidenceRoot
    Assert-PSOBBPathOutsideTrackedSource -Path $fullPath -Purpose $Purpose
}

function Get-PSOBBValidatedRenderDocProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)][string]$SelectedProfileId
    )

    $catalogPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
    $catalog = Get-Content -Raw -LiteralPath $catalogPath | ConvertFrom-Json -Depth 50
    $declaredProfiles = @($catalog.profiles | Where-Object {
        [string]$_.id -ceq $SelectedProfileId -and
        [string]$_.channel -ceq 'local-lab'
    })
    if ([int]$catalog.schemaVersion -ne 1 -or $declaredProfiles.Count -ne 1) {
        throw "Profile '$SelectedProfileId' is not declared exactly once for channel 'local-lab'"
    }

    $materialized = Assert-PSOBBLocalLabClientRuntimeContract -Layout $Layout
    if ([string]$materialized.profileId -cne $SelectedProfileId -or
        [string]$materialized.channel -cne 'local-lab') {
        throw "The materialized LocalLab profile is not '$SelectedProfileId'"
    }

    $declared = $declaredProfiles[0]
    $clientExecutable = Get-PSOBBClientExecutablePath -Layout $Layout -Channel LocalLab
    $identity = Assert-PSOBBApprovedClientExecutable -Path $clientExecutable
    if ([string]$catalog.baseClient.executableSha256 -cne [string]$identity.Sha256 -or
        [string]$materialized.baseExecutableSha256 -cne [string]$identity.Sha256) {
        throw 'The catalog or materialized LocalLab profile does not match the approved client hash'
    }

    $renderCandidate = @($declared.display.internalRenderCandidates | Where-Object {
        [int]$_.width -eq [int]$materialized.renderWidth -and
        [int]$_.height -eq [int]$materialized.renderHeight
    })
    if ($renderCandidate.Count -ne 1 -or
        [int]$declared.display.output.width -ne [int]$materialized.desktopWidth -or
        [int]$declared.display.output.height -ne [int]$materialized.desktopHeight -or
        [string]$declared.display.aspectPolicy -cne [string]$materialized.aspectPolicy) {
        throw 'The materialized LocalLab render/output expectations do not match the profile catalog'
    }

    $profilePath = Assert-PathWithinRoot `
        -Path (Join-Path (Split-Path -Parent $clientExecutable) 'client-profile.json') `
        -Root $Layout.Root
    [pscustomobject]@{
        ProfileId = $SelectedProfileId
        Declared = $declared
        Materialized = $materialized
        ProfilePath = $profilePath
        ProfileSha256 = Get-LowerSha256 -Path $profilePath
        ClientExecutable = $clientExecutable
        ClientExecutableSha256 = [string]$identity.Sha256
        ClientExecutableSize = [long]$identity.Size
        ClientRoot = Split-Path -Parent $clientExecutable
        RequestedInternalWidth = [int]$materialized.renderWidth
        RequestedInternalHeight = [int]$materialized.renderHeight
        RequestedOutputWidth = [int]$materialized.desktopWidth
        RequestedOutputHeight = [int]$materialized.desktopHeight
        AspectPolicy = [string]$materialized.aspectPolicy
    }
}

function Get-PSOBBLockedRenderDoc {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $sources = Get-Content -Raw `
        -LiteralPath (Join-Path $repositoryRoot 'config\sources.lock.json') |
        ConvertFrom-Json -Depth 50
    $components = @($sources.components | Where-Object {
        [string]$_.id -ceq 'renderdoc-diagnostic'
    })
    if ($components.Count -ne 1 -or
        [string]$components[0].version -cne 'v1.45' -or
        [string]$components[0].commit -cnotmatch '^[a-f0-9]{40}$' -or
        [string]$components[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [long]$components[0].size -le 0) {
        throw 'sources.lock.json does not contain one valid RenderDoc v1.45 component'
    }
    $component = $components[0]

    $archivePath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Archives 'graphics-lab\RenderDoc_1.45_64.zip') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "The locked RenderDoc archive is missing: $archivePath"
    }
    $archiveItem = Get-Item -LiteralPath $archivePath -Force
    if ($archiveItem.Length -ne [long]$component.size -or
        (Get-LowerSha256 -Path $archivePath) -cne [string]$component.sha256) {
        throw 'The RenderDoc archive does not match its locked size and SHA-256'
    }
    Assert-PSOBBZipArchiveSafe -Path $archivePath | Out-Null

    $executablePath = Assert-PathWithinRoot `
        -Path (Join-Path $Layout.Root 'tools\renderdoc-1.45\RenderDoc_1.45_64\renderdoccmd.exe') `
        -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
        throw "The RenderDoc command-line executable is missing: $executablePath"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $entries = @($archive.Entries | Where-Object {
            $_.FullName.Replace('\', '/') -ceq 'RenderDoc_1.45_64/renderdoccmd.exe'
        })
        if ($entries.Count -ne 1 -or [long]$entries[0].Length -le 0) {
            throw 'The locked RenderDoc archive has no unique x64 renderdoccmd.exe member'
        }
        $entryStream = $entries[0].Open()
        try {
            $archiveExecutableSha256 = [Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData($entryStream)).ToLowerInvariant()
        } finally {
            $entryStream.Dispose()
        }
        $archiveExecutableSize = [long]$entries[0].Length
    } finally {
        $archive.Dispose()
    }

    $executableItem = Get-Item -LiteralPath $executablePath -Force
    $executableSha256 = Get-LowerSha256 -Path $executablePath
    if ($executableItem.Length -ne $archiveExecutableSize -or
        $executableSha256 -cne $archiveExecutableSha256) {
        throw 'renderdoccmd.exe is not byte-identical to the member in the locked archive'
    }

    $version = $executableItem.VersionInfo
    if ([string]$version.ProductVersion -cne 'v1.45' -or
        [string]$version.FileVersion -cne '1.45.0.0' -or
        [string]$version.OriginalFilename -cne 'renderdoccmd.exe' -or
        [string]$version.ProductName -cne 'RenderDoc') {
        throw 'renderdoccmd.exe does not have the required v1.45 version identity'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $executablePath
    $signerSubject = if ($signature.SignerCertificate) {
        [string]$signature.SignerCertificate.Subject
    } else {
        ''
    }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signerSubject.StartsWith(
            'CN=Baldur Scott Karlsson,',
            [System.StringComparison]::Ordinal)) {
        throw "renderdoccmd.exe does not have the required valid RenderDoc author signature (status=$($signature.Status); signer=$signerSubject)"
    }

    [pscustomobject]@{
        ComponentId = 'renderdoc-diagnostic'
        Version = [string]$component.version
        Commit = [string]$component.commit
        ArchivePath = $archivePath
        ArchiveSize = [long]$archiveItem.Length
        ArchiveSha256 = [string]$component.sha256
        ExecutablePath = $executablePath
        ExecutableSize = [long]$executableItem.Length
        ExecutableSha256 = $executableSha256
        SignerSubject = $signerSubject
        SignerThumbprint = [string]$signature.SignerCertificate.Thumbprint
    }
}

function Get-PSOBBDgVoodooRenderDocImportContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "The exact dgVoodoo D3D8 owner is missing: $fullPath"
    }

    $stream = [System.IO.File]::Open(
        $fullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 512 -or $stream.Length -gt 64MB) {
            throw 'The exact dgVoodoo D3D8 owner has an invalid PE byte size'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $read = 0
        while ($read -lt $bytes.Length) {
            $count = $stream.Read($bytes, $read, $bytes.Length - $read)
            if ($count -le 0) {
                throw 'The exact dgVoodoo D3D8 owner could not be read completely'
            }
            $read += $count
        }
    } finally {
        $stream.Dispose()
    }

    $memory = [System.IO.MemoryStream]::new($bytes, $false)
    $peReader = $null
    try {
        $peReader = [System.Reflection.PortableExecutable.PEReader]::new($memory)
        $headers = $peReader.PEHeaders
        if ($null -eq $headers.PEHeader -or
            [int]$headers.CoffHeader.Machine -ne 0x014C -or
            [int]$headers.PEHeader.Magic -ne 0x010B) {
            throw 'The exact dgVoodoo D3D8 owner is not an x86 PE32 image'
        }

        $importDirectory = $headers.PEHeader.ImportTableDirectory
        if ([uint32]$importDirectory.RelativeVirtualAddress -eq 0 -or
            [int]$importDirectory.Size -lt 20) {
            throw 'The exact dgVoodoo D3D8 owner has no valid PE import directory'
        }

        $ensureRange = {
            param(
                [Parameter(Mandatory)][long]$Offset,
                [Parameter(Mandatory)][int]$Count,
                [Parameter(Mandatory)][string]$Label
            )
            if ($Offset -lt 0 -or $Count -lt 0 -or
                $Offset -gt ($bytes.LongLength - $Count)) {
                throw "The exact dgVoodoo D3D8 owner has an out-of-range $Label"
            }
        }
        $rvaToOffset = {
            param(
                [Parameter(Mandatory)][uint32]$Rva,
                [Parameter(Mandatory)][int]$Count,
                [Parameter(Mandatory)][string]$Label
            )
            if ([uint64]$Rva -lt [uint64]$headers.PEHeader.SizeOfHeaders) {
                & $ensureRange -Offset ([long]$Rva) -Count $Count -Label $Label
                return [long]$Rva
            }
            foreach ($section in $headers.SectionHeaders) {
                $span = [Math]::Max(
                    [uint64][uint32]$section.VirtualSize,
                    [uint64][uint32]$section.SizeOfRawData)
                $start = [uint64][uint32]$section.VirtualAddress
                $end = $start + $span
                if ([uint64]$Rva -ge $start -and [uint64]$Rva -lt $end) {
                    $delta = [uint64]$Rva - $start
                    if ($delta + [uint64]$Count -gt
                        [uint64][uint32]$section.SizeOfRawData) {
                        throw "The exact dgVoodoo D3D8 owner maps $Label outside file-backed section data"
                    }
                    $offset = [uint64][uint32]$section.PointerToRawData + $delta
                    if ($offset -gt [uint64][long]::MaxValue) {
                        throw "The exact dgVoodoo D3D8 owner has an invalid $Label offset"
                    }
                    & $ensureRange -Offset ([long]$offset) -Count $Count -Label $Label
                    return [long]$offset
                }
            }
            throw ('The exact dgVoodoo D3D8 owner cannot map ' +
                "$Label RVA 0x$($Rva.ToString('X8')) to file-backed data")
        }
        $readUInt16 = {
            param([uint32]$Rva, [string]$Label)
            $offset = & $rvaToOffset -Rva $Rva -Count 2 -Label $Label
            [System.BitConverter]::ToUInt16($bytes, [int]$offset)
        }
        $readUInt32 = {
            param([uint32]$Rva, [string]$Label)
            $offset = & $rvaToOffset -Rva $Rva -Count 4 -Label $Label
            [System.BitConverter]::ToUInt32($bytes, [int]$offset)
        }
        $readAscii = {
            param(
                [uint32]$Rva,
                [int]$MaximumLength,
                [string]$Label
            )
            $characters = [System.Collections.Generic.List[byte]]::new()
            $terminated = $false
            for ($index = 0; $index -lt $MaximumLength; $index++) {
                $characterRva = [uint64]$Rva + [uint64]$index
                if ($characterRva -gt [uint32]::MaxValue) {
                    throw "The exact dgVoodoo D3D8 owner has an overflowing $Label RVA"
                }
                $offset = & $rvaToOffset `
                    -Rva ([uint32]$characterRva) `
                    -Count 1 `
                    -Label $Label
                $value = $bytes[[int]$offset]
                if ($value -eq 0) {
                    $terminated = $true
                    break
                }
                if ($value -lt 0x20 -or $value -gt 0x7E) {
                    throw "The exact dgVoodoo D3D8 owner has a non-ASCII $Label"
                }
                $characters.Add($value)
            }
            if (-not $terminated -or $characters.Count -eq 0) {
                throw "The exact dgVoodoo D3D8 owner has an invalid $Label"
            }
            [System.Text.Encoding]::ASCII.GetString($characters.ToArray())
        }

        $kernelDescriptors = [System.Collections.Generic.List[object]]::new()
        $descriptorLimit = [Math]::Min(
            [int][Math]::Floor([double]$importDirectory.Size / 20.0),
            1024)
        $descriptorTerminated = $false
        for ($index = 0; $index -lt $descriptorLimit; $index++) {
            $descriptorRva64 =
                [uint64][uint32]$importDirectory.RelativeVirtualAddress +
                ([uint64]$index * 20)
            if ($descriptorRva64 -gt [uint32]::MaxValue) {
                throw 'The exact dgVoodoo D3D8 owner has an overflowing import descriptor RVA'
            }
            $descriptorRva = [uint32]$descriptorRva64
            $originalFirstThunk = & $readUInt32 `
                -Rva $descriptorRva `
                -Label 'import OriginalFirstThunk'
            $timeDateStamp = & $readUInt32 `
                -Rva ([uint32]($descriptorRva + 4)) `
                -Label 'import TimeDateStamp'
            $forwarderChain = & $readUInt32 `
                -Rva ([uint32]($descriptorRva + 8)) `
                -Label 'import ForwarderChain'
            $nameRva = & $readUInt32 `
                -Rva ([uint32]($descriptorRva + 12)) `
                -Label 'import Name'
            $firstThunk = & $readUInt32 `
                -Rva ([uint32]($descriptorRva + 16)) `
                -Label 'import FirstThunk'
            if ($originalFirstThunk -eq 0 -and $timeDateStamp -eq 0 -and
                $forwarderChain -eq 0 -and $nameRva -eq 0 -and
                $firstThunk -eq 0) {
                $descriptorTerminated = $true
                break
            }
            if ($nameRva -eq 0 -or $firstThunk -eq 0) {
                throw 'The exact dgVoodoo D3D8 owner has an incomplete PE import descriptor'
            }
            $libraryName = & $readAscii `
                -Rva $nameRva `
                -MaximumLength 128 `
                -Label 'import library name'
            if ($libraryName.Equals(
                'KERNEL32.DLL',
                [System.StringComparison]::OrdinalIgnoreCase)) {
                $kernelDescriptors.Add([pscustomobject]@{
                    LibraryName = $libraryName
                    OriginalFirstThunkRva = [uint32]$originalFirstThunk
                    FirstThunkRva = [uint32]$firstThunk
                })
            }
        }
        if (-not $descriptorTerminated) {
            throw 'The exact dgVoodoo D3D8 owner has no terminated PE import descriptor table'
        }
        if ($kernelDescriptors.Count -ne 1) {
            throw 'The exact dgVoodoo D3D8 owner must have one KERNEL32 import descriptor'
        }

        $kernel = $kernelDescriptors[0]
        $lookupRva = if ($kernel.OriginalFirstThunkRva -ne 0) {
            [uint32]$kernel.OriginalFirstThunkRva
        } else {
            [uint32]$kernel.FirstThunkRva
        }
        $imports = [System.Collections.Generic.List[string]]::new()
        $thunkTerminated = $false
        for ($index = 0; $index -lt 1024; $index++) {
            $thunkRva64 = [uint64]$lookupRva + ([uint64]$index * 4)
            if ($thunkRva64 -gt [uint32]::MaxValue) {
                throw 'The exact dgVoodoo D3D8 owner has an overflowing import thunk RVA'
            }
            $thunk = & $readUInt32 `
                -Rva ([uint32]$thunkRva64) `
                -Label 'KERNEL32 import thunk'
            if ($thunk -eq 0) {
                $thunkTerminated = $true
                break
            }
            if (([uint64]$thunk -band [uint64]2147483648) -ne 0) {
                continue
            }
            $hint = & $readUInt16 `
                -Rva ([uint32]$thunk) `
                -Label 'KERNEL32 import hint'
            $nameRva64 = [uint64]$thunk + 2
            if ($nameRva64 -gt [uint32]::MaxValue) {
                throw 'The exact dgVoodoo D3D8 owner has an overflowing import name RVA'
            }
            $importName = & $readAscii `
                -Rva ([uint32]$nameRva64) `
                -MaximumLength 256 `
                -Label 'KERNEL32 import name'
            $imports.Add($importName)
        }
        if (-not $thunkTerminated) {
            throw 'The exact dgVoodoo D3D8 owner has no terminated KERNEL32 import thunk table'
        }
        foreach ($requiredImport in @('LoadLibraryA', 'GetProcAddress')) {
            if (-not $imports.Contains($requiredImport)) {
                throw "The exact dgVoodoo D3D8 owner does not import $requiredImport from KERNEL32"
            }
        }

        [pscustomobject]@{
            Path = $fullPath
            Machine = 'I386'
            LibraryName = [string]$kernel.LibraryName
            OriginalFirstThunkRva = [uint32]$kernel.OriginalFirstThunkRva
            FirstThunkRva = [uint32]$kernel.FirstThunkRva
            Imports = @($imports)
            RenderDocV145Compatible =
                ([uint32]$kernel.OriginalFirstThunkRva -ne 0)
        }
    } finally {
        if ($peReader) {
            $peReader.Dispose()
        }
        $memory.Dispose()
    }
}

function Assert-PSOBBDgVoodooRenderDocCompatibility {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $contract = Get-PSOBBDgVoodooRenderDocImportContract -Path $Path
    if (-not $contract.RenderDocV145Compatible) {
        throw ('RenderDoc v1.45 cannot register the D3D11 API for the exact ' +
            'dgVoodoo D3D8 owner because its KERNEL32 import descriptor has ' +
            'OriginalFirstThunk=0; launching it would produce API: None.')
    }
    $contract
}

function Assert-PSOBBRenderDocProfileCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Profile
    )

    $owner = $Profile.Declared.renderer.d3d8Owner
    if ([string]$owner.componentId -cne 'dgvoodoo2-x86-d3d8') {
        return [pscustomobject]@{
            Applicable = $false
            ComponentId = [string]$owner.componentId
        }
    }

    $relativePath = ([string]$owner.relativePath).Replace('/', '\')
    if ($relativePath -cne 'd3d8.dll') {
        throw 'The exact dgVoodoo D3D8 owner is not materialized at d3d8.dll'
    }
    $clientRoot = Assert-PathWithinRoot `
        -Path $Profile.ClientRoot `
        -Root $Layout.Root
    $ownerPath = Assert-PathWithinRoot `
        -Path (Join-Path $clientRoot $relativePath) `
        -Root $clientRoot
    $contract = Assert-PSOBBDgVoodooRenderDocCompatibility -Path $ownerPath
    $contract | Add-Member -NotePropertyName Applicable -NotePropertyValue $true
    $contract | Add-Member `
        -NotePropertyName ComponentId `
        -NotePropertyValue ([string]$owner.componentId)
    $contract
}

function ConvertTo-PSOBBUInt32ExitCode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ExitCode)

    [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($ExitCode), 0)
}

function Write-PSOBBJsonAtomically {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to overwrite existing evidence metadata: $Path"
    }
    $temporaryPath = $Path + '.new'
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            ($Value | ConvertTo-Json -Depth 30),
            [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $Path
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$clientOperationMutex = Enter-PSOBBClientOperationLock -Layout $layout
try {

$approvedProcesses = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel All)
$anyNamedProcesses = @(Get-Process -Name 'Psobb' -ErrorAction SilentlyContinue)
if ($approvedProcesses.Count -ne 0 -or $anyNamedProcesses.Count -ne 0) {
    throw "RenderDoc launch requires no existing PSOBB client process (approved=$($approvedProcesses.Count); named=$($anyNamedProcesses.Count))"
}

$profile = Get-PSOBBValidatedRenderDocProfile `
    -Layout $layout `
    -SelectedProfileId $ProfileId
$renderDoc = Get-PSOBBLockedRenderDoc -Layout $layout
$renderDocCompatibility = Assert-PSOBBRenderDocProfileCompatibility `
    -Layout $layout `
    -Profile $profile

$evidenceRoot = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Root 'graphics-evidence') `
    -Root $layout.Root
[void][System.IO.Directory]::CreateDirectory($evidenceRoot)
$profileEvidenceRoot = Assert-PSOBBPrivateRenderDocPath `
    -Path (Join-Path $evidenceRoot $ProfileId) `
    -RuntimeEvidenceRoot $evidenceRoot `
    -Purpose 'RenderDoc profile evidence'
[void][System.IO.Directory]::CreateDirectory($profileEvidenceRoot)
$runId = '{0}-renderdoc-{1}' -f `
    [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), `
    [Guid]::NewGuid().ToString('N').Substring(0, 12)
$runRoot = Assert-PSOBBPrivateRenderDocPath `
    -Path (Join-Path $profileEvidenceRoot $runId) `
    -RuntimeEvidenceRoot $evidenceRoot `
    -Purpose 'RenderDoc run evidence'
if (Test-Path -LiteralPath $runRoot) {
    throw "The unique RenderDoc run directory already exists: $runRoot"
}
[void][System.IO.Directory]::CreateDirectory($runRoot)
$captureDirectory = Join-Path $runRoot 'capture'
[void][System.IO.Directory]::CreateDirectory($captureDirectory)
$captureTemplate = Join-Path $captureDirectory 'psobb-frame'
$stdoutPath = Join-Path $runRoot 'renderdoccmd.stdout.log'
$stderrPath = Join-Path $runRoot 'renderdoccmd.stderr.log'
$manifestPath = Join-Path $runRoot 'renderdoc-launch-manifest.json'

$arguments = @(
    'capture',
    '-d', $profile.ClientRoot,
    '-c', $captureTemplate,
    $profile.ClientExecutable
)
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $renderDoc.ExecutablePath
$startInfo.WorkingDirectory = Split-Path -Parent $renderDoc.ExecutablePath
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
foreach ($argument in $arguments) {
    $startInfo.ArgumentList.Add([string]$argument)
}

$launchStartedAtUtc = [DateTime]::UtcNow
$runner = $null
$stdoutTask = $null
$stderrTask = $null
$stdout = ''
$stderr = ''
$graphicsRegistryTransaction = $null
try {
    # renderdoccmd creates the game process itself. Validate the registry
    # contract without reading or altering locally remembered credentials.
    Assert-PSOBBClientLoginRegistry | Out-Null
    $graphicsRegistryTransaction = Set-PSOBBClientNativeGraphics `
        -Layout $layout `
        -Profile $profile.Materialized
    $runner = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $runner) {
        throw 'Windows did not start the locked RenderDoc command-line executable'
    }
    $stdoutTask = $runner.StandardOutput.ReadToEndAsync()
    $stderrTask = $runner.StandardError.ReadToEndAsync()
    if (-not $runner.WaitForExit(30000)) {
        try {
            $runner.Kill($true)
            [void]$runner.WaitForExit(10000)
        } catch { }
        throw 'renderdoccmd did not return a capture identity within 30 seconds'
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $identityMatches = [regex]::Matches(
        $stderr,
        '(?m)^Launched as ID ([0-9]+)\s*$')
    if ($identityMatches.Count -ne 1) {
        throw "renderdoccmd did not return one unambiguous capture identity: $($stderr.Trim())"
    }
    $captureIdentity = [uint32]::Parse(
        $identityMatches[0].Groups[1].Value,
        [System.Globalization.CultureInfo]::InvariantCulture)
    $unsignedExitCode = ConvertTo-PSOBBUInt32ExitCode -ExitCode $runner.ExitCode
    if ($captureIdentity -eq 0 -or $unsignedExitCode -ne $captureIdentity) {
        throw "renderdoccmd exit identity $unsignedExitCode did not match reported capture identity $captureIdentity"
    }
} catch {
    $launchError = $_
    if ($graphicsRegistryTransaction -and
        $graphicsRegistryTransaction.Applied -and
        @(Get-Process -Name 'Psobb' -ErrorAction SilentlyContinue).Count -eq 0) {
        try {
            Restore-PSOBBClientGraphicCtrlBackup `
                -Layout $layout `
                -BackupPath $graphicsRegistryTransaction.BackupPath | Out-Null
        } catch {
            throw ('RenderDoc launch failed and its native graphics registry ' +
                "transaction also failed to roll back. Launch: $($launchError.Exception.Message) " +
                "Rollback: $($_.Exception.Message)")
        }
    }
    throw $launchError
} finally {
    $runnerExited = $false
    if ($runner) {
        try { $runnerExited = $runner.HasExited } catch { }
    }
    if ($stdoutTask -and $runnerExited) {
        try { $stdout = $stdoutTask.GetAwaiter().GetResult() } catch { }
    }
    if ($stderrTask -and $runnerExited) {
        try { $stderr = $stderrTask.GetAwaiter().GetResult() } catch { }
    }
    [System.IO.File]::WriteAllText(
        $stdoutPath, $stdout, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText(
        $stderrPath, $stderr, [System.Text.UTF8Encoding]::new($false))
    if ($runner) {
        $runner.Dispose()
    }
}

$deadline = [DateTime]::UtcNow.AddSeconds($WindowWaitSeconds)
$targetRecord = $null
$targetProcess = $null
$window = $null
while ([DateTime]::UtcNow -lt $deadline) {
    $records = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel All)
    $named = @(Get-Process -Name 'Psobb' -ErrorAction SilentlyContinue)
    if ($records.Count -gt 1 -or $named.Count -gt 1) {
        throw 'More than one PSOBB process appeared after the RenderDoc launch'
    }
    if ($named.Count -gt 0 -and $named.Count -ne $records.Count) {
        throw 'A PSOBB-named process appeared but could not be proven to be the approved client'
    }
    if ($records.Count -eq 1 -and $named.Count -eq 1) {
        $candidateRecord = $records[0]
        if ([string]$candidateRecord.Channel -cne 'LocalLab' -or
            -not ([System.IO.Path]::GetFullPath([string]$candidateRecord.ExecutablePath)).Equals(
                [System.IO.Path]::GetFullPath($profile.ClientExecutable),
                [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]$candidateRecord.ExecutableSha256 -cne $profile.ClientExecutableSha256 -or
            [DateTime]$candidateRecord.StartTimeUtc -lt $launchStartedAtUtc.AddSeconds(-2)) {
            throw 'The process created by RenderDoc is not the requested exact LocalLab client'
        }
        $candidateProcess = Get-Process `
            -Id ([int]$candidateRecord.ProcessId) `
            -ErrorAction SilentlyContinue
        if ($candidateProcess -and
            (Test-PSOBBProcessAtExactPath `
                -Process $candidateProcess `
                -Name 'Psobb' `
                -ExpectedPath $profile.ClientExecutable)) {
            $candidateProcess.Refresh()
            if (-not $candidateProcess.HasExited -and
                $candidateProcess.MainWindowHandle -ne [IntPtr]::Zero) {
                $targetRecord = $candidateRecord
                $targetProcess = $candidateProcess
                $window = Get-PSOBBClientWindowPresentation -Process $candidateProcess
                break
            }
        }
    }
    Start-Sleep -Milliseconds 250
}
if (-not $targetRecord -or -not $targetProcess -or -not $window) {
    throw "The exact RenderDoc-launched LocalLab client did not expose a main window within $WindowWaitSeconds seconds"
}

$profileAfter = Get-PSOBBValidatedRenderDocProfile `
    -Layout $layout `
    -SelectedProfileId $ProfileId
$renderDocAfter = Get-PSOBBLockedRenderDoc -Layout $layout
if ($profileAfter.ProfileSha256 -cne $profile.ProfileSha256 -or
    $renderDocAfter.ArchiveSha256 -cne $renderDoc.ArchiveSha256 -or
    $renderDocAfter.ExecutableSha256 -cne $renderDoc.ExecutableSha256) {
    throw 'The client profile or RenderDoc artifact changed during launch'
}
$targetProcess.Refresh()
if ($targetProcess.HasExited -or
    [Math]::Abs((
        $targetProcess.StartTime.ToUniversalTime() -
        [DateTime]$targetRecord.StartTimeUtc).TotalSeconds) -gt 0.5 -or
    -not (Test-PSOBBProcessAtExactPath `
        -Process $targetProcess `
        -Name 'Psobb' `
        -ExpectedPath $profile.ClientExecutable)) {
    throw 'The RenderDoc-launched client identity changed before evidence metadata was written'
}

$relativeExecutable = [System.IO.Path]::GetRelativePath(
    $layout.Root,
    $profile.ClientExecutable).Replace('\', '/')
$manifest = [ordered]@{
    schemaVersion = 1
    kind = 'psobb-renderdoc-launch'
    runId = $runId
    state = 'capture-armed-awaiting-manual-trigger'
    startedAtUtc = $launchStartedAtUtc.ToString('o')
    readyAtUtc = [DateTime]::UtcNow.ToString('o')
    channel = 'local-lab'
    profile = [ordered]@{
        id = $ProfileId
        materializedFile = 'client-profile.json'
        materializedSha256 = $profile.ProfileSha256
        nativeGraphicsPresetId = [string]$graphicsRegistryTransaction.PresetId
        graphicCtrlSha256 = [string]$graphicsRegistryTransaction.GraphicCtrlSha256
        requestedExpectations = [ordered]@{
            internalRender = [ordered]@{
                width = $profile.RequestedInternalWidth
                height = $profile.RequestedInternalHeight
                evidenceClass = 'configuration-only'
            }
            output = [ordered]@{
                width = $profile.RequestedOutputWidth
                height = $profile.RequestedOutputHeight
                evidenceClass = 'configuration-and-window-only'
            }
            aspectPolicy = $profile.AspectPolicy
            outputApi = [string]$profile.Declared.renderer.outputApi
        }
    }
    target = [ordered]@{
        application = 'Psobb.exe'
        processId = [int]$targetRecord.ProcessId
        processStartTimeUtc = ([DateTime]$targetRecord.StartTimeUtc).ToString('o')
        executable = 'runtime:' + $relativeExecutable
        executableSize = $profile.ClientExecutableSize
        executableSha256 = $profile.ClientExecutableSha256
        window = [ordered]@{
            handle = ('0x{0:X}' -f $targetProcess.MainWindowHandle.ToInt64())
            x = [int]$window.X
            y = [int]$window.Y
            width = [int]$window.Width
            height = [int]$window.Height
            clientWidth = [int]$window.ClientWidth
            clientHeight = [int]$window.ClientHeight
        }
    }
    renderDoc = [ordered]@{
        componentId = $renderDoc.ComponentId
        version = $renderDoc.Version
        commit = $renderDoc.Commit
        archiveSize = $renderDoc.ArchiveSize
        archiveSha256 = $renderDoc.ArchiveSha256
        executableSize = $renderDoc.ExecutableSize
        executableSha256 = $renderDoc.ExecutableSha256
        authenticodeStatus = 'Valid'
        signerSubject = $renderDoc.SignerSubject
        signerThumbprint = $renderDoc.SignerThumbprint
        captureIdentity = $captureIdentity
        invocation = @(
            'capture',
            '-d <validated-client-root>',
            '-c capture/psobb-frame',
            '<validated-Psobb.exe>'
        )
        stdout = [ordered]@{
            file = 'renderdoccmd.stdout.log'
            sha256 = Get-LowerSha256 -Path $stdoutPath
        }
        stderr = [ordered]@{
            file = 'renderdoccmd.stderr.log'
            sha256 = Get-LowerSha256 -Path $stderrPath
        }
    }
    capture = [ordered]@{
        template = 'capture/psobb-frame'
        trigger = 'manual-f12'
        artifact = $null
    }
    renderTargetEvidence = [ordered]@{
        status = 'pending-replay-inspection'
        observedInternalRender = $null
        observedOutput = $null
        note = 'Configured dimensions are expectations only until replay evidence is inspected.'
    }
}
Write-PSOBBJsonAtomically -Value $manifest -Path $manifestPath

[pscustomobject]@{
    Ready = $true
    ProfileId = $ProfileId
    ProcessId = [int]$targetRecord.ProcessId
    ProcessStartTimeUtc = ([DateTime]$targetRecord.StartTimeUtc).ToString('o')
    CaptureIdentity = $captureIdentity
    RunId = $runId
    RunRoot = $runRoot
    CaptureTemplate = $captureTemplate
    LaunchManifestPath = $manifestPath
    RequestedInternalResolution = '{0}x{1}' -f `
        $profile.RequestedInternalWidth, $profile.RequestedInternalHeight
    RequestedOutputResolution = '{0}x{1}' -f `
        $profile.RequestedOutputWidth, $profile.RequestedOutputHeight
    RenderTargetEvidence = 'pending-replay-inspection'
    NextAction = 'Bring PSOBB to the required scene and press F12 manually once. Do not enter credentials while recording evidence.'
}
} finally {
    Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
}
