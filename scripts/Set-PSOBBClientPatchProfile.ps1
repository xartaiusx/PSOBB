[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('stable-qol', 'baseline')]
    [string]$Profile = 'stable-qol',
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

function Write-PSOBBAtomicText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Root
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $temporary = $safePath + '.' + [Guid]::NewGuid().ToString('N') + '.new'
    Assert-PathWithinRoot -Path $temporary -Root $Root | Out-Null
    try {
        [System.IO.File]::WriteAllText(
            $temporary,
            $Text,
            [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($temporary, $safePath, $true)
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$configPath = Assert-PathWithinRoot `
    -Path (Join-Path $layout.Server 'system\config.json') `
    -Root $layout.Root
$installRecordPath = Assert-PathWithinRoot -Path $layout.InstallRecord -Root $layout.Root
$policyPath = Join-Path $script:PSOBBRepositoryRoot 'config\client-patch-profiles.json'
$policy = Get-PSOBBClientPatchPolicy -Path $policyPath
$selectedProfiles = @($policy.profiles | Where-Object id -CEQ $Profile)
if ($selectedProfiles.Count -ne 1 -or [string]$selectedProfiles[0].channel -cne 'stable') {
    throw "The requested client-patch profile is not approved for stable: $Profile"
}
Assert-NewservClientPatchProfileAvailable `
    -ServerRoot $layout.Server `
    -Profile $Profile `
    -PolicyPath $policyPath | Out-Null
foreach ($path in @($configPath, $installRecordPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required runtime metadata is missing: $path"
    }
}

$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
try {
    $ownsMutex = $mutex.WaitOne(0)
    if (-not $ownsMutex) {
        throw 'Another PSOBB start, stop, or patch-profile operation is already in progress'
    }
    $running = @(Get-NewservProcessesAtPath -Layout $layout)
    if ($running.Count -gt 0) {
        throw "Stop the approved newserv process before changing client patches (PID(s): $($running.Id -join ', '))"
    }

    $originalConfig = Get-Content -Raw -LiteralPath $configPath
    $updatedConfig = Get-NewservClientPatchConfiguration `
        -Text $originalConfig `
        -Profile $Profile `
        -PolicyPath $policyPath
    $observedAutoPatches = @(Get-ActiveConfigStringArray -Text $updatedConfig -Key 'AutoPatches')
    $observedRequiredPatches = @(Get-ActiveConfigStringArray -Text $updatedConfig -Key 'BBRequiredPatches')
    if (-not (Test-ExactStringSequence `
            -Expected @($selectedProfiles[0].autoPatches) `
            -Actual $observedAutoPatches) -or
        -not (Test-ExactStringSequence `
            -Expected @($selectedProfiles[0].bbRequiredPatches) `
            -Actual $observedRequiredPatches)) {
        throw 'Client-patch profile transform did not produce the exact selected profile'
    }

    $originalRecordText = Get-Content -Raw -LiteralPath $installRecordPath
    $record = $originalRecordText | ConvertFrom-Json -Depth 10
    if (($record.schemaVersion -ne 2) -or
        ([string]$record.installationId -cne [string]$marker.installationId)) {
        throw 'Runtime installation record is not valid for this installation'
    }
    $originalRecordProfile = if ($record.PSObject.Properties['clientPatchProfile']) {
        [string]$record.clientPatchProfile
    } else { '' }
    $originalRecordPolicyHash = if ($record.PSObject.Properties['clientPatchPolicySha256']) {
        [string]$record.clientPatchPolicySha256
    } else { '' }
    $policyHash = Get-LowerSha256 $policyPath
    $record | Add-Member -NotePropertyName clientPatchProfile -NotePropertyValue $Profile -Force
    $record | Add-Member -NotePropertyName clientPatchPolicySha256 `
        -NotePropertyValue $policyHash -Force
    $updatedRecordText = $record | ConvertTo-Json -Depth 10

    $alreadyApplied = ($originalConfig -ceq $updatedConfig) -and
        ($originalRecordProfile -ceq $Profile) -and
        ($originalRecordPolicyHash -ceq $policyHash)
    $applied = $false
    if (-not $alreadyApplied -and $PSCmdlet.ShouldProcess(
            $layout.Root,
            "apply the reversible newserv client-patch profile '$Profile'")) {
        try {
            Write-PSOBBAtomicText -Path $configPath -Text $updatedConfig -Root $layout.Root
            Write-PSOBBAtomicText -Path $installRecordPath -Text $updatedRecordText -Root $layout.Root
        } catch {
            Write-PSOBBAtomicText -Path $configPath -Text $originalConfig -Root $layout.Root
            Write-PSOBBAtomicText -Path $installRecordPath -Text $originalRecordText -Root $layout.Root
            throw
        }
        $applied = $true
    }

    [pscustomobject]@{
        RuntimeRoot = $layout.Root
        Profile = $Profile
        AutoPatches = $observedAutoPatches
        BBRequiredPatches = $observedRequiredPatches
        Changed = $applied
        RestartRequired = $applied
        Pending = (-not $alreadyApplied) -and (-not $applied)
    }
} finally {
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
