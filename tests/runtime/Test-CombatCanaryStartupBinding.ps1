[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
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

function Write-InstallationRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [switch]$Protect
    )

    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
    if ($Protect) {
        Set-PSOBBProtectedAcl -Path $Path
    }
}

function New-InstallationRecord {
    [ordered]@{
        schemaVersion = 1
        environment = 'CombatCanary'
        environmentId = 'combat-canary'
        initializedAtUtc = '2026-07-20T12:00:00.0000000Z'
        buildContractSha256 = 'a' * 64
        serverReleaseManifestSha256 = 'b' * 64
        baseClientManifestSha256 = 'c' * 64
        clientBindingSha256 = 'd' * 64
        snapshotDirectoryName = 'twills-slot0-20260720T120000000Z-1234abcd'
        snapshotId = '12345678-1234-1234-1234-123456789abc'
        snapshotManifestSha256 = 'e' * 64
        stateBindingSha256 = 'f' * 64
        twillsContractSha256 = '1' * 64
        signingPublicKeySpkiSha256 = '2' * 64
        configurationSha256 = '3' * 64
    }
}

function Get-CommandInvocationCount {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CommandName
    )

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "$Path has $($errors.Count) parser error(s)"
    }
    @($ast.FindAll({
                param($Node)
                $Node -is [System.Management.Automation.Language.CommandAst] -and
                    $Node.GetCommandName() -ceq $CommandName
            }, $true)).Count
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'psobb-canary-startup-binding-' + [Guid]::NewGuid().ToString('N'))
try {
    $layout = Get-PSOBBLayout -RuntimeRoot $fixtureRoot
    $combat = Get-PSOBBServerEnvironmentLayout `
        -Layout $layout -Environment CombatCanary
    [System.IO.Directory]::CreateDirectory($combat.EnvironmentRoot) | Out-Null

    $record = New-InstallationRecord
    Write-InstallationRecord `
        -Path $combat.InstallRecord -Value $record -Protect
    $expectations = Get-PSOBBCombatCanaryInstallationBindingExpectations `
        -Layout $layout
    Add-Result 'protected exact installation record yields only three expectations' (
        @($expectations.PSObject.Properties.Name).Count -eq 3 -and
        [string]$expectations.BuildContractSha256 -ceq ('a' * 64) -and
        [string]$expectations.ClientBindingSha256 -ceq ('d' * 64) -and
        [string]$expectations.StateBindingSha256 -ceq ('f' * 64)) `
        'outer startup receives build, client, and state hashes without exhaustive verification'

    $record.environmentId = 'stable'
    Write-InstallationRecord `
        -Path $combat.InstallRecord -Value $record -Protect
    $wrongIdentityRejected = $false
    try {
        Get-PSOBBCombatCanaryInstallationBindingExpectations `
            -Layout $layout | Out-Null
    } catch {
        $wrongIdentityRejected =
            $_.Exception.Message -match 'invalid identity'
    }
    Add-Result 'wrong installation identity is rejected' $wrongIdentityRejected `
        'a Stable environment binding cannot seed CombatCanary startup'

    $record = New-InstallationRecord
    $record.stateBindingSha256 = 'F' * 64
    Write-InstallationRecord `
        -Path $combat.InstallRecord -Value $record -Protect
    $wrongHashRejected = $false
    try {
        Get-PSOBBCombatCanaryInstallationBindingExpectations `
            -Layout $layout | Out-Null
    } catch {
        $wrongHashRejected =
            $_.Exception.Message -match 'invalid stateBindingSha256'
    }
    Add-Result 'noncanonical binding hash is rejected' $wrongHashRejected `
        'only lowercase exact SHA-256 expectations are accepted'

    $record = New-InstallationRecord
    $record.unexpected = 'value'
    Write-InstallationRecord `
        -Path $combat.InstallRecord -Value $record -Protect
    $extraPropertyRejected = $false
    try {
        Get-PSOBBCombatCanaryInstallationBindingExpectations `
            -Layout $layout | Out-Null
    } catch {
        $extraPropertyRejected =
            $_.Exception.Message -match 'exact property set'
    }
    Add-Result 'expanded installation schema is rejected' $extraPropertyRejected `
        'the expectation reader accepts only the exact schema-1 record'

    $malformedJson = '{"schemaVersion":1,"schemaVersion":1}'
    [System.IO.File]::WriteAllText(
        $combat.InstallRecord,
        $malformedJson,
        [System.Text.UTF8Encoding]::new($false))
    Set-PSOBBProtectedAcl -Path $combat.InstallRecord
    $malformedRejected = $false
    try {
        Get-PSOBBCombatCanaryInstallationBindingExpectations `
            -Layout $layout | Out-Null
    } catch {
        $malformedRejected =
            $_.Exception.Message -match 'duplicate decoded property'
    }
    Add-Result 'duplicate-property JSON is rejected' $malformedRejected `
        'strict bounded UTF-8 JSON parsing occurs before expectations are returned'

    $record = New-InstallationRecord
    Remove-Item -LiteralPath $combat.InstallRecord -Force
    Write-InstallationRecord -Path $combat.InstallRecord -Value $record
    $unprotectedRejected = $false
    try {
        Get-PSOBBCombatCanaryInstallationBindingExpectations `
            -Layout $layout | Out-Null
    } catch {
        $unprotectedRejected =
            $_.Exception.Message -match 'unprotected'
    }
    Add-Result 'unprotected installation record is rejected' $unprotectedRejected `
        'an inherited temporary-file DACL cannot seed protected lifecycle state'
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

$commonPath = Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1'
$startPath = Join-Path $repositoryRoot 'scripts\Start-PSOBB.ps1'
$supervisorPath = Join-Path $repositoryRoot 'scripts\Invoke-NewservSupervisor.ps1'
$sessionPath = Join-Path $repositoryRoot 'scripts\Start-PSOBBSession.ps1'
$clientPath = Join-Path $repositoryRoot 'scripts\Start-PSOBBClient.ps1'
$startSource = Get-Content -Raw -LiteralPath $startPath
$supervisorSource = Get-Content -Raw -LiteralPath $supervisorPath
$sessionSource = Get-Content -Raw -LiteralPath $sessionPath

$outerExpectationReads = Get-CommandInvocationCount `
    -Path $startPath `
    -CommandName 'Get-PSOBBCombatCanaryInstallationBindingExpectations'
$outerFullVerifications = Get-CommandInvocationCount `
    -Path $startPath -CommandName 'Get-PSOBBCombatCanaryInstalledBinding'
$supervisorFullVerifications = Get-CommandInvocationCount `
    -Path $supervisorPath -CommandName 'Get-PSOBBCombatCanaryInstalledBinding'
$sessionFullVerifications = Get-CommandInvocationCount `
    -Path $sessionPath -CommandName 'Get-PSOBBCombatCanaryInstalledBinding'
$clientContractVerifications = Get-CommandInvocationCount `
    -Path $commonPath -CommandName 'Get-PSOBBCombatCanaryInstalledBinding'
$clientContractCalls = Get-CommandInvocationCount `
    -Path $clientPath -CommandName 'Get-PSOBBCombatCanaryClientLaunchContract'
Add-Result 'server launch has one exhaustive verifier at the child boundary' (
    $outerExpectationReads -eq 1 -and
    $outerFullVerifications -eq 0 -and
    $supervisorFullVerifications -eq 1) `
    "outer expectations=$outerExpectationReads; outer full=$outerFullVerifications; supervisor full=$supervisorFullVerifications"
Add-Result 'session removes only the redundant pre-client verifier' (
    $sessionFullVerifications -eq 0 -and
    $clientContractVerifications -eq 1 -and
    $clientContractCalls -eq 1 -and
    $sessionSource -match "serverEnvironmentName -ceq 'Stable'[\s\S]{0,160}Test-PSOBB\.ps1") `
    'CombatCanary client verification remains in its closer launcher; Stable baseline verification remains'

$verificationIndex = $supervisorSource.IndexOf(
    'Get-PSOBBCombatCanaryInstalledBinding',
    [System.StringComparison]::Ordinal)
$bindingMismatchIndex = $supervisorSource.IndexOf(
    'startup binding expectations do not match',
    [System.StringComparison]::Ordinal)
$childStartIndex = $supervisorSource.IndexOf(
    '$child = [System.Diagnostics.Process]::Start',
    [System.StringComparison]::Ordinal)
Add-Result 'all three verified binding comparisons precede child creation' (
    $verificationIndex -ge 0 -and
    $bindingMismatchIndex -gt $verificationIndex -and
    $childStartIndex -gt $bindingMismatchIndex -and
    $supervisorSource.Substring(
        $verificationIndex,
        $childStartIndex - $verificationIndex) -match
            'BuildContractSha256[\s\S]*ClientBindingSha256[\s\S]*StateBindingSha256') `
    "verification index=$verificationIndex; mismatch index=$bindingMismatchIndex; child index=$childStartIndex"

$recordBindingIndex = $startSource.IndexOf(
    'supervisor process record did not retain',
    [System.StringComparison]::Ordinal)
$listenerClockIndex = $startSource.IndexOf(
    '$listenerDeadline = [DateTime]::UtcNow.AddSeconds(',
    $recordBindingIndex,
    [System.StringComparison]::Ordinal)
Add-Result 'verification and listener clocks are distinct' (
    $startSource -match '\$verificationDeadline[\s\S]{0,180}\$VerificationTimeoutSeconds' -and
    $recordBindingIndex -ge 0 -and
    $listenerClockIndex -gt $recordBindingIndex -and
    $startSource -match 'installation verification and child creation did not complete' -and
    $startSource -match 'after verified child creation' -and
    $startSource -match 'before the startup timeout') `
    'CombatCanary verification has its own deadline; listener time starts only after the authenticated child record; Stable wording remains'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) combat-canary startup-binding test(s) failed"
}
[pscustomobject]@{
    Suite = 'CombatCanaryStartupBinding'
    Total = $results.Count
    Passed = $results.Count
    Failed = 0
}
