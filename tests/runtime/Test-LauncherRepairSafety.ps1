[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

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

function Test-FailsClosed {
    param([Parameter(Mandatory)][scriptblock]$Action)
    try {
        & $Action
        $false
    } catch {
        $_.Exception.Message -like 'Client runtime replacement requires*'
    }
}

foreach ($relativePath in @(
        'scripts\PSOBB.Common.ps1',
        'scripts\Reset-PSOBBClientRuntime.ps1',
        'scripts\New-PSOBBGraphicsLabRuntime.ps1',
        'scripts\Set-PSOBBAshenbubsHDClientActivation.ps1')) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repositoryRoot $relativePath),
        [ref]$tokens,
        [ref]$parseErrors) | Out-Null
    Add-Result "PowerShell syntax: $relativePath" ($parseErrors.Count -eq 0) `
        "$($parseErrors.Count) parser error(s)"
}

$originalServers = (Get-Item Function:\Get-PSOBBServerEnvironmentProcessRecords).ScriptBlock
$originalLifecycleEvidence = (Get-Item Function:\Get-PSOBBServerLifecycleEvidenceRecords).ScriptBlock
$originalClients = (Get-Item Function:\Get-PSOBBAllClientProcessRecords).ScriptBlock
$originalListeners = (Get-Item Function:\Get-PSOBBReservedServerPortListeners).ScriptBlock
$script:ServerRecords = @()
$script:LifecycleEvidence = @()
$script:ClientRecords = @()
$script:ListenerRecords = @()
$script:HelperRecords = @()
try {
    Set-Item Function:\Get-PSOBBServerLifecycleEvidenceRecords -Value {
        @($script:LifecycleEvidence)
    }
    Set-Item Function:\Get-PSOBBServerEnvironmentProcessRecords -Value {
        @($script:ServerRecords)
    }
    Set-Item Function:\Get-PSOBBAllClientProcessRecords -Value {
        @($script:ClientRecords)
    }
    Set-Item Function:\Get-PSOBBReservedServerPortListeners -Value {
        @($script:ListenerRecords)
    }
    Set-Item Function:\Get-Process -Value {
        @($script:HelperRecords)
    }
    $layout = [pscustomobject]@{ Root = 'fixture' }

    $emptyPassed = Assert-PSOBBGlobalStoppedRuntime -Layout $layout
    Add-Result 'global stopped assertion accepts only a complete empty census' (
        $emptyPassed -eq $true) `
        'both environments, clients/helpers, and listeners were absent'

    $serverCases = @('Stable', 'CombatCanary')
    $serverFailures = foreach ($environment in $serverCases) {
        $script:ServerRecords = @([pscustomobject]@{
                ServerEnvironment = $environment
                ProcessId = 41
                Classification = 'ApprovedExactPath'
            })
        Test-FailsClosed {
            Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null
        }
    }
    Add-Result 'global stopped assertion covers both server environments' (
        @($serverFailures | Where-Object { -not $_ }).Count -eq 0) `
        'Stable and CombatCanary named-server evidence both fail closed'
    $script:ServerRecords = @()

    $script:LifecycleEvidence = @([pscustomobject]@{
            ServerEnvironment = 'Stable'
            Classification = 'InvalidOrIncomplete'
        })
    Add-Result 'global stopped assertion rejects stale lifecycle evidence' (
        (Test-FailsClosed {
                Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null
            })) `
        'incomplete control state cannot be treated as exact Stopped'
    $script:LifecycleEvidence = @()

    $script:ClientRecords = @([pscustomobject]@{
            ServerEnvironment = 'Unknown'
            Channel = 'Unknown'
            ProcessId = 51
            Classification = 'UnexpectedPath'
        })
    Add-Result 'global stopped assertion rejects every named Psobb client' (
        (Test-FailsClosed {
                Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null
            })) `
        'unexpected and uninspectable client identities remain blocking'
    $script:ClientRecords = @()

    $script:HelperRecords = @([pscustomobject]@{
            ProcessName = 'online'
            Id = 61
        })
    Add-Result 'global stopped assertion rejects named client helpers' (
        (Test-FailsClosed {
                Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null
            })) `
        'online and option helpers are part of the stopped boundary'
    $script:HelperRecords = @()

    $script:ListenerRecords = @([pscustomobject]@{
            LocalAddress = '127.0.0.1'
            LocalPort = 11000
            OwningProcess = 71
        })
    Add-Result 'global stopped assertion rejects reserved listeners' (
        (Test-FailsClosed {
                Assert-PSOBBGlobalStoppedRuntime -Layout $layout | Out-Null
            })) `
        'a reserved listener blocks replacement even without a named process'
} finally {
    Set-Item Function:\Get-PSOBBServerLifecycleEvidenceRecords -Value $originalLifecycleEvidence
    Set-Item Function:\Get-PSOBBServerEnvironmentProcessRecords -Value $originalServers
    Set-Item Function:\Get-PSOBBAllClientProcessRecords -Value $originalClients
    Set-Item Function:\Get-PSOBBReservedServerPortListeners -Value $originalListeners
    Remove-Item Function:\Get-Process -ErrorAction SilentlyContinue
}

$commonSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')
$resetSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Reset-PSOBBClientRuntime.ps1')
$graphicsSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\New-PSOBBGraphicsLabRuntime.ps1')
$assetsSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Set-PSOBBAshenbubsHDClientActivation.ps1')

Add-Result 'shared assertion reuses the complete existing censuses' (
    $commonSource -match
        'function\s+Assert-PSOBBGlobalStoppedRuntime[\s\S]{0,900}Get-PSOBBServerLifecycleEvidenceRecords[\s\S]{0,300}Get-PSOBBServerEnvironmentProcessRecords[\s\S]{0,300}Get-PSOBBAllClientProcessRecords[\s\S]{0,300}Get-Process\s+-Name\s+''online'',\s*''option''[\s\S]{0,300}Get-PSOBBReservedServerPortListeners') `
    'no path-only or selected-environment-only replacement census was introduced'

Add-Result 'launcher repair materializers recheck while the client lock is held' (
    $resetSource -match
        'Enter-PSOBBClientOperationLock[\s\S]+Assert-PSOBBGlobalStoppedRuntime[\s\S]{0,220}if \(Test-Path -LiteralPath \$targetClient\)[\s\S]{0,220}Move-Item' -and
    $graphicsSource -match
        'Enter-PSOBBClientOperationLock[\s\S]+Assert-PSOBBGlobalStoppedRuntime[\s\S]{0,220}if \(Test-Path -LiteralPath \$targetClient\)[\s\S]{0,220}Move-Item' -and
    $assetsSource -match
        'ShouldProcess\([\s\S]{0,260}restore AshenbubsHD[\s\S]{0,220}Assert-PSOBBGlobalStoppedRuntime[\s\S]{0,180}Restore-ActivationSnapshot' -and
    $assetsSource -match
        'ShouldProcess\([\s\S]{0,300}activate unchanged AshenbubsHD[\s\S]{0,220}Assert-PSOBBGlobalStoppedRuntime[\s\S]{0,300}\$snapshotId') `
    'every reachable replacement path performs the global census after locking and immediately before mutation'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
[pscustomobject]@{
    Suite = 'LauncherRepairSafety'
    Passed = $results.Count - $failed.Count
    Failed = $failed.Count
} | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    throw "$($failed.Count) launcher repair-safety test(s) failed"
}
