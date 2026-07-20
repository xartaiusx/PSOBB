[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
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

$optionsSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'src\PSOBB.Launcher\Models\LauncherOptions.cs')
$lifecycleModelSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'src\PSOBB.Launcher\Models\Lifecycle.cs')
$controllerSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'src\PSOBB.Launcher\Services\LifecycleScriptController.cs')
$commandHostSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'src\PSOBB.Launcher\Services\LauncherCommandHost.cs')
$viewModelSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'src\PSOBB.Launcher\ViewModels\MainWindowViewModel.cs')
$windowSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'src\PSOBB.Launcher\MainWindow.xaml')
$shortcutSource = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts\Install-PSOBBDesktopShortcuts.ps1')

Add-Result 'launcher exposes an exact Stable-default server environment option' (
    $lifecycleModelSource -match
        'enum\s+ServerEnvironmentKind\s*\{\s*Stable,\s*CombatCanary,' -and
    $optionsSource -match
        'ServerEnvironmentKind\s+ServerEnvironment' -and
    $optionsSource -match
        'ServerEnvironmentKind\.Stable' -and
    $optionsSource -match
        'case\s+"--server-environment"' -and
    $optionsSource -match
        '"combat-canary"\s*=>\s*ServerEnvironmentKind\.CombatCanary' -and
    $optionsSource -match
        '--server-environment must be stable or combat-canary') `
    'option omission defaults to Stable; CombatCanary requires one exact value'

Add-Result 'observer paths are disjoint by selected environment' (
    $controllerSource -match
        'GetLifecycleFilePaths\([\s\S]*?ServerEnvironmentKind\s+serverEnvironment' -and
    $controllerSource -match
        'ServerEnvironmentKind\.Stable\s*=>\s*"stable"' -and
    $controllerSource -match
        'ServerEnvironmentKind\.CombatCanary\s*=>\s*"combat-canary"' -and
    $controllerSource -match
        'combat-canary",\s*"runtime",\s*"client",\s*"Psobb\.exe"' -and
    $controllerSource -notmatch
        'ServerEnvironmentKind\.CombatCanary\s*=>\s*new HashSet<string>[\s\S]{0,500}"stable"') `
    'CombatCanary observes only its control directory and one Native client path'

Add-Result 'every lifecycle operation forwards the selected environment' (
    ([regex]::Matches(
            $commandHostSource,
            'options\.ServerEnvironment')).Count -eq 6 -and
    $controllerSource -match
        '"Start-PSOBB\.ps1"[\s\S]{0,160}EnvironmentArguments' -and
    $controllerSource -match
        '"Start-PSOBBClient\.ps1"[\s\S]{0,160}arguments' -and
    $controllerSource -match
        '"Start-PSOBBSession\.ps1"[\s\S]{0,160}arguments' -and
    $controllerSource -match
        '"Stop-PSOBBClient\.ps1"[\s\S]{0,160}EnvironmentArguments' -and
    $controllerSource -match
        '"Stop-PSOBBSession\.ps1"[\s\S]{0,240}"-ServerEnvironment"') `
    'Start, Play, Stop Client, Stop Server, and Stop All remain environment-bound'

Add-Result 'CombatCanary keeps the sealed Native client and foreground option' (
    $controllerSource -match
        'serverEnvironment\s*==\s*ServerEnvironmentKind\.Stable[\s\S]{0,300}arguments\.Add\("-Channel"\)' -and
    $controllerSource -match
        'serverEnvironment\s*!=\s*ServerEnvironmentKind\.CombatCanary' -and
    $controllerSource -match
        'selection\.PreserveForeground[\s\S]{0,100}"-PreserveForeground"' -and
    $viewModelSource -match
        'SelectedServerEnvironment[\s\S]{0,600}GraphicsProfileOption\.SafeNative' -and
    $viewModelSource -match
        'SelectedWindowMode\s*=\s*LauncherWindowMode\.ProfileDefault') `
    'no CombatCanary graphics override or gameplay input path was added'

Add-Result 'the WPF controls select an environment without changing lifecycle buttons' (
    $windowSource -match
        'ItemsSource="\{Binding ServerEnvironments\}"' -and
    $windowSource -match
        'SelectedItem="\{Binding SelectedServerEnvironment\}"' -and
    $windowSource -match
        'Command="\{Binding RepairCommand\}"[\s\S]{0,160}IsEnabled="\{Binding StableGraphicsSelectionEnabled\}"' -and
    ([regex]::Matches($windowSource, 'Content="Start session"')).Count -eq 1 -and
    ([regex]::Matches($windowSource, 'Content="Start server"')).Count -eq 1 -and
    ([regex]::Matches($windowSource, 'Content="Start client"')).Count -eq 1 -and
    ([regex]::Matches($windowSource, 'Content="Stop client"')).Count -eq 1 -and
    ([regex]::Matches($windowSource, 'Content="Stop server"')).Count -eq 1 -and
    ([regex]::Matches($windowSource, 'Content="Stop all"')).Count -eq 1) `
    'the existing buttons remain singular and unchanged'

$scriptContractsValid = $true
foreach ($scriptName in @(
        'Start-PSOBB.ps1',
        'Start-PSOBBClient.ps1',
        'Start-PSOBBSession.ps1',
        'Stop-PSOBB.ps1',
        'Stop-PSOBBClient.ps1',
        'Stop-PSOBBSession.ps1')) {
    $source = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot ('scripts\' + $scriptName))
    if ($source -notmatch
        "ValidateSet\('Stable', 'CombatCanary'\)\]\s*\[string\]\`$ServerEnvironment\s*=\s*'Stable'") {
        $scriptContractsValid = $false
    }
}
Add-Result 'PowerShell lifecycle contracts accept only Stable or CombatCanary' (
    $scriptContractsValid) `
    'all six stopped-runtime lifecycle entry points retain Stable defaults'

Add-Result 'the three Desktop shortcuts remain Stable-default definitions' (
    ([regex]::Matches($shortcutSource, "-Name 'PSOBB (?:Start Server|Stop Server|Play)'" )).Count -eq 3 -and
    $shortcutSource -notmatch '--server-environment') `
    'no fourth shortcut or explicit CombatCanary shortcut was introduced'

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) launcher server-environment test(s) failed"
}

[pscustomobject]@{
    Suite = 'LauncherServerEnvironment'
    Passed = $results.Count
    Failed = 0
}
