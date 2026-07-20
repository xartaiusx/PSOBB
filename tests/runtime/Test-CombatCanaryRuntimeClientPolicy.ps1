[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..'))
. (Join-Path $repositoryRoot 'scripts\PSOBB.CombatCanary.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Name, [bool]$Passed) {
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed })
}

function New-Entry([string]$Path, [long]$Size, [char]$HashDigit) {
    [pscustomobject]@{
        path = $Path
        size = $Size
        sha256 = ([string]$HashDigit) * 64
    }
}

$base = @(
    (New-Entry 'Psobb.exe' 4096 'a'),
    (New-Entry 'data/unit.bin' 512 'b'),
    (New-Entry 'GameGuard/0npgg.erl' 128 'c'),
    (New-Entry 'GameGuard/0npgl.erl' 192 'd'),
    (New-Entry 'GameGuard/npgl.erl' 256 'e'),
    (New-Entry 'GameGuard/npgl2.erl' 320 '9'),
    (New-Entry 'log/error.log' 0 'f'),
    (New-Entry 'log/generic.log' 0 '0'),
    (New-Entry 'log/spec.log' 32 '1'))
$profile = New-Entry 'client-profile.json' 96 '2'
$exact = @($base + $profile)

Add-Result 'exact base plus profile passes' (
    Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $exact `
        -ClientProfileEntry $profile)

$nativeMutable = @(
    (New-Entry 'Psobb.exe' 4096 'a'),
    (New-Entry 'data/unit.bin' 512 'b'),
    (New-Entry 'GameGuard/0npgl.erl' 256 'e'),
    (New-Entry 'GameGuard/npgl.erl' 384 '3'),
    (New-Entry 'GameGuard/npgl2.erl' 320 '9'),
    (New-Entry 'GameGuard/1npgg.erl' 128 'c'),
    (New-Entry 'GameGuard/1npgl.erl' 192 'd'),
    (New-Entry 'log/generic.log' 100 '4'),
    (New-Entry 'log/spec.log' 100 '5'),
    (New-Entry 'log/chat20260720.txt' 100 '6'),
    $profile)
Add-Result 'bounded native GameGuard and log mutations pass' (
    Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $nativeMutable `
        -ClientProfileEntry $profile)

function Test-Rejected([object[]]$Actual) {
    -not (Test-PSOBBCombatCanaryRuntimeClientManifest `
        -BaseEntries $base -ActualEntries $Actual `
        -ClientProfileEntry $profile)
}

Add-Result 'changed executable rejected' (Test-Rejected @(
        $exact | ForEach-Object {
            if ($_.path -ceq 'Psobb.exe') {
                New-Entry 'Psobb.exe' 4096 '9'
            } else { $_ }
        }))
Add-Result 'missing exact data rejected' (Test-Rejected @(
        $exact | Where-Object { $_.path -cne 'data/unit.bin' }))
Add-Result 'extra DLL rejected' (Test-Rejected @(
        $exact + (New-Entry 'version.dll' 256 '7')))
Add-Result 'changed profile rejected' (Test-Rejected @(
        $base + (New-Entry 'client-profile.json' 96 '8')))
Add-Result 'missing profile rejected' (Test-Rejected $base)
Add-Result 'case-variant path rejected' (Test-Rejected @(
        $exact | ForEach-Object {
            if ($_.path -ceq 'Psobb.exe') {
                New-Entry 'psobb.exe' 4096 'a'
            } else { $_ }
        }))
Add-Result 'unapproved log rejected' (Test-Rejected @(
        $exact + (New-Entry 'log/session.txt' 20 '7')))
Add-Result 'oversized GameGuard state rejected' (Test-Rejected @(
        $exact + (New-Entry 'GameGuard/1npgg.erl' (1MB + 1) '7')))
Add-Result 'unchanged GameGuard state remains exact' (Test-Rejected @(
        $exact | ForEach-Object {
            if ($_.path -ceq 'GameGuard/npgl2.erl') {
                New-Entry 'GameGuard/npgl2.erl' 320 '8'
            } else { $_ }
        }))
Add-Result 'invalid chat-log name rejected' (Test-Rejected @(
        $exact + (New-Entry 'log/chat-current.txt' 20 '7')))
Add-Result 'duplicate path rejected' (Test-Rejected @($exact + $profile))

$passed = @($results | Where-Object Passed).Count
$failed = @($results | Where-Object { -not $_.Passed })
$results | Format-Table -AutoSize
Write-Host "Passed: $passed / $($results.Count)"
if ($failed.Count -ne 0) {
    throw "CombatCanary runtime-client policy tests failed: $($failed.Name -join ', ')"
}
