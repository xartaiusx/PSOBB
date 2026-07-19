[CmdletBinding()]
param([string]$RuntimeRoot)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1')

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$fixture = Assert-PathWithinRoot -Path (Join-Path $layout.Backups (
    'acl-acceptance-' + [Guid]::NewGuid().ToString('N'))) -Root $layout.Backups
$junctionTarget = Assert-PathWithinRoot -Path (Join-Path $layout.Backups (
    'acl-junction-target-' + [Guid]::NewGuid().ToString('N'))) -Root $layout.Backups
$junction = Join-Path $fixture 'unsafe-junction'

try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $file = Join-Path $fixture 'fixture.txt'
    New-Item -ItemType File -Path $file | Out-Null
    $nested = Join-Path $fixture 'nested'
    New-Item -ItemType Directory -Path $nested | Out-Null
    $nestedFile = Join-Path $nested 'nested.txt'
    New-Item -ItemType File -Path $nestedFile | Out-Null

    Set-PSOBBProtectedTreeAcl -Path $fixture -Root $layout.Backups
    # A second application proves the tree writer is idempotent.
    Set-PSOBBProtectedTreeAcl -Path $fixture -Root $layout.Backups

    if (-not (Test-PSOBBProtectedAcl -Path $fixture) -or
        -not (Test-PSOBBProtectedAcl -Path $file) -or
        -not (Test-PSOBBProtectedAcl -Path $nested) -or
        -not (Test-PSOBBProtectedAcl -Path $nestedFile)) {
        throw 'The tree DACL writer did not produce the required protected ACL'
    }

    New-Item -ItemType Directory -Path $junctionTarget | Out-Null
    Set-PSOBBProtectedAcl -Path $junctionTarget
    $targetAclBefore = (Get-Acl -LiteralPath $junctionTarget).
        GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access)
    New-Item -ItemType Junction -Path $junction -Target $junctionTarget | Out-Null
    $junctionRejected = $false
    try {
        Set-PSOBBProtectedTreeAcl -Path $fixture -Root $layout.Backups
    } catch {
        $junctionRejected = $_.Exception.Message -match 'reparse point'
    }
    $targetAclAfter = (Get-Acl -LiteralPath $junctionTarget).
        GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::Access)
    if (-not $junctionRejected -or $targetAclAfter -cne $targetAclBefore) {
        throw 'The tree DACL writer did not fail closed on a nested junction'
    }

    [pscustomobject]@{
        Suite = 'ProtectedAclMutation'
        Passed = 5
        Failed = 0
        Operator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
} finally {
    if (Test-Path -LiteralPath $junction) {
        Remove-Item -LiteralPath $junction -Force
    }
    if (Test-Path -LiteralPath $fixture) {
        $safeFixture = Assert-PathWithinRoot -Path $fixture -Root $layout.Backups
        if (-not ([System.IO.Path]::GetFileName($safeFixture)).StartsWith(
            'acl-acceptance-', [System.StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected ACL acceptance path'
        }
        Remove-Item -LiteralPath $safeFixture -Recurse -Force
    }
    if (Test-Path -LiteralPath $junctionTarget) {
        $safeTarget = Assert-PathWithinRoot -Path $junctionTarget -Root $layout.Backups
        if (-not ([System.IO.Path]::GetFileName($safeTarget)).StartsWith(
            'acl-junction-target-', [System.StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected ACL junction target'
        }
        Remove-Item -LiteralPath $safeTarget -Recurse -Force
    }
}
