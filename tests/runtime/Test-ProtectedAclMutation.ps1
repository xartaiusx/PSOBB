[CmdletBinding()]
param([string]$RuntimeRoot)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\Set-PSOBBAdminCredential.ps1')

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$fixture = Assert-PathWithinRoot -Path (Join-Path $layout.Backups (
    'acl-acceptance-' + [Guid]::NewGuid().ToString('N'))) -Root $layout.Backups

try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $file = Join-Path $fixture 'fixture.txt'
    New-Item -ItemType File -Path $file | Out-Null

    Set-PSOBBProtectedAcl -Path $fixture
    Set-PSOBBProtectedAcl -Path $file
    # A second application proves the DACL writer is idempotent.
    Set-PSOBBProtectedAcl -Path $fixture
    Set-PSOBBProtectedAcl -Path $file

    if (-not (Test-PSOBBProtectedAcl -Path $fixture) -or
        -not (Test-PSOBBProtectedAcl -Path $file)) {
        throw 'The DACL-only writer did not produce the required protected ACL'
    }

    [pscustomobject]@{
        Suite = 'ProtectedAclMutation'
        Passed = 2
        Failed = 0
        Operator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
} finally {
    if (Test-Path -LiteralPath $fixture) {
        $safeFixture = Assert-PathWithinRoot -Path $fixture -Root $layout.Backups
        if (-not ([System.IO.Path]::GetFileName($safeFixture)).StartsWith(
            'acl-acceptance-', [System.StringComparison]::Ordinal)) {
            throw 'Refusing to remove an unexpected ACL acceptance path'
        }
        Remove-Item -LiteralPath $safeFixture -Recurse -Force
    }
}
