[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$RuntimeRoot,
    [switch]$MigrateLegacyRuntimeMarkerAcl
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if ($MigrateLegacyRuntimeMarkerAcl) {
    try {
        Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
        $protectedMarker = Get-PSOBBRuntimeMarkerMetadataSnapshot -Layout $layout
        return [pscustomobject]@{
            Path = $protectedMarker.Path
            ItemsProtected = 0
            Principals = 'current-user; BUILTIN\Administrators; SYSTEM'
            Changed = $false
            Kind = 'runtime-marker-migration'
        }
    } catch {
        $legacyMarker = Assert-PSOBBLegacyRuntimeMarkerAclState -Layout $layout
    }
    if (-not $PSCmdlet.ShouldProcess(
            $legacyMarker.Path,
            'Replace the exact known legacy runtime-marker DACL')) {
        return [pscustomobject]@{
            Path = $legacyMarker.Path
            ItemsProtected = 0
            Principals = 'current-user; BUILTIN\Administrators; SYSTEM'
            Changed = $false
            Kind = 'runtime-marker-migration-preview'
        }
    }
    $markerMigration = Repair-PSOBBLegacyRuntimeMarkerAcl -Layout $layout
    Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
    return [pscustomobject]@{
        Path = $markerMigration.Path
        ItemsProtected = if ($markerMigration.Changed) { 1 } else { 0 }
        Principals = 'current-user; BUILTIN\Administrators; SYSTEM'
        Changed = [bool]$markerMigration.Changed
        Kind = 'runtime-marker-migration'
    }
}
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$principals = @(Get-PSOBBRuntimeAclPrincipals)
$targets = @(Get-PSOBBRuntimeAclTargets -Layout $layout)

function New-PSOBBRuntimeDacl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$IsContainer,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier[]]$Principals
    )

    # Build only the access-control section this operation owns. Persisting a
    # descriptor read from disk can also attempt to write its audit section,
    # which normal runtime operators are not privileged to change.
    $security = if ($IsContainer) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($principal in $Principals) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    $security
}

function Set-PSOBBRuntimeItemDacl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.FileSystemInfo]$Item,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier[]]$Principals,
        [Parameter(Mandatory)][string]$Root
    )

    # Revalidate immediately before mutation so a path substitution or reparse
    # point cannot redirect the access-control write outside the runtime root.
    $safePath = Assert-PathWithinRoot -Path $Item.FullName -Root $Root
    $currentItem = Get-Item -Force -LiteralPath $safePath
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Sensitive runtime tree contains a reparse point: $safePath"
    }

    $security = New-PSOBBRuntimeDacl `
        -IsContainer $currentItem.PSIsContainer `
        -Principals $Principals
    if ($currentItem.PSIsContainer) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo]$currentItem,
            [System.Security.AccessControl.DirectorySecurity]$security)
    } else {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo]$currentItem,
            [System.Security.AccessControl.FileSecurity]$security)
    }
}

$validatedTargets = foreach ($target in $targets) {
    [pscustomobject]@{
        Name = $target.Name
        Path = Assert-PathWithinRoot -Path $target.Path -Root $layout.Root
        Items = @(Get-PSOBBRuntimeAclTargetItems -Layout $layout -Target $target)
    }
}

$results = foreach ($targetRecord in $validatedTargets) {
    $changed = $PSCmdlet.ShouldProcess(
        $targetRecord.Path,
        "Replace ACLs on $($targetRecord.Items.Count) sensitive runtime items")
    if ($changed) {
        foreach ($item in $targetRecord.Items) {
            Set-PSOBBRuntimeItemDacl `
                -Item $item `
                -Principals $principals `
                -Root $layout.Root
        }
    }

    [pscustomobject]@{
        Path = $targetRecord.Path
        ItemsProtected = if ($changed) { $targetRecord.Items.Count } else { 0 }
        Principals = 'current-user; BUILTIN\Administrators; SYSTEM'
        Changed = $changed
    }
}

$results
