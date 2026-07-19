Set-StrictMode -Version Latest

function Get-PSOBBRuntimeAclPrincipals {
    [CmdletBinding()]
    param()

    @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    )
}

function Get-PSOBBRuntimeAclTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    @(
        [pscustomobject]@{
            Name = 'licenses'
            Path = Join-Path $Layout.Server 'system\licenses'
        },
        [pscustomobject]@{
            Name = 'players'
            Path = Join-Path $Layout.Server 'system\players'
        },
        [pscustomobject]@{
            Name = 'teams'
            Path = Join-Path $Layout.Server 'system\teams'
        },
        [pscustomobject]@{
            Name = 'secrets'
            Path = $Layout.Secrets
        },
        [pscustomobject]@{
            Name = 'backups'
            Path = $Layout.Backups
        },
        [pscustomobject]@{
            Name = 'logs'
            Path = $Layout.Logs
        },
        [pscustomobject]@{
            Name = 'graphics-evidence'
            Path = Join-Path $Layout.Root 'graphics-evidence'
        },
        [pscustomobject]@{
            Name = 'local-asset-archives'
            Path = Join-Path $Layout.Archives 'graphics-lab\local-assets'
        },
        [pscustomobject]@{
            Name = 'local-asset-overlays'
            Path = Join-Path $Layout.LocalLab 'asset-overlays'
        },
        [pscustomobject]@{
            Name = 'local-asset-activations'
            Path = Join-Path $Layout.LocalLab 'asset-activations'
        },
        [pscustomobject]@{
            Name = 'supplemental-asset-activations'
            Path = Join-Path $Layout.LocalLab 'visual-asset-activations'
        }
    )
}

function Get-PSOBBRuntimeAclTargetItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Target
    )

    $safeTarget = Assert-PathWithinRoot -Path ([string]$Target.Path) -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $safeTarget -PathType Container)) {
        throw "Sensitive runtime directory is missing: $safeTarget"
    }

    # Walk one proven directory at a time. Assert-PathWithinRoot checks every
    # existing ancestor for reparse points before the item can be returned or
    # a child directory can be entered.
    $items = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($safeTarget)

    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        $safeDirectory = Assert-PathWithinRoot -Path $directory -Root $Layout.Root
        $directoryItem = Get-Item -LiteralPath $safeDirectory -Force
        if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Sensitive runtime tree contains a reparse point: $($directoryItem.FullName)"
        }
        if ($seen.Add($directoryItem.FullName)) {
            [void]$items.Add($directoryItem)
        }

        foreach ($child in @(Get-ChildItem -LiteralPath $safeDirectory -Force |
                Sort-Object -Property FullName)) {
            $safeChild = Assert-PathWithinRoot -Path $child.FullName -Root $Layout.Root
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Sensitive runtime tree contains a reparse point: $safeChild"
            }
            if ($child.PSIsContainer) {
                $pending.Enqueue($safeChild)
            } elseif ($seen.Add($safeChild)) {
                [void]$items.Add($child)
            }
        }
    }

    $items
}

function Get-PSOBBLifecycleAclPrincipals {
    [CmdletBinding()]
    param()

    @(Get-PSOBBRuntimeAclPrincipals)
}

function New-PSOBBLifecycleDacl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][bool]$IsContainer)

    $security = if ($IsContainer) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $security.SetOwner($currentUser)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($principal in @(Get-PSOBBLifecycleAclPrincipals)) {
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

function Assert-PSOBBLifecyclePathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$IsContainer
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    if (-not (Test-Path -LiteralPath $safePath)) {
        throw "Protected lifecycle path is missing: $safePath"
    }
    $item = Get-Item -LiteralPath $safePath -Force
    if ($item.PSIsContainer -ne $IsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Protected lifecycle path has an invalid filesystem type: $safePath"
    }

    $acl = Get-Acl -LiteralPath $safePath
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -cne $currentUserSid) {
        throw "Protected lifecycle path owner is not the current user: $safePath"
    }
    if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) {
        throw "Protected lifecycle path does not have one canonical protected DACL: $safePath"
    }

    $expectedSids = @(Get-PSOBBLifecycleAclPrincipals |
        ForEach-Object { $_.Value } | Sort-Object -Unique)
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expectedSids.Count) {
        throw "Protected lifecycle path DACL does not contain exactly $($expectedSids.Count) rules: $safePath"
    }
    $actualSids = @($rules | ForEach-Object {
            $_.IdentityReference.Value
        } | Sort-Object -Unique)
    if ($actualSids.Count -ne $expectedSids.Count -or
        @(Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids).Count -ne 0) {
        throw "Protected lifecycle path DACL identities are not exact: $safePath"
    }

    $expectedInheritance = if ($IsContainer) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($rule in $rules) {
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne
                [System.Security.AccessControl.AccessControlType]::Allow -or
            [int64]$rule.FileSystemRights -ne
                [int64][System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne
                [System.Security.AccessControl.PropagationFlags]::None) {
            throw "Protected lifecycle path DACL rule is not exact: $safePath"
        }
    }
    $safePath
}

function Set-PSOBBLifecyclePathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $item = Get-Item -LiteralPath $safePath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to protect a lifecycle reparse point: $safePath"
    }
    $security = New-PSOBBLifecycleDacl -IsContainer $item.PSIsContainer
    if ($item.PSIsContainer) {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.DirectoryInfo]$item,
            [System.Security.AccessControl.DirectorySecurity]$security)
    } else {
        [System.IO.FileSystemAclExtensions]::SetAccessControl(
            [System.IO.FileInfo]$item,
            [System.Security.AccessControl.FileSecurity]$security)
    }
    Assert-PSOBBLifecyclePathAcl `
        -Path $safePath -Root $Root -IsContainer $item.PSIsContainer
}

function Initialize-PSOBBLifecycleControlDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    $property = $Layout.PSObject.Properties['ControlDirectory']
    if ($null -eq $property -or
        [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw 'The runtime layout does not declare a lifecycle control directory'
    }
    $controlDirectory = Assert-PathWithinRoot `
        -Path ([string]$property.Value) -Root $Layout.Root
    if (Test-Path -LiteralPath $controlDirectory) {
        return Assert-PSOBBLifecyclePathAcl `
            -Path $controlDirectory -Root $Layout.Root -IsContainer $true
    }

    $parent = Split-Path -Parent $controlDirectory
    $safeParent = Assert-PathWithinRoot -Path $parent -Root $Layout.Root
    if (-not (Test-Path -LiteralPath $safeParent -PathType Container)) {
        throw "Lifecycle control directory parent is missing: $safeParent"
    }
    $temporary = Assert-PathWithinRoot `
        -Path (Join-Path $safeParent (
            '.newserv-control.' + [Guid]::NewGuid().ToString('N') + '.new')) `
        -Root $Layout.Root
    [void][System.IO.Directory]::CreateDirectory($temporary)
    try {
        Set-PSOBBLifecyclePathAcl -Path $temporary -Root $Layout.Root | Out-Null
        [System.IO.Directory]::Move($temporary, $controlDirectory)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Container) {
            try { [System.IO.Directory]::Delete($temporary, $false) } catch { }
        }
    }
    Assert-PSOBBLifecyclePathAcl `
        -Path $controlDirectory -Root $Layout.Root -IsContainer $true
}

function Get-PSOBBRetiredLifecyclePaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    @(
        'newserv.process.json',
        'newserv.pid',
        'newserv-host.pid',
        'newserv-control.json',
        'newserv-control.request.json'
    ) | ForEach-Object {
        Assert-PathWithinRoot `
            -Path (Join-Path $Layout.Stable $_) -Root $Layout.Root
    }
}

function Remove-PSOBBRetiredLifecycleFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Layout)

    foreach ($path in @(Get-PSOBBRetiredLifecyclePaths -Layout $Layout)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            if ($item.PSIsContainer -or
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Retired lifecycle path has an unsafe filesystem type: $path"
            }
            $safePath = Assert-PathWithinRoot -Path $path -Root $Layout.Root
            Remove-Item -LiteralPath $safePath -Force -ErrorAction Stop
        }
    }
}
