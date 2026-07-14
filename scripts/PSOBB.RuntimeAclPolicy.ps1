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
