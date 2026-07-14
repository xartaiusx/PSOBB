[CmdletBinding()]
param([string]$RuntimeRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$principals = @(Get-PSOBBRuntimeAclPrincipals)
$expectedSids = @($principals | ForEach-Object { $_.Value } | Sort-Object -Unique)
$allowedOwnerSids = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($sid in $expectedSids) {
    [void]$allowedOwnerSids.Add($sid)
}

$failures = [System.Collections.Generic.List[object]]::new()
$targetResults = [System.Collections.Generic.List[object]]::new()
$itemsChecked = 0

foreach ($target in @(Get-PSOBBRuntimeAclTargets -Layout $layout)) {
    $targetFailureCount = 0
    $targetItemCount = 0
    try {
        $safeTarget = Assert-PathWithinRoot -Path $target.Path -Root $layout.Root
        $items = @(Get-PSOBBRuntimeAclTargetItems -Layout $layout -Target $target)
        $targetItemCount = $items.Count
        foreach ($item in $items) {
            $itemsChecked++
            $issues = [System.Collections.Generic.List[string]]::new()
            $safeItem = Assert-PathWithinRoot -Path $item.FullName -Root $layout.Root
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                [void]$issues.Add('item is a reparse point')
            }

            try {
                $acl = Get-Acl -LiteralPath $safeItem
                if (-not $acl.AreAccessRulesProtected) {
                    [void]$issues.Add('DACL inheritance is enabled; expected a protected DACL')
                }
                if (-not $acl.AreAccessRulesCanonical) {
                    [void]$issues.Add('DACL rules are not in canonical order')
                }

                try {
                    $ownerSid = $acl.GetOwner(
                        [System.Security.Principal.SecurityIdentifier]).Value
                    if (-not $allowedOwnerSids.Contains($ownerSid)) {
                        [void]$issues.Add("owner SID $ownerSid is not an approved runtime principal")
                    }
                } catch {
                    [void]$issues.Add("owner SID could not be verified: $($_.Exception.Message)")
                }

                $rules = @($acl.GetAccessRules(
                    $true,
                    $true,
                    [System.Security.Principal.SecurityIdentifier]))
                if ($rules.Count -ne $expectedSids.Count) {
                    [void]$issues.Add(
                        "DACL contains $($rules.Count) rules; expected exactly $($expectedSids.Count)")
                }

                $actualSids = @($rules | ForEach-Object {
                        $_.IdentityReference.Value
                    } | Sort-Object -Unique)
                $comparisonParameters = @{
                    ReferenceObject = $expectedSids
                    DifferenceObject = $actualSids
                }
                foreach ($difference in @(Compare-Object @comparisonParameters)) {
                    if ($difference.SideIndicator -eq '=>') {
                        [void]$issues.Add("unexpected DACL identity SID $($difference.InputObject)")
                    } else {
                        [void]$issues.Add("required DACL identity SID $($difference.InputObject) is missing")
                    }
                }

                $expectedInheritance = if ($item.PSIsContainer) {
                    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
                } else {
                    [System.Security.AccessControl.InheritanceFlags]::None
                }
                foreach ($rule in $rules) {
                    $sid = $rule.IdentityReference.Value
                    if ($rule.IsInherited) {
                        [void]$issues.Add("DACL rule for SID $sid is inherited; expected explicit")
                    }
                    if ($rule.AccessControlType -ne
                        [System.Security.AccessControl.AccessControlType]::Allow) {
                        [void]$issues.Add("DACL rule for SID $sid is not Allow")
                    }
                    if ([int64]$rule.FileSystemRights -ne
                        [int64][System.Security.AccessControl.FileSystemRights]::FullControl) {
                        [void]$issues.Add(
                            "DACL rule for SID $sid grants $($rule.FileSystemRights); expected FullControl")
                    }
                    if ($rule.InheritanceFlags -ne $expectedInheritance) {
                        [void]$issues.Add(
                            "DACL rule for SID $sid has inheritance $($rule.InheritanceFlags); expected $expectedInheritance")
                    }
                    if ($rule.PropagationFlags -ne
                        [System.Security.AccessControl.PropagationFlags]::None) {
                        [void]$issues.Add(
                            "DACL rule for SID $sid has propagation $($rule.PropagationFlags); expected None")
                    }
                }
            } catch {
                [void]$issues.Add("ACL could not be verified: $($_.Exception.Message)")
            }

            if ($issues.Count -gt 0) {
                $targetFailureCount++
                $failures.Add([pscustomobject]@{
                    RecordType = 'Failure'
                    Target = $target.Name
                    Path = $safeItem
                    ItemType = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                    Issues = @($issues)
                })
            }
        }
    } catch {
        $targetFailureCount++
        $failures.Add([pscustomobject]@{
            RecordType = 'Failure'
            Target = $target.Name
            Path = [System.IO.Path]::GetFullPath([string]$target.Path)
            ItemType = 'Target'
            Issues = @("target tree could not be verified: $($_.Exception.Message)")
        })
    }

    $targetResults.Add([pscustomobject]@{
        RecordType = 'TargetSummary'
        Target = $target.Name
        Path = [System.IO.Path]::GetFullPath([string]$target.Path)
        ItemsChecked = $targetItemCount
        Failures = $targetFailureCount
        Passed = ($targetFailureCount -eq 0)
    })
}

$failures
$targetResults
[pscustomobject]@{
    RecordType = 'Summary'
    Suite = 'RuntimeAcl'
    TargetsChecked = $targetResults.Count
    ItemsChecked = $itemsChecked
    Failures = $failures.Count
    Passed = ($failures.Count -eq 0)
}

if ($failures.Count -gt 0) {
    throw "Runtime ACL verification failed for $($failures.Count) protected item or target record(s)"
}
