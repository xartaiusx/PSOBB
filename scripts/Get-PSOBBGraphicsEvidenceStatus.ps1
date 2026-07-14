[CmdletBinding()]
param(
    [switch]$RequireAccepted
)

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$profilesPath = Join-Path $repositoryRoot 'config\graphics-profiles.json'
$evidencePath = Join-Path $repositoryRoot 'config\graphics-evidence.json'

& (Join-Path $PSScriptRoot 'Test-PSOBBGraphicsProfiles.ps1') -Quiet | Out-Null
$profiles = Get-Content -Raw -LiteralPath $profilesPath | ConvertFrom-Json -Depth 50
$evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json -Depth 50
$rows = foreach ($profile in @($profiles.profiles)) {
    $candidate = @($evidence.candidates | Where-Object profileId -ceq $profile.id)[0]
    $gateProperties = @($candidate.gates.PSObject.Properties)
    [pscustomobject]@{
        Profile = [string]$profile.id
        Channel = [string]$profile.channel
        Stage = [string]$candidate.stage
        Disposition = [string]$candidate.disposition
        Pass = @($gateProperties | Where-Object { [string]$_.Value.state -ceq 'pass' }).Count
        Pending = @($gateProperties | Where-Object { [string]$_.Value.state -ceq 'pending' }).Count
        Blocked = @($gateProperties | Where-Object { [string]$_.Value.state -ceq 'blocked' }).Count
        Failed = @($gateProperties | Where-Object { [string]$_.Value.state -ceq 'fail' }).Count
        NotApplicable = @($gateProperties | Where-Object {
            [string]$_.Value.state -ceq 'not-applicable'
        }).Count
    }
}

$rows | Format-Table -AutoSize
$accepted = @($rows | Where-Object Disposition -ceq 'accepted')
$blocked = @($rows | Where-Object Disposition -ceq 'blocked')
$summary = [pscustomobject]@{
    Suite = 'GraphicsEvidenceStatus'
    Profiles = $rows.Count
    Accepted = $accepted.Count
    Blocked = $blocked.Count
    Pending = @($rows | Where-Object Disposition -ceq 'pending').Count
}
if ($RequireAccepted -and $accepted.Count -eq 0) {
    throw 'No graphics candidate has a complete accepted evidence record'
}
$summary
