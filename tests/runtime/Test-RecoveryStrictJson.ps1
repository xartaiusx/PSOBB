[CmdletBinding()]
param()

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repositoryRoot 'scripts\PSOBB.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Name, [bool]$Passed, [string]$Detail) {
    $results.Add([pscustomobject]@{
            Name = $Name
            Passed = $Passed
            Detail = $Detail
        })
}

function Write-Utf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText(
        $Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Test-RejectedLicenseFixture(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Root,
    [AllowEmptyString()][string]$Text,
    [byte[]]$Bytes
) {
    if ($null -ne $Bytes) {
        [System.IO.File]::WriteAllBytes($Path, $Bytes)
    } else {
        Write-Utf8 -Path $Path -Text $Text
    }
    $lengthBefore = (Get-Item -LiteralPath $Path).Length
    $sha256Before = Get-LowerSha256 $Path
    $sddlBefore = (Get-Acl -LiteralPath $Path).Sddl
    $names = [System.Collections.Generic.Dictionary[string, int]]::new(
        [System.StringComparer]::Ordinal)
    $names.Add('existingfixture', 2)
    $passwords = [System.Collections.Generic.List[string]]::new()
    $passwords.Add('EXISTINGSYNTHETIC')
    try {
        Add-PSOBBRecoveryBBLicenseRedactionTerms `
            -Path $Path -Root $Root -UserNameCounts $names `
            -Passwords $passwords -Label 'synthetic licenses item' | Out-Null
        $false
    } catch {
        $_.Exception.Message -ceq (
            'The synthetic licenses item cannot be inspected for recovery redaction') -and
            $names.Count -eq 1 -and $names['existingfixture'] -eq 2 -and
            $passwords.Count -eq 1 -and
            $passwords[0] -ceq 'EXISTINGSYNTHETIC' -and
            $_.Exception.Message -notmatch 'DO-NOT-LEAK' -and
            (Get-Item -LiteralPath $Path).Length -eq $lengthBefore -and
            (Get-LowerSha256 $Path) -ceq $sha256Before -and
            (Get-Acl -LiteralPath $Path).Sddl -ceq $sddlBefore
    }
}

function Test-Rejected(
    [Parameter(Mandatory)][scriptblock]$Action,
    [string]$Pattern = '(duplicate|exact property|type|fractional|out-of-range|invalid|strict)'
) {
    try {
        & $Action | Out-Null
        $false
    } catch {
        $_.Exception.Message -match $Pattern
    }
}

function New-InstallationRecord([string]$InstallationId, [string]$RuntimeRoot) {
    $hash = [string]::new([char]'0', 64)
    [ordered]@{
        schemaVersion = 2
        installationId = $InstallationId
        initializedAtUtc = '2026-07-19T00:00:00.0000000+00:00'
        runtimeRoot = $RuntimeRoot
        serverVersion = 'fixture'
        serverArchiveSha256 = $hash
        serverExecutableSha256 = $hash
        serverBaseManifestSha256 = $hash
        clientVersion = 'fixture'
        clientArchiveSha256 = $hash
        baseClientExecutableSha256 = $hash
        baseClientManifestSha256 = $hash
        clientExecutableSha256 = $hash
        rendererVersion = 'fixture'
        rendererArchiveSha256 = $hash
        rendererWrapperSha256 = $hash
        rendererConfigurationSha256 = $hash
        patchManifestSha256 = $hash
        synchronizedPatchFiles = 0
        clientPatchProfile = 'baseline'
        clientPatchPolicySha256 = Get-LowerSha256 (
            Join-Path $repositoryRoot 'config\client-patch-profiles.json')
        networkScope = 'loopback-only'
    }
}

function New-RecoveryManifest([string]$InstallationId) {
    $hash = [string]::new([char]'0', 64)
    [ordered]@{
        schemaVersion = 3
        backupId = [Guid]::NewGuid().ToString('D')
        backupKind = 'state'
        createdAtUtc = '2026-07-19T00:00:00.0000000+00:00'
        serverExecutable = [ordered]@{
            path = 'newserv-windows.exe'
            sourceLockComponent = 'newserv-stable-release'
            size = 1
            sha256 = $hash
        }
        clientPatchState = [ordered]@{
            profile = 'baseline'
            policySha256 = $hash
            configPath = 'system/config.json'
            configSha256 = $hash
            installationPath = 'stable/installation.json'
            installationSha256 = $hash
            installationId = $InstallationId
        }
        stateRoots = @(
            [ordered]@{ path = 'system/config.json'; kind = 'file' }
            [ordered]@{ path = 'system/licenses'; kind = 'directory' }
            [ordered]@{ path = 'system/players'; kind = 'directory' }
            [ordered]@{ path = 'system/teams'; kind = 'directory' }
            [ordered]@{ path = 'stable/installation.json'; kind = 'file' }
        )
        files = @(
            [ordered]@{
                path = 'system/config.json'
                size = 1
                sha256 = $hash
            }
        )
    }
}

$repoFixtureRoot = Join-Path $repositoryRoot (
    '.recovery-strict-json-test-' + [Guid]::NewGuid().ToString('N'))
$runtimeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'PSOBB-RecoveryTests-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $repoFixtureRoot | Out-Null
    $layout = Get-PSOBBLayout -RuntimeRoot $runtimeRoot
    New-Item -ItemType Directory -Path $layout.Stable -Force | Out-Null
    $marker = Initialize-PSOBBRuntimeMarker -Layout $layout

    $policySource = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'config\client-patch-profiles.json')
    $policyPath = Join-Path $repoFixtureRoot 'policy.json'
    Write-Utf8 -Path $policyPath -Text $policySource
    $policySnapshot = Read-PSOBBClientPatchPolicySnapshot -Path $policyPath
    Add-Result 'strict policy accepts the exact tracked shape' (
        $policySnapshot.Value.defaultProfile -ceq 'baseline' -and
        $policySnapshot.Sha256 -ceq (Get-LowerSha256 $policyPath)) `
        'parsed-byte digest equals the locked file digest'

    $policyCases = [ordered]@{
        'decoded duplicate root' = $policySource.Replace(
            '"schemaVersion": 1,',
            '"schemaVersion": 1,"\u0073chemaVersion":1,')
        'decoded duplicate nested profile' = $policySource.Replace(
            '"channel": "stable",',
            '"channel": "stable","ch\u0061nnel":"stable",')
        'extra nested property' = $policySource.Replace(
            '"description": "Unmodified',
            '"unexpected":true,"description": "Unmodified')
        'missing root property' = [regex]::Replace(
            $policySource, '(?m)^\s*"defaultProfile"[^\r\n]*\r?\n', '', 1)
        'wrong root type' = $policySource.Replace(
            '"schemaVersion": 1', '"schemaVersion": "1"')
        'fractional root number' = $policySource.Replace(
            '"schemaVersion": 1', '"schemaVersion": 1.5')
        'overflow root number' = $policySource.Replace(
            '"schemaVersion": 1', '"schemaVersion": 9223372036854775808')
    }
    foreach ($case in $policyCases.GetEnumerator()) {
        Write-Utf8 -Path $policyPath -Text ([string]$case.Value)
        Add-Result "strict policy rejects $($case.Key)" (
            Test-Rejected {
                Read-PSOBBClientPatchPolicySnapshot -Path $policyPath
            }) 'no coercion, duplicate collapse, or schema widening'
    }

    $recordPath = Join-Path $layout.Stable 'installation.json'
    $recordText = (New-InstallationRecord `
            -InstallationId $marker.installationId `
            -RuntimeRoot $layout.Root) | ConvertTo-Json -Depth 5
    Write-Utf8 -Path $recordPath -Text $recordText
    $recordSnapshot = Read-PSOBBInstallationRecordSnapshot `
        -Path $recordPath -Root $layout.Root `
        -ExpectedInstallationId $marker.installationId `
        -ExpectedRuntimeRoot $layout.Root
    Add-Result 'strict installation accepts exactly 22 typed fields' (
        @($recordSnapshot.Value.PSObject.Properties).Count -eq 22) `
        'schema-2 producer and consumer shapes are identical'
    $recordCases = [ordered]@{
        'decoded duplicate property' = $recordText.Replace(
            '"networkScope": "loopback-only"',
            '"networkScope":"loopback-only","network\u0053cope":"loopback-only"')
        'extra property' = $recordText.Replace(
            '"networkScope": "loopback-only"',
            '"networkScope":"loopback-only","unexpected":true')
        'missing property' = $recordText.Replace(
            '  "serverVersion": "fixture",' + [Environment]::NewLine, '')
        'wrong integer type' = $recordText.Replace(
            '"synchronizedPatchFiles": 0', '"synchronizedPatchFiles": "0"')
        'fractional integer' = $recordText.Replace(
            '"synchronizedPatchFiles": 0', '"synchronizedPatchFiles": 0.5')
        'overflow integer' = $recordText.Replace(
            '"synchronizedPatchFiles": 0',
            '"synchronizedPatchFiles": 9223372036854775808')
    }
    foreach ($case in $recordCases.GetEnumerator()) {
        Write-Utf8 -Path $recordPath -Text ([string]$case.Value)
        Add-Result "strict installation rejects $($case.Key)" (
            Test-Rejected {
                Read-PSOBBInstallationRecordSnapshot `
                    -Path $recordPath -Root $layout.Root
            }) 'exact properties and Int64 types are mandatory'
    }

    $manifestRoot = Join-Path $runtimeRoot 'manifest-fixture'
    New-Item -ItemType Directory -Path $manifestRoot | Out-Null
    $manifestPath = Join-Path $manifestRoot 'manifest.json'
    $manifestText = (New-RecoveryManifest `
            -InstallationId $marker.installationId) | ConvertTo-Json -Depth 8
    Write-Utf8 -Path $manifestPath -Text $manifestText
    $manifestSnapshot = Read-PSOBBRecoveryManifestSnapshot `
        -Path $manifestPath -Root $manifestRoot
    Add-Result 'strict recovery manifest accepts every exact nesting level' (
        $manifestSnapshot.Value.files.Count -eq 1) `
        'root, server, client-patch, state-root, and file entries are typed'
    $manifestCases = [ordered]@{
        'decoded duplicate nested file property' = $manifestText.Replace(
            '"path": "system/config.json"',
            '"path":"system/config.json","p\u0061th":"system/config.json"')
        'extra server property' = $manifestText.Replace(
            '"sourceLockComponent": "newserv-stable-release",',
            '"sourceLockComponent":"newserv-stable-release","unexpected":true,')
        'missing client-patch property' = $manifestText.Replace(
            '    "configPath": "system/config.json",' + [Environment]::NewLine, '')
        'wrong nested size type' = $manifestText.Replace(
            '"size": 1', '"size": "1"')
        'fractional nested size' = $manifestText.Replace(
            '"size": 1', '"size": 1.25')
        'overflow nested size' = $manifestText.Replace(
            '"size": 1', '"size": 9223372036854775808')
    }
    foreach ($case in $manifestCases.GetEnumerator()) {
        Write-Utf8 -Path $manifestPath -Text ([string]$case.Value)
        Add-Result "strict recovery manifest rejects $($case.Key)" (
            Test-Rejected {
                Read-PSOBBRecoveryManifestSnapshot `
                    -Path $manifestPath -Root $manifestRoot
            }) 'all nested properties and numeric types are exact'
    }

    $markerText = Get-Content -Raw -LiteralPath $layout.RuntimeMarker
    $markerCases = [ordered]@{
        'decoded duplicate' = $markerText.Replace(
            '"runtimeRoot":', '"runt\u0069meRoot":"wrong","runtimeRoot":')
        'extra property' = $markerText.Replace(
            '"createdAtUtc":', '"unexpected":true,"createdAtUtc":')
        'wrong schema type' = $markerText.Replace(
            '"schemaVersion": 1', '"schemaVersion": "1"')
    }
    foreach ($case in $markerCases.GetEnumerator()) {
        Write-Utf8 -Path $layout.RuntimeMarker -Text ([string]$case.Value)
        Add-Result "strict runtime marker rejects $($case.Key)" (
            Test-Rejected {
                Assert-PSOBBRuntimeMarker -Layout $layout
            }) 'runtime ownership never accepts collapsed or widened JSON'
    }
    Write-Utf8 -Path $layout.RuntimeMarker -Text $markerText
    $inheritedAcl = Get-Acl -LiteralPath $layout.RuntimeMarker
    $inheritedAcl.SetAccessRuleProtection($false, $true)
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $layout.RuntimeMarker),
        [System.Security.AccessControl.FileSecurity]$inheritedAcl)
    Add-Result 'strict runtime marker rejects inherited ACLs' (
        Test-Rejected {
            Assert-PSOBBRuntimeMarker -Layout $layout
        } 'ACL') 'installation identity requires an exact protected descriptor'
    Set-PSOBBProtectedAcl -Path $layout.RuntimeMarker

    $permissiveMarkerAcl = [System.Security.AccessControl.FileSecurity]::new()
    $permissiveMarkerAcl.SetAccessRuleProtection($true, $false)
    $permissiveMarkerAcl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow))
    $permissiveMarkerAcl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
            [System.Security.AccessControl.FileSystemRights]::ReadData,
            [System.Security.AccessControl.AccessControlType]::Allow))
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.FileInfo](Get-Item -Force -LiteralPath $layout.RuntimeMarker),
        $permissiveMarkerAcl)
    Add-Result 'strict runtime marker rejects permissive ACLs' (
        Test-Rejected {
            Assert-PSOBBRuntimeMarker -Layout $layout
        } 'ACL') 'additional principals cannot influence installation identity'
    Set-PSOBBProtectedAcl -Path $layout.RuntimeMarker
    Add-Result 'strict runtime marker accepts restored protected ACL' (
        (Assert-PSOBBRuntimeMarker -Layout $layout).installationId -ceq
            $marker.installationId) 'pre-read and post-read ACL checks remain coherent'

    $sourceLockPath = Join-Path $repoFixtureRoot 'sources.lock.json'
    $sourceLockText = Get-Content -Raw -LiteralPath (
        Join-Path $repositoryRoot 'config\sources.lock.json')
    Write-Utf8 -Path $sourceLockPath -Text $sourceLockText
    $sourceIdentity = Get-PSOBBStableServerSourceLockIdentity `
        -Path $sourceLockPath
    Add-Result 'strict source lock binds the final parsed bytes' (
        $sourceIdentity.SourceLockSha256 -ceq
            (Get-LowerSha256 $sourceLockPath)) `
        'final frozen source-lock bytes and Stable member are consumed together'
    $sourceCases = [ordered]@{
        'decoded duplicate root' = $sourceLockText.Replace(
            '"schemaVersion": 1,',
            '"schemaVersion":1,"schema\u0056ersion":1,')
        'extra consumed component property' = $sourceLockText.Replace(
            '"id": "newserv-stable-release",',
            '"id":"newserv-stable-release","unexpected":true,')
        'extra consumed member property' = $sourceLockText.Replace(
            '"path": "release/newserv-windows.exe",',
            '"path":"release/newserv-windows.exe","unexpected":true,')
        'wrong consumed member size type' = $sourceLockText.Replace(
            '"size": 31162999,', '"size": "31162999",')
    }
    foreach ($case in $sourceCases.GetEnumerator()) {
        Write-Utf8 -Path $sourceLockPath -Text ([string]$case.Value)
        Add-Result "strict source lock rejects $($case.Key)" (
            Test-Rejected {
                Get-PSOBBStableServerSourceLockIdentity -Path $sourceLockPath
            }) 'root and consumed Stable component/member shapes are exact'
    }

    $licenseRoot = Join-Path $runtimeRoot 'license-reader'
    New-Item -ItemType Directory -Path $licenseRoot | Out-Null
    $licensePath = Join-Path $licenseRoot 'DO-NOT-LEAK-LICENSE-PATH.json'
    $newservLicenseText = @'
{
  "BBTeamID": 0x0,
  "FormatVersion": 0x1,
  "AccountID": 0x1,
  "LastPlayerName": "literal 0xABC",
  "DCNTELicenses": [],
  "BBLicenses": [
    {"UserName": "fixtureacct", "Password": "SYNTH\u0053ECRET"},
    {"UserName": "abcdefghijklmnop", "Password": "123456789012345\u0041"}
  ],
  "BanEndTime": 0x0,
  "PCLicenses": [],
  "AutoReplyMessage": "",
  "GCLicenses": [],
  "AutoPatchesEnabled": [],
  "XBLicenses": [],
  "Flags": 0x7FFFFFFF,
  "Ep3TotalMesetaEarned": 0x0,
  "Ep3CurrentMeseta": 0x0,
  "DCLicenses": [],
  "UserFlags": 0x0
}
'@
    Write-Utf8 -Path $licensePath -Text $newservLicenseText
    $licenseLengthBefore = (Get-Item -LiteralPath $licensePath).Length
    $licenseHashBefore = Get-LowerSha256 $licensePath
    $licenseAclBefore = (Get-Acl -LiteralPath $licensePath).Sddl
    $licenseNames = [System.Collections.Generic.Dictionary[string, int]]::new(
        [System.StringComparer]::Ordinal)
    $licensePasswords = [System.Collections.Generic.List[string]]::new()
    $licenseCount = Add-PSOBBRecoveryBBLicenseRedactionTerms `
        -Path $licensePath -Root $licenseRoot `
        -UserNameCounts $licenseNames -Passwords $licensePasswords `
        -Label 'synthetic licenses item'
    Add-Result 'license redaction accepts exact current newserv hex JSON' (
        $licenseCount -eq 2 -and $licenseNames.Count -eq 2 -and
        $licenseNames['fixtureacct'] -eq 1 -and
        $licenseNames['abcdefghijklmnop'] -eq 1 -and
        $licensePasswords.Count -eq 2 -and
        $licensePasswords[0] -ceq 'SYNTHSECRET' -and
        $licensePasswords[1] -ceq '123456789012345A') `
        'current BBLicenses decode through the exact 16-byte inclusive boundary'
    Add-Result 'license redaction leaves source bytes and ACL unchanged' (
        (Get-Item -LiteralPath $licensePath).Length -eq $licenseLengthBefore -and
        (Get-LowerSha256 $licensePath) -ceq $licenseHashBefore -and
        (Get-Acl -LiteralPath $licensePath).Sddl -ceq $licenseAclBefore) `
        'the reader is bounded and read-only'

    $genericReaderStillStrict = Test-Rejected {
        Read-PSOBBRedactedRecoveryStrictJsonSnapshot `
            -Path $licensePath -Root $licenseRoot -MaximumBytes 1MB `
            -Label 'synthetic generic item'
    } '^The synthetic generic item failed strict JSON validation$'
    Add-Result 'generic recovery JSON reader still rejects hex integers' `
        $genericReaderStillStrict `
        'the newserv lexical extension is confined to BB license redaction'

    $boundaryText = ConvertTo-PSOBBNewservLicenseStrictJsonText `
        -Text '{"maximum":0x7FFFFFFFFFFFFFFF,"minimum":-0x8000000000000000}' `
        -Label 'synthetic boundary item'
    $boundaryValue = $boundaryText | ConvertFrom-Json
    Add-Result 'license hex normalizer accepts exact Int64 boundaries' (
        $boundaryValue.maximum -eq [long]::MaxValue -and
        $boundaryValue.minimum -eq [long]::MinValue) `
        'validated phosg integer values survive strict normalization'

    $licenseFailureCases = [ordered]@{
        'duplicate BBLicenses key' =
            '{"FormatVersion":0x1,"BBLicenses":[],"BBLicenses":[]}'
        'decoded duplicate BBLicenses key' =
            '{"FormatVersion":0x1,"BBLicenses":[],"\u0042BLicenses":[]}'
        'escaped FormatVersion key alias' =
            '{"Format\u0056ersion":0x1,"BBLicenses":[]}'
        'escaped BBLicenses key alias' =
            '{"FormatVersion":0x1,"BB\u004Cicenses":[]}'
        'escaped username key alias' =
            '{"FormatVersion":0x1,"BBLicenses":[{"User\u004Eame":"fixtureacct","Password":"SYNTHPASS"}]}'
        'escaped password key alias' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Pass\u0077ord":"SYNTHPASS"}]}'
        'duplicate username field' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"DO-NOT-LEAK-USER","UserName":"x","Password":"DO-NOT-LEAK-PASSWORD"}]}'
        'missing BBLicenses key' = '{"FormatVersion":0x1}'
        'non-array BBLicenses value' =
            '{"FormatVersion":0x1,"BBLicenses":{}}'
        'non-object BBLicenses entry' =
            '{"FormatVersion":0x1,"BBLicenses":["x"]}'
        'missing password field' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct"}]}'
        'extra BBLicenses field' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTHPASS","Extra":0}]}'
        'non-string username' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":1,"Password":"SYNTHPASS"}]}'
        'non-string password' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":true}]}'
        'empty username' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"","Password":"SYNTHPASS"}]}'
        'overlength username' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"abcdefghijklmnopq","Password":"SYNTHPASS"}]}'
        'empty password' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":""}]}'
        'overlength password' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"abcdefghijklmnopq"}]}'
        'partial valid list' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"firstfixture","Password":"FIRSTSYNTH"},{"UserName":"secondfixture","Password":false}]}'
        'line comment' =
            '{"FormatVersion":0x1,"BBLicenses":[] // comment' + "`n" + '}'
        'block comment' =
            '{"FormatVersion":0x1,"BBLicenses":[]/* comment */}'
        'trailing comma' =
            '{"FormatVersion":0x1,"BBLicenses":[],}'
        'trailing content' =
            '{"FormatVersion":0x1,"BBLicenses":[]}{}'
        'non-object root' = '[]'
        'single-quoted JSON' =
            "{'FormatVersion':0x1,'BBLicenses':[]}"
        'unquoted property' =
            '{FormatVersion:0x1,BBLicenses:[]}'
        'missing FormatVersion' = '{"BBLicenses":[]}'
        'legacy fields without FormatVersion' =
            '{"BBUsername":"legacy","BBPassword":"SYNTHPASS"}'
        'zero legacy FormatVersion' =
            '{"FormatVersion":0x0,"BBUsername":"legacy","BBPassword":"SYNTHPASS"}'
        'zero hybrid FormatVersion' =
            '{"FormatVersion":0x0,"BBLicenses":[]}'
        'current hybrid credential fields' =
            '{"FormatVersion":0x1,"BBLicenses":[],"BBUsername":"legacy","BBPassword":"SYNTHPASS"}'
        'decimal current FormatVersion' =
            '{"FormatVersion":1,"BBLicenses":[]}'
        'string current FormatVersion' =
            '{"FormatVersion":"0x1","BBLicenses":[]}'
        'negative current FormatVersion' =
            '{"FormatVersion":-0x1,"BBLicenses":[]}'
        'uppercase hex prefix' =
            '{"FormatVersion":0X1,"BBLicenses":[]}'
        'lowercase hex digit' =
            '{"FormatVersion":0xabc,"BBLicenses":[]}'
        'missing hex digits' =
            '{"FormatVersion":0x,"BBLicenses":[]}'
        'positive hex overflow' =
            '{"FormatVersion":0x8000000000000000,"BBLicenses":[]}'
        'negative hex overflow' =
            '{"FormatVersion":-0x8000000000000001,"BBLicenses":[]}'
        'overlength hex token' =
            '{"FormatVersion":0x00000000000000000,"BBLicenses":[]}'
        'non-ASCII byte escape' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTH\u0080"}]}'
        'escaped control byte' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTH\nPASS"}]}'
        'escaped DEL byte' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTH\u007F"}]}'
        'non-byte Unicode escape' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTH\u0100"}]}'
        'surrogate escape' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTH\uD800"}]}'
        'raw non-ASCII credential' =
            '{"FormatVersion":0x1,"BBLicenses":[{"UserName":"fixtureacct","Password":"SYNTHé"}]}'
    }
    foreach ($case in $licenseFailureCases.GetEnumerator()) {
        Add-Result "license redaction rejects $($case.Key)" (
            Test-RejectedLicenseFixture `
                -Path $licensePath -Root $licenseRoot -Text ([string]$case.Value)) `
            'strict shape, syntax, bounds, transactional outputs, and redacted errors'
    }

    $invalidUtf8Prefix = [System.Text.Encoding]::UTF8.GetBytes(
        '{"BBLicenses":[{"UserName":"fixtureacct","Password":"')
    $invalidUtf8Suffix = [System.Text.Encoding]::UTF8.GetBytes('"}]}')
    $invalidUtf8 = [byte[]]::new(
        $invalidUtf8Prefix.Length + 2 + $invalidUtf8Suffix.Length)
    [Array]::Copy($invalidUtf8Prefix, 0, $invalidUtf8, 0, $invalidUtf8Prefix.Length)
    $invalidUtf8[$invalidUtf8Prefix.Length] = 0xC3
    $invalidUtf8[$invalidUtf8Prefix.Length + 1] = 0x28
    [Array]::Copy(
        $invalidUtf8Suffix, 0, $invalidUtf8,
        $invalidUtf8Prefix.Length + 2, $invalidUtf8Suffix.Length)
    try {
        Add-Result 'license redaction rejects malformed UTF-8' (
            Test-RejectedLicenseFixture `
                -Path $licensePath -Root $licenseRoot -Bytes $invalidUtf8) `
            'the public error does not expose the path or malformed credential bytes'
    } finally {
        [Array]::Clear($invalidUtf8Prefix, 0, $invalidUtf8Prefix.Length)
        [Array]::Clear($invalidUtf8Suffix, 0, $invalidUtf8Suffix.Length)
        [Array]::Clear($invalidUtf8, 0, $invalidUtf8.Length)
    }

    $sentinelPath = Join-Path $runtimeRoot `
        'DO-NOT-LEAK-ACCOUNT-FILENAME.json'
    Write-Utf8 -Path $sentinelPath -Text '{invalid'
    $sentinelSafe = $false
    try {
        Read-PSOBBStrictJsonSnapshot `
            -Path $sentinelPath -Root $runtimeRoot -MaximumBytes 1KB `
            -Label 'redacted recovery item' | Out-Null
    } catch {
        $sentinelSafe = $_.Exception.Message -notmatch
            'DO-NOT-LEAK-ACCOUNT-FILENAME'
    }
    Add-Result 'strict reader errors redact the source filename' $sentinelSafe `
        'only the caller-provided category label is emitted'

    $racePath = Join-Path $runtimeRoot 'same-handle.json'
    $replacementPath = Join-Path $runtimeRoot 'same-handle.next'
    Write-Utf8 -Path $racePath -Text '{"generation":1}'
    Write-Utf8 -Path $replacementPath -Text '{"generation":2}'
    $held = [System.IO.FileStream]::new(
        $racePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $replacementBlocked = Test-Rejected {
            [System.IO.File]::Move($replacementPath, $racePath, $true)
        } '(used by another process|access|being used)'
    } finally {
        $held.Dispose()
    }
    $raceSnapshot = Read-PSOBBStrictJsonSnapshot `
        -Path $racePath -Root $runtimeRoot -MaximumBytes 1KB `
        -Label 'same-handle fixture'
    Add-Result 'same-handle JSON read blocks path replacement and hashes parsed bytes' (
        $replacementBlocked -and
        $raceSnapshot.Sha256 -ceq (Get-LowerSha256 $racePath) -and
        $raceSnapshot.Value.generation -eq 1) `
        'FileShare.Read denies write/delete replacement while parse and hash share one handle'
} finally {
    if (Test-Path -LiteralPath $repoFixtureRoot) {
        Remove-PSOBBValidatedRecoveryTree `
            -Path $repoFixtureRoot -Root $repositoryRoot `
            -Label 'strict JSON repository fixture'
    }
    if (Test-Path -LiteralPath $runtimeRoot) {
        Remove-PSOBBValidatedRecoveryTree `
            -Path $runtimeRoot -Root ([System.IO.Path]::GetTempPath()) `
            -Label 'strict JSON runtime fixture'
    }
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) recovery strict-JSON test(s) failed"
}
[pscustomobject]@{
    Suite = 'RecoveryStrictJson'
    Passed = $results.Count
    Failed = 0
}
