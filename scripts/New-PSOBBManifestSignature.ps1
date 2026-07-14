[CmdletBinding()]
param(
    [string]$ManifestPath,
    [string]$PrivateKeyPath,
    [string]$PublicKeyPath,
    [switch]$CreateLocalAcceptanceKey,
    [string]$RuntimeRoot
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $layout.Stable 'release-manifest.json'
}
if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
    $PrivateKeyPath = Join-Path $layout.Secrets 'local-acceptance-signing-private.pem'
}
if ([string]::IsNullOrWhiteSpace($PublicKeyPath)) {
    $PublicKeyPath = Join-Path (Split-Path -Parent $ManifestPath) 'release-public-key.pem'
}

$ManifestPath = [System.IO.Path]::GetFullPath($ManifestPath)
$PrivateKeyPath = [System.IO.Path]::GetFullPath($PrivateKeyPath)
$PublicKeyPath = [System.IO.Path]::GetFullPath($PublicKeyPath)
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Manifest does not exist: $ManifestPath"
}

$ecdsa = $null
try {
    if (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf) {
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportFromPem([System.IO.File]::ReadAllText($PrivateKeyPath))
    } elseif ($CreateLocalAcceptanceKey) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PrivateKeyPath) | Out-Null
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create(
            [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        [System.IO.File]::WriteAllText(
            $PrivateKeyPath,
            $ecdsa.ExportPkcs8PrivateKeyPem(),
            [System.Text.UTF8Encoding]::new($false))

        $keyAcl = Get-Acl -LiteralPath $PrivateKeyPath
        $keyAcl.SetAccessRuleProtection($true, $false)
        foreach ($existingRule in @($keyAcl.Access)) {
            [void]$keyAcl.RemoveAccessRuleSpecific($existingRule)
        }
        foreach ($sid in @(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow)
            [void]$keyAcl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $PrivateKeyPath -AclObject $keyAcl
    } else {
        throw 'No signing private key exists; use an offline key path or explicitly create a local acceptance key'
    }

    $parameters = $ecdsa.ExportParameters($false)
    if (($parameters.Curve.Oid.FriendlyName -notmatch 'nistP256|ECDSA_P256') -and
        ($parameters.Curve.Oid.Value -ne '1.2.840.10045.3.1.7')) {
        throw 'Manifest signing requires an ECDSA P-256 private key'
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PublicKeyPath) | Out-Null
    $publicPem = $ecdsa.ExportSubjectPublicKeyInfoPem()
    [System.IO.File]::WriteAllText($PublicKeyPath, $publicPem, [System.Text.UTF8Encoding]::new($false))
    $manifestBytes = [System.IO.File]::ReadAllBytes($ManifestPath)
    $signature = $ecdsa.SignData(
        $manifestBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    if ($signature.Length -ne 64) {
        throw "Unexpected P-256 signature length: $($signature.Length)"
    }
    $signaturePath = $ManifestPath + '.sig'
    [System.IO.File]::WriteAllText(
        $signaturePath,
        [Convert]::ToBase64String($signature),
        [System.Text.Encoding]::ASCII)

    $verifier = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $verifier.ImportFromPem($publicPem)
        if (-not $verifier.VerifyData(
            $manifestBytes,
            $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
            throw 'Detached signature self-verification failed'
        }
    } finally {
        $verifier.Dispose()
    }

    $publicDer = $ecdsa.ExportSubjectPublicKeyInfo()
    $fingerprint = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($publicDer)).ToLowerInvariant()
    [pscustomobject]@{
        ManifestPath = $ManifestPath
        SignaturePath = $signaturePath
        PublicKeyPath = $PublicKeyPath
        PublicKeySha256 = $fingerprint
        Algorithm = 'ECDSA-P256-SHA256-P1363'
        LocalAcceptanceKey = $CreateLocalAcceptanceKey.IsPresent
        Verified = $true
    }
} finally {
    if ($ecdsa) {
        $ecdsa.Dispose()
    }
}
