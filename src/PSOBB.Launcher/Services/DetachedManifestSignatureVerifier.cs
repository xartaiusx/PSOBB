using System.Security.Cryptography;

namespace PSOBB.Launcher.Services;

public sealed class DetachedManifestSignatureVerifier
{
    private const int P256SignatureBytes = 64;
    private const int MaximumSignatureFileBytes = 1024;
    private const string P256ObjectIdentifier = "1.2.840.10045.3.1.7";

    public async Task<byte[]> ReadAndVerifyAsync(
        string manifestPath,
        string detachedSignaturePath,
        string trustedPublicKeyPem,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detachedSignaturePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedPublicKeyPem);

        var manifestBytes = await ReleaseManifestService.ReadManifestBytesAsync(manifestPath, cancellationToken)
            .ConfigureAwait(false);
        var signatureFile = new FileInfo(Path.GetFullPath(detachedSignaturePath));
        if (!signatureFile.Exists)
        {
            throw new FileNotFoundException("The detached manifest signature was not found.", signatureFile.FullName);
        }

        if (signatureFile.Length is <= 0 or > MaximumSignatureFileBytes)
        {
            throw new InvalidDataException($"The detached signature file must be between 1 and {MaximumSignatureFileBytes} bytes.");
        }

        var signatureText = (await File.ReadAllTextAsync(signatureFile.FullName, cancellationToken).ConfigureAwait(false)).Trim();
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(signatureText);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The detached signature must contain a base64-encoded P-256 signature.", exception);
        }

        if (signature.Length != P256SignatureBytes)
        {
            throw new InvalidDataException("The detached signature must be a 64-byte IEEE P1363 P-256 signature.");
        }

        using var verifier = ECDsa.Create();
        try
        {
            verifier.ImportFromPem(trustedPublicKeyPem);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The trusted release key is not a valid ECDSA public-key PEM document.", exception);
        }

        var parameters = verifier.ExportParameters(includePrivateParameters: false);
        if (!string.Equals(parameters.Curve.Oid.Value, P256ObjectIdentifier, StringComparison.Ordinal)
            || parameters.Q.X is not { Length: 32 }
            || parameters.Q.Y is not { Length: 32 })
        {
            throw new InvalidDataException("The trusted release key must use the NIST P-256 curve.");
        }

        if (!verifier.VerifyData(
                manifestBytes,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new CryptographicException("The detached release-manifest signature is invalid.");
        }

        return manifestBytes;
    }
}
