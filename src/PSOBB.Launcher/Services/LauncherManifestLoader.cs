using System.Security.Cryptography;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class LauncherManifestLoader
{
    public const string TrustedPublicKeyFileName = "release-public-key.pem";

    // Local-acceptance trust anchor. Production publication is intentionally
    // gated on replacing this value and signing the launcher executable.
    public const string TrustedPublicKeySpkiSha256 =
        "26dbc6e3756ccb39866fd798767f415dda27e84c92277ea131c571ea5da4d680";

    private readonly ReleaseManifestService _manifestService;
    private readonly string _trustedSpkiSha256;
    private readonly bool _allowUnsignedLocalDevelopment;

    public LauncherManifestLoader(
        ReleaseManifestService manifestService,
        string? trustedSpkiSha256 = null,
        bool allowUnsignedLocalDevelopment = false)
    {
        _manifestService = manifestService;
        _trustedSpkiSha256 = trustedSpkiSha256 ?? TrustedPublicKeySpkiSha256;
        _allowUnsignedLocalDevelopment = allowUnsignedLocalDevelopment;
    }

    public async Task<LoadedReleaseManifest> LoadAsync(
        string manifestPath,
        string launcherDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(launcherDirectory);
        var trustedKeyPath = Path.Combine(Path.GetFullPath(launcherDirectory), TrustedPublicKeyFileName);
        if (!File.Exists(trustedKeyPath))
        {
            if (!_allowUnsignedLocalDevelopment)
            {
                throw new FileNotFoundException(
                    "The pinned release public key is missing; unsigned launch is disabled.",
                    trustedKeyPath);
            }

            var unsignedManifest = await _manifestService.LoadAsync(manifestPath, cancellationToken).ConfigureAwait(false);
            return new(unsignedManifest, ManifestTrustMode.UnsignedLocalDevelopment);
        }

        var trustedPublicKeyPem = await File.ReadAllTextAsync(trustedKeyPath, cancellationToken).ConfigureAwait(false);
        VerifyPinnedKey(trustedPublicKeyPem);
        var signaturePath = manifestPath + ".sig";
        var signedManifest = await _manifestService.LoadSignedAsync(
            manifestPath,
            signaturePath,
            trustedPublicKeyPem,
            cancellationToken).ConfigureAwait(false);
        return new(signedManifest, ManifestTrustMode.VerifiedDetachedSignature);
    }

    private void VerifyPinnedKey(string publicKeyPem)
    {
        using var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(publicKeyPem);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException("The packaged release public key is invalid.", exception);
        }

        var actual = SHA256.HashData(key.ExportSubjectPublicKeyInfo());
        byte[] expected;
        try
        {
            expected = Convert.FromHexString(_trustedSpkiSha256);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("The compiled release trust anchor is invalid.", exception);
        }

        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new InvalidDataException("The packaged release public key does not match the compiled trust anchor.");
        }
    }
}

public enum ManifestTrustMode
{
    UnsignedLocalDevelopment,
    VerifiedDetachedSignature,
}

public sealed record LoadedReleaseManifest(ReleaseManifest Manifest, ManifestTrustMode TrustMode);
