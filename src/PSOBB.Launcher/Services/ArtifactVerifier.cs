using System.Security.Cryptography;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class ArtifactVerifier
{
    public async Task<ReleaseVerification> VerifyAsync(
        ReleaseManifest manifest,
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);

        var results = new List<FileVerification>();
        var verifiedBaseFiles = new Dictionary<string, FileVerification>(StringComparer.OrdinalIgnoreCase);

        foreach (var artifact in manifest.Artifacts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await VerifyFileAsync(
                artifact.Id,
                artifact.Destination,
                artifact.Sha256,
                artifact.ByteSize,
                runtimeRoot,
                cancellationToken).ConfigureAwait(false));

            if (artifact.RequiredBase is null)
            {
                continue;
            }

            var baseKey = $"{artifact.RequiredBase.Path}|{artifact.RequiredBase.Sha256}|{artifact.RequiredBase.ByteSize}";
            if (!verifiedBaseFiles.TryGetValue(baseKey, out var baseResult))
            {
                baseResult = await VerifyFileAsync(
                    $"{artifact.Id}:required-base",
                    artifact.RequiredBase.Path,
                    artifact.RequiredBase.Sha256,
                    artifact.RequiredBase.ByteSize,
                    runtimeRoot,
                    cancellationToken).ConfigureAwait(false);
                verifiedBaseFiles.Add(baseKey, baseResult);
                results.Add(baseResult);
            }
        }

        return new ReleaseVerification(results);
    }

    public async Task<FileVerification> VerifyFileAsync(
        string id,
        string relativePath,
        string expectedSha256,
        long? expectedByteSize,
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        string filePath;
        try
        {
            filePath = SafePathResolver.ResolveWithinRoot(runtimeRoot, relativePath);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidDataException or IOException)
        {
            return new(id, relativePath, VerificationStatus.UnsafePath, exception.Message);
        }

        if (!File.Exists(filePath))
        {
            return new(id, relativePath, VerificationStatus.Missing, "File is missing.");
        }

        try
        {
            var file = new FileInfo(filePath);
            if (expectedByteSize.HasValue && file.Length != expectedByteSize.Value)
            {
                return new(
                    id,
                    relativePath,
                    VerificationStatus.SizeMismatch,
                    $"Expected {expectedByteSize.Value} bytes; found {file.Length} bytes.");
            }

            await using var stream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var actualHash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            var expectedHash = Convert.FromHexString(expectedSha256);

            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
            {
                return new(id, relativePath, VerificationStatus.HashMismatch, "SHA-256 did not match the manifest.");
            }

            return new(id, relativePath, VerificationStatus.Verified, "SHA-256 verified.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException)
        {
            return new(id, relativePath, VerificationStatus.Error, exception.Message);
        }
    }
}
