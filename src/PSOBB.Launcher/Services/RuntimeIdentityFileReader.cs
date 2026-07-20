using System.Security.Cryptography;
using System.Text.Json;

namespace PSOBB.Launcher.Services;

internal sealed partial class ExactRuntimeIdentityProbe
{
    private const long MaximumIdentityJsonBytes = 4 * 1024 * 1024;
    private const long MaximumIdentityFileBytes = 512 * 1024 * 1024;

    private async Task RequireFileIdentityAsync(
        string path,
        string containmentRoot,
        ApprovedFileIdentity expected,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        var file = await ReadFileAndTrackAsync(
            path,
            containmentRoot,
            MaximumIdentityFileBytes,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        if (file.Identity.Size != expected.Size
            || !file.Identity.Sha256.Equals(expected.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("An executable no longer matches its tracked size and SHA-256.");
        }
    }

    private async Task RequireFileHashAsync(
        string path,
        string containmentRoot,
        string expectedSha256,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        var file = await ReadFileAndTrackAsync(
            path,
            containmentRoot,
            MaximumIdentityFileBytes,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        if (!file.Identity.Sha256.Equals(expectedSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"A sealed file hash changed: {Path.GetFileName(path)}.");
        }
    }

    private async Task<JsonFileContent> ReadJsonFileAsync(
        string path,
        string containmentRoot,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken,
        bool allowTrailingCommas = false,
        ProtectedRuntimeAclScope? protectedAclScope = null)
    {
        var content = await ReadFileAndTrackAsync(
            path,
            containmentRoot,
            MaximumIdentityJsonBytes,
            sealedFiles,
            cancellationToken,
            protectedAclScope).ConfigureAwait(false);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(
                content.Bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = allowTrailingCommas,
                    CommentHandling = JsonCommentHandling.Disallow,
                });
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Identity JSON is malformed: {Path.GetFileName(path)}.", exception);
        }
        try
        {
            ValidateNoDuplicateProperties(document.RootElement);
            return new(document, content.Identity);
        }
        catch
        {
            document.Dispose();
            throw;
        }
    }

    private async Task<FileContent> ReadFileAndTrackAsync(
        string path,
        string containmentRoot,
        long maximumBytes,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken,
        ProtectedRuntimeAclScope? protectedAclScope = null)
    {
        var content = await ReadFileContentAsync(
            path,
            containmentRoot,
            maximumBytes,
            protectedAclScope,
            cancellationToken).ConfigureAwait(false);
        if (sealedFiles.TryGetValue(content.Identity.Path, out var prior)
            && (prior.Size != content.Identity.Size
                || !prior.Sha256.Equals(content.Identity.Sha256, StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                $"An identity file changed between reads: {Path.GetFileName(path)}.");
        }
        sealedFiles[content.Identity.Path] = content.Identity;
        return content;
    }

    private static async Task RequireSealedFilesUnchangedAsync(
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        foreach (var sealedFile in sealedFiles.Values.ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await ReadFileContentAsync(
                sealedFile.Path,
                sealedFile.ContainmentRoot,
                sealedFile.MaximumBytes,
                sealedFile.ProtectedAclScope,
                cancellationToken).ConfigureAwait(false);
            if (current.Identity.Size != sealedFile.Size
                || !current.Identity.Sha256.Equals(sealedFile.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"An authenticated identity file changed during observation: {Path.GetFileName(sealedFile.Path)}.");
            }
        }
    }

    private static async Task<FileContent> ReadFileContentAsync(
        string path,
        string containmentRoot,
        long maximumBytes,
        ProtectedRuntimeAclScope? protectedAclScope,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var safePath = EnsureSafePath(containmentRoot, path, mustExist: true);
        if (protectedAclScope is { } initialAclScope)
        {
            ProtectedRuntimeFileAcl.Require(safePath, containmentRoot, initialAclScope);
        }
        await using var stream = new FileStream(
            safePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length is <= 0 || stream.Length > maximumBytes || stream.Length > int.MaxValue)
        {
            throw new InvalidDataException("An identity file is empty or oversized.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException("An identity file changed length while it was read.");
        }
        if (protectedAclScope is { } finalAclScope)
        {
            ProtectedRuntimeFileAcl.Require(safePath, containmentRoot, finalAclScope);
        }
        var identity = new SealedFileIdentity(
            safePath,
            Path.GetFullPath(containmentRoot),
            maximumBytes,
            protectedAclScope,
            bytes.LongLength,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
        return new(bytes, identity);
    }

    private static string EnsureSafePath(string containmentRoot, string path, bool mustExist)
    {
        var root = Path.GetFullPath(containmentRoot).TrimEnd(Path.DirectorySeparatorChar);
        var candidate = Path.GetFullPath(path);
        var relative = Path.GetRelativePath(root, candidate);
        if (Path.IsPathRooted(relative)
            || relative.Equals("..", StringComparison.Ordinal)
            || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new InvalidDataException("An identity path escapes its canonical root.");
        }
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException("A canonical identity root is missing.");
        }

        CheckExistingPath(root);
        if (!relative.Equals(".", StringComparison.Ordinal))
        {
            var cursor = root;
            foreach (var segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            {
                cursor = Path.Combine(cursor, segment);
                if (!TryCheckExistingPath(cursor))
                {
                    break;
                }
            }
        }
        if (mustExist && !TryCheckExistingPath(candidate))
        {
            throw new FileNotFoundException("A required identity path is missing.", candidate);
        }
        return candidate;
    }

    private static bool TryCheckExistingPath(string path)
    {
        try
        {
            CheckExistingPath(path);
            return true;
        }
        catch (Exception exception) when (exception is FileNotFoundException
            or DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void CheckExistingPath(string path)
    {
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException("A canonical identity path contains a reparse-point ancestor.");
        }
    }
}
