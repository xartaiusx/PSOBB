using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed partial class ReleaseManifestService
{
    public const int SupportedSchemaVersion = 1;
    internal const int MaximumManifestBytes = 4 * 1024 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        AllowTrailingCommas = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter<ReleaseChannel>(JsonNamingPolicy.CamelCase, allowIntegerValues: false) },
    };

    public async Task<ReleaseManifest> LoadAsync(string manifestPath, CancellationToken cancellationToken = default)
    {
        var manifestBytes = await ReadManifestBytesAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        return DeserializeAndValidate(manifestBytes);
    }

    public async Task<ReleaseManifest> LoadSignedAsync(
        string manifestPath,
        string detachedSignaturePath,
        string trustedPublicKeyPem,
        CancellationToken cancellationToken = default)
    {
        var verifier = new DetachedManifestSignatureVerifier();
        var verifiedManifestBytes = await verifier.ReadAndVerifyAsync(
            manifestPath,
            detachedSignaturePath,
            trustedPublicKeyPem,
            cancellationToken).ConfigureAwait(false);
        return DeserializeAndValidate(verifiedManifestBytes);
    }

    public void Validate(ReleaseManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var errors = new List<string>();

        if (manifest.SchemaVersion != SupportedSchemaVersion)
        {
            errors.Add($"schemaVersion must be {SupportedSchemaVersion}.");
        }

        if (!Identifier().IsMatch(manifest.ReleaseId ?? string.Empty))
        {
            errors.Add("releaseId must contain 1-64 ASCII letters, numbers, periods, underscores, or hyphens.");
        }

        if (manifest.ProtocolRevision <= 0)
        {
            errors.Add("protocolRevision must be a positive integer.");
        }

        if (manifest.Artifacts is not { Count: >= 1 and <= 256 } artifacts)
        {
            errors.Add("artifacts must contain between 1 and 256 entries.");
        }
        else
        {
            var artifactIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var artifact in artifacts)
            {
                ValidateArtifact(
                    artifact,
                    manifest.Channel,
                    manifest.ProtocolRevision,
                    artifactIds,
                    destinations,
                    errors);
            }

            ValidateLaunchSettings(manifest.Launch, destinations, errors);
        }

        if (errors.Count > 0)
        {
            throw new ManifestValidationException(errors);
        }
    }

    internal static async Task<byte[]> ReadManifestBytesAsync(
        string manifestPath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        var file = new FileInfo(Path.GetFullPath(manifestPath));
        if (!file.Exists)
        {
            throw new FileNotFoundException("The release manifest was not found.", file.FullName);
        }

        if (file.Length is <= 0 or > MaximumManifestBytes)
        {
            throw new InvalidDataException($"The release manifest must be between 1 and {MaximumManifestBytes} bytes.");
        }

        await using var stream = new FileStream(
            file.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var bytes = new byte[file.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    private ReleaseManifest DeserializeAndValidate(byte[] manifestBytes)
    {
        ReleaseManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<ReleaseManifest>(manifestBytes, SerializerOptions)
                ?? throw new InvalidDataException("The release manifest contained JSON null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The release manifest is not valid schema-v1 JSON.", exception);
        }

        Validate(manifest);
        return manifest;
    }

    private static void ValidateArtifact(
        ReleaseArtifact? artifact,
        ReleaseChannel expectedChannel,
        int expectedProtocolRevision,
        HashSet<string> artifactIds,
        HashSet<string> destinations,
        List<string> errors)
    {
        if (artifact is null)
        {
            errors.Add("Artifact entries may not be null.");
            return;
        }

        var artifactId = artifact.Id ?? string.Empty;
        if (!Identifier().IsMatch(artifactId))
        {
            errors.Add("Every artifact id must contain 1-64 ASCII letters, numbers, periods, underscores, or hyphens.");
        }
        else if (!artifactIds.Add(artifactId))
        {
            errors.Add($"Artifact id '{artifactId}' is duplicated.");
        }

        if (artifact.SourceKind == ArtifactSourceKind.Remote
            && (string.IsNullOrWhiteSpace(artifact.SourceUrl)
                || !Uri.TryCreate(artifact.SourceUrl, UriKind.Absolute, out var uri)
                || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || !string.IsNullOrEmpty(uri.UserInfo)))
        {
            errors.Add($"Artifact '{artifact.Id}' sourceUrl must use absolute HTTPS without embedded credentials for a remote source.");
        }
        else if (artifact.SourceKind == ArtifactSourceKind.LocalImport
                 && !string.IsNullOrWhiteSpace(artifact.SourceUrl))
        {
            errors.Add($"Artifact '{artifact.Id}' local-import source must not contain a download URL.");
        }

        if (artifact.Channel != expectedChannel)
        {
            errors.Add($"Artifact '{artifact.Id}' channel must match the release channel.");
        }

        if (artifact.ProtocolRevision != expectedProtocolRevision)
        {
            errors.Add($"Artifact '{artifact.Id}' protocolRevision must match the release protocolRevision.");
        }

        if (!TryValidateRelativePath(artifact.Destination, out var destinationError))
        {
            errors.Add($"Artifact '{artifact.Id}' destination is unsafe: {destinationError}");
        }
        else if (!destinations.Add(NormalizeRelativePath(artifact.Destination)))
        {
            errors.Add($"Artifact destination '{artifact.Destination}' is duplicated.");
        }

        if (!Sha256().IsMatch(artifact.Sha256 ?? string.Empty))
        {
            errors.Add($"Artifact '{artifact.Id}' sha256 must be 64 hexadecimal characters.");
        }

        if (artifact.ByteSize <= 0)
        {
            errors.Add($"Artifact '{artifact.Id}' byteSize must be positive.");
        }

        if (string.IsNullOrWhiteSpace(artifact.License)
            || artifact.License.Length > 128
            || artifact.License.Any(char.IsControl))
        {
            errors.Add($"Artifact '{artifact.Id}' license must contain 1-128 characters.");
        }

        if (string.IsNullOrWhiteSpace(artifact.Redistribution)
            || artifact.Redistribution.Length > 256
            || artifact.Redistribution.Any(char.IsControl))
        {
            errors.Add($"Artifact '{artifact.Id}' redistribution must contain 1-256 characters.");
        }

        if (artifact.Rollback is null
            || string.IsNullOrWhiteSpace(artifact.Rollback.Target)
            || artifact.Rollback.Target.Length > 128
            || artifact.Rollback.Target.Any(char.IsControl))
        {
            errors.Add($"Artifact '{artifact.Id}' rollback target must contain 1-128 characters.");
        }

        if (artifact.RequiredBase is not null)
        {
            if (!TryValidateRelativePath(artifact.RequiredBase.Path, out var basePathError))
            {
                errors.Add($"Artifact '{artifact.Id}' requiredBase path is unsafe: {basePathError}");
            }

            if (!Sha256().IsMatch(artifact.RequiredBase.Sha256 ?? string.Empty))
            {
                errors.Add($"Artifact '{artifact.Id}' requiredBase sha256 must be 64 hexadecimal characters.");
            }


            if (artifact.RequiredBase.ByteSize <= 0)
            {
                errors.Add($"Artifact '{artifact.Id}' requiredBase byteSize must be positive.");
            }
        }
    }

    private static void ValidateLaunchSettings(
        LaunchSettings? settings,
        HashSet<string> artifactDestinations,
        List<string> errors)
    {
        if (settings is null)
        {
            errors.Add("launch is required.");
            return;
        }

        ValidateExecutable("serverExecutable", settings.ServerExecutable, artifactDestinations, errors);
        ValidateExecutable("clientExecutable", settings.ClientExecutable, artifactDestinations, errors);
        ValidateArguments("serverArguments", settings.ServerArguments, errors);
        ValidateArguments("clientArguments", settings.ClientArguments, errors);

        if (settings.HealthPorts is not { Count: >= 1 and <= 16 } healthPorts)
        {
            errors.Add("launch.healthPorts must contain between 1 and 16 ports.");
        }
        else if (healthPorts.Any(port => port is < 1 or > 65535))
        {
            errors.Add("launch.healthPorts contains a port outside 1-65535.");
        }
        else if (healthPorts.Distinct().Count() != healthPorts.Count)
        {
            errors.Add("launch.healthPorts may not contain duplicates.");
        }
    }

    private static void ValidateExecutable(
        string propertyName,
        string relativePath,
        HashSet<string> artifactDestinations,
        List<string> errors)
    {
        if (!TryValidateRelativePath(relativePath, out var pathError))
        {
            errors.Add($"launch.{propertyName} is unsafe: {pathError}");
            return;
        }

        if (!string.Equals(Path.GetExtension(relativePath), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add($"launch.{propertyName} must identify an .exe file.");
        }

        if (!artifactDestinations.Contains(NormalizeRelativePath(relativePath)))
        {
            errors.Add($"launch.{propertyName} must match an artifact destination.");
        }
    }

    private static void ValidateArguments(string propertyName, List<string>? arguments, List<string> errors)
    {
        if (arguments is null)
        {
            errors.Add($"launch.{propertyName} is required.");
            return;
        }

        if (arguments.Count > 32)
        {
            errors.Add($"launch.{propertyName} may contain at most 32 arguments.");
            return;
        }

        foreach (var argument in arguments)
        {
            if (string.IsNullOrWhiteSpace(argument) || argument.Length > 1024 || argument.Any(char.IsControl))
            {
                errors.Add($"launch.{propertyName} contains an empty, oversized, or control-character argument.");
                continue;
            }

            if (SensitiveArgument().IsMatch(argument))
            {
                errors.Add($"launch.{propertyName} may not contain credentials or secrets.");
            }
        }
    }

    private static bool TryValidateRelativePath(string path, out string error)
    {
        try
        {
            SafePathResolver.ValidateRelativePath(path);
            error = string.Empty;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidDataException)
        {
            error = exception.Message;
            return false;
        }
    }

    private static string NormalizeRelativePath(string path) => path.Replace('/', '\\');

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex Identifier();

    [GeneratedRegex("^[A-Fa-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();

    [GeneratedRegex("(?i)(password|passwd|token|secret|credential)", RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveArgument();
}

public sealed class ManifestValidationException(IReadOnlyList<string> errors)
    : InvalidOperationException("The release manifest failed validation: " + string.Join(" ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
