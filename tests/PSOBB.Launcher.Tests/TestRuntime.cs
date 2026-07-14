using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Tests;

internal sealed class TestRuntime : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public TestRuntime()
    {
        Root = Path.Combine(Path.GetTempPath(), "psobb-launcher-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string CreateFile(string relativePath, byte[] content)
    {
        var path = Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return path;
    }

    public string WriteManifest(ReleaseManifest manifest)
    {
        var path = Path.Combine(Root, "release-manifest.json");
        File.WriteAllText(path, JsonSerializer.Serialize(manifest, JsonOptions));
        return path;
    }

    public static string Hash(byte[] content) => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

    public static ReleaseManifest CreateManifest(byte[] server, byte[] client, RequiredBaseFile? requiredBase = null) => new()
    {
        SchemaVersion = 1,
        ReleaseId = "test-stable-1",
        Channel = ReleaseChannel.Stable,
        ProtocolRevision = 1,
        Artifacts =
        [
            new ReleaseArtifact
            {
                Id = "server",
                SourceKind = ArtifactSourceKind.Remote,
                SourceUrl = "https://example.invalid/newserv.exe",
                Channel = ReleaseChannel.Stable,
                ProtocolRevision = 1,
                Destination = "server/newserv.exe",
                Sha256 = Hash(server),
                ByteSize = server.Length,
                License = "MIT",
                Redistribution = "MIT redistribution allowed",
                Rollback = new ArtifactRollback { Target = "last-known-good/server", Strategy = RollbackStrategy.Snapshot },
            },
            new ReleaseArtifact
            {
                Id = "client",
                SourceKind = ArtifactSourceKind.LocalImport,
                Channel = ReleaseChannel.Stable,
                ProtocolRevision = 1,
                Destination = "client/psobb.exe",
                Sha256 = Hash(client),
                ByteSize = client.Length,
                License = "User-imported proprietary client",
                Redistribution = "Local import only",
                Rollback = new ArtifactRollback { Target = "immutable/client-base", Strategy = RollbackStrategy.ReimportBase },
                RequiredBase = requiredBase,
            },
        ],
        Launch = new LaunchSettings
        {
            ServerExecutable = "server/newserv.exe",
            ClientExecutable = "client/psobb.exe",
            ServerArguments = ["--config", "config.json"],
            ClientArguments = [],
            HealthPorts = [11000, 12000, 12001],
        },
    };

    public void Dispose()
    {
        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
