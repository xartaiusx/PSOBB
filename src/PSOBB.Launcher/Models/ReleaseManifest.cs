using System.Text.Json.Serialization;

namespace PSOBB.Launcher.Models;

[JsonConverter(typeof(JsonStringEnumConverter<ReleaseChannel>))]
public enum ReleaseChannel
{
    Stable,
    Canary,
    LocalLab,
}

[JsonConverter(typeof(JsonStringEnumConverter<ArtifactSourceKind>))]
public enum ArtifactSourceKind
{
    Remote,
    LocalImport,
}

[JsonConverter(typeof(JsonStringEnumConverter<RollbackStrategy>))]
public enum RollbackStrategy
{
    Snapshot,
    ReimportBase,
    NativeProfile,
}

public sealed class ReleaseManifest
{
    public int SchemaVersion { get; init; }

    public string ReleaseId { get; init; } = string.Empty;

    public ReleaseChannel Channel { get; init; }

    public int ProtocolRevision { get; init; }

    public List<ReleaseArtifact> Artifacts { get; init; } = [];

    public LaunchSettings Launch { get; init; } = new();
}

public sealed class ReleaseArtifact
{
    public string Id { get; init; } = string.Empty;

    public string? SourceUrl { get; init; }

    public ArtifactSourceKind SourceKind { get; init; }

    public ReleaseChannel Channel { get; init; }

    public int ProtocolRevision { get; init; }

    public string Destination { get; init; } = string.Empty;

    public string Sha256 { get; init; } = string.Empty;

    public long ByteSize { get; init; }

    public string License { get; init; } = string.Empty;

    public string Redistribution { get; init; } = string.Empty;

    public ArtifactRollback Rollback { get; init; } = new();

    public RequiredBaseFile? RequiredBase { get; init; }
}

public sealed class RequiredBaseFile
{
    public string Path { get; init; } = string.Empty;

    public string Sha256 { get; init; } = string.Empty;

    public long ByteSize { get; init; }
}

public sealed class ArtifactRollback
{
    public string Target { get; init; } = string.Empty;

    public RollbackStrategy Strategy { get; init; }
}

public sealed class LaunchSettings
{
    public string ServerExecutable { get; init; } = string.Empty;

    public string ClientExecutable { get; init; } = string.Empty;

    public List<string> ServerArguments { get; init; } = [];

    public List<string> ClientArguments { get; init; } = [];

    public List<int> HealthPorts { get; init; } = [];
}
