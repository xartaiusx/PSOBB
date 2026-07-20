using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

internal sealed class TestRuntime : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public TestRuntime(string? root = null)
    {
        Root = root ?? Path.Combine(
            Path.GetTempPath(),
            "psobb-launcher-tests",
            Guid.NewGuid().ToString("N"));
        Root = Path.GetFullPath(Root);
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

    public static void SetProtectedFileAcl(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(CurrentUserSid());
        foreach (var sidValue in ProtectedSidValues())
        {
            security.AddAccessRule(new(
                new SecurityIdentifier(sidValue),
                FileSystemRights.FullControl,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        FileSystemAclExtensions.SetAccessControl(new FileInfo(path), security);
    }

    public static void SetProtectedRuntimeFileAcl(
        string containmentRoot,
        string path,
        bool protectProducerBoundary)
    {
        var root = Path.GetFullPath(containmentRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var file = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(file)
            ?? throw new InvalidOperationException("The protected test file has no parent.");
        var relative = Path.GetRelativePath(root, parent);
        if (Path.IsPathRooted(relative)
            || relative.Equals("..", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The protected test file escapes its containment root.");
        }

        var directories = new List<string> { root };
        if (!relative.Equals(".", StringComparison.Ordinal))
        {
            var cursor = root;
            foreach (var segment in relative.Split(
                         [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                cursor = Path.Combine(cursor, segment);
                directories.Add(cursor);
            }
        }
        foreach (var directory in directories)
        {
            if (protectProducerBoundary
                && directory.Equals(parent, StringComparison.OrdinalIgnoreCase))
            {
                SetProtectedDirectoryAcl(directory);
            }
            else
            {
                SetTrustedAncestorDirectoryAcl(directory);
            }
        }
        SetProtectedFileAcl(file);
    }

    public static void SetProtectedDirectoryAcl(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(CurrentUserSid());
        foreach (var sidValue in ProtectedSidValues())
        {
            security.AddAccessRule(new(
                new SecurityIdentifier(sidValue),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), security);
    }

    public static void SetTrustedAncestorDirectoryAcl(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(CurrentUserSid());
        foreach (var sidValue in ProtectedSidValues())
        {
            security.AddAccessRule(new(
                new SecurityIdentifier(sidValue),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        security.AddAccessRule(new(
            new SecurityIdentifier(WellKnownSidType.WorldSid, domainSid: null),
            FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), security);
    }

    public static void EnableFileAclInheritance(string path)
    {
        var file = new FileInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(
            file,
            AccessControlSections.Access);
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
        FileSystemAclExtensions.SetAccessControl(file, security);
    }

    public static void AddPermissiveFileAcl(string path)
    {
        var file = new FileInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(
            file,
            AccessControlSections.Access);
        security.AddAccessRule(new(
            new SecurityIdentifier(WellKnownSidType.WorldSid, domainSid: null),
            FileSystemRights.ReadAndExecute,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(file, security);
    }

    public static void EnableDirectoryAclInheritance(string path)
    {
        var directory = new DirectoryInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access);
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
        FileSystemAclExtensions.SetAccessControl(directory, security);
    }

    public static void AddPermissiveDirectoryAcl(string path)
    {
        var directory = new DirectoryInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access);
        security.AddAccessRule(new(
            new SecurityIdentifier(WellKnownSidType.WorldSid, domainSid: null),
            FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(directory, security);
    }

    public static void AddUntrustedDirectoryWriteAcl(string path)
    {
        var directory = new DirectoryInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(
            directory,
            AccessControlSections.Access);
        security.AddAccessRule(new(
            new SecurityIdentifier(WellKnownSidType.WorldSid, domainSid: null),
            FileSystemRights.Write | FileSystemRights.Delete,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(directory, security);
    }

    private static SecurityIdentifier CurrentUserSid() =>
        WindowsIdentity.GetCurrent().User
        ?? throw new InvalidOperationException("The test user SID is unavailable.");

    private static HashSet<string> ProtectedSidValues() =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            CurrentUserSid().Value,
            "S-1-5-32-544",
            "S-1-5-18",
        };

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

internal sealed class CanonicalRepositoryFixture : IDisposable
{
    private readonly TestRuntime _repository;

    public CanonicalRepositoryFixture()
    {
        _repository = new TestRuntime();
        MaterializeRepository(_repository.Root);
        SourceBuildOrigin = CreateSourceBuildOrigin(_repository.Root);
        PackagedLauncherOrigin = Directory.CreateDirectory(Path.Combine(
            RuntimeRoot,
            "stable",
            "launcher")).FullName;
    }

    public string RepositoryRoot => _repository.Root;

    public string RuntimeRoot => Path.Combine(RepositoryRoot, "PSOBB-Runtime");

    public string SourceBuildOrigin { get; }

    public string PackagedLauncherOrigin { get; }

    public static void MaterializeRepository(string repositoryRoot)
    {
        Directory.CreateDirectory(repositoryRoot);
        File.WriteAllText(Path.Combine(repositoryRoot, "AGENTS.md"), "test repository");
        File.WriteAllText(Path.Combine(repositoryRoot, "PSOBB.slnx"), "<Solution />");
        var projectRoot = Directory.CreateDirectory(Path.Combine(
            repositoryRoot,
            "src",
            "PSOBB.Launcher"));
        File.WriteAllText(
            Path.Combine(projectRoot.FullName, "PSOBB.Launcher.csproj"),
            "<Project />");
        Directory.CreateDirectory(Path.Combine(repositoryRoot, "PSOBB-Runtime"));
        var scriptsRoot = Directory.CreateDirectory(Path.Combine(repositoryRoot, "scripts"));
        foreach (var scriptName in CanonicalLifecycleRepositoryGuard.ScriptInventory)
        {
            File.WriteAllText(Path.Combine(scriptsRoot.FullName, scriptName), string.Empty);
        }
    }

    public static string CreateSourceBuildOrigin(string repositoryRoot) =>
        Directory.CreateDirectory(Path.Combine(
            repositoryRoot,
            "src",
            "PSOBB.Launcher",
            "bin",
            "Debug",
            "net10.0-windows")).FullName;

    public void Dispose() => _repository.Dispose();
}
