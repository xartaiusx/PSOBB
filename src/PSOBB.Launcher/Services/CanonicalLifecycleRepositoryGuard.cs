using System.Security.Cryptography;

namespace PSOBB.Launcher.Services;

internal sealed record CanonicalLifecycleScriptIdentity(
    string Path,
    long Size,
    string Sha256);

internal sealed record CanonicalLifecycleLayout(
    string RepositoryRoot,
    string RuntimeRoot,
    string ScriptsRoot,
    IReadOnlyDictionary<string, CanonicalLifecycleScriptIdentity> ScriptIdentities)
{
    public IReadOnlyDictionary<string, string> ScriptPaths { get; } =
        ScriptIdentities.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.Path,
            StringComparer.Ordinal);

    public bool HasSameScriptInventory(CanonicalLifecycleLayout other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (ScriptIdentities.Count != other.ScriptIdentities.Count)
        {
            return false;
        }

        foreach (var (name, expected) in ScriptIdentities)
        {
            if (!other.ScriptIdentities.TryGetValue(name, out var current)
                || !expected.Path.Equals(current.Path, StringComparison.OrdinalIgnoreCase)
                || expected.Size != current.Size
                || !expected.Sha256.Equals(current.Sha256, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }
}

internal sealed class CanonicalLifecycleInstallationResolver
{
    private static readonly string[] RequiredRepositoryMarkers =
    [
        "AGENTS.md",
        "PSOBB.slnx",
        Path.Combine("src", "PSOBB.Launcher", "PSOBB.Launcher.csproj"),
    ];

    public CanonicalLifecycleLayout Resolve() => ResolveFromOrigin(AppContext.BaseDirectory);

    internal CanonicalLifecycleLayout ResolveFromOrigin(string installationOrigin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installationOrigin);
        var originDirectory = NormalizeExistingOriginDirectory(installationOrigin);
        var candidates = new List<CanonicalLifecycleLayout>();

        for (var current = new DirectoryInfo(originDirectory);
             current is not null;
             current = current.Parent)
        {
            RequireOrdinaryDirectory(current.FullName, "launcher installation origin");
            if (!HasExactRepositoryMarkers(current.FullName))
            {
                continue;
            }

            var guard = new CanonicalLifecycleRepositoryGuard(current.FullName);
            candidates.Add(guard.Validate(Path.Combine(current.FullName, "PSOBB-Runtime")));
        }

        if (candidates.Count == 0)
        {
            throw new InvalidOperationException(
                "The launcher installation is not below a complete canonical PSOBB repository.");
        }

        if (candidates.Count != 1)
        {
            throw new InvalidOperationException(
                "The launcher installation has multiple canonical PSOBB repository ancestors.");
        }

        var layout = candidates[0];
        if (!IsWithin(originDirectory, layout.RuntimeRoot)
            && !IsRepositoryBuildOutput(originDirectory, layout.RepositoryRoot))
        {
            throw new InvalidOperationException(
                "The launcher must run from its canonical runtime package or source build directory.");
        }

        return layout;
    }

    private static bool IsRepositoryBuildOutput(string path, string repositoryRoot)
    {
        if (!IsWithin(path, repositoryRoot))
        {
            return false;
        }

        var parts = Path.GetRelativePath(repositoryRoot, path)
            .Split(
                [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2
            && (parts[0].Equals("src", StringComparison.OrdinalIgnoreCase)
                || parts[0].Equals("tests", StringComparison.OrdinalIgnoreCase))
            && parts.Skip(1).Any(part => part.Equals("bin", StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasExactRepositoryMarkers(string repositoryRoot)
    {
        var markerPaths = RequiredRepositoryMarkers
            .Select(relativePath => Path.Combine(repositoryRoot, relativePath))
            .ToArray();
        if (!markerPaths.All(File.Exists))
        {
            return false;
        }

        foreach (var markerPath in markerPaths)
        {
            RequireOrdinaryFile(markerPath, "canonical repository marker");
        }

        return true;
    }

    private static string NormalizeExistingOriginDirectory(string origin)
    {
        var normalized = Path.GetFullPath(origin);
        if (File.Exists(normalized))
        {
            RequireOrdinaryFile(normalized, "launcher installation origin");
            return Path.GetDirectoryName(normalized)
                ?? throw new InvalidOperationException("The launcher installation file has no parent directory.");
        }

        if (!Directory.Exists(normalized))
        {
            throw new DirectoryNotFoundException(
                $"The launcher installation origin does not exist: {normalized}");
        }

        return NormalizeDirectory(normalized);
    }

    private static bool IsWithin(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        return !Path.IsPathRooted(relative)
            && !relative.Equals("..", StringComparison.Ordinal)
            && !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            && !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static void RequireOrdinaryDirectory(string path, string label)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"The required {label} is missing: {path}");
        }

        RequireNoReparsePoint(path, label);
    }

    private static void RequireOrdinaryFile(string path, string label)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"The required {label} is missing.", path);
        }

        RequireNoReparsePoint(path, label);
        for (var current = new FileInfo(path).Directory;
             current is not null;
             current = current.Parent)
        {
            RequireNoReparsePoint(current.FullName, label);
        }
    }

    private static void RequireNoReparsePoint(string path, string label)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"The {label} has a reparse-point path component and cannot be trusted.");
        }
    }
}

internal sealed class CanonicalLifecycleRepositoryGuard
{
    private static readonly string[] EntryScriptNames =
    [
        "Reset-PSOBBClientRuntime.ps1",
        "New-PSOBBGraphicsLabRuntime.ps1",
        "Set-PSOBBAshenbubsHDClientActivation.ps1",
        "Start-PSOBB.ps1",
        "Start-PSOBBClient.ps1",
        "Start-PSOBBSession.ps1",
        "Stop-PSOBB.ps1",
        "Stop-PSOBBClient.ps1",
        "Stop-PSOBBSession.ps1",
        "Test-PSOBBClientGraphics.ps1",
        "Test-PSOBBCombatCanary.ps1",
    ];
    private static readonly string[] RequiredScriptNames =
    [
        "Backup-PSOBB.ps1",
        "Get-PSOBBCharacterSummary.ps1",
        "Invoke-NewservSupervisor.ps1",
        "New-PSOBBGraphicsLabRuntime.ps1",
        "PSOBB.CombatCanary.Common.ps1",
        "PSOBB.Common.ps1",
        "PSOBB.RuntimeAclPolicy.ps1",
        "Reset-PSOBBClientRuntime.ps1",
        "Set-PSOBBAdminCredential.ps1",
        "Set-PSOBBAshenbubsHDClientActivation.ps1",
        "Set-PSOBBAshenbubsHDOverlay.ps1",
        "Start-PSOBB.ps1",
        "Start-PSOBBClient.ps1",
        "Start-PSOBBSession.ps1",
        "Stop-PSOBB.ps1",
        "Stop-PSOBBClient.ps1",
        "Stop-PSOBBSession.ps1",
        "Test-PSOBB.ps1",
        "Test-PSOBBCharacterBuild.ps1",
        "Test-PSOBBClientGraphics.ps1",
        "Test-PSOBBCombatCanary.ps1",
        "Test-PSOBBTwillsBank.ps1",
    ];

    private readonly string? _expectedRepositoryRoot;

    public CanonicalLifecycleRepositoryGuard(string? expectedRepositoryRoot = null)
    {
        _expectedRepositoryRoot = string.IsNullOrWhiteSpace(expectedRepositoryRoot)
            ? null
            : NormalizeDirectory(expectedRepositoryRoot);
    }

    public string? ExpectedRepositoryRoot => _expectedRepositoryRoot;

    public CanonicalLifecycleLayout Validate(string runtimeRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var normalizedRuntimeRoot = NormalizeDirectory(runtimeRoot);
        if (!Path.GetFileName(normalizedRuntimeRoot).Equals(
                "PSOBB-Runtime",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The lifecycle runtime must be the canonical nested PSOBB-Runtime directory.");
        }

        var repositoryRoot = Directory.GetParent(normalizedRuntimeRoot)?.FullName
            ?? throw new InvalidDataException("The canonical runtime has no repository parent.");
        repositoryRoot = NormalizeDirectory(repositoryRoot);
        if (_expectedRepositoryRoot is not null
            && !repositoryRoot.Equals(_expectedRepositoryRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The requested runtime does not belong to the launcher's exact repository root.");
        }

        var scriptsRoot = Path.GetFullPath(Path.Combine(repositoryRoot, "scripts"));
        RequireContained(repositoryRoot, normalizedRuntimeRoot, "runtime root");
        RequireContained(repositoryRoot, scriptsRoot, "scripts root");
        RequireOrdinaryDirectoryWithOrdinaryAncestors(repositoryRoot, "repository root");
        RequireOrdinaryDirectoryWithOrdinaryAncestors(normalizedRuntimeRoot, "runtime root");
        RequireOrdinaryDirectoryWithOrdinaryAncestors(scriptsRoot, "scripts root");

        var scriptIdentities = new Dictionary<string, CanonicalLifecycleScriptIdentity>(
            StringComparer.Ordinal);
        foreach (var scriptName in RequiredScriptNames)
        {
            var scriptPath = Path.GetFullPath(Path.Combine(scriptsRoot, scriptName));
            RequireContained(scriptsRoot, scriptPath, $"lifecycle script '{scriptName}'");
            scriptIdentities.Add(
                scriptName,
                CaptureOrdinaryScriptIdentity(scriptPath, scriptName));
        }

        return new(
            repositoryRoot,
            normalizedRuntimeRoot,
            scriptsRoot,
            scriptIdentities);
    }

    public (CanonicalLifecycleLayout Layout, string ScriptPath) ValidateScript(
        string runtimeRoot,
        string scriptName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scriptName);
        var layout = Validate(runtimeRoot);
        if (!EntryScriptNames.Contains(scriptName, StringComparer.Ordinal)
            || !layout.ScriptIdentities.TryGetValue(scriptName, out var scriptIdentity))
        {
            throw new InvalidOperationException($"Lifecycle script '{scriptName}' is not allowlisted.");
        }

        return (layout, scriptIdentity.Path);
    }

    public CanonicalLifecycleInvocationLease AcquireScriptInvocation(
        string runtimeRoot,
        string scriptName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scriptName);
        var initialLayout = Validate(runtimeRoot);
        if (!EntryScriptNames.Contains(scriptName, StringComparer.Ordinal)
            || !initialLayout.ScriptIdentities.ContainsKey(scriptName))
        {
            throw new InvalidOperationException($"Lifecycle script '{scriptName}' is not allowlisted.");
        }

        var leases = new List<CanonicalLifecycleScriptLease>(RequiredScriptNames.Length);
        try
        {
            foreach (var requiredScriptName in RequiredScriptNames)
            {
                var initialIdentity = initialLayout.ScriptIdentities[requiredScriptName];
                leases.Add(CanonicalLifecycleScriptLease.Acquire(
                    initialIdentity.Path,
                    requiredScriptName));
            }

            var leasedIdentities = new Dictionary<string, CanonicalLifecycleScriptIdentity>(
                StringComparer.Ordinal);
            for (var index = 0; index < RequiredScriptNames.Length; index++)
            {
                leasedIdentities.Add(RequiredScriptNames[index], leases[index].Identity);
            }
            var leasedLayout = new CanonicalLifecycleLayout(
                initialLayout.RepositoryRoot,
                initialLayout.RuntimeRoot,
                initialLayout.ScriptsRoot,
                leasedIdentities);
            if (!initialLayout.HasSameScriptInventory(leasedLayout))
            {
                throw new InvalidDataException(
                    "The canonical lifecycle script inventory changed while leases were acquired.");
            }

            return new(
                leasedLayout,
                leasedLayout.ScriptIdentities[scriptName].Path,
                leases);
        }
        catch
        {
            foreach (var lease in leases)
            {
                lease.Dispose();
            }
            throw;
        }
    }

    internal static IReadOnlyList<string> EntryScriptInventory => EntryScriptNames;

    internal static IReadOnlyList<string> ScriptInventory => RequiredScriptNames;

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static void RequireContained(string root, string path, string label)
    {
        var relative = Path.GetRelativePath(root, path);
        if (Path.IsPathRooted(relative)
            || relative.Equals("..", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"The {label} escapes its canonical containment root.");
        }
    }

    private static void RequireOrdinaryDirectoryWithOrdinaryAncestors(string path, string label)
    {
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"The required {label} is missing: {path}");
        }

        RequireNoReparsePoint(path, label);
        RequireAncestorChainWithoutReparsePoints(new DirectoryInfo(path).Parent, label);
    }

    internal static void RequireOrdinaryFileWithOrdinaryAncestors(string path, string label)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"The required lifecycle script is missing: {label}", path);
        }

        RequireNoReparsePoint(path, label);
        RequireAncestorChainWithoutReparsePoints(new FileInfo(path).Directory, label);
    }

    private static CanonicalLifecycleScriptIdentity CaptureOrdinaryScriptIdentity(
        string path,
        string label)
    {
        RequireOrdinaryFileWithOrdinaryAncestors(path, label);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        var size = stream.Length;
        var sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        RequireOrdinaryFileWithOrdinaryAncestors(path, label);
        return new(path, size, sha256);
    }

    private static void RequireAncestorChainWithoutReparsePoints(DirectoryInfo? directory, string label)
    {
        for (var current = directory; current is not null; current = current.Parent)
        {
            RequireNoReparsePoint(current.FullName, label);
        }
    }

    private static void RequireNoReparsePoint(string path, string label)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                $"The {label} has a reparse-point path component and cannot be trusted.");
        }
    }
}
