using System.Security.Cryptography;

namespace PSOBB.Launcher.Services;

internal sealed class CanonicalLifecycleScriptLease : IDisposable
{
    private readonly string _label;
    private FileStream? _stream;

    private CanonicalLifecycleScriptLease(
        string label,
        FileStream stream,
        CanonicalLifecycleScriptIdentity identity)
    {
        _label = label;
        _stream = stream;
        Identity = identity;
    }

    public CanonicalLifecycleScriptIdentity Identity { get; }

    public static CanonicalLifecycleScriptLease Acquire(string path, string label)
    {
        CanonicalLifecycleRepositoryGuard.RequireOrdinaryFileWithOrdinaryAncestors(path, label);
        FileStream? stream = null;
        try
        {
            stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            var identity = new CanonicalLifecycleScriptIdentity(
                Path.GetFullPath(path),
                stream.Length,
                HashStream(stream));
            CanonicalLifecycleRepositoryGuard.RequireOrdinaryFileWithOrdinaryAncestors(
                path,
                label);
            return new(label, stream, identity);
        }
        catch
        {
            stream?.Dispose();
            throw;
        }
    }

    public void Revalidate()
    {
        var stream = _stream
            ?? throw new ObjectDisposedException(nameof(CanonicalLifecycleScriptLease));
        CanonicalLifecycleRepositoryGuard.RequireOrdinaryFileWithOrdinaryAncestors(
            Identity.Path,
            _label);
        if (!stream.Name.Equals(Identity.Path, StringComparison.OrdinalIgnoreCase)
            || stream.Length != Identity.Size
            || !HashStream(stream).Equals(Identity.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The canonical lifecycle script handle identity changed before invocation.");
        }
        CanonicalLifecycleRepositoryGuard.RequireOrdinaryFileWithOrdinaryAncestors(
            Identity.Path,
            _label);
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _stream = null;
    }

    private static string HashStream(FileStream stream)
    {
        stream.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        stream.Position = 0;
        return sha256;
    }
}

internal sealed class CanonicalLifecycleInvocationLease : IDisposable
{
    private IReadOnlyList<CanonicalLifecycleScriptLease>? _leases;

    internal CanonicalLifecycleInvocationLease(
        CanonicalLifecycleLayout layout,
        string scriptPath,
        IReadOnlyList<CanonicalLifecycleScriptLease> leases)
    {
        Layout = layout;
        ScriptPath = scriptPath;
        _leases = leases;
    }

    public CanonicalLifecycleLayout Layout { get; }

    public string ScriptPath { get; }

    public void Revalidate()
    {
        var leases = _leases
            ?? throw new ObjectDisposedException(nameof(CanonicalLifecycleInvocationLease));
        foreach (var lease in leases)
        {
            lease.Revalidate();
        }
    }

    public void Dispose()
    {
        if (_leases is null)
        {
            return;
        }
        foreach (var lease in _leases.Reverse())
        {
            lease.Dispose();
        }
        _leases = null;
    }
}
