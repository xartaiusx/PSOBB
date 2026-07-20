using System.Security.Cryptography;

namespace PSOBB.Launcher.Services;

internal sealed record PowerShellExecutableIdentity(
    string FullPath,
    long Size,
    string Sha256);

internal interface IPowerShellExecutableAuthority
{
    PowerShellExecutableLease Acquire();
}

internal sealed class PowerShellExecutableLease : IDisposable
{
    private FileStream? _stream;

    internal PowerShellExecutableLease(FileStream stream, PowerShellExecutableIdentity identity)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
    }

    public PowerShellExecutableIdentity Identity { get; }

    public void Revalidate()
    {
        var stream = _stream
            ?? throw new ObjectDisposedException(nameof(PowerShellExecutableLease));
        TrustedPowerShellExecutableAuthority.RequireOrdinaryAbsoluteFile(Identity.FullPath);
        if (!stream.Name.Equals(Identity.FullPath, StringComparison.OrdinalIgnoreCase)
            || stream.Length != Identity.Size
            || !TrustedPowerShellExecutableAuthority.HashStream(stream).Equals(
                Identity.Sha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The trusted PowerShell executable identity changed before invocation.");
        }
        TrustedPowerShellExecutableAuthority.RequireOrdinaryAbsoluteFile(Identity.FullPath);
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _stream = null;
    }
}

internal sealed class TrustedPowerShellExecutableAuthority : IPowerShellExecutableAuthority
{
    private const string PowerShellExecutableName = "pwsh.exe";
    private readonly string _expectedPath;

    private TrustedPowerShellExecutableAuthority(string expectedPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPath);
        if (!Path.IsPathFullyQualified(expectedPath))
        {
            throw new ArgumentException(
                "The trusted PowerShell executable path must be absolute.",
                nameof(expectedPath));
        }

        _expectedPath = Path.GetFullPath(expectedPath);
        if (!Path.GetFileName(_expectedPath).Equals(
                PowerShellExecutableName,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The trusted PowerShell executable must be pwsh.exe.",
                nameof(expectedPath));
        }
    }

    public static TrustedPowerShellExecutableAuthority CreateProduction()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles) || !Path.IsPathFullyQualified(programFiles))
        {
            throw new InvalidOperationException(
                "Windows did not return an absolute Program Files directory for PowerShell.");
        }

        return CreateFromProgramFilesRoot(programFiles);
    }

    internal static TrustedPowerShellExecutableAuthority CreateFromProgramFilesRoot(
        string programFilesRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(programFilesRoot);
        if (!Path.IsPathFullyQualified(programFilesRoot))
        {
            throw new ArgumentException(
                "The trusted Program Files directory must be absolute.",
                nameof(programFilesRoot));
        }

        return new(Path.Combine(
            Path.GetFullPath(programFilesRoot),
            "PowerShell",
            "7",
            PowerShellExecutableName));
    }

    internal static TrustedPowerShellExecutableAuthority CreateForTesting(string absolutePath) =>
        new(absolutePath);

    public PowerShellExecutableLease Acquire()
    {
        RequireOrdinaryAbsoluteFile(_expectedPath);
        FileStream? stream = null;
        try
        {
            stream = new FileStream(
                _expectedPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            var size = stream.Length;
            if (size <= 0)
            {
                throw new InvalidDataException("The trusted PowerShell executable is empty.");
            }

            var identity = new PowerShellExecutableIdentity(
                _expectedPath,
                size,
                HashStream(stream));
            RequireOrdinaryAbsoluteFile(_expectedPath);
            return new(stream, identity);
        }
        catch
        {
            stream?.Dispose();
            throw;
        }
    }

    internal static string HashStream(FileStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        stream.Position = 0;
        var sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        stream.Position = 0;
        return sha256;
    }

    internal static void RequireOrdinaryAbsoluteFile(string path)
    {
        if (!Path.IsPathFullyQualified(path))
        {
            throw new InvalidDataException("The trusted PowerShell executable path is not absolute.");
        }

        var file = new FileInfo(path);
        if (!file.Exists)
        {
            throw new FileNotFoundException("The trusted PowerShell executable is missing.", path);
        }

        RequireNoReparsePoint(file.FullName);
        for (var directory = file.Directory; directory is not null; directory = directory.Parent)
        {
            RequireNoReparsePoint(directory.FullName);
        }
    }

    private static void RequireNoReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException(
                "The trusted PowerShell executable has a reparse-point path component.");
        }
    }
}
