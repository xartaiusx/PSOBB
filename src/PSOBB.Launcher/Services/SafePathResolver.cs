using System.Text.RegularExpressions;

namespace PSOBB.Launcher.Services;

public static partial class SafePathResolver
{
    private static readonly char[] InvalidWindowsFileNameCharacters = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

    public static string ResolveWithinRoot(string rootPath, string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ValidateRelativePath(relativePath);

        var root = Path.GetFullPath(rootPath);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException("The runtime root does not exist or is not a directory.");
        }

        var normalizedRelative = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var resolved = Path.GetFullPath(Path.Combine(root, normalizedRelative));
        var rootPrefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;

        if (!resolved.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The path resolves outside the runtime root.");
        }

        RejectExistingReparsePoints(root, resolved);
        return resolved;
    }

    public static void ValidateRelativePath(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);

        if (Path.IsPathRooted(relativePath) || relativePath.Contains('\0'))
        {
            throw new InvalidDataException("Only non-empty relative paths are allowed.");
        }

        var segments = relativePath.Split(['/', '\\'], StringSplitOptions.None);
        if (segments.Length == 0)
        {
            throw new InvalidDataException("A relative path must contain at least one segment.");
        }

        foreach (var segment in segments)
        {
            ValidateSegment(segment);
        }
    }

    private static void ValidateSegment(string segment)
    {
        if (string.IsNullOrWhiteSpace(segment) || segment is "." or "..")
        {
            throw new InvalidDataException("Empty, current-directory, and parent-directory segments are not allowed.");
        }

        if (segment.EndsWith(' ') || segment.EndsWith('.'))
        {
            throw new InvalidDataException("Windows paths may not contain segments ending in a space or period.");
        }

        if (segment.Any(character => character < 32 || InvalidWindowsFileNameCharacters.Contains(character)))
        {
            throw new InvalidDataException("The path contains a Windows-invalid character.");
        }

        var deviceCandidate = segment.Split('.', 2)[0].TrimEnd(' ', '.');
        if (ReservedDeviceName().IsMatch(deviceCandidate))
        {
            throw new InvalidDataException("Windows reserved device names are not allowed.");
        }
    }

    private static void RejectExistingReparsePoints(string root, string resolved)
    {
        if (Exists(root) && IsReparsePoint(root))
        {
            throw new InvalidDataException("The runtime root may not be a reparse point.");
        }

        var relative = Path.GetRelativePath(root, resolved);
        var current = root;
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (Exists(current) && IsReparsePoint(current))
            {
                throw new InvalidDataException("Runtime paths may not traverse reparse points.");
            }
        }
    }

    private static bool Exists(string path) => File.Exists(path) || Directory.Exists(path);

    private static bool IsReparsePoint(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    [GeneratedRegex("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ReservedDeviceName();
}
