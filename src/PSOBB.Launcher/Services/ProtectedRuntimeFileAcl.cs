using System.Security.AccessControl;
using System.Security.Principal;

namespace PSOBB.Launcher.Services;

internal enum ProtectedRuntimeAclScope
{
    ExactFileWithTrustedOwner,
    ExactFileAndProducerBoundary,
}

internal static class ProtectedRuntimeFileAcl
{
    private const string BuiltinAdministratorsSid = "S-1-5-32-544";
    private const string LocalSystemSid = "S-1-5-18";
    private const FileSystemRights UntrustedMutationRights =
        FileSystemRights.Write
        | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions
        | FileSystemRights.TakeOwnership;

    public static void Require(
        string path,
        string containmentRoot,
        ProtectedRuntimeAclScope scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(containmentRoot);
        var root = Path.GetFullPath(containmentRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var file = new FileInfo(Path.GetFullPath(path));
        var relative = Path.GetRelativePath(root, file.FullName);
        if (Path.IsPathRooted(relative)
            || relative.Equals("..", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "A protected lifecycle file escapes its authoritative runtime root.");
        }

        var currentUser = CurrentUserSid();
        var trusted = CreateTrustedSidSet(currentUser);
        var parent = file.Directory
            ?? throw new InvalidDataException("A protected lifecycle file has no parent directory.");
        if (scope == ProtectedRuntimeAclScope.ExactFileAndProducerBoundary
            && parent.FullName.Equals(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The authoritative runtime root cannot be treated as a producer-owned boundary.");
        }

        var directories = EnumerateDirectoryChain(root, parent.FullName);
        foreach (var directory in directories)
        {
            if (scope == ProtectedRuntimeAclScope.ExactFileAndProducerBoundary
                && directory.FullName.Equals(parent.FullName, StringComparison.OrdinalIgnoreCase))
            {
                RequireExactDirectory(directory, currentUser, trusted);
            }
            else
            {
                RequireTrustedAncestor(directory, trusted);
            }
        }

        RequireExactFile(
            file,
            currentUser,
            requireCurrentUserOwner: scope == ProtectedRuntimeAclScope.ExactFileAndProducerBoundary);
    }

    private static List<DirectoryInfo> EnumerateDirectoryChain(
        string root,
        string parent)
    {
        var parentRelative = Path.GetRelativePath(root, parent);
        if (Path.IsPathRooted(parentRelative)
            || parentRelative.Equals("..", StringComparison.Ordinal)
            || parentRelative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || parentRelative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "A protected lifecycle boundary escapes its authoritative runtime root.");
        }

        var result = new List<DirectoryInfo> { new(root) };
        if (!parentRelative.Equals(".", StringComparison.Ordinal))
        {
            var cursor = root;
            foreach (var segment in parentRelative.Split(
                         [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                cursor = Path.Combine(cursor, segment);
                result.Add(new(cursor));
            }
        }
        return result;
    }

    private static void RequireExactFile(
        FileInfo file,
        string currentUser,
        bool requireCurrentUserOwner)
    {
        if (!file.Exists || file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "A protected lifecycle file is missing or is a reparse point.");
        }

        var security = ReadFileSecurity(file);
        RequireExactFileDescriptor(
            security,
            currentUser,
            requireCurrentUserOwner);
    }

    internal static void RequireExactFileDescriptor(
        FileSecurity security,
        string currentUser,
        bool requireCurrentUserOwner)
    {
        ArgumentNullException.ThrowIfNull(security);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentUser);
        RequireExactDescriptor(
            security,
            currentUser,
            CreateTrustedSidSet(currentUser),
            InheritanceFlags.None,
            "file",
            requireCurrentUserOwner);
    }

    private static void RequireExactDirectory(
        DirectoryInfo directory,
        string currentUser,
        HashSet<string> trusted)
    {
        RequireOrdinaryDirectory(directory);
        var security = ReadDirectorySecurity(directory);
        RequireExactDescriptor(
            security,
            currentUser,
            trusted,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            "producer boundary",
            requireCurrentUserOwner: true);
    }

    private static void RequireTrustedAncestor(
        DirectoryInfo directory,
        HashSet<string> trusted)
    {
        RequireOrdinaryDirectory(directory);
        var security = ReadDirectorySecurity(directory);
        var owner = OwnerSid(security);
        if (!trusted.Contains(owner))
        {
            throw new InvalidDataException(
                "A lifecycle ancestor directory does not have a trusted owner.");
        }

        foreach (var rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>())
        {
            var sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            if (rule.AccessControlType == AccessControlType.Allow
                && !trusted.Contains(sid)
                && (rule.FileSystemRights & UntrustedMutationRights) != 0)
            {
                throw new InvalidDataException(
                    "A lifecycle ancestor grants mutation rights to an untrusted principal.");
            }
        }
    }

    private static void RequireOrdinaryDirectory(DirectoryInfo directory)
    {
        if (!directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "A lifecycle ancestor directory is missing or is a reparse point.");
        }
    }

    private static void RequireExactDescriptor(
        FileSystemSecurity security,
        string currentUser,
        HashSet<string> trusted,
        InheritanceFlags expectedInheritance,
        string itemKind,
        bool requireCurrentUserOwner)
    {
        var owner = OwnerSid(security);
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        if ((requireCurrentUserOwner
                ? !owner.Equals(currentUser, StringComparison.OrdinalIgnoreCase)
                : !trusted.Contains(owner))
            || !security.AreAccessRulesProtected
            || !security.AreAccessRulesCanonical
            || rules.Length != trusted.Count)
        {
            throw new InvalidDataException(
                ExactDescriptorFailureMessage(itemKind, requireCurrentUserOwner));
        }

        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            var sid = ((SecurityIdentifier)rule.IdentityReference).Value;
            if (rule.AccessControlType != AccessControlType.Allow
                || rule.IsInherited
                || rule.FileSystemRights != FileSystemRights.FullControl
                || rule.InheritanceFlags != expectedInheritance
                || rule.PropagationFlags != PropagationFlags.None
                || !trusted.Contains(sid)
                || !found.Add(sid))
            {
                throw new InvalidDataException(
                    ExactDescriptorFailureMessage(itemKind, requireCurrentUserOwner));
            }
        }

        if (!found.SetEquals(trusted))
        {
            throw new InvalidDataException(
                ExactDescriptorFailureMessage(itemKind, requireCurrentUserOwner));
        }
    }

    private static string ExactDescriptorFailureMessage(
        string itemKind,
        bool requireCurrentUserOwner) =>
        requireCurrentUserOwner
            ? $"A lifecycle {itemKind} does not have the exact protected ACL and current-user owner."
            : $"A lifecycle {itemKind} does not have the exact protected ACL and trusted owner.";

    private static string OwnerSid(FileSystemSecurity security) =>
        (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value
        ?? throw new InvalidDataException("A lifecycle ACL owner SID is unavailable.");

    private static FileSecurity ReadFileSecurity(FileInfo file)
    {
        try
        {
            return FileSystemAclExtensions.GetAccessControl(
                file,
                AccessControlSections.Access | AccessControlSections.Owner);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            throw new InvalidDataException(
                "A protected lifecycle file ACL could not be authenticated.",
                exception);
        }
    }

    private static DirectorySecurity ReadDirectorySecurity(DirectoryInfo directory)
    {
        try
        {
            return FileSystemAclExtensions.GetAccessControl(
                directory,
                AccessControlSections.Access | AccessControlSections.Owner);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            throw new InvalidDataException(
                "A lifecycle directory ACL could not be authenticated.",
                exception);
        }
    }

    private static string CurrentUserSid() =>
        WindowsIdentity.GetCurrent().User?.Value
        ?? throw new InvalidDataException("The current Windows user SID is unavailable.");

    private static HashSet<string> CreateTrustedSidSet(string currentUser) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            currentUser,
            BuiltinAdministratorsSid,
            LocalSystemSid,
        };
}
