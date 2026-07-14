namespace PSOBB.Launcher.Models;

public enum VerificationStatus
{
    Verified,
    Missing,
    SizeMismatch,
    HashMismatch,
    UnsafePath,
    Error,
}

public sealed record FileVerification(
    string Id,
    string RelativePath,
    VerificationStatus Status,
    string Detail)
{
    public bool IsSuccess => Status == VerificationStatus.Verified;
}

public sealed record ReleaseVerification(IReadOnlyList<FileVerification> Files)
{
    public bool IsSuccess => Files.Count > 0 && Files.All(file => file.IsSuccess);
}

public sealed record PortHealth(int Port, bool IsHealthy, string Detail);
