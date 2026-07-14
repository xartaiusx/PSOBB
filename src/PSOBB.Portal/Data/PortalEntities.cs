using Microsoft.AspNetCore.Identity;

namespace PSOBB.Portal.Data;

public sealed class PortalUser : IdentityUser<Guid>
{
    public DateTimeOffset CreatedAt { get; set; }
    public bool IsDisabled { get; set; }
    public GameAccountLink? GameAccountLink { get; set; }
}

public sealed class PortalRole : IdentityRole<Guid>;

public sealed class Invite
{
    public Guid Id { get; set; }
    public required string TokenHash { get; set; }
    public Guid IssuedByPortalUserId { get; set; }
    // SQLite can compare UTC DateTime values atomically; DateTimeOffset comparisons
    // are not supported by its EF provider.
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RedeemedAt { get; set; }
    public Guid? RedeemedByPortalUserId { get; set; }
}

public enum GameAccountState
{
    Provisioning,
    Active,
    Disabled,
    Failed,
}

public sealed class GameAccountLink
{
    public Guid Id { get; set; }
    public Guid PortalUserId { get; set; }
    public PortalUser PortalUser { get; set; } = null!;
    public required string GameUsername { get; set; }
    public string? NewservAccountId { get; set; }
    public GameAccountState State { get; set; }
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public enum ProvisioningState
{
    Pending,
    Succeeded,
    Failed,
}

public sealed class ProvisioningRequest
{
    public Guid RequestId { get; set; }
    public Guid PortalUserId { get; set; }
    public required string Operation { get; set; }
    public ProvisioningState State { get; set; }
    public long Version { get; set; }
    public string? ErrorCode { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class AuditEvent
{
    public long Id { get; set; }
    public Guid CorrelationId { get; set; }
    public required string EventType { get; set; }
    public required string Outcome { get; set; }
    public Guid? ActorPortalUserId { get; set; }
    public string? TargetId { get; set; }
    public string? SourceAddressHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
