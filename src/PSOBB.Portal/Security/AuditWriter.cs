using System.Security.Cryptography;
using System.Text;
using PSOBB.Portal.Data;

namespace PSOBB.Portal.Security;

public sealed class AuditWriter(
    PortalDbContext database,
    IConfiguration configuration,
    TimeProvider timeProvider)
{
    public async Task WriteAsync(
        Guid correlationId,
        string eventType,
        string outcome,
        Guid? actorPortalUserId = null,
        string? targetId = null,
        string? sourceAddress = null,
        CancellationToken cancellationToken = default)
    {
        database.AuditEvents.Add(new AuditEvent
        {
            CorrelationId = correlationId,
            EventType = eventType,
            Outcome = outcome,
            ActorPortalUserId = actorPortalUserId,
            TargetId = targetId,
            SourceAddressHash = HashSourceAddress(sourceAddress),
            CreatedAt = timeProvider.GetUtcNow(),
        });
        await database.SaveChangesAsync(cancellationToken);
    }

    private string? HashSourceAddress(string? sourceAddress)
    {
        var key = configuration["Security:AuditHmacKey"];
        if (string.IsNullOrWhiteSpace(sourceAddress) || string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        return Convert.ToHexStringLower(HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(key),
            Encoding.UTF8.GetBytes(sourceAddress)));
    }
}
