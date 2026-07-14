using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using PSOBB.Portal.Data;

namespace PSOBB.Portal.Security;

public sealed record IssuedInvite(string Token, DateTimeOffset ExpiresAt);

public sealed class InviteTokenService(
    PortalDbContext database,
    TimeProvider timeProvider)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);
    public const int TokenBytes = 32;

    public async Task<IssuedInvite> IssueAsync(
        Guid issuedByPortalUserId,
        CancellationToken cancellationToken = default)
    {
        var bytes = RandomNumberGenerator.GetBytes(TokenBytes);
        var token = WebEncoders.Base64UrlEncode(bytes);
        var now = timeProvider.GetUtcNow();
        var expiresAt = now.Add(Lifetime);
        var invite = new Invite
        {
            Id = Guid.NewGuid(),
            TokenHash = Hash(token),
            IssuedByPortalUserId = issuedByPortalUserId,
            CreatedAt = now.UtcDateTime,
            ExpiresAt = expiresAt.UtcDateTime,
        };

        database.Invites.Add(invite);
        await database.SaveChangesAsync(cancellationToken);
        return new(token, expiresAt);
    }

    public async Task<bool> ConsumeAsync(
        string token,
        Guid redeemedByPortalUserId,
        CancellationToken cancellationToken = default)
    {
        if (!TryHash(token, out var tokenHash))
        {
            return false;
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var changed = await database.Invites
            .Where(invite =>
                invite.TokenHash == tokenHash &&
                invite.RedeemedAt == null &&
                invite.ExpiresAt > now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(invite => invite.RedeemedAt, now)
                .SetProperty(invite => invite.RedeemedByPortalUserId, redeemedByPortalUserId),
                cancellationToken);
        return changed == 1;
    }

    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));

    private static bool TryHash(string? token, out string hash)
    {
        hash = string.Empty;
        if (string.IsNullOrWhiteSpace(token) || token.Length is < 40 or > 64)
        {
            return false;
        }

        try
        {
            if (WebEncoders.Base64UrlDecode(token).Length != TokenBytes)
            {
                return false;
            }
        }
        catch (FormatException)
        {
            return false;
        }

        hash = Hash(token);
        return true;
    }
}
