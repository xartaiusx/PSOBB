using System.Globalization;

namespace PSOBB.Portal.Security;

public static class RecentAuthenticationEndpointExtensions
{
    public const string ClaimType = "auth_time";
    public static readonly TimeSpan MaximumAge = TimeSpan.FromMinutes(5);

    public static RouteHandlerBuilder RequireRecentAuthentication(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter(async (context, next) =>
        {
            var claim = context.HttpContext.User.FindFirst(ClaimType)?.Value;
            if (!long.TryParse(claim, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                return Results.Json(
                    new { error = "recent_authentication_required" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            var authenticatedAt = DateTimeOffset.FromUnixTimeSeconds(seconds);
            if (TimeProvider.System.GetUtcNow() - authenticatedAt > MaximumAge)
            {
                return Results.Json(
                    new { error = "recent_authentication_required" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return await next(context);
        });
}
