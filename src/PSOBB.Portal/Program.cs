using System.Security.Claims;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PSOBB.Portal.Accounts;
using PSOBB.Portal.Broker;
using PSOBB.Portal.Data;
using PSOBB.Portal.Security;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16 * 1024);
var connectionString = builder.Configuration.GetConnectionString("Portal")
    ?? throw new InvalidOperationException("ConnectionStrings:Portal is required.");
var databasePath = new SqliteConnectionStringBuilder(connectionString).DataSource;
var dataProtectionKeysPath = builder.Configuration["Security:DataProtectionKeysPath"];
var compromisedPasswordPath = builder.Configuration["Security:CompromisedPasswordDatabasePath"];
var auditHmacKey = builder.Configuration["Security:AuditHmacKey"];
var hostingMode = builder.Configuration["Hosting:Mode"] ?? "DirectTls";
var knownProxyValues = builder.Configuration.GetSection("Hosting:KnownProxies").Get<string[]>() ?? [];
var allowedHosts = builder.Configuration["AllowedHosts"];
var publicHttpsUrl = builder.Configuration["Hosting:PublicHttpsUrl"];

if (builder.Environment.IsProduction())
{
    if (!Path.IsPathFullyQualified(databasePath))
    {
        throw new InvalidOperationException("Production portal database path must be absolute.");
    }

    if (string.IsNullOrWhiteSpace(dataProtectionKeysPath) ||
        !Path.IsPathFullyQualified(dataProtectionKeysPath))
    {
        throw new InvalidOperationException(
            "Production Data Protection key path must be configured and absolute.");
    }

    if (string.IsNullOrWhiteSpace(compromisedPasswordPath) ||
        !Path.IsPathFullyQualified(compromisedPasswordPath) ||
        !File.Exists(compromisedPasswordPath))
    {
        throw new InvalidOperationException(
            "Production compromised-password database must be configured.");
    }

    if (string.IsNullOrWhiteSpace(auditHmacKey) || auditHmacKey.Length < 32)
    {
        throw new InvalidOperationException(
            "Production audit HMAC key must contain at least 32 characters.");
    }

    if (!string.Equals(
            builder.Configuration["DatabaseInitialization:Mode"],
            "Migrate",
            StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            "Production database initialization must use reviewed migrations.");
    }

    if (string.IsNullOrWhiteSpace(allowedHosts) ||
        allowedHosts is "*" ||
        string.Equals(allowedHosts, "localhost", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException("Production AllowedHosts must name the public host.");
    }
}

if (!string.IsNullOrWhiteSpace(compromisedPasswordPath))
{
    CompromisedPasswordValidator.ValidateDatabase(compromisedPasswordPath);
}

if (!string.IsNullOrWhiteSpace(dataProtectionKeysPath))
{
    Directory.CreateDirectory(Path.GetFullPath(dataProtectionKeysPath));
    builder.Services.AddDataProtection()
        .SetApplicationName("PSOBB.AccountPortal.v1")
        .PersistKeysToFileSystem(new DirectoryInfo(Path.GetFullPath(dataProtectionKeysPath)))
        .ProtectKeysWithDpapi(protectToLocalMachine: false);
}

var useForwardedHeaders = string.Equals(hostingMode, "ReverseProxy", StringComparison.OrdinalIgnoreCase);
if (useForwardedHeaders)
{
    if (knownProxyValues.Length == 0)
    {
        throw new InvalidOperationException("ReverseProxy mode requires explicit KnownProxies.");
    }

    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = 1;
        foreach (var value in knownProxyValues)
        {
            options.KnownProxies.Add(IPAddress.Parse(value));
        }
    });
}
else if (!string.Equals(hostingMode, "DirectTls", StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException("Hosting:Mode must be DirectTls or ReverseProxy.");
}
else if (builder.Environment.IsProduction())
{
    if (!Uri.TryCreate(publicHttpsUrl, UriKind.Absolute, out var publicUri) ||
        !string.Equals(publicUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException("DirectTls mode requires Hosting:PublicHttpsUrl using HTTPS.");
    }

    builder.WebHost.UseUrls(publicUri.ToString());
}

builder.Services.AddDbContext<PortalDbContext>(options => options.UseSqlite(connectionString));
builder.Services.AddIdentity<PortalUser, PortalRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 15;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<PortalDbContext>()
    .AddPasswordValidator<CompromisedPasswordValidator>()
    .AddDefaultTokenProviders();
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "__Host-PSOBBPortal";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = false;
    options.LoginPath = "/";
    options.AccessDeniedPath = "/";
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("PortalAdminMfa", policy => policy
        .RequireAuthenticatedUser()
        .RequireRole("Administrator")
        .RequireClaim("amr", "mfa"));
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "__Host-PSOBBPortal-CSRF";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
    options.AddPolicy("authentication", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
});
builder.Services.AddOptions<BrokerClientOptions>()
    .Bind(builder.Configuration.GetSection(BrokerClientOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.PipeName), "PipeName is required.")
    .Validate(options => options.ConnectTimeoutMilliseconds is >= 100 and <= 10000,
        "ConnectTimeoutMilliseconds must be between 100 and 10000.")
    .Validate(options => builder.Environment.IsDevelopment() ||
        IsDedicatedIdentitySid(
            options.ExpectedBrokerSid, allowDevelopmentAccount: false),
        "ExpectedBrokerSid must be the dedicated broker account or service SID.")
    .ValidateOnStart();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<InviteTokenService>();
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<PortalAccountService>();
builder.Services.AddSingleton<AccountOperationLock>();
builder.Services.AddSingleton<IAccountBrokerClient, NamedPipeBrokerClient>();
builder.Services.AddHostedService<PortalDatabaseInitializer>();
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});

var app = builder.Build();
if (useForwardedHeaders)
{
    app.UseForwardedHeaders();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
    if (context.Request.Path.StartsWithSegments("/account") ||
        context.Request.Path.StartsWithSegments("/admin"))
    {
        context.Response.Headers.CacheControl = "no-store";
    }
    await next();
});
app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.MapGet("/security/csrf", (HttpContext context, IAntiforgery antiforgery) =>
{
    context.Response.Headers.CacheControl = "no-store";
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { token = tokens.RequestToken });
});

app.MapPost("/account/login", async (
    LoginRequest request,
    UserManager<PortalUser> users,
    SignInManager<PortalUser> signIn,
    AuditWriter audit,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    var correlationId = Guid.NewGuid();
    if (!IsValidLoginRequest(request))
    {
        await audit.WriteAsync(
            correlationId, "portal_login", "rejected",
            sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
            cancellationToken: cancellationToken);
        return Results.Json(new { error = "invalid_credentials" }, statusCode: 401);
    }

    var user = await users.FindByEmailAsync(request.Email!.Trim());
    if (user is null || user.IsDisabled)
    {
        await audit.WriteAsync(
            correlationId, "portal_login", "rejected",
            sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
            cancellationToken: cancellationToken);
        return Results.Json(new { error = "invalid_credentials" }, statusCode: 401);
    }

    if (await users.IsLockedOutAsync(user) ||
        !await users.CheckPasswordAsync(user, request.Password!))
    {
        if (!await users.IsLockedOutAsync(user))
        {
            await users.AccessFailedAsync(user);
        }

        await audit.WriteAsync(
            correlationId, "portal_login", "rejected", user.Id,
            sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
            cancellationToken: cancellationToken);
        return Results.Json(new { error = "invalid_credentials" }, statusCode: 401);
    }

    if (user.TwoFactorEnabled)
    {
        if (string.IsNullOrWhiteSpace(request.AuthenticatorCode))
        {
            await audit.WriteAsync(
                correlationId, "portal_login", "mfa_required", user.Id,
                sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
                cancellationToken: cancellationToken);
            return Results.Json(new { error = "mfa_required" }, statusCode: 401);
        }

        var validCode = await users.VerifyTwoFactorTokenAsync(
            user,
            users.Options.Tokens.AuthenticatorTokenProvider,
            request.AuthenticatorCode.Replace(" ", string.Empty, StringComparison.Ordinal)
                .Replace("-", string.Empty, StringComparison.Ordinal));
        if (!validCode)
        {
            await users.AccessFailedAsync(user);
            await audit.WriteAsync(
                correlationId, "portal_login", "rejected", user.Id,
                sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
                cancellationToken: cancellationToken);
            return Results.Json(new { error = "invalid_credentials" }, statusCode: 401);
        }

        await users.ResetAccessFailedCountAsync(user);
        await signIn.SignInWithClaimsAsync(user, isPersistent: false,
        [
            new Claim("amr", "mfa"),
            new Claim(
                RecentAuthenticationEndpointExtensions.ClaimType,
                TimeProvider.System.GetUtcNow().ToUnixTimeSeconds().ToString(
                    System.Globalization.CultureInfo.InvariantCulture)),
        ]);
    }
    else
    {
        await users.ResetAccessFailedCountAsync(user);
        await signIn.SignInWithClaimsAsync(user, isPersistent: false,
        [
            new Claim(
                RecentAuthenticationEndpointExtensions.ClaimType,
                TimeProvider.System.GetUtcNow().ToUnixTimeSeconds().ToString(
                    System.Globalization.CultureInfo.InvariantCulture)),
        ]);
    }

    await audit.WriteAsync(
        correlationId, "portal_login", "succeeded", user.Id,
        sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
        cancellationToken: cancellationToken);
    return Results.Ok(new { status = "authenticated" });
})
    .RequireRateLimiting("authentication")
    .RequireAntiforgery();

app.MapPost("/account/logout", async (SignInManager<PortalUser> signIn) =>
{
    await signIn.SignOutAsync();
    return Results.Ok(new { status = "signed_out" });
})
    .RequireAuthorization()
    .RequireAntiforgery();

app.MapPost("/admin/invites", async (
    HttpContext context,
    InviteTokenService inviteTokens,
    AuditWriter audit,
    CancellationToken cancellationToken) =>
{
    context.Response.Headers.CacheControl = "no-store";
    var userId = Guid.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var invite = await inviteTokens.IssueAsync(userId, cancellationToken);
    await audit.WriteAsync(
        Guid.NewGuid(), "invite_issue", "succeeded", userId,
        sourceAddress: context.Connection.RemoteIpAddress?.ToString(),
        cancellationToken: cancellationToken);
    return Results.Ok(new { token = invite.Token, expiresAt = invite.ExpiresAt });
})
    .RequireAuthorization("PortalAdminMfa")
    .RequireRecentAuthentication()
    .RequireRateLimiting("authentication")
    .RequireAntiforgery();

app.MapPost("/account/redeem-invite", async (
    HttpContext context,
    RedeemInviteRequest request,
    PortalAccountService accounts,
    CancellationToken cancellationToken) =>
{
    context.Response.Headers.CacheControl = "no-store";
    if (!IsValidRedemptionRequest(request))
    {
        return Results.BadRequest(new { error = "request_rejected" });
    }

    var result = await accounts.RedeemInviteAsync(
        request.InviteToken!,
        request.Email!,
        request.PortalPassword!,
        request.GameUsername!,
        context.Connection.RemoteIpAddress?.ToString(),
        cancellationToken);
    if (result.ServiceUnavailable)
    {
        return Results.Json(new { error = "service_unavailable" }, statusCode: 503);
    }

    if (!result.Accepted)
    {
        return Results.BadRequest(new { error = "request_rejected" });
    }

    if (result.Provisioned)
    {
        return Results.Ok(new
        {
            gameUsername = result.GameUsername,
            gamePassword = result.GamePassword,
            displayOnce = true,
        });
    }

    return result.Pending
        ? Results.Json(new { status = "provisioning_pending" }, statusCode: 202)
        : Results.Json(new { error = "provisioning_failed" }, statusCode: 503);
})
    .RequireRateLimiting("authentication")
    .RequireAntiforgery();

app.MapPost("/account/game-password/rotate", async (
    HttpContext context,
    PortalAccountService accounts,
    CancellationToken cancellationToken) =>
{
    context.Response.Headers.CacheControl = "no-store";
    var userId = Guid.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var result = await accounts.RotateGamePasswordAsync(userId, cancellationToken);
    return result.Succeeded
        ? Results.Ok(new
        {
            gameUsername = result.GameUsername,
            gamePassword = result.GamePassword,
            displayOnce = true,
        })
        : Results.Json(new { error = "request_failed" }, statusCode: 503);
})
    .RequireAuthorization()
    .RequireRecentAuthentication()
    .RequireRateLimiting("authentication")
    .RequireAntiforgery();

app.MapPost("/account/game/disable", async (
    HttpContext context,
    PortalAccountService accounts,
    CancellationToken cancellationToken) =>
{
    var userId = Guid.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var disabled = await accounts.DisableGameAccountAsync(userId, cancellationToken);
    return disabled
        ? Results.Ok(new { status = "disabled" })
        : Results.Json(new { error = "request_failed" }, statusCode: 503);
})
    .RequireAuthorization()
    .RequireRecentAuthentication()
    .RequireRateLimiting("authentication")
    .RequireAntiforgery();

app.MapPost("/account/provisioning/reconcile", async (
    HttpContext context,
    PortalAccountService accounts,
    CancellationToken cancellationToken) =>
{
    context.Response.Headers.CacheControl = "no-store";
    var userId = Guid.Parse(context.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    var result = await accounts.ReconcileProvisioningAsync(userId, cancellationToken);
    if (result.Succeeded)
    {
        return Results.Ok(new
        {
            gameUsername = result.GameUsername,
            gamePassword = result.GamePassword,
            displayOnce = true,
        });
    }

    return result.Pending
        ? Results.Json(new { status = "provisioning_pending" }, statusCode: 202)
        : Results.Json(new { error = "provisioning_failed" }, statusCode: 409);
})
    .RequireAuthorization()
    .RequireRecentAuthentication()
    .RequireRateLimiting("authentication")
    .RequireAntiforgery();

await app.RunAsync();

static bool IsDedicatedIdentitySid(string value, bool allowDevelopmentAccount)
{
    try
    {
        var sid = new System.Security.Principal.SecurityIdentifier(value).Value;
        return sid.StartsWith("S-1-5-80-", StringComparison.Ordinal) ||
               (allowDevelopmentAccount && sid.StartsWith(
                   "S-1-5-21-", StringComparison.Ordinal));
    }
    catch (ArgumentException)
    {
        return false;
    }
}

static bool IsValidLoginRequest(LoginRequest request) =>
    !string.IsNullOrWhiteSpace(request.Email) &&
    request.Email.Length <= 254 &&
    !string.IsNullOrEmpty(request.Password) &&
    request.Password.Length <= 256 &&
    (request.AuthenticatorCode is null || request.AuthenticatorCode.Length <= 16);

static bool IsValidRedemptionRequest(RedeemInviteRequest request) =>
    request.InviteToken is { Length: >= 40 and <= 64 } &&
    request.Email is { Length: >= 3 and <= 254 } &&
    request.PortalPassword is { Length: >= 15 and <= 256 } &&
    request.GameUsername is { Length: >= 3 and <= 16 };

public sealed record LoginRequest(string? Email, string? Password, string? AuthenticatorCode = null);
public sealed record RedeemInviteRequest(
    string? InviteToken,
    string? Email,
    string? PortalPassword,
    string? GameUsername);

public partial class Program;
