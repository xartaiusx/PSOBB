using PSOBB.AccountBroker.Provisioning;
using PSOBB.AccountBroker.Security;
using PSOBB.AccountBroker.Transport;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "PSOBB Account Broker");
builder.Services.AddOptions<AccountBrokerPipeOptions>()
    .Bind(builder.Configuration.GetSection(AccountBrokerPipeOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.PipeName), "PipeName is required.")
    .Validate(options => options.MaxMessageBytes is >= 1024 and <= 65536,
        "MaxMessageBytes must be between 1024 and 65536.")
    .Validate(options => IsDedicatedIdentitySid(
            options.AllowedClientSid, builder.Environment.IsDevelopment()),
        "AllowedClientSid must be a dedicated Windows account or service SID.")
    .Validate(options => options.MaxConcurrentConnections is >= 1 and <= 32,
        "MaxConcurrentConnections must be between 1 and 32.")
    .Validate(options => options.RequestTimeoutSeconds is >= 2 and <= 60,
        "RequestTimeoutSeconds must be between 2 and 60.")
    .ValidateOnStart();
builder.Services.AddOptions<AccountBrokerReceiptOptions>()
    .Bind(builder.Configuration.GetSection(AccountBrokerReceiptOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.DatabasePath),
        "ReceiptStore:DatabasePath is required.")
    .Validate(options => options.CompletedRetentionDays is >= 1 and <= 365,
        "CompletedRetentionDays must be between 1 and 365.")
    .Validate(options => !builder.Environment.IsProduction() ||
        Path.IsPathFullyQualified(options.DatabasePath),
        "Production ReceiptStore:DatabasePath must be absolute.")
    .ValidateOnStart();
builder.Services.AddSingleton<SecureNamedPipeFactory>();
builder.Services.AddSingleton<IGamePasswordGenerator, CrockfordGamePasswordGenerator>();
builder.Services.AddSingleton<IIdempotencyStore, SqliteIdempotencyStore>();
builder.Services.AddSingleton<INewservAccountGateway, UnconfiguredNewservAccountGateway>();
builder.Services.AddSingleton<BrokerCommandHandler>();
builder.Services.AddHostedService<AccountBrokerWorker>();

await builder.Build().RunAsync();

static bool IsDedicatedIdentitySid(string value, bool allowDevelopmentAccount)
{
    try
    {
        var sid = new System.Security.Principal.SecurityIdentifier(value);
        var canonical = sid.Value;
        return canonical.StartsWith("S-1-5-80-", StringComparison.Ordinal) ||
               (allowDevelopmentAccount &&
                canonical.StartsWith("S-1-5-21-", StringComparison.Ordinal));
    }
    catch (ArgumentException)
    {
        return false;
    }
}
