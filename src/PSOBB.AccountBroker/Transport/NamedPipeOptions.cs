namespace PSOBB.AccountBroker.Transport;

public sealed class AccountBrokerPipeOptions
{
    public const string SectionName = "AccountBrokerPipe";
    public string PipeName { get; init; } = "PSOBB.AccountBroker.v1";
    public string AllowedClientSid { get; init; } = string.Empty;
    public int MaxMessageBytes { get; init; } = 16 * 1024;
    public int MaxConcurrentConnections { get; init; } = 8;
    public int RequestTimeoutSeconds { get; init; } = 15;
}
