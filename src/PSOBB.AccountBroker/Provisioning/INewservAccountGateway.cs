namespace PSOBB.AccountBroker.Provisioning;

public sealed record NewservAccountResult(string GameAccountId, string GameUsername);

public enum NewservOperationState
{
    Unknown,
    InProgress,
    Succeeded,
    Failed,
}

public sealed record NewservOperationStatus(
    NewservOperationState State,
    string? GameAccountId = null,
    string? GameUsername = null,
    string? ErrorCode = null);

public interface INewservAccountGateway
{
    bool IsReady { get; }

    Task<NewservAccountResult> CreatePlayerAccountAsync(
        Guid requestId,
        string portalUserId,
        string gameUsername,
        string gamePassword,
        CancellationToken cancellationToken);

    Task<NewservAccountResult> RotateGamePasswordAsync(
        Guid requestId,
        string gameUsername,
        string gamePassword,
        CancellationToken cancellationToken);

    Task<NewservAccountResult> DisablePlayerAccountAsync(
        Guid requestId,
        string gameUsername,
        CancellationToken cancellationToken);

    Task<NewservOperationStatus> GetOperationStatusAsync(
        Guid requestId,
        CancellationToken cancellationToken);
}

public sealed class UnconfiguredNewservAccountGateway : INewservAccountGateway
{
    private const string Message =
        "The reviewed atomic newserv account adapter has not been configured.";

    public bool IsReady => false;

    public Task<NewservAccountResult> CreatePlayerAccountAsync(
        Guid requestId,
        string portalUserId,
        string gameUsername,
        string gamePassword,
        CancellationToken cancellationToken) => throw new InvalidOperationException(Message);

    public Task<NewservAccountResult> RotateGamePasswordAsync(
        Guid requestId,
        string gameUsername,
        string gamePassword,
        CancellationToken cancellationToken) => throw new InvalidOperationException(Message);

    public Task<NewservAccountResult> DisablePlayerAccountAsync(
        Guid requestId,
        string gameUsername,
        CancellationToken cancellationToken) => throw new InvalidOperationException(Message);

    public Task<NewservOperationStatus> GetOperationStatusAsync(
        Guid requestId,
        CancellationToken cancellationToken) => Task.FromResult(
            new NewservOperationStatus(NewservOperationState.Unknown));
}
