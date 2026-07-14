using Microsoft.Extensions.Logging.Abstractions;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;
using PSOBB.AccountBroker.Security;

namespace PSOBB.Accounts.Tests;

public sealed class BrokerCommandHandlerTests
{
    [Fact]
    public async Task CreateReturnsSecretOnceAndDoesNotRepeatSideEffect()
    {
        var gateway = new RecordingGateway();
        var handler = CreateHandler(gateway);
        var request = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            "player01");

        var first = await handler.HandleAsync(request, CancellationToken.None);
        var replay = await handler.HandleAsync(request, CancellationToken.None);

        Assert.Equal(BrokerResponseStatus.Succeeded, first.Status);
        Assert.NotNull(first.GamePassword);
        Assert.Equal(CrockfordGamePasswordGenerator.PasswordLength, first.GamePassword.Length);
        Assert.Equal(BrokerResponseStatus.Succeeded, replay.Status);
        Assert.True(replay.Replayed);
        Assert.Null(replay.GamePassword);
        Assert.Equal(1, gateway.CreateCalls);
    }

    [Fact]
    public async Task UnknownOperationIsRejectedWithoutCallingGateway()
    {
        var gateway = new RecordingGateway();
        var handler = CreateHandler(gateway);
        var request = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            (BrokerOperation)999,
            Guid.NewGuid().ToString("D"),
            "player01");

        var response = await handler.HandleAsync(request, CancellationToken.None);

        Assert.Equal(BrokerResponseStatus.Rejected, response.Status);
        Assert.Equal("operation_not_allowed", response.ErrorCode);
        Assert.Equal(0, gateway.CreateCalls);
    }

    [Fact]
    public async Task StatusLookupDoesNotReserveAnUnknownTargetId()
    {
        var gateway = new RecordingGateway();
        var handler = CreateHandler(gateway);
        var targetRequestId = Guid.NewGuid();
        var status = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.GetProvisioningStatus,
            TargetRequestId: targetRequestId);

        var unknown = await handler.HandleAsync(status, CancellationToken.None);
        var create = await handler.HandleAsync(new(
            BrokerCommandHandler.ProtocolVersion,
            targetRequestId,
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            "player02"), CancellationToken.None);

        Assert.Equal("target_request_not_found", unknown.ErrorCode);
        Assert.Equal(BrokerResponseStatus.Succeeded, create.Status);
    }

    [Fact]
    public async Task GatewayExceptionBecomesDurableUnknownOutcome()
    {
        var gateway = new RecordingGateway { ThrowOnCreate = true };
        var handler = CreateHandler(gateway);
        var request = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            "player03");

        var first = await handler.HandleAsync(request, CancellationToken.None);
        var replay = await handler.HandleAsync(request, CancellationToken.None);

        Assert.Equal(BrokerResponseStatus.OutcomeUnknown, first.Status);
        Assert.Equal(BrokerResponseStatus.OutcomeUnknown, replay.Status);
        Assert.True(replay.Replayed);
        Assert.False(replay.IsSuccess);
        Assert.Null(replay.GamePassword);
    }

    [Fact]
    public async Task UnknownOutcomeCanBeResolvedByRequestAwareGateway()
    {
        var gateway = new RecordingGateway { ThrowOnCreate = true };
        var handler = CreateHandler(gateway);
        var request = new BrokerRequest(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            "player06");
        _ = await handler.HandleAsync(request, CancellationToken.None);
        gateway.OperationStatus = new(
            NewservOperationState.Succeeded,
            "1006",
            "player06");

        var resolved = await handler.HandleAsync(new(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.GetProvisioningStatus,
            TargetRequestId: request.RequestId), CancellationToken.None);
        var originalReplay = await handler.HandleAsync(request, CancellationToken.None);

        Assert.Equal(BrokerResponseStatus.Succeeded, resolved.Status);
        Assert.Equal("1006", resolved.GameAccountId);
        Assert.True(resolved.Replayed);
        Assert.Equal(BrokerResponseStatus.Succeeded, originalReplay.Status);
        Assert.Null(originalReplay.GamePassword);
    }

    [Fact]
    public async Task SameRequestIdWithDifferentPayloadIsRejected()
    {
        var gateway = new RecordingGateway();
        var handler = CreateHandler(gateway);
        var requestId = Guid.NewGuid();
        var first = await handler.HandleAsync(new(
            BrokerCommandHandler.ProtocolVersion,
            requestId,
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            "player04"), CancellationToken.None);
        var conflict = await handler.HandleAsync(new(
            BrokerCommandHandler.ProtocolVersion,
            requestId,
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            "player05"), CancellationToken.None);

        Assert.Equal(BrokerResponseStatus.Succeeded, first.Status);
        Assert.Equal("request_id_conflict", conflict.ErrorCode);
        Assert.Equal(1, gateway.CreateCalls);
    }

    [Fact]
    public async Task ReadinessFailsClosedWithoutConfiguredGateway()
    {
        var handler = CreateHandler(new UnconfiguredNewservAccountGateway());

        var response = await handler.HandleAsync(new(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.GetProvisioningStatus), CancellationToken.None);

        Assert.Equal(BrokerResponseStatus.Failed, response.Status);
        Assert.Equal("backend_unavailable", response.ErrorCode);
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("abcdefghijklmnopq")]
    [InlineData("MixedCase")]
    [InlineData("has-dash")]
    [InlineData("nonasciié")]
    public async Task InvalidUsernameIsRejected(string username)
    {
        var handler = CreateHandler(new RecordingGateway());
        var response = await handler.HandleAsync(new(
            BrokerCommandHandler.ProtocolVersion,
            Guid.NewGuid(),
            BrokerOperation.CreatePlayerAccount,
            Guid.NewGuid().ToString("D"),
            username), CancellationToken.None);

        Assert.Equal("invalid_game_username", response.ErrorCode);
    }

    private static BrokerCommandHandler CreateHandler(INewservAccountGateway gateway) => new(
        gateway,
        new CrockfordGamePasswordGenerator(),
        new InMemoryIdempotencyStore(),
        NullLogger<BrokerCommandHandler>.Instance);

    private sealed class RecordingGateway : INewservAccountGateway
    {
        public int CreateCalls { get; private set; }
        public bool IsReady => true;
        public bool ThrowOnCreate { get; init; }
        public NewservOperationStatus OperationStatus { get; set; } =
            new(NewservOperationState.Unknown);

        public Task<NewservAccountResult> CreatePlayerAccountAsync(
            Guid requestId,
            string portalUserId,
            string gameUsername,
            string gamePassword,
            CancellationToken cancellationToken)
        {
            CreateCalls++;
            if (ThrowOnCreate)
            {
                throw new InvalidOperationException("Synthetic failure.");
            }

            return Task.FromResult(new NewservAccountResult("1001", gameUsername));
        }

        public Task<NewservAccountResult> RotateGamePasswordAsync(
            Guid requestId,
            string gameUsername,
            string gamePassword,
            CancellationToken cancellationToken) =>
            Task.FromResult(new NewservAccountResult("1001", gameUsername));

        public Task<NewservAccountResult> DisablePlayerAccountAsync(
            Guid requestId,
            string gameUsername,
            CancellationToken cancellationToken) =>
            Task.FromResult(new NewservAccountResult("1001", gameUsername));

        public Task<NewservOperationStatus> GetOperationStatusAsync(
            Guid requestId,
            CancellationToken cancellationToken) => Task.FromResult(OperationStatus);
    }
}
