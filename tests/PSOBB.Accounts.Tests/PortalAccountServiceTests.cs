using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;
using PSOBB.Portal.Accounts;
using PSOBB.Portal.Broker;
using PSOBB.Portal.Data;
using PSOBB.Portal.Security;

namespace PSOBB.Accounts.Tests;

public sealed class PortalAccountServiceTests
{
    [Fact]
    public async Task UnavailableBrokerDoesNotConsumeInvite()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<PortalDbContext>()
            .UseSqlite(connection)
            .Options;
        await using var database = new PortalDbContext(options);
        await database.Database.EnsureCreatedAsync();
        var clock = TimeProvider.System;
        var tokens = new InviteTokenService(database, clock);
        var issued = await tokens.IssueAsync(Guid.NewGuid());
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();
        var service = new PortalAccountService(
            database,
            userManager: null!,
            tokens,
            new UnavailableBrokerClient(),
            new AuditWriter(database, configuration, clock),
            new AccountOperationLock(),
            clock);

        var result = await service.RedeemInviteAsync(
            issued.Token,
            "player@example.invalid",
            "ValidPortalPassword!123",
            "player01",
            "127.0.0.1",
            CancellationToken.None);

        database.ChangeTracker.Clear();
        var invite = await database.Invites.SingleAsync();
        Assert.True(result.ServiceUnavailable);
        Assert.False(result.Accepted);
        Assert.Null(invite.RedeemedAt);
        Assert.Null(invite.RedeemedByPortalUserId);
    }

    [Fact]
    public async Task LostCreateResponseIsReconciledWithImmediatePasswordRotation()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<PortalDbContext>()
            .UseSqlite(connection)
            .Options;
        await using var database = new PortalDbContext(options);
        await database.Database.EnsureCreatedAsync();
        var portalUserId = Guid.NewGuid();
        var createRequestId = Guid.NewGuid();
        var now = TimeProvider.System.GetUtcNow();
        database.Users.Add(new PortalUser
        {
            Id = portalUserId,
            UserName = "player@example.invalid",
            NormalizedUserName = "PLAYER@EXAMPLE.INVALID",
            Email = "player@example.invalid",
            NormalizedEmail = "PLAYER@EXAMPLE.INVALID",
            CreatedAt = now,
        });
        database.GameAccountLinks.Add(new GameAccountLink
        {
            Id = Guid.NewGuid(),
            PortalUserId = portalUserId,
            GameUsername = "player02",
            State = GameAccountState.Provisioning,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.ProvisioningRequests.Add(new ProvisioningRequest
        {
            RequestId = createRequestId,
            PortalUserId = portalUserId,
            Operation = BrokerOperation.CreatePlayerAccount.ToString(),
            State = ProvisioningState.Pending,
            ErrorCode = "broker_outcome_unknown",
            CreatedAt = now,
            UpdatedAt = now,
        });
        await database.SaveChangesAsync();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();
        var service = new PortalAccountService(
            database,
            userManager: null!,
            inviteTokens: null!,
            new ReconciliationBrokerClient(createRequestId),
            new AuditWriter(database, configuration, TimeProvider.System),
            new AccountOperationLock(),
            TimeProvider.System);

        var result = await service.ReconcileProvisioningAsync(
            portalUserId, CancellationToken.None);

        database.ChangeTracker.Clear();
        var link = await database.GameAccountLinks.SingleAsync();
        var createRequest = await database.ProvisioningRequests
            .SingleAsync(value => value.RequestId == createRequestId);
        Assert.True(result.Succeeded);
        Assert.False(result.Pending);
        Assert.Equal("0123456789ABCDEF", result.GamePassword);
        Assert.Equal(GameAccountState.Active, link.State);
        Assert.Equal("1002", link.NewservAccountId);
        Assert.Equal(ProvisioningState.Succeeded, createRequest.State);
    }

    private sealed class UnavailableBrokerClient : IAccountBrokerClient
    {
        public Task<BrokerResponse> SendAsync(
            BrokerRequest request,
            CancellationToken cancellationToken) => Task.FromResult(new BrokerResponse(
                BrokerCommandHandler.ProtocolVersion,
                request.RequestId,
                BrokerResponseStatus.Failed,
                ErrorCode: "backend_unavailable"));
    }

    private sealed class ReconciliationBrokerClient(Guid expectedCreateRequestId)
        : IAccountBrokerClient
    {
        public Task<BrokerResponse> SendAsync(
            BrokerRequest request,
            CancellationToken cancellationToken)
        {
            if (request.Operation is BrokerOperation.GetProvisioningStatus)
            {
                Assert.Equal(expectedCreateRequestId, request.TargetRequestId);
                return Task.FromResult(new BrokerResponse(
                    BrokerCommandHandler.ProtocolVersion,
                    request.RequestId,
                    BrokerResponseStatus.Succeeded,
                    GameAccountId: "1002",
                    GameUsername: "player02",
                    Replayed: true));
            }

            Assert.Equal(BrokerOperation.RotateGamePassword, request.Operation);
            return Task.FromResult(new BrokerResponse(
                BrokerCommandHandler.ProtocolVersion,
                request.RequestId,
                BrokerResponseStatus.Succeeded,
                GameAccountId: "1002",
                GameUsername: "player02",
                GamePassword: "0123456789ABCDEF"));
        }
    }
}
