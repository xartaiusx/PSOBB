using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;
using PSOBB.AccountBroker.Security;
using PSOBB.Portal.Broker;
using PSOBB.Portal.Data;
using PSOBB.Portal.Security;

namespace PSOBB.Portal.Accounts;

public sealed record InviteRedemptionResult(
    bool Accepted,
    bool Provisioned,
    bool ServiceUnavailable = false,
    bool Pending = false,
    string? GameUsername = null,
    string? GamePassword = null);

public sealed record GameCredentialResult(
    bool Succeeded,
    string? GameUsername = null,
    string? GamePassword = null);

public sealed record ProvisioningReconciliationResult(
    bool Succeeded,
    bool Pending,
    string? GameUsername = null,
    string? GamePassword = null);

public sealed class PortalAccountService(
    PortalDbContext database,
    UserManager<PortalUser> userManager,
    InviteTokenService inviteTokens,
    IAccountBrokerClient broker,
    AuditWriter audit,
    AccountOperationLock operationLock,
    TimeProvider timeProvider)
{
    public async Task<InviteRedemptionResult> RedeemInviteAsync(
        string inviteToken,
        string email,
        string portalPassword,
        string gameUsername,
        string? sourceAddress,
        CancellationToken cancellationToken)
    {
        var correlationId = Guid.NewGuid();
        if (!await IsBrokerReadyAsync(cancellationToken))
        {
            await audit.WriteAsync(
                correlationId, "invite_redeem", "service_unavailable",
                sourceAddress: sourceAddress,
                cancellationToken: cancellationToken);
            return new(false, false, ServiceUnavailable: true);
        }

        if (!GameUsernamePolicy.IsValid(gameUsername) ||
            string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(portalPassword))
        {
            await audit.WriteAsync(
                correlationId, "invite_redeem", "rejected",
                targetId: gameUsername, sourceAddress: sourceAddress,
                cancellationToken: cancellationToken);
            return new(false, false);
        }

        var now = timeProvider.GetUtcNow();
        var portalUser = new PortalUser
        {
            Id = Guid.NewGuid(),
            UserName = email.Trim(),
            Email = email.Trim(),
            CreatedAt = now,
        };
        var requestId = Guid.NewGuid();

        await using var accountLock = await operationLock.AcquireAsync(
            portalUser.Id, cancellationToken);
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        var consumed = await inviteTokens.ConsumeAsync(
            inviteToken, portalUser.Id, cancellationToken);
        if (!consumed)
        {
            await transaction.RollbackAsync(cancellationToken);
            await audit.WriteAsync(
                correlationId, "invite_redeem", "rejected",
                targetId: gameUsername, sourceAddress: sourceAddress,
                cancellationToken: cancellationToken);
            return new(false, false);
        }

        var createResult = await userManager.CreateAsync(portalUser, portalPassword);
        if (!createResult.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            await audit.WriteAsync(
                correlationId, "invite_redeem", "rejected",
                targetId: gameUsername, sourceAddress: sourceAddress,
                cancellationToken: cancellationToken);
            return new(false, false);
        }

        database.GameAccountLinks.Add(new GameAccountLink
        {
            Id = Guid.NewGuid(),
            PortalUserId = portalUser.Id,
            GameUsername = gameUsername,
            State = GameAccountState.Provisioning,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.ProvisioningRequests.Add(new ProvisioningRequest
        {
            RequestId = requestId,
            PortalUserId = portalUser.Id,
            Operation = BrokerOperation.CreatePlayerAccount.ToString(),
            State = ProvisioningState.Pending,
            CreatedAt = now,
            UpdatedAt = now,
        });
        try
        {
            // Audit and dispatch intent commit atomically with the consumed invite.
            // An audit-storage failure therefore cannot strand an accepted user.
            await audit.WriteAsync(
                correlationId, "invite_redeem", "accepted", portalUser.Id,
                gameUsername, sourceAddress, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(false, false);
        }

        BrokerResponse response;
        try
        {
            response = await broker.SendAsync(new(
                BrokerCommandHandler.ProtocolVersion,
                requestId,
                BrokerOperation.CreatePlayerAccount,
                portalUser.Id.ToString("D"),
                gameUsername), cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            await RecordBrokerPendingAsync(
                portalUser.Id, requestId, "broker_outcome_unknown", cancellationToken);
            return new(true, false, Pending: true, GameUsername: gameUsername);
        }

        var request = await database.ProvisioningRequests.FindAsync([requestId], cancellationToken);
        var link = await database.GameAccountLinks.SingleAsync(
            value => value.PortalUserId == portalUser.Id, cancellationToken);
        if (response.Status == BrokerResponseStatus.Succeeded &&
            response.GamePassword is not null)
        {
            request!.State = ProvisioningState.Succeeded;
            request.Version++;
            request.UpdatedAt = timeProvider.GetUtcNow();
            link.NewservAccountId = response.GameAccountId;
            link.State = GameAccountState.Active;
            link.Version++;
            link.UpdatedAt = request.UpdatedAt;
            await database.SaveChangesAsync(cancellationToken);
            return new(true, true, GameUsername: gameUsername, GamePassword: response.GamePassword);
        }

        if (response.Status == BrokerResponseStatus.Succeeded)
        {
            request!.State = ProvisioningState.Pending;
            request.ErrorCode = "one_time_secret_unavailable";
            request.Version++;
            request.UpdatedAt = timeProvider.GetUtcNow();
            link.State = GameAccountState.Provisioning;
            link.Version++;
            link.UpdatedAt = request.UpdatedAt;
            await database.SaveChangesAsync(cancellationToken);
            return new(true, false, Pending: true, GameUsername: gameUsername);
        }

        if (response.Status is BrokerResponseStatus.OutcomeUnknown or
            BrokerResponseStatus.InProgress)
        {
            request!.State = ProvisioningState.Pending;
            request.ErrorCode = response.ErrorCode ?? "operation_outcome_unknown";
            request.Version++;
            request.UpdatedAt = timeProvider.GetUtcNow();
            link.State = GameAccountState.Provisioning;
            link.Version++;
            link.UpdatedAt = request.UpdatedAt;
            await database.SaveChangesAsync(cancellationToken);
            return new(true, false, Pending: true, GameUsername: gameUsername);
        }

        request!.State = ProvisioningState.Failed;
        request.ErrorCode = response.ErrorCode ?? "provisioning_failed";
        request.Version++;
        request.UpdatedAt = timeProvider.GetUtcNow();
        link.State = GameAccountState.Failed;
        link.Version++;
        link.UpdatedAt = request.UpdatedAt;
        await database.SaveChangesAsync(cancellationToken);
        return new(true, false, GameUsername: gameUsername);
    }

    public async Task<GameCredentialResult> RotateGamePasswordAsync(
        Guid portalUserId,
        CancellationToken cancellationToken)
    {
        await using var accountLock = await operationLock.AcquireAsync(
            portalUserId, cancellationToken);
        var link = await database.GameAccountLinks.SingleOrDefaultAsync(
            value => value.PortalUserId == portalUserId &&
                value.State == GameAccountState.Active,
            cancellationToken);
        if (link is null)
        {
            return new(false);
        }

        var response = await SendTrackedRequestAsync(
            portalUserId,
            BrokerOperation.RotateGamePassword,
            link.GameUsername,
            cancellationToken);
        var succeeded = response.Status == BrokerResponseStatus.Succeeded &&
            response.GamePassword is not null;
        await audit.WriteAsync(
            response.RequestId, "game_password_rotate", succeeded ? "succeeded" : "failed",
            portalUserId, link.GameUsername, cancellationToken: cancellationToken);
        return succeeded
            ? new(true, link.GameUsername, response.GamePassword)
            : new(false);
    }

    public async Task<bool> DisableGameAccountAsync(
        Guid portalUserId,
        CancellationToken cancellationToken)
    {
        await using var accountLock = await operationLock.AcquireAsync(
            portalUserId, cancellationToken);
        var link = await database.GameAccountLinks.SingleOrDefaultAsync(
            value => value.PortalUserId == portalUserId &&
                value.State == GameAccountState.Active,
            cancellationToken);
        if (link is null)
        {
            return false;
        }

        var response = await SendTrackedRequestAsync(
            portalUserId,
            BrokerOperation.DisablePlayerAccount,
            link.GameUsername,
            cancellationToken);
        if (response.Status != BrokerResponseStatus.Succeeded)
        {
            return false;
        }

        link.State = GameAccountState.Disabled;
        link.Version++;
        link.UpdatedAt = timeProvider.GetUtcNow();
        await database.SaveChangesAsync(cancellationToken);
        await audit.WriteAsync(
            response.RequestId, "game_account_disable", "succeeded",
            portalUserId, link.GameUsername, cancellationToken: cancellationToken);
        return true;
    }

    public async Task<ProvisioningReconciliationResult> ReconcileProvisioningAsync(
        Guid portalUserId,
        CancellationToken cancellationToken)
    {
        await using var accountLock = await operationLock.AcquireAsync(
            portalUserId, cancellationToken);
        var link = await database.GameAccountLinks.SingleOrDefaultAsync(
            value => value.PortalUserId == portalUserId &&
                value.State == GameAccountState.Provisioning,
            cancellationToken);
        var createRequest = await database.ProvisioningRequests
            .Where(value => value.PortalUserId == portalUserId &&
                value.Operation == BrokerOperation.CreatePlayerAccount.ToString() &&
                value.State == ProvisioningState.Pending)
            .OrderByDescending(value => value.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);
        if (link is null || createRequest is null)
        {
            return new(false, false);
        }

        BrokerResponse status;
        try
        {
            status = await broker.SendAsync(new(
                BrokerCommandHandler.ProtocolVersion,
                Guid.NewGuid(),
                BrokerOperation.GetProvisioningStatus,
                TargetRequestId: createRequest.RequestId), cancellationToken);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, true);
        }

        if (status.Status is BrokerResponseStatus.InProgress or
            BrokerResponseStatus.OutcomeUnknown)
        {
            return new(false, true);
        }

        if (status.Status != BrokerResponseStatus.Succeeded || status.GameAccountId is null)
        {
            createRequest.State = ProvisioningState.Failed;
            createRequest.ErrorCode = status.ErrorCode ?? "provisioning_failed";
            createRequest.Version++;
            createRequest.UpdatedAt = timeProvider.GetUtcNow();
            link.State = GameAccountState.Failed;
            link.Version++;
            link.UpdatedAt = createRequest.UpdatedAt;
            await database.SaveChangesAsync(cancellationToken);
            return new(false, false);
        }

        createRequest.State = ProvisioningState.Succeeded;
        createRequest.ErrorCode = null;
        createRequest.Version++;
        createRequest.UpdatedAt = timeProvider.GetUtcNow();
        link.NewservAccountId = status.GameAccountId;
        link.State = GameAccountState.Active;
        link.Version++;
        link.UpdatedAt = createRequest.UpdatedAt;
        await database.SaveChangesAsync(cancellationToken);

        // A status receipt never contains the original one-time secret. Rotate to
        // a new password immediately, then return that new value exactly once.
        var rotated = await SendTrackedRequestAsync(
            portalUserId,
            BrokerOperation.RotateGamePassword,
            link.GameUsername,
            cancellationToken);
        var succeeded = rotated.Status == BrokerResponseStatus.Succeeded &&
            rotated.GamePassword is not null;
        await audit.WriteAsync(
            rotated.RequestId, "provisioning_reconcile",
            succeeded ? "succeeded" : "password_rotation_failed",
            portalUserId, link.GameUsername, cancellationToken: cancellationToken);
        return succeeded
            ? new(true, false, link.GameUsername, rotated.GamePassword)
            : new(false, false);
    }

    private async Task<BrokerResponse> SendTrackedRequestAsync(
        Guid portalUserId,
        BrokerOperation operation,
        string gameUsername,
        CancellationToken cancellationToken)
    {
        var requestId = Guid.NewGuid();
        var now = timeProvider.GetUtcNow();
        var tracked = new ProvisioningRequest
        {
            RequestId = requestId,
            PortalUserId = portalUserId,
            Operation = operation.ToString(),
            State = ProvisioningState.Pending,
            CreatedAt = now,
            UpdatedAt = now,
        };
        database.ProvisioningRequests.Add(tracked);
        await database.SaveChangesAsync(cancellationToken);

        try
        {
            var response = await broker.SendAsync(new(
                BrokerCommandHandler.ProtocolVersion,
                requestId,
                operation,
                GameUsername: gameUsername), cancellationToken);
            tracked.State = response.Status == BrokerResponseStatus.Succeeded
                ? ProvisioningState.Succeeded
                : ProvisioningState.Failed;
            tracked.Version++;
            tracked.ErrorCode = response.ErrorCode;
            tracked.UpdatedAt = timeProvider.GetUtcNow();
            await database.SaveChangesAsync(cancellationToken);
            return response;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            tracked.State = ProvisioningState.Failed;
            tracked.Version++;
            tracked.ErrorCode = "broker_unavailable";
            tracked.UpdatedAt = timeProvider.GetUtcNow();
            await database.SaveChangesAsync(cancellationToken);
            return new(
                BrokerCommandHandler.ProtocolVersion,
                requestId,
                BrokerResponseStatus.Failed,
                "broker_unavailable");
        }
    }

    private async Task RecordBrokerPendingAsync(
        Guid portalUserId,
        Guid requestId,
        string errorCode,
        CancellationToken cancellationToken)
    {
        var request = await database.ProvisioningRequests.FindAsync([requestId], cancellationToken);
        var link = await database.GameAccountLinks.SingleAsync(
            value => value.PortalUserId == portalUserId, cancellationToken);
        request!.State = ProvisioningState.Pending;
        request.ErrorCode = errorCode;
        request.Version++;
        request.UpdatedAt = timeProvider.GetUtcNow();
        link.State = GameAccountState.Provisioning;
        link.Version++;
        link.UpdatedAt = request.UpdatedAt;
        await database.SaveChangesAsync(cancellationToken);
    }

    private async Task<bool> IsBrokerReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            var response = await broker.SendAsync(new(
                BrokerCommandHandler.ProtocolVersion,
                Guid.NewGuid(),
                BrokerOperation.GetProvisioningStatus), cancellationToken);
            return response.Status == BrokerResponseStatus.Succeeded;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
