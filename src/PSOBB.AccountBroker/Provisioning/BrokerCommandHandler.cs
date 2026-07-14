using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Security;
using System.Security.Cryptography;
using System.Text;

namespace PSOBB.AccountBroker.Provisioning;

public sealed class BrokerCommandHandler(
    INewservAccountGateway gateway,
    IGamePasswordGenerator passwordGenerator,
    IIdempotencyStore idempotencyStore,
    ILogger<BrokerCommandHandler> logger)
{
    public const int ProtocolVersion = 1;

    public async Task<BrokerResponse> HandleAsync(
        BrokerRequest request,
        CancellationToken cancellationToken)
    {
        var validationError = Validate(request);
        if (validationError is not null)
        {
            return Reject(request.RequestId, validationError);
        }

        // Status/readiness checks are read-only and should not grow the durable
        // idempotency database under polling or unauthenticated readiness probes.
        if (request.Operation is BrokerOperation.GetProvisioningStatus)
        {
            return await GetStatusAsync(request, cancellationToken);
        }

        var begin = idempotencyStore.TryBegin(request.RequestId, Fingerprint(request));
        if (begin.Status is IdempotencyBeginStatus.Conflict)
        {
            return Reject(request.RequestId, "request_id_conflict");
        }

        if (begin.Status is IdempotencyBeginStatus.OutcomeUnknown)
        {
            return OutcomeUnknown(request.RequestId);
        }

        if (begin.Status is IdempotencyBeginStatus.InProgress)
        {
            return new(
                ProtocolVersion,
                request.RequestId,
                BrokerResponseStatus.InProgress,
                ErrorCode: "request_in_progress");
        }

        if (begin.Status is IdempotencyBeginStatus.Completed)
        {
            return begin.CompletedResponse! with
            {
                GamePassword = null,
                Replayed = true,
            };
        }

        BrokerResponse response;
        try
        {
            response = request.Operation switch
            {
                BrokerOperation.CreatePlayerAccount =>
                    await CreateAsync(request, cancellationToken),
                BrokerOperation.RotateGamePassword =>
                    await RotateAsync(request, cancellationToken),
                BrokerOperation.DisablePlayerAccount =>
                    await DisableAsync(request, cancellationToken),
                _ => Reject(request.RequestId, "operation_not_allowed"),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            idempotencyStore.MarkOutcomeUnknown(request.RequestId);
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                "Account broker request {RequestId} failed for operation {Operation} " +
                "with exception type {ExceptionType}.",
                request.RequestId,
                request.Operation,
                exception.GetType().Name);
            idempotencyStore.MarkOutcomeUnknown(request.RequestId);
            return OutcomeUnknown(request.RequestId);
        }

        idempotencyStore.Complete(request.RequestId, response.WithoutSecret());
        return response;
    }

    private async Task<BrokerResponse> CreateAsync(
        BrokerRequest request,
        CancellationToken cancellationToken)
    {
        var password = passwordGenerator.Generate();
        var result = await gateway.CreatePlayerAccountAsync(
            request.RequestId,
            request.PortalUserId!, request.GameUsername!, password, cancellationToken);
        return new(
            ProtocolVersion,
            request.RequestId,
            BrokerResponseStatus.Succeeded,
            GameAccountId: result.GameAccountId,
            GameUsername: result.GameUsername,
            GamePassword: password);
    }

    private async Task<BrokerResponse> RotateAsync(
        BrokerRequest request,
        CancellationToken cancellationToken)
    {
        var password = passwordGenerator.Generate();
        var result = await gateway.RotateGamePasswordAsync(
            request.RequestId,
            request.GameUsername!, password, cancellationToken);
        return new(
            ProtocolVersion,
            request.RequestId,
            BrokerResponseStatus.Succeeded,
            GameAccountId: result.GameAccountId,
            GameUsername: result.GameUsername,
            GamePassword: password);
    }

    private async Task<BrokerResponse> DisableAsync(
        BrokerRequest request,
        CancellationToken cancellationToken)
    {
        var result = await gateway.DisablePlayerAccountAsync(
            request.RequestId,
            request.GameUsername!, cancellationToken);
        return new(
            ProtocolVersion,
            request.RequestId,
            BrokerResponseStatus.Succeeded,
            GameAccountId: result.GameAccountId,
            GameUsername: result.GameUsername);
    }

    private async Task<BrokerResponse> GetStatusAsync(
        BrokerRequest request,
        CancellationToken cancellationToken)
    {
        if (request.TargetRequestId is null)
        {
            return gateway.IsReady
                ? new(ProtocolVersion, request.RequestId, BrokerResponseStatus.Succeeded)
                : new(
                    ProtocolVersion,
                    request.RequestId,
                    BrokerResponseStatus.Failed,
                    ErrorCode: "backend_unavailable");
        }

        var targetRequestId = request.TargetRequestId!.Value;
        var target = idempotencyStore.Lookup(targetRequestId);
        if (target.Status is IdempotencyBeginStatus.OutcomeUnknown)
        {
            NewservOperationStatus gatewayStatus;
            try
            {
                gatewayStatus = await gateway.GetOperationStatusAsync(
                    targetRequestId, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(
                    "Could not resolve unknown operation {RequestId}; gateway returned {ExceptionType}.",
                    targetRequestId,
                    exception.GetType().Name);
                return OutcomeUnknown(request.RequestId);
            }

            var resolved = gatewayStatus.State switch
            {
                NewservOperationState.Succeeded => new BrokerResponse(
                    ProtocolVersion,
                    targetRequestId,
                    BrokerResponseStatus.Succeeded,
                    GameAccountId: gatewayStatus.GameAccountId,
                    GameUsername: gatewayStatus.GameUsername),
                NewservOperationState.Failed => new BrokerResponse(
                    ProtocolVersion,
                    targetRequestId,
                    BrokerResponseStatus.Failed,
                    ErrorCode: gatewayStatus.ErrorCode ?? "operation_failed"),
                NewservOperationState.InProgress => new BrokerResponse(
                    ProtocolVersion,
                    request.RequestId,
                    BrokerResponseStatus.InProgress,
                    ErrorCode: "request_in_progress"),
                _ => OutcomeUnknown(request.RequestId),
            };

            if (gatewayStatus.State is NewservOperationState.Succeeded or
                NewservOperationState.Failed)
            {
                idempotencyStore.Complete(targetRequestId, resolved.WithoutSecret());
                return resolved with { RequestId = request.RequestId, Replayed = true };
            }

            return resolved;
        }

        return target.Status switch
        {
            IdempotencyBeginStatus.InProgress => new(
                ProtocolVersion,
                request.RequestId,
                BrokerResponseStatus.InProgress),
            IdempotencyBeginStatus.Completed => target.CompletedResponse! with
            {
                RequestId = request.RequestId,
                GamePassword = null,
                Replayed = true,
            },
            _ => new(
                ProtocolVersion,
                request.RequestId,
                BrokerResponseStatus.Rejected,
                ErrorCode: "target_request_not_found"),
        };
    }

    private static string? Validate(BrokerRequest request)
    {
        if (request.ProtocolVersion != ProtocolVersion)
        {
            return "unsupported_protocol";
        }

        if (request.RequestId == Guid.Empty)
        {
            return "invalid_request_id";
        }

        if (!Enum.IsDefined(request.Operation))
        {
            return "operation_not_allowed";
        }

        if (request.Operation is BrokerOperation.GetProvisioningStatus)
        {
            return request.TargetRequestId == Guid.Empty
                ? "invalid_target_request_id"
                : null;
        }

        if (!GameUsernamePolicy.IsValid(request.GameUsername))
        {
            return "invalid_game_username";
        }

        if (request.Operation is BrokerOperation.CreatePlayerAccount &&
            (string.IsNullOrWhiteSpace(request.PortalUserId) || request.PortalUserId.Length > 64))
        {
            return "invalid_portal_user_id";
        }

        return null;
    }

    private static BrokerResponse Reject(Guid requestId, string errorCode) => new(
        ProtocolVersion,
        requestId,
        BrokerResponseStatus.Rejected,
        ErrorCode: errorCode);

    private static BrokerResponse OutcomeUnknown(Guid requestId) => new(
        ProtocolVersion,
        requestId,
        BrokerResponseStatus.OutcomeUnknown,
        ErrorCode: "operation_outcome_unknown",
        Replayed: true);

    private static string Fingerprint(BrokerRequest request)
    {
        var canonical = string.Join(
            '\u001f',
            request.ProtocolVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ((int)request.Operation).ToString(System.Globalization.CultureInfo.InvariantCulture),
            request.PortalUserId ?? string.Empty,
            request.GameUsername ?? string.Empty,
            request.TargetRequestId?.ToString("D") ?? string.Empty);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
