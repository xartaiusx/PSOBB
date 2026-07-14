using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;
using PSOBB.AccountBroker.Security;

namespace PSOBB.Portal.Broker;

public sealed class BrokerClientOptions
{
    public const string SectionName = "AccountBroker";
    public string PipeName { get; init; } = "PSOBB.AccountBroker.v1";
    public string ExpectedBrokerSid { get; init; } = string.Empty;
    public int ConnectTimeoutMilliseconds { get; init; } = 3000;
    public int MaxResponseBytes { get; init; } = 16 * 1024;
}

public interface IAccountBrokerClient
{
    Task<BrokerResponse> SendAsync(BrokerRequest request, CancellationToken cancellationToken);
}

public sealed class NamedPipeBrokerClient(
    IOptions<BrokerClientOptions> options,
    IHostEnvironment environment)
    : IAccountBrokerClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public async Task<BrokerResponse> SendAsync(
        BrokerRequest request,
        CancellationToken cancellationToken)
    {
        var value = options.Value;
        await using var pipe = new NamedPipeClientStream(
            ".",
            value.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(value.ConnectTimeoutMilliseconds, cancellationToken);
        ValidateServerIdentity(pipe, value.ExpectedBrokerSid);

        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
        await BrokerWireProtocol.WriteAsync(
            pipe, requestBytes, value.MaxResponseBytes, cancellationToken);
        var responseBytes = await BrokerWireProtocol.ReadAsync(
            pipe, value.MaxResponseBytes, cancellationToken);

        var response = JsonSerializer.Deserialize<BrokerResponse>(responseBytes, JsonOptions)
            ?? throw new InvalidDataException("The broker response was empty.");
        ValidateResponse(request, response);
        return response;
    }

    private void ValidateServerIdentity(NamedPipeClientStream pipe, string configuredSid)
    {
        var expectedSid = string.IsNullOrWhiteSpace(configuredSid) && environment.IsDevelopment()
            ? WindowsIdentity.GetCurrent().User
            : new SecurityIdentifier(configuredSid);
        var security = pipe.GetAccessControl();
        var actualSid = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (expectedSid is null || actualSid is null || !actualSid.Equals(expectedSid))
        {
            throw new UnauthorizedAccessException("The account broker pipe owner is not trusted.");
        }
    }

    private static void ValidateResponse(BrokerRequest request, BrokerResponse response)
    {
        if (response.ProtocolVersion != BrokerCommandHandler.ProtocolVersion ||
            response.RequestId != request.RequestId)
        {
            throw new InvalidDataException("The broker response correlation is invalid.");
        }

        if (request.Operation is not BrokerOperation.GetProvisioningStatus &&
            response.IsSuccess &&
            !string.Equals(response.GameUsername, request.GameUsername, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The broker response username is invalid.");
        }

        var secretExpected = response.Status == BrokerResponseStatus.Succeeded &&
            !response.Replayed &&
            request.Operation is BrokerOperation.CreatePlayerAccount
                or BrokerOperation.RotateGamePassword;
        if (secretExpected != (response.GamePassword is not null))
        {
            throw new InvalidDataException("The broker response secret state is invalid.");
        }

        if (response.GamePassword is { } password &&
            (password.Length != CrockfordGamePasswordGenerator.PasswordLength ||
             password.Any(character =>
                 "0123456789ABCDEFGHJKMNPQRSTVWXYZ".IndexOf(character) < 0)))
        {
            throw new InvalidDataException("The broker response password is invalid.");
        }
    }
}
