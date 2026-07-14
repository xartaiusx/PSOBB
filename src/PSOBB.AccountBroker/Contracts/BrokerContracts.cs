using System.Text.Json.Serialization;

namespace PSOBB.AccountBroker.Contracts;

[JsonConverter(typeof(JsonStringEnumConverter<BrokerOperation>))]
public enum BrokerOperation
{
    CreatePlayerAccount,
    RotateGamePassword,
    DisablePlayerAccount,
    GetProvisioningStatus,
}

[JsonConverter(typeof(JsonStringEnumConverter<BrokerResponseStatus>))]
public enum BrokerResponseStatus
{
    Succeeded,
    Accepted,
    InProgress,
    OutcomeUnknown,
    Rejected,
    Failed,
}

public sealed record BrokerRequest(
    int ProtocolVersion,
    Guid RequestId,
    BrokerOperation Operation,
    string? PortalUserId = null,
    string? GameUsername = null,
    Guid? TargetRequestId = null);

public sealed record BrokerResponse(
    int ProtocolVersion,
    Guid RequestId,
    BrokerResponseStatus Status,
    string? ErrorCode = null,
    string? GameAccountId = null,
    string? GameUsername = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GamePassword = null,
    bool Replayed = false)
{
    public bool IsSuccess => Status is BrokerResponseStatus.Succeeded
        or BrokerResponseStatus.Accepted;

    public BrokerResponse WithoutSecret(BrokerResponseStatus? status = null) =>
        this with { Status = status ?? Status, GamePassword = null };
}
