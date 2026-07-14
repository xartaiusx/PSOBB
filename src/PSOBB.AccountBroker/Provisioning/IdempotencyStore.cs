using System.Collections.Concurrent;
using PSOBB.AccountBroker.Contracts;

namespace PSOBB.AccountBroker.Provisioning;

public enum IdempotencyBeginStatus
{
    Acquired,
    InProgress,
    Completed,
    NotFound,
    Conflict,
    OutcomeUnknown,
}

public sealed record IdempotencyBeginResult(
    IdempotencyBeginStatus Status,
    BrokerResponse? CompletedResponse = null);

public interface IIdempotencyStore
{
    IdempotencyBeginResult TryBegin(Guid requestId, string requestFingerprint);
    IdempotencyBeginResult Lookup(Guid requestId);
    void MarkOutcomeUnknown(Guid requestId);
    void Complete(Guid requestId, BrokerResponse responseWithoutSecret);
}

public sealed class InMemoryIdempotencyStore : IIdempotencyStore
{
    private sealed class Entry
    {
        public required string RequestFingerprint { get; init; }
        public BrokerResponse? CompletedResponse { get; set; }
        public bool OutcomeUnknown { get; set; }
    }

    private readonly ConcurrentDictionary<Guid, Entry> entries = new();

    public IdempotencyBeginResult TryBegin(Guid requestId, string requestFingerprint)
    {
        var candidate = new Entry { RequestFingerprint = requestFingerprint };
        var entry = entries.GetOrAdd(requestId, candidate);
        if (ReferenceEquals(candidate, entry))
        {
            return new(IdempotencyBeginStatus.Acquired);
        }

        lock (entry)
        {
            if (!string.Equals(
                    entry.RequestFingerprint, requestFingerprint, StringComparison.Ordinal))
            {
                return new(IdempotencyBeginStatus.Conflict);
            }

            if (entry.OutcomeUnknown)
            {
                return new(IdempotencyBeginStatus.OutcomeUnknown);
            }

            return entry.CompletedResponse is null
                ? new(IdempotencyBeginStatus.InProgress)
                : new(IdempotencyBeginStatus.Completed, entry.CompletedResponse);
        }
    }

    public IdempotencyBeginResult Lookup(Guid requestId)
    {
        if (!entries.TryGetValue(requestId, out var entry))
        {
            return new(IdempotencyBeginStatus.NotFound);
        }

        lock (entry)
        {
            if (entry.OutcomeUnknown)
            {
                return new(IdempotencyBeginStatus.OutcomeUnknown);
            }

            return entry.CompletedResponse is null
                ? new(IdempotencyBeginStatus.InProgress)
                : new(IdempotencyBeginStatus.Completed, entry.CompletedResponse);
        }
    }

    public void Complete(Guid requestId, BrokerResponse responseWithoutSecret)
    {
        if (responseWithoutSecret.GamePassword is not null)
        {
            throw new ArgumentException(
                "Idempotency receipts must never retain a game password.",
                nameof(responseWithoutSecret));
        }

        if (!entries.TryGetValue(requestId, out var entry))
        {
            throw new InvalidOperationException("The request was not acquired.");
        }

        lock (entry)
        {
            entry.CompletedResponse = responseWithoutSecret;
            entry.OutcomeUnknown = false;
        }
    }

    public void MarkOutcomeUnknown(Guid requestId)
    {
        if (!entries.TryGetValue(requestId, out var entry))
        {
            throw new InvalidOperationException("The request was not acquired.");
        }

        lock (entry)
        {
            entry.CompletedResponse = null;
            entry.OutcomeUnknown = true;
        }
    }
}
