# PSOBB Account Broker

A Windows service that provides the project's constrained game-account interface over an access-controlled named pipe.

The contract supports exactly four typed operations: `CreatePlayerAccount`, `RotateGamePassword`, `DisablePlayerAccount`, and `GetProvisioningStatus`. It accepts no arbitrary command or shell payload.

## Deployment status

The checked-in `UnconfiguredNewservAccountGateway` is deliberately not ready. A reviewed, request-ID-aware adapter for atomic newserv account operations is required before provisioning can work.

That adapter must enforce unprivileged player accounts, durable game-side idempotency, and rollback of partial creation. It must not expose newserv stdin, its HTTP API, or shell execution.

## Configuration and safety

- Set `AccountBrokerPipe:AllowedClientSid` to the dedicated portal identity. Missing, broad, or invalid identities block startup.
- Keep portal and broker identities separate. The pipe uses a protected DACL, first-instance ownership, bounded messages, and connection deadlines.
- Store SQLite receipts at `ReceiptStore:DatabasePath`, using an absolute path protected for the broker identity in Production.
- Receipts bind each request ID to its SHA-256 fingerprint. Completed receipts expire according to retention settings; unresolved receipts are never pruned automatically.

Blue Burst passwords support 1–16 ASCII alphanumeric characters. The broker generates 16-character Crockford base32 passwords and returns them once. Receipts never retain the password; retries return status only. Custom portal password input remains unimplemented.

Cancellation after dispatch or interrupted work is recorded as `operation_outcome_unknown`, never replayed automatically. Resolving it requires the real adapter to query or resume the original request. Confirmed creation with a lost password requires rotation.

See [the gateway contract](Provisioning/INewservAccountGateway.cs), [the portal guide](../PSOBB.Portal/README.md), and [deployment gates](../../docs/PRODUCTION-GATES.md).
