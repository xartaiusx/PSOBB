# PSOBB Account Broker

This Windows service is the only component allowed to provision game accounts.
It listens on an ACL-restricted local named pipe and accepts exactly four typed
operations: `CreatePlayerAccount`, `RotateGamePassword`,
`DisablePlayerAccount`, and `GetProvisioningStatus`. There is no arbitrary
command or shell field in the wire contract.

Set `AccountBrokerPipe:AllowedClientSid` to the SID of the dedicated portal
service identity before starting the service. Startup fails closed when the SID
is absent, broad, or invalid. The pipe DACL is protected, the broker owns the
first pipe instance, messages are length-bounded, and each connection has a
deadline. Do not run the portal and broker under a shared production identity.

Blue Burst accepts game passwords from 1 through 16 ASCII alphanumeric
characters. The broker generates 16-character Crockford base32 values by
default. Custom portal password input is not implemented yet; when it is added,
12-16 characters will be the recommended range. A successful create or
rotation response contains the generated password once. Idempotency receipts
deliberately discard it; a repeated request returns completion status without
the password.

Idempotency receipts are stored in SQLite at `ReceiptStore:DatabasePath`, bind
the request ID to a SHA-256 request fingerprint, and survive service restarts.
The receipt contains only the terminal response and never the game password.
Use an absolute, broker-identity-protected path in Production. Completed
receipts rotate after the configured retention period; unresolved receipts are
never pruned automatically.

## Deliberate deployment gate

`UnconfiguredNewservAccountGateway` reports not-ready and always fails. Replace it only with the
reviewed adapter for the planned atomic newserv operations. The adapter must use
typed calls, use the supplied request ID for durable game-side idempotency,
enforce no-flags player accounts, roll back partial creation, and
must not expose newserv stdin, its HTTP API, or arbitrary shell execution.

Cancellation after a gateway call is recorded as `operation_outcome_unknown`.
A receipt left in progress by a process crash is converted to that explicit
unknown state at the next startup and is never replayed automatically. The
portal reconciliation flow can query the receipt; resolving an unknown outcome
still requires the real request-ID-aware adapter to query/resume the atomic
newserv operation. After confirmed creation, reconciliation rotates the lost
one-time password. A real adapter remains the hard production/readiness gate.
