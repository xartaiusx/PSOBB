# PSOBB Invite Portal

An invite-only account-service foundation built with ASP.NET Core Identity and SQLite. Portal credentials and Blue Burst accounts remain separate; game-account changes go through the [Account Broker](../PSOBB.AccountBroker/README.md).

## Status

Public deployment is blocked by design until reviewed EF migrations and a real atomic newserv account adapter are supplied. Neither is included as a working production path.

The first administrator must be created offline and enrolled in MFA. There is no public bootstrap or open-registration route. Multi-host deployment also requires a transactional outbox/lease design beyond the current single-process account serialization.

## Security

- Invites contain 256 random bits, expire after 24 hours, and are stored as SHA-256 hashes. Redemption is atomic and one-time.
- Portal passwords require at least 15 characters and complexity. Login attempts are rate-limited and locked out on repeated failures.
- Cookies use `__Host-`, `Secure`, `HttpOnly`, and `SameSite=Strict`. Mutating requests require an antiforgery header from `GET /security/csrf`.
- Invite issuance requires the Administrator role and an MFA-authenticated cookie.
- Invite issuance, password rotation, disable, and reconciliation require authentication no more than five minutes old.
- Broker responses are checked for identity, protocol, request correlation, username, and secret shape. The portal has no newserv shell or file-access interface.

Game usernames are 3–16 lowercase ASCII letters/digits. The broker currently generates a 16-character game password and returns it once; custom password entry is not implemented. Passwords are never retained in portal entities, receipts, or audit records.

Readiness is checked before consuming an invite. An ambiguous response remains pending; `POST /account/provisioning/reconcile` checks the original receipt and rotates a lost one-time password after confirmed creation.

## Required configuration

Use protected configuration sources for:

- `ConnectionStrings__Portal`: SQLite connection string with an absolute protected database path
- `AccountBroker__PipeName` and `AccountBroker__ExpectedBrokerSid`
- `Security__AuditHmacKey`: random secret for pseudonymized address auditing
- `Security__DataProtectionKeysPath`: protected key directory using Windows user-scoped DPAPI
- `Security__CompromisedPasswordDatabasePath`: reviewed, read-only SQLite corpus with indexed `compromised_passwords(sha1 TEXT PRIMARY KEY)`
- `Hosting__Mode`: `DirectTls` or `ReverseProxy` with explicit `Hosting__KnownProxies`
- `DatabaseInitialization__Mode=Migrate` after reviewed migrations exist

The offline password corpus uses uppercase SHA-1 hashes; startup validates its integrity and schema. Passwords are not sent to an external checking service. The empty checked-in audit HMAC setting disables address retention; never put secrets in `appsettings.json`.

`EnsureCreated` is Development-only. Production rejects it, and `Migrate` fails when no reviewed migration exists. HTTPS, service identities/ACLs, password corpus, MFA, signing, backups, and the real adapter remain deployment prerequisites.

See [production gates](../../docs/PRODUCTION-GATES.md), [database initialization](Data/PortalDatabaseInitializer.cs), and [the project overview](../../README.md).
