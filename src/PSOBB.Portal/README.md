# PSOBB Invite Portal

This is the invite-only account foundation for the planned Windows production
deployment. It uses ASP.NET Core Identity with SQLite for portal credentials and
keeps portal and Blue Burst identities separate.

## Security properties

- Invite values contain 256 random bits, expire after 24 hours, and are stored
  only as SHA-256 hashes. Redemption is an atomic one-time database update.
- Portal passwords require at least 15 characters and complexity; failed login
  attempts are locked out and authentication endpoints are rate limited.
- Cookies use the `__Host-` prefix, `Secure`, `HttpOnly`, and `SameSite=Strict`.
  Mutating endpoints require an antiforgery header obtained from
  `GET /security/csrf`.
- HSTS and restrictive baseline browser headers are enabled outside Development.
- Administrative invite creation requires the `Administrator` role and an
  authentication cookie bearing `amr=mfa`. Password-only administrators cannot
  issue invitations.
- Game usernames are exactly 3–16 lowercase ASCII letters/digits. Newserv's game
  password compatibility range is 1–16 ASCII letters/digits (12–16 recommended),
  but custom portal input is not implemented yet: the broker currently generates
  a 16-character value. Passwords are returned once and are absent from every
  portal entity, provisioning receipt, and audit record.
- The broker is reached only through its local named pipe. Portal code has no
  newserv shell or filesystem interface. The pipe owner SID, response protocol,
  request correlation, username, and one-time-secret shape are validated.
- Invite redemption checks broker/backend readiness before touching the invite.
  An ambiguous lost response remains `Pending`; authenticated users can call
  `POST /account/provisioning/reconcile`, which confirms the original receipt
  and rotates the lost one-time password.
- Password rotation, disable, reconciliation, and invite issuance require an
  authentication ceremony no more than five minutes old.

## Required configuration

Override these settings through protected environment/configuration sources:

- `ConnectionStrings__Portal`: absolute path to the protected SQLite database.
- `AccountBroker__PipeName`: must match the broker service.
- `AccountBroker__ExpectedBrokerSid`: dedicated broker service SID.
- `Security__AuditHmacKey`: a random secret used to pseudonymize source IPs.
- `Security__DataProtectionKeysPath`: absolute protected key-ring directory;
  keys are persisted and protected with user-scoped Windows DPAPI.
- `Security__CompromisedPasswordDatabasePath`: absolute path to a reviewed,
  read-only SQLite database containing indexed uppercase SHA-1 hashes in
  `compromised_passwords(sha1 TEXT PRIMARY KEY)`. This supports large offline
  breached-password corpora without loading them into memory; passwords never
  leave the machine. Startup runs SQLite `quick_check` and validates the indexed
  schema before accepting traffic.
- `Hosting__Mode`: `DirectTls`, or `ReverseProxy` together with explicit
  `Hosting__KnownProxies` addresses.
- `DatabaseInitialization__Mode=Migrate` and an absolute database path.

The checked-in empty audit HMAC value intentionally disables address retention;
it is not a production secret. Do not put secrets in `appsettings.json`.

## Deployment gates and limitations

- `EnsureCreated` bootstraps only the Development database. Production startup
  rejects it and also rejects `Migrate` until at least one reviewed EF migration
  exists. No production migration is included yet, so public readiness fails
  closed by design.
- Seed the first Identity administrator offline, enroll an authenticator, and
  verify the resulting MFA login before issuing invites. There is deliberately
  no public bootstrap or open-registration route.
- The broker's newserv gateway is deliberately unconfigured. Registration can
  not consume an invite until the separately reviewed atomic newserv adapter is
  installed and reports ready.
- SQLite is appropriate for the invite-first single-host deployment. Revisit the
  database choice before multi-host or high-concurrency operation.
- Provisioning requests are a durable reconciliation seam and account
  operations are serialized within the single portal process with optimistic
  concurrency fields. A multi-host transactional outbox/lease implementation is
  still required before scaling beyond one portal process.
- The offline password corpus, first administrator, MFA enrollment, migrations,
  service-account ACLs, trusted TLS endpoint, and real newserv adapter are
  deployment inputs, not generated secrets or silently relaxed defaults.
