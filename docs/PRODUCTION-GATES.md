# Production Gates

No provider or public-network mutation is authorized by the local setup.
Before deployment, all of the following must be supplied and approved:

- Dedicated Windows host/provider, region, budget, and static IPv4
- Final server name and hostname/domain
- Provider and Windows firewall rules derived from proven BB listeners
- Key-authenticated administrative access and source-address allowlist
- TLS certificate mechanism for the future portal
- Encrypted off-host backup destination and tested recovery key
- Monitoring/alert destination and incident owner
- Code-signing and manifest-signing key custody
- Explicit approval of portal runtime/packages and any email/anti-abuse provider
- Reviewed, request-ID-aware atomic newserv account adapter and initial EF Core migration
- Replacement of the local-acceptance release key plus Authenticode signing

Public launch remains invite-only. Open registration, the home router, public
RDP/SMB, newserv HTTP, and database ports are outside the approved boundary.
