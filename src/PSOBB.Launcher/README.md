# PSOBB Launcher

A WPF launcher for Windows, targeting .NET 10. It selects supported profiles, verifies installed files, and delegates launch/stop actions to allowlisted project scripts.

It does not download or redistribute game assets, request or store game passwords, or provision accounts.

## Build and test

From the repository root with the SDK selected by [global.json](../../global.json):

```powershell
dotnet build .\src\PSOBB.Launcher\PSOBB.Launcher.csproj -c Release
dotnet test .\tests\PSOBB.Launcher.Tests\PSOBB.Launcher.Tests.csproj -c Release
```

The launcher has no production NuGet dependencies. Tests use Microsoft Test SDK and MSTest.

## Verification model

- Strict schema-v1 JSON and semantic validation precede manifest use.
- Signed loading verifies ECDSA P-256/SHA-256 over the exact bytes subsequently parsed. The sibling `.sig` file contains a base64-encoded 64-byte IEEE P1363 signature.
- A trusted `release-public-key.pem` beside the executable makes a missing or invalid signature fatal. Without a trusted key, the UI labels the manifest `unsigned local`; this is development-only.
- Every installed artifact and declared imported base file is SHA-256 checked immediately before launch.
- Destinations must be safe relative Windows paths below the selected root. Traversal, alternate streams, reserved names, trailing dots/spaces, and reparse points are rejected.
- Optional source URLs must use HTTPS. Acquisition, extraction, atomic installation, and private-key custody belong to the release process.

See the [manifest example](../../config/release-manifest.example.json) and [models](Models/ReleaseManifest.cs). Production packages require a trusted packaged public key and signing; never use an untrusted installation tree.

## Launch behavior

The launcher derives the repository and its nested `PSOBB-Runtime` from its installation. `--runtime-root` and `PSOBB_RUNTIME_ROOT` are assertions of that exact location, not arbitrary overrides.

Stable is the default. CombatCanary must be selected explicitly and uses its separately sealed Native client. It never reads or rewrites Stable's graphics selection. Stable and CombatCanary must not run concurrently.

Only materialized, verified profiles can launch. Private HD and renderer profiles have additional exact configuration and file-hash requirements; CAS profiles are evidence-only and cannot be selected for normal play. Private visual assets are never valid public release payloads.

Lifecycle checks bind status to the exact executable, process creation identity, profile, and process-owned loopback listeners. Switching profiles invalidates stale displayed status. Health checks use declared IPv4 loopback ports only.

## Command line

Supply one operation at a time:

```powershell
PSOBB.Launcher.exe --safe-play
PSOBB.Launcher.exe --start-server
PSOBB.Launcher.exe --stop-client
PSOBB.Launcher.exe --stop-all
PSOBB.Launcher.exe --play --server-environment combat-canary --preserve-foreground
```

`--stop-server` refuses while an approved client is active. `--stop-all` closes the client before requesting authenticated server shutdown. Closing the launcher window does not stop either process.

The three supported shortcuts start the server, safely stop the session, or play the selected profile. A second interactive launcher instance exits without changing either process. Account and credential data are forbidden in launcher or shortcut arguments.

See [the setup and lifecycle guide](../../docs/OPERATIONS.md) for installation, profile-specific commands, and recovery. Diagnostics redact private identifiers and paths. Public deployment remains subject to [production gates](../../docs/PRODUCTION-GATES.md).
