# PSOBB Modernization Project

A Windows development project for improving Phantasy Star Online Blue Burst while preserving a verified native-game baseline.

The project includes client graphics and gameplay modules, a launcher, account-service foundations, server build patches, configuration, tests, and backup/recovery tools. Proprietary client assets and mutable player data are supplied separately.

## Status

Active development. Stable Native is the accepted recovery baseline. The isolated CombatCanary has recorded native-gameplay acceptance, while final baseline closure and newer gameplay observation work remain gated.

Graphics candidates, quality-of-life changes, and modern combat features have separate acceptance requirements. Modern hotbar and control behavior remain roadmap work. The account portal is a foundation with explicit deployment blockers, not a ready public service.

Read the [implementation ledger](docs/COMBAT-IMPLEMENTATION-LEDGER.md) for accepted checkpoints and limitations. Build success or source implementation alone does not establish gameplay acceptance.

## Components

- [ClientSafety](src/PSOBB.ClientSafety/README.md): shared exact-client checks and reversible native changes
- [Gameplay](src/PSOBB.Gameplay/README.md): passive combat observation and the foundation for future input/hotbar work
- [Enhancement](src/PSOBB.Enhancement/README.md): Direct3D 8 presentation experiments
- [LargeAssets](src/PSOBB.LargeAssets/README.md): an exact-client-gated asset-size extension
- [Launcher](src/PSOBB.Launcher/README.md): profile selection, file validation, and safe launch/stop controls
- [AccountBroker](src/PSOBB.AccountBroker/README.md) and [Portal](src/PSOBB.Portal/README.md): constrained account provisioning and invite-only service foundations
- [Server patches](patches/newserv/): ordered changes for the pinned newserv build

## Start developing

1. Read the [architecture](docs/ARCHITECTURE.md) and the relevant component guide.
2. Use the .NET SDK selected by [global.json](global.json) for managed projects. Native modules use their CMake configuration and build manifests.
3. Run the component's source tests before the applicable isolated acceptance procedure.

```powershell
dotnet build .\PSOBB.slnx -c Release
dotnet test .\PSOBB.slnx -c Release
```

These commands cover managed projects. Native builds and in-game acceptance are separate.

## Documentation

- [Development roadmap](docs/COMBAT-MODERNIZATION.md)
- [Gameplay acceptance](docs/COMBAT-ACCEPTANCE.md) and [graphics acceptance](docs/GRAPHICS-ACCEPTANCE.md)
- [Quality-of-life matrix](docs/QOL-MATRIX.md)
- [Build reproducibility](docs/COMBAT-CANARY-BUILD.md)
- [Setup, maintenance, and recovery](docs/OPERATIONS.md)
- [Release and deployment gates](docs/PRODUCTION-GATES.md)

## Safety and licensing

Client changes require the exact supported executable, expected bytes, exclusive ownership, and verified rollback. Keep Stable and CombatCanary isolated, and stop both before publication or restore work.

Keep credentials, accounts, saves, logs, captures, private assets, and generated binaries out of Git. Source availability does not grant rights to proprietary game content. Follow each component's license and third-party notices; a distributable release requires the separate production gates.
