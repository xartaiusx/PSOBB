# PSOBB Modernization Project

A Windows development project for improving Phantasy Star Online Blue Burst while preserving a tested native-game setup.

The project includes client graphics and gameplay modules, a launcher, account-service foundations, server build patches, configuration, tests, and backup/recovery tools. Proprietary client assets and mutable player data are supplied separately.

## Status

Active development. Stable Native is the regular recovery setup and has passed native-gameplay checks. CombatCanary is the isolated test setup; it has passed a five-minute native-gameplay scenario, restart, relog, save, and reset checks. A final five-minute in-game check of Stable after those tests is still pending.

The gameplay-observation module is implemented and source-tested; installation, module-load verification, and in-game observation tests remain pending. Modern hotbar and control behavior remain planned. Graphics and quality-of-life changes each require their own in-game checks. The account portal still needs the deployment prerequisites listed in its [component guide](src/PSOBB.Portal/README.md) before it can serve users.

Read the [implementation ledger](docs/COMBAT-IMPLEMENTATION-LEDGER.md) for completed checks and limitations. A successful build or source test alone does not show that a feature works correctly in the game.

## Components

- [ClientSafety](src/PSOBB.ClientSafety/README.md): shared exact-client checks and reversible native changes
- [Gameplay](src/PSOBB.Gameplay/README.md): passive combat observation and the foundation for future input/hotbar work
- [Enhancement](src/PSOBB.Enhancement/README.md): Direct3D 8 presentation experiments
- [LargeAssets](src/PSOBB.LargeAssets/README.md): an asset-size extension limited to one verified client version
- [Launcher](src/PSOBB.Launcher/README.md): profile selection, file validation, and safe launch/stop controls
- [AccountBroker](src/PSOBB.AccountBroker/README.md) and [Portal](src/PSOBB.Portal/README.md): constrained account provisioning and invite-only service foundations
- [Server patches](patches/newserv/): ordered changes for the pinned newserv build

## Start developing

1. Read the [architecture](docs/ARCHITECTURE.md) and the relevant component guide.
2. Use the .NET SDK selected by [global.json](global.json) for managed projects. Native modules use their CMake configuration and build manifests.
3. Run the component's source tests before its documented isolated in-game checks.

```powershell
dotnet build .\PSOBB.slnx -c Release
dotnet test .\PSOBB.slnx -c Release
```

These commands cover managed projects. Native builds and in-game checks are separate.

## Documentation

- [Development roadmap](docs/COMBAT-MODERNIZATION.md)
- [Gameplay acceptance](docs/COMBAT-ACCEPTANCE.md) and [graphics acceptance](docs/GRAPHICS-ACCEPTANCE.md)
- [Quality-of-life matrix](docs/QOL-MATRIX.md)
- [Build reproducibility](docs/COMBAT-CANARY-BUILD.md)
- [Setup, maintenance, and recovery](docs/OPERATIONS.md)
- [Release and deployment requirements](docs/PRODUCTION-GATES.md)

## Safety and licensing

Client changes require the exact supported executable, expected bytes, exclusive ownership, and verified rollback. Keep Stable and CombatCanary isolated, and stop both before installing changes or restoring files.

Keep credentials, accounts, saves, logs, captures, private assets, and generated binaries out of Git. Source availability does not grant rights to proprietary game content. Follow each component's license and third-party notices; a distributable release must meet the separate [release requirements](docs/PRODUCTION-GATES.md).
