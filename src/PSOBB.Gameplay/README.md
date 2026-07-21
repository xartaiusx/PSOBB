# PSOBB.Gameplay

`PSOBB.Gameplay.asi` is the exact-client-gated owner for future native combat,
focused input, buffering, and hotbar behavior. The current source slice exposes
the versioned fixed-layout capability ABI and a fixed-capacity observation
buffer, but installs no hook and observes or dispatches no gameplay action.

The module remains disabled when `PSOBB.Gameplay.ini` is absent or when its
`[Gameplay]` section does not explicitly set `Enabled=1`. In this build,
`Enabled=1` can only report `exact_client_ready` after exact file-hash and
loaded-PE checks pass. All feature bits and hotbar slots remain zero/empty.
The observation buffer also remains empty until a separately accepted exact
client adapter supplies native events.

This source slice performs no automatic initialization from `DllMain`. The
conventional deferred `InitializeASI` loader adapter is integrated and
source-tested; it delegates to the same idempotent
`PSOBBGameplay_Initialize` preflight after the module has loaded. Runtime
publication, exact loader-overlay integration, runtime-load proof, and
observation-hook acceptance remain separate gates.

## Build and test

```powershell
Push-Location .\src\PSOBB.Gameplay
cmake --preset x86
cmake --build --preset release --parallel
ctest --preset release
Pop-Location
```

The preset deliberately uses CMake's discovered Visual Studio generator and
requires one that supports the `Win32` platform; it does not pin a
machine-specific Visual Studio version. Acceptance configures from scratch with
`cmake --fresh --preset x86` before using the build and test presets.

The ignored Release artifact is
`src\PSOBB.Gameplay\bin\build-x86\Release\PSOBB.Gameplay.asi`. This source
slice does not deploy or activate it in any runtime.

## Exported ABI

The ASI exports six undecorated x86 functions:

- `InitializeASI`
- `PSOBBGameplay_DrainObservations`
- `PSOBBGameplay_Initialize`
- `PSOBBGameplay_GetCapabilities`
- `PSOBBGameplay_GetVersion`
- `PSOBBGameplay_Rollback`

`GameplayCapabilitiesV1`, `ObservationEventV1`, and `ObservationSnapshotV1`
contain only fixed-size values and arrays. The observation snapshot drains at
most 2,048 ordered events. The fixed ring is single-producer/single-consumer:
the producer binds to its actual Windows thread identity, a second producer
fails closed, and simultaneous drains or reset/drain overlap return without
waiting. Overflow and producer-identity counters saturate at `UINT32_MAX` and
are totals since the last quiescent reset. Event sequence numbers start at one;
after `UINT64_MAX` is emitted, later events are rejected until reset so zero is
never published. No owning pointer or exception crosses the DLL boundary.

Callers initialize `ObservationSnapshotV1::struct_size` to
`sizeof(ObservationSnapshotV1)`. A successful drain destructively consumes the
events published before its acquired write-cursor snapshot. A rejected
concurrent drain leaves the caller's buffer unchanged.

`PSOBBGameplay_Rollback` resets the ring only at a caller-proven
producer-quiescent point. If a drain is active, rollback fails without partially
publishing the rolled-back state and the caller may retry. The current no-hook
slice has no producer, so its observation snapshot remains exact and empty.
