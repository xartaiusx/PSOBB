# PSOBB.Gameplay

`PSOBB.Gameplay.asi` is the exact-client-gated owner for future native combat,
focused input, buffering, and hotbar behavior. Version 0.3.0 adds the first
passive exact-59NL adapter to the versioned fixed-layout capability ABI and
fixed-capacity observation buffer. It observes selected native `send_60`
serialization attempts but never dispatches an action or synthetic packet.

The module remains disabled when `PSOBB.Gameplay.ini` is absent or when its
`[Gameplay]` section does not explicitly set `Enabled=1`. `Enabled=1` with
`Observation=0` performs exact file-hash and loaded-PE verification only.
Observation additionally requires `Observation=1`, the tracked 11-byte
callsite digest, a permanently pinned Gameplay module, and exclusive ownership
of the exact call instruction. Any mismatch leaves the adapter inert.

The adapter atomically replaces only the aligned four-byte relative operand of
one native `CALL`; it never changes page protection. Its wrapper invokes the
exact original copy target once and then retains only the first four-byte
`G_ClientIDHeader` for commands `0x43` through `0x48`. Records therefore prove
a `send_60` serialization attempt, not server receipt, attack type, damage, or
legal combo timing. The hotbar slots remain empty.

This source slice performs no automatic initialization from `DllMain`. The
conventional deferred `InitializeASI` loader adapter is integrated and
source-tested; it delegates to the same idempotent
`PSOBBGameplay_Initialize` preflight after the module has loaded. Runtime
publication, exact loader-overlay integration, runtime-load proof, and live
observation acceptance remain separate gates.

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

`PSOBBGameplay_Rollback` first disables publication, atomically restores and
flushes the original call target, then resets the ring only after the callback
and consumer are quiescent. An active callback or drain produces a retryable
failure; foreign callsite mutation fails closed and is never overwritten.
Rollback lifecycle calls are serialized without waiting; a concurrent caller
returns false without changing the published state or reason.
