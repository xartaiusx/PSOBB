# PSOBB.Gameplay

`PSOBB.Gameplay.asi` is the exact-client-gated owner for future native combat,
focused input, buffering, and hotbar behavior. Version 0.4.0 retains the
passive exact-59NL `send_60` adapter and adds an opt-in, bounded evidence
consumer. It observes selected native serialization attempts but never
dispatches an action or synthetic packet.

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

`DllMain` stores only the module handle. The conventional deferred
`InitializeASI` loader adapter delegates to the same idempotent
`PSOBBGameplay_Initialize` preflight after the module has loaded. It never
starts or joins a thread, installs or restores a hook, hashes a file, or writes
evidence while the loader lock is held.

The project lifecycle may explicitly request one evidence run by passing a
strict generated run ID in `PSOBB_GAMEPLAY_OBSERVATION_RUN_ID`. The module
accepts no path. It independently derives the existing protected run directory
from the exact
`combat-canary\runtime\client\plugins\PSOBB.Gameplay.asi` placement, rejects
reparse/final-path drift, and creates only `events-v1.partial` with no-clobber
semantics. Ordinary launches clear ambient activation, so evidence I/O is off
by default even while passive observation is enabled.

For an evidence launch, the lifecycle holds handle-bound, read-only leases on
the exact loader, Gameplay module, and configuration from immediately before
process creation through native readiness and protected manifest creation. It
rehashes those same handles after readiness. New writers and replacement or
rename attempts are excluded throughout that interval.

The evidence worker runs below normal priority. It first writes and flushes a
`ready` header, then remains paused behind a separate activation handshake
until initialization has published its success state. After activation it
drains every 250 ms and writes a one-second heartbeat. It retains at most
16,384 fixed 32-byte records behind a 256-byte header, making the exact file
524,544 bytes. Records are written before the committed-count header; ring
drops, producer violations, and evidence-cap drops remain separate saturating
counters. The header records ready, active, completed, and failed lifecycle
states, UTC audit timestamps, and `GetTickCount64` active-start and last-commit
values. A completed five-minute capture therefore depends on monotonic elapsed
time and heartbeat liveness, not an adjustable wall clock.

Writes and periodic flushes occur only on the worker. The action hook continues
to allocate nothing, take no lock, and perform no file or IPC operation. The
worker atomically claims the ring's consumer gate before its thread starts, so
the exported drain and reset reject a second consumer without a check/use race.

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
slice does not itself deploy or activate it in any runtime.

## Exported ABI

The ASI exports six undecorated x86 functions:

- `InitializeASI`
- `PSOBBGameplay_DrainObservations`
- `PSOBBGameplay_Initialize`
- `PSOBBGameplay_GetCapabilities`
- `PSOBBGameplay_GetVersion`
- `PSOBBGameplay_Rollback`

`GameplayCapabilitiesV1`, `ObservationEventV1`, `ObservationSnapshotV1`, and
`ObservationEvidenceHeaderV1` contain only fixed-size values and arrays. The
observation snapshot drains at most 2,048 ordered events. The fixed ring is
single-producer/single-consumer:
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

`PSOBBGameplay_Rollback` first disables publication and atomically restores and
flushes the original call target. After callbacks are quiescent, it signals the
evidence worker, waits at most five seconds for its final drain and flush, and
resets the ring only after the worker has exited. The stopped-runtime lifecycle
uses the same process-ID/process-start-bound finalization event and waits for a
separate native completion acknowledgement before closing the game window.
Preexisting named events fail closed. A timeout retains every handle and
returns a retryable failure; it never terminates the worker or resets live
state. Foreign callsite mutation fails closed and is never overwritten.
Rollback lifecycle calls are serialized without waiting; a concurrent caller
returns false without changing the published state.

Normal process termination performs no `DllMain` wait or flush. A manual quit,
crash, or forced termination may therefore leave the durable state `active`,
which stopped-runtime tooling never accepts. An accepted run must first use
the project lifecycle finalization path, reach `completed` with no terminal
failure or loss counter, retain events, prove at least 300,000 monotonic
milliseconds and 300 heartbeats, and then prove that the exact producer process
is stopped. Runtime-load proof and live Twills observation acceptance remain
separate gates.
