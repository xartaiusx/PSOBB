# PSOBB.Gameplay

An x86 module for recording selected native gameplay activity in one exact supported client, with foundations for future combat, focused-input, buffering, and hotbar work.

Version 0.4.0 is implemented and source-tested. Installation in CombatCanary, the isolated test setup, module-load verification, and live observation tests remain pending.

The implementation observes selected native `send_60` serialization attempts and provides an opt-in bounded evidence recorder. It does not dispatch actions or synthetic packets; hotbar slots remain empty.

## Activation and safety

The module is disabled without `[Gameplay] Enabled=1` in `PSOBB.Gameplay.ini`. With `Observation=0`, initialization performs identity verification only.

Observation also requires `Observation=1`, the exact 59NL executable, the tracked 11-byte callsite digest, a pinned module, and exclusive callsite ownership. Any mismatch leaves the adapter inert.

The adapter atomically replaces only an aligned four-byte relative `CALL` operand without changing page protection. It invokes the original target once, then retains the first four-byte header for commands `0x43`–`0x48`. A record proves a serialization attempt, not server receipt, attack type, damage, or legal combo timing.

Deferred `InitializeASI` performs the same idempotent preflight as the public initializer. `DllMain` only stores the module handle; it never installs hooks, hashes files, starts/joins threads, or writes evidence under the loader lock.

## Evidence recording

A strict `PSOBB_GAMEPLAY_OBSERVATION_RUN_ID` enables one explicitly requested capture. It accepts no path. The module derives the protected capture directory from its approved CombatCanary placement, rejects redirected paths, and creates `events-v1.partial` without overwriting an existing file.

Ordinary launches clear ambient activation. Evidence launch holds read-only identity leases on the loader, module, and configuration through readiness and rehashes the same handles before recording acceptance.

The recorder:

- Runs on a separate below-normal-priority worker after a readiness/activation handshake
- Drains every 250 ms and records a one-second heartbeat
- Stores at most 16,384 fixed 32-byte records plus a 256-byte header
- Tracks ring drops, producer violations, and capacity drops separately
- Uses monotonic elapsed time for capture duration

The action hook does not allocate, lock, or perform file/IPC work. The ring has one producer and one consumer; competing producers or consumers fail closed. See [the public contracts](include/psobb_gameplay/) for buffer sizes, sequence/counter rules, and drain semantics.

## Rollback and acceptance

Rollback disables publication, restores and flushes the owned call target, waits for callbacks to become quiescent, and requests the worker's final drain. A five-second timeout retains handles and permits retry; it never kills the worker, resets live state, or overwrites foreign changes. Concurrent rollback returns failure without waiting.

Manual quit, crash, or forced termination can leave evidence incomplete. Accepted captures require the supported finalization handshake, `completed` state, retained events, zero failure/loss counters, at least 300,000 monotonic milliseconds and 300 heartbeats, and proof that the exact producer process has stopped.

Installing the module, verifying that it loaded, and passing live observation tests are separate required checks. Check the [implementation ledger](../../docs/COMBAT-IMPLEMENTATION-LEDGER.md) and [acceptance guide](../../docs/COMBAT-ACCEPTANCE.md).

## Build and test

From the repository root, using a Visual Studio generator that supports Win32:

```powershell
Push-Location .\src\PSOBB.Gameplay
cmake --fresh --preset x86
cmake --build --preset release --parallel
ctest --preset release
Pop-Location
```

The ignored output is `bin/build-x86/Release/PSOBB.Gameplay.asi` within this component. Building does not publish or activate it. [build-manifest.json](build-manifest.json) records the pinned inputs and artifact identity.
