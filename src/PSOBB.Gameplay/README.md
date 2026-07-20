# PSOBB.Gameplay

`PSOBB.Gameplay.asi` is the exact-client-gated owner for future native combat,
focused input, buffering, and hotbar behavior. This first source slice is an
inert native foundation: it exposes the stable capability ABI and can
verify the approved 59NL executable, but installs no hook and observes or
dispatches no gameplay action.

The module remains disabled when `PSOBB.Gameplay.ini` is absent or when its
`[Gameplay]` section does not explicitly set `Enabled=1`. In this build,
`Enabled=1` can only report `exact_client_ready` after exact file-hash and
loaded-PE checks pass. All feature bits and hotbar slots remain zero/empty.

This source slice performs no automatic initialization from `DllMain`. An
owning in-process loader must call `PSOBBGameplay_Initialize` after Windows
loader-lock work has completed. Runtime deployment remains deferred until that
activation path is integrated and accepted.

## Build and test

```powershell
cmake --fresh -S .\src\PSOBB.Gameplay `
  -B .\src\PSOBB.Gameplay\bin\build-x86 -A Win32 `
  -DBUILD_TESTING=ON
cmake --build .\src\PSOBB.Gameplay\bin\build-x86 `
  --config Release --parallel
ctest --test-dir .\src\PSOBB.Gameplay\bin\build-x86 `
  -C Release --output-on-failure
```

The ignored Release artifact is
`src\PSOBB.Gameplay\bin\build-x86\Release\PSOBB.Gameplay.asi`. This source
slice does not deploy or activate it in any runtime.

## Capability ABI

The ASI exports four undecorated x86 functions:

- `PSOBBGameplay_Initialize`
- `PSOBBGameplay_GetCapabilities`
- `PSOBBGameplay_GetVersion`
- `PSOBBGameplay_Rollback`

`GameplayCapabilitiesV1` contains only fixed-size values and arrays. No owning
pointer or exception crosses the DLL boundary.
