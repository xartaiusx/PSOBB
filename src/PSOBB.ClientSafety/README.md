# PSOBB.ClientSafety

`PSOBB.ClientSafety` is the internal static library for exact-client safety
checks shared by project-owned native modules. It identifies only the approved
x86 59NL executable and provides generic RVA expected-byte checks for file and
loaded-image preflight.

This component does not install hooks, modify process memory, read gameplay
state, or ship a runtime binary of its own. File hashing and PE parsing run
only during module initialization, never in a real-time action path.

## Build and test

```powershell
cmake --fresh -S .\src\PSOBB.ClientSafety `
  -B .\src\PSOBB.ClientSafety\bin\build-x86 -A Win32 `
  -DBUILD_TESTING=ON
cmake --build .\src\PSOBB.ClientSafety\bin\build-x86 `
  --config Release --parallel
ctest --test-dir .\src\PSOBB.ClientSafety\bin\build-x86 `
  -C Release --output-on-failure
```

Tests use synthetic PE images and known public SHA-256 vectors. They do not
read or copy the proprietary game client.
