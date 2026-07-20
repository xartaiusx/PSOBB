# PSOBB.ClientSafety

`PSOBB.ClientSafety` is the internal static library for exact-client safety
checks shared by project-owned native modules. It identifies only the approved
x86 59NL executable and provides generic RVA expected-byte checks for file and
loaded-image preflight. It also provides a fixed-capacity code-patch
transaction with exact byte gates, executable-range validation, exclusive
process-wide byte-range and touched-page ownership across static-library
copies, and compare-before-restore rollback. Page ownership serializes the
page-granular protection transitions required even for disjoint patch bytes.

Each logical owner uses a stable, nonzero, process-wide unique token. Its
module remains pinned while any claim is active and performs an explicit
rollback; ownership is not tied to a fallible object destructor. Failed cache
flushes or protection restores retain the claim and the exact owed state until
a verified retry succeeds. Every executable protection transition preserves
the page's existing CFG call-target information.

Code-byte writes are 2-16 bytes and are not atomic. The caller must prove that
target code is quiescent for install and rollback. The first Gameplay use must
prove that `InitializeASI` runs before the target site is reachable, or marshal
the operation to a separately proven safe point.

The transaction primitive is inert until a caller supplies an already verified
executable range and an exact patch plan. This component does not contain or
install a game-specific hook, read gameplay state, or ship a runtime binary of
its own. File hashing, PE parsing, installation, and rollback run only during
module lifecycle work, never in a real-time action path.

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
