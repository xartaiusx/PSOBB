# PSOBB.ClientSafety

A static C++ library providing exact-client validation and reversible native changes for project-owned modules.

It supports only the approved x86 59NL executable. Shared primitives cover file/loaded-image checks, expected-byte validation, fixed-capacity patch transactions, and atomic near-call hooks. It does not install a game-specific hook or ship a standalone runtime binary.

## Integration requirements

- Validate the executable range and exact patch plan before use.
- Give each logical owner a stable, nonzero, process-wide unique token. Keep its module pinned while any claim is active.
- Claim both byte ranges and touched pages exclusively across all library copies. Page claims serialize protection changes even when bytes do not overlap.
- Perform explicit compare-before-restore rollback. Failed cache flushes or protection restores retain the claim and owed state until a verified retry succeeds.
- Preserve existing CFG call-target information during executable protection changes.

Code-patch writes are 2–16 bytes and are not atomic. Callers must prove that target code is quiescent during installation and rollback. Gameplay initialization must occur before a target becomes reachable or at a separately proven safe point.

The atomic x86 near-call helper accepts an already writable exact-image `E8 rel32` instruction contained on one page. It validates both executable targets, claims the five-byte instruction and page, and atomically compares the aligned four-byte operand. It will not widen protection or patch a non-image allocation.

Hashing, PE parsing, installation, and rollback belong in module lifecycle work, never a real-time action path. See the [public headers](include/psobb_client_safety/) for the exact contracts.

## Build and test

From the repository root:

```powershell
Push-Location .\src\PSOBB.ClientSafety
cmake --fresh --preset x86
cmake --build --preset release --parallel
ctest --preset release
Pop-Location
```

Tests use synthetic PE images and public SHA-256 vectors, without reading or copying the proprietary game client.
