# PSOBB.LargeAssets

`PSOBB.LargeAssets.asi` is an isolated, project-owned x86 patch for one exact
59NL PSO Blue Burst executable. It raises 17 unique embedded asset-size limits
to `100000000` without editing `Psobb.exe` on disk. It has no Direct3D hooks,
so it can coexist with a separate widescreen ASI and renderer chain without
activating `PSOBB.Enhancement.asi`.

The module remains inert unless an adjacent `PSOBB.LargeAssets.ini` contains:

```ini
[LargeAssets]
Enabled=1
```

Any other value is disabled or rejected. The only accepted base is:

```text
SHA-256: DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535
Size:    6971904 bytes
PE:      x86, fixed image base 0x00400000, SizeOfImage 0x00762000
```

Before any write, the module verifies the complete file hash and size, the PE
contract, loaded base and image, and the original `uint32_t` at every site.
The write phase is transactional: it preflights every site first and restores
the already-written prefix in reverse order if any compare/write fails.
Rollback only replaces values still equal to this module's `100000000` value,
so it fails closed instead of overwriting an unknown owner.

## Provenance and exact original values

The address list and replacement value come only from the MIT-licensed
[Blue Burst Patch Project `large_assets.cpp`](https://github.com/Solybum/Blue-Burst-Patch-Project/blob/dc123c5630b36c1bbf5a98660b178ba1ed316db8/Blue%20Burst%20Patch%20Project/large_assets.cpp)
at commit `dc123c5630b36c1bbf5a98660b178ba1ed316db8`. The immutable official source
archive used during derivation has SHA-256
`683812D22C095DB554A6529DF050B4DB852C977A33598166365DFDFE7BAF88F1`.
The upstream list has 18 entries because `0x005B7CFC` occurs twice; this module
deduplicates it deterministically to 17 writes.

The original values below were read from the pinned executable by mapping each
RVA through the PE section table to its raw file offset. A naive `VA - base`
file offset is invalid because `.text` has distinct virtual and raw offsets.
All 17 sites map to `.text`.

| Virtual address | RVA | Raw file offset | Original `uint32_t` |
|---:|---:|---:|---:|
| `0x00800C32` | `0x00400C32` | `0x00400032` | `589824 (0x00090000)` |
| `0x005B7CFC` | `0x001B7CFC` | `0x001B70FC` | `589824 (0x00090000)` |
| `0x005B80F8` | `0x001B80F8` | `0x001B74F8` | `589824 (0x00090000)` |
| `0x005B913F` | `0x001B913F` | `0x001B853F` | `589824 (0x00090000)` |
| `0x005B7215` | `0x001B7215` | `0x001B6615` | `589824 (0x00090000)` |
| `0x005B7937` | `0x001B7937` | `0x001B6D37` | `589824 (0x00090000)` |
| `0x005B97C2` | `0x001B97C2` | `0x001B8BC2` | `589824 (0x00090000)` |
| `0x005BA613` | `0x001BA613` | `0x001B9A13` | `589824 (0x00090000)` |
| `0x005BB405` | `0x001BB405` | `0x001BA805` | `589824 (0x00090000)` |
| `0x005B77E3` | `0x001B77E3` | `0x001B6BE3` | `589824 (0x00090000)` |
| `0x005C74C1` | `0x001C74C1` | `0x001C68C1` | `589824 (0x00090000)` |
| `0x0070EB5B` | `0x0030EB5B` | `0x0030DF5B` | `589824 (0x00090000)` |
| `0x00800A34` | `0x00400A34` | `0x003FFE34` | `589824 (0x00090000)` |
| `0x005B82AD` | `0x001B82AD` | `0x001B76AD` | `589824 (0x00090000)` |
| `0x005BB40C` | `0x001BB40C` | `0x001BA80C` | `589824 (0x00090000)` |
| `0x005E581E` | `0x001E581E` | `0x001E4C1E` | `589824 (0x00090000)` |
| `0x007A6573` | `0x003A6573` | `0x003A5973` | `1048576 (0x00100000)` |

## Build and verify

Use the manifest-pinned CMake 4.4.0 and Visual Studio 2026 x86 toolchain. The
Release ASI and verifier use reproducible-build flags; acceptance requires
matching hashes from a separate source root.

```powershell
cmake -S .\src\PSOBB.LargeAssets `
  -B .\src\PSOBB.LargeAssets\bin\build-x86 -A Win32
cmake --build .\src\PSOBB.LargeAssets\bin\build-x86 `
  --config Release --parallel
ctest --test-dir .\src\PSOBB.LargeAssets\bin\build-x86 `
  -C Release --output-on-failure

& .\src\PSOBB.LargeAssets\bin\build-x86\Release\PSOBB.LargeAssets.Verify.exe `
  'C:\path\to\Psobb.exe'
```

The source-only repository does not contain an ASI loader, proprietary client
files, or built binaries. See [LICENSE.md](LICENSE.md) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for redistribution terms.

## Runtime API

The ASI exports undecorated x86 entry points:

- `PSOBBLargeAssets_Initialize`
- `PSOBBLargeAssets_GetCapabilities`
- `PSOBBLargeAssets_GetVersion`
- `PSOBBLargeAssets_Rollback`

Capability status reports the exact-client gates, 18 upstream entries, 17
unique patch sites, active/restored counts, and the last fail-closed reason.
Explicit rollback is preferred before unload. A normal `FreeLibrary` detach
also attempts a non-blocking best-effort rollback when initialization is not
in flight; process-termination detach does not write to a dying address space.
