# PSOBB.Enhancement

`PSOBB.Enhancement.asi` is a clean-room, x86 Direct3D 8 enhancement for one
exact PSO Blue Burst executable. It never edits `Psobb.exe` on disk. The
component is inert unless an adjacent `PSOBB.Enhancement.ini` explicitly sets
`Enabled=1`, and every pointer write is preceded by the pinned executable hash,
PE/byte gates, and an expected-pointer compare.

The only pinned base is:

```text
SHA-256: DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535
Size:    6971904 bytes
PE:      x86, fixed image base 0x00400000
```

See [`docs/CLEANROOM-ENHANCEMENT.md`](../../docs/CLEANROOM-ENHANCEMENT.md) for
the derivation record, exact gates, capability status, and unresolved runtime
acceptance work.

## Build and verify

Use the manifest-pinned CMake 4.4.0 and Visual Studio 2026 x86 toolchain. The
Release targets compile and link with reproducible-build flags, and acceptance
requires matching hashes from a separate source root:

```powershell
cmake -S .\src\PSOBB.Enhancement `
  -B .\src\PSOBB.Enhancement\bin\build-x86 -A Win32
cmake --build .\src\PSOBB.Enhancement\bin\build-x86 `
  --config Release --parallel
ctest --test-dir .\src\PSOBB.Enhancement\bin\build-x86 `
  -C Release --output-on-failure

& .\src\PSOBB.Enhancement\bin\build-x86\Release\PSOBB.Enhancement.Verify.exe `
  'C:\path\to\Psobb.exe'
```

The Release artifact is
`src\PSOBB.Enhancement\bin\build-x86\Release\PSOBB.Enhancement.asi`.
No ASI loader or proprietary client content is built or distributed here.

## Configuration

Copy `PSOBB.Enhancement.ini.example` beside the ASI as
`PSOBB.Enhancement.ini`. The parser accepts only the two 16:10 render targets
and rejects gated features instead of silently enabling partial behavior.

- `Width=2560`, `Height=1600`, or `Width=3840`, `Height=2400`
- `WindowMode=Unchanged`, `Borderless`, or `Resizable`
- `HorizontalFov=1` adjusts only perspective-shaped projection matrices
- `HudMinimap` must remain `0`
- `AutomaticDeviceRecreation` must remain `0`

If modified `CreateDevice` or game-initiated `Reset` parameters fail, the hook
retries the original parameters and reports `runtime_fallback`.

## Capability API and rollback

The ASI exports stable, undecorated x86 entry points:

- `PSOBBEnhancement_Initialize`
- `PSOBBEnhancement_GetCapabilities`
- `PSOBBEnhancement_GetVersion`
- `PSOBBEnhancement_Rollback`

`PSOBBEnhancement_GetCapabilities` fills `CapabilitiesV1` from
`include/psobb_enhancement/api.h`, including the runtime state, installed hook
flags, selected resolution, fallback count, and observed/adjusted projection
counts.

Rollback restores only pointers still owned by this module and restores the
captured window style/rectangle. It never overwrites a pointer changed by
another component. The existing D3D device remains alive, so a relaunch is the
full rollback for back-buffer state.

## License and build identity

Project-authored source in this subtree is available under the adjacent
[MIT license](LICENSE.md). The checked-in `build-manifest.json` pins every
source and test input, the supported toolchain, and the exact unsigned x86
canary artifact produced by the verified build. The binary remains ignored;
the manifest is an identity and reproducibility record, not a bundled runtime.
