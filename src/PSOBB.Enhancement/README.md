# PSOBB.Enhancement

An experimental x86 Direct3D 8 presentation module for one exact PSO Blue Burst executable. It changes in-memory behavior without editing `Psobb.exe` on disk.

The module is disabled unless the adjacent configuration explicitly sets `Enabled=1`. Every pointer write requires the pinned executable hash, PE/byte checks, and an expected-pointer comparison.

## Compatibility and status

The supported client is pinned in [build-manifest.json](build-manifest.json):

- SHA-256: `DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535`
- Size: `6971904` bytes
- x86 fixed image base: `0x00400000`

Read [the derivation and acceptance record](../../docs/CLEANROOM-ENHANCEMENT.md) before using a candidate. Source or build verification is separate from graphics acceptance.

## Build and verify

Use the toolchain pinned in the build manifest. From the repository root:

```powershell
cmake -S .\src\PSOBB.Enhancement -B .\src\PSOBB.Enhancement\bin\build-x86 -A Win32
cmake --build .\src\PSOBB.Enhancement\bin\build-x86 --config Release --parallel
ctest --test-dir .\src\PSOBB.Enhancement\bin\build-x86 -C Release --output-on-failure
```

The output includes `PSOBB.Enhancement.asi` and `PSOBB.Enhancement.Verify.exe`. Run the verifier against the separately supplied client. Reproducibility acceptance requires matching artifact hashes from a separate source root.

## Configuration and rollback

Start with [PSOBB.Enhancement.ini.example](PSOBB.Enhancement.ini.example). Supported settings are:

- Resolution: `2560×1600` or `3840×2400`
- Window mode: `Unchanged`, `Borderless`, or `Resizable`
- `HorizontalFov=1`: perspective-shaped projection adjustment
- `HudMinimap=0` and `AutomaticDeviceRecreation=0`: required until separately implemented and accepted

Failed modified device creation/reset retries the original parameters and reports `runtime_fallback`.

The [capability API](include/psobb_enhancement/api.h) reports hook state, resolution, fallbacks, and projection counts. Rollback restores only pointers still owned by this module plus the captured window placement. It never overwrites another component's changes. Relaunching is required for complete back-buffer rollback.

## License

Project-authored source uses the [MIT license](LICENSE.md). The manifest records source, toolchain, and artifact identity; it does not bundle a runtime. ASI loaders, proprietary client files, and built binaries are not distributed here.
