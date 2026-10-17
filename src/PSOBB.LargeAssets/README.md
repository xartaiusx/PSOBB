# PSOBB.LargeAssets

An isolated x86 module that raises 17 embedded asset-size limits in the supported 59NL PSO Blue Burst executable to `100000000`.

It changes memory only, has no Direct3D hooks, and does not require `PSOBB.Enhancement`. It remains inert unless an adjacent `PSOBB.LargeAssets.ini` explicitly contains:

```ini
[LargeAssets]
Enabled=1
```

## Exact-client requirements

The supported base is pinned in [build-manifest.json](build-manifest.json):

- SHA-256: `DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535`
- Size: `6971904` bytes
- x86 image base: `0x00400000`; image size: `0x00762000`

Before writing, the module checks the complete file hash/size, PE contract, loaded image, and every original value. A failed write restores the changed prefix in reverse order. Rollback only replaces values that still match this module's patch; it will not overwrite another component's changes.

## Provenance

The address list and replacement value derive from the MIT-licensed [Blue Burst Patch Project](https://github.com/Solybum/Blue-Burst-Patch-Project/blob/dc123c5630b36c1bbf5a98660b178ba1ed316db8/Blue%20Burst%20Patch%20Project/large_assets.cpp), commit `dc123c5630b36c1bbf5a98660b178ba1ed316db8`.

Its 18 entries include one duplicate, producing 17 unique writes. The [patch plan](include/psobb_large_assets/patch_plan.h) and [manifest](build-manifest.json) retain the exact addresses, expected values, archive hash, and toolchain identity. Original values must be resolved through PE sections; subtracting the image base is not a valid raw-file offset.

## Build and verify

Use the manifest-pinned toolchain. From the repository root:

```powershell
cmake -S .\src\PSOBB.LargeAssets -B .\src\PSOBB.LargeAssets\bin\build-x86 -A Win32
cmake --build .\src\PSOBB.LargeAssets\bin\build-x86 --config Release --parallel
ctest --test-dir .\src\PSOBB.LargeAssets\bin\build-x86 -C Release --output-on-failure
```

Run the generated `PSOBB.LargeAssets.Verify.exe` against the separately supplied client. Reproducibility acceptance requires matching hashes from a separate source root.

The [API](include/psobb_large_assets/api.h) reports identity checks, patch counts, restoration, and failure reasons. Use explicit rollback before unloading. Normal unload attempts only best-effort non-blocking rollback; process-termination detach does not write to the dying process.

## License and distribution

See [LICENSE.md](LICENSE.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), including the Blue Burst Patch Project attribution. No ASI loader, proprietary client files, or built binaries are bundled here.
