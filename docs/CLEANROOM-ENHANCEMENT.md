# Clean-room PSOBB enhancement record

## Scope and result

This subtree was derived from read-only inspection of exactly:

```text
C:\Users\xtyty\Documents\PSOBB-Runtime\stable\runtime\client\Psobb.exe
```

No local-lab widescreen overlay and no Ephinea, Ragol, Destiny, or Ultima
private code or binary was used. The implementation does not contain, modify,
or redistribute the client executable. It builds an independent x86 ASI and a
read-only verifier.

The result is a buildable, fail-closed Direct3D 8 interception layer with:

- exact-base SHA-256 and expected-byte preflight before the first write;
- expected-pointer compare/exchange for the IAT and COM vtable slots;
- explicit 2560x1600 and 3840x2400 presentation policies;
- guarded horizontal-FOV expansion for perspective projections only;
- borderless and resizable Windows styles;
- policy reuse when the game initiates `IDirect3DDevice8::Reset`;
- original-parameter fallback, pointer/window rollback, and capability exports.

HUD/minimap transformation and automatic resize-triggered device recreation
are not implemented. Their configuration switches fail closed.

## Pinned base executable

| Property | Pinned value |
| --- | --- |
| SHA-256 | `DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535` |
| File size | `6,971,904` bytes (`0x006A6200`) |
| Signature | Not Authenticode-signed |
| Machine | x86 (`IMAGE_FILE_MACHINE_I386`) |
| Image base | `0x00400000` |
| Size of image | `0x00762000` |
| Entry point RVA / VA | `0x00760000` / `0x00B60000` |
| Sections | 9 |
| Relocations | Stripped; base-relocation directory empty |

The verifier checks the whole-file hash and size before parsing the PE. The
runtime then checks the same file through its loaded module path and separately
checks immutable bytes in the mapped image.

## Independently observed Direct3D path

Read-only `dumpbin` and byte inspection of the pinned executable established:

| Evidence | Value |
| --- | --- |
| Imported API | `d3d8.dll!Direct3DCreate8` |
| IAT VA / RVA | `0x008F841C` / `0x004F841C` |
| IAT raw file offset and bytes | `0x004F701C`: `1E F6 75 00` |
| Import hint/name RVA | `0x0075F61E` (`00 00` + `Direct3DCreate8\0`) |
| Import thunk VA / RVA | `0x008BEFF2` / `0x004BEFF2` |
| Import thunk bytes | `FF 25 1C 84 8F 00` (`jmp [0x008F841C]`) |
| Direct3D call | `0x00838ECD` calls the thunk after `push 0xDC` at `0x00838CE8` |
| Direct3D object storage | return value stored at `0x00ACD4A0` |
| CreateDevice calls | object vtable `+0x3C`, including call at `0x00837C6B` |
| Device storage | CreateDevice output pointer `0x00ACD528` |
| SetTransform calls | device vtable `+0x94`, including `0x00835D28` |

The ASI does not patch those call sites or global object addresses. It uses
only the proven `Direct3DCreate8` IAT slot, then public Direct3D 8 COM ABI slots
on objects returned by the intercepted API. This keeps game-specific writes to
one pinned IAT pointer.

## Fail-closed write sequence

With a missing file or `Enabled=0`, initialization performs no pointer write.
With `Enabled=1`, the sequence is:

1. Validate the INI and reject unsupported/gated settings.
2. Require the loaded main module at fixed base `0x00400000`.
3. Recompute and match the complete executable SHA-256 and file size.
4. Validate PE32 machine, image size, entry point, section count, and empty
   relocation directory.
5. Match the entrypoint, import thunk, on-disk IAT, and import-name byte gates.
6. Match entrypoint and import-thunk bytes again in the mapped image.
7. Require the live IAT pointer to equal the current
   `d3d8.dll!Direct3DCreate8` export exactly.
8. Pin the ASI so a hook cannot outlive its code.
9. Change page protection narrowly, compare/exchange the expected pointer, and
   restore the original protection. A changed pointer aborts the write.

COM vtable hooks repeat the executable-memory and expected-pointer checks.
Rollback uses reverse-order compare/exchange and refuses to overwrite a slot
no longer owned by the ASI.

## Implemented behavior and acceptance state

| Capability | Implementation | Current acceptance |
| --- | --- | --- |
| 2560x1600 | Overrides D3D8 back-buffer width/height | Unit-tested; live client gate remains |
| 3840x2400 | Overrides D3D8 back-buffer width/height | Unit-tested; wrapper/GPU/live gate remains |
| 16:10 horizontal FOV | Multiplies projection `_11` by `(4/3)/(16/10) = 5/6` only for finite perspective-shaped matrices | Unit-tested; scene-by-scene visual gate remains |
| Orthographic/UI projection safety | Leaves non-perspective matrices unchanged | Unit-tested |
| Borderless | Uses the device window and its nearest monitor; captures/restores style and rectangle | Built; live focus/input/presentation gate remains |
| Resizable | Applies an overlapped resizable style and a monitor-bounded initial rectangle | Built; live resize/presentation gate remains |
| Game-initiated Reset | Reapplies the selected presentation policy and falls back on failure | Built; live lost-device gate remains |
| Automatic resize Reset | Not implemented | Explicit configuration rejection |
| Resolution-independent HUD/minimap | Not implemented | No defensible render-path classification yet; explicit configuration rejection |
| Version/capability report | Four stable C exports and ABI v1 status structure | Export table verified |
| Safe rollback | Restores owned pointer slots and window state; preserves conflicting third-party writes | Unit/code-path reviewed; live gate remains |

The projection hook changes a temporary API argument, not game memory. A
failed adjusted `SetTransform` call is retried with the original matrix.
Modified `CreateDevice` and `Reset` failures are likewise retried with the
original presentation parameters so the client can continue unmodified.

## Build and verification evidence

Toolchain used:

```text
Visual Studio 18 2026 Community
MSVC x86 19.51.36248.0
Windows SDK 10.0.28000.0
CMake Visual Studio 18 2026 generator, -A Win32
```

Commands:

```powershell
cmake -S .\src\PSOBB.Enhancement `
  -B .\src\PSOBB.Enhancement\bin\build-x86 -A Win32
cmake --build .\src\PSOBB.Enhancement\bin\build-x86 `
  --config Release --parallel
ctest --test-dir .\src\PSOBB.Enhancement\bin\build-x86 `
  -C Release --output-on-failure
& .\src\PSOBB.Enhancement\bin\build-x86\Release\PSOBB.Enhancement.Verify.exe `
  'C:\Users\xtyty\Documents\PSOBB-Runtime\stable\runtime\client\Psobb.exe'
```

Observed results on 2026-07-14:

- Release x86 build: pass with `/W4 /WX /sdl /guard:cf`.
- Native policy/byte-gate and disabled-default ABI tests: 2/2 pass.
- Exact executable verifier: file-size, SHA-256, PE32, and byte gates pass.
- ASI header: PE32 x86, ASLR, NX, and Control Flow Guard enabled.
- Runtime dependencies: `KERNEL32.dll`, `USER32.dll`, and `bcrypt.dll` only.
- Release ASI: `216,576` bytes; SHA-256
  `63B565F940698D13D9D70B9EEE24551A7CD456A8B268F70663FC8638BEA92674`.

Any source or toolchain change intentionally requires a new ASI digest.

## Remaining gates and blockers

No executable or runtime files were changed or launched during this work.
Before this can be called playable or promoted:

1. Stage the ASI and an explicitly enabled INI only in an isolated canary.
2. Confirm the loader starts the worker before the pinned Direct3D call. The
   worker avoids loader-lock file I/O; a late start will report `armed` but no
   `CreateDevice` attempts and requires launcher/loader sequencing work.
3. Query `CapabilitiesV1`; require both hash/byte flags, the IAT hook, state
   `active`, at least one CreateDevice attempt, and zero fallbacks.
4. Capture projection counters and visually compare 4:3 versus 16:10 in lobby,
   gameplay, cutscenes, menus, and telepipe/area transitions.
5. Validate borderless focus, Alt-Tab, input clipping, monitor selection, and
   rollback.
6. Validate resizable presentation separately. Window resizing does not
   automatically call `Reset`; implementing that remains blocked on proving
   the client's default-pool resource lifecycle.
7. Derive HUD/minimap draw classification from new clean-room evidence before
   adding any coordinate hook. No coordinate/address guess is permitted.
8. Run the repository's graphics capture, frame pacing, soak, and rollback
   acceptance gates before any promotion.

The ASI is unsigned. It is a canary artifact, not a production acceptance
claim.
