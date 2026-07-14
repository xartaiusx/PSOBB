# PSOBB Launcher

This is a dependency-free WPF launcher for the local Windows acceptance environment. It targets .NET 10 LTS and deliberately does not download or redistribute PSOBB client assets.

## Security boundary

- A schema-v1 manifest must pass strict JSON and semantic validation before use.
- `LoadSignedAsync` verifies a detached ECDSA P-256/SHA-256 signature over the exact manifest bytes before parsing those same bytes, avoiding a verify/reopen race.
- Every installed artifact and every declared imported base file is checked with SHA-256 immediately before launch.
- Destinations must be relative Windows paths beneath the selected runtime root. Traversal, absolute paths, alternate data streams, reserved device names, trailing dots/spaces, and existing reparse points are rejected.
- Source URLs, when supplied, must be absolute HTTPS URLs.
- Lifecycle operations invoke only allowlisted repository scripts with `pwsh -File` and `ProcessStartInfo.ArgumentList`; secret-like manifest and launcher arguments are rejected.
- Health checks connect only to IPv4 loopback and only to manifest-declared ports.
- Diagnostics omit absolute runtime paths and launch arguments, and redact usernames, account/license identifiers, Guild Card numbers, passwords, credentials, tokens, secrets, and the Windows user-profile path.
- The launcher never asks for or stores a game password. Account creation remains an operator-side server action.

The launcher validates signed manifests and installed files; acquisition, archive extraction, atomic installation, and private-key custody belong to the release pipeline. Do not point the launcher at an untrusted runtime tree.

## Manifest contract

Property names are case-sensitive and unknown properties are rejected. `sourceUrl` may be omitted for a user-imported proprietary base file. Both launch executables must appear as artifact destinations.

```json
{
  "schemaVersion": 1,
  "releaseId": "local-stable-2026-02-27",
  "channel": "stable",
  "protocolRevision": 1,
  "artifacts": [
    {
      "id": "newserv",
      "sourceUrl": "https://example.invalid/newserv.exe",
      "destination": "server/newserv.exe",
      "sha256": "<64 hexadecimal characters>",
      "byteSize": 123456,
      "license": "MIT"
    },
    {
      "id": "imported-client",
      "destination": "client/psobb.exe",
      "sha256": "<64 hexadecimal characters>",
      "byteSize": 123456,
      "license": "SEGA proprietary; user-imported",
      "requiredBase": {
        "path": "client/base/psobb.exe",
        "sha256": "<64 hexadecimal characters>"
      }
    }
  ],
  "launch": {
    "serverExecutable": "server/newserv.exe",
    "clientExecutable": "client/psobb.exe",
    "serverArguments": ["--config", "config.json"],
    "clientArguments": [],
    "healthPorts": [11000, 12000, 12001]
  }
}
```

The manifest does not contain its own signature. Its sibling `release-manifest.json.sig` contains only the base64 encoding of a 64-byte IEEE P1363 P-256 signature (`r || s`) calculated with SHA-256 over the manifest's exact bytes. `LoadSignedAsync` accepts the corresponding trusted `PUBLIC KEY` PEM text; production must embed or package that public key with the code-signed launcher, while the private key remains offline.

The WPF application looks for `release-public-key.pem` beside its executable. When present, its absence of a sibling `.sig` file or any invalid signature blocks loading. When the launcher package has no trusted public key, the UI labels the manifest `unsigned local`; this is intentionally limited to local-development acceptance and is not a valid production package.

The interactive Control Center holds a per-Windows-session named mutex. A
second shortcut launch reports that the Control Center is already open and
exits without starting or stopping either PSOBB process. Headless lifecycle
commands do not take this UI mutex; their allowlisted PowerShell scripts retain
the operation locks and remain the sole process authority.

`Install-PSOBBDesktopShortcuts.ps1` resolves the current user's Desktop through
the Windows special-folder API, stages and verifies both `.lnk` files before an
atomic replacement, and is idempotent. **PSOBB Control Center** has no
arguments. **PSOBB Play** contains only the selected channel, exact profile,
window mode, and runtime root; credentials and account identifiers are never
valid shortcut arguments. The private HD profile is eligible only by its exact
`lab-widescreen-hd-16x10` identity; CAS profiles remain evidence-only and are
not valid GUI, command-line, or shortcut selections. Installation
rehashes every file in the signed launcher payload, rejects extra or unsafe
paths, and recomputes the signed payload-index digest before creating either
shortcut.

Profile, monitor, and window-mode selection is written atomically to the schema-v2 `.launcher/active-profile.json` contract. Safe mode selects the stable native 4:3 runtime. Before client startup, the launcher checks the selected channel's materialized `client-profile.json`; a lab, modern, DXVK, or d3d8to9 selection is rejected unless that exact profile ID has actually been built. The private HD profile additionally requires D3D11, exact 2560x1600 true-16:10 output, a disabled watermark, no CAS or ReShade state, the exact local-only AshenbubsHD activation declaration, and exactly one hash-pinned project-owned LargeAssets ASI/INI module. Its **Verify / repair** operation runs activation `Verify`; it never rebuilds or silently reinstalls private assets. The known dgVoodoo clarity profile additionally requires D3D11, 2560x1600 output, the approved 3840x2880 4:3 preset, preserved aspect ratio, and a disabled watermark.

For the primary display profile, the renderer guard also enforces the
watermark-free Ultra D3D11 configuration: 3840x2880 4:3 internal rendering,
Lanczos-3 presentation to the 2560x1600 canvas, point-sampled texture
preservation, 16x anisotropic filtering for other textures, MSAA off, and
forced bilinear 2D scaling off. The WPF controls and command line delegate
borderless/resizable presentation to `scripts/Start-PSOBBClient.ps1`; the
launcher never starts `Psobb.exe` or newserv directly and closing the Control
Center does not stop either process.

## Lifecycle command line

Exactly one operation may be supplied. Runtime, channel, profile, monitor, and
window options never accept account or credential data.

```powershell
PSOBB.Launcher.exe --play --channel canary --profile clarity-dgvoodoo-4x3 --window-mode borderless --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --play --channel local-lab --profile lab-widescreen-hd-16x10 --window-mode borderless --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --safe-play --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --start-server --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --start-client --channel canary --profile clarity-dgvoodoo-4x3 --window-mode resizable --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --stop-client --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --stop-server --runtime-root "C:\path\to\PSOBB-Runtime"
PSOBB.Launcher.exe --stop-all --runtime-root "C:\path\to\PSOBB-Runtime"
```

`--stop-server` refuses while an approved client is active. `--stop-all`
always requests client shutdown before the authenticated newserv shutdown
script. The scripts directory is resolved from `PSOBB_SCRIPT_ROOT`, a parent
repository directory, or the local `Documents\PSOBB\scripts` development path.

## Build and test

From the repository root:

```powershell
dotnet build .\src\PSOBB.Launcher\PSOBB.Launcher.csproj -c Release
dotnet test .\tests\PSOBB.Launcher.Tests\PSOBB.Launcher.Tests.csproj -c Release
```

No production NuGet packages are used. The test project uses only Microsoft Test SDK and MSTest packages.
