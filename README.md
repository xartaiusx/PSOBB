# Modern PSOBB Server

This repository is the tracked control plane for a provenance-first,
Tethealla-client-compatible PSO Blue Burst server. The playable runtime uses
`newserv`; downloaded server releases, the SEGA client, player data, secrets,
and backups live outside Git under `C:\Users\xtyty\Documents\PSOBB-Runtime`.

## Safety boundary

- The retired public Tethealla server is not used.
- Local acceptance binds only to `127.0.0.1` and opens no firewall/router port.
- `newserv`'s HTTP API remains disabled.
- Existing MariaDB data on this PC is not used or changed.
- Client files and other copyrighted assets are never committed or
  redistributed by this repository.
- No broad Microsoft Defender exclusions are created.

## Operator workflow

```powershell
pwsh -File .\scripts\Initialize-PSOBB.ps1
pwsh -File .\scripts\Initialize-PSOBBClientRegistry.ps1
pwsh -File .\scripts\Set-PSOBBRuntimeAcl.ps1
pwsh -File .\scripts\New-PSOBBAccount.ps1 -Role Admin
pwsh -File .\scripts\New-PSOBBAccount.ps1 -Role Admin -Provision
pwsh -File .\scripts\New-PSOBBAccount.ps1 -Role Player
pwsh -File .\scripts\New-PSOBBAccount.ps1 -Role Player -Provision
pwsh -File .\scripts\Set-PSOBBAdminCredential.ps1 -Relaunch
pwsh -File .\scripts\Set-PSOBBPlayerCredential.ps1 -Relaunch -RelaunchChannel LocalLab
pwsh -File .\scripts\Set-PSOBBRememberedLogin.ps1 -Mode Enable -Confirm:$false
pwsh -File .\scripts\Reset-PSOBBClientRuntime.ps1 -Renderer Native
pwsh -File .\scripts\Start-PSOBB.ps1
pwsh -File .\scripts\Start-PSOBBClient.ps1
pwsh -File .\scripts\Test-PSOBB.ps1 -Suite Baseline
pwsh -File .\scripts\Stop-PSOBB.ps1
pwsh -File .\scripts\Set-PSOBBClientPatchProfile.ps1 -Profile stable-qol -Confirm:$false
pwsh -File .\scripts\Backup-PSOBB.ps1
pwsh -File .\scripts\Test-PSOBBRestoreDrill.ps1
```

Prepare and validate the separately staged D3D11 graphics canary without
replacing a running stable client:

```powershell
pwsh -File .\scripts\Reset-PSOBBClientRuntime.ps1 -Channel Canary -Renderer DgVoodooD3D11 -GraphicsPreset Ultra3840x2880 -DefaultWindowMode Borderless -Confirm:$false
pwsh -File .\scripts\Test-PSOBBClientGraphics.ps1 -Channel Canary -ExpectedRenderer DgVoodooD3D11 -ExpectedGraphicsPreset Ultra3840x2880 -ExpectedWindowMode Borderless
pwsh -File .\scripts\Start-PSOBBClient.ps1 -Channel Canary -WindowMode Borderless
pwsh -File .\scripts\Start-PSOBBClient.ps1 -Channel Canary -WindowMode Resizable
pwsh -File .\scripts\Start-PSOBBSession.ps1 -Channel LocalLab -WindowMode Borderless -PreserveForeground
```

The approved Ultra canary uses the exact x86 dgVoodoo D3D8 wrapper with D3D11
feature level 11. It renders the unmodified client's 4:3 scene at 3840x2880,
then uses Lanczos-3 to present it inside the 2560x1600 desktop canvas without
stretching. Pillarboxing is expected. The profile preserves point-sampled UI
textures, applies 16x anisotropic filtering only where appropriate, keeps
mipmaps application-driven, disables forced bilinear 2D scaling and redundant
MSAA, and disables the dgVoodoo watermark. `Borderless` fills the desktop;
`Resizable` starts with a movable, captioned 1600x1200 client area.
Add `-PreserveForeground` to a client or session start to make a best-effort
launch that keeps the most recently selected non-game application focused. The
launcher exposes the same opt-in behavior as **Try to keep current app focused**.
Activating PSOBB is still required for normal keyboard and mouse gameplay.

Supersampling improves geometry and edge clarity but cannot manufacture detail
missing from the original low-resolution HUD, font, or texture assets. True
16:10 camera and HUD expansion remains gated on a licensed or project-owned
patch; no unlicensed widescreen binary is part of this runtime.

The scripts default to the external runtime root above. Override it with the
`PSOBB_RUNTIME_ROOT` environment variable when testing an isolated copy on a
local volume. Runtime roots inside this Git repository and UNC/network roots
are rejected by default.
Passwords are not printed. Bootstrap credentials begin in user-DPAPI-protected
files outside Git, and newserv's required BB license copy is protected by a
narrow filesystem ACL. After `Set-PSOBBPlayerCredential.ps1` successfully
verifies an unprivileged rotation, it retires the live player DPAPI copy: the
operator must remember or independently store the new password and enter it
manually. Protected transaction/state backups remain sensitive rollback data.

`Set-PSOBBAdminCredential.ps1 -Relaunch` securely prompts for a custom admin
username and a 1-16-character password (12-16 recommended), closes
script-managed processes normally, backs up and rotates the existing root
license, clears stale cached login fields, verifies the baseline, and opens the
client for one manual credential entry. Normal start, stop, and graphics-capture
workflows preserve the selected native login policy without reading the cached
username or password.

Remembered login is local and opt-in. `Set-PSOBBRememberedLogin.ps1 -Mode
Enable` sets the native `ACCOUNT_CHECK=1` option; enter the credentials once in
PSOBB and later launches can reuse them. `-Mode Disable` clears the cached
fields. Treat the current Windows account as trusted: the legacy client stores a
locally recoverable password value in the user registry, so never export or
share that registry key. Reinitializing client settings creates a protected
whole-key recovery export that may contain the prior cached login; treat that
runtime backup as credential-bearing and never copy or publish it.

`Set-PSOBBPlayerCredential.ps1` provides the corresponding authorization-test
workflow for exactly one metadata-bound `Player` account with `Flags=0`. It
refuses root flags, duplicate account IDs/usernames, unsafe ACLs, and username
changes after username-bound save data exists. Secrets cannot be passed as
arguments, displayed, copied to the clipboard, or written to a replacement
DPAPI file. A later rotation securely prompts for the current password because
the prior new password was intentionally retained only by newserv.

`Start-PSOBB.ps1` uses a hidden local supervisor that owns newserv's redirected
shell input. `Stop-PSOBB.ps1` sends the actual newserv `exit` command and does
not describe console-window closure as a graceful shutdown.

Fresh initialization selects the reversible `stable-qol` client auto-patch
profile. On an existing installation, apply it only while newserv is stopped;
use `Set-PSOBBClientPatchProfile.ps1 -Profile baseline` to return both
`AutoPatches` and `BBRequiredPatches` to empty. The stable profile contains only
the five pinned non-protocol 59NL patches documented in the QoL matrix.

See [Architecture](docs/ARCHITECTURE.md), [Operations](docs/OPERATIONS.md),
[QoL matrix](docs/QOL-MATRIX.md), and [Production gates](docs/PRODUCTION-GATES.md).
The user-owned AshenbubsHD v1.02 texture experiment has a separate
[local-lab-only compatibility and rights gate](docs/ASHENBUBS-HD-LOCAL-LAB.md);
the asset materializer only stages it. A separate transactional activation can
create the exact no-CAS `lab-widescreen-hd-16x10` LocalLab candidate with the
project-owned large-asset patch, full per-file verification, and exact rollback.
Private assets and composed manifests remain outside Git and public releases.
The launcher can select this private HD identity only after activation and its
**Verify / repair** action runs activation verification without rebuilding or
reinstalling assets. Clean LocalLab materialization refuses an active private
overlay until explicit rollback. CAS profiles remain evidence-only and are not
eligible in the GUI, command line, or desktop shortcuts.
