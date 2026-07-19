# Local Operations

1. Run `Initialize-PSOBB.ps1` to verify archives, preserve the clean base,
   generate the loopback configuration, synchronize BB data, and bind the
   tracked `stable-qol` client-patch profile to the installation record.
2. Run `Initialize-PSOBBClientRegistry.ps1`; it installs only the required
   per-user game values and disables the archive's obsolete web links.
3. Harden the sensitive game-state, secrets, backup, log, private-asset, and
   graphics-evidence directories with `Set-PSOBBRuntimeAcl.ps1`. The log and
   evidence roots are included because server output and captures can contain
   operational or player-related details even when credential-dumping commands
   are never used. Then run the read-only
   `Test-PSOBBRuntimeAcl.ps1`; it recursively checks the setter's shared target
   inventory, rejects reparse points, and requires a protected, canonical DACL
   containing exactly current-user, SYSTEM, and Administrators FullControl
   rules on every item. It reads ACL metadata and paths only, never file
   contents. Re-run the setter and verifier after creating or restoring runtime
   state because newly created children can inherit their parent DACL.

   ```powershell
   pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-PSOBBRuntimeAcl.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime"
   ```

   The current local target inventory is licenses (including account/license
   records), players, teams, secrets, backups, logs, graphics evidence, local
   asset archives, staged asset overlays, Ashenbubs activation state, and
   supplemental visual-asset activation state. Server configuration and future
   portal state are not silently treated as covered; add them to the shared
   policy when those stores are deliberately brought under this ACL boundary.
4. Generate and provision `Admin` and `Player` credentials with the two-step
   `New-PSOBBAccount.ps1` commands in the root README. Passwords are not
   printed or placed in process arguments. Never run or capture newserv's
   `list-accounts` command: the pinned stable release and current source both
   include plaintext BB passwords in that command's output. Project helpers
   verify account/license files without invoking it.
   Before first character creation, an operator may run
   `Set-PSOBBAdminCredential.ps1 -Relaunch` to choose a custom root username and
   1–16-character ASCII alphanumeric password (12–16 recommended). The helper
   blocks username changes after username-bound player data exists;
   password-only rotation remains available.
   Use `Set-PSOBBPlayerCredential.ps1` for the separate authorization-negative
   account. It targets only the metadata-bound `Player` license with `Flags=0`,
   rejects root/admin or ambiguous targets, and prompts for all secrets without
   accepting credential arguments. After a verified rotation it removes the
   stale live `player.credential.clixml` rather than persisting the new password
   in DPAPI. Remember or independently store that password and type it manually;
   future rotations securely prompt for the current password. The protected
   transaction and full-state backups contain sensitive rollback material and
   remain subject to the runtime ACL and retention policy.
   The WPF launcher delegates every server/client action to the same lifecycle
   scripts and never owns newserv or `Psobb.exe` directly. Before credential
   rotation, use **Stop all** or let the approved `-Relaunch` helper perform its
   guarded stop, mutation, and restart sequence; do not terminate either
   process from Task Manager as a normal workflow.
   Select **Try to keep current app focused**, or pass `-PreserveForeground` to
   `Start-PSOBBClient.ps1` or `Start-PSOBBSession.ps1`, when another application
   should remain foreground during startup. This is a best-effort Windows focus
   request: the lifecycle tracks the latest non-game foreground window and never
   stops a healthy client merely because focus restoration is unavailable. The
   client remains visible, responsive, and connected; click it normally when
   login or gameplay input is needed. Screenshot and RenderDoc evidence flows
   intentionally continue to require foreground access.
   The historic client embeds `requireAdministrator`; credential relaunch uses
   a process-local Windows `RunAsInvoker` compatibility fix. This preserves the
   immutable client, leaves UAC enabled, and creates no persistent AppCompat
   registry setting.
   Remembered login is a local opt-in. Run
   `Set-PSOBBRememberedLogin.ps1 -Mode Enable` to set the native
   `ACCOUNT_CHECK=1` option, then enter the credentials once in PSOBB. Normal
   start, stop, graphics-profile, and RenderDoc paths validate the registry
   types but never read, export, log, or clear `ACCOUNT` and `PASSWORD`.
   Credential rotation clears a
   stale cache while preserving the selected policy; `-Mode Disable` explicitly
   disables and clears it. Pioneer 2 community guidance confirms the flag and
   warns that the saved password becomes a sensitive `REG_BINARY` value:
   [save-login flag](https://www.pioneer2.net/community/threads/another-way-to-save-id-and-pass-or-fix-that-cannot-change-resolution.1997/#post-20151),
   [registry security](https://www.pioneer2.net/community/threads/script-for-switching-accounts.511/).
   Client-registry initialization and graphics-profile launch back up only the
   36-byte `GRAPHICCTRL` value as ACL-protected JSON beneath the runtime backup
   directory. Whole-key exports are forbidden: an existing `ACCOUNT`,
   `PASSWORD`, and `ACCOUNT_CHECK` remain byte-for-byte untouched. Each launch
   verifies the profile's nine DWORD values and SHA-256 before writing, reads
   back the exact binary value, and restores its value-only backup if startup
   fails. Launching the native rollback profile applies that profile's own
   `GRAPHICCTRL` contract instead of relying on stale machine-global state.
   Credential backup ACL changes construct a DACL-only security descriptor;
   they never request SACL access or `SeSecurityPrivilege` from the operator.
5. Rebuild a disposable native client with
   `Reset-PSOBBClientRuntime.ps1 -Renderer Native`. Reset verifies the complete
   immutable client inventory, not only `Psobb.exe`.
6. Run `Start-PSOBB.ps1` and `Test-PSOBB.ps1 -Suite Baseline`; confirm the only
   listeners are loopback TCP 11000, 12000, and 12001.
7. Complete login, character creation, one-person game, combat, item, bank,
   save, restart, and relog acceptance using the disposable client.
8. Run `Stop-PSOBB.ps1` so the supervisor sends newserv's shell `exit`; then run
   `Backup-PSOBB.ps1` and `Test-PSOBBRestoreDrill.ps1`.
9. Back up state before any server, client, map, quest, or save-format change.

## Graphics canary

The stable client stays Native until the complete combat, bank, restart, and
relog acceptance sequence passes. A renderer can be prepared without touching
the running stable client:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Reset-PSOBBClientRuntime.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Channel Canary -Renderer DgVoodooD3D11 -GraphicsPreset Ultra3840x2880 -DefaultWindowMode Borderless -Confirm:$false
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-PSOBBClientGraphics.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Channel Canary -ExpectedRenderer DgVoodooD3D11 -ExpectedGraphicsPreset Ultra3840x2880 -ExpectedWindowMode Borderless
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Start-PSOBBClient.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Channel Canary -WindowMode Borderless
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Start-PSOBBClient.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Channel Canary -WindowMode Resizable
```

The canary is rebuilt from the immutable 59NL base. It accepts only the locked
x86 `D3D8.dll` and locked source `dgVoodoo.conf`, transforms exactly one
approved configuration from that source, records the resulting config hash,
rejects competing proxy DLLs, and snapshots any prior canary. The transform
selects D3D11 feature level 11, 3840x2880 4:3 internal rendering, Lanczos-3
presentation, 16x anisotropic filtering for non-point-sampled textures,
application-driven mipmaps, no redundant MSAA, no forced bilinear 2D scaling,
and no watermark.

Borderless mode owns a 2560x1600 desktop canvas. The original client projection
remains 4:3, so the 3840x2880 image is downsampled into an aspect-correct active
area with side pillars. Resizable mode starts with a movable, captioned
1600x1200 client area. This is supersampling, not true 3840x2400 widescreen;
the latter requires a licensed or project-owned camera/HUD patch.

Validate login, character selection, lobby, one-person combat, HUD/minimap,
effects, fog, Alt-Tab, Windows scaling, and save/relog in both window modes.
Supersampling cannot add detail to low-resolution source art. Restore Native at
any time with `Reset-PSOBBClientRuntime.ps1 -Channel Stable -Renderer Native`.
Do not add a second `d3d8.dll`, `d3d9.dll`, `dxgi.dll`, shader injector, or
widescreen engine without a separate manifest profile and acceptance pass.

## Staged Tier-1 server defaults

The next graceful server restart loads switch assistance by default and BB rare
text notifications by default. Players can still toggle them with `$swa` and
`$itemnotifs`. Stable shared EXP is explicitly zero until a same-floor-only
implementation passes two-client tests; upstream's multiplier also rewards a
tagged player on another floor and therefore cannot satisfy that contract by
configuration alone.

## Stable client auto-patches

For an existing runtime, stop newserv normally, then explicitly promote the
hash-bound `stable-qol` profile:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBClientPatchProfile.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Profile stable-qol -Confirm:$false
```

The command refuses to edit configuration while the approved newserv binary is
running. It changes only `AutoPatches`, keeps `BBRequiredPatches` empty, verifies
that every exact 59NL patch source matches its size and SHA-256 in
`sources.lock.json`, and records
the selected profile plus policy hash in `installation.json`. Start newserv only
after the command succeeds. Roll back with the same stopped-server procedure and
`-Profile baseline`; this restores both patch arrays to empty without touching
licenses, players, teams, quests, or patch data.

`stable-qol` contains only `AccurateKillCount`, `FastTekker`,
`HungryMagSound`, `NoRareSelling`, and `Palette`. Source-canary, protocol, and
save-migration patches are classified separately in
`config/client-patch-profiles.json` and cannot enter either stable profile.

Backups are schema-v3 exact-file snapshots. They bind `system/config.json` and
`stable/installation.json` to one verified client-patch profile and policy hash.
Restore rejects older incomplete snapshots and any config/metadata mismatch,
stages state on the same volume, and rolls both files back if any swap fails.
The automated drill rechecks that binding before it proves startup, listeners,
and account indexing; full
character/bank/team recovery is not accepted until the game-protocol relog
scenario is completed with disposable state.

The pinned unmodified `v2026-02-27` release at commit
`a649a4a146d04dba320bb579ac291527db0febb5` has no
`AllowSameAccountConcurrentLogins` or `CensorCredentials` configuration keys.
The separately locked canary source at commit
`d754a34e271a4fb387be63db34ef0c303e49dcf2` adds both controls, but it remains
canary-only until the exact build passes two-client acceptance or ships in an
accepted release. Packet-data logging is disabled in stable, and unsupported
keys are never added to an older release as false security.

The HTTP API, automatic registration, DNS listener, proxy modes, and public
firewall rules remain disabled in local operation.

The checked-in trust configuration currently pins a local-acceptance ECDSA
public key. It is not a production signing identity. Production publication
requires replacing the compiled and repository trust anchor together, signing
the launcher executable, and retaining the private release key offline.
