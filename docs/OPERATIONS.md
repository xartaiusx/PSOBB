# Local Operations

1. Run `Initialize-PSOBB.ps1` to verify archives, preserve the clean base,
   generate the loopback configuration, synchronize BB data, and bind the
   tracked empty `baseline` client-patch profile to the installation record.
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

   The 2026-07-20 source-only gate did not run the canonical runtime-marker
   migration. If the normal setter reports the one recognized inherited legacy
   marker DACL, preview and then apply only this explicit migration:

   ```powershell
   pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBRuntimeAcl.ps1 `
     -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" `
     -MigrateLegacyRuntimeMarkerAcl `
     -WhatIf

   pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBRuntimeAcl.ps1 `
     -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" `
     -MigrateLegacyRuntimeMarkerAcl `
     -Confirm:$false
   ```

   Migration accepts no other ACL shape. It holds the exact native file
   identity and bytes, revalidates owner, group, DACL, process/listener state,
   and writes only the DACL. Failure rollback is attempted only while the
   captured post-write identity and protected DACL still match exactly. Unknown
   or concurrently changed state remains untouched for investigation.

   After migration, apply the complete target inventory and verify it:

   ```powershell
   pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBRuntimeAcl.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Confirm:$false
   pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-PSOBBRuntimeAcl.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime"
   ```

   The current target inventory includes Stable licenses, players, teams,
   secrets, backups, and logs; graphics evidence; local asset archives; staged
   asset overlays; Ashenbubs and supplemental visual-asset activation state;
   and any existing CombatCanary licenses, players, teams, secrets, backups,
   logs, snapshots, control records, and builds. Server configuration and future
   portal state are not silently treated as covered; add them to the shared
   policy only when those stores deliberately enter this ACL boundary.
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
7. Stable Native is the accepted recovery baseline. Its 2026-07-19
   loopback-only acceptance used only slot-0 Twills, a FOnewearl, and completed
   a five-minute Forest/manual-combat scenario, read-only bank inspection,
   graceful restart, slot-0 relog, semantic verification, and graceful
   shutdown.
8. Run `Stop-PSOBB.ps1` so the supervisor sends newserv's shell `exit`; then run
   `Backup-PSOBB.ps1` and `Test-PSOBBRestoreDrill.ps1`.
9. Back up state before any server, client, map, quest, or save-format change.

## Restore-drill quarantine

The 2026-07-20 canonical Stable restore drill passed against the protected
baseline backup. Its schema-v3 receipt is
`backups/restore-drill-20260720T105025429Z/drill-result.json`. Its bounded
identity and termination fields include `approvedServerExecutableSha256`,
`serverExecutableSha256`, `processId`, `processStartTimeFileTimeUtc`,
`processImageVerified`, `quarantineReason`, `quarantinePublicationState`, and
`quarantineNextAction`.

If process exit or either bounded output reader cannot be confirmed, preserve
the complete protected drill root. The primary record is
`.restore-drill-quarantine.json`; if primary publication fails, the fallback is
`.restore-drill-quarantine-incomplete.json`. If neither record can be confirmed,
the protected `.work` tree and result remain the cleanup hold. The only accepted
reasons are `exit-unconfirmed` and `output-reader-unconfirmed`.

Do not remove a quarantine merely because a timeout elapsed. First confirm that
the recorded PID with its exact start-time identity and executable digest is
absent and that ports 11000, 12000, and 12001 have no listeners. There is not yet
an authenticated project command that releases a quarantine after those checks;
stop for an operator review instead of deleting the tree manually or changing
its ACL.

## Combat canary materialization runbook

The implementation range from `6f5e78b` through `96bcddc`, inclusive, passed a
source-only gate. The current real Stable restore drill passed on 2026-07-20.
The canonical runtime-marker migration, CombatCanary materialization, and both
five-minute Twills smokes have not run. Do not start this sequence until the
marker and restore-drill prerequisites pass, the Git tree is clean, every
PSOBB/newserv process is
stopped, ports 11000, 12000, and 12001 are free, and no `P:` build mapping
exists. Stable and CombatCanary must never run concurrently.

Establish explicit tracked identities and verify the already built server
artifact. A new publication, if deliberately required, follows
[the separate build contract](COMBAT-CANARY-BUILD.md).

```powershell
$runtimeRoot = "C:\Github Repo's\PSOBB\PSOBB-Runtime"
$buildContractSha256 = (Get-FileHash `
  -LiteralPath .\config\combat-canary-build.json `
  -Algorithm SHA256).Hash.ToLowerInvariant()
$twillsContractSha256 = (Get-FileHash `
  -LiteralPath .\config\twills-fonewearl-build.json `
  -Algorithm SHA256).Hash.ToLowerInvariant()
$trust = Get-Content -Raw -LiteralPath .\config\release-trust.json |
  ConvertFrom-Json
$activeTrustKey = @($trust.keys | Where-Object {
    $_.id -ceq $trust.activeKeyId
  })
if ($activeTrustKey.Count -ne 1) {
  throw 'The tracked active acceptance key is not unique'
}
$signingPublicKeySpkiSha256 = [string]$activeTrustKey[0].spkiSha256

$buildVerification = & .\scripts\Build-PSOBBCombatCanaryServer.ps1 `
  -Action Verify `
  -RuntimeRoot $runtimeRoot
if (-not $buildVerification.Verified) {
  throw 'CombatCanary server verification did not pass'
}
```

Create one fresh Stable backup, then create and verify a signed Twills-only
snapshot. Keep the returned object in the same trusted PowerShell session; do
not substitute an account-derived path or copy individual state files.

```powershell
$stableBackup = & .\scripts\Backup-PSOBB.ps1 `
  -RuntimeRoot $runtimeRoot
$snapshot = & .\scripts\New-PSOBBCombatCanarySnapshot.ps1 `
  -RuntimeRoot $runtimeRoot `
  -StableBackupPath $stableBackup.BackupPath `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256 `
  -Confirm:$false

& .\scripts\Test-PSOBBCombatCanary.ps1 `
  -RuntimeRoot $runtimeRoot `
  -Target Snapshot `
  -SnapshotPath $snapshot.SnapshotPath `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256
```

Preview first initialization, apply it only after reviewing the exact target,
then perform complete installed readback:

```powershell
& .\scripts\Initialize-PSOBBCombatCanary.ps1 `
  -RuntimeRoot $runtimeRoot `
  -SnapshotPath $snapshot.SnapshotPath `
  -ExpectedBuildContractSha256 $buildContractSha256 `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256 `
  -WhatIf

& .\scripts\Initialize-PSOBBCombatCanary.ps1 `
  -RuntimeRoot $runtimeRoot `
  -SnapshotPath $snapshot.SnapshotPath `
  -ExpectedBuildContractSha256 $buildContractSha256 `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256 `
  -Confirm:$false

& .\scripts\Test-PSOBBCombatCanary.ps1 `
  -RuntimeRoot $runtimeRoot `
  -Target Both `
  -SnapshotPath $snapshot.SnapshotPath `
  -ExpectedBuildContractSha256 $buildContractSha256 `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256
```

CombatCanary permits only its sealed Native client and profile-default window
mode. Lifecycle startup may preserve another application's foreground focus;
normal gameplay input still requires PSOBB to be focused.

```powershell
& .\scripts\Start-PSOBBSession.ps1 `
  -RuntimeRoot $runtimeRoot `
  -ServerEnvironment CombatCanary `
  -Channel Native `
  -WindowMode ProfileDefault `
  -PreserveForeground

& .\scripts\Stop-PSOBBSession.ps1 `
  -RuntimeRoot $runtimeRoot `
  -ServerEnvironment CombatCanary `
  -Target All
```

After a stateful isolated scenario, restore only from the same verified signed
snapshot and repeat complete readback:

```powershell
& .\scripts\Reset-PSOBBCombatCanaryState.ps1 `
  -RuntimeRoot $runtimeRoot `
  -SnapshotPath $snapshot.SnapshotPath `
  -ExpectedBuildContractSha256 $buildContractSha256 `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256 `
  -Confirm:$false

& .\scripts\Test-PSOBBCombatCanary.ps1 `
  -RuntimeRoot $runtimeRoot `
  -Target Both `
  -SnapshotPath $snapshot.SnapshotPath `
  -ExpectedBuildContractSha256 $buildContractSha256 `
  -ExpectedTwillsContractSha256 $twillsContractSha256 `
  -ExpectedSigningPublicKeySpkiSha256 $signingPublicKeySpkiSha256
```

Snapshot reset is not server-artifact rollback. Failed replacement publication
automatically restores the immediately prior release, but there is no supported
post-success CombatCanary server release-selection or rollback command.

## Graphics canary

The stable client remains Native as the accepted recovery baseline after the
2026-07-19 loopback-only combat, bank, restart, relog, and shutdown acceptance.
This does not accept a graphics canary or any Phase 1 QoL patch. A renderer can
be prepared without touching the running stable client:

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

## Client auto-patch reference profile

The accepted Stable recovery profile is `baseline`, with both patch arrays
empty. The hash-bound `stable-qol` profile is retained only as a compatibility
reference for its exact 59NL sources; do not promote it as a group. Each patch
must pass its own CombatCanary acceptance checkpoint.

To inspect or deliberately exercise that reference in an isolated stopped
runtime, the underlying reversible command is:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBClientPatchProfile.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Profile stable-qol -Confirm:$false
```

The command refuses to edit configuration while either approved newserv
environment or any client is running. It changes only `AutoPatches`, keeps
`BBRequiredPatches` empty, verifies
that every exact 59NL patch source matches its size and SHA-256 in
`sources.lock.json`, and records
the selected profile plus policy hash in `installation.json`. Start newserv only
after the command succeeds. Roll back with the same stopped-server procedure and
`-Profile baseline`; this restores both patch arrays to empty without touching
licenses, players, teams, quests, or patch data.

`stable-qol` contains only `AccurateKillCount`, `FastTekker`,
`HungryMagSound`, `NoRareSelling`, and `Palette`. `Palette` is reference-only
because the planned Modern Gameplay module exclusively owns the number
hotbar. Source-canary, protocol, and save-migration patches are classified
separately in `config/client-patch-profiles.json` and cannot enter either stable
profile.

### One-time Stable installation-record repair

An installation created before the baseline policy update can have the exact
schema-v2 property set that predates renderer provenance while its client and
server files are already current. Its `stable\installation.json` can also retain
the one recognized inherited legacy DACL. Do not use the normal recursive ACL
inventory or the broad initializer to repair either state. With both server
environments and all clients stopped, preview and then apply only the explicit
one-file ACL migration:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBRuntimeAcl.ps1 `
  -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" `
  -MigrateLegacyStableInstallationRecordAcl `
  -WhatIf

pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Set-PSOBBRuntimeAcl.ps1 `
  -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" `
  -MigrateLegacyStableInstallationRecordAcl `
  -Confirm:$false
```

This mode returns before the recursive ACL target inventory. It accepts only
the exact known legacy record and source/runtime/policy binding, an ordinary
single-link file, the canonical inherited three-principal FullControl DACL, and
approved unchanged owner and group. It retains the target and ancestor
identities, rechecks the globally stopped lifecycle at each mutation boundary,
and writes only the access DACL. Unknown state is left untouched. Conditional
rollback restores the captured legacy access SDDL only while the exact target,
bytes, ownership, stopped state, and captured protected DACL still match. An
already protected exact legacy record is returned unchanged.

After that prerequisite is exact, preview the narrow metadata transaction:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-PSOBBStableInstallationRecord.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -WhatIf
```

If the preview recognizes the exact legacy baseline record, apply it with:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-PSOBBStableInstallationRecord.ps1 -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" -Confirm:$false
```

The metadata repair adds only `rendererVersion`, `rendererArchiveSha256`,
`rendererWrapperSha256`, and `rendererConfigurationSha256` from the current
source lock, and changes only `clientPatchPolicySha256` to the current empty
`baseline` policy. It requires the exact known legacy policy hash, current
runtime marker and source bindings, matching renderer/server/client files,
an exact strict patch-data manifest and synchronized-file count, empty patch
arrays, protected single-link metadata, and a globally stopped runtime. The
transaction journal binds its ownership marker and every rollback identity. On
success, the protected original, candidate, displaced original, completion
record, and immutable journal move together beneath the protected Stable
backups boundary. An ambiguous identity, publication, or interrupted rollback
retains or revalidates the exact transaction evidence. Keep the runtime stopped
and rerun the same command to resume exact conditional recovery. An already
repaired record and its sole completed evidence bundle are revalidated without
another write.

Backups are schema-v3 exact-file snapshots. They bind `system/config.json` and
`stable/installation.json` to one verified client-patch profile and policy hash.
Restore rejects older incomplete snapshots and any config/metadata mismatch,
stages state on the same volume, and rolls both files back if any swap fails.
The automated drill rechecks that binding before it proves startup, listeners,
and account indexing. The 2026-07-19 loopback-only Stable Native
game-protocol relog and character/bank semantic verifier completed the
remaining recovery-baseline acceptance.

The pinned upstream newserv sorts bank records before sending BB bank contents,
and a later character save can persist that normalized order. It also assigns
transient runtime item IDs. A bank inspection is therefore read-only by
ownership even when only those serialization details change. Verification keeps
the inventory layout, descriptors, and equipment exact, while the embedded and
authoritative slot-0 bank representations must match exact order-insensitive
multisets of full canonical item descriptors. Bank counts and structural
validity remain fail-closed; physical bank order and transient runtime item IDs
are not ownership identities.

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
