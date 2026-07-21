# Combat implementation ledger

This file is append-only. Add a dated entry for every accepted, rejected, or
rolled-back checkpoint. Never rewrite an earlier entry; add a correction that
references it. Do not include account identifiers, credentials, private key
material, saves, captures, runtime logs, proprietary bytes, or external tool
attribution.

Each entry records:

- date and stable entry ID;
- feature/profile and outcome;
- exact tracked commit and relevant source/client/module hashes;
- tests and active scenario duration;
- semantic save/state result;
- evidence location using a runtime-relative, non-identifying path;
- known limitation; and
- exact safe rollback command or procedure.

## 2026-07-19 / stable-native-forest-v1

- Feature/profile: Stable Native, `baseline`
- Outcome: accepted recovery baseline
- Tracked commit: `8bdcbee` records the acceptance; later Phase 0 layout work
  is recorded by `ba5c888`
- Live identity: slot-0 Twills FOnewearl only
- Scenario: five active minutes in Forest with manual Normal/Heavy/Special
  combo, technique, item, bank read, explicit save, graceful stop, restart,
  relog, and graceful final shutdown
- State result: character, inventory, equipment, techniques, MAG, bank, and
  identity passed the semantic before/after contract
- Network/process result: loopback-only listeners; client and server absent
  after shutdown
- Evidence location: protected Stable acceptance evidence beneath the ignored
  runtime
- Limitation: accepts native Stable behavior only; no QoL patch, graphics
  canary, CombatCanary artifact, or Modern feature is accepted by this entry
- Rollback: keep Stable on the empty `baseline` profile and use the protected
  Stable backup/restore workflow

## 2026-07-19 / combat-canary-layout-v1

- Feature/profile: isolated CombatCanary filesystem and ACL layout
- Outcome: source implementation accepted; live canary not materialized
- Tracked commit: `ba5c888`
- Tests: path-pair isolation, canonical nested-runtime boundary, reparse
  rejection, and protected ACL layout checks
- State result: no CombatCanary mutable account/player/team state created
- Evidence location: tracked tests and protected runtime ACL verification
- Limitation: reproducible server build, sealed snapshot transaction, launcher
  integration, and five-minute smoke remain pending
- Rollback: no live-state rollback required because materialization has not
  occurred

## 2026-07-19 / phase0-hardening-pending-v1

- Feature/profile: reproducible server, sealed Twills state, lifecycle,
  recovery interlocks, and launcher integration
- Outcome: pending; not accepted by this entry
- Tracked commit: none until focused local commits pass final review
- Tests: partial focused suites are recorded only in working notes; final
  combined results must be appended in a later entry
- State result: Stable remains the recovery target; no canonical CombatCanary
  mutable state or snapshot has been materialized
- Evidence location: none promoted
- Limitation: open build and state review findings prevent materialization
- Rollback: keep all PSOBB processes stopped and do not initialize CombatCanary

## 2026-07-20 / stable-native-forest-v1-rollback-correction

- Correction target: `stable-native-forest-v1`
- Reason: the earlier entry named the protected Stable backup/restore workflow
  but did not record its exact stopped-runtime command sequence
- Outcome: documentation correction only; the 2026-07-19 Stable Native
  acceptance result is unchanged
- Exact rollback procedure:

  ```powershell
  $runtimeRoot = "C:\Github Repo's\PSOBB\PSOBB-Runtime"
  $backupPath = '<verified-protected-stable-backup>'

  & .\scripts\Stop-PSOBBSession.ps1 `
    -RuntimeRoot $runtimeRoot `
    -ServerEnvironment Stable `
    -Target All
  & .\scripts\Restore-PSOBB.ps1 `
    -RuntimeRoot $runtimeRoot `
    -BackupPath $backupPath `
    -ValidateOnly
  & .\scripts\Restore-PSOBB.ps1 `
    -RuntimeRoot $runtimeRoot `
    -BackupPath $backupPath `
    -Confirm:$false
  & .\scripts\Set-PSOBBClientPatchProfile.ps1 `
    -RuntimeRoot $runtimeRoot `
    -Profile baseline `
    -Confirm:$false
  & .\scripts\Test-PSOBB.ps1 `
    -RuntimeRoot $runtimeRoot `
    -Suite Baseline
  ```

- Semantic readback: run `Test-PSOBBCharacterBuild.ps1` against the restored
  private slot-0 Twills character and `Test-PSOBBTwillsBank.ps1` against the
  restored private slot-0 bank with the exact tracked build-contract SHA-256;
  do not record either private path in Git
- Limitation: this correction supplies a procedure; it does not record a new
  restore or live gameplay run

## 2026-07-20 / phase0-source-gate-v1

- Feature/profile: Phase 0 deterministic canary build, isolated signed state,
  environment lifecycle/launcher, ACL, and recovery source implementation
- Outcome: source-only gate passed; no CombatCanary runtime or combat feature is
  accepted by this entry
- Implementation commits: inclusive range `6f5e78b` through `96bcddc`
- Source and artifact identities: pinned newserv source
  `d754a34e271a4fb387be63db34ef0c303e49dcf2`; deterministic canary executable
  SHA-256
  `3208b811791e591955a50084276e522cfbfa13f9e807d2287d5ce66f712f717a`;
  build contract SHA-256
  `d2019c44b677ae238c005e38f72c12e9da8cc7af9c7ef20395ea4622b67d6e7a`;
  Twills FOnewearl contract SHA-256
  `1582691fe1cb3019e7ee33e303d0d7811a9bf271e505bae22580e094b3ee1fd1`;
  exact Native 59NL client SHA-256
  `dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535`;
  no Gameplay module exists yet
- Tests: build 50/50 plus successful Verify; independent state 105/105;
  launcher/lifecycle/graphics 397/397; recovery/client 256/256; recovery
  transaction fault matrix 138/138
- Scenario: source-only; live identity not logged in, active scenario not run,
  duration 0 seconds
- State result: the immutable canary server artifact was published and verified,
  but `canonicalStateMaterialized = false`; no canonical snapshot, selected
  server, base/playable canary client, account, player, team, or binding state
  was created
- Evidence location:
  `combat-canary/evidence/source-gate-20260720T064219Z/source-gate.json`
  (SHA-256
  `78b6b71930584677ef99e0418c52771e33bc53790c5f4a840f95e4d80b0cddf5`)
- Recovery-matrix manifest:
  `combat-canary/evidence/source-gate-20260720T064219Z/recovery-matrix/manifest.json`
  (SHA-256
  `1a74b37efd900782b35b82641b76d1296f3174fd00c5c876b322914c56a7d20c`)
- Limitation: canonical runtime-marker migration, a current real restore drill,
  CombatCanary materialization, isolated five-minute Twills smoke, and
  non-destructive canonical five-minute Twills smoke have not run. Failed
  server replacement publication can restore the immediately prior release,
  but no supported post-success release-selection or rollback command exists.
- Source rollback procedure: with every PSOBB process stopped and the Git tree
  clean, run `git status --short` and then `git switch psobb-fidelity`. No
  runtime rollback is required because this source gate materialized no
  canonical state.

## 2026-07-20 / stable-restore-drill-v1

- Feature/profile: Phase 0 Stable recovery prerequisite under the native
  `baseline` client-patch profile
- Outcome: accepted; the isolated schema-v3 restore drill started and verified
  the exact Stable newserv image, indexed both expected accounts, bound all
  three loopback listeners, exited gracefully, and retained only its protected
  result
- Implementation commit: `495fdcf` (`fix: parse native newserv licenses`)
- Tests: recovery strict JSON 86/86; recovery integration 35/35 with the prior
  failed live receipt intentionally excluded; complete recovery suite 37/37
  after successful drill publication
- Scenario: stopped-runtime recovery drill, 5,367 scaffold files verified,
  2/2 accounts indexed, exact process image verified, three loopback listeners,
  and 115.4 seconds elapsed; no game client or live gameplay was started
- State result: slot-0 Twills remained the verified FOnewearl with 29 bank
  entries before and after; no PSOBB/newserv process or reserved listener
  remained; the Git tree remained clean with no remote
- Evidence location:
  `backups/restore-drill-20260720T105025429Z/drill-result.json`
- Limitation: this accepts recovery safety only. CombatCanary materialization,
  its isolated five-minute Twills smoke, and the later non-destructive canonical
  five-minute smoke have not run
- Rollback: no runtime rollback is required because the drill used and removed
  an isolated work tree. Revert the focused parser commit locally only if its
  current-format recovery policy must be withdrawn.

## 2026-07-20 / combat-canary-startup-cutoff-v1

- Feature/profile: pinned-current CombatCanary Native startup gate
- Outcome: rejected and frozen before gameplay; the agreed single startup
  retry exposed a server-package content dependency outside the combat-lab
  contract
- Implementation commits: `84f3be8` (`fix: avoid duplicate canary
  verification`) and `e07f68b` (`fix: require canary startup directory`)
- Source and runtime identities: pinned newserv source
  `d754a34e271a4fb387be63db34ef0c303e49dcf2`; build contract SHA-256
  `31adbc4c333e0ed45da413aaea7ff4cd3676df23f68268cf0f16a27702297d35`;
  release-manifest SHA-256
  `d9626c5a2159f9478a5ef058dbcdc1dbafda7f3aad57aead9a5a343bc32c7bbb`;
  client binding SHA-256
  `e022ecf1930c41b0391cc548b27dfb052cdf593b82309ab2baf569a3985df808`;
  state binding SHA-256
  `a5045cc374f559fd63bf11bf356a141bd15f2dbe9ccd6ca325aef202da5f1cd6`
- Tests: startup binding 10/10; lifecycle 32/32; strict lifecycle JSON
  25/25; background launch 12/12; synthetic state transactions 75/75;
  exact required-directory repair verified; explicit snapshot plus installed
  `Both` readback valid
- Scenario: server-only startup attempt; no client or character login occurred,
  so active gameplay duration was 0 seconds
- State result: the sealed slot-0 Twills FOnewearl snapshot and installed
  canary passed semantic and binding verification; no character, bank,
  inventory, equipment, technique, MAG, or Stable state was changed
- Process/network result: the child exited before readiness and no PSOBB
  process or reserved listener remained
- Evidence location:
  `combat-canary/logs/newserv-20260720-142834906.stderr.log`; the earlier
  pre-reseal and failed-build quarantines remain protected beneath
  `archives/combat-canary-retained-evidence-20260720`
- Failure: after the empty Episode 3 map directory removed the original abort,
  startup reached item-table loading and rejected an auction-pool card whose
  stripped Episode 3 definition was absent. The same package also lacked
  include data needed to compile the pinned client QoL functions.
- Limitation: this package is a non-promotable combat-lab artifact, not a
  retail-complete newserv release. No five-minute canary or canonical smoke is
  accepted by this entry.
- Rollback: keep CombatCanary stopped, verify no reserved listener, and retain
  the protected installation, snapshot, logs, and quarantines. Stable remains
  the unchanged Native recovery target. Do not retry this server package;
  proceed with the separately bound Stable-derived isolated combat fixture.

## 2026-07-20 / gameplay-native-foundation-v1

- Feature/profile: exact-client safety primitives and inert native Gameplay
  capability ABI
- Outcome: source-only foundation accepted; no hook, action observation,
  gameplay input, process-memory write, runtime deployment, or combat behavior
  is accepted by this entry
- Implementation commits: `3d1805d` (`feat: add exact client safety library`),
  `bd428a4` (`fix: bound expected-byte gates to PE ranges`), `c3bb1f3`
  (`test: cover expected-byte RVA overflow`), and `49d06af` (`feat: add inert
  gameplay module`)
- Exact-client gate: x86 59NL executable SHA-256
  `dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535`;
  file size, PE32 contract, and nonempty hook-specific expected-byte ranges
  must all pass before a later hook may be installed
- Tests: ClientSafety 1/1; Gameplay ABI 3/3; existing Enhancement regression
  2/2; MSVC code analysis completed without a remaining diagnostic
- Binary policy result: the ignored Gameplay test artifact was x86 with ASLR,
  NX, Control Flow Guard, four undecorated exports, and only `bcrypt.dll` and
  `KERNEL32.dll` dependencies
- ABI/state result: explicit pack-8 fixed layout; missing, disabled, and
  unpinned hosts remain inert with zero feature bits, no accepted client hash,
  and ten empty display slots; loading the module performs no initialization
- Scenario: source-only; no server or client was started, no character was
  logged in, and active gameplay duration was 0 seconds
- State result: Stable, CombatCanary, Twills, bank, inventory, equipment,
  techniques, MAG, registry, shortcuts, and shared RenderDoc state were not
  changed
- Limitation: safe post-loader activation, committed-page ownership and
  protection primitives, hook-specific expected bytes, action-state mapping,
  bounded diagnostics, runtime publication, and both five-minute Twills smokes
  remain pending
- Rollback: no runtime rollback is required. Keep the module unpublished; use
  focused local Git reverts only if this source foundation must be withdrawn.

## 2026-07-20 / gameplay-deferred-loader-adapter-v1

- Feature/profile: deferred post-load initialization adapter for the inert
  Gameplay native foundation
- Outcome: source-only adapter accepted; `DllMain` remains inert and no hook,
  input, action observation, process-memory write, runtime deployment, or
  combat behavior is accepted by this entry
- Implementation commit: `47b6fd2` (`feat: add deferred Gameplay
  initialization`)
- ABI correction: the ignored x86 test artifact now has five undecorated
  exports, not the four recorded by the preceding foundation entry;
  `InitializeASI` delegates only to the existing idempotent
  `PSOBBGameplay_Initialize` preflight
- Tests: Gameplay ABI 3/3; existing Enhancement regression 2/2; MSVC code
  analysis completed without a diagnostic; independent read-only review found
  no loader-lock, ABI, idempotence, or rollback blocker
- Binary policy result: ignored Release artifact SHA-256
  `8cbbc4484fec548ac9c2113a0dfca9f8bb76726825ba1258e4e1a81377f8fb7b`,
  229,888 bytes, x86, ASLR, NX, Control Flow Guard, SafeSEH, and dependencies
  limited to `bcrypt.dll` and `KERNEL32.dll`
- State result: Stable, CombatCanary, Twills, bank, inventory, equipment,
  techniques, MAG, registry, shortcuts, and shared RenderDoc state were not
  changed
- Limitation: the exact loader overlay, immutable module publication,
  runtime-load proof, observation hook, action-state mapping, and both
  five-minute Twills smokes remain pending
- Rollback: no runtime rollback is required. Keep the module unpublished; use
  a focused local Git revert only if the adapter contract must be withdrawn.

## 2026-07-20 / combat-canary-stable-shadow-source-v1

- Feature/profile: Phase 0 Stable-derived CombatCanary replacement source gate
  under the native `baseline` client-patch profile
- Outcome: source and isolated transaction gate accepted; no canonical runtime
  materialization, server start, client start, or character login is accepted
  by this entry
- Implementation commit: `d446e25` (`feat: add Stable-derived combat
  fixture`)
- Server identity: Stable newserv v2026-02-27 commit
  `a649a4a146d04dba320bb579ac291527db0febb5`; exact executable SHA-256
  `7e82732ca1dd84fa7cd5bd8261f8bb9f42e3a704c66cef83c0fb51a9802eb1cd`;
  StableShadow contract SHA-256
  `472d2a4b443eef5427a1074b7dead87ddd8bc7750f3170a5d2518f3e88963cda`
- Retail-content result: the immutable Stable server base contributes 5,259
  files and the exact verified Blue Burst overlay contributes 108 files; the
  assembled fixture contract therefore retains the Stable retail-content set
  instead of using the rejected stripped current-upstream package
- Isolation result: replacement is permitted only from the exact verified
  CurrentUpstream installation; the existing exact canary client, immutable
  client manifest, and client binding are reused byte-for-byte; server base,
  mutable server, player/team/license state, backups, logs, secrets, control,
  and installation bindings remain isolated from Stable
- Tests: StableShadow 10/10; startup binding 11/11; synthetic transactions
  84/84 including StableShadow transition 6/6; launcher 191/191; launcher
  identity 48/48; CombatCanary lifecycle 32/32; environment isolation 12/12;
  lifecycle scripts 62/62; schema, PowerShell AST, whitespace, attribution,
  compensation, and temporary-fixture cleanup checks passed
- Pre-materialization correction: `ae67089` (`fix: bound Stable manifest
  parsing`) gives only the exact Stable server-base manifest role a bounded
  4-MiB/262,144-token/65,536-property-and-item budget. The sealed 2,038,464-byte
  manifest parsed with exact SHA-256
  `ec72183bde0dd747c5796b4a92060dba87d20dd0bde2ed236712fd17d8c5f048` in
  88.6 seconds; a 4-MiB text payload was rejected. Dedicated parser, AST 6/6,
  StableShadow 10/10, and startup-binding 11/11 checks passed.
- State result: Stable, CombatCanary, Twills, bank, inventory, equipment,
  techniques, MAG, registry, shortcuts, and shared RenderDoc state were not
  changed by the source gate
- Limitation: exact stopped-runtime `WhatIf`, canonical StableShadow
  replacement, installed readback, server readiness, five-minute isolated
  Twills parity, restoration, and five-minute non-destructive canonical smoke
  remain pending
- Rollback: no runtime rollback is required for this source-only entry. Use a
  focused local Git revert only if the StableShadow transition contract must be
  withdrawn; do not remove retained CurrentUpstream evidence.

## 2026-07-20 / client-safety-hook-transaction-v1

- Feature/profile: shared exact-client hook transaction foundation; no
  Gameplay feature flag or runtime profile was enabled
- Outcome: source gate accepted; the component remains inert until a caller
  supplies an exact-image-gated patch plan and separately proves target-code
  quiescence
- Implementation commit: `2d045ab` (`feat: add fail-closed hook
  transactions`)
- Safety result: fixed-capacity transactions require exact expected bytes,
  committed executable ranges, stable explicit owner identities, and exclusive
  process-wide byte and touched-page claims across static-library copies
- Mutation result: executable page changes preserve existing CFG target state;
  cache-flush and protection uncertainty remain owned for retry; rollback is
  reverse-ordered, compare-before-restore, and reports primary and rollback
  failures independently
- Tests: fresh Win32 Release ClientSafety configure/build and CTest 2/2;
  production and fault-injection MSVC code analysis with zero diagnostics;
  dependent Gameplay CTest 3/3; dependent Enhancement CTest 2/2; PE readback
  confirmed x86, ASLR, NX, and CFG; whitespace and attribution scans passed;
  independent review reported no blocking findings
- State result: no hook was installed, no runtime binary was published, and
  Stable, CombatCanary, Twills, saves, registry, shortcuts, and shared
  RenderDoc state were not changed
- Limitation: 2-16-byte x86 code writes are not atomic. Gameplay integration
  must still prove the exact client identity, expected site bytes, exclusive
  ownership, and a target-code-quiescent install and rollback point before any
  live observation candidate is allowed
- Rollback: no runtime rollback is required. Use a focused local Git revert of
  `2d045ab` only if the source contract must be withdrawn.

## 2026-07-20 / combat-canary-stable-shadow-materialized-v1

- Feature/profile: isolated Stable-derived CombatCanary under the Native
  `baseline` client profile
- Outcome: the exact StableShadow fixture was materialized successfully; this
  entry does not yet accept server readiness, a client login, gameplay, or a
  five-minute Twills scenario
- Implementation commits: `858268f` (`perf: avoid duplicate canary preview
  hashes`), `b2378a8` (`fix: bound StableShadow cleanup`), and `78e42a8`
  (`fix: respect Stable config capabilities`)
- Server identity: Stable newserv v2026-02-27 commit
  `a649a4a146d04dba320bb579ac291527db0febb5`; executable SHA-256
  `7e82732ca1dd84fa7cd5bd8261f8bb9f42e3a704c66cef83c0fb51a9802eb1cd`;
  StableShadow contract SHA-256
  `472d2a4b443eef5427a1074b7dead87ddd8bc7750f3170a5d2518f3e88963cda`
- Snapshot identity: sealed snapshot ID
  `dda85ff8-9c23-497d-b3b4-285efe6781ad`; snapshot-manifest SHA-256
  `90ba01ca235d929d434c8ca146423e2260ea8463eaacb8a0cb07a18cb95bf4bb`;
  slot-0 Twills FOnewearl contract SHA-256
  `1582691fe1cb3019e7ee33e303d0d7811a9bf271e505bae22580e094b3ee1fd1`
- Cleanup result: the retained failed stage was independently verified as an
  ordinary, non-reparse, transaction-bound tree and removed through its exact
  authenticated marker. Initialize-stage and initialize-rollback cleanup is
  bounded to 16,384 entries and 1 GiB; all other transaction purposes retain
  the 4,096-entry and 256-MiB defaults.
- Configuration result: StableShadow preserves exact absence of unsupported
  `CensorCredentials` and `AllowSameAccountConcurrentLogins` properties,
  including escaped-property detection through strict decoded JSON. The same
  controls remain mandatory with exact safe values for CurrentUpstream. Normal
  games remain private-drop; Battle and Challenge remain shared.
- Materialization result: the authenticated replacement completed in
  1,339.713 seconds, reported `Initialized`, `Changed`, and
  `ReplacedExisting`, retained the prior CurrentUpstream installation as
  protected frozen evidence, and left no initialize-stage or
  initialize-rollback debris.
- Stable invariance: the protected Stable installation record remained SHA-256
  `e31321851b4e9e411fa57eab97348ab1e0e4fba8854e2b69e6fb829396096316`;
  the Stable server-base manifest remained SHA-256
  `ec72183bde0dd747c5796b4a92060dba87d20dd0bde2ed236712fd17d8c5f048`;
  the Stable executable remained byte-exact.
- Tests: StableShadow 14/14; startup binding 11/11; four modified PowerShell
  files parsed cleanly; whitespace and attribution scans passed; real Stable
  configuration finalized and strict-parsed in memory; an independent review
  found no blocker. The materializer completed its source, staged payload,
  source-readback, sealed-state, and publication checks successfully.
- Bounded verifier result: a separate complete `Target Both` readback produced
  no integrity error but exceeded the five-minute command ceiling and was
  stopped at 300 seconds. No success is claimed for that separate pass; it left
  no verifier process, server/client process, listener, or transaction debris.
- State result: no character was logged in and no gameplay action occurred.
  Stable, the canonical Twills state, registry, Desktop shortcuts, and shared
  RenderDoc state were unchanged.
- Limitation: complete installed-state verification must be made to finish
  within the lifecycle's 300-second startup limit before the server readiness
  probe and both five-minute Twills scenarios can run.
- Rollback: there is no supported post-success server-artifact rollback
  command. Keep CombatCanary stopped and retain the protected frozen
  CurrentUpstream receipt; do not manually swap its trees. Snapshot reset is
  only for isolated Twills state and is not a server-artifact rollback.

## 2026-07-20 / combat-canary-installed-verification-v1

- Feature/profile: exact installed-state verification for the isolated
  Stable-derived CombatCanary under the Native `baseline` client profile
- Outcome: accepted. A complete `Target Installed` readback finished in
  196.899 seconds, below the explicit 300-second startup verification ceiling.
  This supersedes only the preceding entry's verifier-duration limitation; no
  server readiness, client login, gameplay, or Twills scenario is accepted by
  this entry.
- Implementation commit: `c38d0a6` (`perf: fit canary verification deadline`)
- Exact result: `Valid=True`, `ServerArtifact=StableShadow`, component
  `newserv-stable-release`, build-contract SHA-256
  `472d2a4b443eef5427a1074b7dead87ddd8bc7750f3170a5d2518f3e88963cda`,
  snapshot ID `dda85ff8-9c23-497d-b3b4-285efe6781ad`, base-client manifest
  SHA-256 `4f90a80ae944b2f5f65a818a77118c29514a907a2be287a9ef51bd4b021e8f9b`,
  client-binding SHA-256
  `e022ecf1930c41b0391cc548b27dfb052cdf593b82309ab2baf569a3985df808`,
  and configuration SHA-256
  `bb072a70e55a6d345c5934db5f47edf910740a4144343f6874714a0d6f08647c`
- Safety result: strict phosg-compatible parsing now batches ordinary UTF-8
  spans and caches only validated key identities. Exact directory hashing and
  ordinary-tree/reparse validation share one traversal. Duplicate manifest
  paths on either side are rejected, and the CurrentUpstream executable stays
  explicitly bound to its sealed build-contract identity without a second file
  hash.
- Tests: StableShadow 18/18; startup binding 11/11; four modified PowerShell
  files parsed cleanly; whitespace and attribution scans passed; independent
  review found no remaining parser, walker, reparse, manifest, or executable
  identity blocker.
- State result: the check was read-only. No PSOBB or newserv process or listener
  was started; Stable, CombatCanary, Twills, registry, Desktop shortcuts, and
  shared RenderDoc state were not changed.
- Limitation: the launcher observer still has a 60-second verification limit,
  so this first live gate must use the canonical direct lifecycle scripts with
  a 300-second verification timeout. Launcher timing remains a later lifecycle
  optimization and does not weaken the live gate.
- Rollback: no runtime rollback is required. Revert `c38d0a6` locally only if
  this verifier implementation must be withdrawn.

## 2026-07-20 / combat-canary-native-parity-scenario-v1

- Feature/profile: isolated Stable-derived CombatCanary using the Native
  `baseline` client profile; no Gameplay module or combat enhancement was
  published or enabled
- Outcome: the active Forest scenario and post-save semantic integrity gate
  passed. Exact restoration, restart/relog, and the canonical non-destructive
  smoke remain pending and are not accepted by this entry.
- Scenario: slot-0 Twills FOnewearl only; 2026-07-20T19:49:42.1900419Z through
  2026-07-20T19:54:47.1546148Z; 304.965 active seconds with 58 bounded samples
- Gameplay result: the operator confirmed native Normal, Heavy, and Special
  attacks, techniques, movement fluidity, and the on-screen fluid action. The
  client remained responsive, all three exact loopback listeners remained
  present, and one exact client game connection was observed throughout.
- Lifecycle result: the client exited normally. The server then stopped through
  its authenticated shell-exit protocol with no force action; server,
  supervisor, client, and reserved listeners were absent afterward.
- Lifecycle correction: the first combined stopped-client/server cleanup
  exposed an empty-client-census strict-mode defect. Commit `7bfbfc3` makes the
  census helper accept an empty array while still rejecting null or malformed
  records. Lifecycle tests passed 63/63 and CombatCanary lifecycle tests passed
  32/32; a real stopped-runtime retry returned `not-running` for both targets.
- Post-save state result: the sealed and saved character each passed all 11
  Twills build checks with the exact 57-item ownership contract; the sealed and
  saved authoritative bank each contained the exact 29-item contract and had
  the same SHA-256. Both license files, card, system, team, and bank were
  byte-exact.
- Bounded character delta: both files remained 14,748 bytes. The sealed
  character SHA-256 was
  `d092108a0d8cde09e6c1177947b1c2d5290cca5e2b108f8aabd83731aa9802d5`;
  the saved SHA-256 was
  `35e2bcd1ffcf9ad1dd9bb28dd9bc7b985dc3e667350f7c6e8949343a3c46d53c`.
  All 31 changed bytes were confined to 28 transient inventory item-ID
  namespace bytes, the four-byte play-time field with two changed bytes, and
  one Choice Search configuration byte. No descriptor, stack, equipment,
  technique, MAG, bank-ownership, or unrelated protected-state byte changed.
- Limitation: the visual fluid action did not produce a persisted stack delta.
  Consumable save/relog persistence and no-double-consumption are therefore
  unverified and must receive a controlled item-only scenario before item
  quick-use work. This does not block the observation-only action probe.
- Rollback: restore only through `Reset-PSOBBCombatCanaryState.ps1` from sealed
  snapshot ID `dda85ff8-9c23-497d-b3b4-285efe6781ad`, then require exact
  `Target Both` readback before another candidate.

## 2026-07-21 / combat-canary-native-relog-reset-v1

- Feature/profile: isolated Stable-derived CombatCanary using the Native
  `baseline` client profile; no Gameplay module or combat enhancement was
  published or enabled
- Outcome: restart/relog, bounded save-delta verification, and exact isolated
  state reset accepted. The separate five-minute canonical Stable smoke remains
  pending and is not accepted by this entry.
- Verification implementation: `937c920` (`test: verify bounded canary live
  deltas`)
- Relog result: the exact foreground-preserving 59NL client started at
  2026-07-21T21:13:00Z. The server recorded a real session from 21:14:10Z
  through 21:15:13Z, including slot-0 Twills load, game/map load, graceful
  character, bank, system, and card save, disconnect, and normal server
  shutdown.
- Bounded delta: the character gained 50 seconds of play time through exactly
  two changed bytes. The six noncharacter state files were byte-exact, all 28
  inventory records remained present, and no item identity, descriptor,
  quantity, equipment, technique, MAG, or bank-ownership change was accepted.
- Reset result: at 2026-07-21T21:19:47Z, the isolated state was transactionally
  reset to snapshot ID `dda85ff8-9c23-497d-b3b4-285efe6781ad`, manifest SHA-256
  `90ba01ca235d929d434c8ca146423e2260ea8463eaacb8a0cb07a18cb95bf4bb`.
  The binding matched and all seven mutable canary state files were byte-exact
  to the sealed snapshot.
- Tests: complete combat-canary state suite 170/170; focused live-delta,
  strict-policy, state-reader, and reset suites 24/24, 13/13, 25/25, and 14/14;
  independent review found no remaining P0, P1, or P2 issue.
- Stable smoke result: a later Stable server ran from 21:24:49Z through
  21:30:15Z and shut down normally, but recorded no client session, character
  load, save, or disconnect. Its prelaunch backup remained byte-exact. Elapsed
  process time alone is not an active Twills smoke.
- Limitation: a later complete `Target Both` hash pass exceeded its 120-second
  command bound and is not claimed. The focused bound-manifest and seven-file
  reset comparisons passed; the canonical active Stable Forest smoke remains
  required before Phase 0 closure.
- Rollback: keep both environments stopped and use
  `Reset-PSOBBCombatCanaryState.ps1` with the bound sealed snapshot directory;
  never copy individual player, bank, license, system, card, or team files.

## 2026-07-21 / gameplay-observation-core-v1

- Feature/profile: bounded source-only observation ABI and SPSC evidence ring;
  no Gameplay feature flag or runtime profile was enabled
- Outcome: source gate accepted; no native hook, live event observation,
  gameplay input, process-memory write, runtime publication, or combat behavior
  is accepted by this entry
- Implementation commit: `ff811d6` (`feat: add bounded combat observations`)
- ABI result: module `0.2.0-observation-core`; existing capability ABI v1 and
  904-byte layout unchanged; observation ABI v1 uses 32-byte events and a
  65,568-byte, 2,048-event snapshot
- Concurrency result: actual-thread single-producer binding, acquire/release
  publication, non-waiting single-consumer drain, saturating counters, nonzero
  bounded sequencing, caller-proven producer quiescence, and reset/drain
  exclusion. The record path performs no allocation, blocking lock, file I/O,
  IPC, or logging.
- Build result: strict target-scoped C++20/x86 with compiler extensions off,
  static CRT, warnings as errors, SDL checks, reproducible compilation, and CFG
  protection; the portable preset discovers an installed Visual Studio
  generator that supports `Win32` rather than pinning a machine-specific
  version.
- Tests: fresh Win32 Release configure and clean build; MSVC code analysis with
  zero diagnostics; CTest 4/4; allocation counter remained zero; 50,000-event
  concurrent SPSC ordering, true 32-bit cursor rollover, sequence exhaustion,
  saturating counters, wrong-thread producer, and reset/drain boundaries
  passed; ProjectLayout 14/14; whitespace and changed-file attribution scans
  passed; independent re-review found no P0, P1, or P2 issue.
- PE result: `pei-i386` with ASLR, NX, and CFG; six undecorated exports including
  `PSOBBGameplay_DrainObservations`; only `bcrypt.dll` and `KERNEL32.dll`
  imports were reported.
- State result: no runtime was started or changed by this source gate. Twills,
  saves, registry, shortcuts, Stable, CombatCanary, and shared RenderDoc state
  were unchanged.
- Limitation: exact hook sites, adapter publication, action-state mapping,
  packet evidence, runtime-load proof, and both required live checkpoints remain
  pending. The observation probe itself is not yet complete.
- Rollback: no runtime rollback is required; keep the module unpublished and
  use a focused local Git revert of `ff811d6` if this source slice must be
  withdrawn.
