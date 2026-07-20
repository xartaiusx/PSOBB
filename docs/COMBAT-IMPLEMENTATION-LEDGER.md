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
