# Operations

PSOBB operations are performed through project-owned lifecycle, validation, publication, recovery, and evidence workflows.

This document defines the supported operational procedures for the development runtime. It is intentionally repository-relative and avoids workstation-specific paths, historical migration detail, and implementation-specific external tooling.

For structural boundaries, see [Architecture](ARCHITECTURE.md).
For logical filesystem ownership, see [Project layout](PROJECT-LAYOUT.md).
For authoritative development checkpoints, see [Combat implementation ledger](COMBAT-IMPLEMENTATION-LEDGER.md).

## Operational principles

All supported operations follow the same rules.

**Verify before mutation.**
Validate the target runtime, environment, component identities, and applicable contracts before changing state.

**Stop before structural mutation.**
Publication, restore, state reset, profile changes, and other structural operations require the affected runtime to be stopped unless the workflow explicitly defines a live-safe operation.

**Use project lifecycle commands.**
Start and stop environments through project tooling so process identity, ownership, receipts, and graceful shutdown behavior remain verifiable.

**Keep environments explicit.**
Stable and CombatCanary are separate runtime authorities. An operation must never infer permission to cross their state boundaries.

**Preview consequential operations.**
When a command supports preview semantics, inspect the proposed mutation before applying it.

**Back up before persistent change.**
Persistent-state, runtime, profile, or compatibility changes require a current recoverable state where the applicable contract calls for one.

**Treat unknown state as a stop condition.**
Unexpected processes, files, identities, listeners, bindings, or transaction remnants are investigated rather than overwritten.

**Keep secrets private.**
Credentials, signing material, private evidence, and protected recovery data remain outside source history and command-line arguments.

## Command context

Run project scripts from the repository root unless a workflow explicitly states otherwise.

The canonical runtime is the repository-relative:

```text
PSOBB-Runtime/
```

Most project commands resolve that runtime automatically.

`-RuntimeRoot` exists for explicitly supported isolated or test contexts. Routine canonical operation should not depend on hard-coded absolute paths.

The effective runtime must always pass the project's runtime-marker, containment, and identity checks before mutation.

## Operational authority

The primary operational surfaces are:

| Area                         | Primary commands                                                    |
| ---------------------------- | ------------------------------------------------------------------- |
| Initialization               | `Initialize-PSOBB.ps1`                                              |
| Client integration           | `Initialize-PSOBBClientRegistry.ps1`                                |
| Runtime protection           | `Set-PSOBBRuntimeAcl.ps1`, `Test-PSOBBRuntimeAcl.ps1`               |
| Provenance validation        | `Test-PSOBBSupplyChain.ps1`                                         |
| Accounts                     | `New-PSOBBAccount.ps1`, credential rotation helpers                 |
| Stable lifecycle             | `Start-PSOBBSession.ps1`, `Stop-PSOBBSession.ps1`, `Test-PSOBB.ps1` |
| Client reconstruction        | `Reset-PSOBBClientRuntime.ps1`                                      |
| Backup                       | `Backup-PSOBB.ps1`                                                  |
| Restore                      | `Restore-PSOBB.ps1`                                                 |
| Restore testing              | `Test-PSOBBRestoreDrill.ps1`                                        |
| CombatCanary verification    | `Test-PSOBBCombatCanary.ps1`                                        |
| CombatCanary build           | `Build-PSOBBCombatCanaryServer.ps1`                                 |
| CombatCanary materialization | `Initialize-PSOBBCombatCanary.ps1`                                  |
| CombatCanary snapshot        | `New-PSOBBCombatCanarySnapshot.ps1`                                 |
| CombatCanary reset           | `Reset-PSOBBCombatCanaryState.ps1`                                  |
| Gameplay publication         | `Set-PSOBBCombatCanaryGameplay.ps1`                                 |
| Gameplay evidence            | `Get-PSOBBGameplayObservationEvidence.ps1`                          |
| Graphics validation          | `Test-PSOBBGraphicsProfiles.ps1`, `Test-PSOBBGraphicsArtifacts.ps1` |
| Graphics evidence            | `Get-PSOBBGraphicsEvidenceStatus.ps1`                               |
| LocalLab                     | `New-PSOBBGraphicsLabRuntime.ps1`                                   |
| Profile selection            | `Set-PSOBBClientPatchProfile.ps1`                                   |
| Cleanup                      | Project-owned bounded cleanup commands                              |

The scripts themselves remain authoritative for exact parameter validation.

## Current operational state

The operational model has advanced beyond initial canary construction.

| Area                                    | Current state                                                   |
| --------------------------------------- | --------------------------------------------------------------- |
| **Stable Native**                       | Accepted recovery baseline                                      |
| **Stable backup/restore**               | Backup and restore-drill workflows established and accepted     |
| **CombatCanary**                        | Materialized and isolated                                       |
| **CombatCanary Native gameplay**        | Accepted under its defined isolated scenario                    |
| **CombatCanary restart/relog**          | Accepted                                                        |
| **CombatCanary state reset**            | Exact sealed-state restoration accepted                         |
| **Gameplay observation implementation** | Source-ready                                                    |
| **Gameplay overlay publication**        | Transactional source and fixture validation passed              |
| **Canonical live gameplay overlay**     | Pending                                                         |
| **Canonical observation evidence**      | Pending                                                         |
| **Graphics**                            | Multiple candidates runtime-validated; final acceptance pending |
| **Release**                             | Separately gated and not authorized by development acceptance   |

The latest applicable entry in the implementation ledger governs if this summary ever becomes stale.

## Initial runtime materialization

Initial setup begins only after the required immutable project inputs are present under the runtime boundary.

First validate the tracked provenance and compatibility contracts:

```text
.\scripts\Test-PSOBBSupplyChain.ps1
```

Initialize the canonical runtime:

```text
.\scripts\Initialize-PSOBB.ps1
```

Initialization is responsible for validating approved immutable inputs, creating the runtime structure, establishing installation identity, preparing the Stable runtime, and binding the baseline profile.

Do not manually populate generated runtime directories as a substitute for initialization.

### Client integration

Initialize the supported client-side integration when required:

```text
.\scripts\Initialize-PSOBBClientRegistry.ps1
```

This is a project-owned initialization step.

Its implementation details are not part of the project layout contract and must not become a source of manually maintained runtime authority.

## Runtime protection

Protected runtime state includes credentials, mutable gameplay state, backups, logs, evidence, snapshots, private evaluation material, and other sensitive runtime data identified by the current policy.

Apply the project runtime-protection policy:

```text
.\scripts\Set-PSOBBRuntimeAcl.ps1 -Confirm:$false
```

Verify it independently:

```text
.\scripts\Test-PSOBBRuntimeAcl.ps1
```

Protection should be reverified after workflows that create new protected runtime state, including:

* initialization;
* backup;
* restore;
* snapshot creation;
* canary materialization;
* evidence generation; and
* private runtime activation.

A protection failure blocks further acceptance-sensitive operation.

Do not broaden permissions simply to make a failing workflow succeed.

## Account provisioning

Account creation uses the project-owned provisioning workflow.

Create the account metadata first:

```text
.\scripts\New-PSOBBAccount.ps1 -Role Admin
.\scripts\New-PSOBBAccount.ps1 -Role Player
```

Provision each intended runtime account explicitly:

```text
.\scripts\New-PSOBBAccount.ps1 -Role Admin -Provision
.\scripts\New-PSOBBAccount.ps1 -Role Player -Provision
```

Administrative and ordinary-player roles remain distinct.

Credentials must not be:

* passed as ordinary command arguments;
* written into source-controlled configuration;
* emitted into logs;
* included in evidence summaries; or
* copied into documentation.

Use the project credential-rotation commands for later changes:

```text
.\scripts\Set-PSOBBAdminCredential.ps1
.\scripts\Set-PSOBBPlayerCredential.ps1
```

Credential rotation must use the command's protected interactive workflow.

A credential operation that cannot prove its intended account identity must fail without mutation.

## Stable Native preparation

Stable Native is the accepted recovery authority.

Reconstruct the playable Stable client from its immutable base when required:

```text
.\scripts\Reset-PSOBBClientRuntime.ps1 -Renderer Native
```

Stable reconstruction must verify the complete expected client inventory rather than trusting only a primary executable.

The accepted baseline profile remains the recovery profile.

Select it explicitly when recovery requires profile normalization:

```text
.\scripts\Set-PSOBBClientPatchProfile.ps1 -Profile baseline -Confirm:$false
```

Profile changes require the affected runtime to be stopped.

## Stable lifecycle

Use the combined session command for ordinary Stable operation:

```text
.\scripts\Start-PSOBBSession.ps1 `
  -ServerEnvironment Stable `
  -Channel Native `
  -WindowMode ProfileDefault
```

The session workflow:

1. resolves and validates the canonical runtime;
2. rejects ambiguous existing runtime processes;
3. starts the Stable service environment if needed;
4. verifies readiness;
5. runs the Stable baseline verification;
6. launches the exact selected client; and
7. records bounded lifecycle information.

Validate Stable independently when required:

```text
.\scripts\Test-PSOBB.ps1 -Suite Baseline
```

Stop the complete Stable session through the lifecycle controller:

```text
.\scripts\Stop-PSOBBSession.ps1 `
  -ServerEnvironment Stable `
  -Target All
```

Graceful shutdown is the normal path.

Force options exist as recovery mechanisms and should be used only after the corresponding graceful path cannot complete and the remaining process identity is known.

## Environment switching

Stable and CombatCanary must not operate concurrently.

Before switching environments:

1. stop the active session through the project lifecycle command;
2. confirm the stop completed successfully;
3. validate the target environment; and
4. start the new environment explicitly.

The lifecycle controller performs a global process census and rejects ambiguous or cross-environment ownership.

Do not manually terminate a process and assume the environment is now clean.

If the lifecycle controller reports unknown or uninspectable state, investigate that state before continuing.

## Stable backup

Create a Stable backup before any operation capable of changing persistent state or recovery authority when the applicable acceptance contract requires one.

```text
$backup = .\scripts\Backup-PSOBB.ps1
```

A backup is valid only when its project manifest and protected contents pass verification.

Do not edit a backup in place.

Do not use individual files extracted from a backup as an informal replacement for the restore workflow.

## Restore drill

A backup should periodically prove that it can be restored through the isolated restore-drill workflow.

```text
.\scripts\Test-PSOBBRestoreDrill.ps1 `
  -BackupPath $backup.BackupPath
```

The restore drill operates outside live Stable state.

A passing drill demonstrates recoverability under the drill's defined contract. It does not authorize unrelated runtime changes.

### Restore-drill quarantine

If a restore drill cannot prove process termination or cannot confirm all bounded output readers reached a terminal state, the drill preserves its working root as quarantine.

A quarantined drill must not be manually deleted merely because a timeout has elapsed.

Preserve it until the recorded process identity can be proven absent and the reserved runtime listener set is confirmed clear.

Unknown or conflicting process identity remains a stop condition.

The quarantine exists specifically to avoid destroying evidence while process ownership is uncertain.

## Stable restore

A real restore is consequential and requires the Stable runtime to be stopped.

Validate the candidate backup first:

```text
.\scripts\Restore-PSOBB.ps1 `
  -BackupPath <backup-path> `
  -ValidateOnly
```

Preview the restore:

```text
.\scripts\Restore-PSOBB.ps1 `
  -BackupPath <backup-path> `
  -WhatIf
```

Apply only after the validation and preview match the intended target:

```text
.\scripts\Restore-PSOBB.ps1 `
  -BackupPath <backup-path> `
  -Confirm:$false
```

The restore workflow is transactional.

It prepares recovery state before replacing live state and preserves enough information to compensate for an interrupted mutation where the current identity still permits safe compensation.

After restore:

```text
.\scripts\Test-PSOBB.ps1 -Suite Baseline
```

A restore is complete only when its resulting Stable state passes the required verification.

## CombatCanary

CombatCanary is already materialized and is the isolated authority for gameplay-sensitive, protocol-sensitive, and persistent-state-sensitive development.

Routine operation should validate the installed canary rather than recreating it.

Verify its installed state:

```text
.\scripts\Test-PSOBBCombatCanary.ps1 -Target Installed
```

This verification checks the environment against the tracked build and installation contracts.

A failed installed-state check blocks canary execution.

## CombatCanary lifecycle

Start the isolated Native canary:

```text
.\scripts\Start-PSOBBSession.ps1 `
  -ServerEnvironment CombatCanary `
  -Channel Native `
  -WindowMode ProfileDefault
```

Stop it through the same project lifecycle:

```text
.\scripts\Stop-PSOBBSession.ps1 `
  -ServerEnvironment CombatCanary `
  -Target All
```

CombatCanary owns its own:

* runtime;
* account state;
* character state;
* shared gameplay state;
* bindings;
* backups;
* snapshots;
* logs;
* secrets;
* evidence; and
* lifecycle records.

Stable state must never be used as writable canary state.

## CombatCanary build verification

Rebuilding the isolated server artifact is a development operation, not a routine startup step.

Verify the currently built artifact when required:

```text
.\scripts\Build-PSOBBCombatCanaryServer.ps1 -Action Verify
```

A build is not accepted merely because compilation succeeds.

Its deterministic build identity, source contract, artifact inventory, publication result, and rollback behavior must satisfy the separate build contract.

See [CombatCanary build](COMBAT-CANARY-BUILD.md).

## CombatCanary materialization

`Initialize-PSOBBCombatCanary.ps1` is reserved for deliberate construction or reconstruction of the isolated canary environment.

Routine operation should not repeatedly rematerialize a valid canary.

Materialization requires:

* a verified build artifact;
* an accepted Stable-derived source state;
* a current protected backup where required;
* a valid sealed canary snapshot;
* tracked contract identities;
* no conflicting runtime processes;
* no conflicting environment ownership; and
* successful post-materialization readback.

Preview the materialization before applying it.

Do not substitute manually copied client, account, character, or server files for the transactional materialization workflow.

## CombatCanary snapshots

Create canary snapshots only through:

```text
.\scripts\New-PSOBBCombatCanarySnapshot.ps1
```

A snapshot is an exact sealed state authority.

It binds the complete state set required by the canary acceptance contract.

Do not:

* edit a snapshot;
* copy individual state files from it;
* combine files from multiple snapshots; or
* treat a Stable backup as an interchangeable canary snapshot.

Snapshot verification must succeed before materialization or reset uses it.

## CombatCanary state reset

A stateful canary scenario must be reset through the transactional canary-state workflow.

The reset target must be completely stopped.

Use:

```text
.\scripts\Reset-PSOBBCombatCanaryState.ps1 `
  -SnapshotPath <verified-snapshot-path> `
  -WhatIf
```

After reviewing the preview:

```text
.\scripts\Reset-PSOBBCombatCanaryState.ps1 `
  -SnapshotPath <verified-snapshot-path> `
  -Confirm:$false
```

Supply the additional tracked contract identities required by the selected snapshot when the current contract requires them.

After reset, perform complete installed verification again.

```text
.\scripts\Test-PSOBBCombatCanary.ps1 -Target Installed
```

State reset and runtime-artifact rollback are separate operations.

A successful state reset does not imply that a changed executable or gameplay module has been rolled back.

## Gameplay publication

Gameplay publication is a stopped-runtime transaction against CombatCanary.

The current publication mechanism supports activation and exact rollback:

```text
.\scripts\Set-PSOBBCombatCanaryGameplay.ps1 `
  -Action Activate `
  -WhatIf
```

Apply only after the preview is correct and the applicable acceptance prerequisites are satisfied:

```text
.\scripts\Set-PSOBBCombatCanaryGameplay.ps1 `
  -Action Activate `
  -Confirm:$false
```

Publication success proves that the transaction completed and its exact readback passed.

It does not establish gameplay acceptance.

### Gameplay rollback

Rollback uses the same project-owned transaction boundary:

```text
.\scripts\Set-PSOBBCombatCanaryGameplay.ps1 `
  -Action Rollback `
  -WhatIf
```

Then:

```text
.\scripts\Set-PSOBBCombatCanaryGameplay.ps1 `
  -Action Rollback `
  -Confirm:$false
```

Rollback must refuse to overwrite unknown or foreign current state.

Unexpected mutation is preserved for investigation.

## Gameplay observation evidence

Gameplay observation is the current foundation for later behavior-changing work.

Observation evidence is available only in CombatCanary.

After an accepted gameplay-overlay publication and all prerequisite verification, begin an explicit evidence session:

```text
$session = .\scripts\Start-PSOBBSession.ps1 `
  -ServerEnvironment CombatCanary `
  -Channel Native `
  -WindowMode ProfileDefault `
  -GameplayObservationEvidence
```

The session returns the exact observation run identity.

Perform the active gameplay scenario required by the current acceptance contract.

Stop the complete session:

```text
.\scripts\Stop-PSOBBSession.ps1 `
  -ServerEnvironment CombatCanary `
  -Target All
```

Parse and verify the stopped-runtime evidence:

```text
.\scripts\Get-PSOBBGameplayObservationEvidence.ps1 `
  -RunId $session.GameplayObservationRunId
```

The verifier binds the result to the recorded:

* environment;
* run;
* process;
* client;
* gameplay module;
* configuration;
* evidence file; and
* lifecycle identities.

Raw evidence remains private runtime state.

Only the bounded semantic acceptance result belongs in tracked project documentation.

Observation success does not authorize behavior-changing combat logic.

## Current gameplay acceptance gate

At the current project stage:

* the bounded observation core exists;
* passive exact-client instrumentation exists;
* protected evidence generation exists;
* stopped-runtime evidence verification exists;
* gameplay publication and rollback have passed source and fixture validation;
* canonical gameplay publication remains pending;
* canonical live observation acceptance remains pending;
* action-state mapping remains pending; and
* behavior-changing modern combat work remains gated.

Do not advance later combat phases by bypassing these pending gates.

## Graphics operations

Graphics work remains isolated from Stable recovery behavior.

Before evaluating a candidate, validate the tracked graphics contracts:

```text
.\scripts\Test-PSOBBGraphicsProfiles.ps1
.\scripts\Test-PSOBBGraphicsArtifacts.ps1
```

Inspect the current evidence state:

```text
.\scripts\Get-PSOBBGraphicsEvidenceStatus.ps1
```

The graphics acceptance registry remains fail closed.

A profile with incomplete evidence is still pending even when it launches successfully.

### GraphicsCanary

Use the disposable canary client for presentation candidates that remain within the graphics-only architectural boundary.

Client reconstruction occurs through:

```text
.\scripts\Reset-PSOBBClientRuntime.ps1
```

The exact renderer, profile, window mode, and related parameters must come from the tracked graphics contracts.

Do not manually compose a canary by copying arbitrary runtime files.

### Graphics evidence

Project-owned evidence tooling includes:

```text
.\scripts\Capture-PSOBBGraphicsTelemetry.ps1
.\scripts\Capture-PSOBBLosslessScreenshot.ps1
.\scripts\Get-PSOBBScreenshotEvidence.ps1
```

Raw captures remain under the runtime evidence boundary.

A tracked graphics decision should record bounded identity and acceptance results rather than embedding private evidence into source history.

## LocalLab

LocalLab is the private evaluation boundary.

Materialize a LocalLab runtime through:

```text
.\scripts\New-PSOBBGraphicsLabRuntime.ps1
```

LocalLab may contain evaluation-only material that cannot enter a distributable runtime.

A working LocalLab configuration proves only local evaluation behavior.

Promotion requires a separate project-owned candidate whose provenance, distribution classification, behavior, rollback, and evidence satisfy the normal acceptance path.

LocalLab content must not be copied directly into Stable, CombatCanary, or a future release.

## Quality-of-life profile operations

Stable Native remains the recovery profile.

Additional quality-of-life candidates are evaluated individually.

Profile selection uses:

```text
.\scripts\Set-PSOBBClientPatchProfile.ps1
```

Apply profile changes only while the affected runtime is stopped.

A grouped or reference profile does not imply that all capabilities within it are accepted.

Promotion remains capability-specific.

## Client runtime reconstruction

Use `Reset-PSOBBClientRuntime.ps1` when a disposable playable client needs to be reconstructed from its verified base.

The reset workflow should:

* verify the immutable base;
* recreate the selected runtime tree;
* apply only the declared profile;
* establish the expected runtime identity; and
* leave canonical persistent state untouched.

Do not repair an unknown playable client by manually replacing individual binaries.

Reconstruct it from the verified base instead.

## Installation-record repair

`Repair-PSOBBStableInstallationRecord.ps1` exists for narrowly defined installation-record recovery.

It is not a general-purpose way to bless an altered runtime.

Use it only when:

1. the supported repair preconditions are satisfied;
2. underlying runtime identities independently verify;
3. the operation can prove the intended installation; and
4. normal initialization would be inappropriate.

A failed repair precondition means stop and investigate.

## Evidence handling

Evidence has two classes.

**Raw evidence** remains under the protected runtime.

**Semantic records** may be tracked when they contain only the bounded result needed to support an acceptance decision.

Raw evidence may contain:

* detailed runtime identities;
* process information;
* captures;
* performance data;
* private state;
* diagnostic output; and
* transaction material.

Do not commit raw evidence by default.

Do not redact evidence manually and then treat the modified file as the original acceptance artifact.

Use project verification tooling to derive the tracked result.

## Cleanup

Cleanup must be narrow and identity-aware.

Never use broad deletion against the ignored runtime.

The runtime contains material that source control does not track but the project still depends on, including:

* live state;
* credentials;
* backups;
* snapshots;
* private evidence;
* immutable input archives; and
* recovery data.

### Build staging cleanup

Use the dedicated canary build-staging cleanup workflow when applicable:

```text
.\scripts\Remove-PSOBBCombatCanaryBuildStaging.ps1
```

It must not be replaced with recursive deletion of the canary build tree.

### Legacy-remnant cleanup

Historical project remnants may be audited through:

```text
.\scripts\Remove-PSOBBLegacyRemnants.ps1 -WhatIf
```

Apply cleanup only after the preview identifies exactly the intended project-owned remnants.

Do not widen cleanup rules to arbitrary directories, shared caches, unrelated application state, or unknown files.

Legacy cleanup is maintenance. It is not part of ordinary project startup.

## Relocation

The project layout is repository-relative.

A relocation must preserve the same logical source/runtime boundary defined by [Project layout](PROJECT-LAYOUT.md).

After relocation:

1. validate the canonical runtime marker;
2. regenerate or repair only path-bound generated state through supported project workflows;
3. verify Stable installation identity;
4. verify protected runtime state;
5. verify the Stable baseline;
6. validate CombatCanary independently; and
7. remove obsolete copies only through bounded cleanup after the new location is proven authoritative.

Do not retain multiple apparently canonical writable runtimes.

Path-dependent generated records from an obsolete location must not silently become authority at a new location.

## Failure handling

When a project command fails:

1. preserve the reported state;
2. do not repeat the command with weaker validation;
3. do not manually replace the target file;
4. inspect the exact failed identity or contract;
5. use the workflow's defined compensation or rollback path where available; and
6. return to Stable recovery when the experimental environment cannot be proven valid.

A failed command may intentionally leave protected transaction evidence.

Do not delete that evidence before determining whether it is required for safe recovery.

## Unknown process state

Lifecycle-sensitive commands fail closed when process ownership cannot be established.

If an unknown or uninspectable process appears related to the runtime:

* do not act on its process identifier merely because its name looks correct;
* do not force-stop it through unrelated tools as the first response;
* preserve lifecycle evidence;
* identify the executable and environment authority; and
* continue only after ambiguity is resolved.

Force-stop functionality is a controlled recovery mechanism for a known project-owned process.

## Transaction remnants

Publication and restore workflows may intentionally retain journals, staging state, rollback material, or quarantine records after interrupted operations.

Their presence is significant.

Do not delete a transaction remnant because the primary runtime appears functional.

Resume, compensate, verify, or quarantine according to the owning workflow.

Unknown transaction state blocks further mutation of the same target.

## Source-control safety

The runtime is excluded from source history, but exclusion does not make it disposable.

Avoid source-maintenance operations that recursively remove ignored files from the project root.

Before committing changes:

* inspect staged files;
* confirm runtime content is absent;
* confirm credentials and private evidence are absent;
* confirm generated binaries are absent; and
* confirm only intended project source and contracts are included.

If a secret is ever committed, treat it as exposed and rotate it. Removing the visible file alone is insufficient.

## Operational acceptance

An operational step is successful only when its required verification also succeeds.

Examples:

| Operation              | Required completion evidence                           |
| ---------------------- | ------------------------------------------------------ |
| Initialization         | Installation identity and baseline validation          |
| Runtime protection     | Independent protection verification                    |
| Stable start           | Exact lifecycle and baseline readiness                 |
| Stable stop            | Confirmed lifecycle shutdown                           |
| Backup                 | Valid protected backup manifest                        |
| Restore drill          | Passing isolated drill result                          |
| Restore                | Transaction completion plus Stable verification        |
| Canary materialization | Complete installed readback                            |
| Canary reset           | Snapshot verification plus complete installed readback |
| Gameplay publication   | Exact publication readback                             |
| Gameplay rollback      | Exact restored identity                                |
| Observation run        | Stopped-runtime bounded evidence verification          |
| Graphics candidate     | Applicable graphics evidence gates                     |
| LocalLab evaluation    | Local evidence only, with no promotion implied         |

Success output from a command is not a substitute for a separate verification step when the contract requires one.

## Release boundary

Development operations stop at accepted development artifacts and capabilities.

They do not authorize deployment or distribution.

A future release must independently satisfy the requirements in [Production gates](PRODUCTION-GATES.md), including the applicable:

* accepted capability set;
* provenance;
* signing;
* security;
* backup and recovery;
* monitoring;
* deployment;
* distribution; and
* operational-readiness gates.

Development credentials, development signing material, private evidence, LocalLab inputs, and canary mutable state must never enter a release merely because they exist in the development runtime.

## Routine workflow

The normal Stable workflow is:

```text
verify
  ↓
start Stable
  ↓
baseline validation
  ↓
use
  ↓
graceful stop
  ↓
backup when required
```

The normal canary workflow is:

```text
verify Stable recovery authority
  ↓
verify CombatCanary installation
  ↓
apply one isolated candidate
  ↓
verify publication
  ↓
run the defined scenario
  ↓
stop
  ↓
verify evidence and state
  ↓
reset isolated state where required
  ↓
prove rollback
  ↓
record the checkpoint
```

Only after a candidate completes its full required path is it eligible for promotion.

## Documentation authority

Operational decisions use the following authority order:

| Document                                                        | Responsibility                             |
| --------------------------------------------------------------- | ------------------------------------------ |
| [Architecture](ARCHITECTURE.md)                                 | Structural invariants and trust boundaries |
| [Project layout](PROJECT-LAYOUT.md)                             | Runtime and repository ownership           |
| `OPERATIONS.md`                                                 | Supported operator procedures              |
| [Combat acceptance](COMBAT-ACCEPTANCE.md)                       | Required gameplay acceptance evidence      |
| [CombatCanary build](COMBAT-CANARY-BUILD.md)                    | Isolated build and publication contract    |
| [Graphics acceptance](GRAPHICS-ACCEPTANCE.md)                   | Graphics evidence requirements             |
| [Combat implementation ledger](COMBAT-IMPLEMENTATION-LEDGER.md) | Authoritative checkpoint history           |
| [Production gates](PRODUCTION-GATES.md)                         | Deployment and release requirements        |

If an operational procedure would violate an architectural invariant, stop and resolve the conflict before proceeding.

If this document's status description differs from the implementation ledger, the latest applicable accepted ledger entry governs.
