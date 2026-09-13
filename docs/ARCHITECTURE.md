# Architecture

PSOBB uses a layered architecture built around strict environment isolation, explicit component ownership, versioned contracts, deterministic recovery, and evidence-gated promotion.

This document defines the project's structural model and architectural invariants. It intentionally avoids workstation layout, operational commands, transient test history, and implementation-specific deployment details.

For checkpoint status, the [implementation ledger](COMBAT-IMPLEMENTATION-LEDGER.md) is authoritative. For procedures, see [Operations](OPERATIONS.md).

## Architectural principles

The architecture follows six core rules.

**Stable is recoverable.**
Experimental work must preserve a verified path back to the accepted Stable Native baseline.

**Stateful experimentation is isolated.**
Gameplay-sensitive, protocol-sensitive, and persistence-sensitive candidates use an environment with independent mutable state.

**Ownership is narrow.**
Presentation, gameplay, client safety, lifecycle orchestration, account operations, and service-facing behavior have separate owners.

**Identity precedes mutation.**
Runtime-sensitive changes require exact component, executable, configuration, and state identities before modification is permitted.

**Failure is closed and reversible.**
Ambiguous identity, unexpected state, incomplete verification, or foreign mutation blocks advancement rather than widening the accepted boundary.

**Acceptance is evidence-based.**
A successful build, launch, or isolated observation does not independently establish accepted behavior.

## System model

PSOBB separates tracked engineering state from mutable runtime state and separates accepted operation from experimental environments.

```text
Repository
│
├── Source
├── Configuration and schemas
├── Ordered runtime changes
├── Tests and validation
├── Orchestration
└── Documentation
        │
        ▼
Build and verification
        │
        ▼
┌───────────────────────────────────────────┐
│              Runtime domains              │
├───────────────────────────────────────────┤
│ Stable Native                             │
│ GraphicsCanary                            │
│ CombatCanary                              │
│ LocalLab                                  │
└───────────────────────────────────────────┘
        │
        ▼
Acceptance and promotion
        │
        ▼
Release boundary
```

Each runtime domain has a distinct purpose. Passing one domain's gates does not implicitly authorize another.

## Runtime environments

| Environment        | Purpose                                                                    | State model                                                                           | Promotion role                                          |
| ------------------ | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| **Stable Native**  | Known-good compatibility and recovery baseline                             | Canonical persistent state                                                            | Recovery authority and regression target                |
| **GraphicsCanary** | Presentation and renderer evaluation                                       | Uses Stable runtime services and persistent state under presentation-only constraints | Graphics acceptance only                                |
| **CombatCanary**   | Gameplay, protocol, persistence, and client-runtime development            | Fully isolated mutable state and bindings                                             | Primary behavioral acceptance environment               |
| **LocalLab**       | Controlled evaluation of private, restricted, or reference-only candidates | Separately staged evaluation state                                                    | Never sufficient by itself for distributable acceptance |
| **Release**        | Future distributable runtime                                               | Derived only from explicitly accepted identities                                      | Final promotion boundary                                |

### Stable Native

Stable Native is the project's recovery authority.

It defines the accepted baseline for:

* client compatibility;
* persistent character and account state;
* lifecycle behavior;
* save and relog behavior;
* recovery verification; and
* regression comparison.

Stable is not the normal location for experimental mutation. A candidate that could affect gameplay semantics, protocol behavior, persistent state, or client execution must first advance through the applicable isolated environment.

Accepted Stable state must remain independently recoverable from experimental state.

### GraphicsCanary

GraphicsCanary exists for presentation changes that do not require an independent gameplay or persistence environment.

It may evaluate rendering, presentation, window behavior, scaling, geometry, display integration, and project-owned visual enhancement behavior.

GraphicsCanary must not independently redefine:

* persistent-state formats;
* gameplay protocol semantics;
* account identity;
* character state;
* combat behavior; or
* save behavior.

A presentation candidate that crosses one of those boundaries becomes a CombatCanary concern.

### CombatCanary

CombatCanary is the isolated acceptance environment for runtime-sensitive development.

It owns an independent set of:

* runtime binaries;
* client bindings;
* runtime configuration;
* account state;
* character state;
* team or shared state;
* backups;
* snapshots;
* lifecycle records;
* evidence;
* secrets; and
* recovery metadata.

Stable and CombatCanary state must never overlap.

CombatCanary is the only normal environment in which a candidate may intentionally exercise protocol-sensitive, save-sensitive, gameplay-sensitive, or native client behavior before promotion.

Stable and CombatCanary are mutually exclusive where concurrent runtime ownership could create ambiguity over listeners, processes, mutable state, or lifecycle authority.

### LocalLab

LocalLab is an evaluation boundary rather than an acceptance authority.

It may contain private, restricted, experimental, or reference-only material required to understand behavior or compare candidate implementations.

LocalLab results can inform project-owned implementation, but LocalLab content does not become distributable merely because it functions correctly.

Promotion from LocalLab requires a separately accepted implementation whose ownership, provenance, distribution classification, and rollback behavior satisfy the project's release rules.

## Component ownership

Runtime-sensitive responsibilities are divided deliberately.

| Component             | Architectural ownership                                                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `PSOBB.ClientSafety`  | Exact-client identity, memory-range validation, mutation ownership, hook safety, and deterministic native rollback primitives              |
| `PSOBB.Gameplay`      | Gameplay observation, action state, hotbar behavior, focused input, buffering, native-action integration, and bounded gameplay diagnostics |
| `PSOBB.Enhancement`   | Presentation, display integration, and presentation-side runtime enhancement                                                               |
| `PSOBB.LargeAssets`   | Project-controlled large-asset handling required by accepted presentation work                                                             |
| `PSOBB.Launcher`      | Environment selection, supported lifecycle entry points, runtime validation, and user-facing launch behavior                               |
| `PSOBB.AccountBroker` | Narrow account-management operations across the protected service boundary                                                                 |
| `PSOBB.Portal`        | Service-facing application behavior without direct ownership of protected runtime state                                                    |
| `scripts/`            | Stopped-runtime orchestration, publication, recovery, evidence handling, and verification                                                  |
| `config/`             | Versioned capabilities, manifests, profiles, schemas, provenance records, and compatibility contracts                                      |

Ownership is exclusive where conflicting mutation could affect correctness.

A component must not silently absorb another component's responsibility merely because the required data or execution surface is technically reachable.

## Client runtime boundary

Client-sensitive functionality is divided between safety, gameplay, and presentation layers.

```text
Supported client process
│
├── PSOBB.ClientSafety
│     └── identity and mutation safety
│
├── PSOBB.Gameplay
│     └── gameplay state and behavior
│
└── PSOBB.Enhancement
      └── presentation and display behavior
```

`PSOBB.ClientSafety` is the common safety authority for native runtime mutation.

Gameplay and presentation components must not independently implement competing mutation-safety mechanisms for shared executable surfaces.

A native mutation requires, as applicable:

1. exact supported executable identity;
2. exact expected original state;
3. validated executable or data range;
4. exclusive ownership of the target;
5. bounded mutation scope;
6. deterministic rollback;
7. verification after mutation; and
8. an inert failure state.

Unexpected mutation by another owner is treated as foreign state. It must not be overwritten merely to force rollback or publication to succeed.

## Real-time execution boundary

Real-time gameplay code has stricter constraints than orchestration code.

Gameplay-critical paths must remain bounded and predictable. They must avoid:

* unbounded allocation;
* blocking synchronization;
* filesystem access;
* inter-process communication;
* unbounded diagnostic output; and
* general-purpose external control.

Bounded diagnostics use fixed-capacity structures and remain disabled unless explicitly required by an accepted evidence workflow.

Stopped-runtime orchestration is responsible for filesystem transactions, publication, recovery, configuration changes, and evidence preparation. It is not a real-time gameplay controller.

## Gameplay observation architecture

Gameplay observation is intentionally separated from gameplay modification.

The observation path is structured as:

```text
Native game event
      │
      ▼
Exact-client observation adapter
      │
      ▼
Bounded in-process event buffer
      │
      ▼
Bounded evidence consumer
      │
      ▼
Protected run evidence
      │
      ▼
Stopped-runtime verifier
      │
      ▼
Bounded semantic summary
```

The observation adapter records only explicitly defined events.

Observation does not by itself authorize:

* synthetic actions;
* synthetic protocol traffic;
* combat decisions;
* action timing;
* input generation; or
* persistent-state mutation.

The in-process evidence path has fixed capacity and bounded records. Evidence production must not turn the gameplay path into a general logging or telemetry subsystem.

Each explicit evidence run binds the relevant process, executable, module, configuration, and run identities before its result can be accepted.

Raw runtime evidence remains outside source control. The stopped-runtime verifier reduces it to the bounded information required for acceptance.

## Service trust boundaries

Account, portal, launcher, and runtime responsibilities remain separated.

```text
Portal
  │
  ▼
AccountBroker
  │
  ▼
Narrow account operation boundary
  │
  ▼
Protected runtime state
```

### Portal boundary

`PSOBB.Portal` is an application-facing layer.

It must not directly:

* read protected game credentials;
* traverse protected runtime state;
* control runtime processes;
* execute arbitrary runtime commands;
* modify character or save data; or
* bypass account-service authorization.

The portal consumes explicitly defined service contracts.

### AccountBroker boundary

`PSOBB.AccountBroker` is the narrow authority for account-management operations that require access beyond the portal boundary.

Its interface must be allowlisted and typed.

The broker must not expose:

* arbitrary command execution;
* arbitrary filesystem access;
* unrestricted process control; or
* raw protected-state access to callers.

Account operations and general runtime administration remain separate concerns.

### Launcher boundary

`PSOBB.Launcher` owns supported user-facing runtime selection and lifecycle entry points.

The launcher may request validated project operations, but it is not a general administrative shell.

Environment identity and runtime validation precede state-changing launcher operations.

## Credential boundaries

Game credentials and future service-facing credentials are separate security domains.

One credential must not implicitly become another service's credential merely because both represent the same user.

Credential material is excluded from source control and must remain inside the protected runtime boundary.

Secrets must not be exposed through:

* command arguments;
* logs;
* source-controlled configuration;
* evidence summaries;
* clipboard-dependent automation; or
* public manifests.

Development acceptance credentials and release-signing credentials are also separate trust roots.

A development acceptance identity must never be promoted implicitly into release authority.

## State architecture

PSOBB distinguishes source state, immutable runtime identity, mutable gameplay state, private evidence, and recovery state.

| State class                    | Characteristics                                                        | Source controlled |
| ------------------------------ | ---------------------------------------------------------------------- | ----------------- |
| **Project source**             | Code, schemas, tests, orchestration, documentation                     | Yes               |
| **Declarative contracts**      | Profiles, capabilities, provenance, expected identities                | Yes               |
| **Build identity**             | Deterministically derived or cryptographically bound artifact identity | Contract only     |
| **Stable mutable state**       | Canonical accepted account and gameplay state                          | No                |
| **CombatCanary mutable state** | Isolated experimental account and gameplay state                       | No                |
| **Private evidence**           | Runtime captures, bounded event files, detailed diagnostics            | No                |
| **Secrets**                    | Credentials, signing material, protected authorization state           | No                |
| **Backups and snapshots**      | Recovery and transactional state                                       | No                |

Source control is therefore an engineering-history boundary, not a runtime database or backup system.

## State isolation

Stable and CombatCanary maintain independent mutable-state trees.

A CombatCanary operation must never satisfy its requirements by reading or mutating Stable state unless the operation explicitly uses an immutable verified Stable-derived input as part of a defined materialization contract.

Once materialized, canary mutable state belongs exclusively to CombatCanary.

Canary state restoration uses the bound snapshot or transaction mechanism for the entire defined state set. Individual persistent files are not manually substituted as a shortcut around a failed state gate.

GraphicsCanary may operate against Stable state only because its architectural contract is presentation-only. If a graphics candidate begins mutating gameplay or persistence semantics, that sharing assumption is invalid.

## Identity model

Runtime authority is established through composable identities rather than filenames or path existence alone.

Important identities include:

**Executable identity**
The exact supported client or runtime executable.

**Artifact identity**
The exact built component and its reproducible source relationship.

**Configuration identity**
The exact configuration accepted for that component or environment.

**Client binding**
The closed set of executable, module, loader, and configuration identities that constitute one playable client.

**Installation identity**
The runtime components and bindings selected for an environment.

**State binding**
The exact snapshot or mutable-state authority associated with the isolated environment.

**Provenance identity**
The immutable source, artifact, compatibility, distribution, and rollback information used to reproduce or evaluate a component.

A valid higher-level identity depends on every required lower-level identity remaining valid.

## Contract model

Durable project contracts are versioned and closed wherever ambiguity could affect safety.

Contracts should:

* reject unsupported schema versions;
* reject ambiguous or duplicate fields;
* reject unsupported extra state where compatibility does not require it;
* apply explicit size and count bounds;
* use exact identities for security-sensitive decisions;
* separate optional absence from malformed input; and
* fail before mutation when validation is incomplete.

Compatibility expansion requires an explicit contract change. It must not emerge accidentally from permissive parsing.

## Publication model

Runtime publication is a stopped-state transaction.

The general model is:

```text
candidate
   │
   ▼
preflight identity verification
   │
   ▼
durable transaction preparation
   │
   ▼
bounded mutation
   │
   ▼
exact readback
   │
   ├── valid ──► commit
   │
   └── invalid ► compensate or recover
```

A publication operation must establish sufficient recovery information before its first live mutation.

Where replacement occurs, the project preserves enough identity information to distinguish:

* the original object;
* the candidate object;
* the committed replacement; and
* any unexpected foreign object.

Successful publication and rollback are independently verified.

Publication of a component does not establish behavioral acceptance. Runtime acceptance remains a separate gate.

## Promotion model

Candidates advance through progressively stronger evidence.

```text
design
  │
  ▼
source implementation
  │
  ▼
deterministic build
  │
  ▼
static and unit verification
  │
  ▼
isolated publication
  │
  ▼
runtime validation
  │
  ▼
state and lifecycle verification
  │
  ▼
rollback proof
  │
  ▼
accepted capability
  │
  ▼
eligible promotion
```

Promotion is capability-specific.

Acceptance of one behavior does not authorize unrelated configuration, assets, hooks, protocol changes, or runtime mutations.

Release eligibility additionally requires the applicable provenance, distribution, security, and production gates.

## Rollback and recovery

Rollback is an architectural capability, not an emergency afterthought.

The project distinguishes several forms of recovery:

**Mutation rollback**
Returns a modified component to its exact pre-mutation state.

**Publication rollback**
Reverses a transactional runtime publication where the publication contract supports it.

**State reset**
Restores an isolated mutable-state set from its bound snapshot.

**Backup restore**
Recovers persistent runtime state through the verified recovery workflow.

**Stable recovery**
Returns operation to the accepted Stable Native baseline.

These operations are not interchangeable.

For example, restoring isolated character state does not constitute rollback of a changed runtime artifact.

Rollback uses compare-before-restore behavior where foreign mutation is possible. Unknown current state is preserved for investigation rather than overwritten merely to recreate an expected result.

## Evidence boundary

Acceptance evidence is divided into private raw evidence and source-controlled semantic records.

Private evidence can include:

* runtime event files;
* diagnostic output;
* performance captures;
* screenshots or visual captures;
* detailed process information;
* protected transaction receipts; and
* private state-verification material.

These remain outside source control.

Tracked documentation records only the bounded evidence necessary to establish the checkpoint outcome.

The [implementation ledger](COMBAT-IMPLEMENTATION-LEDGER.md) is append-only. Historical results are corrected through later entries rather than rewriting prior checkpoints.

## Repository boundary

The repository tracks the project-owned engineering surface:

```text
config/      declarative contracts and schemas
docs/        architecture, acceptance, roadmap, and records
patches/     ordered project runtime changes
scripts/     orchestration and verification
src/         project-owned implementation
tests/       automated validation
```

Mutable runtime material remains outside source control.

The runtime boundary contains generated artifacts, mutable state, credentials, evidence, private inputs, backups, snapshots, and other data whose lifecycle differs from source history.

The exact physical layout is an operational concern documented in [Project layout](PROJECT-LAYOUT.md), rather than an architectural dependency.

## Release boundary

Development acceptance and release authorization are separate.

A release candidate must derive only from explicitly permitted identities and must satisfy the applicable:

* capability acceptance;
* provenance;
* distribution;
* security;
* signing;
* recovery;
* deployment; and
* operational gates.

Evaluation-only material cannot enter the release boundary solely because it was useful during development.

Development trust material also cannot become release trust material implicitly.

See [Production gates](PRODUCTION-GATES.md) for the requirements beyond development acceptance.

## Current architectural state

This section is a concise architectural snapshot. Detailed checkpoint history remains in the implementation ledger.

| Area                      | Current architectural state                                                                                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stable Native**         | Established and accepted as the recovery authority                                                                                                                              |
| **CombatCanary**          | Materialized with isolated runtime and persistent state; Native gameplay, restart/relog, state verification, and sealed-state restoration have passed their defined gates       |
| **Baseline closure**      | Final post-canary Stable active-gameplay acceptance remains pending                                                                                                             |
| **Gameplay observation**  | Bounded observation, passive exact-client instrumentation, in-process evidence capture, protected run binding, and stopped-runtime verification are implemented at source level |
| **Gameplay publication**  | Transactional publication and rollback mechanisms are validated; canonical live publication and observation acceptance remain gated                                             |
| **Modern gameplay**       | Observation infrastructure exists; action-state mapping and behavior-changing candidates have not yet crossed their acceptance gates                                            |
| **Graphics architecture** | GraphicsCanary and LocalLab boundaries are established; multiple candidates are runtime-validated while final distributable presentation acceptance remains pending             |
| **Service architecture**  | Launcher, account-broker, and portal ownership boundaries exist in source; deployment authority remains separately gated                                                        |
| **Release architecture**  | Release is a future promotion boundary and is not implied by development acceptance                                                                                             |

## Architectural invariants

The following conditions must remain true as the project evolves:

1. Stable remains a valid independent recovery authority.
2. CombatCanary mutable state remains isolated from Stable mutable state.
3. Presentation and gameplay mutation ownership remain separate.
4. Shared native mutation safety remains centralized in `PSOBB.ClientSafety`.
5. Real-time gameplay behavior remains bounded and free of stopped-runtime orchestration concerns.
6. Portal-facing code does not gain direct protected-runtime authority.
7. Account-management interfaces remain narrow and allowlisted.
8. Runtime publication remains transactional and independently verifiable.
9. Unknown or foreign runtime state fails closed.
10. Raw private evidence, credentials, and mutable gameplay state remain outside source control.
11. Acceptance remains capability-specific.
12. Development acceptance never implicitly grants release authorization.

A change that violates one of these invariants is an architectural change and requires explicit review rather than being treated as an ordinary implementation detail.

## Documentation authority

Project documentation has deliberately separate responsibilities.

| Document                          | Authority                                                                   |
| --------------------------------- | --------------------------------------------------------------------------- |
| `README.md`                       | Project identity, goals, high-level state, and navigation                   |
| `ARCHITECTURE.md`                 | Structural boundaries, component ownership, trust, state, and invariants    |
| `COMBAT-IMPLEMENTATION-LEDGER.md` | Authoritative accepted, rejected, pending, and corrected checkpoint history |
| `COMBAT-ACCEPTANCE.md`            | Behavioral acceptance requirements                                          |
| `COMBAT-MODERNIZATION.md`         | Ordered gameplay direction and feature roadmap                              |
| `GRAPHICS-ACCEPTANCE.md`          | Presentation acceptance contracts and evidence requirements                 |
| `PROJECT-LAYOUT.md`               | Physical runtime organization and filesystem policy                         |
| `OPERATIONS.md`                   | Supported operator procedures                                               |
| `PRODUCTION-GATES.md`             | Requirements beyond development acceptance                                  |

When descriptive status conflicts with the implementation ledger, the latest applicable accepted ledger entry governs.

When an operational procedure conflicts with an architectural invariant, the invariant governs until the conflict is explicitly resolved.
