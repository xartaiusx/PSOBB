# Project layout

PSOBB maintains a strict boundary between the source-controlled engineering project and its mutable runtime.

This document defines the logical filesystem organization, ownership of major runtime areas, and invariants that keep source, generated artifacts, persistent state, evidence, and recovery data separated.

Physical workstation paths, migration procedures, cleanup commands, and operating-system-specific integration belong in [Operations](OPERATIONS.md).

## Layout principles

The project layout follows five rules.

**Source history stays reproducible.**
Project-owned code, configuration, schemas, tests, documentation, and orchestration belong in version control.

**Runtime state stays mutable.**
Generated binaries, credentials, player data, evidence, logs, backups, private inputs, and other runtime state remain outside source history.

**Environments stay isolated.**
Stable, GraphicsCanary, CombatCanary, and LocalLab have explicit ownership boundaries.

**Identity is explicit.**
Runtime directories are not trusted merely because they exist. Important installations, bindings, snapshots, artifacts, and evidence are associated with versioned identity records.

**Recovery state stays separate from active state.**
Backups, snapshots, immutable inputs, and rollback material must not be confused with active runtime state.

## Repository root

The canonical project layout is repository-relative:

```text
PSOBB/
├── .gitignore
├── AGENTS.md
├── README.md
├── PSOBB.slnx
├── global.json
│
├── config/
├── docs/
├── patches/
├── scripts/
├── src/
├── tests/
│
└── PSOBB-Runtime/
```

`PSOBB-Runtime/` is part of the logical project layout but is excluded from source control.

The repository therefore presents one coherent project boundary while preserving a strict distinction between tracked engineering state and mutable runtime state.

## Tracked project surface

### `config/`

Versioned declarative project contracts.

This area contains:

* feature and capability definitions;
* runtime profiles;
* component identities;
* provenance records;
* build contracts;
* release and compatibility metadata;
* evidence indexes;
* versioned schemas; and
* other bounded machine-readable configuration.

Configuration that controls safety-sensitive behavior should be explicit, versioned, bounded, and validated before use.

Machine-local overrides and secrets do not belong here.

### `docs/`

Project documentation and engineering authority.

The documentation tree contains separate documents for:

* architecture;
* project layout;
* operations;
* acceptance contracts;
* modernization roadmaps;
* implementation history;
* recovery;
* graphics validation;
* quality-of-life evaluation; and
* release gates.

Documentation files have distinct authority. In particular, checkpoint history belongs in the implementation ledger rather than being duplicated as mutable historical prose throughout the repository.

### `patches/`

Ordered project-controlled source changes applied to external build inputs where the project does not directly own the entire input tree.

Patches are source history.

Generated patched trees and resulting binaries are runtime/build products and remain outside this directory.

Patch ordering must be deterministic so that a declared build identity can be reproduced from its defined inputs.

### `scripts/`

Stopped-runtime orchestration and verification tooling.

This area owns workflows such as:

* initialization;
* lifecycle control;
* publication;
* rollback;
* backup;
* recovery;
* state validation;
* artifact verification;
* evidence preparation;
* evidence verification;
* environment materialization; and
* maintenance.

Scripts may coordinate runtime state but do not become real-time gameplay controllers.

### `src/`

Project-owned implementation.

Current ownership is divided into focused components:

```text
src/
├── PSOBB.AccountBroker/
├── PSOBB.ClientSafety/
├── PSOBB.Enhancement/
├── PSOBB.Gameplay/
├── PSOBB.LargeAssets/
├── PSOBB.Launcher/
└── PSOBB.Portal/
```

Each component follows the ownership boundaries defined in [Architecture](ARCHITECTURE.md).

Generated build output does not belong in `src/`.

### `tests/`

Automated project validation.

Tests cover the applicable:

* unit behavior;
* contracts and schemas;
* client safety;
* gameplay logic;
* launcher behavior;
* account services;
* lifecycle;
* environment isolation;
* publication;
* rollback;
* recovery;
* state verification;
* graphics policy; and
* runtime acceptance tooling.

Private runtime evidence and mutable test state are not promoted into the test source tree.

## Runtime boundary

`PSOBB-Runtime/` owns material whose lifecycle differs from source history.

Typical runtime state includes:

* generated binaries;
* immutable acquired inputs;
* reproducible build work;
* playable runtime trees;
* mutable account and gameplay state;
* credentials and keys;
* private evidence;
* logs;
* snapshots;
* backups;
* rollback material;
* private evaluation inputs; and
* generated manifests or transaction records.

The runtime is excluded from version control through the repository's root ignore policy.

Ignore rules are a source-tracking boundary. They do not replace access control, backup, integrity verification, or secret-handling policy.

## Logical runtime layout

The canonical logical runtime is organized as follows:

```text
PSOBB-Runtime/
├── archives/
├── sources/
├── builds/
│
├── stable/
├── canary/
├── combat-canary/
├── local-lab/
│
├── backups/
├── secrets/
├── logs/
└── graphics-evidence/
```

Some environments contain their own environment-scoped backup, evidence, log, secret, or build areas where stronger isolation is required.

Top-level shared areas must not be used to bypass an environment's dedicated ownership boundary.

## Immutable input areas

### `archives/`

Stores immutable acquired or imported inputs that must be preserved in their original form.

Examples include:

* source archives;
* binary inputs;
* private evaluation material;
* visual reference inputs; and
* other externally obtained artifacts required for reproducibility or controlled evaluation.

An archived input should be treated as immutable once its identity has been recorded.

Extraction, composition, modification, or activation occurs elsewhere.

### `sources/`

Stores extracted and identity-bound source or build-input trees.

This area is intended for material that participates in reproducible builds but is not itself tracked as project-authored repository source.

A source tree should correspond to an explicit provenance or build contract.

Downloaded archives remain in `archives/`; extracted or prepared build inputs belong in `sources/`.

### `builds/`

Stores generated build working state where a build is not owned by a more specific environment.

Build directories are disposable unless a workflow explicitly retains them as evidence.

Accepted artifact identity is established by the applicable build contract and verification results rather than by retaining arbitrary build directories.

## Stable environment

`stable/` is the accepted recovery environment.

Its logical structure is:

```text
stable/
├── server/
│   └── release/
├── client/
├── runtime/
├── overlays/
├── control/
└── state/
```

The exact physical arrangement may evolve as long as the ownership model remains equivalent.

### `stable/server/`

Contains the selected Stable server runtime and its canonical persistent state.

Persistent Stable account and gameplay state belongs exclusively to this environment.

### `stable/client/`

Contains the immutable or sealed client foundation used to materialize playable Stable runtime state.

It is distinct from the disposable playable tree.

### `stable/runtime/`

Contains the playable Stable client and currently selected accepted profile.

The runtime may be reconstructed from accepted inputs and bindings. Canonical persistent player state is not owned by this directory.

### `stable/overlays/`

Contains validated Stable-compatible overlay inputs where the project architecture requires them.

An overlay existing here does not imply acceptance. Acceptance is determined by the applicable profile and evidence contracts.

### `stable/control/`

Contains Stable-specific lifecycle and runtime authority where environment-bound records are required.

### `stable/state/`

Represents Stable-owned supporting mutable state when that state is not already structurally owned by the server runtime.

Stable is the recovery authority. Experimental state must never be written into Stable merely because Stable data is convenient to access.

## GraphicsCanary environment

`canary/` is the presentation-only development environment.

Its primary responsibility is a separately staged disposable client used for graphics and presentation validation.

```text
canary/
├── client/
├── runtime/
├── control/
└── evidence/
```

GraphicsCanary may rely on Stable services and persistent gameplay state only while the candidate remains inside the presentation-only contract defined in [Architecture](ARCHITECTURE.md).

It does not own an independent gameplay-state authority.

If a candidate begins changing protocol, persistence, gameplay, or save semantics, it belongs in CombatCanary.

## CombatCanary environment

`combat-canary/` is the isolated behavioral development environment.

It owns its runtime, bindings, mutable state, recovery state, secrets, evidence, and lifecycle independently of Stable.

Its logical structure is:

```text
combat-canary/
├── server-base/
│   └── release/
│
├── server/
│   └── release/
│       └── system/
│           ├── licenses/
│           ├── players/
│           └── teams/
│
├── client/
├── runtime/
│   └── client/
│
├── control/
├── backups/
├── logs/
├── secrets/
├── snapshots/
├── builds/
└── evidence/
```

Additional binding and installation records live at the environment root where required.

### `server-base/`

Contains the immutable server artifact from which the selected isolated runtime is constructed.

The base is treated as an identity-bound input rather than mutable gameplay state.

### `server/`

Contains the selected executable server runtime and CombatCanary-owned persistent state.

The mutable state below this tree belongs exclusively to CombatCanary.

Stable and CombatCanary persistent-state paths must never overlap.

### `client/`

Contains the sealed client foundation for the isolated environment.

The client foundation is distinct from the playable runtime tree.

### `runtime/client/`

Contains the playable CombatCanary client materialized from its exact accepted inputs and binding.

Publication of an experimental module or profile occurs against this isolated client rather than Stable.

### `control/`

Contains environment-specific lifecycle authority and process-control records.

A lifecycle record from one environment must not authorize control over another environment.

### `backups/`

Contains CombatCanary-specific recovery material.

Canary recovery state must remain distinguishable from Stable backup state.

### `logs/`

Contains environment-specific diagnostics.

Logs are runtime evidence and are never treated as source history.

### `secrets/`

Contains protected environment-specific secret or signing material required by the canary workflow.

Secrets remain outside version control and outside ordinary evidence summaries.

### `snapshots/`

Contains sealed isolated-state snapshots and their associated identity records.

Snapshots provide a transactional recovery boundary for defined canary mutable state.

Restoration uses the complete bound state set required by the snapshot contract rather than manually substituting individual gameplay files.

### `builds/`

Contains CombatCanary-specific reproducible build working state.

Generated build trees are separate from immutable published artifacts and may be discarded after their identities and required evidence are established.

### `evidence/`

Contains protected source-gate and live-gate evidence belonging specifically to CombatCanary.

Evidence remains private runtime material unless a bounded semantic result is explicitly promoted into tracked documentation.

## CombatCanary identity records

The environment uses explicit records to bind important layers of runtime state.

Representative records include:

```text
combat-canary/
├── installation.json
├── client-binding.json
├── state-binding.json
└── base-client.manifest.json
```

Their roles are distinct.

### Installation identity

Binds the selected runtime components and environment installation state.

### Client binding

Defines the closed playable-client identity, including every component whose presence or absence is relevant to that binding.

### State binding

Associates the isolated environment with its permitted mutable-state or snapshot authority.

### Base-client manifest

Defines the immutable client inventory used as the foundation for later playable-client materialization.

A higher-level binding is valid only while all identities on which it depends remain valid.

## Gameplay observation evidence

Explicit gameplay-observation runs use a dedicated CombatCanary evidence namespace:

```text
combat-canary/
└── evidence/
    └── gameplay-observation/
        └── <run-id>/
            ├── events-v1.partial
            └── run-manifest-v1.json
```

Each run receives its own immutable logical identity.

`events-v1.partial` is a bounded binary evidence file produced by the in-process evidence path.

`run-manifest-v1.json` binds the evidence to the applicable run, process, executable, module, configuration, and related identities.

The stopped-runtime verifier reads private evidence in place and produces only the bounded semantic result needed by the acceptance workflow.

Raw observation evidence is never copied into tracked source merely to make an acceptance result easier to inspect.

## LocalLab environment

`local-lab/` contains evaluation state that is intentionally outside normal Stable and CombatCanary promotion paths.

Its logical areas may include:

```text
local-lab/
├── runtime/
├── asset-overlays/
├── asset-activations/
├── visual-asset-activations/
├── control/
└── evidence/
```

LocalLab may evaluate:

* private inputs;
* restricted assets;
* compatibility references;
* experimental presentation compositions; and
* other non-distributable development material.

Activation state must identify exactly what material owns each destination.

A LocalLab result can guide project development but does not establish distributable acceptance.

Project-owned implementations derived from evaluation must pass their own provenance, identity, behavior, rollback, and release gates.

## Evidence areas

### `graphics-evidence/`

Contains private presentation evidence such as:

* captures;
* measurements;
* comparison material;
* frame or timing evidence;
* replay data; and
* other large or private graphics-validation artifacts.

Tracked graphics configuration may reference bounded identities or semantic results from this evidence, but raw captures remain outside Git.

### Environment-scoped evidence

When evidence is required to prove isolation or bind directly to one environment, it belongs beneath that environment instead of the shared evidence area.

CombatCanary is the primary example.

This keeps evidence ownership consistent with the state and runtime that produced it.

## Backup and recovery areas

### `backups/`

Contains shared or Stable-oriented recovery material where a more specific environment does not own the backup.

Backups are mutable recovery state rather than source history.

### Environment-specific backups

An isolated environment should use its own backup tree when sharing recovery state could make authority ambiguous.

CombatCanary therefore maintains independent backup state.

### Snapshots versus backups

Snapshots and backups serve different purposes.

A **snapshot** binds an exact defined state set for deterministic isolated restoration.

A **backup** provides broader recovery material for supported restore workflows.

Neither is equivalent to runtime-artifact rollback.

## Secrets

`secrets/` and environment-scoped secret directories contain runtime-only authorization material.

Secrets must never be committed to:

* `config/`;
* source files;
* tests;
* documentation;
* tracked manifests;
* evidence summaries; or
* example configuration containing real values.

Tracked configuration may describe the expected type or location of a secret without containing the secret itself.

## Logs

Runtime logs remain outside source history.

Logs may contain diagnostic detail that is useful during development but inappropriate as durable repository state.

When a log contributes to an accepted checkpoint, the tracked record should retain only the bounded semantic result and non-sensitive identity information required to support the acceptance claim.

## Generated artifacts

Generated artifacts are excluded from tracked source unless the project deliberately defines a small generated file as source authority.

Typical excluded artifacts include:

* executables;
* libraries;
* native modules;
* debug symbols;
* package archives;
* generated build directories;
* test results;
* runtime manifests;
* temporary transaction state; and
* generated client or server trees.

The repository should retain the source and contracts required to regenerate an artifact rather than accumulating disposable outputs.

## Version-control boundary

The root `.gitignore` defines the shared repository exclusion policy for runtime and generated material.

At minimum, the current policy excludes categories including:

* `PSOBB-Runtime/`;
* alternate runtime or artifact roots;
* client and server runtime trees;
* account and gameplay state;
* backups;
* logs;
* secrets;
* local configuration;
* private keys and credentials;
* build outputs;
* generated archives; and
* generated binaries.

A new runtime-owned category should be added to the shared ignore policy before it can accidentally enter source history.

Ignore status alone is never proof that sensitive data is protected.

## Runtime-root invariants

The canonical runtime is the repository-relative `PSOBB-Runtime/` tree.

Project tooling may support explicitly authorized isolated test roots where required by automated validation, but those roots must preserve the same source/runtime separation and must not weaken environment isolation.

Runtime tooling must not silently select an arbitrary nearby directory based only on name similarity.

The effective runtime root must be derived from an explicit project contract or an explicitly authorized test context.

## Cross-environment invariants

The following layout rules are mandatory:

1. Stable mutable state and CombatCanary mutable state never overlap.
2. GraphicsCanary does not acquire independent persistent gameplay ownership.
3. LocalLab material cannot silently enter Stable, CombatCanary, or release state.
4. Environment-specific secrets remain scoped to their owning environment.
5. Environment-specific lifecycle records cannot control another environment.
6. Backups and snapshots remain distinguishable from active state.
7. Immutable source and archive inputs are not modified in place.
8. Generated build trees are not treated as source authority.
9. Private evidence remains outside tracked source.
10. Runtime artifacts do not become accepted solely because they exist at an expected path.
11. Environment identity is established through bindings and manifests, not directory names alone.
12. Release composition cannot include evaluation-only material without a separately accepted distribution path.

A layout change that violates one of these rules is an architectural change and requires explicit review.

## Cleanup boundary

Cleanup must distinguish tracked source, disposable generated data, protected runtime state, and retained evidence.

Ordinary repository maintenance must never treat ignored runtime content as disposable merely because version control does not track it.

In particular, broad cleanup operations that delete ignored files can destroy:

* runtime installations;
* persistent state;
* backups;
* secrets;
* private evidence;
* immutable inputs; and
* recovery material.

Cleanup workflows therefore operate on explicitly recognized project-owned targets rather than broad filesystem patterns.

Detailed cleanup and migration procedures belong in [Operations](OPERATIONS.md).

## Relocation boundary

The logical project layout is repository-relative and must not depend on a historical absolute workstation path.

When the project is relocated:

* tracked source remains path-independent where practical;
* runtime bindings are regenerated or revalidated where path identity matters;
* stale path-bearing generated state is not treated as current authority;
* retained historical evidence must remain independently identifiable; and
* obsolete copies must not become alternate supported runtimes.

Relocation is an operational procedure, not a change to the logical architecture.

## Current layout state

The current layout has advanced beyond the original source-only canary arrangement.

| Area                         | Current state                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Repository/runtime split** | Established and enforced through the root ignore policy                                                                               |
| **Stable**                   | Materialized accepted recovery environment                                                                                            |
| **GraphicsCanary**           | Established presentation-development environment                                                                                      |
| **CombatCanary**             | Materialized with isolated server, client, persistent state, bindings, backups, logs, secrets, snapshots, control state, and evidence |
| **CombatCanary restoration** | Sealed-state reset and semantic verification have passed their defined acceptance gates                                               |
| **Gameplay observation**     | Dedicated bounded evidence layout and stopped-runtime verification path are implemented at source level                               |
| **LocalLab**                 | Established private evaluation boundary                                                                                               |
| **Release layout**           | Remains a future derived composition rather than a mutable development environment                                                    |

For exact checkpoint history, refer to [Combat implementation ledger](COMBAT-IMPLEMENTATION-LEDGER.md).

## Documentation boundaries

Layout, architecture, and operations intentionally describe different concerns.

| Document                                                        | Responsibility                                                                                              |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [Architecture](ARCHITECTURE.md)                                 | Environment relationships, component ownership, trust boundaries, state model, and architectural invariants |
| `PROJECT-LAYOUT.md`                                             | Logical tracked/runtime filesystem organization and directory ownership                                     |
| [Operations](OPERATIONS.md)                                     | Commands, machine-specific procedures, migration, cleanup, lifecycle, backup, restore, and maintenance      |
| [Combat implementation ledger](COMBAT-IMPLEMENTATION-LEDGER.md) | Authoritative historical acceptance state                                                                   |
| [Combat acceptance](COMBAT-ACCEPTANCE.md)                       | Behavioral evidence requirements                                                                            |
| [Graphics acceptance](GRAPHICS-ACCEPTANCE.md)                   | Presentation evidence and promotion requirements                                                            |

If a machine-specific procedure appears necessary to explain a directory's architectural purpose, document the purpose here and place the procedure in Operations.

If historical state differs from this document's current-state summary, the latest applicable accepted implementation-ledger entry governs.
