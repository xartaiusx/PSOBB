# PSOBB Modernization Project

PSOBBMP is a modernization, compatibility, and validation project for the supported PSOBB runtime.

The project develops a controlled modern runtime around a verified native baseline, with project-owned client modules, services, tooling, configuration, lifecycle management, recovery, testing, and acceptance infrastructure.

Development follows an evidence-driven model: every behavioral change is isolated, validated, measured, and required to preserve defined state and rollback guarantees before it can advance.

> **Status:** active development. Stable Native remains the accepted recovery baseline while graphics, gameplay, quality-of-life, and supporting systems progress through independent acceptance gates.

## Project goals

PSOBB is designed around four principles:

**Preserve compatibility.**
Existing game behavior, actions, state formats, and core mechanics remain the foundation unless a change is explicitly developed and accepted.

**Modernize incrementally.**
Graphics, interface, gameplay, input, services, and quality-of-life improvements advance as small independently verifiable features.

**Fail safely.**
Client-sensitive changes require exact identity, expected state, bounded ownership, deterministic rollback, and an inert failure path.

**Prove behavior.**
Build success alone does not constitute acceptance. Runtime behavior, persistence, lifecycle integrity, recovery, and applicable performance characteristics must also pass their defined gates.

## Current state

The implementation ledger is the authoritative record of accepted, rejected, pending, and rolled-back development checkpoints.

| Area                     | State                                                                                                                                              |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stable Native**        | Accepted recovery baseline with verified gameplay, save, restart, relog, bank, and character-state behavior                                        |
| **CombatCanary**         | Materialized isolated development environment with Native gameplay, restart/relog, state verification, and sealed-state restoration accepted       |
| **Baseline closure**     | Final post-canary Stable gameplay acceptance remains pending                                                                                       |
| **Gameplay observation** | Bounded observation core, exact-client passive instrumentation, protected evidence capture, and stopped-runtime verification are source-ready      |
| **Gameplay publication** | Transactional publication and exact rollback have passed source and fixture validation; live publication and observation acceptance remain pending |
| **Modern gameplay**      | Observation infrastructure is established; action-state mapping and behavioral candidates remain gated                                             |
| **Graphics**             | Multiple presentation and enhancement candidates have reached runtime validation; final acceptance remains pending                                 |
| **Quality of life**      | Baseline capabilities are retained while additional candidates advance independently through acceptance                                            |
| **Release readiness**    | Development acceptance is active; distributable release and deployment remain separately gated                                                     |

## Architecture

PSOBB separates stable recovery, experimental development, presentation, gameplay, services, and runtime orchestration into explicit ownership boundaries.

### Stable Native

The known-good recovery environment.

Stable defines the compatibility baseline for client behavior, persistent state, lifecycle behavior, and rollback verification. Experimental work must preserve a valid path back to this state.

### CombatCanary

The isolated environment for gameplay-sensitive, protocol-sensitive, and persistent-state-sensitive development.

Canary candidates operate against separately controlled state and must pass the applicable lifecycle, integrity, evidence, recovery, and gameplay gates before promotion.

### Project components

`PSOBB.ClientSafety`
Owns exact-client validation and shared safety primitives for controlled native modification.

`PSOBB.Gameplay`
Owns gameplay observation and the developing modern gameplay layer, including action state, hotbar behavior, focused input, buffering, and native-action integration.

`PSOBB.Enhancement`
Owns presentation-side enhancement and display integration.

`PSOBB.LargeAssets`
Owns project-defined support for validated large-asset handling where required by accepted presentation work.

`PSOBB.Launcher`
Owns environment selection, runtime controls, validation entry points, and supported user-facing launch behavior.

`PSOBB.AccountBroker`
Provides the constrained account-management boundary for service integration.

`PSOBB.Portal`
Provides the application layer for future account and service-facing functionality without direct ownership of protected runtime state.

These ownership boundaries are intentional. Runtime-sensitive responsibilities remain narrow so that validation, rollback, and failure behavior can be reasoned about independently.

## Repository structure

| Path          | Purpose                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------- |
| `src/`        | Project-owned application, client, gameplay, enhancement, and service source                   |
| `tests/`      | Unit, integration, lifecycle, recovery, safety, and acceptance validation                      |
| `scripts/`    | Bounded runtime orchestration, publication, recovery, evidence, and verification workflows     |
| `config/`     | Versioned project configuration, capabilities, manifests, provenance records, and schemas      |
| `patches/`    | Ordered source-level changes required by project-controlled runtime behavior                   |
| `docs/`       | Architecture, development contracts, acceptance protocols, roadmap, and implementation records |
| `PSOBB.slnx`  | Managed project solution                                                                       |
| `global.json` | Repository toolchain contract                                                                  |

Mutable runtime state, credentials, player data, private evidence, restricted assets, backups, and generated runtime artifacts remain outside version control.

The repository contains the complete project-owned source and engineering contracts required to develop, validate, and reproduce PSOBB changes.

## Development model

A candidate normally progresses through:

```text
design
  ↓
source implementation
  ↓
deterministic build
  ↓
static and unit verification
  ↓
isolated publication
  ↓
runtime acceptance
  ↓
state and lifecycle verification
  ↓
rollback proof
  ↓
promotion
```

A later stage cannot compensate for failure at an earlier one.

Runtime-sensitive client changes additionally require:

* exact supported executable identity;
* expected original state;
* exclusive mutation ownership;
* bounded memory and execution behavior;
* deterministic removal or rollback;
* fail-closed behavior on identity or state mismatch; and
* evidence sufficient to distinguish observed behavior from assumption.

Real-time gameplay paths are designed to remain bounded and predictable. Persistent state changes require explicit validation before promotion.

## Acceptance model

PSOBB distinguishes implementation from acceptance.

A feature may be:

**Planned**
The behavior and boundaries are defined.

**Source-ready**
The implementation has passed its source-level requirements.

**Runtime-validated**
The candidate has executed successfully under its defined isolated conditions.

**Accepted**
All required behavior, state, lifecycle, recovery, evidence, and regression gates have passed.

**Rejected**
The candidate failed a required gate and cannot advance in its tested form.

Accepted status applies only to the exact capability and evidence defined by that checkpoint.

## Roadmap

### Phase 0 — Trusted foundation

Complete the Stable and CombatCanary acceptance foundation, recovery guarantees, state isolation, and final baseline closure.

### Phase 1 — Quality of life

Evaluate existing quality-of-life capabilities individually and promote only those that preserve the accepted baseline.

### Phase 2 — Modern hotbar

Develop the project-owned multi-page hotbar and its native-backed action, persistence, capability, and display contracts.

### Phase 3 — Modern controls

Introduce modernized combat interaction while continuing to use validated native actions and game state.

Candidates include held physical actions, controlled buffering, quick-use behavior, recovery tuning, movement continuity, target handling, and camera refinement.

### Later phases

Expand validated presentation, diagnostics, item visibility, controller support, state inspection, and other independently gated improvements.

Large changes remain decomposed into individually measurable and reversible capabilities.

## Engineering principles

The repository favors small complete vertical slices over speculative frameworks.

Project contracts are explicit, versioned, bounded, and fail closed where ambiguity could affect runtime integrity.

Native client work uses narrow ownership boundaries and fixed interfaces. Runtime-critical paths avoid unbounded allocation, blocking operations, filesystem access, inter-process communication, and uncontrolled diagnostics.

Persistent mutations use transactional workflows where applicable. Recovery procedures are treated as first-class project behavior.

Optimization follows measurement. A more complex implementation must demonstrate a meaningful benefit before replacing a simpler accepted design.

## Reproducibility and provenance

Inputs that affect reproducibility are bound through source-controlled provenance records.

These contracts can include:

* exact source identity;
* immutable content hashes;
* component and artifact inventories;
* compatibility boundaries;
* build identity;
* validation state;
* distribution classification; and
* rollback target.

Generated binaries, runtime state, credentials, private evidence, and restricted material are excluded from source control.

This keeps the repository reproducible without conflating source history with mutable runtime state.

## Documentation

| Document                                                             | Purpose                                                  |
| -------------------------------------------------------------------- | -------------------------------------------------------- |
| [Architecture](docs/ARCHITECTURE.md)                                 | Structural environments, ownership, and trust boundaries |
| [Operations](docs/OPERATIONS.md)                                     | Supported runtime and maintenance workflows              |
| [Combat modernization](docs/COMBAT-MODERNIZATION.md)                 | Gameplay direction and ordered development phases        |
| [Combat acceptance](docs/COMBAT-ACCEPTANCE.md)                       | Runtime acceptance requirements                          |
| [Combat implementation ledger](docs/COMBAT-IMPLEMENTATION-LEDGER.md) | Authoritative checkpoint history                         |
| [CombatCanary build](docs/COMBAT-CANARY-BUILD.md)                    | Reproducible isolated-build contract                     |
| [Graphics acceptance](docs/GRAPHICS-ACCEPTANCE.md)                   | Presentation and visual acceptance model                 |
| [QoL matrix](docs/QOL-MATRIX.md)                                     | Quality-of-life candidate tracking                       |
| [Production gates](docs/PRODUCTION-GATES.md)                         | Requirements preceding deployment or distribution        |

Where status differs between descriptive documentation and the implementation ledger, the latest accepted ledger checkpoint governs.

## Repository boundary

This repository tracks project-owned source, configuration, schemas, tests, documentation, orchestration, patches, and reproducibility contracts.

It intentionally excludes mutable runtime state, credentials, private user data, backups, captures, restricted assets, and other material that does not belong in source control.

Availability of source in this repository does not by itself grant redistribution rights. Project licensing and distribution terms should be treated according to the repository's explicit licensing files and release policy.
