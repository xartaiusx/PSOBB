# PSOBB repository instructions

These instructions apply to the entire repository.

## Canonical boundaries

- Treat `C:\Github Repo's\PSOBB` as the only Git/source workspace.
- Treat `C:\Github Repo's\PSOBB\PSOBB-Runtime` as the only proprietary and
  mutable runtime. It must remain covered by the anchored
  `/PSOBB-Runtime/` ignore rule.
- Do not recreate a Documents checkout or a sibling `PSOBB-Runtime`.
- Never run `git clean -x`, `git clean -X`, or another ignored-file cleanup
  against this worktree.
- Never track client/server binaries, saves, accounts, credentials, captures,
  logs, private assets, runtime manifests, or other proprietary state.

## Live-test identity and safety

- Slot 0 Twills, a FOnewearl, is the only character permitted in live
  development tests. Do not create, modify, clone, or log in another
  character to bypass a test limitation.
- Stable Native with the `baseline` patch profile is the operator recovery
  target. Keep Stable and CombatCanary isolated and never run them
  concurrently.
- Seal and verify character, bank, inventory, equipment, techniques, MAG,
  sidecar, and installation state before and after every live candidate.
- Use an isolated restored Twills snapshot for destructive or stateful canary
  tests. Follow it with a non-destructive five-minute canonical-Twills smoke.
- Stop the client and server before profile, save, sidecar, build-publication,
  backup, restore, or runtime-layout changes.
- Preserve the three Desktop shortcuts, the native saved-login/graphics
  registry state, and shared RenderDoc state.

## Modernization constraints

- Implement one feature at a time on top of the last accepted profile.
- This track is animation-free: do not add or replace animations, models,
  effects, sounds, weapons, enemies, or proprietary assets.
- Do not add an external controller, memory reader, macro, AutoHotkey process,
  `SendInput`, global keyboard hook, chat-command injection, or synthetic
  combat packet.
- Lifecycle control may preserve another application's foreground focus.
  Gameplay input remains focused-window-only.
- `PSOBB.Gameplay` will own combat observation, focused input, hotbar state,
  buffering, and combat hooks. `PSOBB.Enhancement` remains the only Direct3D
  presentation owner. Shared hooks must use `PSOBB.ClientSafety`.
- Every client hook must require the exact approved executable identity,
  expected original bytes, exclusive address ownership, narrow page
  protection, deterministic rollback, and an inert failure state.
- Modern games will require an exact client/server capability handshake.
  Battle and Challenge retain native/shared behavior until separately tested.

## Workflow and verification

- Begin from a clean tree with no merge/rebase, stopped PSOBB processes, no
  reserved listener, and no temporary build mapping.
- Keep Stable v2026-02-27 untouched. Build the pinned current-upstream canary
  only through `scripts/Build-PSOBBCombatCanaryServer.ps1` and export every
  server change as an ordered patch under `patches/newserv`.
- Use the explicit `Set-PSOBBRuntimeAcl.ps1` legacy migration switches only for
  the exact previewed runtime-marker or Stable installation-record DACL
  recognized by their policy. Do not use them to normalize an unknown target
  identity, owner, group, ACL, binding, or byte state.
- Preserve a restore-drill quarantine record and its protected `.work` tree
  whenever process exit or output-reader completion is unconfirmed. Do not
  remove that evidence until its recorded process identity is absent and all
  reserved listeners are clear.
- Run the narrow unit/static suite, source build checks, rollback checks, and
  the applicable runtime suite before any live test.
- A live feature checkpoint requires one five-minute active scenario, bounded
  evidence, graceful save/quit/relog/restart, semantic state verification,
  isolated-state restoration, and a separate non-destructive five-minute
  canonical smoke.
- Reject crashes, undocumented save drift, item loss/duplication, packet
  amplification, hook conflicts, new missed presents, or a p95 frame-time
  regression greater than the larger of 2 percent or 0.5 ms.
- Record every result in `docs/COMBAT-IMPLEMENTATION-LEDGER.md`. The ledger is
  append-only; correct an error with a new entry rather than rewriting history.
- Keep each accepted feature in one focused local commit. Do not push,
  publish, create a pull request, add a remote, or rewrite history without
  explicit authorization.

## Source quality

- Preserve existing C++20/x86, C#/.NET, PowerShell, schema, naming, and test
  conventions. Prefer small reviewable changes and exact typed contracts.
- Prefer the C++ standard library, .NET base class library, Windows APIs already
  wrapped by the project, and existing newserv primitives before adding code or
  dependencies. A new production dependency requires a missing proven need,
  exact version/license/provenance, and a clear reduction in owned code or risk.
- Implement the smallest complete vertical slice. Do not add a framework,
  generic abstraction, configuration field, protocol field, or extension point
  for a hypothetical future consumer. Extract shared machinery only after a
  concrete feature needs it or duplicated behavior has two proven consumers.
- In C++, prefer value types, fixed-width integers at binary boundaries, strong
  enums, `constexpr` tables, bounded views, RAII, and explicit ownership. Keep
  Windows/client-specific behavior behind narrow interfaces and keep the C ABI
  fixed-size, versioned, and non-throwing.
- Keep native compiler policy target-scoped and express repeatable configure,
  build, and test workflows through tracked CMake presets. Keep machine-local
  paths and overrides out of tracked presets.
- In C#, keep nullable analysis and warnings-as-errors enabled, use typed models,
  use asynchronous APIs for I/O with cancellation, and avoid reflection,
  `dynamic`, service-location, and sync-over-async unless a measured requirement
  justifies them.
- Keep JSON contracts versioned, bounded, and closed to unknown properties where
  compatibility permits. Validate before use and fail closed on duplicate,
  ambiguous, oversized, or unsupported input.
- Measure before optimizing. Preserve the simplest correct implementation until
  profiling identifies a relevant cost, then record the baseline, candidate,
  and regression threshold with the feature evidence.
- Do not pause the combat roadmap for broad style, framework, test-library, or
  legacy-module migrations. Repair existing code when it blocks a verified
  slice or when that component is already the focused change.
- Real-time action paths must not allocate, block, perform file or IPC I/O, or
  emit unbounded logs. Diagnostics use a fixed ring buffer and default off.
- PowerShell is stopped-runtime orchestration only, never a real-time gameplay
  controller. State-changing commands use advanced-function contracts,
  `ShouldProcess` where applicable, literal canonical paths, bounded input, and
  deterministic cleanup.
- Repository text and commit messages must not contain secrets, private
  identifiers, runtime paths outside the canonical boundary, proprietary
  bytes, or assistant/code-generation vendor attribution.
