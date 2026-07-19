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
- Real-time action paths must not allocate, block, perform file or IPC I/O, or
  emit unbounded logs. Diagnostics use a fixed ring buffer and default off.
- PowerShell is stopped-runtime orchestration only, never a real-time gameplay
  controller.
- Repository text and commit messages must not contain secrets, private
  identifiers, runtime paths outside the canonical boundary, proprietary
  bytes, or tool/vendor attribution.
