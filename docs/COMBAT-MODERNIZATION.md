# Combat modernization roadmap

## Purpose and current status

The project is modernizing normal PSO Blue Burst play through exact-client,
capability-gated changes that reuse native 59NL actions and animations. Stable
Native remains the recovery target. CombatCanary is the isolated development
environment; it is not accepted until the build, sealed-state, lifecycle,
rollback, and five-minute Twills gates in
[COMBAT-ACCEPTANCE.md](COMBAT-ACCEPTANCE.md) pass.

Current accepted facts:

- The tracked workspace and ignored runtime use the canonical boundaries in
  the root `AGENTS.md`.
- Stable Native completed the slot-0 Twills FOnewearl Forest, manual-combat,
  bank, save, restart, relog, and shutdown acceptance on 2026-07-19.
- Stable uses the empty `baseline` patch profile for recovery.
- Normal games already use private drops; Battle and Challenge remain shared.
- The inclusive source implementation range `6f5e78b` through `96bcddc`
  passed the 2026-07-20 source-only gate for the deterministic server build,
  sealed-state transaction, environment-aware lifecycle/launcher, ACL, and
  recovery boundaries.
- The current Stable restore drill passed, and the Stable-derived CombatCanary
  was materialized with the complete Stable retail-content base and isolated
  client, server, account, player, team, backup, log, and control state.
- The five-minute isolated Native scenario passed on 2026-07-20. Restart,
  slot-0 Twills relog, graceful save/disconnect, and exact sealed-state reset
  passed on 2026-07-21.
- The required post-canary five-minute canonical Stable smoke remains pending.
  The 2026-07-21 Stable attempt ran for five minutes but had no client session,
  so elapsed process time was not accepted as gameplay evidence.
- `PSOBB.Gameplay` 0.4.0 now has a source-ready, fixed-capacity observation
  core, exact-59NL passive `send_60` adapter, and permitted in-process bounded
  evidence consumer. An explicit evidence launch waits for the exact file and
  process identities, then writes a protected no-clobber run manifest. The
  stopped-runtime parser validates the fixed file, committed prefix, lifecycle,
  identities, and counters and returns only a bounded summary. Runtime
  publication, live Twills acceptance, action-state mapping, and all combat
  behavior remain pending.
- CombatCanary client binding schema 2 is source-ready and closes over exactly
  the approved x86 loader, Gameplay observation module, and canonical
  observation configuration. Its stopped-runtime publisher and exact rollback
  passed the bounded source/fixture gate on 2026-07-26. Schema 1 remains the
  exact Native recovery contract; no overlay has been published yet.
- The complete canonical installed-state verifier passed read-only in 207.08
  seconds on 2026-07-26. The canary remained at its exact schema-1 binding, so
  module load, live observation evidence, and combat behavior remain pending.

## Locked product boundaries

- Only slot-0 Twills FOnewearl is used for live development testing.
- Normal gameplay is eventually Modern-only. Native behavior remains an
  operator recovery profile.
- Hotbar v1 has eight launcher-edited pages of ten slots: General DPS,
  Support/Heal, Fire, Ice, Lightning, Light, Dark, and Items/Utility.
- TP, native Normal/Heavy/Special attacks, Photon Blasts, weapon animations,
  and the existing 12 classes remain.
- No new animation, model, effect, sound, weapon, enemy, or proprietary asset
  is part of this track.
- Gameplay input is focused-window-only. No external controller, macro,
  synthetic input, chat injection, or synthetic combat packet is permitted.

## Ownership and contracts

Planned native source ownership is deliberately narrow:

```text
src/
  PSOBB.ClientSafety/   exact-image and hook-safety primitives
  PSOBB.Gameplay/       combat, hotbar, input, and action-state ASI
  PSOBB.Enhancement/    presentation and read-only hotbar display

tests/
  PSOBB.ClientSafety/
  PSOBB.Gameplay/
  PSOBB.Enhancement/

patches/newserv/        ordered patches for one pinned upstream commit
```

The public contracts are:

- `GameplayCapabilitiesV1`: fixed C ABI for exact client identity, accepted
  feature bits, active page, ten display records, runtime state, and the last
  fail-closed reason. No owning pointer or exception crosses the ABI.
- `ModernCapabilitiesV1`: server/client protocol revision, exact build and
  module identities, supported feature bits, selected profile, and
  acknowledgement. Mismatched Modern clients are rejected before gameplay.
- `HotbarProfileV1`: exactly eight named pages and ten logical slots, stored in
  a checksummed generation-numbered server sidecar keyed by server-derived
  account ID and character slot. It never extends `.psochar` or stores raw
  client-memory records.
- `GameplayProfileV1`: independent observation, hotbar, held-attack, buffer,
  quick-use, recovery, movement, and diagnostics flags. A candidate adds
  exactly one behavior to the accepted profile.

## Ordered delivery

### Phase 0: trustworthy canary

1. Keep the clean Stable Native acceptance and external-state preservation
   evidence current.
2. Source-verified: reproducible, offline-input deterministic, two-clean-build
   CombatCanary server workflow from the pinned source and ordered patch series.
3. Source-verified: signed exact-inventory Twills snapshot creation,
   transactional initialization/reset, compensation, and read-back verification.
4. Source-verified: environment-aware lifecycle and launcher controls that
   preserve the three Stable Desktop shortcuts and foreground-preserving Play.
5. Completed: current Stable restore drill and Stable-derived CombatCanary
   materialization from a stopped, clean-tree gate.
6. Completed for CombatCanary: isolated five-minute Twills scenario,
   restart/relog, semantic save check, and exact sealed-state restoration.
7. Pending: separate non-destructive five-minute canonical Stable smoke with an
   actual slot-0 Twills Forest session, then final Phase 0 closure.

### Phase 1: existing QoL, one candidate at a time

Accept `NoRareSelling`, `HungryMagSound`, `FastTekker`, and
`AccurateKillCount` individually. `Palette` is compatibility/reference-only;
it must be absent from the Modern profile because Gameplay will exclusively
own the number hotbar. Return to baseline between candidates.

Verify existing private/shared/duplicate drops, common bank, explicit save,
rare notifications, material and kill information, solo switch assistance,
and the existing diagnostic/backup commands without reimplementing them.
`EnemyDamageSync` is client-reported damage-desynchronization mitigation, not
fully server-authoritative damage.

### Phase 2: eight-page hotbar

Deliver read-only discovery, launcher editing, stopped-runtime transactional
sidecar persistence, observation-only native lookup, volatile page switching,
native-setter compilation, required-client handshake, then native-font page
display. Add Pickup, Map, and Diagnostics only as later allowlisted actions.

The sole writable native palette boundary is the main-bank number-record range
for records 4 through 13 at `player + 0x538`. Preserve all state words, face
records, the back bank, and the `player + 0x5AC` Photon Blast/temporary group.
Block switching in chat, menus, Customize, Photon Blast state, death, warp,
action-disabled state, and while an item or technique dispatches.

### Phase 3: PSO2-like control with native actions

1. Observation-only action probe. The allocation-free ring, exact-59NL passive
   adapter, permitted in-process bounded consumer, protected run manifest,
   stopped-runtime parser, and publication transaction are source-ready.
   Isolated runtime publication, live Twills acceptance, and exact action-state
   mapping remain pending.
2. Held Normal three-hit native combo.
3. Held Heavy combo.
4. Manual mixed-combo override.
5. Separately disabled Held Special candidate with exact resource checks.
6. One physical action buffer, expiring at a native transition or 250 ms.
7. One deliberate-press technique buffer with full revalidation.
8. Deliberate-press native item quick-use with one-consumption maximum.
9. Separately gated recovery scales: physical 0.85, technique 0.90, existing
   knockdown get-up 0.85.
10. Movement resume, target stickiness, and camera recenter polish without a
    world-speed increase.

Native state, never a timer, authorizes execution. Cancel queued behavior on
release where applicable, focus loss, menus/chat, death, warp, knockdown,
freeze, paralysis, unequip, invalid target, quest transition, or capability
mismatch. Packet sequences may not exceed equivalent legal manual play.

### Phase 4 and later

Next animation-free candidates are owner-safe rare markers, an in-process
private-drop-aware item reader, enemy HP bars, party/quest diagnostics,
optional server-fed rare information, verified snapshot UI, game filters,
safe loading/audio/map/camera options, project-owned XInput, and read-only
Twills loadout previews.

Multiplayer fixtures may be developed now, but live two-player drop, EXP,
damage-sync, and concurrency claims require a separately authorized observer
identity. Do not clone Twills or reuse one account twice. Passive FOnewearl
specialization is deferred until combat/save/multiplayer parity is stable and
a separate balance specification is approved.

## Lean engineering gate

- Build one complete feature slice on the last accepted profile and remove
  candidate-only code when the slice is rejected. Do not build a general combat
  framework ahead of verified behavior.
- Use standard-library, .NET base-library, existing Windows wrapper, and pinned
  newserv capabilities before introducing a dependency. A production dependency
  must replace more owned complexity or risk than it adds and retain exact
  version, license, provenance, and rollback evidence.
- Keep native runtime state compact and strongly typed. The action hot path uses
  fixed-capacity storage and performs no allocation, blocking, file/IPC access,
  or unbounded logging. Platform and exact-client violations stay isolated
  behind `PSOBB.ClientSafety` interfaces.
- Put pure action state, cancellation, expiry, and bounded evidence logic in a
  platform-independent, table-tested Gameplay core. Keep the ASI as a thin
  exact-client adapter and keep repeatable x86 configure/build/test settings in
  tracked CMake presets with target-scoped compiler policy.
- Keep launcher and orchestration code direct: typed nullable C# models and
  cancellable asynchronous I/O in the launcher; bounded stopped-runtime
  PowerShell transactions for lifecycle work; closed, versioned JSON contracts
  for durable data.
- Do not optimize from intuition. First prove correctness, then use action-state,
  packet, build/test, and frame-time evidence to identify a material cost. Retain
  the simpler implementation when a candidate has no measured benefit.
- Apply modernization to the files required by the active slice. Broad style,
  dependency, test-framework, or accepted legacy-module migrations do not block
  the next combat test and remain separate focused changes.

## Explicit deferrals

Dodge/step attacks, counters, sprint, dash/aerial actions, charged-technique
poses, Photon Arts, weapon actions, unique motions/projectiles, new classes,
new weapons/enemies/raids, blanket no-knockdown, enemy stagger redesign, PP,
rate/loot content changes, expanded save formats, and fully
server-authoritative damage are outside this animation-free track.

## Reference basis

Design choices use official SEGA manuals for palettes, subpalettes, movement,
class trees, and My Sets; pinned newserv source/release behavior; and recurring
documented QoL behavior from long-running PSO private servers. Community
behavior is adopted as a clean-room requirement, never by copying binaries,
private code, quests, tables, branding, music, art, or animation assets.

- [SEGA NGS palettes](https://pso2.jp/players/manual/battle/palette/)
- [SEGA NGS equipment and subpalette assignments](https://pso2.jp/players/manual/preparations/equipment/)
- [SEGA NGS movement and combat actions](https://pso2.jp/players/manual/battle/actionbasic/)
- [SEGA PSO2 skill trees](https://pso2.jp/players/manual/pso2/preparations/class/tree/)
- [SEGA PSO2 My Sets](https://pso2.jp/players/manual/pso2/preparations/class/level/)
- [newserv v2026-02-27](https://github.com/fuzziqersoftware/newserv/releases/tag/v2026-02-27)
- [Ephinea features](https://ephinea.pioneer2.net/about-ephinea/)
- [Ultima commands and palettes](https://www.phantasystaronline.net/forum/index.php?/tool-box/commands/)
- [Ragol features](https://ragol.org/features)
- [Destiny item-reader design](https://playpso.net/forums/topic/800-about-item-readers-destiny-reader-beta/)
- [Schthack server features](https://gc.schtserv.wiki/index.php/Server_Features)
- [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [MSVC SDL checks](https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks)
- [MSVC Control Flow Guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- [CMake presets](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html)
- [.NET C# coding conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions)
- [PowerShell Script Analyzer](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
