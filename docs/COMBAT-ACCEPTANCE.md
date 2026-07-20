# Combat acceptance protocol

## Promotion rule

A feature is accepted only when one candidate flag is enabled on the previous
accepted profile and every checkpoint below passes. A source build, unit test,
or short launch is evidence for its own gate only; none substitutes for the
five-minute live scenario, save/relog verification, rollback, or canonical
Twills smoke.

## Fixed identities and boundaries

- Git root: `C:\Github Repo's\PSOBB`
- Ignored runtime: `C:\Github Repo's\PSOBB\PSOBB-Runtime`
- Stable server: newserv v2026-02-27 at
  `a649a4a146d04dba320bb579ac291527db0febb5`
- Pinned canary source: newserv at
  `d754a34e271a4fb387be63db34ef0c303e49dcf2`
- Exact 59NL client SHA-256:
  `dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535`
- Live identity: slot 0 Twills, FOnewearl, and no other character
- Stable recovery patch profile: `baseline`

Never record an account filename, account-derived stem, login, password,
private key, save, capture, runtime log, or proprietary byte in Git evidence.

## Mandatory checkpoint

1. Confirm a clean tree, exact branch/commit, no merge/rebase, no remote
   operation, stopped server/client, expected hashes, no reserved listener,
   and no temporary build mapping.
2. Verify exact slot-0 Twills FOnewearl identity. Create and validate a signed,
   sealed character/bank/hotbar snapshot.
3. Enable exactly one candidate on top of the accepted profile.
4. Run applicable schema validation, static analysis, unit/ABI tests, patch
   application checks, two-clean-build verification, runtime policy tests,
   and rollback tests.
5. Start isolated CombatCanary without stealing foreground focus.
6. Run one five-minute active, feature-specific Twills scenario. Measure from
   scenario start to finish; do not replace activity with an idle sleep.
7. Capture bounded action-state/packet evidence. Capture paired five-minute
   PresentMon traces when frame behavior is relevant. Use RenderDoc only for
   rendering/HUD work and never during credential entry.
8. Save, quit, relog, stop gracefully, and verify character, bank, inventory,
   equipment, techniques, MAG, sidecars, installation state, and rollback
   evidence. Restore and reverify the isolated snapshot.
9. Run a separate non-destructive five-minute canonical-Twills smoke with no
   consumption, pickup, equipment change, or bank write.
10. Append the exact result, hashes, evidence location, limitation, and
    rollback command to `COMBAT-IMPLEMENTATION-LEDGER.md`; create one focused
    local commit and require a clean tree before the next candidate.

## Required scenario coverage

Across the applicable feature checkpoints, cover lobby, Forest, boss arena,
telepipe/floor transition, death, knockdown, freeze/paralysis, empty TP/item,
menu/chat/Customize, Photon Blast at 100, focus loss/Alt-Tab, keyboard, later
gamepad, save/relog, server restart, and exact rollback.

Held and buffered actions must cancel on every inapplicable state. Page
switching is additionally blocked during native temporary/PB palette state and
while an item or technique dispatches. Missing techniques/items remain visible
but disabled.

## Automatic rejection

Reject promotion for any:

- crash or unhandled exception;
- save/state drift outside the documented allowlist;
- item loss, duplication, or double consumption;
- packet sequence beyond equivalent legal manual play;
- hook address or presentation ownership conflict;
- new missed-present behavior; or
- p95 frame-time regression greater than the larger of 2 percent or 0.5 ms.

Do not weaken a gate to accept a candidate. Record the failure, roll back, and
keep the last accepted profile.

## 2026-07-20 source-only gate

The implementation range from `6f5e78b` through `96bcddc`, inclusive, passed
the source-only Phase 0 gate. The protected receipt is
`combat-canary/evidence/source-gate-20260720T064219Z/source-gate.json`
(SHA-256
`78b6b71930584677ef99e0418c52771e33bc53790c5f4a840f95e4d80b0cddf5`).
Its recovery-matrix manifest is
`combat-canary/evidence/source-gate-20260720T064219Z/recovery-matrix/manifest.json`
(SHA-256
`1a74b37efd900782b35b82641b76d1296f3174fd00c5c876b322914c56a7d20c`).

This gate verifies source behavior only. It did not run the canonical
runtime-marker migration or a real restore drill, materialize CombatCanary, or
run either five-minute Twills smoke. A verified immutable canary server artifact
exists in `server-base\release`; no server is selected into `server\release`
and no client, binding, snapshot, or mutable canary state is installed.

## Phase 0 acceptance matrix

| Gate | Current status | Required evidence |
|---|---|---|
| Stable Native Forest/manual combat | Accepted 2026-07-19 | Five-minute Twills scenario and graceful quit |
| Stable bank/save/restart/relog | Accepted 2026-07-19 | Semantic slot-0 character and bank verification |
| Canonical path and remnant audit | Accepted; recheck before materialization | Retired paths absent; nested runtime only |
| Three Desktop shortcuts | Accepted; recheck before materialization | Exact roles, canonical launcher, no credentials |
| Saved login/graphics and shared RenderDoc | Preserved; recheck before materialization | Metadata/digest-only readback |
| CombatCanary layout and ACL isolation | Source verified; canonical migration/recheck pending | Isolation, ACL, and recovery suites |
| Reproducible canary server | Source verified 2026-07-20; not live accepted | Offline-input deterministic two-clean-build equality, source-lock proof, and Verify; native sockets are not OS-denied |
| Sealed Twills snapshot/transaction | Source verified 2026-07-20; no canonical snapshot created | Strict JSON, exact inventories, independent state suite, and rollback fault matrix |
| CombatCanary lifecycle/launcher | Source verified 2026-07-20; not live accepted | Environment-specific start/observe/stop and launcher tests |
| Canonical runtime-marker ACL migration | Not run | Exact known-legacy preview, apply, and recursive ACL readback |
| Current real Stable restore drill | Not run | Protected schema-v3 drill receipt and clean termination |
| CombatCanary materialization | Not started | Clean-tree, stopped-state, signed install readback |
| Five-minute canary and canonical smokes | Not started | Ledger entry plus restored snapshot proof |

## Rollback boundaries

- Client patch rollback: apply the `baseline` profile only while both server
  environments and clients are stopped.
- Canary state rollback: use the signed snapshot reset workflow; never copy
  individual account/player files by hand.
- Server artifact rollback: failed replacement publication automatically
  restores the immediately prior release. No supported post-success
  release-selection or rollback command exists; Stable is never replaced by
  canary publication.
- Lifecycle rollback: graceful Stop All first, then verify the environment's
  authenticated control records, processes, and listeners are absent.

Exact commands and accepted artifact hashes belong in the append-only ledger
after their implementing scripts and contracts pass review.
