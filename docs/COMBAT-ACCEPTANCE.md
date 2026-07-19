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

## Phase 0 acceptance matrix

| Gate | Current status | Required evidence |
|---|---|---|
| Stable Native Forest/manual combat | Accepted 2026-07-19 | Five-minute Twills scenario and graceful quit |
| Stable bank/save/restart/relog | Accepted 2026-07-19 | Semantic slot-0 character and bank verification |
| Canonical path and remnant audit | Accepted; recheck before materialization | Retired paths absent; nested runtime only |
| Three Desktop shortcuts | Accepted; recheck before materialization | Exact roles, canonical launcher, no credentials |
| Saved login/graphics and shared RenderDoc | Preserved; recheck before materialization | Metadata/digest-only readback |
| CombatCanary layout and ACL isolation | Implemented | Isolation and ACL suites |
| Reproducible canary server | Pending final review | Hermetic two-clean-build equality and source-lock proof |
| Sealed Twills snapshot/transaction | Pending final review | Strict JSON, exact inventories, rollback fault matrix |
| CombatCanary lifecycle/launcher | Pending final integration | Environment-specific start/observe/stop tests |
| CombatCanary materialization | Not started | Clean-tree, stopped-state, signed install readback |
| Five-minute canary and canonical smokes | Not started | Ledger entry plus restored snapshot proof |

## Rollback boundaries

- Client patch rollback: apply the `baseline` profile only while both server
  environments and clients are stopped.
- Canary state rollback: use the signed snapshot reset workflow; never copy
  individual account/player files by hand.
- Server artifact rollback: select only a previously verified canary build;
  Stable is not replaced by canary promotion.
- Lifecycle rollback: graceful Stop All first, then verify the environment's
  authenticated control records, processes, and listeners are absent.

Exact commands and accepted artifact hashes belong in the append-only ledger
after their implementing scripts and contracts pass review.
