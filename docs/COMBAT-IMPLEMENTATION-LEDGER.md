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
