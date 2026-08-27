# Project layout

The supported local installation uses one project home with a strict boundary
between tracked source and an ignored mutable runtime:

```text
C:\Github Repo's\PSOBB\
  .git\               Git metadata
  config\             tracked declarative configuration and lock data
  docs\               tracked architecture and operations documentation
  scripts\            tracked lifecycle and verification tooling
  src\                tracked project-authored source
  tests\              tracked automated checks
  PSOBB-Runtime\      ignored proprietary binaries, private assets, saves,
                      secrets, captures, build products, logs, and backups
```

The anchored `/PSOBB-Runtime/` rule in the root `.gitignore` keeps the runtime
out of Git while retaining one operator-facing project folder. Runtime safety
checks accept only that exact nested directory beneath the repository; they
reject every other in-repository runtime location. An explicit `-RuntimeRoot`
or `PSOBB_RUNTIME_ROOT` remains available for isolated tests on a local volume.
Git ignore is a tracking boundary, not encryption or backup: runtime ACL,
credential, and backup policies still apply.

Never run `git clean -x`, `git clean -X`, or an equivalent ignored-file cleanup
against this worktree: those modes can delete the entire nested runtime,
including its local backups. Preview ordinary tracked-source cleanup narrowly,
and keep an independent recovery copy outside the worktree deletion boundary.

The runtime owns these major areas:

- `archives` contains immutable acquired artifacts, including private
  author-origin local assets grouped beneath `graphics-lab\local-assets`.
- `stable`, `canary`, `combat-canary`, and `local-lab` contain isolated
  environments. `canary` is graphics-only and uses Stable server/state;
  `combat-canary` owns or reserves a reproducible `server-base\release`, a
  selected `server\release`, sealed `client` and `runtime\client` trees,
  control and binding records, state, backups, logs, secrets, builds, evidence,
  and signed snapshots. The 2026-07-20 source-only gate populated the immutable
  `server-base\release`, archived build outputs, and protected evidence. It did
  not populate the selected `server\release`, base/playable clients, bindings,
  snapshots, or mutable canary state.
- The source-ready Gameplay observation workflow reserves each explicit run
  beneath `combat-canary\evidence\gameplay-observation\<run-id>`. Its protected
  non-reparse run directory contains the fixed bounded `events-v1.partial` and
  protected no-clobber `run-manifest-v1.json`. The stopped-runtime parser reads
  that private evidence in place and returns a bounded summary; neither file is
  tracked or copied into source.
- Stable live account state is beneath
  `stable\server\release\system\licenses`, `players`, and `teams`.
  CombatCanary uses the corresponding paths beneath
  `combat-canary\server\release\system`; these trees never overlap.
- `graphics-evidence` contains raw private captures and measurements.
- `sources` contains extracted, pinned source trees and build inputs; downloaded
  archives do not belong there.
- `backups` contains rollback and recovery state.

The runtime ACL policy protects `graphics-evidence`,
`archives\graphics-lab\local-assets`, `local-lab\asset-overlays`,
`local-lab\asset-activations`, and `local-lab\visual-asset-activations` along
with Stable live game state, secrets, backups, and logs. Any existing
CombatCanary licenses, players, teams, secrets, backups, logs, snapshots,
control records, and builds enter the same protected target inventory. The
policy permits only the current user, SYSTEM, and Administrators. Reapply and
recursively verify it after activation, capture, backup, restore, build, or
canary initialization creates new state.

The 2026-07-15 relocation retired last-known-good trees, launcher/build output,
capture-job logs, and diagnostic launch records whose contents were bound to
the pre-relocation Documents roots. Surviving historical results are retained
only when they are path-independent and hash-indexed; current artifacts were
regenerated beneath the canonical nested runtime. Absolute references to the
retired roots do not belong in source, manifests, or runtime state.

No PSOBB source or runtime directory should remain under the user's Documents
folder after a verified relocation. Desktop shortcuts are the only expected
filesystem integration outside the project home. Native PSOBB
registry settings remain necessary for graphics configuration and remembered
login; only obsolete path-bearing values are removed during relocation.

After a relocation, audit and remove only verified legacy PSOBB remnants:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Remove-PSOBBLegacyRemnants.ps1 `
  -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" `
  -WhatIf
```

Review the exact candidate list, then repeat with `-Confirm:$false`. The command
removes only empty retired project/test/crash-report directories. Optional
renderer caches require an explicit cache path or switch. A temporary dgVoodoo
extraction is eligible only when its bundled archive and complete extracted
inventory match the exact `sources.lock.json` runtime archive byte for byte. It
refuses nonempty directories, reparse points or ancestors, paths outside fixed
Windows parents, and any path overlapping either canonical project root. The
ReShade cache is removed only when every file is a generated PSOBB NeutralCAS
cache entry and the directory contains no shared content.

Use `-VerifiedDgVoodooCacheDirectory <absolute-temp-cache-path>` and
`-RemoveVerifiedReShadeCache` only when those optional caches should also be
audited. Windows Error Reporting archives can require a one-off elevated
PowerShell. In that case, rerun only this command with
`-SkipDocumentsDirectories -SkipTemporaryDirectories`. Add
`-RemoveArchivedCrashReports` only after reviewing the preview; it accepts an
archived PSOBB crash folder only when it contains exactly one ordinary
`Report.wer` file no larger than 1 MiB and nothing else. Do not take ownership,
change WER ACLs, stop WER, or delete the parent archive or queue.
