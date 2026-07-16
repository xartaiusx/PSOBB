# Project layout

The supported local installation uses two sibling directories under the same
development root:

```text
C:\Github Repo's\
  PSOBB\             Git-tracked source, configuration, tests, and docs
  PSOBB-Runtime\     proprietary binaries, private assets, saves, secrets,
                     captures, build products, logs, and backups
```

Keeping the runtime beside, rather than inside, the repository prevents SEGA
client files, third-party local-only assets, credentials, and generated state
from entering Git. Scripts derive this sibling runtime automatically; an
explicit `-RuntimeRoot` or `PSOBB_RUNTIME_ROOT` remains available for isolated
tests.

The runtime owns these major areas:

- `archives` contains immutable acquired artifacts, including private
  author-origin local assets grouped beneath `graphics-lab\local-assets`.
- `stable`, `canary`, and `local-lab` contain isolated release channels.
- `secrets`, `licenses`, `players`, and `teams` contain protected live state.
- `graphics-evidence` contains raw private captures and measurements.
- `sources` contains extracted, pinned source trees and build inputs; downloaded
  archives do not belong there.
- `backups` contains rollback and recovery state.

The runtime ACL policy protects `graphics-evidence`,
`archives\graphics-lab\local-assets`, `local-lab\asset-overlays`,
`local-lab\asset-activations`, and `local-lab\visual-asset-activations` along
with live game state, secrets, backups, and logs. The policy permits only the
current user, SYSTEM, and Administrators. Reapply and recursively verify it
after activation, capture, backup, or restore work creates new state.

The 2026-07-15 relocation retired last-known-good trees, launcher/build output,
capture-job logs, and diagnostic launch records whose contents were bound to
the pre-relocation Documents roots. Surviving historical results are retained
only when they are path-independent and hash-indexed; current artifacts were
regenerated beneath the canonical sibling runtime. Absolute references to the
retired roots do not belong in source, manifests, or runtime state.

No PSOBB source or runtime directory should remain under the user's Documents
folder after a verified relocation. Desktop shortcuts are the only expected
filesystem integration outside the two project directories. Native PSOBB
registry settings remain necessary for graphics configuration and remembered
login; only obsolete path-bearing values are removed during relocation.

After a relocation, audit and remove only verified legacy PSOBB remnants:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\Remove-PSOBBLegacyRemnants.ps1 `
  -RuntimeRoot "C:\Github Repo's\PSOBB-Runtime" `
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
