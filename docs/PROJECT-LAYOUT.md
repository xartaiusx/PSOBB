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
