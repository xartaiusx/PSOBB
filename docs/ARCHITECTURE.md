# Architecture

## Environments

- **Local stable:** pinned upstream Windows release, loopback-only, canonical
  login/save acceptance target.
- **Local graphics canary:** a separately staged disposable client that uses
  the stable server and canonical stable account/player state. It validates
  renderer configuration and Windows presentation only. It does not change the
  59NL camera, HUD layout, executable, protocol, or save format, and it is not
  a protocol or save-format test environment.
- **Local combat canary:** a separately pinned and reproducibly built server,
  sealed Native 59NL client, and completely isolated account/player/team,
  backup, log, secret, and lifecycle state. It is the only environment for
  protocol-, save-, or combat-sensitive development. The deterministic build,
  sealed-state transaction, lifecycle, launcher, ACL, and recovery source
  implementations passed the 2026-07-20 source-only gate. Canonical mutable
  state and live use remain blocked until marker migration, a current real
  restore drill, materialization, rollback, and both five-minute acceptance
  smokes pass.
- **Production:** a later dedicated Windows host. It is never the home PC and
  receives only an artifact that passed the local suite.

## Trust boundaries

The game server, future account broker, and future portal use separate service
identities. The portal must never read `system/licenses`, control the newserv
process, or reach newserv's HTTP API. The broker exposes only a local named-pipe
allowlist and never accepts an arbitrary shell command.

The legacy BB game credential is separate from any future portal credential.
Because upstream serializes the BB password in the license JSON, players must
use a unique game password and storage/backups require strict access control.
The accepted compatibility range is 1–16 ASCII alphanumeric characters, with
12–16 recommended. The broker generates 16 characters by default; custom portal
password input requires a separately versioned, end-to-end secret-handling
contract and is not implemented yet.

## Runtime layout

```text
C:\Github Repo's\PSOBB\PSOBB-Runtime\
  archives\          immutable downloads
  sources\           immutable, commit-pinned source snapshots
  stable\server\     pinned newserv runtime and file-based game state
  stable\client\     clean, never-launched 59NL base client
  stable\runtime\    disposable playable client and active profile
  stable\overlays\   scanned renderer/client overlay sources
  last-known-good\   atomic client rollback trees
  canary\runtime\    separately staged disposable graphics client; uses stable server/state
  combat-canary\
    server-base\release\  immutable reproducible server artifact
    server\release\      selected release; mutable state is under system\
      system\licenses\   isolated canary license state
      system\players\    isolated canary character and bank state
      system\teams\      isolated canary team state
    client\            sealed, never-launched Native 59NL base client
    base-client.manifest.json  exact base-client inventory
    runtime\client\   sealed Native 59NL client
    control\          environment-bound supervisor lifecycle evidence
    installation.json  installed build/client/state identity
    client-binding.json  sealed playable-client identity
    state-binding.json   signed snapshot/state identity
    backups\          canary-only rollback state
    logs\             canary-only diagnostics
    secrets\          canary-only signing/state material
    snapshots\        signed isolated Twills snapshots
    builds\           ignored deterministic build work
    evidence\         protected source and live gate receipts
  backups\            rotating local state copies
  secrets\            DPAPI credentials and local-only acceptance key
  logs\               operator and validation logs
  graphics-evidence\  private captures, RenderDoc files, and measurements
  archives\graphics-lab\local-assets\  immutable private author archives
  local-lab\asset-overlays\             staged private asset inventories
  local-lab\asset-activations\          Ashenbubs activation/rollback state
  local-lab\visual-asset-activations\   supplemental activation/rollback state
```

No path above is tracked by this Git repository. Sensitive game state, logs,
evidence, private archives, staged overlays, and activation state are covered
by the runtime's narrow recursively verified ACL. Local-only third-party assets
remain excluded from every public launcher package and release manifest.
The source-only gate populated the immutable `server-base\release`, archived
build outputs, and protected evidence paths. It did not populate the selected
`server\release`, base/playable clients, bindings, or mutable state; those
remain absent until the guarded initialization workflow succeeds.

Stable and CombatCanary are mutually exclusive at the process and listener
boundary. Their lifecycle records, clients, server releases, mutable state,
backups, logs, and secrets are disjoint. The WPF launcher defaults to Stable;
CombatCanary requires an explicit environment selection. The three Desktop
shortcuts remain Stable-only operator controls.

The local acceptance signing key is deliberately labeled non-production. A
production manifest is signed by a separate offline P-256 key; only its public
key is packaged with the launcher.
