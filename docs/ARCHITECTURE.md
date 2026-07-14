# Architecture

## Environments

- **Local stable:** pinned upstream Windows release, loopback-only, canonical
  login/save acceptance target.
- **Local graphics canary:** a separately staged disposable client that uses
  the stable server and canonical stable account/player state. It validates
  renderer configuration and Windows presentation only. It does not change the
  59NL camera, HUD layout, executable, protocol, or save format, and it is not
  a protocol or save-format test environment.
- **Future protocol/save canary:** requires a separately pinned server/build
  and completely isolated account/player state before any protocol- or
  save-sensitive feature can be activated.
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
C:\Users\xtyty\Documents\PSOBB-Runtime\
  archives\          immutable downloads
  sources\           immutable, commit-pinned source snapshots
  stable\server\     pinned newserv runtime and file-based game state
  stable\client\     clean, never-launched 59NL base client
  stable\runtime\    disposable playable client and active profile
  stable\overlays\   scanned renderer/client overlay sources
  last-known-good\   atomic client rollback trees
  canary\runtime\    separately staged disposable graphics client; uses stable server/state
  backups\            rotating local state copies
  secrets\            DPAPI credentials and local-only acceptance key
  logs\               operator and validation logs
```

No path above is tracked by this Git repository.

The local acceptance signing key is deliberately labeled non-production. A
production manifest is signed by a separate offline P-256 key; only its public
key is packaged with the launcher.
