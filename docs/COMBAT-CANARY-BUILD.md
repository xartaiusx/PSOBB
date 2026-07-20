# Combat-canary build provenance

The combat-canary server is a local-only, reproducible source build. The stable
server is not modified by this workflow. Build and verification are performed
by `scripts/Build-PSOBBCombatCanaryServer.ps1` against the exact contract in
`config/combat-canary-build.json`.

## Native execution boundary

Top-level native programs are resolved to exact absolute paths and checked by
size, SHA-256, and version immediately before each invocation. Child processes
receive a cleared environment with an explicit PATH, locale, temporary root,
Windows architecture, Git configuration, and profile-free Bash mode.

Top-level hashes alone do not bind programs or loadable code that those tools
may start or load. `config/native-execution-payloads.json` therefore records
the exact relative path, size, and SHA-256 of every allowed `.exe`, `.dll`,
`.pyd`, `.bat`, `.cmd`, and `.com` below these five non-OS roots:

- CMake `bin`
- Git for Windows
- GnuPG `bin`
- the Ninja package root
- the complete WinLibs `mingw64` root

The manifest includes compiler and binutils helpers such as `cc1`, `cc1plus`,
`collect2`, `as`, `ld`, `ar`, `ranlib`, `windres`, `dlltool`, and `strip`, along
with their adjacent runtime DLLs. Verification compares the actual set to the
manifest, so an added, missing, renamed, reordered, resized, or rehashed entry
fails closed. Reparse-point path escapes also fail closed. Before each native
tool invocation, payload ownership is derived from the tool's exact path and
every non-System32 directory exposed through its child PATH. Every selected
payload is then enumerated and rehashed. An uncovered or ambiguously owned
non-System32 tool or PATH directory fails before process creation.

Executable-code coverage is not sufficient build-input provenance. The same
manifest therefore contains an `ordinaryFileTrees` contract for every ordinary
file below the complete CMake, Git for Windows, GnuPG, Ninja-package, and
WinLibs roots. No file within those roots is excluded. This binds GCC specs,
headers, static libraries, CMake platform/compiler modules, Git/MSYS scripts,
configuration data, and every other ordinary file that could affect output.

Each tree digest is SHA-256 over UTF-8 records sorted by ordinal normalized
relative path. A record is `path`, NUL, invariant decimal byte length, NUL,
lowercase file SHA-256, and LF. The contract also fixes the exact file count
and total bytes. The full trees are recomputed during initial preflight and
again immediately before each of the two clean newserv builds. Any content or
exact-set change fails closed before compilation.

Windows System32 is the exact OS-managed trust boundary. Other directories
below the Windows root are not exempt. `cmd.exe`, `tar.exe`, and `subst.exe`
are still individually hash-locked, but Windows system DLL servicing is not
duplicated into the repository manifest. This is the only behavior-bearing
host-file exclusion from the full-tree contracts.

## Other locked inputs

- Every source and build repository-local `.git/config` is parsed before Git
  use and must contain only the exact minimal `core` allowlist. Includes, URL
  rewrites and remotes, filters, credentials, proxies, hooks, file-system
  monitors, duplicate keys, and unknown keys fail closed. System and global
  config are disabled. Git runs from a verified empty directory with explicit
  `--git-dir` and `--work-tree`; build checkouts use only an exact approved
  local object-store alternate and do not clone or fetch.
- Release archives are size- and SHA-256-locked and verified by pinned `gpgv`
  against the read-only project keyring and an empty isolated home.
- The ordered newserv patch series contains only the reviewed deterministic
  build-metadata patch.
- Both newserv builds must be byte-identical to each other and to the output
  contract before publication.
- README, license, and `system` package inputs come only from the second
  disposable checkout's validated Git index and worktree. Index modes and
  normalized paths are allowlisted, duplicate and case-colliding paths fail,
  and reviewed `120000` links must resolve to another tracked ordinary file
  inside that checkout. Ignored and untracked origin files cannot enter the
  package.
- The release manifest is complete, reparse-free, source-lock-bound, and sorted
  by unique normalized paths using ordinal comparison.
- The built executable's read-only `--help` version header and ordered PE import
  table are recomputed. PE imports are parsed by the exact hash-locked WinLibs
  `objdump` payload. The published package is scanned for ASCII and UTF-16LE
  `P:\` and `P:/` build-path needles before publication and during Verify.
- Build parses the exact CTest totals for zlib and phosg. The schema fixes test
  names and counts, path-normalization flags, linker flags, version output, PE
  import order, and the explicit not-run status for newserv's fixture-dependent
  CTest suite.

## Offline-input boundary

The workflow intentionally invokes no network command. Native child
environments are rebuilt from an empty environment, proxy and credential state
is absent, Git permits only the local `file` protocol, and Git's helper
execution directory is empty. Git for Windows `/usr/bin` remains available to
the profile-free Bash process because the libiconv configure script requires
its POSIX utilities; that installed tree also contains network-capable programs
which this workflow does not invoke.

This is an offline-input deterministic build policy, not an operating-system
network sandbox. Native socket creation is not denied by Windows policy, so
local-only use and stopped server/client boundaries remain explicit limits.

## Publication and rollback

The build holds project build and lifecycle mutexes, requires all PSOBB and
newserv processes and listeners to be stopped, and uses a unique ignored build
root mapped temporarily to `P:`. The mapping is removed and the stopped-runtime
boundary is rechecked before transactional canary publication. Replacement
failure restores the prior canary release. The stable release is not a target
of this operation. This is an automatic failed-publication recovery boundary;
the current workflow does not expose a post-success release-selection or
rollback command.

Build command:

```powershell
& .\scripts\Build-PSOBBCombatCanaryServer.ps1 `
  -Action Build `
  -RuntimeRoot "C:\Github Repo's\PSOBB\PSOBB-Runtime" `
  -Confirm:$false
```

Verification command:

```powershell
& .\scripts\Build-PSOBBCombatCanaryServer.ps1 -Action Verify
```

Successful verification returns the profile ID, source commit, executable
SHA-256 and size, release file count and byte total, version output, runtime
import count, release root, and `Verified = true`. These fields verify the
published artifact; they do not by themselves accept runtime materialization
or live gameplay.

Focused acceptance command:

```powershell
& .\tests\runtime\Test-CombatCanaryBuild.ps1
```
