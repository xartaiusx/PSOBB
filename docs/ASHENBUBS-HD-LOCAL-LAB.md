# AshenbubsHD v1.02 local-lab gate

AshenbubsHD is a private, user-imported graphics experiment, not a project
dependency or distributable client component. The source-controlled integration
stores only provenance, hashes, inventory rules, automation, and test fixtures.
The texture files, nested archives, extracted overlay, captures, and any future
composed client remain outside Git.

## Provenance and rights boundary

The approved user-owned source is:

```text
C:\Github Repo's\PSOBB-Runtime\archives\graphics-lab\local-assets\AshenbubsHD-PSOBB-v1.02-cfe0fd18.zip
size:   1,147,485,243 bytes
SHA-256: cfe0fd182485e34d05f5d93b08580453a351ad7ba8ad35056d9167a412b2efea
```

The [official Nexus description](https://www.nexusmods.com/phantasystaronline/mods/3)
identifies the author and scope. The
[official files page](https://www.nexusmods.com/phantasystaronline/mods/3?tab=files)
identifies the main file as version 1.02. Nexus records that the file may not be
uploaded elsewhere, modification and asset use require author permission, and
conversion is forbidden. This repository therefore treats it as immutable,
local-only, nonredistributable material. It must never be repacked, modified,
published, committed, placed in a launcher release, or served to players.

The author also says the pack currently works only on Ephinea because that
client raises texture-allocation limits. That statement is a compatibility
warning, not permission to copy Ephinea's client changes. Staging the files does
not establish compatibility with this project's 59NL client.

## Locked inventory

The outer ZIP and its five file members are SHA-256 locked. The four nested RAR
packs are independently locked and must contain exactly:

| Selection | Destination when eventually composed | Files | Expanded bytes | Largest file |
| --- | --- | ---: | ---: | ---: |
| `Characters` | `data` | 12 AFS | 444,502,016 | 61,546,496 |
| `Objects` | `data` | 192 BML | 77,103,296 | 8,782,144 |
| `Monsters` | `data` | 137 BML | 231,514,592 | 22,422,432 |
| `Maps` | `data/scene` | 143 XVM | 2,696,614,100 | 85,533,184 |
| `All` | all of the above | 484 source entries | 3,449,734,004 | 85,533,184 |

Every member must be a flat regular file with the declared extension, a valid
archive CRC, and a size no greater than the independently reviewed 100,000,000
byte large-asset ceiling. Executables, links, alternate streams, encryption,
directories, traversal, drive-qualified names, extra files, and case-colliding
names fail closed.

Three BML destinations occur in both the monster and object packs. They have
identical size and CRC in the locked source. The materializer keeps every pack
physically separate and permits only these three declared identical collisions
during `All` composition:

- `data/bm_obj_ep4_bee_a.bml`
- `data/bm_obj_ep4_bee_b.bml`
- `data/bm_obj_ep4_bee_nest.bml`

## Recommended order

This experiment belongs after the renderer, true-widescreen layout, and
borderless 2560x1600 baseline are stable. The playable HD candidate is no-CAS.
CAS remains available only in the isolated evidence materializer; texture
changes can alter scene edges, so any research comparison must be repeated
after final texture selection and cannot make a CAS profile launcher-eligible.
Activation starts only from the exact no-CAS `lab-widescreen-16x10` profile and
materializes the distinct `lab-widescreen-hd-16x10` identity. Its rollback
profile is always `lab-widescreen-16x10`; the private texture candidate cannot
masquerade as the clean reference profile.

Use the lowest-risk progression:

1. Stop every PSOBB client and newserv. Run a Microsoft Defender custom scan on
   the exact archive without adding an exclusion.
2. Stage `Characters` and inspect character selection, creation, dressing room,
   lobby, animation, seams, alpha, and VRAM use.
3. Stage `Objects`, then `Monsters`, testing each independently in every episode.
4. Stage `Maps` last and perform area-by-area load, telepipe, boss, fog, VRAM,
   device-reset, and 30-minute soak checks.
5. Stage `All` only after every isolated pack passes. Re-run renderer rollback,
   lossless screenshots, PresentMon, and the CAS blind comparison.

Each staging install replaces only the isolated asset overlay and snapshots its
previous staged state. It does not alter the stable client, local-lab playable
client, server patch data, or newserv data. The separate activation script then
requires and hash-records the project-owned `PSOBB.LargeAssets.asi`, its exact
`[LargeAssets] Enabled=1` companion INI, the pinned build manifest, and the
pinned exact-client verifier. It proves the 59NL executable and
`large-assets-59nl` capability before it copies any unchanged private asset.

Activation preflights every destination against the immutable base client.
Unknown existing bytes and undeclared conflicts fail closed. It snapshots the
prior profile, every replaced file, and every previously absent destination
before the first replacement; each new file is size/SHA-256 checked before and
after its same-volume atomic rename. The runtime-only activation manifest holds
the exact per-file inventory. Source control and public release manifests hold
none of the private asset files or their composed payload.

Graphics-profile rematerialization refuses to replace a LocalLab runtime while
`localAssetOverlay` or `localModules` is active. Use the explicit activation
rollback first, then materialize a clean profile. Launcher **Verify / repair**
for the HD profile runs `-Action Verify` only; it never rebuilds, removes, or
silently reinstalls local-only assets.

## Commands

With the server and client stopped, stage one isolated selection:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\Set-PSOBBAshenbubsHDOverlay.ps1 `
  -Action Install `
  -Pack Characters `
  -ArchivePath "C:\Github Repo's\PSOBB-Runtime\archives\graphics-lab\local-assets\AshenbubsHD-PSOBB-v1.02-cfe0fd18.zip"
```

Use `Objects`, `Monsters`, `Maps`, or `All` for later isolated stages. Verify the
complete current overlay inventory and every extracted SHA-256:

```powershell
pwsh -File .\scripts\Set-PSOBBAshenbubsHDOverlay.ps1 -Action Verify
```

Restore the newest prior snapshot, or name one shown beneath the runtime
`snapshots` directory:

```powershell
pwsh -File .\scripts\Set-PSOBBAshenbubsHDOverlay.ps1 -Action Rollback
pwsh -File .\scripts\Set-PSOBBAshenbubsHDOverlay.ps1 -Action Rollback -SnapshotId <id>
```

The materializer locks the locally installed official 7-Zip 26.02 `7z.exe` and
`7z.dll` because RAR extraction depends on both. 7-Zip's
[official site](https://www.7-zip.org/) documents RAR unpacking and its license.
A tool update requires an explicit provenance/hash review before use.

## Client activation and rollback

With newserv and every PSOBB client stopped, first materialize the clean no-CAS
reference and stage one pack using the commands above. Activation also requires
the catalog to contain the exact `lab-widescreen-hd-16x10` LocalLab declaration
with `rollbackProfileId` set to `lab-widescreen-16x10`:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\Set-PSOBBAshenbubsHDClientActivation.ps1 `
  -Action Activate
```

Verify the current staged overlay, activation manifest, exact data inventory,
ASI, enabled INI, build inputs, verifier, client executable, and LocalLab
profile as one closed contract:

```powershell
pwsh -File .\scripts\Set-PSOBBAshenbubsHDClientActivation.ps1 -Action Verify
```

Rollback accepts only the snapshot ID declared by the active profile and
refuses to overwrite any activated target whose bytes changed unexpectedly:

```powershell
pwsh -File .\scripts\Set-PSOBBAshenbubsHDClientActivation.ps1 -Action Rollback
```

Rollback restores the complete prior `lab-widescreen-16x10` profile and every
original/absent file state. It never touches stable, canary, server patch data,
or newserv state.
