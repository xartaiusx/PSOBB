# Graphics profiles and acceptance

The source-controlled graphics contract is split across three files:

- `config/graphics-profiles.json` declares the only ten renderer
  chains and binds them to the exact 59NL executable.
- `config/graphics-evidence.json` records the candidate stage, disposition,
  blockers, and acceptance gates without storing raw captures.
- `config/sources.lock.json` records source, tag/commit identity, archive and
  member hashes, signature state, license, distribution boundary, and rollback
  target.

Validate the graph and print its current state with:

```powershell
pwsh -File .\scripts\Test-PSOBBGraphicsProfiles.ps1
pwsh -File .\scripts\Test-PSOBBGraphicsArtifacts.ps1
pwsh -File .\scripts\Get-PSOBBGraphicsEvidenceStatus.ps1
pwsh -File .\tests\runtime\Test-ScreenshotEvidenceTooling.ps1
pwsh -File .\tests\runtime\Test-CasF10PairImport.ps1
```

The validator fails when a profile declares a second D3D8 owner, references an
unknown component, exceeds the 3840x2400 true-widescreen ceiling, enables
dgVoodoo D3D12, enables the watermark, selects an undeclared resolution/filter,
drifts a project-owned source hash, or claims acceptance without all evidence.

## Profile boundaries

| Profile | Boundary | Current role |
| --- | --- | --- |
| `safe-native-4x3` | Stable, no proxy | Emergency rollback |
| `clarity-dgvoodoo-4x3` | Canary, dgVoodoo D3D11 FL11 | Runtime-verified comparison baseline |
| `lab-widescreen-16x10` | Local-only, dgVoodoo + explicit ASI layers | Black-box behavior reference only |
| `lab-widescreen-hd-16x10` | Local-only reference layout + private AshenbubsHD + project LargeAssets ASI | Runtime-verified no-CAS private texture candidate; evidence incomplete |
| `lab-widescreen-cas-16x10` | Local-only reference layout + standard imported ReShade | Evidence materializer only; not launcher, CLI, or shortcut eligible |
| `cleanroom-widescreen-canary` | Local-lab staging, dgVoodoo + project ASI, no ReShade | Partial clean-room widescreen isolation candidate |
| `cas-evaluation-16x10` | Local-only, clean-room chain + standard imported ReShade | Explicit 0.15/0.25/0.35 CAS comparison only |
| `fidelity-modern-16x10` | Canary, project-owned enhancement + local ReShade import | Blocked intended target |
| `dxvk-canary` | Local-only x32 D3D8/D3D9 pair | Unsupported-on-Windows comparison |
| `d3d8to9-canary` | Isolated D3D8 translation | Compatibility comparison, not an upscaler |

The current evidence reconciliation records these outcomes:

- `lab-widescreen-16x10` is runtime-verified but still pending RenderDoc,
  complete scene/HUD geometry, gameplay pacing, soak, rollback, and blind A/B
  gates. It remains a local-only black-box reference.
- `lab-widescreen-hd-16x10` is runtime-verified and pending. Characters,
  Objects, Monsters, and Maps passed isolated activation and load checks, and
  exact All activation composed 484 source entries into 481 files while
  loading the pinned LargeAssets module. A lossless 2560x1600 Forest frame, a
  600.165-second gameplay trace, and a 1800.104-second soak are indexed.
  RenderDoc was armed for the exact profile, but no `.rdc` was captured, so
  replay-inspected render-target proof remains pending. The complete scene and
  HUD corpus, dynamic resize-triggered D3D device recreation, and blind
  stock/HD selection also remain incomplete. Full rollback of the exact All
  activation passed, and the same composition was reactivated while stopped
  with new exact current hashes.
- `lab-widescreen-cas-16x10` is runtime-verified and pending. CAS `0.15` is
  technically rejected because it introduced 12 exact-black pixels and reached
  `6.27451%` maximum halo overshoot against the `3%` limit. The `0.25` trace
  whose metadata says `lobby` was actually recorded at character selection and
  is quarantined from lobby acceptance; aligned `0.25` and `0.35` capture pairs
  are still missing.
  This profile remains an evidence-materializer input and is not playable from
  the launcher, command line, or desktop shortcuts.
- `cleanroom-widescreen-canary` and `cas-evaluation-16x10` are rejected because
  the tested project enhancement produced only an approximately 640x480
  upper-left viewport with the rest of the 2560x1600 output black.
- `dxvk-canary` and `d3d8to9-canary` are rejected because each stretched the
  4:3 client image across 16:10. Their successful module loads do not override
  that geometry failure.

### AshenbubsHD local-only candidate

`lab-widescreen-hd-16x10` is a first-class catalog and evidence identity, but
it is never a clean-materializer target. Transactional activation alone creates
it from `lab-widescreen-16x10`; launcher **Verify / repair** invokes activation
`Verify` and cannot rebuild, reinstall, or remove private assets. The profile
remains local-only and uses no CAS. Verified evidence now covers:

- the exact AshenbubsHD archive and extracted inventory;
- the exact large-asset module preflight, isolated character/object/monster/map
  loads, exact All activation, and loaded-module inspection;
- watermark-free 2560x1600 borderless presentation, initial movable 1600x1000
  resizable presentation, reversible switching between those policies, and an
  indexed lossless Forest frame;
- a 600.165-second representative gameplay trace and 1800.104-second soak; and
- full restoration of all 481 All-overlay targets to a strict clean no-HD
  runtime, followed by stopped reactivation of the exact 481-file,
  3,447,006,836-byte All composition with new current hashes.

It remains pending on:

- an actual RenderDoc `.rdc` capture and replay-inspected backbuffer and
  internal-render evidence;
- the complete lossless scene/HUD/geometry corpus and arbitrary
  resize-triggered D3D device recreation; and
- a blind same-scene HD versus stock A/B.

An explicit LocalLab `-WindowMode Borderless` or `-WindowMode Resizable`
selection is materialized before process creation while the lifecycle lock is
held. For the client-patch-owned widescreen profiles, this transaction changes
only `widescreen.cfg`'s guarded `Windowed` value plus the matching
`client-profile.json` mode and configuration hash; every asset, module,
activation, renderer, and rollback declaration remains protected and the full
runtime contract is revalidated before launch. Resizable mode is currently an
initial movable 16:10 window. The local reference ASI supplies its caption and
thick frame; after it settles, lifecycle corrects only that exact component's
initial client area to the profile-bound 1600x1000 when necessary and then
reobserves it. An already-correct client-owned window is left untouched, and
the project enhancement is never eligible for this correction. Live acceptance
observed a responsive captioned/thick-frame 1600x1000 client at aspect ratio
1.6, a reversible 1280x800-to-1600x1000 window-size test, and return to
watermark-free 2560x1600 Borderless at `(0,0)`. Arbitrary resize-triggered D3D
device recreation remains a project-owned enhancement gate and is not claimed
by this switch.

The clean graphics materializer rejects any replacement while an active
`localAssetOverlay` or `localModules` declaration exists. Explicit activation
rollback must restore `lab-widescreen-16x10` first. CAS catalog profiles remain
available for controlled evidence collection only and are deliberately absent
from GUI, command-line, and desktop-shortcut eligibility.

The local-lab runtime contract is
`PSOBB-Runtime\local-lab\runtime\client\Psobb.exe`; its immutable artifacts and
overlays stay under `PSOBB-Runtime\archives\graphics-lab` and
`PSOBB-Runtime\local-lab\overlays`. Merely acquiring or extracting an artifact
does not make a profile runnable or accepted.

Exactly one layer owns D3D8. dgVoodoo, DXVK, and d3d8to9 are mutually exclusive
owners. `dinput8.dll` may load an explicitly allowed ASI and ReShade may be an
explicit `dxgi.dll` layer behind dgVoodoo; neither is an implicit second D3D8
owner. Wrapper files never belong in a Windows system directory.

## Current security findings

- Ultimate ASI Loader 9.7.2 matches the official GitHub archive digest, but its
  `CN=FusionFix` signer chain ends at an untrusted root on this machine.
- ReShade 6.7.3 came from the official site and is locally hash-locked, but its
  `CN=ReShade` signer chain also ends at an untrusted root.
- The widescreen reference ASI is unsigned and has no explicit reuse license.
  It remains an immutable, nonredistributable black-box reference.
- The project-owned enhancement is MIT-licensed and its exact unsigned x86
  artifact is pinned by a reproducible source-input build manifest. It does not
  yet implement HUD/minimap transforms or resize-triggered device recreation.
- PresentMon 2.5.1 and RenderDoc 1.45 are external diagnostics, never playable
  client modules. Their selected executables have valid signatures.
- The ten locked graphics/source provenance entries, selected members, ZIP/TAR
  paths, and recorded signature states pass the contract suite. Downloaded
  archive/module/tool paths retain their recorded Defender scan results.

Those findings are recorded, not bypassed. Runtime promotion still requires
the exact runtime module allowlist and an isolated module load. No certificate
or Defender exclusion is installed.

## Evidence storage and promotion

Raw PNGs, RenderDoc captures, PresentMon traces, private local-asset tests, and
Twills login screens stay outside Git under a run-specific path such as:

```text
PSOBB-Runtime\graphics-evidence\<profile-id>\<UTC-run-id>\
```

The tracked evidence file stores only redacted `runtime:` references, hashes,
metrics, and a reviewed pass/fail result. It must never contain credentials,
raw account data, private client assets, or absolute secret paths.

Index one private lossless screenshot, or compare an aligned candidate against
an aligned reference, with:

```powershell
pwsh -File .\scripts\Get-PSOBBScreenshotEvidence.ps1 `
  -ScreenshotPath "$run\screenshots\candidate.png" `
  -ReferencePath "$run\screenshots\reference.png" `
  -ProfileId lab-widescreen-16x10 `
  -CandidateId lanczos2-cas015 `
  -SceneId lobby-fixed-camera `
  -ValidationSpecPath "$run\lobby-validation.json" `
  -Disposition pending `
  -OutputPath "$run\indexes\lobby-candidate.json"
```

Both PNG inputs must be outside the repository. The output is a redacted JSON
index containing only safe caller IDs, exact SHA-256/byte size/dimensions,
edge-band and pillar measurements, active-content sharpness metrics, geometry
checks, and optional reference deltas. It contains no input path, filename, or
pixel data and is written atomically without overwriting an existing index.

Geometry is never guessed from arbitrary scene pixels. A version 1 validation
spec supplies the expected output/content aspect and reviewer-measured
landmarks for circles or other known shapes:

```json
{
  "schemaVersion": 1,
  "expectedOutput": { "width": 2560, "height": 1600 },
  "expectedOutputAspectRatio": 1.6,
  "expectedContentAspectRatio": 1.6,
  "maximumAspectErrorPercent": 0.1,
  "maximumPillarSymmetryDeltaPixels": 1,
  "requiresCircleChecks": true,
  "casExpected": true,
  "maximumCasHaloOvershootPercent": 3,
  "circles": [
    {
      "id": "minimap-ring",
      "horizontalDiameterPixels": 240,
      "verticalDiameterPixels": 240,
      "maximumAxisErrorPercent": 0.1
    }
  ],
  "aspects": [
    {
      "id": "known-ui-landmarks",
      "observedWidthPixels": 160,
      "observedHeightPixels": 100,
      "expectedRatio": 1.6,
      "maximumErrorPercent": 0.1
    }
  ]
}
```

The sharpness record reports mean and p95 central-difference gradient,
Laplacian variance, and edge density over detected active content. CAS
comparison additionally reports luma MAE/RMSE/PSNR, newly introduced exact
black/white clipping, and overshoot beyond each reference-edge pixel's local
3x3 luma range. Screenshots must therefore be same-scene, same-camera,
same-dimension captures. These metrics screen out invalid candidates; they do
not replace the required blind visual A/B.

Acceptance requires every applicable gate to pass. Capture, screenshot,
frame-pacing, soak, rollback, and manual A/B gates also require an artifact
reference. A profile with a failed gate must be rejected with a reason; a
blocked profile must retain at least one blocker.

The objective run consists of a 120-second lobby trace, at least ten minutes of
representative gameplay, and at least a 30-minute soak. Reject a candidate for
a crash/device reset, thermal cadence loss, or a p95 frame-time regression over
10 percent without a clear visual win. True 16:10 must remain within 0.1 percent
aspect error. CAS must stay at or under 3 percent halo overshoot with no black
or white clipping.

The project-owned CAS source is under `patches/reshade`. It is disabled by
default until `0.15`, `0.25`, and `0.35` are compared; the weakest passing value
wins. Bloom, AO, depth of field, film grain, chromatic aberration, HDR/tone
mapping, color grading, and SMAA remain excluded from the default profile.

Materialize the clean-room layer without ReShade first. CAS materialization
requires an explicit strength and generates a single-technique preset; it does
not import an upstream shader pack. Use `lab-widescreen-cas-16x10` to compare
CAS on the already proven local-only reference layout. Do not treat that result
as evidence that the partial clean-room implementation is complete:

```powershell
pwsh -File .\scripts\New-PSOBBGraphicsLabRuntime.ps1 `
  -ProfileId cleanroom-widescreen-canary -Confirm:$false

pwsh -File .\scripts\New-PSOBBGraphicsLabRuntime.ps1 `
  -ProfileId lab-widescreen-cas-16x10 -CasStrength 0.15 -Confirm:$false

pwsh -File .\scripts\New-PSOBBGraphicsLabRuntime.ps1 `
  -ProfileId cas-evaluation-16x10 -CasStrength 0.15 -Confirm:$false
```

Each CAS materialization writes an immutable
`PSOBB-ReShade-Template.ini` beside the mutable `ReShade.ini`. ReShade 6.7.3
may expand the latter on first launch. Post-launch validation accepts only the
closed, pinned set of generated sections and keys, the project shader and
preset paths, a user-local ReShade cache path, inert command fields, the exact
single technique and strength, and no `.addon`/`.addon32` modules. Unknown
fields, paths, effects, modules, or strength drift fail closed.

The generated screenshot contract binds F10 to lossless PNG and enables
ReShade's before/after capture pair. A single request therefore produces a
pixel-aligned no-CAS reference and post-CAS candidate from the same frame;
the overlay and tutorial are excluded. This is the required input pair for
CAS halo and clipping analysis.

After materializing one CAS strength, focus PSOBB and press F10 exactly once.
Do not press it again until the importer completes. Import the sole stable pair
from the exact LocalLab client and run the analyzer in one transaction with:

```powershell
pwsh -File .\scripts\Import-PSOBBCasF10Pair.ps1 `
  -RuntimeRoot 'C:\Users\xtyty\Documents\PSOBB-Runtime' `
  -SceneId character-select-fixed-camera `
  -ValidationSpecPath 'C:\Users\xtyty\Documents\PSOBB-Runtime\graphics-evidence\lab-widescreen-cas-16x10\cas-comparison-20260714\cas-2560x1600-validation.json'
```

The importer is safe whether the client is running or stopped: it never sends
input, starts, stops, or closes a process. It requires the fully validated
LocalLab CAS profile at exactly `0.15`, `0.25`, or `0.35`; accepts exactly two
top-level PNGs named by ReShade as one same-stem `Before`/`After` pair; waits
for multiple exclusive, hash-stable reads; and refuses an existing evidence
run. `Before` is always the analyzer reference and `After` is always the CAS
candidate. The files and redacted JSON index are staged on the runtime volume
and exposed under `graphics-evidence` by one directory rename. If validation or
analysis fails, both original screenshots are moved back and no partial run is
published.

Primary implementation references are the
[dgVoodoo documentation](https://www.dege.freeweb.hu/dgVoodoo2/ReadmeGeneral/),
[DXVK Windows guidance](https://github.com/doitsujin/dxvk/wiki/Windows),
[PresentMon](https://github.com/GameTechDev/PresentMon),
[RenderDoc](https://github.com/baldurk/renderdoc),
[ReShade](https://github.com/crosire/reshade), and
[AMD FidelityFX CAS](https://github.com/GPUOpen-Effects/FidelityFX-CAS).
