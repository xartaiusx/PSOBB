# Private local visual assets

These assets are excluded from Git and every public release. The runtime keeps
the author-origin archives unchanged and records their exact hashes in
`config/sources.lock.json`. Rejected supplemental archives remain under
`archives\graphics-lab\local-assets\supplemental`; extracted source trees stay
separate under `sources`. Author archives, staged overlays, activation state,
and raw evaluation evidence are covered by the runtime's narrow recursively
verified ACL.

## Candidate disposition

| Component | Status | Combined-profile rule |
|---|---|---|
| AshenbubsHD v1.02 All | Controlled launch passed; full acceptance pending | Intended immutable foundation; owns map, character-texture, monster, and object replacements, while later layers may only fill untouched destinations |
| Luthee/Eleria HD UI v1.1.6 standard | Rejected for the exact 59NL composition | Causes a controlled `Psobb.exe` access violation when loaded alone above exact Ashenbubs All; retain unchanged for provenance only |
| Higher Resolution Item Boxes, 2025-12-30 | Rejected for the exact 59NL composition | The live lobby/game path crashes with this layer active; retain unchanged for provenance only |
| Echelon HD Effects & Technics, 2019-05-27 | Rejected from the Ashenbubs stack | Collides with Ashenbubs `data/bm_eff_ice.bml` |
| Echelon HD Blood, 2018-06-16 | Rejected from the Ashenbubs stack | Collides with Ashenbubs `data/bm_ene_common_all.bml` |

The typed `assetCandidates` matrix in `config/graphics-evidence.json` is the
source of truth. It fixes evaluation order as Ashenbubs (10), Luthee (20), item
boxes (30), Echelon Effects (40), and Echelon Blood (50). Ashenbubs remains
pending because a clean launch and Forest frame are not full graphical
acceptance. Luthee, item boxes, and both Echelon candidates are final
rejections for this exact composition. Local graphical completion requires
every entry to be either accepted or rejected. An accepted HD profile must list
exactly the accepted assets in activation order.

Luthee's two files under `data/ephinea/custom` were copied byte-for-byte to the
ordinary stock-59NL `data` directory during isolation. This was destination
routing only; the files were not edited or repacked. The author prohibits
editing, repacking, bundling, rereleasing, and alternate hosting. The unchanged
archive remains local for provenance but is excluded from the playable stack.

### Controlled launch isolation on 2026-07-15

- Exact Ashenbubs All alone reached Forest, produced a lossless 2560x1600 frame,
  and remained responsive past 388 seconds without a Windows Application Error.
- Exact Ashenbubs All plus the unchanged item-box layer passed a short launch
  window, but the later principal-account lobby/game path failed after
  approximately 74 seconds with exception `0xc0000005` at offset `0x0046cf08`.
- Luthee HD UI v1.1.6 alone above exact Ashenbubs All failed approximately
  9-10 seconds after `Psobb.exe` appeared with exception `0xc0000005` at offset
  `0x00388270`.

Machine-specific Windows Error Reporting records remain private outside Git.
These isolation results reject both supplemental layers without modifying or
redistributing their archives. They do not yet accept Ashenbubs visually or
satisfy the exact-profile pacing, soak, scene-corpus, RenderDoc, and rollback
gates.

## Transactional activation

Stop the client and server before every operation. Activations are ordered and
must be rolled back in reverse order. Each activation snapshots the exact
previous files and `client-profile.json`, verifies every source/destination
hash, and records a runtime-only manifest.

No supplemental candidate is currently activatable: the tooling reads the
evidence registry and fails closed on every rejected disposition. A future
re-evaluation requires a separate reviewed evidence change before another
isolated lab activation. AshenbubsHD All is the immutable foundation: preflight
also rejects every archive that targets an Ashenbubs-owned destination. The
rejected candidates remain provenance records but cannot enter the playable or
accepted stack.

## Visual acceptance

- Compare HUD scale 1.00 against the 1.25 readability target.
- Inspect palette frames, inventory and action icons, section IDs, damage
  numbers, radar frame, menus, chat, and every character screen for clipping.
- Inspect stock drop-box colors, eggs, transparency, mip behavior, inventory,
  shop, bank, and floor pickup at native and supersampled internal resolution.
- Do not activate any supplemental archive over Ashenbubs; the evidence
  registry and immutable-foundation collision checks enforce their final
  rejected dispositions.
- Never treat a clean archive load as visual acceptance. Keep the candidate
  pending until same-scene captures and blind A/B selection are complete.

Author sources: [Luthee HD UI](https://www.pioneer2.net/community/threads/hd-ui-project-by-luthee-a-k-a-eleria.23410/),
[Higher Resolution Item Boxes](https://www.pioneer2.net/community/threads/higher-resolution-item-box-textures.32333/),
and [Echelon's maintained collection](https://www.pioneer2.net/community/threads/echelons-skins-modifications.4357/).
