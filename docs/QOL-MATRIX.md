# Quality-of-Life Compatibility Matrix

| Capability | Initial status | Source/strategy | Public distribution |
| --- | --- | --- | --- |
| Private/shared/duplicate drops | Stable | newserv | Yes, with MIT notice |
| Common bank and explicit save | Stable | newserv | Yes, with MIT notice |
| Rare text notifications | Stable; BB default staged on next restart | newserv `$itemnotifs` | Yes |
| Rare sound/minimap marker | Planned/gated | Licensed/project-owned 59NL client patch | After client acceptance |
| Material/kill information | Stable profile; gameplay acceptance pending | newserv chat commands plus pinned `AccurateKillCount` 59NL auto-patch | Yes, with MIT notice |
| Solo switch assistance | Stable; default staged on next restart | newserv, player-toggleable with `$swa` | Yes |
| Early-walk, slow-Gibbles, fast-warp | Planned/gated | Reviewed MIT Blue Burst Patch Project source or project-built deltas; never its bundled modified SEGA executable | Source/delta only |
| dgVoodoo renderer profiles | Watermark-free Ultra D3D11 FL11 canary; aspect-correct 3840x2880 supersampling with 2560x1600 borderless and movable/resizable presentation; stable remains Native | Official x86 dgVoodoo | Per upstream terms |
| True 16:9/16:10 camera and HUD expansion | Not integrated; local evaluation only | Unlicensed public mod as behavior reference, or a licensed/project-owned replacement | No, pending rights |
| Same-floor shared EXP | Stable set to 0; fork/gate required | Upstream `BBEXPShareMultiplier=1` also rewards tagged players on another floor, so it does not meet the approved contract | After fork and multi-client tests |
| Server-authoritative damage synchronization | Upstream-capable canary | newserv `EnemyDamageSync` 59NL patch + required-patch gate | Only after multi-client tests |
| Reject concurrent use of one account | Planned/gated | Project fork; upstream release has no matching configuration switch | Only after multi-client tests |
| 32 slots and expanded limits | Planned/gated migration | Project fork + versioned save schema | Only after restore tests |
| Fast tekker, MAG alert, rare-sale protection | Stable profile; gameplay acceptance pending | Pinned newserv `FastTekker`, `HungryMagSound`, and `NoRareSelling` 59NL auto-patches | Yes, with MIT notice |
| 26 palette inputs | Stable profile; full input acceptance pending | Pinned newserv `Palette` 59NL auto-patch, credited upstream to licensed BBPP work | Yes, after client tests |
| XInput/pickup controls | Planned/gated client patch | Project-owned/licensed source | Only after client tests |
| Rotating 25% boosts/Purist mode | Disabled | Project configuration | After soft launch |

Ephinea and Ragol are behavior references only. Their private binaries, code,
quests, tables, branding, and assets are not copied.

## Client patch order

1. Prefer the exact-version MIT patches shipped by the pinned newserv release.
2. Build reviewed startup fixes from licensed Blue Burst Patch Project source,
   assigning one owner to every overlapping feature.
3. Keep newserv as the sole owner of `NoRareSelling` and `Palette`; do not build
   overlapping BBPP variants. Gate protocol, damage, and storage patches on
   exact client/server parity and the corresponding multi-client or restore
   tests.
4. Keep `psobb-widescreen` evaluation local because its original code has no
   explicit reuse grant. Public true-widescreen support requires permission or
   a licensed/project-owned implementation.
5. Use exactly one graphics API owner per profile. dgVoodoo, d3d8to9, DXVK,
   ReShade, and other D3D proxies are not combined implicitly.

The tracked `stable-qol` profile contains exactly `AccurateKillCount`,
`FastTekker`, `HungryMagSound`, `NoRareSelling`, and `Palette` in `AutoPatches`.
It keeps `BBRequiredPatches` empty. `DrawDistance`, `EnemyHPBars`, and
`ItemPickup` remain source-canary-only; `EnemyDamageSync`, `ServerEXPDisplay`,
and `StackLimits` remain protocol-gated; `MoreSaveSlots` remains migration-
gated. Use the empty `baseline` profile for immediate configuration rollback.
