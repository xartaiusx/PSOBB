# PSOBB neutral CAS

This directory contains source and a conservative candidate preset only. It
does not include or redistribute ReShade binaries or the upstream shader
bundle. The preset is not approved for the playable runtime until the graphics
evidence matrix records passing screenshot, halo, frame-pacing, soak, rollback,
and manual A/B results.

Project-authored files in this directory use the adjacent MIT license. AMD CAS
attribution and its required MIT notice are in `THIRD-PARTY-NOTICES.md`.

The only accepted evaluation values are `0.15`, `0.25`, and `0.35`. The weakest
passing value wins. If all three create visible halos, clipping, HUD damage, or
an unacceptable performance regression, sharpening remains disabled.

The shader consumes ReShade's final SDR backbuffer. It must not be combined
with bloom, ambient occlusion, depth of field, film grain, chromatic
aberration, HDR conversion, tone mapping, or color grading in the default
profile.

The effect is self-contained and does not require an external `ReShade.fxh` or
shader bundle. Runtime materialization must include only this effect and a
generated single-technique preset.
