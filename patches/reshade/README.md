# Neutral CAS Candidate

A self-contained sharpening shader and conservative candidate preset for PSOBB. ReShade binaries and upstream shader bundles are not included.

The preset remains unapproved for normal play until [graphics acceptance](../../docs/GRAPHICS-ACCEPTANCE.md) records passing screenshot, halo, frame-pacing, soak, rollback, and manual A/B checks.

## Evaluation limits

Test only `0.15`, `0.25`, and `0.35`; choose the weakest passing value. Leave sharpening disabled if all three produce halos, clipping, HUD damage, or unacceptable performance loss.

The shader uses the final SDR backbuffer. The default profile must not combine it with bloom, ambient occlusion, depth of field, film grain, chromatic aberration, HDR conversion, tone mapping, or color grading.

Include only this effect and a generated single-technique preset when staging a candidate. It does not need `ReShade.fxh` or an external shader bundle.

## License

Project-authored files use the adjacent [MIT license](LICENSE.md). Preserve the AMD CAS attribution and required MIT notice in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
