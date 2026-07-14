// SPDX-License-Identifier: MIT
//
// PSOBB neutral contrast-adaptive sharpening for ReShade.
// The cross-neighborhood limiter is derived from AMD FidelityFX CAS, which is
// available under the MIT License. See THIRD-PARTY-NOTICES.md.

// Keep this effect self-contained. ReShade exposes the final color buffer via
// the COLOR semantic and supplies reciprocal backbuffer dimensions.
texture2D PSOBB_BackBufferTex : COLOR;
sampler2D PSOBB_BackBuffer
{
    Texture = PSOBB_BackBufferTex;
};

void PSOBB_FullscreenVS(
    in uint id : SV_VertexID,
    out float4 position : SV_Position,
    out float2 texcoord : TEXCOORD)
{
    texcoord.x = (id == 2) ? 2.0 : 0.0;
    texcoord.y = (id == 1) ? 2.0 : 0.0;
    position = float4(
        texcoord * float2(2.0, -2.0) + float2(-1.0, 1.0),
        0.0,
        1.0);
}

uniform float PSOBB_CAS_Strength <
    ui_type = "slider";
    ui_label = "PSOBB CAS strength";
    ui_tooltip = "Use only the accepted 0.15, 0.25, or 0.35 test values.";
    ui_min = 0.0;
    ui_max = 0.35;
    ui_step = 0.05;
> = 0.15;

float4 PSOBB_NeutralCAS_PS(float4 position : SV_Position, float2 texcoord : TEXCOORD) : SV_Target
{
    const float2 pixel = float2(BUFFER_RCP_WIDTH, BUFFER_RCP_HEIGHT);
    const float4 centerSample = tex2D(PSOBB_BackBuffer, texcoord);
    const float3 center = centerSample.rgb;
    const float3 north = tex2D(PSOBB_BackBuffer, texcoord + float2(0.0, -pixel.y)).rgb;
    const float3 west = tex2D(PSOBB_BackBuffer, texcoord + float2(-pixel.x, 0.0)).rgb;
    const float3 east = tex2D(PSOBB_BackBuffer, texcoord + float2(pixel.x, 0.0)).rgb;
    const float3 south = tex2D(PSOBB_BackBuffer, texcoord + float2(0.0, pixel.y)).rgb;

    const float3 minimumColor = min(center, min(min(north, south), min(west, east)));
    const float3 maximumColor = max(center, max(max(north, south), max(west, east)));
    const float3 availableHeadroom = saturate(
        min(minimumColor, 1.0 - maximumColor) / max(maximumColor, 1.0e-4));
    const float3 adaptiveAmplitude = sqrt(availableHeadroom);

    // Build the full, conservative CAS result and blend toward it. A strength
    // of zero is a byte-for-byte color pass-through apart from shader rounding.
    const float3 neighborWeight = adaptiveAmplitude * (-1.0 / 8.0);
    const float3 denominator = max(1.0 + (4.0 * neighborWeight), 1.0e-4);
    const float3 sharpened = (
        center + (neighborWeight * (north + west + east + south))) / denominator;
    const float blendAmount = saturate(PSOBB_CAS_Strength / 0.35);

    return float4(saturate(lerp(center, sharpened, blendAmount)), centerSample.a);
}

technique PSOBB_NeutralCAS
{
    pass
    {
        VertexShader = PSOBB_FullscreenVS;
        PixelShader = PSOBB_NeutralCAS_PS;
    }
}
