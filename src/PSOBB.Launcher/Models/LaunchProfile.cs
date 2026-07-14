namespace PSOBB.Launcher.Models;

public enum RendererKind
{
    NativeSafe,
    DgVoodooD3D11,
    DgVoodooD3D12,
    DxvkVulkan,
    D3d8To9,
}

public sealed record RendererProfile(RendererKind Kind, string DisplayName)
{
    public static IReadOnlyList<RendererProfile> Supported { get; } =
    [
        new(RendererKind.NativeSafe, "Native safe mode"),
        new(RendererKind.DgVoodooD3D11, "dgVoodoo2 D3D11 (default)"),
        new(RendererKind.DgVoodooD3D12, "dgVoodoo2 D3D12 (canary)"),
        new(RendererKind.DxvkVulkan, "DXVK / Vulkan (canary)"),
        new(RendererKind.D3d8To9, "d3d8to9 (canary)"),
    ];

    public override string ToString() => DisplayName;
}

public sealed record DisplayProfile(string Id, string DisplayName, int Width, int Height, decimal HudScale)
{
    public static DisplayProfile Primary { get; } = new("primary-16x10", "2560 x 1600 (16:10)", 2560, 1600, 1.25m);

    public static DisplayProfile Compatibility { get; } = new("compatibility-16x9", "1920 x 1080 (16:9)", 1920, 1080, 1.00m);

    public static DisplayProfile Safe { get; } = new("safe-4x3", "1024 x 768 (safe)", 1024, 768, 1.00m);

    public static IReadOnlyList<DisplayProfile> Supported { get; } = [Primary, Compatibility, Safe];

    public override string ToString() => DisplayName;
}

public sealed record LaunchProfile(
    ReleaseChannel Channel,
    RendererProfile Renderer,
    DisplayProfile Display,
    bool SafeMode)
{
    public static LaunchProfile Create(
        ReleaseChannel channel,
        RendererProfile renderer,
        DisplayProfile display,
        bool safeMode)
    {
        ArgumentNullException.ThrowIfNull(renderer);
        ArgumentNullException.ThrowIfNull(display);

        if (!safeMode)
        {
            return new(channel, renderer, display, false);
        }

        return new(
            channel,
            RendererProfile.Supported.Single(profile => profile.Kind == RendererKind.NativeSafe),
            DisplayProfile.Safe,
            true);
    }
}
