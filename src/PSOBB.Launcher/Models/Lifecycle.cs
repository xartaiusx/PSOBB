namespace PSOBB.Launcher.Models;

public enum LauncherLifecycleState
{
    Stopped,
    ServerStarting,
    ServerReady,
    ClientStarting,
    Running,
    Stopping,
    Faulted,
}

public enum LauncherWindowMode
{
    ProfileDefault,
    Borderless,
    Resizable,
}

public sealed record GraphicsProfileOption(
    string Id,
    string DisplayName,
    ReleaseChannel Channel,
    RendererKind Renderer,
    bool SafeMode)
{
    public static GraphicsProfileOption SafeNative { get; } =
        new("safe-native-4x3", "Safe native 4:3", ReleaseChannel.Stable, RendererKind.NativeSafe, true);

    public static GraphicsProfileOption ClarityDgVoodoo { get; } =
        new("clarity-dgvoodoo-4x3", "dgVoodoo clarity 4:3", ReleaseChannel.Canary, RendererKind.DgVoodooD3D11, false);

    public static GraphicsProfileOption LocalLabWidescreen { get; } =
        new("lab-widescreen-16x10", "Local-lab widescreen 16:10", ReleaseChannel.LocalLab, RendererKind.DgVoodooD3D11, false);

    public static GraphicsProfileOption LocalLabWidescreenHd { get; } =
        new("lab-widescreen-hd-16x10", "Local-lab widescreen 16:10 + private HD assets", ReleaseChannel.LocalLab, RendererKind.DgVoodooD3D11, false);

    public static IReadOnlyList<GraphicsProfileOption> Supported { get; } =
    [
        SafeNative,
        ClarityDgVoodoo,
        LocalLabWidescreen,
        LocalLabWidescreenHd,
        new("fidelity-modern-16x10", "Modern fidelity 16:10", ReleaseChannel.Canary, RendererKind.DgVoodooD3D11, false),
        new("dxvk-canary", "DXVK canary", ReleaseChannel.LocalLab, RendererKind.DxvkVulkan, false),
        new("d3d8to9-canary", "d3d8to9 canary", ReleaseChannel.LocalLab, RendererKind.D3d8To9, false),
    ];

    public override string ToString() => DisplayName;
}

public sealed record MonitorOption(string Id, string DisplayName)
{
    public static MonitorOption PrimaryPhysical { get; } =
        new("primary-physical", "Primary physical display (2560 x 1600)");

    // Virtual displays are intentionally not launch targets. They remain visible
    // to Windows but cannot accidentally replace the physical acceptance panel.
    public static IReadOnlyList<MonitorOption> Supported { get; } = [PrimaryPhysical];

    public override string ToString() => DisplayName;
}

public sealed record LifecycleSelection(
    ReleaseChannel Channel,
    GraphicsProfileOption Profile,
    MonitorOption Monitor,
    LauncherWindowMode WindowMode,
    bool PreserveForeground = false)
{
    public static LifecycleSelection Create(
        ReleaseChannel channel,
        GraphicsProfileOption profile,
        MonitorOption monitor,
        LauncherWindowMode windowMode,
        bool preserveForeground = false)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(monitor);

        if (profile.Channel != channel)
        {
            throw new InvalidOperationException(
                $"Graphics profile '{profile.Id}' requires the {profile.Channel} channel, not {channel}.");
        }

        if (!GraphicsProfileOption.Supported.Contains(profile))
        {
            throw new InvalidOperationException($"Graphics profile '{profile.Id}' is not supported by this launcher.");
        }

        if (!MonitorOption.Supported.Contains(monitor))
        {
            throw new InvalidOperationException($"Monitor target '{monitor.Id}' is not supported by this launcher.");
        }

        return new(channel, profile, monitor, windowMode, preserveForeground);
    }

    public LaunchProfile ToLaunchProfile()
    {
        var renderer = RendererProfile.Supported.Single(candidate => candidate.Kind == Profile.Renderer);
        var display = Profile.SafeMode ? DisplayProfile.Safe : DisplayProfile.Primary;
        return LaunchProfile.Create(Channel, renderer, display, Profile.SafeMode);
    }
}

public sealed record LifecycleSnapshot(
    LauncherLifecycleState State,
    bool ServerRunning,
    bool ClientRunning,
    string Detail);
