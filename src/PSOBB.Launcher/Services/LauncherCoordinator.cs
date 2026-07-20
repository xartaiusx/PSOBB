using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

internal interface ILauncherCoordinator : IAsyncDisposable
{
    IReadOnlyList<string> ServerLogLines { get; }

    Task<ReleaseVerification> VerifyAsync(
        ReleaseManifest manifest,
        string runtimeRoot,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PortHealth>> CheckHealthAsync(
        ReleaseManifest manifest,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> StartServerAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> StartClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> StartSessionAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> StopClientAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> StopServerAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> StopAllAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> RepairClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);
}

public sealed class LauncherCoordinator : ILauncherCoordinator
{
    private readonly ArtifactVerifier _artifactVerifier;
    private readonly LoopbackHealthProbe _healthProbe;
    private readonly ProfileContractWriter _profileWriter;
    private readonly RendererProfileGuard _rendererGuard;
    private readonly RuntimeProfileCompatibilityGuard _runtimeProfileGuard;
    private readonly LifecycleScriptController _lifecycle;

    public LauncherCoordinator(
        ArtifactVerifier artifactVerifier,
        LoopbackHealthProbe healthProbe,
        ProfileContractWriter profileWriter,
        RendererProfileGuard rendererGuard,
        RuntimeProfileCompatibilityGuard runtimeProfileGuard,
        LifecycleScriptController lifecycle)
    {
        _artifactVerifier = artifactVerifier;
        _healthProbe = healthProbe;
        _profileWriter = profileWriter;
        _rendererGuard = rendererGuard;
        _runtimeProfileGuard = runtimeProfileGuard;
        _lifecycle = lifecycle;
    }

    public IReadOnlyList<string> ServerLogLines => _lifecycle.LogTail;

    public Task<ReleaseVerification> VerifyAsync(
        ReleaseManifest manifest,
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        _artifactVerifier.VerifyAsync(manifest, runtimeRoot, cancellationToken);

    public Task<IReadOnlyList<PortHealth>> CheckHealthAsync(
        ReleaseManifest manifest,
        CancellationToken cancellationToken = default) =>
        _healthProbe.ProbeAsync(manifest.Launch.HealthPorts, TimeSpan.FromSeconds(1), cancellationToken);

    public Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        ObserveAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default) =>
        _lifecycle.ObserveAsync(runtimeRoot, serverEnvironment, cancellationToken);

    public Task<LifecycleSnapshot> StartServerAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StartServerAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> StartServerAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default) =>
        _lifecycle.StartServerAsync(runtimeRoot, serverEnvironment, cancellationToken);

    public Task<LifecycleSnapshot> StartClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default) =>
        StartClientAsync(runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StartClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        await PrepareSelectionAsync(
            runtimeRoot, selection, serverEnvironment, cancellationToken).ConfigureAwait(false);
        return await _lifecycle.StartClientAsync(
            runtimeRoot, selection, serverEnvironment, cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> StartSessionAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default) =>
        StartSessionAsync(runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StartSessionAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        await PrepareSelectionAsync(
            runtimeRoot, selection, serverEnvironment, cancellationToken).ConfigureAwait(false);
        return await _lifecycle.PlayAsync(
            runtimeRoot, selection, serverEnvironment, cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> StopClientAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StopClientAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> StopClientAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default) =>
        _lifecycle.StopClientAsync(runtimeRoot, serverEnvironment, cancellationToken);

    public Task<LifecycleSnapshot> StopServerAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StopServerAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> StopServerAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default) =>
        _lifecycle.StopServerAsync(runtimeRoot, serverEnvironment, cancellationToken);

    public Task<LifecycleSnapshot> StopAllAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StopAllAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> StopAllAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default) =>
        _lifecycle.StopAllAsync(runtimeRoot, serverEnvironment, cancellationToken);

    public Task<LifecycleSnapshot> RepairClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default) =>
        RepairClientAsync(runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> RepairClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        if (serverEnvironment == ServerEnvironmentKind.CombatCanary)
        {
            throw new NotSupportedException(
                "CombatCanary client repair is owned by its sealed initialization and reset workflow.");
        }

        var state = await _lifecycle.RepairClientAsync(
            runtimeRoot, selection, serverEnvironment, cancellationToken).ConfigureAwait(false);
        await _runtimeProfileGuard.ValidateAsync(runtimeRoot, selection, cancellationToken).ConfigureAwait(false);
        await WriteSelectionAsync(runtimeRoot, selection, cancellationToken).ConfigureAwait(false);
        return state;
    }

    // Retained for manifest-bound callers. Process ownership is still delegated
    // to the lifecycle scripts after all release and renderer checks pass.
    public async Task<LaunchResult> StartLocalAsync(
        ReleaseManifest manifest,
        string runtimeRoot,
        LaunchProfile profile,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Channel != manifest.Channel)
        {
            throw new InvalidOperationException(
                $"The selected {profile.Channel} channel does not match manifest channel {manifest.Channel}.");
        }

        var verification = await VerifyAsync(manifest, runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (!verification.IsSuccess)
        {
            throw new LaunchVerificationException(verification);
        }

        var normalized = LaunchProfile.Create(profile.Channel, profile.Renderer, profile.Display, profile.SafeMode);
        _rendererGuard.Validate(manifest, runtimeRoot, normalized);
        var graphics = normalized.SafeMode
            ? GraphicsProfileOption.SafeNative
            : normalized.Renderer.Kind switch
            {
                RendererKind.DgVoodooD3D11 => GraphicsProfileOption.ClarityDgVoodoo,
                RendererKind.DxvkVulkan => GraphicsProfileOption.Supported.Single(option => option.Id == "dxvk-canary"),
                RendererKind.D3d8To9 => GraphicsProfileOption.Supported.Single(option => option.Id == "d3d8to9-canary"),
                _ => throw new NotSupportedException(
                    $"Renderer {normalized.Renderer.Kind} has no script-managed graphics profile."),
            };
        var selection = LifecycleSelection.Create(
            normalized.Channel,
            graphics,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.ProfileDefault);
        var state = await StartSessionAsync(
            runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken).ConfigureAwait(false);
        var health = await CheckHealthAsync(manifest, cancellationToken).ConfigureAwait(false);
        if (!state.ClientRunning || health.Count == 0 || health.Any(port => !port.IsHealthy))
        {
            throw new InvalidOperationException("The script-managed local session did not reach a healthy running state.");
        }

        return new(verification, health, normalized);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private Task<string> WriteSelectionAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken) =>
        _profileWriter.WriteAsync(
            runtimeRoot,
            selection.ToLaunchProfile(),
            selection,
            cancellationToken);

    private async Task PrepareSelectionAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selection);
        if (serverEnvironment == ServerEnvironmentKind.CombatCanary)
        {
            if (selection.Channel != ReleaseChannel.Stable
                || selection.Profile != GraphicsProfileOption.SafeNative
                || selection.WindowMode != LauncherWindowMode.ProfileDefault)
            {
                throw new InvalidOperationException(
                    "CombatCanary uses only its sealed Native client with profile-default presentation.");
            }

            return;
        }

        if (serverEnvironment != ServerEnvironmentKind.Stable)
        {
            throw new ArgumentOutOfRangeException(nameof(serverEnvironment));
        }

        await _runtimeProfileGuard.ValidateAsync(runtimeRoot, selection, cancellationToken).ConfigureAwait(false);
        await WriteSelectionAsync(runtimeRoot, selection, cancellationToken).ConfigureAwait(false);
    }
}

public sealed record LaunchResult(
    ReleaseVerification Verification,
    IReadOnlyList<PortHealth> Health,
    LaunchProfile Profile);

public sealed class LaunchVerificationException(ReleaseVerification verification)
    : InvalidOperationException("Launch was blocked because one or more runtime files failed verification.")
{
    public ReleaseVerification Verification { get; } = verification;
}
