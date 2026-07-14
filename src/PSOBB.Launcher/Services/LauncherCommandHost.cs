using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class LauncherCommandHost
{
    private readonly LauncherCoordinator _coordinator;

    public LauncherCommandHost(LauncherCoordinator coordinator)
    {
        _coordinator = coordinator;
    }

    public Task<LifecycleSnapshot> ExecuteAsync(
        LauncherOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.Operation switch
        {
            LauncherOperation.Play or LauncherOperation.SafePlay =>
                _coordinator.StartSessionAsync(options.RuntimeRoot, options.Selection, cancellationToken),
            LauncherOperation.StartServer =>
                _coordinator.StartServerAsync(options.RuntimeRoot, cancellationToken),
            LauncherOperation.StopServer =>
                _coordinator.StopServerAsync(options.RuntimeRoot, cancellationToken),
            LauncherOperation.StartClient =>
                _coordinator.StartClientAsync(options.RuntimeRoot, options.Selection, cancellationToken),
            LauncherOperation.StopClient =>
                _coordinator.StopClientAsync(options.RuntimeRoot, cancellationToken),
            LauncherOperation.StopAll =>
                _coordinator.StopAllAsync(options.RuntimeRoot, cancellationToken),
            LauncherOperation.Gui => throw new InvalidOperationException("GUI mode is not a headless lifecycle operation."),
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };
    }
}

public static class LauncherServices
{
    public static LauncherCoordinator CreateCoordinator()
    {
        var healthProbe = new LoopbackHealthProbe();
        var scriptController = new LifecycleScriptController(
            new RuntimeLifecycleObserver(healthProbe),
            new PowerShellLifecycleScriptExecutor());
        return new LauncherCoordinator(
            new ArtifactVerifier(),
            healthProbe,
            new ProfileContractWriter(),
            new RendererProfileGuard(),
            new RuntimeProfileCompatibilityGuard(),
            scriptController);
    }
}
