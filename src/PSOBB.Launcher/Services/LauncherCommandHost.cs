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
                _coordinator.StartSessionAsync(
                    options.RuntimeRoot, options.Selection, options.ServerEnvironment, cancellationToken),
            LauncherOperation.StartServer =>
                _coordinator.StartServerAsync(
                    options.RuntimeRoot, options.ServerEnvironment, cancellationToken),
            LauncherOperation.StopServer =>
                _coordinator.StopServerAsync(
                    options.RuntimeRoot, options.ServerEnvironment, cancellationToken),
            LauncherOperation.StartClient =>
                _coordinator.StartClientAsync(
                    options.RuntimeRoot, options.Selection, options.ServerEnvironment, cancellationToken),
            LauncherOperation.StopClient =>
                _coordinator.StopClientAsync(
                    options.RuntimeRoot, options.ServerEnvironment, cancellationToken),
            LauncherOperation.StopAll =>
                _coordinator.StopAllAsync(
                    options.RuntimeRoot, options.ServerEnvironment, cancellationToken),
            LauncherOperation.Gui => throw new InvalidOperationException("GUI mode is not a headless lifecycle operation."),
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };
    }
}

public static class LauncherServices
{
    public static LauncherCoordinator CreateCoordinator()
    {
        var layout = new CanonicalLifecycleInstallationResolver().Resolve();
        LauncherOptions.RequireExactConfiguredRuntimeRoot(
            layout.RuntimeRoot,
            Environment.GetEnvironmentVariable("PSOBB_RUNTIME_ROOT"));
        return CreateCoordinator(layout.RuntimeRoot, layout);
    }

    public static LauncherCoordinator CreateCoordinator(string runtimeRoot)
    {
        var layout = new CanonicalLifecycleInstallationResolver().Resolve();
        LauncherOptions.RequireExactConfiguredRuntimeRoot(
            layout.RuntimeRoot,
            Environment.GetEnvironmentVariable("PSOBB_RUNTIME_ROOT"));
        return CreateCoordinator(runtimeRoot, layout);
    }

    internal static LauncherCoordinator CreateCoordinatorFromInstallationOrigin(
        string runtimeRoot,
        string installationOrigin,
        string? configuredRuntimeRoot = null)
    {
        var layout = new CanonicalLifecycleInstallationResolver()
            .ResolveFromOrigin(installationOrigin);
        LauncherOptions.RequireExactConfiguredRuntimeRoot(
            layout.RuntimeRoot,
            configuredRuntimeRoot);
        return CreateCoordinator(runtimeRoot, layout);
    }

    private static LauncherCoordinator CreateCoordinator(
        string runtimeRoot,
        CanonicalLifecycleLayout canonicalLayout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var rootGuard = new CanonicalLifecycleRepositoryGuard(canonicalLayout.RepositoryRoot);
        var requestedLayout = rootGuard.Validate(runtimeRoot);
        if (!requestedLayout.RuntimeRoot.Equals(
                canonicalLayout.RuntimeRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The requested runtime does not match the launcher's canonical nested runtime.");
        }

        var healthProbe = new LoopbackHealthProbe();
        var scriptController = new LifecycleScriptController(
            new RuntimeLifecycleObserver(
                new ExactRuntimeIdentityProbe(rootGuard),
                rootGuard),
            new PowerShellLifecycleScriptExecutor(rootGuard));
        return new LauncherCoordinator(
            new ArtifactVerifier(),
            healthProbe,
            new ProfileContractWriter(),
            new RendererProfileGuard(),
            new RuntimeProfileCompatibilityGuard(),
            scriptController);
    }
}
