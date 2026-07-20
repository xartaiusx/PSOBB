using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;
using PSOBB.Launcher.ViewModels;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class MainWindowViewModelTests
{
    [TestMethod]
    public async Task Constructor_UsesPreserveForegroundSelection()
    {
        var defaults = LauncherOptions.Defaults();
        var options = defaults with
        {
            Selection = defaults.Selection with { PreserveForeground = true },
        };
        await using var viewModel = new MainWindowViewModel(options);

        Assert.IsTrue(viewModel.PreserveForeground);
    }

    [TestMethod]
    public async Task SelectedServerEnvironment_CombatCanaryLocksSealedNativeSelection()
    {
        await using var viewModel = new MainWindowViewModel(LauncherOptions.Defaults());
        viewModel.SelectedChannel = ReleaseChannel.Canary;
        viewModel.SelectedWindowMode = LauncherWindowMode.Borderless;
        viewModel.PreserveForeground = true;

        viewModel.SelectedServerEnvironment = ServerEnvironmentKind.CombatCanary;
        viewModel.SelectedChannel = ReleaseChannel.LocalLab;
        viewModel.SelectedGraphicsProfile = GraphicsProfileOption.ClarityDgVoodoo;
        viewModel.SelectedWindowMode = LauncherWindowMode.Borderless;
        viewModel.SafeMode = false;

        Assert.AreEqual(ServerEnvironmentKind.CombatCanary, viewModel.SelectedServerEnvironment);
        Assert.AreEqual(ReleaseChannel.Stable, viewModel.SelectedChannel);
        Assert.AreSame(GraphicsProfileOption.SafeNative, viewModel.SelectedGraphicsProfile);
        Assert.AreEqual(LauncherWindowMode.ProfileDefault, viewModel.SelectedWindowMode);
        Assert.IsFalse(viewModel.StableGraphicsSelectionEnabled);
        Assert.IsTrue(viewModel.PreserveForeground);
        Assert.AreEqual(LauncherLifecycleState.Unknown, viewModel.LifecycleState);
        StringAssert.Contains(viewModel.Status, "refresh is required");
    }

    [TestMethod]
    [DataRow(ReleaseChannel.Canary)]
    [DataRow(ReleaseChannel.LocalLab)]
    public async Task ApplyLoadedManifest_CombatCanaryPreservesSealedNativeSelection(
        ReleaseChannel manifestChannel)
    {
        await using var viewModel = new MainWindowViewModel(LauncherOptions.Defaults());
        viewModel.SelectedServerEnvironment = ServerEnvironmentKind.CombatCanary;

        viewModel.ApplyLoadedManifest(new(
            new ReleaseManifest
            {
                SchemaVersion = 1,
                ReleaseId = "selection-test",
                Channel = manifestChannel,
                ProtocolRevision = 1,
            },
            ManifestTrustMode.UnsignedLocalDevelopment));

        Assert.AreEqual(ReleaseChannel.Stable, viewModel.SelectedChannel);
        Assert.AreSame(GraphicsProfileOption.SafeNative, viewModel.SelectedGraphicsProfile);
        Assert.AreEqual(LauncherWindowMode.ProfileDefault, viewModel.SelectedWindowMode);
        Assert.IsTrue(viewModel.SafeMode);
    }

    [TestMethod]
    public async Task InitializeAsync_DiscardsStaleObservationAfterEnvironmentSwitch()
    {
        var coordinator = new DelayedCoordinator();
        var loader = new LauncherManifestLoader(
            new ReleaseManifestService(),
            allowUnsignedLocalDevelopment: true);
        await using var viewModel = new MainWindowViewModel(
            LauncherOptions.Defaults(), loader, coordinator);

        var pending = viewModel.InitializeAsync();
        await coordinator.ObserveStarted.Task;
        viewModel.SelectedServerEnvironment = ServerEnvironmentKind.CombatCanary;
        coordinator.Observation.SetResult(new(
            LauncherLifecycleState.Running,
            ServerRunning: true,
            ClientRunning: true,
            "Stale Stable completion",
            IdentityAuthenticated: true));
        await pending;

        Assert.AreEqual(LauncherLifecycleState.Unknown, viewModel.LifecycleState);
        StringAssert.Contains(viewModel.Status, "refresh is required");
        Assert.DoesNotContain("Stale Stable completion", viewModel.Status, StringComparison.Ordinal);
    }

    private sealed class DelayedCoordinator : ILauncherCoordinator
    {
        public TaskCompletionSource ObserveStarted { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<LifecycleSnapshot> Observation { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public IReadOnlyList<string> ServerLogLines => [];

        public Task<LifecycleSnapshot> ObserveAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default)
        {
            ObserveStarted.TrySetResult();
            return Observation.Task.WaitAsync(cancellationToken);
        }

        public Task<ReleaseVerification> VerifyAsync(
            ReleaseManifest manifest,
            string runtimeRoot,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<PortHealth>> CheckHealthAsync(
            ReleaseManifest manifest,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> StartServerAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> StartClientAsync(
            string runtimeRoot,
            LifecycleSelection selection,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> StartSessionAsync(
            string runtimeRoot,
            LifecycleSelection selection,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> StopClientAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> StopServerAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> StopAllAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<LifecycleSnapshot> RepairClientAsync(
            string runtimeRoot,
            LifecycleSelection selection,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
