using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LifecycleScriptControllerTests
{
    private static readonly string[] StartSequence = ["Start-PSOBBSession.ps1"];
    private static readonly string[] StopSequence = ["Stop-PSOBBSession.ps1"];

    [TestMethod]
    public async Task PlayAsync_UsesServerThenClientScripts()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBBSession.ps1" ? Running() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        var result = await controller.PlayAsync(runtime.Root, CanarySelection());

        Assert.AreEqual(LauncherLifecycleState.Running, result.State);
        CollectionAssert.AreEqual(
            StartSequence,
            executor.Calls.Select(call => call.Script).ToArray());
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "Canary");
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "Borderless");
        Assert.IsFalse(executor.Calls.SelectMany(call => call.Arguments).Any(argument =>
            argument.Contains("password", StringComparison.OrdinalIgnoreCase)
            || argument.Contains("username", StringComparison.OrdinalIgnoreCase)));
        CollectionAssert.DoesNotContain(executor.Calls[0].Arguments.ToArray(), "-PreserveForeground");
    }

    [TestMethod]
    public async Task PlayAsync_ForwardsPreserveForegroundToSessionScript()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBBSession.ps1" ? Running() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);
        var selection = CanarySelection() with { PreserveForeground = true };

        await controller.PlayAsync(runtime.Root, selection);

        Assert.HasCount(1, executor.Calls);
        Assert.AreEqual("Start-PSOBBSession.ps1", executor.Calls[0].Script);
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "-PreserveForeground");
    }

    [TestMethod]
    public async Task StartClientAsync_ForwardsPreserveForegroundToClientScript()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(ServerReady());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBBClient.ps1" ? Running() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);
        var selection = CanarySelection() with { PreserveForeground = true };

        await controller.StartClientAsync(runtime.Root, selection);

        Assert.HasCount(1, executor.Calls);
        Assert.AreEqual("Start-PSOBBClient.ps1", executor.Calls[0].Script);
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "-PreserveForeground");
    }

    [TestMethod]
    public async Task StopAllAsync_StopsClientBeforeServer()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Running());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Stop-PSOBBSession.ps1" ? Stopped() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        var result = await controller.StopAllAsync(runtime.Root);

        Assert.AreEqual(LauncherLifecycleState.Stopped, result.State);
        CollectionAssert.AreEqual(
            StopSequence,
            executor.Calls.Select(call => call.Script).ToArray());
    }

    [TestMethod]
    public async Task StopServerAsync_RefusesWhileClientIsRunning()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Running());
        var executor = new RecordingExecutor((_, _) => { });
        var controller = new LifecycleScriptController(observer, executor);

        var exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => controller.StopServerAsync(runtime.Root));

        StringAssert.Contains(exception.Message, "Stop the client first");
        Assert.IsEmpty(executor.Calls);
    }

    [TestMethod]
    public async Task RepairClientAsync_RejectsUnmaterializedProfile()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((_, _) => { });
        var controller = new LifecycleScriptController(observer, executor);
        var modern = LifecycleSelection.Create(
            ReleaseChannel.Canary,
            GraphicsProfileOption.Supported.Single(profile => profile.Id == "fidelity-modern-16x10"),
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        var exception = await Assert.ThrowsExactlyAsync<NotSupportedException>(
            () => controller.RepairClientAsync(runtime.Root, modern));

        StringAssert.Contains(exception.Message, "signed overlay");
        Assert.IsEmpty(executor.Calls);
    }

    [TestMethod]
    public async Task RepairClientAsync_UsesLocalLabMaterializerForWidescreen()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((_, _) => { });
        var controller = new LifecycleScriptController(observer, executor);
        var selection = LifecycleSelection.Create(
            ReleaseChannel.LocalLab,
            GraphicsProfileOption.LocalLabWidescreen,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        await controller.RepairClientAsync(runtime.Root, selection);

        Assert.HasCount(1, executor.Calls);
        Assert.AreEqual("New-PSOBBGraphicsLabRuntime.ps1", executor.Calls[0].Script);
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "lab-widescreen-16x10");
    }

    [TestMethod]
    public async Task RepairClientAsync_VerifiesPrivateHdActivationWithoutRematerializing()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((_, _) => { });
        var controller = new LifecycleScriptController(observer, executor);
        var selection = LifecycleSelection.Create(
            ReleaseChannel.LocalLab,
            GraphicsProfileOption.LocalLabWidescreenHd,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        await controller.RepairClientAsync(runtime.Root, selection);

        Assert.HasCount(1, executor.Calls);
        Assert.AreEqual("Set-PSOBBAshenbubsHDClientActivation.ps1", executor.Calls[0].Script);
        var arguments = executor.Calls[0].Arguments.ToArray();
        CollectionAssert.Contains(arguments, "-Action");
        CollectionAssert.Contains(arguments, "Verify");
        CollectionAssert.DoesNotContain(arguments, "Activate");
        CollectionAssert.DoesNotContain(arguments, "New-PSOBBGraphicsLabRuntime.ps1");
    }

    private static LifecycleSelection CanarySelection() => LifecycleSelection.Create(
        ReleaseChannel.Canary,
        GraphicsProfileOption.ClarityDgVoodoo,
        MonitorOption.PrimaryPhysical,
        LauncherWindowMode.Borderless);

    private static LifecycleSnapshot Stopped() =>
        new(LauncherLifecycleState.Stopped, false, false, "Stopped");

    private static LifecycleSnapshot ServerReady() =>
        new(LauncherLifecycleState.ServerReady, true, false, "Ready");

    private static LifecycleSnapshot Running() =>
        new(LauncherLifecycleState.Running, true, true, "Running");

    private sealed class MutableObserver(LifecycleSnapshot initial) : ILifecycleStateObserver
    {
        public LifecycleSnapshot Current { get; set; } = initial;

        public Task<LifecycleSnapshot> ObserveAsync(string runtimeRoot, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Current);
        }
    }

    private sealed class RecordingExecutor(Action<string, IReadOnlyList<string>> onExecute) : ILifecycleScriptExecutor
    {
        public List<ScriptCall> Calls { get; } = [];

        public IReadOnlyList<string> LogTail => [];

        public Task ExecuteAsync(
            string scriptName,
            string runtimeRoot,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add(new(scriptName, arguments));
            onExecute(scriptName, arguments);
            return Task.CompletedTask;
        }
    }

    private sealed record ScriptCall(string Script, IReadOnlyList<string> Arguments);
}
