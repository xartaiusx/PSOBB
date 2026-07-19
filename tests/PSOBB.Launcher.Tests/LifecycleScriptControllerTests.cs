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
    public void RuntimeObserver_UsesProtectedControlDirectory()
    {
        using var runtime = new TestRuntime();

        var paths = RuntimeLifecycleObserver.GetLifecycleFilePaths(runtime.Root);

        Assert.AreEqual(
            Path.Combine(runtime.Root, "stable", "control", "newserv-control.json"),
            paths.ControlStatePath);
        Assert.AreEqual(
            Path.Combine(runtime.Root, "stable", "control", "newserv.process.json"),
            paths.ProcessRecordPath);
    }

    [TestMethod]
    public void ScriptLocator_FindsRepositoryScriptsAboveNestedPackagedLauncher()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var packagedLauncher = Directory.CreateDirectory(Path.Combine(
            repository.Root,
            "PSOBB-Runtime",
            "stable",
            "launcher"));

        var resolved = LifecycleScriptLocator.Resolve(
            requestedRoot: null,
            configuredRoot: null,
            origins: [packagedLauncher.FullName]);

        Assert.AreEqual(scripts.FullName, resolved);
    }

    [TestMethod]
    public void ScriptExecutor_ReportsPowerShellMessageInsteadOfAnsiLocationHeader()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var executor = new PowerShellLifecycleScriptExecutor(scripts.FullName);
        const string stderr =
            "\u001b[31;1mException: \u001b[0mC:\\repo\\scripts\\Start-PSOBB.ps1:552\u001b[0m\r\n" +
            "\u001b[36;1mLine |\u001b[0m\r\n" +
            "\u001b[36;1m 552 | \u001b[0m $observedHostPath = ...\r\n" +
            "\u001b[36;1m     | \u001b[31;1m ~~~~~~~~~~~~~~~~~~~~~~~~~\u001b[0m\r\n" +
            "\u001b[36;1m     | \u001b[31;1mException calling \"GetFullPath\": The path is empty.\u001b[0m\r\n";

        var detail = executor.FirstMeaningfulLine(stderr);

        Assert.AreEqual("Exception calling \"GetFullPath\": The path is empty.", detail);
    }

    [TestMethod]
    public void ScriptExecutor_PreservesLegitimatePipeInDiagnosticMessage()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var executor = new PowerShellLifecycleScriptExecutor(scripts.FullName);

        var detail = executor.FirstMeaningfulLine("Failure in stage A | stage B did not start");

        Assert.AreEqual("Failure in stage A | stage B did not start", detail);
    }

    [TestMethod]
    public void ScriptExecutor_PreservesLegitimateNumericPipePrefix()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var executor = new PowerShellLifecycleScriptExecutor(scripts.FullName);

        var detail = executor.FirstMeaningfulLine("12000 | listener failed");

        Assert.AreEqual("12000 | listener failed", detail);
    }

    [TestMethod]
    public void ScriptExecutor_NormalizesControlsAndSecretsForDetailAndLog()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var executor = new PowerShellLifecycleScriptExecutor(scripts.FullName);
        const string raw =
            "\u001b[31mFailure password=super-secret\u001b[0m " +
            "\u001b]8;;https://example.invalid\u001b\\link\u001b]8;;\u001b\\\u0001";

        var detail = executor.FirstMeaningfulLine(raw);
        executor.AddLog(raw);

        Assert.AreEqual("Failure password=[REDACTED] link", detail);
        Assert.HasCount(1, executor.LogTail);
        Assert.AreEqual(detail, executor.LogTail[0]);
        Assert.IsFalse(detail!.Any(char.IsControl));
        Assert.DoesNotContain("super-secret", detail!, StringComparison.Ordinal);
        Assert.DoesNotContain("example.invalid", detail!, StringComparison.Ordinal);
    }

    [TestMethod]
    public void ScriptExecutor_RedactsQuotedJsonSecretsWithoutTruncatingPipeText()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var executor = new PowerShellLifecycleScriptExecutor(scripts.FullName);
        const string raw = "{\"password\":\"super-secret\",\"token\":\"abc123\"} 12000 | listener failed";

        var detail = executor.FirstMeaningfulLine(raw);
        executor.AddLog(raw);

        Assert.AreEqual(
            "{\"password\":\"[REDACTED]\",\"token\":\"[REDACTED]\"} 12000 | listener failed",
            detail);
        Assert.HasCount(1, executor.LogTail);
        Assert.AreEqual(detail, executor.LogTail[0]);
        Assert.DoesNotContain("super-secret", detail!, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", detail!, StringComparison.Ordinal);
    }

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
