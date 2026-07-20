using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LifecycleScriptControllerTests
{
    private static readonly string[] StartSequence = ["Start-PSOBBSession.ps1"];
    private static readonly string[] StopSequence = ["Stop-PSOBBSession.ps1"];
    private static readonly Regex ScriptDependency = new(
        "Join-Path\\s+\\$PSScriptRoot\\s+['\"](?<name>[A-Za-z0-9._-]+\\.ps1)['\"]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ScriptLiteralToken = new(
        "(?<![A-Za-z0-9._-])(?<literal>(?:[A-Za-z0-9._-]+[\\\\/])*[A-Za-z0-9._-]+\\.ps1)(?![A-Za-z0-9._-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex RepositoryParentJoin = new(
        "Join-Path\\s+\\$PSScriptRoot\\s+['\"]\\.\\.['\"]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex RepositoryParentSplit = new(
        "Split-Path\\s+-Parent\\s+\\$PSScriptRoot\\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    [TestMethod]
    public void RuntimeObserver_UsesProtectedControlDirectory()
    {
        using var runtime = new TestRuntime();

        var paths = RuntimeLifecycleObserver.GetLifecycleFilePaths(
            runtime.Root, ServerEnvironmentKind.Stable);

        Assert.AreEqual(
            Path.Combine(runtime.Root, "stable", "control", "newserv-control.json"),
            paths.ControlStatePath);
        Assert.AreEqual(
            Path.Combine(runtime.Root, "stable", "control", "newserv.process.json"),
            paths.ProcessRecordPath);
    }

    [TestMethod]
    public void RuntimeObserver_UsesDisjointCombatCanaryControlAndClientPaths()
    {
        using var runtime = new TestRuntime();

        var stableControl = RuntimeLifecycleObserver.GetLifecycleFilePaths(
            runtime.Root, ServerEnvironmentKind.Stable);
        var combatControl = RuntimeLifecycleObserver.GetLifecycleFilePaths(
            runtime.Root, ServerEnvironmentKind.CombatCanary);
        var stableClients = RuntimeLifecycleObserver.GetApprovedClientPaths(
            runtime.Root, ServerEnvironmentKind.Stable);
        var combatClients = RuntimeLifecycleObserver.GetApprovedClientPaths(
            runtime.Root, ServerEnvironmentKind.CombatCanary);

        Assert.AreEqual(
            Path.Combine(runtime.Root, "combat-canary", "control", "newserv-control.json"),
            combatControl.ControlStatePath);
        Assert.AreEqual(
            Path.Combine(runtime.Root, "combat-canary", "control", "newserv.process.json"),
            combatControl.ProcessRecordPath);
        Assert.AreNotEqual(stableControl.ControlStatePath, combatControl.ControlStatePath);
        Assert.HasCount(3, stableClients);
        Assert.HasCount(1, combatClients);
        Assert.IsFalse(stableClients.Intersect(combatClients, StringComparer.OrdinalIgnoreCase).Any());
        CollectionAssert.Contains(
            combatClients.ToArray(),
            Path.Combine(runtime.Root, "combat-canary", "runtime", "client", "Psobb.exe"));
    }

    [TestMethod]
    public void CanonicalRootGuard_AcceptsOnlyCompleteNestedRuntimeLayout()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var layout = new CanonicalLifecycleRepositoryGuard().Validate(canonical.RuntimeRoot);

        Assert.AreEqual(canonical.Repository.Root, layout.RepositoryRoot);
        Assert.AreEqual(canonical.RuntimeRoot, layout.RuntimeRoot);
        Assert.HasCount(CanonicalLifecycleRepositoryGuard.ScriptInventory.Count, layout.ScriptPaths);

        var nonCanonicalRuntime = Directory.CreateDirectory(
            Path.Combine(canonical.Repository.Root, "runtime")).FullName;
        Assert.ThrowsExactly<InvalidDataException>(
            () => new CanonicalLifecycleRepositoryGuard().Validate(nonCanonicalRuntime));
    }

    [TestMethod]
    public void CanonicalRootGuard_InventoryMatchesSourceDerivedTransitiveClosure()
    {
        var repositoryRoot = GetSourceRepositoryRoot();
        var (closure, _) = DiscoverSourceScriptGraph(repositoryRoot);

        CollectionAssert.AreEquivalent(
            closure.OrderBy(name => name, StringComparer.Ordinal).ToArray(),
            CanonicalLifecycleRepositoryGuard.ScriptInventory.ToArray());
    }

    [TestMethod]
    public void CanonicalRootGuard_RejectsEverySourceDerivedDependencyReparsePoint()
    {
        var repositoryRoot = GetSourceRepositoryRoot();
        var (_, dependencies) = DiscoverSourceScriptGraph(repositoryRoot);
        using var canonical = new CanonicalLifecycleFixture();
        using var external = new TestRuntime();
        var target = external.CreateFile("dependency-target.ps1", []);
        var guard = new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root);

        foreach (var dependency in dependencies.OrderBy(name => name, StringComparer.Ordinal))
        {
            var dependencyPath = Path.Combine(
                canonical.Repository.Root,
                "scripts",
                dependency);
            File.Delete(dependencyPath);
            File.CreateSymbolicLink(dependencyPath, target);
            try
            {
                var exception = Assert.ThrowsExactly<InvalidDataException>(
                    () => guard.Validate(canonical.RuntimeRoot));
                Assert.IsTrue(
                    exception.Message.Contains("reparse-point", StringComparison.OrdinalIgnoreCase),
                    $"Dependency {dependency} was not rejected as a reparse point.");
            }
            finally
            {
                File.Delete(dependencyPath);
                File.WriteAllBytes(dependencyPath, []);
            }
        }
    }

    [TestMethod]
    public void PowerShellAuthority_RejectsRelativeExecutableInjection()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => TrustedPowerShellExecutableAuthority.CreateForTesting("pwsh.exe"));
        var constructors = typeof(PowerShellLifecycleScriptExecutor).GetConstructors();
        Assert.HasCount(1, constructors);
        Assert.HasCount(0, constructors[0].GetParameters());
    }

    [TestMethod]
    [DoNotParallelize]
    public void PowerShellAuthority_IgnoresPathHijack()
    {
        using var trustedProgramFiles = new TestRuntime();
        using var attacker = new TestRuntime();
        var trustedPath = trustedProgramFiles.CreateFile(
            "PowerShell/7/pwsh.exe",
            "trusted"u8.ToArray());
        var attackerPath = attacker.CreateFile("pwsh.exe", "attacker"u8.ToArray());
        var priorPath = Environment.GetEnvironmentVariable("PATH");
        try
        {
            Environment.SetEnvironmentVariable(
                "PATH",
                attacker.Root + Path.PathSeparator + priorPath);
            var authority = TrustedPowerShellExecutableAuthority.CreateFromProgramFilesRoot(
                trustedProgramFiles.Root);

            using var lease = authority.Acquire();
            var identity = lease.Identity;

            Assert.AreEqual(Path.GetFullPath(trustedPath), identity.FullPath);
            Assert.AreNotEqual(Path.GetFullPath(attackerPath), identity.FullPath);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", priorPath);
        }
    }

    [TestMethod]
    public void PowerShellAuthority_LeaseBlocksDeleteAndReparseUntilDisposed()
    {
        using var trusted = new TestRuntime();
        using var external = new TestRuntime();
        var powerShellPath = trusted.CreateFile(
            "PowerShell/7/pwsh.exe",
            "trusted"u8.ToArray());
        var originalBytes = File.ReadAllBytes(powerShellPath);
        var target = external.CreateFile("pwsh.exe", "attacker"u8.ToArray());
        var authority = TrustedPowerShellExecutableAuthority.CreateFromProgramFilesRoot(
            trusted.Root);
        var lease = authority.Acquire();
        try
        {
            Assert.ThrowsExactly<IOException>(() => File.Delete(powerShellPath));
        }
        finally
        {
            lease.Dispose();
        }

        try
        {
            File.Delete(powerShellPath);
            File.CreateSymbolicLink(powerShellPath, target);
            Assert.IsTrue(File.GetAttributes(powerShellPath).HasFlag(FileAttributes.ReparsePoint));
        }
        finally
        {
            File.Delete(powerShellPath);
            File.WriteAllBytes(powerShellPath, originalBytes);
        }
    }

    [TestMethod]
    public void CanonicalRootGuard_RejectsFabricatedStartOnlyRepository()
    {
        using var repository = new TestRuntime();
        var scripts = Directory.CreateDirectory(Path.Combine(repository.Root, "scripts"));
        File.WriteAllText(Path.Combine(scripts.FullName, "Start-PSOBB.ps1"), string.Empty);
        var runtimeRoot = Directory.CreateDirectory(
            Path.Combine(repository.Root, "PSOBB-Runtime")).FullName;

        var exception = Assert.ThrowsExactly<FileNotFoundException>(
            () => new CanonicalLifecycleRepositoryGuard().Validate(runtimeRoot));

        StringAssert.Contains(exception.Message, "required lifecycle script");
    }

    [TestMethod]
    public void CanonicalRootGuard_IgnoresLegacyEnvironmentRedirect()
    {
        using var canonical = new CanonicalLifecycleFixture();
        using var redirect = new TestRuntime();
        var original = Environment.GetEnvironmentVariable("PSOBB_SCRIPT_ROOT");
        try
        {
            Environment.SetEnvironmentVariable("PSOBB_SCRIPT_ROOT", redirect.Root);

            var layout = new CanonicalLifecycleRepositoryGuard().Validate(canonical.RuntimeRoot);

            Assert.AreEqual(canonical.Repository.Root, layout.RepositoryRoot);
            Assert.IsFalse(layout.ScriptPaths.Values.Any(path =>
                path.StartsWith(redirect.Root, StringComparison.OrdinalIgnoreCase)));
        }
        finally
        {
            Environment.SetEnvironmentVariable("PSOBB_SCRIPT_ROOT", original);
        }
    }

    [TestMethod]
    public void CanonicalRootGuard_RejectsRequestedRepositoryMismatch()
    {
        using var expected = new CanonicalLifecycleFixture();
        using var requested = new CanonicalLifecycleFixture();
        var guard = new CanonicalLifecycleRepositoryGuard(expected.Repository.Root);

        var exception = Assert.ThrowsExactly<InvalidDataException>(
            () => guard.Validate(requested.RuntimeRoot));

        StringAssert.Contains(exception.Message, "exact repository root");
    }

    [TestMethod]
    public void CanonicalRootGuard_RejectsAncestorDirectoryLink()
    {
        using var canonical = new CanonicalLifecycleFixture();
        using var container = new TestRuntime();
        var alias = Path.Combine(container.Root, "repository-link");
        Directory.CreateSymbolicLink(alias, canonical.Repository.Root);
        try
        {
            var linkedRuntime = Path.Combine(alias, "PSOBB-Runtime");

            var exception = Assert.ThrowsExactly<InvalidDataException>(
                () => new CanonicalLifecycleRepositoryGuard().Validate(linkedRuntime));

            StringAssert.Contains(exception.Message, "reparse-point");
        }
        finally
        {
            Directory.Delete(alias);
        }
    }

    [TestMethod]
    public void LifecycleController_RejectsObserverExecutorRepositoryDisagreement()
    {
        using var observerRoot = new CanonicalLifecycleFixture();
        using var executorRoot = new CanonicalLifecycleFixture();
        var observerGuard = new CanonicalLifecycleRepositoryGuard(observerRoot.Repository.Root);
        var executorGuard = new CanonicalLifecycleRepositoryGuard(executorRoot.Repository.Root);
        var observer = new RuntimeLifecycleObserver(new NeverIdentityProbe(), observerGuard);
        var executor = new PowerShellLifecycleScriptExecutor(executorGuard);

        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => new LifecycleScriptController(observer, executor));

        StringAssert.Contains(exception.Message, "different repository roots");
    }

    [TestMethod]
    public async Task LifecycleController_RevalidatesCompleteSharedRootBeforeEveryObservation()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var guard = new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root);
        var controller = new LifecycleScriptController(
            new RuntimeLifecycleObserver(new NeverIdentityProbe(), guard),
            new PowerShellLifecycleScriptExecutor(guard));
        File.Delete(Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Stop-PSOBBSession.ps1"));

        var exception = await Assert.ThrowsExactlyAsync<FileNotFoundException>(
            () => controller.ObserveAsync(canonical.RuntimeRoot));

        StringAssert.Contains(exception.Message, "required lifecycle script");
    }

    [TestMethod]
    public async Task ScriptExecutor_PreCanceledRequestDoesNotStartPowerShell()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var executableThatMustNotStart = CreateTestPowerShellExecutable(canonical.Repository.Root);
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateForTesting(executableThatMustNotStart));
        using var source = new CancellationTokenSource();
        source.Cancel();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            [],
            source.Token));

        Assert.IsTrue(File.Exists(executableThatMustNotStart));
        Assert.IsEmpty(executor.LogTail);
    }

    [TestMethod]
    public async Task ScriptExecutor_SuccessReleasesInvocationLeases()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var leasedScript = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateProduction());

        await executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            []);

        File.WriteAllBytes(leasedScript, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(leasedScript));
    }

    [TestMethod]
    public async Task ScriptExecutor_StartFailureReleasesInvocationLeases()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var leasedScript = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var powerShellPath = CreateTestPowerShellExecutable(canonical.Repository.Root);
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            processStarter: _ => false);

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            []));

        File.WriteAllBytes(leasedScript, "script-lease-released"u8.ToArray());
        File.WriteAllBytes(powerShellPath, "powershell-lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "script-lease-released"u8.ToArray(),
            File.ReadAllBytes(leasedScript));
        CollectionAssert.AreEqual(
            "powershell-lease-released"u8.ToArray(),
            File.ReadAllBytes(powerShellPath));
    }

    [TestMethod]
    public async Task ScriptExecutor_CancellationAfterStartReleasesInvocationLeases()
    {
        using var canonical = new CanonicalLifecycleFixture();
        using var source = new CancellationTokenSource();
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: false);
        var stopCoordinator = new LifecycleInvocationProcessStopCoordinator(
            new BoundedChildProcessTerminator(TimeSpan.FromSeconds(2)),
            quarantine);
        var leasedScript = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateProduction(),
            processStarter: process =>
            {
                ConfigureSleepingPowerShell(process.StartInfo);
                var started = process.Start();
                source.CancelAfter(TimeSpan.FromMilliseconds(100));
                return started;
            },
            processStopCoordinator: stopCoordinator);

        await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            [],
            source.Token));

        File.WriteAllBytes(leasedScript, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(leasedScript));
        Assert.AreEqual(0, quarantine.Count);
    }

    [TestMethod]
    public async Task ScriptExecutor_ExecutionTimeoutStopsChildAndReleasesInvocationLeases()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: false);
        var stopCoordinator = new LifecycleInvocationProcessStopCoordinator(
            new BoundedChildProcessTerminator(TimeSpan.FromSeconds(2)),
            quarantine);
        var leasedScript = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateProduction(),
            processStarter: process =>
            {
                ConfigureSleepingPowerShell(process.StartInfo);
                return process.Start();
            },
            processStopCoordinator: stopCoordinator,
            executionTimeout: TimeSpan.FromMilliseconds(100));

        var exception = await Assert.ThrowsExactlyAsync<TimeoutException>(() =>
            executor.ExecuteAsync(
                "Start-PSOBB.ps1",
                canonical.RuntimeRoot,
                []));

        StringAssert.Contains(exception.Message, "0.1-second limit");
        File.WriteAllBytes(leasedScript, "lease-released"u8.ToArray());
        Assert.AreEqual(0, quarantine.Count);
    }

    [TestMethod]
    public async Task ScriptExecutor_KillFailureRetainsEveryLeaseUntilExactExit()
    {
        using var canonical = new CanonicalLifecycleFixture();
        using var source = new CancellationTokenSource();
        var leasedScripts = CanonicalLifecycleRepositoryGuard.ScriptInventory
            .Select(scriptName => Path.Combine(
                canonical.Repository.Root,
                "scripts",
                scriptName))
            .ToArray();
        var powerShellPath = CreateSleepingTestExecutable(canonical.Repository.Root);
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: false);
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(100),
            kill: _ => throw new InvalidOperationException("synthetic kill failure"));
        var stopCoordinator = new LifecycleInvocationProcessStopCoordinator(
            terminator,
            quarantine);
        Process? capturedProcess = null;
        Guid? incidentId = null;
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            processStarter: process =>
            {
                capturedProcess = process;
                ConfigureSleepingPing(process.StartInfo);
                var started = process.Start();
                source.CancelAfter(TimeSpan.FromMilliseconds(100));
                return started;
            },
            processStopCoordinator: stopCoordinator);

        try
        {
            var exception = await Assert.ThrowsExactlyAsync<UnconfirmedLifecycleChildExitException>(
                () => executor.ExecuteAsync(
                    "Start-PSOBB.ps1",
                    canonical.RuntimeRoot,
                    [],
                    source.Token));
            incidentId = exception.QuarantineIncidentId;
            Assert.AreEqual(ChildProcessTerminationFailure.KillFailed, exception.Failure);
            Assert.IsTrue(quarantine.IsRetained(incidentId.Value));
            Assert.AreEqual(1, quarantine.Count);
            foreach (var scriptPath in leasedScripts)
            {
                Assert.ThrowsExactly<IOException>(() =>
                    File.WriteAllBytes(scriptPath, "blocked"u8.ToArray()));
                Assert.ThrowsExactly<IOException>(() => File.Delete(scriptPath));
            }
            Assert.ThrowsExactly<IOException>(() =>
                File.WriteAllBytes(powerShellPath, "blocked"u8.ToArray()));
            Assert.ThrowsExactly<IOException>(() => File.Delete(powerShellPath));
            Assert.IsFalse(quarantine.TryReleaseExited(incidentId.Value));

            await ConfirmExitAndReleaseAsync(
                capturedProcess
                    ?? throw new AssertFailedException("The test child process was not captured."),
                quarantine,
                incidentId.Value);
            capturedProcess = null;
            foreach (var scriptPath in leasedScripts)
            {
                File.WriteAllBytes(scriptPath, "script-lease-released"u8.ToArray());
                File.Delete(scriptPath);
                Assert.IsFalse(File.Exists(scriptPath));
                File.WriteAllBytes(scriptPath, []);
            }
            File.WriteAllBytes(powerShellPath, "powershell-lease-released"u8.ToArray());
            File.Delete(powerShellPath);
            Assert.IsFalse(File.Exists(powerShellPath));
            Assert.AreEqual(0, quarantine.Count);
        }
        finally
        {
            if (capturedProcess is not null)
            {
                await StopTestProcessAsync(capturedProcess);
                if (incidentId.HasValue)
                {
                    _ = quarantine.TryReleaseExited(incidentId.Value);
                }
                else
                {
                    capturedProcess.Dispose();
                }
            }
        }
    }

    [TestMethod]
    public async Task ScriptExecutor_ProcessStartThrowReleasesInvocationLeases()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var leasedScript = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var powerShellPath = CreateTestPowerShellExecutable(canonical.Repository.Root);
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            processStarter: _ => throw new InvalidOperationException("synthetic start failure"));

        var exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            executor.ExecuteAsync(
                "Start-PSOBB.ps1",
                canonical.RuntimeRoot,
                []));

        Assert.AreEqual("synthetic start failure", exception.Message);
        File.WriteAllBytes(leasedScript, "script-lease-released"u8.ToArray());
        File.WriteAllBytes(powerShellPath, "powershell-lease-released"u8.ToArray());
    }

    [TestMethod]
    public async Task BoundedTerminator_AssociationCheckFailureIsUnconfirmed()
    {
        using var process = new Process();
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(25),
            hasAssociatedProcess: _ => throw new InvalidOperationException("synthetic association failure"));

        var result = await terminator.TryTerminateAsync(process);

        Assert.IsFalse(result.ExitConfirmed);
        Assert.AreEqual(ChildProcessTerminationFailure.AssociationCheckFailed, result.Failure);
    }

    [TestMethod]
    public async Task BoundedTerminator_NonCooperativeWaitIsIndependentlyTimedOut()
    {
        using var process = new Process();
        var neverCompletes = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(25),
            hasAssociatedProcess: _ => true,
            hasExited: _ => false,
            kill: _ => { },
            waitForExitAsync: (_, _) => neverCompletes.Task);
        var stopwatch = Stopwatch.StartNew();

        var result = await terminator.TryTerminateAsync(process);

        stopwatch.Stop();
        Assert.IsFalse(result.ExitConfirmed);
        Assert.AreEqual(ChildProcessTerminationFailure.WaitTimedOut, result.Failure);
        Assert.IsLessThan(TimeSpan.FromSeconds(2), stopwatch.Elapsed);
    }

    [TestMethod]
    public async Task BoundedTerminator_WaitFailureIsUnconfirmed()
    {
        using var process = new Process();
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(25),
            hasAssociatedProcess: _ => true,
            hasExited: _ => false,
            kill: _ => { },
            waitForExitAsync: static (_, _) => Task.FromException(
                new InvalidOperationException("synthetic wait failure")));

        var result = await terminator.TryTerminateAsync(process);

        Assert.IsFalse(result.ExitConfirmed);
        Assert.AreEqual(ChildProcessTerminationFailure.WaitFailed, result.Failure);
    }

    [TestMethod]
    public async Task BoundedTerminator_FinalExitCheckFailureIsUnconfirmed()
    {
        using var process = new Process();
        var exitChecks = 0;
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(25),
            hasAssociatedProcess: _ => true,
            hasExited: _ => Interlocked.Increment(ref exitChecks) == 1
                ? false
                : throw new InvalidOperationException("synthetic exit check failure"),
            kill: _ => { },
            waitForExitAsync: static (_, _) => Task.CompletedTask);

        var result = await terminator.TryTerminateAsync(process);

        Assert.IsFalse(result.ExitConfirmed);
        Assert.AreEqual(ChildProcessTerminationFailure.ExitCheckFailed, result.Failure);
    }

    [TestMethod]
    public async Task BoundedTerminator_CompletedWaitWithoutExitIsUnconfirmed()
    {
        using var process = new Process();
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(25),
            hasAssociatedProcess: _ => true,
            hasExited: _ => false,
            kill: _ => { },
            waitForExitAsync: static (_, _) => Task.CompletedTask);

        var result = await terminator.TryTerminateAsync(process);

        Assert.IsFalse(result.ExitConfirmed);
        Assert.AreEqual(ChildProcessTerminationFailure.ExitUnconfirmed, result.Failure);
    }

    [TestMethod]
    public async Task LifecycleInvocationQuarantine_ConcurrentReleaseDisposesExactlyOnce()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var powerShellPath = CreateSleepingTestExecutable(canonical.Repository.Root);
        var scriptPath = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: false);
        CanonicalLifecycleInvocationLease? scriptLease = null;
        PowerShellExecutableLease? powerShellLease = null;
        Process? process = null;
        Guid? incidentId = null;
        try
        {
            scriptLease = new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root)
                .AcquireScriptInvocation(canonical.RuntimeRoot, "Start-PSOBB.ps1");
            powerShellLease = TrustedPowerShellExecutableAuthority
                .CreateForTesting(powerShellPath)
                .Acquire();
            process = CreatePingProcess(powerShellPath, count: 1);
            Assert.IsTrue(process.Start());
            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            Assert.IsTrue(process.HasExited);
            incidentId = quarantine.Retain(process, scriptLease, powerShellLease);
            scriptLease = null;
            powerShellLease = null;

            var releases = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
                Task.Run(() => quarantine.TryReleaseExited(incidentId.Value))));

            Assert.IsTrue(releases.All(static released => released));
            Assert.AreEqual(0, quarantine.Count);
            Assert.AreEqual(1, quarantine.ReleaseCount);
            process = null;
            File.WriteAllBytes(scriptPath, "script-lease-released"u8.ToArray());
            File.WriteAllBytes(powerShellPath, "powershell-lease-released"u8.ToArray());
        }
        finally
        {
            if (incidentId.HasValue && quarantine.IsRetained(incidentId.Value))
            {
                _ = quarantine.TryReleaseExited(incidentId.Value);
            }
            process?.Dispose();
            powerShellLease?.Dispose();
            scriptLease?.Dispose();
        }
    }

    [TestMethod]
    public async Task LifecycleInvocationQuarantine_ExitEventDisposesExactlyOnce()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var powerShellPath = CreateSleepingTestExecutable(canonical.Repository.Root);
        var scriptPath = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "Start-PSOBB.ps1");
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: true);
        CanonicalLifecycleInvocationLease? scriptLease = null;
        PowerShellExecutableLease? powerShellLease = null;
        Process? process = null;
        Guid? incidentId = null;
        try
        {
            scriptLease = new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root)
                .AcquireScriptInvocation(canonical.RuntimeRoot, "Start-PSOBB.ps1");
            powerShellLease = TrustedPowerShellExecutableAuthority
                .CreateForTesting(powerShellPath)
                .Acquire();
            process = CreatePingProcess(powerShellPath, count: 2);
            Assert.IsTrue(process.Start());
            incidentId = quarantine.Retain(process, scriptLease, powerShellLease);
            scriptLease = null;
            powerShellLease = null;

            await WaitUntilAsync(
                () => !quarantine.IsRetained(incidentId.Value),
                TimeSpan.FromSeconds(5));

            Assert.AreEqual(0, quarantine.Count);
            Assert.AreEqual(1, quarantine.ReleaseCount);
            process = null;
            File.WriteAllBytes(scriptPath, "script-lease-released"u8.ToArray());
            File.WriteAllBytes(powerShellPath, "powershell-lease-released"u8.ToArray());
        }
        finally
        {
            if (incidentId.HasValue && quarantine.IsRetained(incidentId.Value))
            {
                try
                {
                    if (process is not null && !process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException
                        or System.ComponentModel.Win32Exception)
                {
                }
                await Task.Delay(100);
                _ = quarantine.TryReleaseExited(incidentId.Value);
            }
            else
            {
                process?.Dispose();
            }
            powerShellLease?.Dispose();
            scriptLease?.Dispose();
        }
    }

    [TestMethod]
    public async Task ScriptExecutor_CanceledAfterSecondValidationDoesNotCallProcessStart()
    {
        using var canonical = new CanonicalLifecycleFixture();
        using var source = new CancellationTokenSource();
        var leasedScript = Path.Combine(
            canonical.Repository.Root,
            "scripts",
            "PSOBB.Common.ps1");
        var originalBytes = File.ReadAllBytes(leasedScript);
        var hookCalls = 0;
        var processStartCalls = 0;
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            CreateTestPowerShellAuthority(canonical.Repository.Root),
            afterSecondValidation: () =>
            {
                hookCalls++;
                source.Cancel();
            },
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            [],
            source.Token));

        Assert.AreEqual(1, hookCalls);
        Assert.AreEqual(0, processStartCalls);
        Assert.IsEmpty(executor.LogTail);
        File.WriteAllBytes(leasedScript, originalBytes);
    }

    [TestMethod]
    public async Task ScriptExecutor_PowerShellMutationAfterSecondValidationFailsBeforeStart()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var powerShellPath = CreateTestPowerShellExecutable(canonical.Repository.Root);
        var processStartCalls = 0;
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            afterSecondValidation: () => File.WriteAllBytes(
                powerShellPath,
                "mutated-powershell"u8.ToArray()),
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<IOException>(() => executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            []));

        Assert.AreEqual(0, processStartCalls);
        File.WriteAllBytes(powerShellPath, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(powerShellPath));
    }

    [TestMethod]
    public async Task ScriptExecutor_DependencyReparseAfterSecondValidationFailsBeforeStart()
    {
        using var canonical = new CanonicalLifecycleFixture();
        using var external = new TestRuntime();
        var dependency = Path.Combine(canonical.Repository.Root, "scripts", "PSOBB.Common.ps1");
        var originalBytes = File.ReadAllBytes(dependency);
        var target = external.CreateFile("common.ps1", []);
        var processStartCalls = 0;
        var executor = new PowerShellLifecycleScriptExecutor(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            CreateTestPowerShellAuthority(canonical.Repository.Root),
            afterSecondValidation: () =>
            {
                File.Delete(dependency);
                File.CreateSymbolicLink(dependency, target);
            },
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<IOException>(() => executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            canonical.RuntimeRoot,
            []));

        Assert.AreEqual(0, processStartCalls);
        File.Delete(dependency);
        File.CreateSymbolicLink(dependency, target);
        Assert.IsTrue(File.GetAttributes(dependency).HasFlag(FileAttributes.ReparsePoint));
        File.Delete(dependency);
        File.WriteAllBytes(dependency, originalBytes);
    }

    [TestMethod]
    public async Task ScriptExecutor_EveryScriptByteMutationAfterSecondValidationFailsBeforeStart()
    {
        using var canonical = new CanonicalLifecycleFixture();
        foreach (var scriptName in CanonicalLifecycleRepositoryGuard.ScriptInventory)
        {
            var scriptPath = Path.Combine(canonical.Repository.Root, "scripts", scriptName);
            var processStartCalls = 0;
            var executor = new PowerShellLifecycleScriptExecutor(
                new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
                CreateTestPowerShellAuthority(canonical.Repository.Root),
                afterSecondValidation: () => File.WriteAllBytes(
                    scriptPath,
                    "ordinary-script-mutation"u8.ToArray()),
                processStarter: _ =>
                {
                    processStartCalls++;
                    return false;
                });
            try
            {
                await Assert.ThrowsExactlyAsync<IOException>(
                    () => executor.ExecuteAsync(
                        "Start-PSOBB.ps1",
                        canonical.RuntimeRoot,
                        []));
                Assert.AreEqual(
                    0,
                    processStartCalls,
                    $"Script mutation reached process start for {scriptName}.");
                File.WriteAllBytes(scriptPath, "lease-released"u8.ToArray());
                CollectionAssert.AreEqual(
                    "lease-released"u8.ToArray(),
                    File.ReadAllBytes(scriptPath),
                    $"Script lease was not released for {scriptName}.");
            }
            finally
            {
                File.WriteAllBytes(scriptPath, []);
            }
        }
    }

    [TestMethod]
    public async Task RuntimeObserver_PreCanceledRequestDoesNotTraverseRuntimeRoot()
    {
        using var repository = new TestRuntime();
        using var source = new CancellationTokenSource();
        source.Cancel();
        var observer = new RuntimeLifecycleObserver(
            new NeverIdentityProbe(),
            new CanonicalLifecycleRepositoryGuard());
        var missingRuntime = Path.Combine(repository.Root, "PSOBB-Runtime");

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => observer.ObserveAsync(
            missingRuntime,
            ServerEnvironmentKind.Stable,
            source.Token));
    }

    [TestMethod]
    public void ScriptExecutor_ReportsPowerShellMessageInsteadOfAnsiLocationHeader()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var executor = CreateExecutor(canonical);
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
        using var canonical = new CanonicalLifecycleFixture();
        var executor = CreateExecutor(canonical);

        var detail = executor.FirstMeaningfulLine("Failure in stage A | stage B did not start");

        Assert.AreEqual("Failure in stage A | stage B did not start", detail);
    }

    [TestMethod]
    public void ScriptExecutor_PreservesLegitimateNumericPipePrefix()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var executor = CreateExecutor(canonical);

        var detail = executor.FirstMeaningfulLine("12000 | listener failed");

        Assert.AreEqual("12000 | listener failed", detail);
    }

    [TestMethod]
    public void ScriptExecutor_NormalizesControlsAndSecretsForDetailAndLog()
    {
        using var canonical = new CanonicalLifecycleFixture();
        var executor = CreateExecutor(canonical);
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
        using var canonical = new CanonicalLifecycleFixture();
        var executor = CreateExecutor(canonical);
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
    public async Task PlayAsync_CombatCanaryUsesOnlySealedNativeEnvironmentArguments()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBBSession.ps1" ? Running() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);
        var selection = StableNativeSelection() with { PreserveForeground = true };

        await controller.PlayAsync(
            runtime.Root, selection, ServerEnvironmentKind.CombatCanary);

        Assert.HasCount(1, executor.Calls);
        var arguments = executor.Calls[0].Arguments.ToArray();
        CollectionAssert.AreEqual(
            new[]
            {
                "-ServerEnvironment", "CombatCanary",
                "-RuntimeRoot", Path.GetFullPath(runtime.Root),
                "-PreserveForeground",
            },
            arguments);
        Assert.IsTrue(observer.ObservedEnvironments.All(
            environment => environment == ServerEnvironmentKind.CombatCanary));
    }

    [TestMethod]
    public async Task PlayAsync_DoesNotAcceptAdvisoryRunningEvidence()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(new(
            LauncherLifecycleState.Running,
            ServerRunning: true,
            ClientRunning: true,
            "Advisory",
            IdentityAuthenticated: false));
        var executor = new RecordingExecutor((_, _) => { });
        var controller = new LifecycleScriptController(observer, executor);

        var exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => controller.PlayAsync(runtime.Root, CanarySelection()));

        StringAssert.Contains(exception.Message, "advisory");
        Assert.IsEmpty(executor.Calls);
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
    public async Task StartServerAsync_CombatCanaryPassesExplicitEnvironment()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBB.ps1" ? ServerReady() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        await controller.StartServerAsync(runtime.Root, ServerEnvironmentKind.CombatCanary);

        Assert.HasCount(1, executor.Calls);
        CollectionAssert.AreEqual(
            new[]
            {
                "-ServerEnvironment", "CombatCanary",
                "-RuntimeRoot", Path.GetFullPath(runtime.Root),
            },
            executor.Calls[0].Arguments.ToArray());
    }

    [TestMethod]
    public async Task StartServerAsync_LegacyPositionalCancellationTokenUsesStable()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Stopped());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBB.ps1" ? ServerReady() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        await controller.StartServerAsync(runtime.Root, CancellationToken.None);

        Assert.IsTrue(observer.ObservedEnvironments.All(
            environment => environment == ServerEnvironmentKind.Stable));
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "Stable");
    }

    [TestMethod]
    public async Task StartClientAsync_CombatCanaryPassesNoGraphicsOverride()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(ServerReady());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Start-PSOBBClient.ps1" ? Running() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        await controller.StartClientAsync(
            runtime.Root, StableNativeSelection(), ServerEnvironmentKind.CombatCanary);

        Assert.HasCount(1, executor.Calls);
        CollectionAssert.AreEqual(
            new[]
            {
                "-ServerEnvironment", "CombatCanary",
                "-RuntimeRoot", Path.GetFullPath(runtime.Root),
            },
            executor.Calls[0].Arguments.ToArray());
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
        CollectionAssert.Contains(executor.Calls[0].Arguments.ToArray(), "Stable");
    }

    [TestMethod]
    public async Task StopAllAsync_CombatCanaryPassesExplicitEnvironment()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Running());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Stop-PSOBBSession.ps1" ? Stopped() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        await controller.StopAllAsync(runtime.Root, ServerEnvironmentKind.CombatCanary);

        Assert.HasCount(1, executor.Calls);
        CollectionAssert.AreEqual(
            new[]
            {
                "-Target", "All",
                "-ServerEnvironment", "CombatCanary",
                "-RuntimeRoot", Path.GetFullPath(runtime.Root),
            },
            executor.Calls[0].Arguments.ToArray());
        Assert.IsTrue(observer.ObservedEnvironments.All(
            environment => environment == ServerEnvironmentKind.CombatCanary));
    }

    [TestMethod]
    public async Task StopClientAsync_CombatCanaryPassesExplicitEnvironment()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(Running());
        var executor = new RecordingExecutor((script, _) => observer.Current =
            script == "Stop-PSOBBClient.ps1" ? ServerReady() : observer.Current);
        var controller = new LifecycleScriptController(observer, executor);

        await controller.StopClientAsync(runtime.Root, ServerEnvironmentKind.CombatCanary);

        Assert.HasCount(1, executor.Calls);
        CollectionAssert.AreEqual(
            new[]
            {
                "-ServerEnvironment", "CombatCanary",
                "-RuntimeRoot", Path.GetFullPath(runtime.Root),
            },
            executor.Calls[0].Arguments.ToArray());
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
    public async Task RepairClientAsync_RejectsFaultedStateEvenWhenProcessFlagsAreFalse()
    {
        using var runtime = new TestRuntime();
        var observer = new MutableObserver(new(
            LauncherLifecycleState.Faulted,
            ServerRunning: false,
            ClientRunning: false,
            "Malformed lifecycle evidence",
            IdentityAuthenticated: false));
        var executor = new RecordingExecutor((_, _) => { });
        var controller = new LifecycleScriptController(observer, executor);

        var exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => controller.RepairClientAsync(runtime.Root, StableNativeSelection()));

        StringAssert.Contains(exception.Message, "exact Stopped state");
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

    private static (HashSet<string> Closure, HashSet<string> Dependencies)
        DiscoverSourceScriptGraph(string repositoryRoot)
    {
        var closure = new HashSet<string>(StringComparer.Ordinal);
        var dependencies = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Queue<string>(CanonicalLifecycleRepositoryGuard.EntryScriptInventory);
        while (pending.Count > 0)
        {
            var scriptName = pending.Dequeue();
            if (!closure.Add(scriptName))
            {
                continue;
            }

            var path = Path.Combine(repositoryRoot, "scripts", scriptName);
            if (!File.Exists(path))
            {
                throw new AssertFailedException(
                    $"The source-derived lifecycle script is missing: {scriptName}");
            }

            var source = File.ReadAllText(path);
            foreach (var line in source.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                var supportedScriptJoin = ScriptDependency.IsMatch(line);
                var supportedParentJoin = RepositoryParentJoin.IsMatch(line);
                var supportedParentSplit = RepositoryParentSplit.IsMatch(line);
                if (line.Contains("$PSScriptRoot", StringComparison.Ordinal)
                    && !supportedScriptJoin
                    && !supportedParentJoin
                    && !supportedParentSplit)
                {
                    throw new AssertFailedException(
                        $"Unsupported or dynamic PSScriptRoot invocation in {scriptName}: {line.Trim()}");
                }
            }

            foreach (Match match in ScriptLiteralToken.Matches(source))
            {
                var literal = match.Groups["literal"].Value;
                var dependency = literal
                    .Replace('\\', '/')
                    .Split('/', StringSplitOptions.RemoveEmptyEntries)
                    .Last();
                dependencies.Add(dependency);
                pending.Enqueue(dependency);
            }
        }

        return (closure, dependencies);
    }

    private static string GetSourceRepositoryRoot(
        [CallerFilePath] string sourceFile = "") =>
        Path.GetFullPath(Path.Combine(
            Path.GetDirectoryName(sourceFile)
                ?? throw new InvalidOperationException("The test source path has no parent."),
            "..",
            ".."));

    private static string CreateTestPowerShellExecutable(string root)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root, "test-host"));
        var path = Path.Combine(directory.FullName, "pwsh.exe");
        File.WriteAllBytes(path, "test-powershell"u8.ToArray());
        return path;
    }

    private static TrustedPowerShellExecutableAuthority CreateTestPowerShellAuthority(string root) =>
        TrustedPowerShellExecutableAuthority.CreateForTesting(
            CreateTestPowerShellExecutable(root));

    private static string CreateSleepingTestExecutable(string root)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root, "sleeping-test-host"));
        var path = Path.Combine(directory.FullName, "pwsh.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "ping.exe"), path);
        return path;
    }

    private static void ConfigureSleepingPowerShell(System.Diagnostics.ProcessStartInfo startInfo)
    {
        startInfo.ArgumentList.Clear();
        foreach (var argument in new[]
                 {
                     "-NoLogo",
                     "-NoProfile",
                     "-NonInteractive",
                     "-Command",
                     "Start-Sleep -Seconds 30",
                 })
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    private static void ConfigureSleepingPing(ProcessStartInfo startInfo)
    {
        ConfigurePing(startInfo, count: 30);
    }

    private static Process CreatePingProcess(string executablePath, int count)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        ConfigurePing(startInfo, count);
        return new Process { StartInfo = startInfo };
    }

    private static void ConfigurePing(ProcessStartInfo startInfo, int count)
    {
        startInfo.ArgumentList.Clear();
        foreach (var argument in new[]
                 {
                     "-n",
                     count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                     "127.0.0.1",
                 })
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (!condition())
        {
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new AssertFailedException("The bounded test condition did not become true.");
            }
            await Task.Delay(10);
        }
    }

    private static async Task ConfirmExitAndReleaseAsync(
        Process process,
        LifecycleInvocationQuarantine quarantine,
        Guid incidentId)
    {
        await StopTestProcessAsync(process);
        Assert.IsTrue(quarantine.TryReleaseExited(incidentId));
        Assert.IsFalse(quarantine.IsRetained(incidentId));
    }

    private static async Task StopTestProcessAsync(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await process.WaitForExitAsync(timeout.Token);
        Assert.IsTrue(process.HasExited);
    }

    private static LifecycleSelection CanarySelection() => LifecycleSelection.Create(
        ReleaseChannel.Canary,
        GraphicsProfileOption.ClarityDgVoodoo,
        MonitorOption.PrimaryPhysical,
        LauncherWindowMode.Borderless);

    private static LifecycleSelection StableNativeSelection() => LifecycleSelection.Create(
        ReleaseChannel.Stable,
        GraphicsProfileOption.SafeNative,
        MonitorOption.PrimaryPhysical,
        LauncherWindowMode.ProfileDefault);

    private static LifecycleSnapshot Stopped() =>
        new(LauncherLifecycleState.Stopped, false, false, "Stopped", IdentityAuthenticated: true);

    private static LifecycleSnapshot ServerReady() =>
        new(LauncherLifecycleState.ServerReady, true, false, "Ready", IdentityAuthenticated: true);

    private static LifecycleSnapshot Running() =>
        new(LauncherLifecycleState.Running, true, true, "Running", IdentityAuthenticated: true);

    private static PowerShellLifecycleScriptExecutor CreateExecutor(
        CanonicalLifecycleFixture canonical) =>
        new(
            new CanonicalLifecycleRepositoryGuard(canonical.Repository.Root),
            CreateTestPowerShellAuthority(canonical.Repository.Root));

    private sealed class MutableObserver(LifecycleSnapshot initial) : ILifecycleStateObserver
    {
        public LifecycleSnapshot Current { get; set; } = initial;

        public List<ServerEnvironmentKind> ObservedEnvironments { get; } = [];

        public Task<LifecycleSnapshot> ObserveAsync(
            string runtimeRoot,
            CancellationToken cancellationToken = default) =>
            ObserveAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

        public Task<LifecycleSnapshot> ObserveAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObservedEnvironments.Add(serverEnvironment);
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

    private sealed class NeverIdentityProbe : IRuntimeIdentityProbe
    {
        public Task<LifecycleSnapshot> ObserveAsync(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment,
            CancellationToken cancellationToken = default) =>
            throw new AssertFailedException("The disagreement test must fail before observation.");
    }

    private sealed class CanonicalLifecycleFixture : IDisposable
    {
        public CanonicalLifecycleFixture()
        {
            Repository = new TestRuntime();
            RuntimeRoot = Directory.CreateDirectory(
                Path.Combine(Repository.Root, "PSOBB-Runtime")).FullName;
            var scriptsRoot = Directory.CreateDirectory(
                Path.Combine(Repository.Root, "scripts")).FullName;
            foreach (var scriptName in CanonicalLifecycleRepositoryGuard.ScriptInventory)
            {
                File.WriteAllText(Path.Combine(scriptsRoot, scriptName), string.Empty);
            }
        }

        public TestRuntime Repository { get; }

        public string RuntimeRoot { get; }

        public void Dispose() => Repository.Dispose();
    }

    private sealed record ScriptCall(string Script, IReadOnlyList<string> Arguments);
}
