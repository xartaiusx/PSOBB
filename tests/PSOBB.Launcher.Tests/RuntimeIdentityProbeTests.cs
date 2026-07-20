using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class RuntimeIdentityProbeTests
{
    [TestMethod]
    public async Task ObserveAsync_PreCanceledObservationPerformsNoCensus()
    {
        using var fixture = new IdentityFixture();
        using var source = new CancellationTokenSource();
        source.Cancel();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => fixture.Probe.ObserveAsync(
            fixture.Runtime.Root,
            ServerEnvironmentKind.Stable,
            source.Token));

        Assert.AreEqual(0, fixture.Platform.QueryCount);
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_PreCanceledRequestDoesNotStartPowerShell()
    {
        using var repository = new TestRuntime();
        var powerShellAuthority = CreateTestPowerShellAuthority(repository.Root);
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.Root),
            powerShellAuthority);
        using var source = new CancellationTokenSource();
        source.Cancel();

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => verifier.VerifyAsync(
            new(repository.Root, "Stable"),
            source.Token));

    }

    [TestMethod]
    public async Task RuntimeContractVerifier_CanceledAfterSecondValidationDoesNotCallProcessStart()
    {
        using var repository = new CanonicalRepositoryFixture();
        using var source = new CancellationTokenSource();
        var leasedScript = Path.Combine(
            repository.RepositoryRoot,
            "scripts",
            "PSOBB.Common.ps1");
        var originalBytes = File.ReadAllBytes(leasedScript);
        var hookCalls = 0;
        var processStartCalls = 0;
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            CreateTestPowerShellAuthority(repository.RepositoryRoot),
            afterSecondValidation: _ =>
            {
                hookCalls++;
                source.Cancel();
            },
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable"),
            source.Token));

        Assert.AreEqual(1, hookCalls);
        Assert.AreEqual(0, processStartCalls);
        File.WriteAllBytes(leasedScript, originalBytes);
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_LinkedTimeoutAfterSecondValidationDoesNotCallProcessStart()
    {
        using var repository = new CanonicalRepositoryFixture();
        var leasedScript = Path.Combine(
            repository.RepositoryRoot,
            "scripts",
            "PSOBB.Common.ps1");
        var originalBytes = File.ReadAllBytes(leasedScript);
        var hookCalls = 0;
        var processStartCalls = 0;
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            CreateTestPowerShellAuthority(repository.RepositoryRoot),
            afterSecondValidation: timeout =>
            {
                hookCalls++;
                timeout.Cancel();
            },
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<TimeoutException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable")));

        Assert.AreEqual(1, hookCalls);
        Assert.AreEqual(0, processStartCalls);
        File.WriteAllBytes(leasedScript, originalBytes);
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_SuccessReleasesInvocationLeases()
    {
        using var repository = new CanonicalRepositoryFixture();
        var leasedScript = Path.Combine(
            repository.RepositoryRoot,
            "scripts",
            "Test-PSOBBClientGraphics.ps1");
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            TrustedPowerShellExecutableAuthority.CreateProduction());

        await verifier.VerifyAsync(new(repository.RuntimeRoot, "Stable"));

        File.WriteAllBytes(leasedScript, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(leasedScript));
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_StartFailureReleasesInvocationLeases()
    {
        using var repository = new CanonicalRepositoryFixture();
        var leasedScript = Path.Combine(
            repository.RepositoryRoot,
            "scripts",
            "Test-PSOBBClientGraphics.ps1");
        var powerShellPath = CreateTestPowerShellExecutable(repository.RepositoryRoot);
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            processStarter: _ => false);

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable")));

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
    public async Task RuntimeContractVerifier_TimeoutAfterStartReleasesInvocationLeases()
    {
        using var repository = new CanonicalRepositoryFixture();
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: false);
        var stopCoordinator = new LifecycleInvocationProcessStopCoordinator(
            new BoundedChildProcessTerminator(TimeSpan.FromSeconds(2)),
            quarantine);
        var leasedScript = Path.Combine(
            repository.RepositoryRoot,
            "scripts",
            "Test-PSOBBClientGraphics.ps1");
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            TrustedPowerShellExecutableAuthority.CreateProduction(),
            processStarter: process =>
            {
                ConfigureSleepingPowerShell(process.StartInfo);
                return process.Start();
            },
            verificationTimeout: TimeSpan.FromMilliseconds(100),
            processStopCoordinator: stopCoordinator);

        await Assert.ThrowsExactlyAsync<TimeoutException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable")));

        File.WriteAllBytes(leasedScript, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(leasedScript));
        Assert.AreEqual(0, quarantine.Count);
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_PostKillWaitTimeoutRetainsLeasesUntilExactExit()
    {
        using var repository = new CanonicalRepositoryFixture();
        var leasedScript = Path.Combine(
            repository.RepositoryRoot,
            "scripts",
            "Test-PSOBBClientGraphics.ps1");
        var powerShellPath = CreateSleepingTestExecutable(repository.RepositoryRoot);
        var quarantine = new LifecycleInvocationQuarantine(observeExitEvents: false);
        var terminator = new BoundedChildProcessTerminator(
            TimeSpan.FromMilliseconds(50),
            kill: _ => { },
            waitForExitAsync: static (_, cancellationToken) =>
                Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken));
        var stopCoordinator = new LifecycleInvocationProcessStopCoordinator(
            terminator,
            quarantine);
        Process? capturedProcess = null;
        Guid? incidentId = null;
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            processStarter: process =>
            {
                capturedProcess = process;
                ConfigureSleepingPing(process.StartInfo);
                return process.Start();
            },
            verificationTimeout: TimeSpan.FromMilliseconds(100),
            processStopCoordinator: stopCoordinator);

        try
        {
            var exception = await Assert.ThrowsExactlyAsync<UnconfirmedLifecycleChildExitException>(
                () => verifier.VerifyAsync(new(repository.RuntimeRoot, "Stable")));
            incidentId = exception.QuarantineIncidentId;
            Assert.AreEqual(ChildProcessTerminationFailure.WaitTimedOut, exception.Failure);
            Assert.IsTrue(quarantine.IsRetained(incidentId.Value));
            Assert.AreEqual(1, quarantine.Count);
            Assert.ThrowsExactly<IOException>(() =>
                File.WriteAllBytes(leasedScript, "blocked"u8.ToArray()));
            Assert.ThrowsExactly<IOException>(() =>
                File.WriteAllBytes(powerShellPath, "blocked"u8.ToArray()));
            Assert.IsFalse(quarantine.TryReleaseExited(incidentId.Value));

            await ConfirmExitAndReleaseAsync(
                capturedProcess
                    ?? throw new AssertFailedException("The verifier child process was not captured."),
                quarantine,
                incidentId.Value);
            capturedProcess = null;
            File.WriteAllBytes(leasedScript, "script-lease-released"u8.ToArray());
            File.WriteAllBytes(powerShellPath, "powershell-lease-released"u8.ToArray());
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
    public async Task RuntimeContractVerifier_PowerShellMutationAfterSecondValidationFailsBeforeStart()
    {
        using var repository = new CanonicalRepositoryFixture();
        var powerShellPath = CreateTestPowerShellExecutable(repository.RepositoryRoot);
        var processStartCalls = 0;
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            TrustedPowerShellExecutableAuthority.CreateForTesting(powerShellPath),
            afterSecondValidation: _ => File.WriteAllBytes(
                powerShellPath,
                "mutated-powershell"u8.ToArray()),
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<IOException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable")));

        Assert.AreEqual(0, processStartCalls);
        File.WriteAllBytes(powerShellPath, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(powerShellPath));
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_DependencyReparseAfterSecondValidationFailsBeforeStart()
    {
        using var repository = new CanonicalRepositoryFixture();
        using var external = new TestRuntime();
        var dependency = Path.Combine(repository.RepositoryRoot, "scripts", "PSOBB.Common.ps1");
        var originalBytes = File.ReadAllBytes(dependency);
        var target = external.CreateFile("common.ps1", []);
        var processStartCalls = 0;
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            CreateTestPowerShellAuthority(repository.RepositoryRoot),
            afterSecondValidation: _ =>
            {
                File.Delete(dependency);
                File.CreateSymbolicLink(dependency, target);
            },
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<IOException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable")));

        Assert.AreEqual(0, processStartCalls);
        File.Delete(dependency);
        File.CreateSymbolicLink(dependency, target);
        Assert.IsTrue(File.GetAttributes(dependency).HasFlag(FileAttributes.ReparsePoint));
        File.Delete(dependency);
        File.WriteAllBytes(dependency, originalBytes);
    }

    [TestMethod]
    public async Task RuntimeContractVerifier_DependencyByteMutationAfterSecondValidationFailsBeforeStart()
    {
        using var repository = new CanonicalRepositoryFixture();
        var dependency = Path.Combine(repository.RepositoryRoot, "scripts", "PSOBB.Common.ps1");
        var processStartCalls = 0;
        var verifier = new PowerShellRuntimeContractVerifier(
            new CanonicalLifecycleRepositoryGuard(repository.RepositoryRoot),
            CreateTestPowerShellAuthority(repository.RepositoryRoot),
            afterSecondValidation: _ => File.WriteAllBytes(
                dependency,
                "ordinary-script-mutation"u8.ToArray()),
            processStarter: _ =>
            {
                processStartCalls++;
                return false;
            });

        await Assert.ThrowsExactlyAsync<IOException>(() => verifier.VerifyAsync(
            new(repository.RuntimeRoot, "Stable")));

        Assert.AreEqual(0, processStartCalls);
        File.WriteAllBytes(dependency, "lease-released"u8.ToArray());
        CollectionAssert.AreEqual(
            "lease-released"u8.ToArray(),
            File.ReadAllBytes(dependency));
    }

    [TestMethod]
    public void RuntimeContractVerifier_SanitizesSecretsControlsAndPrivatePaths()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var privatePath = Path.Combine(userProfile, "private", "account.json");
        var standardError =
            "\u001b]0;credential-window\u0007\u001b[31mFailure password=super-secret " +
            "token=abc123 path=" + privatePath + "\u001b[0m";

        var detail = PowerShellRuntimeContractVerifier.FirstBoundedDiagnostic(
            standardError,
            "account id=private-account");

        Assert.DoesNotContain("super-secret", detail, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", detail, StringComparison.Ordinal);
        Assert.DoesNotContain(userProfile, detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\u001b", detail, StringComparison.Ordinal);
        StringAssert.Contains(detail, "password=[REDACTED]");
        StringAssert.Contains(detail, "token=[REDACTED]");
        StringAssert.Contains(detail, "%USERPROFILE%");
    }

    [TestMethod]
    public async Task ObserveAsync_PortsOnlyFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.Platform.Listeners.AddRange(IdentityFixture.ExactListeners(41));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "incomplete or unbound");
    }

    [TestMethod]
    public async Task ObserveAsync_StaleProcessRecordFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.WriteValidStableServerRecord(processId: 41, publishLiveProcesses: false);
        fixture.Platform.Listeners.AddRange(IdentityFixture.ExactListeners(41));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "exactly one live child process");
    }

    [TestMethod]
    public async Task ObserveAsync_ForeignNamedServerFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.Platform.Servers.Add(new(
            42,
            "newserv-windows",
            fixture.Runtime.CreateFile("foreign/newserv-windows.exe", "foreign"u8.ToArray()),
            fixture.StartTimeUtc));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "exactly one live child process");
    }

    [TestMethod]
    public async Task ObserveAsync_MalformedRecordFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.WriteProtectedLifecycleFile(
            "stable/control/newserv.process.json",
            "{not-json"u8.ToArray());

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "malformed");
    }

    [TestMethod]
    public async Task ObserveAsync_PartialOrExtendedServerRecordFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.MutateJson(
            "stable/control/newserv.process.json",
            document => document["fabricated"] = true);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "exact property set");
    }

    [TestMethod]
    public async Task ObserveAsync_ServerRecordOneTickMismatchFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.MutateJson(
            "stable/control/newserv.process.json",
            document => document["startTimeFileTimeUtc"] =
                ((JsonElement)document["startTimeFileTimeUtc"]!).GetInt64() + 1);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "creation time");
    }

    [TestMethod]
    public async Task ObserveAsync_ReadyStateOneTickMismatchFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.MutateJson(
            "stable/control/newserv-control.json",
            document => document["startTimeFileTimeUtc"] =
                ((JsonElement)document["startTimeFileTimeUtc"]!).GetInt64() + 1);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "child-started control state");
    }

    [TestMethod]
    public async Task ObserveAsync_UnsupervisedExactChildAndPortsFailClosed()
    {
        using var fixture = new IdentityFixture();
        var identity = fixture.ConfigureValidStableServer(processId: 41);
        fixture.Platform.Hosts.Remove(identity.HostProcessId);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "supervisor host identity");
    }

    [TestMethod]
    public async Task ObserveAsync_WrongListenerOwnerFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.Platform.Listeners[2] = new(IPAddress.Loopback, 12001, 99);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "exactly the three approved loopback listeners");
    }

    [TestMethod]
    public async Task ObserveAsync_ModifiedServerAtExactPathFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        File.WriteAllBytes(fixture.StableServerPath, "tamper"u8.ToArray());

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "tracked size and SHA-256");
    }

    [TestMethod]
    public async Task ObserveAsync_ModifiedClientAtExactPathFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.ConfigureValidStableClient(processId: 51);
        File.WriteAllBytes(fixture.StableClientPath, "tamper"u8.ToArray());

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "tracked size and SHA-256");
    }

    [TestMethod]
    public async Task ObserveAsync_SelfConsistentPartialProfileAndReceiptFailClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.ConfigureValidStableClient(processId: 51);
        fixture.WriteSelfConsistentPartialStableProfile(processId: 51);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "exact property set");
    }

    [TestMethod]
    public async Task ObserveAsync_ClientReceiptOneTickMismatchFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.ConfigureValidStableClient(processId: 51);
        fixture.MutateStableClientReceipt(
            processId: 51,
            document => document["processStartTimeFileTimeUtc"] =
                ((JsonElement)document["processStartTimeFileTimeUtc"]!).GetInt64() + 1);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "receipt");
    }

    [TestMethod]
    [DataRow("stable/control/newserv.process.json")]
    [DataRow("stable/control/newserv-host.pid")]
    [DataRow("stable/control/newserv-control.json")]
    public async Task ObserveAsync_InheritedLifecycleAclFailsClosed(string relativePath)
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        TestRuntime.EnableFileAclInheritance(Path.Combine(
            fixture.Runtime.Root,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "exact protected ACL");
    }

    [TestMethod]
    public async Task ObserveAsync_InheritedRuntimeMarkerAclFailsClosed()
    {
        using var fixture = new IdentityFixture();
        TestRuntime.EnableFileAclInheritance(Path.Combine(
            fixture.Runtime.Root,
            ".psobb-runtime.json"));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "exact protected ACL");
    }

    [TestMethod]
    [DataRow("stable/control")]
    public async Task ObserveAsync_InheritedLifecycleParentAclFailsClosed(string relativePath)
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        TestRuntime.EnableDirectoryAclInheritance(Path.Combine(
            fixture.Runtime.Root,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "exact protected ACL");
    }

    [TestMethod]
    public async Task ObserveAsync_ReadOnlyUntrustedAncestorAclIsAccepted()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        TestRuntime.AddPermissiveDirectoryAcl(Path.Combine(
            fixture.Runtime.Root,
            "stable"));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.ServerReady, result.State, result.Detail);
        Assert.IsTrue(result.IdentityAuthenticated);
    }

    [TestMethod]
    public async Task ObserveAsync_UntrustedAncestorWriteAclFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        TestRuntime.AddUntrustedDirectoryWriteAcl(Path.Combine(
            fixture.Runtime.Root,
            "stable"));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "grants mutation rights");
    }

    [TestMethod]
    public async Task ObserveAsync_ExactMarkerWithNonExactSafeRuntimeRootIsAccepted()
    {
        using var fixture = new IdentityFixture();

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Stopped, result.State, result.Detail);
        Assert.IsTrue(result.IdentityAuthenticated);
    }

    [TestMethod]
    [DataRow("S-1-5-32-544")]
    [DataRow("S-1-5-18")]
    public void ProtectedRuntimeAcl_ExactMarkerAcceptsOnlyExplicitTrustedOwners(string ownerSid)
    {
        var currentUser = CurrentUserSidValue();
        var security = CreateExactFileSecurity(currentUser, ownerSid);

        ProtectedRuntimeFileAcl.RequireExactFileDescriptor(
            security,
            currentUser,
            requireCurrentUserOwner: false);

        Assert.ThrowsExactly<InvalidDataException>(() =>
            ProtectedRuntimeFileAcl.RequireExactFileDescriptor(
                security,
                currentUser,
                requireCurrentUserOwner: true));
    }

    [TestMethod]
    public void ProtectedRuntimeAcl_ExactMarkerRejectsUntrustedOwner()
    {
        var currentUser = CurrentUserSidValue();
        var security = CreateExactFileSecurity(currentUser, "S-1-1-0");

        Assert.ThrowsExactly<InvalidDataException>(() =>
            ProtectedRuntimeFileAcl.RequireExactFileDescriptor(
                security,
                currentUser,
                requireCurrentUserOwner: false));
    }

    [TestMethod]
    public void ProtectedRuntimeAcl_RejectsNonCanonicalDescriptor()
    {
        var currentUser = CurrentUserSidValue();
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(
            $"O:{currentUser}D:P(A;;FA;;;{currentUser})(D;;FW;;;WD)");
        Assert.IsFalse(security.AreAccessRulesCanonical);

        Assert.ThrowsExactly<InvalidDataException>(() =>
            ProtectedRuntimeFileAcl.RequireExactFileDescriptor(
                security,
                currentUser,
                requireCurrentUserOwner: false));
    }

    [TestMethod]
    public async Task ObserveAsync_InheritedClientReceiptAclFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.ConfigureValidStableClient(processId: 51);
        TestRuntime.EnableFileAclInheritance(fixture.StableClientReceiptPath(processId: 51));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "exact protected ACL");
    }

    [TestMethod]
    public async Task ObserveAsync_PermissiveLifecycleAclFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        TestRuntime.AddPermissiveFileAcl(Path.Combine(
            fixture.Runtime.Root,
            "stable",
            "control",
            "newserv-control.json"));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "exact protected ACL");
    }

    [TestMethod]
    public async Task ObserveAsync_PermissiveLifecycleParentAclFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        TestRuntime.AddPermissiveDirectoryAcl(Path.Combine(
            fixture.Runtime.Root,
            "stable",
            "control"));

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "exact protected ACL");
    }

    [TestMethod]
    public async Task ObserveAsync_AncestorReparsePointFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        var control = Path.Combine(fixture.Runtime.Root, "stable", "control");
        var target = Path.Combine(fixture.Runtime.Root, "control-target");
        Directory.Move(control, target);
        Directory.CreateSymbolicLink(control, target);
        try
        {
            var result = await fixture.ObserveStableAsync();

            Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
            StringAssert.Contains(result.Detail, "reparse-point ancestor");
        }
        finally
        {
            Directory.Delete(control);
            Directory.Move(target, control);
        }
    }

    [TestMethod]
    public async Task ObserveAsync_IdentityJsonMutationDuringRecensusFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.Platform.ProcessQuery = (name, invocation) =>
        {
            if (name.Equals("newserv-windows", StringComparison.OrdinalIgnoreCase) && invocation == 2)
            {
                File.AppendAllText(
                    Path.Combine(fixture.Runtime.Root, "stable", "control", "newserv-control.json"),
                    " ");
            }
        };

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "changed during observation");
    }

    [TestMethod]
    public async Task ObserveAsync_ProcessRecensusRaceFailsClosed()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.Platform.ProcessQuery = (name, invocation) =>
        {
            if (name.Equals("newserv-windows", StringComparison.OrdinalIgnoreCase) && invocation == 2)
            {
                fixture.Platform.Servers.Clear();
            }
        };

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        StringAssert.Contains(result.Detail, "census changed");
    }

    [TestMethod]
    public async Task ObserveAsync_FullyValidSupervisedServerAndReceiptBoundClientAreAuthenticated()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidStableServer(processId: 41);
        fixture.ConfigureValidStableClient(processId: 51);

        var result = await fixture.ObserveStableAsync();

        Assert.AreEqual(LauncherLifecycleState.Running, result.State, result.Detail);
        Assert.IsTrue(result.ServerRunning);
        Assert.IsTrue(result.ClientRunning);
        Assert.IsTrue(result.IdentityAuthenticated);
        Assert.HasCount(1, fixture.Verifier.Requests);
        Assert.AreEqual("Stable", fixture.Verifier.Requests[0].Channel);
    }

    [TestMethod]
    public async Task ObserveAsync_CombatCanaryRequiresCompleteSignedInstallationSeal()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidCombatCanaryServer(processId: 61);
        fixture.ConfigureValidCombatCanaryClient(processId: 71);

        var accepted = await fixture.Probe.ObserveAsync(
            fixture.Runtime.Root,
            ServerEnvironmentKind.CombatCanary);
        Assert.AreEqual(LauncherLifecycleState.Running, accepted.State, accepted.Detail);
        Assert.IsTrue(accepted.IdentityAuthenticated);
        Assert.HasCount(1, fixture.Verifier.Requests);
        Assert.AreEqual("CombatCanary", fixture.Verifier.Requests[0].Channel);
        Assert.IsNotNull(fixture.Verifier.Requests[0].BuildContractSha256);
        Assert.IsNotNull(fixture.Verifier.Requests[0].TwillsContractSha256);
        Assert.IsNotNull(fixture.Verifier.Requests[0].SigningPublicKeySpkiSha256);

        fixture.MutateJson(
            "combat-canary/installation.json",
            document => document["unsealed"] = true);
        var rejected = await fixture.Probe.ObserveAsync(
            fixture.Runtime.Root,
            ServerEnvironmentKind.CombatCanary);
        Assert.AreEqual(LauncherLifecycleState.Faulted, rejected.State);
        StringAssert.Contains(rejected.Detail, "exact property set");
    }

    [TestMethod]
    public async Task ObserveAsync_CombatCanaryFailsClosedWhenAuthoritativeVerifierRejects()
    {
        using var fixture = new IdentityFixture();
        fixture.ConfigureValidCombatCanaryServer(processId: 61);
        fixture.ConfigureValidCombatCanaryClient(processId: 71);
        fixture.Verifier.Failure = new InvalidDataException("nested signed snapshot contract drifted");

        var result = await fixture.Probe.ObserveAsync(
            fixture.Runtime.Root,
            ServerEnvironmentKind.CombatCanary);

        Assert.AreEqual(LauncherLifecycleState.Faulted, result.State);
        Assert.IsFalse(result.IdentityAuthenticated);
        StringAssert.Contains(result.Detail, "nested signed snapshot contract drifted");
    }

    private static string CreateTestPowerShellExecutable(string root)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root, "test-host"));
        var path = Path.Combine(directory.FullName, "pwsh.exe");
        File.WriteAllBytes(path, "test-powershell"u8.ToArray());
        return path;
    }

    private static string CreateSleepingTestExecutable(string root)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root, "sleeping-test-host"));
        var path = Path.Combine(directory.FullName, "pwsh.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "ping.exe"), path);
        return path;
    }

    private static TrustedPowerShellExecutableAuthority CreateTestPowerShellAuthority(string root) =>
        TrustedPowerShellExecutableAuthority.CreateForTesting(
            CreateTestPowerShellExecutable(root));

    private static string CurrentUserSidValue() =>
        WindowsIdentity.GetCurrent().User?.Value
        ?? throw new InvalidOperationException("The test user SID is unavailable.");

    private static FileSecurity CreateExactFileSecurity(
        string currentUser,
        string ownerSid)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(new SecurityIdentifier(ownerSid));
        foreach (var sid in new[] { currentUser, "S-1-5-32-544", "S-1-5-18" })
        {
            security.AddAccessRule(new(
                new SecurityIdentifier(sid),
                FileSystemRights.FullControl,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        return security;
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
        startInfo.ArgumentList.Clear();
        foreach (var argument in new[] { "-n", "30", "127.0.0.1" })
        {
            startInfo.ArgumentList.Add(argument);
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

    private sealed class IdentityFixture : IDisposable
    {
        private static readonly int[] RequiredGamePorts = [12000, 12001];

        private const string InstallationId = "11111111-2222-3333-4444-555555555555";
        private const string SnapshotDirectoryName = "twills-slot0-20260719T203000000Z-1234abcd";
        private const string SnapshotId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        private readonly byte[] _clientBytes = "approved-client"u8.ToArray();
        private readonly byte[] _combatServerBytes = "approved-combat-server"u8.ToArray();
        private readonly byte[] _stableServerBytes = "approved-stable-server"u8.ToArray();
        private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly object _nativeGraphics;
        private CombatHashes? _combatHashes;

        public IdentityFixture()
        {
            Repository = new TestRuntime();
            Runtime = new TestRuntime(Path.Combine(Repository.Root, "PSOBB-Runtime"));
            foreach (var scriptName in CanonicalLifecycleRepositoryGuard.ScriptInventory)
            {
                Repository.CreateFile($"scripts/{scriptName}", []);
            }
            Platform = new FakeRuntimePlatformProbe();
            Verifier = new FakeRuntimeContractVerifier();
            StartTimeUtc = new DateTimeOffset(2026, 7, 19, 20, 30, 0, TimeSpan.Zero);
            StableServerPath = Runtime.CreateFile(
                "stable/server/release/newserv-windows.exe", _stableServerBytes);
            CombatServerPath = Runtime.CreateFile(
                "combat-canary/server/release/newserv-windows.exe", _combatServerBytes);
            StableClientPath = Runtime.CreateFile(
                "stable/runtime/client/Psobb.exe", _clientBytes);
            CombatClientPath = Runtime.CreateFile(
                "combat-canary/runtime/client/Psobb.exe", _clientBytes);
            _nativeGraphics = NativeGraphics();
            WriteRuntimeMarker();
            WriteRepositoryContracts();
            Probe = new ExactRuntimeIdentityProbe(Repository.Root, Platform, Verifier);
        }

        public TestRuntime Repository { get; }

        public TestRuntime Runtime { get; }

        public FakeRuntimePlatformProbe Platform { get; }

        public FakeRuntimeContractVerifier Verifier { get; }

        public ExactRuntimeIdentityProbe Probe { get; }

        public DateTimeOffset StartTimeUtc { get; }

        public string StableServerPath { get; }

        public string CombatServerPath { get; }

        public string StableClientPath { get; }

        public string CombatClientPath { get; }

        public static IEnumerable<RuntimeTcpListener> ExactListeners(int processId) =>
        [
            new(IPAddress.Loopback, 11000, processId),
            new(IPAddress.Loopback, 12000, processId),
            new(IPAddress.Loopback, 12001, processId),
        ];

        public Task<LifecycleSnapshot> ObserveStableAsync() => Probe.ObserveAsync(
            Runtime.Root,
            ServerEnvironmentKind.Stable);

        public string WriteProtectedLifecycleFile(
            string relativePath,
            byte[] content,
            bool protectProducerBoundary = true)
        {
            var path = Runtime.CreateFile(relativePath, content);
            TestRuntime.SetProtectedRuntimeFileAcl(
                Runtime.Root,
                path,
                protectProducerBoundary);
            return path;
        }

        public string StableClientReceiptPath(int processId)
        {
            var process = Platform.Clients.Single(client => client.ProcessId == processId);
            var receiptName = process.StartTimeUtc.UtcDateTime.ToString(
                "yyyyMMdd'T'HHmmssfff'Z'",
                CultureInfo.InvariantCulture) + $"-{process.ProcessId}.json";
            return Path.Combine(Runtime.Root, "logs", "client-startup", receiptName);
        }

        public ServerIdentity ConfigureValidStableServer(int processId) =>
            WriteValidStableServerRecord(processId, publishLiveProcesses: true);

        public ServerIdentity ConfigureValidCombatCanaryServer(int processId)
        {
            var hashes = EnsureCombatSeal();
            return WriteServerRecord(
                "combat-canary",
                "CombatCanary",
                "combat-canary",
                "newserv-combat-canary-build",
                processId,
                CombatServerPath,
                Hash(_combatServerBytes),
                hashes.BuildContractSha256,
                hashes.ClientBindingSha256,
                hashes.StateBindingSha256,
                publishLiveProcesses: true);
        }

        public ServerIdentity WriteValidStableServerRecord(int processId, bool publishLiveProcesses) =>
            WriteServerRecord(
                "stable",
                "Stable",
                "stable",
                "newserv-stable-release",
                processId,
                StableServerPath,
                Hash(_stableServerBytes),
                null,
                null,
                null,
                publishLiveProcesses);

        public void ConfigureValidStableClient(int processId)
        {
            var profileBytes = StableProfileBytes("stable");
            Runtime.CreateFile("stable/runtime/client/client-profile.json", profileBytes);
            var process = new RuntimeProcessIdentity(
                processId,
                "Psobb",
                StableClientPath,
                StartTimeUtc.AddMinutes(1));
            Platform.Clients.Add(process);
            WriteClientReceipt(
                "stable",
                "Stable",
                "Stable",
                process,
                profileBytes,
                clientBindingSha256: null);
        }

        public void ConfigureValidCombatCanaryClient(int processId)
        {
            var hashes = EnsureCombatSeal();
            var profileBytes = File.ReadAllBytes(Path.Combine(
                Runtime.Root,
                "combat-canary",
                "runtime",
                "client",
                "client-profile.json"));
            var process = new RuntimeProcessIdentity(
                processId,
                "Psobb",
                CombatClientPath,
                StartTimeUtc.AddMinutes(1));
            Platform.Clients.Add(process);
            WriteClientReceipt(
                "combat-canary",
                "CombatCanary",
                "Native",
                process,
                profileBytes,
                hashes.ClientBindingSha256);
        }

        public void WriteSelfConsistentPartialStableProfile(int processId)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 5,
                channel = "stable",
                profileId = "safe-native-4x3",
                baseExecutableSha256 = Hash(_clientBytes),
            });
            Runtime.CreateFile("stable/runtime/client/client-profile.json", bytes);
            var process = Platform.Clients.Single(client => client.ProcessId == processId);
            WriteClientReceipt(
                "stable",
                "Stable",
                "stable",
                process,
                bytes,
                clientBindingSha256: null);
        }

        public void MutateJson(string relativePath, Action<Dictionary<string, object?>> mutation)
        {
            var path = Path.Combine(Runtime.Root, relativePath.Replace('/', Path.DirectorySeparatorChar));
            var value = JsonSerializer.Deserialize<Dictionary<string, object?>>(File.ReadAllBytes(path))!;
            mutation(value);
            File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(value));
        }

        public void MutateStableClientReceipt(
            int processId,
            Action<Dictionary<string, object?>> mutation)
        {
            var process = Platform.Clients.Single(client => client.ProcessId == processId);
            var receiptName = process.StartTimeUtc.UtcDateTime.ToString(
                "yyyyMMdd'T'HHmmssfff'Z'",
                CultureInfo.InvariantCulture) + $"-{process.ProcessId}.json";
            MutateJson($"logs/client-startup/{receiptName}", mutation);
        }

        public void Dispose()
        {
            _signingKey.Dispose();
            Runtime.Dispose();
            Repository.Dispose();
        }

        private ServerIdentity WriteServerRecord(
            string environmentFolder,
            string serverEnvironment,
            string environmentId,
            string componentId,
            int processId,
            string executablePath,
            string executableSha256,
            string? buildContractSha256,
            string? clientBindingSha256,
            string? stateBindingSha256,
            bool publishLiveProcesses)
        {
            var hostProcessId = processId + 1000;
            var hostStart = StartTimeUtc.AddMinutes(-1);
            var hostPath = Repository.CreateFile(
                $"host/{environmentFolder}/pwsh.exe", "approved-pwsh"u8.ToArray());
            var startupRequestId = "0123456789abcdef0123456789abcdef";
            var controlToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi_1234567";
            Assert.AreEqual(43, controlToken.Length);
            var controlIdentity = ControlIdentity(
                environmentId,
                componentId,
                startupRequestId,
                executableSha256);
            var logsRelative = environmentFolder.Equals("stable", StringComparison.Ordinal)
                ? "logs"
                : $"{environmentFolder}/logs";
            var logsRoot = Path.Combine(Runtime.Root, logsRelative.Replace('/', Path.DirectorySeparatorChar));
            var stdout = Runtime.CreateFile(
                $"{logsRelative}/newserv-20260719-203000000.stdout.log", "stdout"u8.ToArray());
            var stderr = Runtime.CreateFile(
                $"{logsRelative}/newserv-20260719-203000000.stderr.log", "stderr"u8.ToArray());
            Assert.AreEqual(logsRoot, Path.GetDirectoryName(stdout));
            WriteProtectedLifecycleFile(
                $"{environmentFolder}/control/newserv.process.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 3,
                    serverEnvironment,
                    environmentId,
                    componentId,
                    controlIdentity,
                    pid = processId,
                    executablePath,
                    executableSha256,
                    startTimeUtc = StartTimeUtc.ToString("r"),
                    startTimeFileTimeUtc = StartTimeUtc.UtcDateTime.ToFileTimeUtc(),
                    hostPid = hostProcessId,
                    hostStartTimeUtc = hostStart.ToString("r"),
                    hostStartTimeFileTimeUtc = hostStart.UtcDateTime.ToFileTimeUtc(),
                    hostExecutablePath = hostPath,
                    startupRequestId,
                    controlToken,
                    controlProtocol = "protected-filesystem-exit-v2",
                    buildContractSha256,
                    clientBindingSha256,
                    stateBindingSha256,
                    stdoutLog = stdout,
                    stderrLog = stderr,
                }));
            WriteProtectedLifecycleFile(
                $"{environmentFolder}/control/newserv-host.pid",
                Encoding.ASCII.GetBytes(hostProcessId.ToString(CultureInfo.InvariantCulture)));
            WriteProtectedLifecycleFile(
                $"{environmentFolder}/control/newserv-control.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 3,
                    state = "child-started",
                    installationId = InstallationId,
                    serverEnvironment,
                    environmentId,
                    componentId,
                    controlIdentity,
                    pid = processId,
                    startTimeFileTimeUtc = StartTimeUtc.UtcDateTime.ToFileTimeUtc(),
                    hostPid = hostProcessId,
                    hostStartTimeFileTimeUtc = hostStart.UtcDateTime.ToFileTimeUtc(),
                    startupRequestId,
                    startTimeUtc = StartTimeUtc.ToString("o"),
                    updatedAtUtc = StartTimeUtc.AddSeconds(2).ToString("o"),
                }));
            if (publishLiveProcesses)
            {
                Platform.Servers.Add(new(
                    processId,
                    "newserv-windows",
                    executablePath,
                    StartTimeUtc));
                Platform.Hosts[hostProcessId] = new(
                    hostProcessId,
                    "pwsh",
                    hostPath,
                    hostStart);
                Platform.Listeners.AddRange(ExactListeners(processId));
            }
            return new(processId, hostProcessId);
        }

        private void WriteClientReceipt(
            string environmentFolder,
            string serverEnvironment,
            string receiptChannel,
            RuntimeProcessIdentity process,
            byte[] profileBytes,
            string? clientBindingSha256)
        {
            var profileId = "safe-native-4x3";
            var receiptName = process.StartTimeUtc.UtcDateTime.ToString(
                "yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture) + $"-{process.ProcessId}.json";
            var logsRelative = environmentFolder.Equals("stable", StringComparison.Ordinal)
                ? "logs"
                : $"{environmentFolder}/logs";
            WriteProtectedLifecycleFile(
                $"{logsRelative}/client-startup/{receiptName}",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 3,
                    completedAtUtc = process.StartTimeUtc.AddSeconds(3).ToString("o"),
                    serverEnvironment,
                    environmentId = environmentFolder,
                    channel = receiptChannel,
                    profileId,
                    materializedProfileSha256 = Hash(profileBytes),
                    configurationSha256 = (string?)null,
                    processId = process.ProcessId,
                    processStartTimeUtc = process.StartTimeUtc.ToString("o"),
                    processStartTimeFileTimeUtc = process.StartTimeFileTimeUtc,
                    executableSize = _clientBytes.LongLength,
                    executableSha256 = Hash(_clientBytes),
                    clientBindingSha256,
                    startupElapsedMilliseconds = 125.5,
                    foregroundPreserved = true,
                    windowMode = "ApplicationControlled",
                    window = new
                    {
                        x = (int?)null,
                        y = (int?)null,
                        width = (int?)null,
                        height = (int?)null,
                        clientWidth = (int?)null,
                        clientHeight = (int?)null,
                    },
                    nativeGraphicsPresetId = "mid-compatibility",
                    graphicCtrlSha256 = NativeGraphicsHash(),
                }));
        }

        private CombatHashes EnsureCombatSeal()
        {
            if (_combatHashes is not null)
            {
                return _combatHashes;
            }
            var profileBytes = StableProfileBytes("combat-canary");
            Runtime.CreateFile("combat-canary/runtime/client/client-profile.json", profileBytes);
            var baseManifestBytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                files = Array.Empty<object>(),
            });
            Runtime.CreateFile("combat-canary/base-client.manifest.json", baseManifestBytes);
            var releaseManifestBytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                profileId = "newserv-combat-canary-build",
                sourceCommit = new string('a', 40),
                patchSeriesSha256 = new string('b', 64),
                files = Array.Empty<object>(),
            });
            Runtime.CreateFile(
                "combat-canary/server-base/release/release-manifest.json",
                releaseManifestBytes);
            var configurationBytes = "{\"ServerName\":\"PSOBB Combat\"}"u8.ToArray();
            Runtime.CreateFile("combat-canary/server/release/system/config.json", configurationBytes);

            var snapshotManifestBytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                snapshotId = SnapshotId,
                character = "Twills",
                slotIndex = 0,
            });
            Runtime.CreateFile(
                $"combat-canary/snapshots/{SnapshotDirectoryName}/manifest.json",
                snapshotManifestBytes);
            var signature = _signingKey.SignData(
                snapshotManifestBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Runtime.CreateFile(
                $"combat-canary/snapshots/{SnapshotDirectoryName}/manifest.sig",
                Encoding.ASCII.GetBytes(Convert.ToBase64String(signature)));
            Runtime.CreateFile(
                $"combat-canary/snapshots/{SnapshotDirectoryName}/trust/signing-public-key.pem",
                Encoding.UTF8.GetBytes(_signingKey.ExportSubjectPublicKeyInfoPem()));

            var signingFingerprint = Convert.ToHexString(
                SHA256.HashData(_signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
            var stateBindingBytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                environment = "CombatCanary",
                environmentId = "combat-canary",
                restoredAtUtc = StartTimeUtc.AddMinutes(-5).ToString("o"),
                snapshotDirectoryName = SnapshotDirectoryName,
                snapshotId = SnapshotId,
                snapshotManifestSha256 = Hash(snapshotManifestBytes),
                twillsContractSha256 = RepositoryFileHash("config/twills-fonewearl-build.json"),
                signingPublicKeySpkiSha256 = signingFingerprint,
                stateFiles = 4,
            });
            Runtime.CreateFile("combat-canary/state-binding.json", stateBindingBytes);
            var bindingBytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                environment = "CombatCanary",
                environmentId = "combat-canary",
                profile = "baseline",
                renderer = "Native",
                serverAddress = "127.0.0.1",
                patchPort = 11000,
                gamePorts = RequiredGamePorts,
                clientExecutablePath = "runtime/client/Psobb.exe",
                clientExecutableSize = _clientBytes.LongLength,
                clientExecutableSha256 = Hash(_clientBytes),
                clientProfileSha256 = Hash(profileBytes),
                baseClientManifestSha256 = Hash(baseManifestBytes),
                createdAtUtc = StartTimeUtc.AddMinutes(-4).ToString("o"),
            });
            Runtime.CreateFile("combat-canary/client-binding.json", bindingBytes);

            var hashes = new CombatHashes(
                RepositoryFileHash("config/combat-canary-build.json"),
                Hash(bindingBytes),
                Hash(stateBindingBytes));
            Runtime.CreateFile(
                "combat-canary/installation.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    environment = "CombatCanary",
                    environmentId = "combat-canary",
                    initializedAtUtc = StartTimeUtc.AddMinutes(-3).ToString("o"),
                    buildContractSha256 = hashes.BuildContractSha256,
                    serverReleaseManifestSha256 = Hash(releaseManifestBytes),
                    baseClientManifestSha256 = Hash(baseManifestBytes),
                    clientBindingSha256 = hashes.ClientBindingSha256,
                    snapshotDirectoryName = SnapshotDirectoryName,
                    snapshotId = SnapshotId,
                    snapshotManifestSha256 = Hash(snapshotManifestBytes),
                    stateBindingSha256 = hashes.StateBindingSha256,
                    twillsContractSha256 = RepositoryFileHash("config/twills-fonewearl-build.json"),
                    signingPublicKeySpkiSha256 = signingFingerprint,
                    configurationSha256 = Hash(configurationBytes),
                }));
            _combatHashes = hashes;
            return hashes;
        }

        private byte[] StableProfileBytes(string channel) => JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 5,
            builtAtUtc = StartTimeUtc.AddHours(-1).ToString("o"),
            channel,
            profileId = "safe-native-4x3",
            nativeGraphics = _nativeGraphics,
            renderer = "Native",
            baseExecutableSha256 = Hash(_clientBytes),
            wrapperSha256 = (string?)null,
            sourceConfigurationSha256 = (string?)null,
            configurationSha256 = (string?)null,
            outputApi = (string?)null,
            graphicsPreset = "Native",
            desktopWidth = (int?)null,
            desktopHeight = (int?)null,
            renderWidth = (int?)null,
            renderHeight = (int?)null,
            aspectPolicy = (string?)null,
            resamplingFilter = (string?)null,
            textureFilterPolicy = (string?)null,
            edgeSmoothingPolicy = (string?)null,
            bilinear2DOperations = (bool?)null,
            defaultWindowMode = (string?)null,
            resizableClientWidth = (int?)null,
            resizableClientHeight = (int?)null,
            watermarkEnabled = (bool?)null,
            compatibilityFirst = false,
        });

        private void WriteRuntimeMarker()
        {
            WriteProtectedLifecycleFile(
                ".psobb-runtime.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    installationId = InstallationId,
                    runtimeRoot = Runtime.Root,
                    createdAtUtc = StartTimeUtc.AddDays(-1).ToString("o"),
                }),
                protectProducerBoundary: false);
        }

        private void WriteRepositoryContracts()
        {
            Repository.CreateFile("scripts/PSOBB.Common.ps1", "# fixture common"u8.ToArray());
            Repository.CreateFile(
                "scripts/PSOBB.CombatCanary.Common.ps1",
                "# fixture combat common"u8.ToArray());
            Repository.CreateFile(
                "scripts/Test-PSOBBCombatCanary.ps1",
                "# fixture combat verifier"u8.ToArray());
            Repository.CreateFile(
                "scripts/Test-PSOBBClientGraphics.ps1",
                "# fixture graphics verifier"u8.ToArray());
            Repository.CreateFile(
                "config/sources.lock.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    components = new object[]
                    {
                        Component("newserv-stable-release", "release/newserv-windows.exe", _stableServerBytes),
                        Component("newserv-combat-canary-build", "release/newserv-windows.exe", _combatServerBytes),
                        Component("tethealla-59nl-english", "Psobb.exe", _clientBytes),
                    },
                }));
            Repository.CreateFile(
                "config/graphics-profiles.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    profiles = new[]
                    {
                        new
                        {
                            id = "safe-native-4x3",
                            channel = "stable",
                            nativeGraphics = _nativeGraphics,
                            renderer = new
                            {
                                d3d8Owner = new
                                {
                                    componentId = (string?)null,
                                },
                            },
                        },
                    },
                }));
            Repository.CreateFile(
                "config/combat-canary-build.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    profileId = "newserv-combat-canary-build",
                    output = new
                    {
                        executable = new
                        {
                            size = _combatServerBytes.LongLength,
                            sha256 = Hash(_combatServerBytes),
                        },
                    },
                }));
            Repository.CreateFile(
                "config/twills-fonewearl-build.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 2,
                    character = new
                    {
                        name = "Twills",
                        classId = 8,
                        className = "FOnewearl",
                        slotIndex = 0,
                    },
                }));
            var signingFingerprint = Convert.ToHexString(
                SHA256.HashData(_signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
            Repository.CreateFile(
                "config/release-trust.json",
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    activeKeyId = "test-key",
                    keys = new[]
                    {
                        new { id = "test-key", spkiSha256 = signingFingerprint },
                    },
                }));
        }

        private string RepositoryFileHash(string relativePath) => Hash(File.ReadAllBytes(
            Path.Combine(Repository.Root, relativePath.Replace('/', Path.DirectorySeparatorChar))));

        private static object Component(string id, string path, byte[] content) => new
        {
            id,
            members = new[]
            {
                new { path, size = content.LongLength, sha256 = Hash(content) },
            },
        };

        private static object NativeGraphics() => new
        {
            presetId = "mid-compatibility",
            graphicCtrlDwords = new uint[] { 1, 0, 0, 0, 1, 1, 1, 0, 0 },
            graphicCtrlSha256 = NativeGraphicsHash(),
            advancedEffectsPolicy = "compatibility",
            pixelFogPolicy = "pixel",
            lowResolutionTexturesPolicy = "disabled",
            frameSkipPolicy = "disabled",
        };

        private static string NativeGraphicsHash()
        {
            var values = new uint[] { 1, 0, 0, 0, 1, 1, 1, 0, 0 };
            var bytes = new byte[36];
            for (var index = 0; index < values.Length; index++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(index * 4, 4), values[index]);
            }
            return Hash(bytes);
        }

        private static string Hash(byte[] content) =>
            Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

        private static string ControlIdentity(
            string environmentId,
            string componentId,
            string startupRequestId,
            string executableSha256)
        {
            var canonical = string.Join(
                '\n',
                "psobb-newserv-control-v2",
                InstallationId,
                environmentId,
                componentId,
                startupRequestId,
                executableSha256);
            return Hash(Encoding.UTF8.GetBytes(canonical));
        }

        public sealed record ServerIdentity(int ProcessId, int HostProcessId);

        private sealed record CombatHashes(
            string BuildContractSha256,
            string ClientBindingSha256,
            string StateBindingSha256);
    }

    private sealed class FakeRuntimePlatformProbe : IRuntimePlatformProbe
    {
        private readonly Dictionary<string, int> _processQueryCounts = new(StringComparer.OrdinalIgnoreCase);

        public List<RuntimeProcessIdentity> Servers { get; } = [];

        public List<RuntimeProcessIdentity> Clients { get; } = [];

        public Dictionary<int, RuntimeProcessIdentity> Hosts { get; } = [];

        public List<RuntimeTcpListener> Listeners { get; } = [];

        public Action<string, int>? ProcessQuery { get; set; }

        public int QueryCount { get; private set; }

        public IReadOnlyList<RuntimeProcessIdentity> GetProcessesByName(string processName)
        {
            QueryCount++;
            var count = _processQueryCounts.TryGetValue(processName, out var prior) ? prior + 1 : 1;
            _processQueryCounts[processName] = count;
            ProcessQuery?.Invoke(processName, count);
            return processName.Equals("newserv-windows", StringComparison.OrdinalIgnoreCase)
                ? Servers.ToArray()
                : Clients.ToArray();
        }

        public RuntimeProcessIdentity? GetProcessById(int processId)
        {
            QueryCount++;
            return Hosts.GetValueOrDefault(processId);
        }

        public IReadOnlyList<RuntimeTcpListener> GetTcpListeners()
        {
            QueryCount++;
            return Listeners.ToArray();
        }

        public async Task<string> ComputeSha256Async(
            string path,
            CancellationToken cancellationToken = default)
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            return Convert.ToHexString(
                await SHA256.HashDataAsync(stream, cancellationToken))
                .ToLowerInvariant();
        }
    }

    private sealed class FakeRuntimeContractVerifier : IRuntimeContractVerifier
    {
        public List<RuntimeContractVerificationRequest> Requests { get; } = [];

        public Exception? Failure { get; set; }

        public Task VerifyAsync(
            RuntimeContractVerificationRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            if (Failure is not null)
            {
                throw Failure;
            }
            return Task.CompletedTask;
        }
    }
}
