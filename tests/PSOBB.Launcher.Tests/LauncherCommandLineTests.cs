using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
[DoNotParallelize]
public sealed class LauncherCommandLineTests : IDisposable
{
    private CanonicalRepositoryFixture? _canonical;

    private CanonicalRepositoryFixture Canonical =>
        _canonical ?? throw new InvalidOperationException("The canonical fixture is unavailable.");

    [TestInitialize]
    public void Initialize() => _canonical = new CanonicalRepositoryFixture();

    [TestCleanup]
    public void Cleanup()
    {
        _canonical?.Dispose();
        _canonical = null;
    }

    public void Dispose() => Cleanup();

    [TestMethod]
    public void SupportedProfiles_ExposePrivateHdButNotEvidenceOnlyCas()
    {
        Assert.IsTrue(GraphicsProfileOption.Supported.Any(
            profile => profile.Id == "lab-widescreen-hd-16x10"));
        Assert.IsFalse(GraphicsProfileOption.Supported.Any(
            profile => profile.Id == "lab-widescreen-cas-16x10"));
    }

    [TestMethod]
    public void Parse_AcceptsPlayShortcutContract()
    {
        var options = Parse(
        [
            "--play",
            "--channel", "canary",
            "--window-mode", "borderless",
            "--runtime-root", Canonical.RuntimeRoot,
        ]);

        Assert.AreEqual(LauncherOperation.Play, options.Operation);
        Assert.AreEqual(ServerEnvironmentKind.Stable, options.ServerEnvironment);
        Assert.AreEqual(ReleaseChannel.Canary, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.ClarityDgVoodoo, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.Borderless, options.Selection.WindowMode);
        Assert.IsFalse(options.Selection.PreserveForeground);
        Assert.AreEqual(Path.GetFullPath(Canonical.RuntimeRoot), options.RuntimeRoot);
    }

    [TestMethod]
    public void ResolveDefaultRuntimeRoot_FailsClosedWithoutCanonicalDiscovery()
    {
        using var origin = new TestRuntime();

        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => LauncherOptions.ResolveDefaultRuntimeRoot(origin.Root, null));

        StringAssert.Contains(exception.Message, "complete canonical PSOBB repository");
    }

    [TestMethod]
    public void ResolveDefaultRuntimeRoot_AcceptsExactRedundantConfiguration()
    {
        var resolved = LauncherOptions.ResolveDefaultRuntimeRoot(
            Canonical.SourceBuildOrigin,
            Canonical.RuntimeRoot);

        Assert.AreEqual(Path.GetFullPath(Canonical.RuntimeRoot), resolved);
    }

    [TestMethod]
    public void ResolveDefaultRuntimeRoot_RejectsConfiguredForeignFullRepository()
    {
        using var foreign = new CanonicalRepositoryFixture();

        var exception = Assert.ThrowsExactly<InvalidOperationException>(() =>
            LauncherOptions.ResolveDefaultRuntimeRoot(
                Canonical.SourceBuildOrigin,
                foreign.RuntimeRoot));

        StringAssert.Contains(exception.Message, "does not exactly match");
    }

    [TestMethod]
    public void ResolveDefaultRuntimeRoot_DiscoversSourceBuildInstallation()
    {
        var resolved = LauncherOptions.ResolveDefaultRuntimeRoot(
            Canonical.SourceBuildOrigin,
            null);

        Assert.AreEqual(Canonical.RuntimeRoot, resolved);
    }

    [TestMethod]
    public void ResolveDefaultRuntimeRoot_DiscoversPackagedRuntimeInstallation()
    {
        var resolved = LauncherOptions.ResolveDefaultRuntimeRoot(
            Canonical.PackagedLauncherOrigin,
            null);

        Assert.AreEqual(Canonical.RuntimeRoot, resolved);
    }

    [TestMethod]
    public void ResolveDefaultRuntimeRoot_DoesNotTrustCurrentDirectory()
    {
        using var foreign = new CanonicalRepositoryFixture();
        var originalCurrentDirectory = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = foreign.SourceBuildOrigin;

            var resolved = LauncherOptions.ResolveDefaultRuntimeRoot(
                Canonical.SourceBuildOrigin,
                null);

            Assert.AreEqual(Canonical.RuntimeRoot, resolved);
            Assert.AreNotEqual(foreign.RuntimeRoot, resolved);
        }
        finally
        {
            Environment.CurrentDirectory = originalCurrentDirectory;
        }
    }

    [TestMethod]
    public void CanonicalInstallationResolver_RejectsMultipleRepositoryAncestors()
    {
        var nestedRepository = Path.Combine(
            Canonical.SourceBuildOrigin,
            "nested-repository");
        CanonicalRepositoryFixture.MaterializeRepository(nestedRepository);
        var nestedOrigin = CanonicalRepositoryFixture.CreateSourceBuildOrigin(nestedRepository);

        var exception = Assert.ThrowsExactly<InvalidOperationException>(() =>
            new CanonicalLifecycleInstallationResolver().ResolveFromOrigin(nestedOrigin));

        StringAssert.Contains(exception.Message, "multiple canonical PSOBB repository ancestors");
    }

    [TestMethod]
    public void Parse_RejectsForeignFullRepositoryRuntimeArgument()
    {
        using var foreign = new CanonicalRepositoryFixture();

        var exception = Assert.ThrowsExactly<ArgumentException>(() => Parse(
        [
            "--start-server",
            "--runtime-root", foreign.RuntimeRoot,
        ]));

        StringAssert.Contains(exception.Message, "must exactly match");
    }

    [TestMethod]
    public void Parse_AcceptsExactRedundantEnvironmentAndRuntimeArgument()
    {
        var options = Parse(
        [
            "--start-server",
            "--runtime-root", Canonical.RuntimeRoot,
        ], Canonical.RuntimeRoot);

        Assert.AreEqual(Canonical.RuntimeRoot, options.RuntimeRoot);
    }

    [TestMethod]
    public void LauncherServices_IndependentlyRejectsForeignFullRepositoryRuntime()
    {
        using var foreign = new CanonicalRepositoryFixture();

        var exception = Assert.ThrowsExactly<InvalidDataException>(() =>
            LauncherServices.CreateCoordinatorFromInstallationOrigin(
                foreign.RuntimeRoot,
                Canonical.SourceBuildOrigin));

        StringAssert.Contains(exception.Message, "exact repository root");
    }

    [TestMethod]
    public void CanonicalOriginInjection_HasNoPublicApiSurface()
    {
        Assert.IsFalse(typeof(CanonicalLifecycleInstallationResolver).IsPublic);
        Assert.IsFalse(typeof(CanonicalLifecycleInstallationResolver)
            .GetMethod(
                "ResolveFromOrigin",
                BindingFlags.Instance | BindingFlags.Public) is not null);
        Assert.IsFalse(typeof(LauncherOptions)
            .GetMethods(BindingFlags.Static | BindingFlags.Public)
            .Any(method => method.Name == "ResolveDefaultRuntimeRoot"));
        Assert.HasCount(1, typeof(LauncherCommandLine)
            .GetMethods(BindingFlags.Static | BindingFlags.Public)
            .Where(method => method.Name == nameof(LauncherCommandLine.Parse)));
    }

    [TestMethod]
    public void Parse_AcceptsPreserveForegroundFlag()
    {
        var options = Parse(
        [
            "--play",
            "--preserve-foreground",
        ]);

        Assert.IsTrue(options.Selection.PreserveForeground);
    }

    [TestMethod]
    public void Parse_AcceptsExplicitCombatCanaryWithSealedNativeSelection()
    {
        var options = Parse(
        [
            "--play",
            "--server-environment", "combat-canary",
            "--preserve-foreground",
        ]);

        Assert.AreEqual(ServerEnvironmentKind.CombatCanary, options.ServerEnvironment);
        Assert.AreEqual(ReleaseChannel.Stable, options.Selection.Channel);
        Assert.AreSame(GraphicsProfileOption.SafeNative, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.ProfileDefault, options.Selection.WindowMode);
        Assert.IsTrue(options.Selection.PreserveForeground);
    }

    [TestMethod]
    public void Parse_RejectsCombatCanaryGraphicsOverride()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(
            [
                "--play",
                "--server-environment", "combat-canary",
                "--channel", "canary",
            ]));

        StringAssert.Contains(exception.Message, "sealed Native client");
    }

    [TestMethod]
    public void Parse_RejectsCombatCanarySafePlay()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(
            [
                "--safe-play",
                "--server-environment", "combat-canary",
            ]));

        StringAssert.Contains(exception.Message, "Stable server environment");
    }

    [TestMethod]
    public void Parse_RejectsUnknownServerEnvironment()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(
            [
                "--start-server",
                "--server-environment", "unknown",
            ]));

        StringAssert.Contains(exception.Message, "stable or combat-canary");
    }

    [TestMethod]
    public void Parse_RejectsPreserveForegroundValue()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(["--play", "--preserve-foreground=true"]));

        StringAssert.Contains(exception.Message, "does not accept a value");
    }

    [TestMethod]
    public void Parse_AcceptsLocalLabPlayShortcutContract()
    {
        var options = Parse(
        [
            "--play",
            "--channel", "local-lab",
            "--window-mode", "borderless",
            "--runtime-root", Canonical.RuntimeRoot,
        ]);

        Assert.AreEqual(ReleaseChannel.LocalLab, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.LocalLabWidescreen, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.Borderless, options.Selection.WindowMode);
    }

    [TestMethod]
    public void Parse_AcceptsExplicitPrivateHdProfile()
    {
        var options = Parse(
        [
            "--play",
            "--channel", "local-lab",
            "--profile", "lab-widescreen-hd-16x10",
            "--monitor", "primary-physical",
            "--window-mode", "borderless",
            "--runtime-root", Canonical.RuntimeRoot,
        ]);

        Assert.AreEqual(LauncherOperation.Play, options.Operation);
        Assert.AreEqual(ReleaseChannel.LocalLab, options.Selection.Channel);
        Assert.AreSame(GraphicsProfileOption.LocalLabWidescreenHd, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.Borderless, options.Selection.WindowMode);
    }

    [TestMethod]
    public void Parse_RejectsEvidenceOnlyCasProfile()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(
            [
                "--play",
                "--channel", "local-lab",
                "--profile", "lab-widescreen-cas-16x10",
            ]));

        StringAssert.Contains(exception.Message, "Unknown graphics profile");
    }

    [TestMethod]
    public void Parse_SafePlayForcesStableNativeProfile()
    {
        var options = Parse(["--safe-play"]);

        Assert.AreEqual(LauncherOperation.SafePlay, options.Operation);
        Assert.AreEqual(ServerEnvironmentKind.Stable, options.ServerEnvironment);
        Assert.AreEqual(ReleaseChannel.Stable, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.SafeNative, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.ProfileDefault, options.Selection.WindowMode);
    }

    [TestMethod]
    public void Parse_RejectsCredentialArguments()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(["--play", "--password", "not-allowed"]));

        StringAssert.Contains(exception.Message, "Credentials");
    }

    [TestMethod]
    public void Parse_RejectsMultipleLifecycleOperations()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => Parse(["--play", "--stop-all"]));

        StringAssert.Contains(exception.Message, "exactly one");
    }

    [TestMethod]
    public void Parse_RejectsProfileChannelMismatch()
    {
        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => Parse(
            [
                "--play",
                "--channel", "stable",
                "--profile", "fidelity-modern-16x10",
            ]));

        StringAssert.Contains(exception.Message, "requires the Canary channel");
    }

    [TestMethod]
    [DataRow("--start-server", LauncherOperation.StartServer)]
    [DataRow("--stop-server", LauncherOperation.StopServer)]
    [DataRow("--start-client", LauncherOperation.StartClient)]
    [DataRow("--stop-client", LauncherOperation.StopClient)]
    [DataRow("--stop-all", LauncherOperation.StopAll)]
    public void Parse_AcceptsCredentialFreeLifecycleOperations(
        string argument,
        LauncherOperation expected)
    {
        var options = Parse([argument]);

        Assert.AreEqual(expected, options.Operation);
        Assert.AreEqual(ServerEnvironmentKind.Stable, options.ServerEnvironment);
    }

    [TestMethod]
    public void Parse_AcceptsExplicitProfileMonitorAndResizableMode()
    {
        var options = Parse(
        [
            "--start-client",
            "--channel", "local-lab",
            "--profile", "lab-widescreen-16x10",
            "--monitor", "primary-physical",
            "--window-mode", "resizable",
        ]);

        Assert.AreEqual(LauncherOperation.StartClient, options.Operation);
        Assert.AreEqual(ReleaseChannel.LocalLab, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.LocalLabWidescreen, options.Selection.Profile);
        Assert.AreEqual(MonitorOption.PrimaryPhysical, options.Selection.Monitor);
        Assert.AreEqual(LauncherWindowMode.Resizable, options.Selection.WindowMode);
    }

    private LauncherOptions Parse(
        IReadOnlyList<string> arguments,
        string? configuredRuntimeRoot = null) =>
        LauncherCommandLine.ParseFromInstallationOrigin(
            arguments,
            Canonical.SourceBuildOrigin,
            configuredRuntimeRoot);
}
