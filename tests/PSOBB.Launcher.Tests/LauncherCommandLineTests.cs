using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LauncherCommandLineTests
{
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
        using var runtime = new TestRuntime();

        var options = LauncherCommandLine.Parse(
        [
            "--play",
            "--channel", "canary",
            "--window-mode", "borderless",
            "--runtime-root", runtime.Root,
        ]);

        Assert.AreEqual(LauncherOperation.Play, options.Operation);
        Assert.AreEqual(ReleaseChannel.Canary, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.ClarityDgVoodoo, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.Borderless, options.Selection.WindowMode);
        Assert.AreEqual(Path.GetFullPath(runtime.Root), options.RuntimeRoot);
    }

    [TestMethod]
    public void Parse_AcceptsLocalLabPlayShortcutContract()
    {
        using var runtime = new TestRuntime();

        var options = LauncherCommandLine.Parse(
        [
            "--play",
            "--channel", "local-lab",
            "--window-mode", "borderless",
            "--runtime-root", runtime.Root,
        ]);

        Assert.AreEqual(ReleaseChannel.LocalLab, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.LocalLabWidescreen, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.Borderless, options.Selection.WindowMode);
    }

    [TestMethod]
    public void Parse_AcceptsExplicitPrivateHdProfile()
    {
        using var runtime = new TestRuntime();

        var options = LauncherCommandLine.Parse(
        [
            "--play",
            "--channel", "local-lab",
            "--profile", "lab-widescreen-hd-16x10",
            "--monitor", "primary-physical",
            "--window-mode", "borderless",
            "--runtime-root", runtime.Root,
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
            () => LauncherCommandLine.Parse(
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
        var options = LauncherCommandLine.Parse(["--safe-play"]);

        Assert.AreEqual(LauncherOperation.SafePlay, options.Operation);
        Assert.AreEqual(ReleaseChannel.Stable, options.Selection.Channel);
        Assert.AreEqual(GraphicsProfileOption.SafeNative, options.Selection.Profile);
        Assert.AreEqual(LauncherWindowMode.ProfileDefault, options.Selection.WindowMode);
    }

    [TestMethod]
    public void Parse_RejectsCredentialArguments()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => LauncherCommandLine.Parse(["--play", "--password", "not-allowed"]));

        StringAssert.Contains(exception.Message, "Credentials");
    }

    [TestMethod]
    public void Parse_RejectsMultipleLifecycleOperations()
    {
        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => LauncherCommandLine.Parse(["--play", "--stop-all"]));

        StringAssert.Contains(exception.Message, "exactly one");
    }

    [TestMethod]
    public void Parse_RejectsProfileChannelMismatch()
    {
        var exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => LauncherCommandLine.Parse(
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
        var options = LauncherCommandLine.Parse([argument]);

        Assert.AreEqual(expected, options.Operation);
    }

    [TestMethod]
    public void Parse_AcceptsExplicitProfileMonitorAndResizableMode()
    {
        var options = LauncherCommandLine.Parse(
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
}
