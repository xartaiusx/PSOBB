using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class ProfileAndDiagnosticsTests
{
    [TestMethod]
    public void LaunchProfile_CreateForSafeModeForcesNativeAndFourByThree()
    {
        var profile = LaunchProfile.Create(
            ReleaseChannel.Canary,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DxvkVulkan),
            DisplayProfile.Primary,
            safeMode: true);

        Assert.AreEqual(RendererKind.NativeSafe, profile.Renderer.Kind);
        Assert.AreEqual(DisplayProfile.Safe, profile.Display);
        Assert.IsTrue(profile.SafeMode);
    }

    [TestMethod]
    public async Task ProfileContractWriter_WritesNormalizedProfileAtomically()
    {
        using var runtime = new TestRuntime();
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DgVoodooD3D12),
            DisplayProfile.Primary,
            safeMode: true);

        var path = await new ProfileContractWriter().WriteAsync(runtime.Root, profile);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(path));

        Assert.AreEqual("nativeSafe", json.RootElement.GetProperty("renderer").GetString());
        Assert.AreEqual(1024, json.RootElement.GetProperty("width").GetInt32());
        Assert.IsTrue(json.RootElement.GetProperty("safeMode").GetBoolean());
        Assert.IsEmpty(Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp-*"));
    }

    [TestMethod]
    public void DiagnosticReport_RedactsCredentialsAndIdentity()
    {
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var manifest = TestRuntime.CreateManifest(server, client);
        var verification = new ReleaseVerification(
        [
            new FileVerification("server", "server/newserv.exe", VerificationStatus.Verified, "SHA-256 verified."),
        ]);
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported[0],
            DisplayProfile.Safe,
            safeMode: true);
        var logs = new[]
        {
            "username: AdminUser password=CorrectHorseBattery",
            "Guild Card: 12345678 token='secret-token'",
            "account id = 98765",
            $"Loaded from {Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\\private",
        };

        var report = new DiagnosticReportBuilder().Build(
            manifest,
            profile,
            verification,
            [new PortHealth(11000, true, "Listening")],
            logs);

        Assert.DoesNotContain("AdminUser", report);
        Assert.DoesNotContain("CorrectHorseBattery", report);
        Assert.DoesNotContain("12345678", report);
        Assert.DoesNotContain("98765", report);
        Assert.DoesNotContain("secret-token", report);
        Assert.DoesNotContain(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), report);
        StringAssert.Contains(report, "[REDACTED]");
        StringAssert.Contains(report, "%USERPROFILE%");
    }

    [TestMethod]
    public async Task ProfileContractWriter_RecordsLifecycleSelectionWithoutCredentials()
    {
        using var runtime = new TestRuntime();
        var selection = LifecycleSelection.Create(
            ReleaseChannel.Canary,
            GraphicsProfileOption.ClarityDgVoodoo,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        var path = await new ProfileContractWriter().WriteAsync(
            runtime.Root,
            selection.ToLaunchProfile(),
            selection);
        var text = await File.ReadAllTextAsync(path);
        using var json = JsonDocument.Parse(text);

        Assert.AreEqual(2, json.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.AreEqual("clarity-dgvoodoo-4x3", json.RootElement.GetProperty("profileId").GetString());
        Assert.AreEqual("primary-physical", json.RootElement.GetProperty("monitorId").GetString());
        Assert.AreEqual("borderless", json.RootElement.GetProperty("windowMode").GetString());
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("username", text, StringComparison.OrdinalIgnoreCase);
    }
}
