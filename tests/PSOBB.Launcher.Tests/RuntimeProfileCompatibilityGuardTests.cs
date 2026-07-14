using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class RuntimeProfileCompatibilityGuardTests
{
    [TestMethod]
    public async Task ValidateAsync_AcceptsCurrentClarityContract()
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "canary/runtime/client/client-profile.json",
            """
            {
              "schemaVersion": 5,
              "renderer": "DgVoodooD3D11",
              "graphicsPreset": "Ultra3840x2880",
              "desktopWidth": 2560,
              "desktopHeight": 1600,
              "aspectPolicy": "preserve-4x3",
              "watermarkEnabled": false
            }
            """u8.ToArray());
        var selection = LifecycleSelection.Create(
            ReleaseChannel.Canary,
            GraphicsProfileOption.ClarityDgVoodoo,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        await new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, selection);
    }

    [TestMethod]
    public async Task ValidateAsync_RejectsSelectedProfileThatIsNotMaterialized()
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "canary/runtime/client/client-profile.json",
            """
            {
              "schemaVersion": 6,
              "profileId": "clarity-dgvoodoo-4x3",
              "renderer": "DgVoodooD3D11"
            }
            """u8.ToArray());
        var modern = LifecycleSelection.Create(
            ReleaseChannel.Canary,
            GraphicsProfileOption.Supported.Single(profile => profile.Id == "fidelity-modern-16x10"),
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        var exception = await Assert.ThrowsExactlyAsync<InvalidDataException>(
            () => new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, modern));

        StringAssert.Contains(exception.Message, "not materialized");
    }

    [TestMethod]
    public async Task ValidateAsync_RejectsWatermarkedClarityRuntime()
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "canary/runtime/client/client-profile.json",
            """
            {
              "renderer": "DgVoodooD3D11",
              "graphicsPreset": "Ultra3840x2880",
              "desktopWidth": 2560,
              "desktopHeight": 1600,
              "aspectPolicy": "preserve-4x3",
              "watermarkEnabled": true
            }
            """u8.ToArray());
        var selection = LifecycleSelection.Create(
            ReleaseChannel.Canary,
            GraphicsProfileOption.ClarityDgVoodoo,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        var exception = await Assert.ThrowsExactlyAsync<InvalidDataException>(
            () => new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, selection));

        StringAssert.Contains(exception.Message, "does not match");
    }

    [TestMethod]
    public async Task ValidateAsync_AcceptsExactLocalLabProfilePathAndChannel()
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "local-lab/runtime/client/client-profile.json",
            """
            {
              "schemaVersion": 6,
              "channel": "local-lab",
              "profileId": "lab-widescreen-16x10",
              "renderer": "DgVoodooD3D11"
            }
            """u8.ToArray());
        var selection = LifecycleSelection.Create(
            ReleaseChannel.LocalLab,
            GraphicsProfileOption.LocalLabWidescreen,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        await new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, selection);
    }

    [TestMethod]
    public async Task ValidateAsync_RejectsLocalLabProfileStoredOnWrongChannel()
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "local-lab/runtime/client/client-profile.json",
            """
            {
              "schemaVersion": 6,
              "channel": "canary",
              "profileId": "lab-widescreen-16x10",
              "renderer": "DgVoodooD3D11"
            }
            """u8.ToArray());
        var selection = LifecycleSelection.Create(
            ReleaseChannel.LocalLab,
            GraphicsProfileOption.LocalLabWidescreen,
            MonitorOption.PrimaryPhysical,
            LauncherWindowMode.Borderless);

        await Assert.ThrowsExactlyAsync<InvalidDataException>(
            () => new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, selection));
    }

    [TestMethod]
    public async Task ValidateAsync_AcceptsExactPrivateHdActivationProfile()
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "local-lab/runtime/client/client-profile.json",
            HdProfileBytes());
        var selection = HdSelection();

        await new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, selection);
    }

    [TestMethod]
    [DataRow(false, true, false)]
    [DataRow(true, false, false)]
    [DataRow(true, true, true)]
    public async Task ValidateAsync_RejectsIncompleteOrCasEnabledPrivateHdProfile(
        bool includeOverlay,
        bool includeModule,
        bool enableCas)
    {
        using var runtime = new TestRuntime();
        runtime.CreateFile(
            "local-lab/runtime/client/client-profile.json",
            HdProfileBytes(includeOverlay, includeModule, enableCas));
        var selection = HdSelection();

        var exception = await Assert.ThrowsExactlyAsync<InvalidDataException>(
            () => new RuntimeProfileCompatibilityGuard().ValidateAsync(runtime.Root, selection));

        StringAssert.Contains(exception.Message, "does not match");
    }

    private static LifecycleSelection HdSelection() => LifecycleSelection.Create(
        ReleaseChannel.LocalLab,
        GraphicsProfileOption.LocalLabWidescreenHd,
        MonitorOption.PrimaryPhysical,
        LauncherWindowMode.Borderless);

    private static byte[] HdProfileBytes(
        bool includeOverlay = true,
        bool includeModule = true,
        bool enableCas = false)
    {
        var overlay = includeOverlay
            ? """
              "localAssetOverlay": {
                "schemaVersion": 1,
                "componentId": "ashenbubs-hd-psobb-v1.02-local-import",
                "version": "1.02",
                "distributionClass": "local-only",
                "selection": "Characters",
                "baseProfileId": "lab-widescreen-16x10",
                "activationManifestPath": "asset-activations/ashenbubs-hd-psobb-v1.02/current/activation.json",
                "activationManifestSha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "sourceArchiveSha256": "cfe0fd182485e34d05f5d93b08580453a351ad7ba8ad35056d9167a412b2efea",
                "stagedManifestSha256": "2222222222222222222222222222222222222222222222222222222222222222",
                "snapshotId": "activation-20260714T123456789Z-deadbeef",
                "sourceEntryCount": 12,
                "composedFileCount": 12,
                "sourceExpandedAssetBytes": 444502016,
                "composedAssetBytes": 444502016
              },
              """
            : string.Empty;
        var modules = includeModule
            ? """
              "localModules": [
                {
                  "componentId": "project-owned-psobb-large-assets",
                  "capability": "large-assets-59nl",
                  "relativePath": "plugins/PSOBB.LargeAssets.asi",
                  "size": 230400,
                  "sha256": "bede4e0a9117a10c0b07a32712a04594604eea586dc779b1f81c34ae8a0b0bcf",
                  "configurationPath": "plugins/PSOBB.LargeAssets.ini",
                  "configurationSha256": "48f5777ef123c4ae6251727b762015431de422326832b5217ff71938b7e36e30",
                  "buildManifestSha256": "5efd70efd8e8b013b9a115bcc4cdaac882d24ac5e621f9510610b9142947379c"
                }
              ],
              """
            : string.Empty;
        var casStrength = enableCas ? "0.15" : "null";
        var casPath = enableCas ? "\"reshade-shaders/Shaders/PSOBB_NeutralCAS.fx\"" : "null";

        return Encoding.UTF8.GetBytes($$"""
            {
              "schemaVersion": 6,
              "channel": "local-lab",
              "profileId": "lab-widescreen-hd-16x10",
              "renderer": "DgVoodooD3D11",
              "outputApi": "d3d11_fl11_0",
              "baseExecutableSha256": "dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535",
              "desktopWidth": 2560,
              "desktopHeight": 1600,
              "aspectPolicy": "expand-horizontal-16x10",
              "watermarkEnabled": false,
              "redistributionClass": "local-only",
              "rollbackProfileId": "lab-widescreen-16x10",
              "casStrength": {{casStrength}},
              "reshadeConfigurationPath": null,
              "reshadeConfigurationSha256": null,
              "reshadeTemplatePath": null,
              "reshadeTemplateSha256": null,
              "reshadePresetPath": null,
              "reshadePresetSha256": null,
              "casShaderPath": {{casPath}},
              "casShaderSha256": null,
              {{overlay}}{{modules}}
              "builtAtUtc": "2026-07-14T12:34:56Z"
            }
            """);
    }
}
