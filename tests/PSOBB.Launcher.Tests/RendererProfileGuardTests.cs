using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class RendererProfileGuardTests
{
    [TestMethod]
    public void Validate_NativeSafeRejectsUndeclaredProxyDll()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/d3d8.dll", "unexpected"u8.ToArray());
        var manifest = TestRuntime.CreateManifest(server, client);
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.NativeSafe),
            DisplayProfile.Safe,
            safeMode: true);

        var exception = Assert.ThrowsExactly<InvalidDataException>(
            () => new RendererProfileGuard().Validate(manifest, runtime.Root, profile));

        StringAssert.Contains(exception.Message, "rejects renderer proxy DLLs");
    }

    [TestMethod]
    public void Validate_DgVoodooD3D11AcceptsExactManifestBoundOverlay()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var baseClient = "immutable-client"u8.ToArray();
        var wrapper = "approved-d3d8-wrapper"u8.ToArray();
        var configuration = CreateDgVoodooConfiguration("d3d11_fl11_0", "false");
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/base/psobb.exe", baseClient);
        runtime.CreateFile("client/d3d8.dll", wrapper);
        runtime.CreateFile("client/dgVoodoo.conf", configuration);
        var requiredBase = new RequiredBaseFile
        {
            Path = "client/base/psobb.exe",
            Sha256 = TestRuntime.Hash(baseClient),
            ByteSize = baseClient.Length,
        };
        var manifest = TestRuntime.CreateManifest(server, client, requiredBase);
        manifest.Artifacts.Add(CreateOverlayArtifact("wrapper", "client/d3d8.dll", wrapper, requiredBase));
        manifest.Artifacts.Add(CreateOverlayArtifact("configuration", "client/dgVoodoo.conf", configuration, requiredBase));
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DgVoodooD3D11),
            DisplayProfile.Primary,
            safeMode: false);

        new RendererProfileGuard().Validate(manifest, runtime.Root, profile);
    }

    [TestMethod]
    public void Validate_DgVoodooRequiresExactOutputApi()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var wrapper = "approved-d3d8-wrapper"u8.ToArray();
        var configuration = CreateDgVoodooConfiguration("bestavailable", "false");
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/d3d8.dll", wrapper);
        runtime.CreateFile("client/dgVoodoo.conf", configuration);
        var requiredBase = new RequiredBaseFile
        {
            Path = "client/psobb.exe",
            Sha256 = TestRuntime.Hash(client),
            ByteSize = client.Length,
        };
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts.Add(CreateOverlayArtifact("wrapper", "client/d3d8.dll", wrapper, requiredBase));
        manifest.Artifacts.Add(CreateOverlayArtifact("configuration", "client/dgVoodoo.conf", configuration, requiredBase));
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DgVoodooD3D11),
            DisplayProfile.Primary,
            safeMode: false);

        var exception = Assert.ThrowsExactly<InvalidDataException>(
            () => new RendererProfileGuard().Validate(manifest, runtime.Root, profile));

        StringAssert.Contains(exception.Message, "d3d11_fl11_0");
    }

    [TestMethod]
    public void Validate_DgVoodooRejectsEnabledWatermark()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var wrapper = "approved-d3d8-wrapper"u8.ToArray();
        var configuration = CreateDgVoodooConfiguration("d3d11_fl11_0", "true");
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/d3d8.dll", wrapper);
        runtime.CreateFile("client/dgVoodoo.conf", configuration);
        var requiredBase = new RequiredBaseFile
        {
            Path = "client/psobb.exe",
            Sha256 = TestRuntime.Hash(client),
            ByteSize = client.Length,
        };
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts.Add(CreateOverlayArtifact("wrapper", "client/d3d8.dll", wrapper, requiredBase));
        manifest.Artifacts.Add(CreateOverlayArtifact("configuration", "client/dgVoodoo.conf", configuration, requiredBase));
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DgVoodooD3D11),
            DisplayProfile.Safe,
            safeMode: false);

        var exception = Assert.ThrowsExactly<InvalidDataException>(
            () => new RendererProfileGuard().Validate(manifest, runtime.Root, profile));

        StringAssert.Contains(exception.Message, "DirectX/dgVoodooWatermark");
    }

    [TestMethod]
    public void Validate_DgVoodooRejectsMsaaInSupersamplingProfile()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var wrapper = "approved-d3d8-wrapper"u8.ToArray();
        var configuration = CreateDgVoodooConfiguration(
            "d3d11_fl11_0", "false", antialiasing: "4x");
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/d3d8.dll", wrapper);
        runtime.CreateFile("client/dgVoodoo.conf", configuration);
        var requiredBase = new RequiredBaseFile
        {
            Path = "client/psobb.exe",
            Sha256 = TestRuntime.Hash(client),
            ByteSize = client.Length,
        };
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts.Add(CreateOverlayArtifact("wrapper", "client/d3d8.dll", wrapper, requiredBase));
        manifest.Artifacts.Add(CreateOverlayArtifact("configuration", "client/dgVoodoo.conf", configuration, requiredBase));
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DgVoodooD3D11),
            DisplayProfile.Primary,
            safeMode: false);

        var exception = Assert.ThrowsExactly<InvalidDataException>(
            () => new RendererProfileGuard().Validate(manifest, runtime.Root, profile));

        StringAssert.Contains(exception.Message, "DirectX/Antialiasing");
    }

    [TestMethod]
    public void Validate_DgVoodooRejectsFilteringPointSampledTextures()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var wrapper = "approved-d3d8-wrapper"u8.ToArray();
        var configuration = CreateDgVoodooConfiguration(
            "d3d11_fl11_0", "false", keepFilterIfPointSampled: "false");
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/d3d8.dll", wrapper);
        runtime.CreateFile("client/dgVoodoo.conf", configuration);
        var requiredBase = new RequiredBaseFile
        {
            Path = "client/psobb.exe",
            Sha256 = TestRuntime.Hash(client),
            ByteSize = client.Length,
        };
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts.Add(CreateOverlayArtifact("wrapper", "client/d3d8.dll", wrapper, requiredBase));
        manifest.Artifacts.Add(CreateOverlayArtifact("configuration", "client/dgVoodoo.conf", configuration, requiredBase));
        var profile = LaunchProfile.Create(
            ReleaseChannel.Stable,
            RendererProfile.Supported.Single(renderer => renderer.Kind == RendererKind.DgVoodooD3D11),
            DisplayProfile.Primary,
            safeMode: false);

        var exception = Assert.ThrowsExactly<InvalidDataException>(
            () => new RendererProfileGuard().Validate(manifest, runtime.Root, profile));

        StringAssert.Contains(exception.Message, "DirectX/KeepFilterIfPointSampled");
    }

    private static byte[] CreateDgVoodooConfiguration(
        string outputApi,
        string watermark,
        string antialiasing = "off",
        string keepFilterIfPointSampled = "true") =>
        System.Text.Encoding.UTF8.GetBytes(
            $"[General]\r\n" +
            $"OutputAPI = {outputApi}\r\n" +
            "ScalingMode = stretched_ar\r\n" +
            "FullScreenMode = false\r\n" +
            "KeepWindowAspectRatio = true\r\n" +
            "CenterAppWindow = true\r\n" +
            "[GeneralExt]\r\n" +
            "DesktopResolution = 2560x1600\r\n" +
            "Resampling = lanczos-3\r\n" +
            "WindowedAttributes = borderless, fullscreensize\r\n" +
            "[DirectX]\r\n" +
            "Resolution = 3840x2880\r\n" +
            "Filtering = 16\r\n" +
            $"KeepFilterIfPointSampled = {keepFilterIfPointSampled}\r\n" +
            $"Antialiasing = {antialiasing}\r\n" +
            "AppControlledScreenMode = false\r\n" +
            "Bilinear2DOperations = false\r\n" +
            $"dgVoodooWatermark = {watermark}\r\n");

    private static ReleaseArtifact CreateOverlayArtifact(
        string id,
        string destination,
        byte[] content,
        RequiredBaseFile requiredBase) => new()
    {
        Id = id,
        SourceKind = ArtifactSourceKind.Remote,
        SourceUrl = "https://example.invalid/" + id,
        Channel = ReleaseChannel.Stable,
        ProtocolRevision = 1,
        Destination = destination,
        Sha256 = TestRuntime.Hash(content),
        ByteSize = content.Length,
        License = "dgVoodoo freeware license",
        Redistribution = "PSOBB-specific distribution only",
        RequiredBase = requiredBase,
        Rollback = new ArtifactRollback
        {
            Target = "native",
            Strategy = RollbackStrategy.NativeProfile,
        },
    };
}
