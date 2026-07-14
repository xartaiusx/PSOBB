using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class ReleaseManifestServiceTests
{
    [TestMethod]
    public async Task LoadAsync_AcceptsStrictValidManifest()
    {
        using var runtime = new TestRuntime();
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var path = runtime.WriteManifest(TestRuntime.CreateManifest(server, client));

        var manifest = await new ReleaseManifestService().LoadAsync(path);

        Assert.AreEqual("test-stable-1", manifest.ReleaseId);
        Assert.AreEqual(ReleaseChannel.Stable, manifest.Channel);
        Assert.HasCount(2, manifest.Artifacts);
    }

    [TestMethod]
    public void Validate_RejectsTraversalDestination()
    {
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts[0] = new ReleaseArtifact
        {
            Id = "server",
            Destination = "../newserv.exe",
            Sha256 = TestRuntime.Hash(server),
            ByteSize = server.Length,
            License = "MIT",
        };

        var exception = Assert.ThrowsExactly<ManifestValidationException>(() => new ReleaseManifestService().Validate(manifest));
        StringAssert.Contains(exception.Message, "unsafe");
    }

    [TestMethod]
    public void Validate_RejectsNonHttpsSource()
    {
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts[0] = new ReleaseArtifact
        {
            Id = "server",
            SourceUrl = "http://example.invalid/newserv.exe",
            Destination = "server/newserv.exe",
            Sha256 = TestRuntime.Hash(server),
            ByteSize = server.Length,
            License = "MIT",
        };

        var exception = Assert.ThrowsExactly<ManifestValidationException>(() => new ReleaseManifestService().Validate(manifest));
        StringAssert.Contains(exception.Message, "HTTPS");
    }

    [TestMethod]
    public void Validate_RejectsCredentialsEmbeddedInSourceUrl()
    {
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts[0] = new ReleaseArtifact
        {
            Id = "server",
            SourceUrl = "https://user:password@example.invalid/newserv.exe",
            Destination = "server/newserv.exe",
            Sha256 = TestRuntime.Hash(server),
            ByteSize = server.Length,
            License = "MIT",
        };

        var exception = Assert.ThrowsExactly<ManifestValidationException>(() => new ReleaseManifestService().Validate(manifest));
        StringAssert.Contains(exception.Message, "embedded credentials");
    }

    [TestMethod]
    public async Task LoadAsync_RejectsUnknownJsonProperties()
    {
        using var runtime = new TestRuntime();
        var path = Path.Combine(runtime.Root, "release-manifest.json");
        await File.WriteAllTextAsync(path, """
            {
              "schemaVersion": 1,
              "releaseId": "test-stable-1",
              "channel": "stable",
              "protocolRevision": 1,
              "artifacts": [],
              "launch": {},
              "unexpected": true
            }
            """);

        var exception = await Assert.ThrowsExactlyAsync<InvalidDataException>(
            () => new ReleaseManifestService().LoadAsync(path));
        Assert.IsInstanceOfType<JsonException>(exception.InnerException);
    }

    [TestMethod]
    public void Validate_RejectsSecretBearingArguments()
    {
        var server = "server"u8.ToArray();
        var client = "client"u8.ToArray();
        var original = TestRuntime.CreateManifest(server, client);
        var manifest = new ReleaseManifest
        {
            SchemaVersion = original.SchemaVersion,
            ReleaseId = original.ReleaseId,
            Channel = original.Channel,
            ProtocolRevision = original.ProtocolRevision,
            Artifacts = original.Artifacts,
            Launch = new LaunchSettings
            {
                ServerExecutable = original.Launch.ServerExecutable,
                ClientExecutable = original.Launch.ClientExecutable,
                ServerArguments = ["--password=do-not-log-this"],
                HealthPorts = original.Launch.HealthPorts,
            },
        };

        var exception = Assert.ThrowsExactly<ManifestValidationException>(() => new ReleaseManifestService().Validate(manifest));
        StringAssert.Contains(exception.Message, "credentials or secrets");
    }

    [TestMethod]
    public async Task LoadAsync_RejectsNullCollectionsWithoutCrashing()
    {
        using var runtime = new TestRuntime();
        var path = Path.Combine(runtime.Root, "release-manifest.json");
        await File.WriteAllTextAsync(path, """
            {
              "schemaVersion": 1,
              "releaseId": "test-stable-1",
              "channel": "stable",
              "protocolRevision": 1,
              "artifacts": null,
              "launch": null
            }
            """);

        var exception = await Assert.ThrowsExactlyAsync<ManifestValidationException>(
            () => new ReleaseManifestService().LoadAsync(path));
        StringAssert.Contains(exception.Message, "artifacts");
    }
}
