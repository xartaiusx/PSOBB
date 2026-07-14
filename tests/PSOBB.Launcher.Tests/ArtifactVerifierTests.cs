using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class ArtifactVerifierTests
{
    [TestMethod]
    public async Task VerifyAsync_VerifiesArtifactsAndRequiredBase()
    {
        using var runtime = new TestRuntime();
        var server = "server-binary"u8.ToArray();
        var client = "client-binary"u8.ToArray();
        var baseClient = "immutable-base"u8.ToArray();
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        runtime.CreateFile("client/base/psobb.exe", baseClient);
        var manifest = TestRuntime.CreateManifest(server, client, new RequiredBaseFile
        {
            Path = "client/base/psobb.exe",
            Sha256 = TestRuntime.Hash(baseClient),
            ByteSize = baseClient.Length,
        });

        var result = await new ArtifactVerifier().VerifyAsync(manifest, runtime.Root);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(3, result.Files);
        Assert.IsTrue(result.Files.All(file => file.Status == VerificationStatus.Verified));
    }

    [TestMethod]
    public async Task VerifyAsync_RejectsHashMismatch()
    {
        using var runtime = new TestRuntime();
        var server = "server-binary"u8.ToArray();
        var client = "client-binary"u8.ToArray();
        runtime.CreateFile("server/newserv.exe", "tampered-binary"u8.ToArray());
        runtime.CreateFile("client/psobb.exe", client);
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts[0] = new ReleaseArtifact
        {
            Id = "server",
            Destination = "server/newserv.exe",
            Sha256 = TestRuntime.Hash(server),
            ByteSize = "tampered-binary"u8.Length,
            License = "MIT",
        };

        var result = await new ArtifactVerifier().VerifyAsync(manifest, runtime.Root);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(VerificationStatus.HashMismatch, result.Files.Single(file => file.Id == "server").Status);
    }

    [TestMethod]
    public async Task VerifyAsync_RejectsSizeMismatchBeforeHashing()
    {
        using var runtime = new TestRuntime();
        var server = "server-binary"u8.ToArray();
        var client = "client-binary"u8.ToArray();
        runtime.CreateFile("server/newserv.exe", server);
        runtime.CreateFile("client/psobb.exe", client);
        var manifest = TestRuntime.CreateManifest(server, client);
        manifest.Artifacts[0] = new ReleaseArtifact
        {
            Id = "server",
            Destination = "server/newserv.exe",
            Sha256 = TestRuntime.Hash(server),
            ByteSize = server.Length + 1,
            License = "MIT",
        };

        var result = await new ArtifactVerifier().VerifyAsync(manifest, runtime.Root);

        Assert.AreEqual(VerificationStatus.SizeMismatch, result.Files.Single(file => file.Id == "server").Status);
    }
}
