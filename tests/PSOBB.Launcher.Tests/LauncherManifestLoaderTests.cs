using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LauncherManifestLoaderTests
{
    [TestMethod]
    public async Task LoadAsync_LabelsLocalManifestUnsignedWhenNoTrustedKeyIsPackaged()
    {
        using var runtime = new TestRuntime();
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));

        var result = await new LauncherManifestLoader(
            new ReleaseManifestService(),
            allowUnsignedLocalDevelopment: true).LoadAsync(
            manifestPath,
            runtime.Root);

        Assert.AreEqual(ManifestTrustMode.UnsignedLocalDevelopment, result.TrustMode);
    }

    [TestMethod]
    public async Task LoadAsync_RequiresAndVerifiesSignatureWhenTrustedKeyIsPackaged()
    {
        using var runtime = new TestRuntime();
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));
        await File.WriteAllTextAsync(
            Path.Combine(runtime.Root, LauncherManifestLoader.TrustedPublicKeyFileName),
            signer.ExportSubjectPublicKeyInfoPem());
        var fingerprint = Convert.ToHexString(
            SHA256.HashData(signer.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        var signature = signer.SignData(
            await File.ReadAllBytesAsync(manifestPath),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await File.WriteAllTextAsync(manifestPath + ".sig", Convert.ToBase64String(signature));

        var result = await new LauncherManifestLoader(new ReleaseManifestService(), fingerprint).LoadAsync(
            manifestPath,
            runtime.Root);

        Assert.AreEqual(ManifestTrustMode.VerifiedDetachedSignature, result.TrustMode);
    }

    [TestMethod]
    public async Task LoadAsync_BlocksUnsignedManifestWhenTrustedKeyIsPackaged()
    {
        using var runtime = new TestRuntime();
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));
        await File.WriteAllTextAsync(
            Path.Combine(runtime.Root, LauncherManifestLoader.TrustedPublicKeyFileName),
            signer.ExportSubjectPublicKeyInfoPem());

        var fingerprint = Convert.ToHexString(
            SHA256.HashData(signer.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        await Assert.ThrowsExactlyAsync<FileNotFoundException>(() =>
            new LauncherManifestLoader(new ReleaseManifestService(), fingerprint).LoadAsync(manifestPath, runtime.Root));
    }

    [TestMethod]
    public async Task LoadAsync_RejectsReplacedPackagedTrustKey()
    {
        using var runtime = new TestRuntime();
        using var trusted = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));
        await File.WriteAllTextAsync(
            Path.Combine(runtime.Root, LauncherManifestLoader.TrustedPublicKeyFileName),
            replacement.ExportSubjectPublicKeyInfoPem());
        var trustedFingerprint = Convert.ToHexString(
            SHA256.HashData(trusted.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

        var exception = await Assert.ThrowsExactlyAsync<InvalidDataException>(() =>
            new LauncherManifestLoader(new ReleaseManifestService(), trustedFingerprint).LoadAsync(manifestPath, runtime.Root));

        StringAssert.Contains(exception.Message, "compiled trust anchor");
    }
}
