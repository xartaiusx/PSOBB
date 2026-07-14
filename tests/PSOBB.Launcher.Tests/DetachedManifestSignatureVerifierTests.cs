using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class DetachedManifestSignatureVerifierTests
{
    [TestMethod]
    public async Task LoadSignedAsync_AcceptsExactManifestBytesSignedByTrustedP256Key()
    {
        using var runtime = new TestRuntime();
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));
        var manifestBytes = await File.ReadAllBytesAsync(manifestPath);
        var signature = signer.SignData(
            manifestBytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var signaturePath = Path.Combine(runtime.Root, "release-manifest.json.sig");
        await File.WriteAllTextAsync(signaturePath, Convert.ToBase64String(signature));

        var manifest = await new ReleaseManifestService().LoadSignedAsync(
            manifestPath,
            signaturePath,
            signer.ExportSubjectPublicKeyInfoPem());

        Assert.AreEqual("test-stable-1", manifest.ReleaseId);
    }

    [TestMethod]
    public async Task ReadAndVerifyAsync_RejectsManifestChangedAfterSigning()
    {
        using var runtime = new TestRuntime();
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));
        var signature = signer.SignData(
            await File.ReadAllBytesAsync(manifestPath),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var signaturePath = Path.Combine(runtime.Root, "release-manifest.json.sig");
        await File.WriteAllTextAsync(signaturePath, Convert.ToBase64String(signature));
        await File.AppendAllTextAsync(manifestPath, " ");

        await Assert.ThrowsExactlyAsync<CryptographicException>(() =>
            new DetachedManifestSignatureVerifier().ReadAndVerifyAsync(
                manifestPath,
                signaturePath,
                signer.ExportSubjectPublicKeyInfoPem()));
    }

    [TestMethod]
    public async Task ReadAndVerifyAsync_RejectsNonP256TrustedKey()
    {
        using var runtime = new TestRuntime();
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var manifestPath = runtime.WriteManifest(TestRuntime.CreateManifest("server"u8.ToArray(), "client"u8.ToArray()));
        var signature = signer.SignData(
            await File.ReadAllBytesAsync(manifestPath),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var signaturePath = Path.Combine(runtime.Root, "release-manifest.json.sig");
        await File.WriteAllTextAsync(signaturePath, Convert.ToBase64String(signature));

        await Assert.ThrowsExactlyAsync<InvalidDataException>(() =>
            new DetachedManifestSignatureVerifier().ReadAndVerifyAsync(
                manifestPath,
                signaturePath,
                signer.ExportSubjectPublicKeyInfoPem()));
    }
}
