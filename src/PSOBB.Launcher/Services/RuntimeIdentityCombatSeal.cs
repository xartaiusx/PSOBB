using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PSOBB.Launcher.Services;

internal sealed partial class ExactRuntimeIdentityProbe
{
    private async Task<CombatInstallationSeal> ReadCombatInstallationSealAsync(
        RuntimeEnvironmentContract contract,
        ApprovedFileIdentity approvedClient,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var installationFile = await ReadJsonFileAsync(
            contract.InstallationPath,
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var installation = installationFile.Document.RootElement;
        RequireExactProperties(
            installation,
            [
                "schemaVersion", "environment", "environmentId", "initializedAtUtc",
                "buildContractSha256", "serverReleaseManifestSha256",
                "baseClientManifestSha256", "clientBindingSha256", "snapshotDirectoryName",
                "snapshotId", "snapshotManifestSha256", "stateBindingSha256",
                "twillsContractSha256", "signingPublicKeySpkiSha256", "configurationSha256",
            ],
            "combat-canary installation record");
        RequiredDateTimeOffset(installation, "initializedAtUtc");
        if (RequiredInt32(installation, "schemaVersion") != 1
            || !RequiredString(installation, "environment").Equals("CombatCanary", StringComparison.Ordinal)
            || !RequiredString(installation, "environmentId").Equals("combat-canary", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The combat-canary installation record identity is invalid.");
        }

        var buildHash = RequiredSha256(installation, "buildContractSha256");
        var releaseHash = RequiredSha256(installation, "serverReleaseManifestSha256");
        var baseManifestHash = RequiredSha256(installation, "baseClientManifestSha256");
        var clientBindingHash = RequiredSha256(installation, "clientBindingSha256");
        var snapshotManifestHash = RequiredSha256(installation, "snapshotManifestSha256");
        var stateBindingHash = RequiredSha256(installation, "stateBindingSha256");
        var twillsHash = RequiredSha256(installation, "twillsContractSha256");
        var signingHash = RequiredSha256(installation, "signingPublicKeySpkiSha256");
        var configurationHash = RequiredSha256(installation, "configurationSha256");
        var snapshotDirectoryName = RequiredString(installation, "snapshotDirectoryName");
        if (!Regex.IsMatch(
                snapshotDirectoryName,
                "^twills-slot0-[0-9]{8}T[0-9]{9}Z-[a-f0-9]{8}$",
                RegexOptions.CultureInvariant)
            || !Guid.TryParseExact(RequiredString(installation, "snapshotId"), "D", out _))
        {
            throw new InvalidDataException("The combat-canary installation snapshot identity is invalid.");
        }

        await RequireFileHashAsync(
            Path.Combine(_repositoryRoot, "config", "combat-canary-build.json"),
            _repositoryRoot,
            buildHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        using (var buildFile = await ReadJsonFileAsync(
                   Path.Combine(_repositoryRoot, "config", "combat-canary-build.json"),
                   _repositoryRoot,
                   sealedFiles,
                   cancellationToken).ConfigureAwait(false))
        {
            if (RequiredInt32(buildFile.Document.RootElement, "schemaVersion") != 1
                || !RequiredString(buildFile.Document.RootElement, "profileId").Equals(
                    "newserv-combat-canary-build", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The tracked combat-canary build contract identity is invalid.");
            }
        }

        var twillsPath = Path.Combine(_repositoryRoot, "config", "twills-fonewearl-build.json");
        await RequireFileHashAsync(
            twillsPath,
            _repositoryRoot,
            twillsHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        using (var twillsFile = await ReadJsonFileAsync(
                   twillsPath,
                   _repositoryRoot,
                   sealedFiles,
                   cancellationToken).ConfigureAwait(false))
        {
            var twills = twillsFile.Document.RootElement;
            var character = RequiredObject(twills, "character");
            if (RequiredInt32(twills, "schemaVersion") != 2
                || !RequiredString(character, "name").Equals("Twills", StringComparison.Ordinal)
                || RequiredInt32(character, "classId") != 8
                || !RequiredString(character, "className").Equals("FOnewearl", StringComparison.Ordinal)
                || RequiredInt32(character, "slotIndex") != 0)
            {
                throw new InvalidDataException("The tracked combat-canary character contract is not slot-0 Twills FOnewearl.");
            }
        }

        var trustedFingerprint = await ReadTrustedSigningFingerprintAsync(
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        if (!signingHash.Equals(trustedFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The combat-canary signing fingerprint does not match release trust.");
        }

        await RequireFileHashAsync(
            Path.Combine(contract.ServerBaseRoot, "release-manifest.json"),
            contract.RuntimeRoot,
            releaseHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        await RequireFileHashAsync(
            Path.Combine(contract.EnvironmentRoot, "base-client.manifest.json"),
            contract.RuntimeRoot,
            baseManifestHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        await RequireFileHashAsync(
            contract.ClientBindingPath,
            contract.RuntimeRoot,
            clientBindingHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        await RequireFileHashAsync(
            Path.Combine(contract.EnvironmentRoot, "state-binding.json"),
            contract.RuntimeRoot,
            stateBindingHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        await RequireFileHashAsync(
            Path.Combine(contract.ServerRoot, "system", "config.json"),
            contract.RuntimeRoot,
            configurationHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);

        var snapshotRoot = Path.Combine(contract.EnvironmentRoot, "snapshots", snapshotDirectoryName);
        var snapshotManifestPath = Path.Combine(snapshotRoot, "manifest.json");
        await RequireFileHashAsync(
            snapshotManifestPath,
            contract.RuntimeRoot,
            snapshotManifestHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        await ValidateSnapshotSignatureAsync(
            snapshotRoot,
            snapshotManifestPath,
            signingHash,
            sealedFiles,
            contract.RuntimeRoot,
            cancellationToken).ConfigureAwait(false);
        await ValidateStateBindingAsync(
            contract,
            snapshotDirectoryName,
            RequiredString(installation, "snapshotId"),
            snapshotManifestHash,
            twillsHash,
            signingHash,
            stateBindingHash,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);

        foreach (var verifierSource in new[]
        {
            "scripts/PSOBB.Common.ps1",
            "scripts/PSOBB.CombatCanary.Common.ps1",
            "scripts/Test-PSOBBCombatCanary.ps1",
        })
        {
            await ReadFileAndTrackAsync(
                Path.Combine(_repositoryRoot, verifierSource.Replace('/', Path.DirectorySeparatorChar)),
                _repositoryRoot,
                MaximumIdentityFileBytes,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
        }
        await _contractVerifier.VerifyAsync(
            new(
                contract.RuntimeRoot,
                "CombatCanary",
                buildHash,
                twillsHash,
                signingHash),
            cancellationToken).ConfigureAwait(false);

        _ = approvedClient;
        return new(
            buildHash,
            clientBindingHash,
            stateBindingHash,
            baseManifestHash,
            twillsHash,
            signingHash);
    }

    private async Task ValidateStateBindingAsync(
        RuntimeEnvironmentContract contract,
        string snapshotDirectoryName,
        string snapshotId,
        string snapshotManifestSha256,
        string twillsContractSha256,
        string signingPublicKeySpkiSha256,
        string stateBindingSha256,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var stateFile = await ReadJsonFileAsync(
            Path.Combine(contract.EnvironmentRoot, "state-binding.json"),
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var state = stateFile.Document.RootElement;
        RequireExactProperties(
            state,
            [
                "schemaVersion", "environment", "environmentId", "restoredAtUtc",
                "snapshotDirectoryName", "snapshotId", "snapshotManifestSha256",
                "twillsContractSha256", "signingPublicKeySpkiSha256", "stateFiles",
            ],
            "combat-canary state binding");
        RequiredDateTimeOffset(state, "restoredAtUtc");
        if (!stateFile.Identity.Sha256.Equals(stateBindingSha256, StringComparison.Ordinal)
            || RequiredInt32(state, "schemaVersion") != 1
            || !RequiredString(state, "environment").Equals("CombatCanary", StringComparison.Ordinal)
            || !RequiredString(state, "environmentId").Equals("combat-canary", StringComparison.Ordinal)
            || !RequiredString(state, "snapshotDirectoryName").Equals(snapshotDirectoryName, StringComparison.Ordinal)
            || !RequiredString(state, "snapshotId").Equals(snapshotId, StringComparison.Ordinal)
            || !RequiredString(state, "snapshotManifestSha256").Equals(snapshotManifestSha256, StringComparison.Ordinal)
            || !RequiredString(state, "twillsContractSha256").Equals(twillsContractSha256, StringComparison.Ordinal)
            || !RequiredString(state, "signingPublicKeySpkiSha256").Equals(signingPublicKeySpkiSha256, StringComparison.Ordinal)
            || RequiredInt32(state, "stateFiles") <= 0)
        {
            throw new InvalidDataException("The combat-canary state binding is not exact.");
        }
    }

    private async Task ValidateSnapshotSignatureAsync(
        string snapshotRoot,
        string manifestPath,
        string expectedFingerprint,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        string runtimeRoot,
        CancellationToken cancellationToken)
    {
        var manifest = await ReadFileAndTrackAsync(
            manifestPath,
            runtimeRoot,
            MaximumIdentityJsonBytes,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var signature = await ReadFileAndTrackAsync(
            Path.Combine(snapshotRoot, "manifest.sig"),
            runtimeRoot,
            16 * 1024,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var publicKey = await ReadFileAndTrackAsync(
            Path.Combine(snapshotRoot, "trust", "signing-public-key.pem"),
            runtimeRoot,
            16 * 1024,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(Encoding.ASCII.GetString(signature.Bytes));
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The combat-canary snapshot signature is not valid Base64.", exception);
        }
        if (signatureBytes.Length != 64)
        {
            throw new InvalidDataException("The combat-canary snapshot signature is not P-256 P1363.");
        }

        using var verifier = ECDsa.Create();
        verifier.ImportFromPem(Encoding.UTF8.GetString(publicKey.Bytes));
        var fingerprint = Convert.ToHexString(SHA256.HashData(verifier.ExportSubjectPublicKeyInfo()))
            .ToLowerInvariant();
        if (!fingerprint.Equals(expectedFingerprint, StringComparison.Ordinal)
            || !verifier.VerifyData(
                manifest.Bytes,
                signatureBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new InvalidDataException("The combat-canary snapshot signature or trust pin is invalid.");
        }
    }

    private async Task<string> ReadTrustedSigningFingerprintAsync(
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var trustFile = await ReadJsonFileAsync(
            Path.Combine(_repositoryRoot, "config", "release-trust.json"),
            _repositoryRoot,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var trust = trustFile.Document.RootElement;
        var activeKeyId = RequiredString(trust, "activeKeyId");
        if (RequiredInt32(trust, "schemaVersion") != 1
            || !trust.TryGetProperty("keys", out var keys)
            || keys.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The release trust policy is invalid.");
        }
        var matches = keys.EnumerateArray()
            .Where(key => RequiredString(key, "id").Equals(activeKeyId, StringComparison.Ordinal))
            .ToArray();
        if (matches.Length != 1)
        {
            throw new InvalidDataException("The release trust policy does not identify one active key.");
        }
        return RequiredSha256(matches[0], "spkiSha256");
    }
}
