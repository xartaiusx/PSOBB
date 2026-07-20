using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

internal sealed partial class ExactRuntimeIdentityProbe
{
    private static readonly string[] Schema5ProfileProperties =
    [
        "schemaVersion", "builtAtUtc", "channel", "profileId", "nativeGraphics",
        "renderer", "baseExecutableSha256", "wrapperSha256",
        "sourceConfigurationSha256", "configurationSha256", "outputApi",
        "graphicsPreset", "desktopWidth", "desktopHeight", "renderWidth",
        "renderHeight", "aspectPolicy", "resamplingFilter", "textureFilterPolicy",
        "edgeSmoothingPolicy", "bilinear2DOperations", "defaultWindowMode",
        "resizableClientWidth", "resizableClientHeight", "watermarkEnabled",
        "compatibilityFirst",
    ];
    private static readonly string[] Schema7ProfileProperties =
    [
        "schemaVersion", "builtAtUtc", "channel", "profileId", "renderer", "outputApi",
        "baseExecutableSha256", "configurationSha256", "widescreenConfigurationPath",
        "widescreenConfigurationSha256", "widescreenIniPath", "widescreenIniSha256",
        "enhancementConfigurationPath", "enhancementConfigurationSha256",
        "reshadeConfigurationPath", "reshadeConfigurationSha256", "reshadeTemplatePath",
        "reshadeTemplateSha256", "reshadePresetPath", "reshadePresetSha256",
        "casShaderPath", "casShaderSha256", "casStrength", "desktopWidth",
        "desktopHeight", "renderWidth", "renderHeight", "aspectPolicy",
        "defaultWindowMode", "presentationOwner", "resizableClientWidth",
        "resizableClientHeight", "scalingFilter", "msaa", "virtualVramMb",
        "vsyncOwner", "nativeGraphics", "hudScale", "watermarkEnabled",
        "redistributionClass", "rollbackProfileId",
    ];
    private static readonly HashSet<string> OptionalSchema7ProfileProperties =
        new(StringComparer.Ordinal)
        {
            "localAssetOverlay",
            "localModules",
            "localVisualAssets",
        };

    private async Task<ClientValidation> ValidateClientsAsync(
        RuntimeEnvironmentContract contract,
        IReadOnlyList<RuntimeProcessIdentity> clients,
        ApprovedFileIdentity approvedClient,
        CombatInstallationSeal? combatSeal,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        if (clients.Count == 0)
        {
            return new(true, false, string.Empty);
        }
        if (clients.Count != 1)
        {
            return new(false, true, "Exactly one selected-environment PSOBB client process is allowed.");
        }

        var process = clients[0];
        var clientContract = contract.Clients.SingleOrDefault(candidate =>
            PathsEqual(candidate.ExecutablePath, process.ExecutablePath));
        if (clientContract is null || process.ProcessId <= 0 || process.StartTimeUtc == default)
        {
            return new(false, true, "A named PSOBB client does not match one exact selected-environment client path and live identity.");
        }

        try
        {
            await RequireFileIdentityAsync(
                clientContract.ExecutablePath,
                contract.RuntimeRoot,
                approvedClient,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            var profile = await ValidateClientProfileAsync(
                contract,
                clientContract,
                approvedClient,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            string? clientBindingSha256 = null;
            if (contract.ServerEnvironment == ServerEnvironmentKind.CombatCanary)
            {
                if (combatSeal is null)
                {
                    return new(false, true, "The combat-canary installation seal is absent.");
                }
                clientBindingSha256 = await ValidateCombatClientBindingAsync(
                    contract,
                    approvedClient,
                    profile,
                    combatSeal,
                    sealedFiles,
                    cancellationToken).ConfigureAwait(false);
            }

            await ValidateClientStartupReceiptAsync(
                contract,
                clientContract,
                process,
                approvedClient,
                profile,
                clientBindingSha256,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            if (contract.ServerEnvironment == ServerEnvironmentKind.Stable)
            {
                foreach (var verifierSource in new[]
                {
                    "scripts/PSOBB.Common.ps1",
                    "scripts/Test-PSOBBClientGraphics.ps1",
                })
                {
                    await ReadFileAndTrackAsync(
                        Path.Combine(
                            _repositoryRoot,
                            verifierSource.Replace('/', Path.DirectorySeparatorChar)),
                        _repositoryRoot,
                        MaximumIdentityFileBytes,
                        sealedFiles,
                        cancellationToken).ConfigureAwait(false);
                }
                var verifierChannel = profile.Channel switch
                {
                    "stable" => "Stable",
                    "canary" => "Canary",
                    "local-lab" => "LocalLab",
                    _ => throw new InvalidDataException("The Stable client verifier channel is unsupported."),
                };
                await _contractVerifier.VerifyAsync(
                    new(contract.RuntimeRoot, verifierChannel),
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new(false, true, $"The selected client identity could not be authenticated: {exception.Message}");
        }

        return new(true, true, string.Empty);
    }

    private async Task<ClientProfileSeal> ValidateClientProfileAsync(
        RuntimeEnvironmentContract contract,
        RuntimeClientContract client,
        ApprovedFileIdentity approvedClient,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var profileFile = await ReadJsonFileAsync(
            client.ProfilePath,
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var profile = profileFile.Document.RootElement;
        var schemaVersion = RequiredInt32(profile, "schemaVersion");
        var channel = RequiredString(profile, "channel");
        var profileId = RequiredString(profile, "profileId");
        var expectedChannel = client.Channel;
        if (!channel.Equals(expectedChannel, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The materialized profile channel does not match its exact client path.");
        }

        if (schemaVersion == 5)
        {
            RequireExactProperties(profile, Schema5ProfileProperties, "schema-5 materialized client profile");
        }
        else if (schemaVersion == 7 && channel.Equals("local-lab", StringComparison.Ordinal))
        {
            RequireSchema7Properties(profile);
        }
        else
        {
            throw new InvalidDataException("The materialized client profile schema is not launchable.");
        }

        RequiredDateTimeOffset(profile, "builtAtUtc");
        if (!RequiredString(profile, "baseExecutableSha256").Equals(
                approvedClient.Sha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The materialized client profile is not bound to the approved executable.");
        }

        using var catalogFile = await ReadJsonFileAsync(
            Path.Combine(_repositoryRoot, "config", "graphics-profiles.json"),
            _repositoryRoot,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var catalog = catalogFile.Document.RootElement;
        if (RequiredInt32(catalog, "schemaVersion") != 1
            || !catalog.TryGetProperty("profiles", out var catalogProfiles)
            || catalogProfiles.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The tracked graphics profile catalog is invalid.");
        }
        var matches = catalogProfiles.EnumerateArray()
            .Where(candidate => RequiredString(candidate, "id").Equals(profileId, StringComparison.Ordinal))
            .ToArray();
        var catalogChannel = channel.Equals("combat-canary", StringComparison.Ordinal)
            ? "stable"
            : channel;
        if (matches.Length != 1
            || !RequiredString(matches[0], "channel").Equals(catalogChannel, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The materialized profile is not declared exactly once for its channel.");
        }

        var expectedRenderer = ExpectedRenderer(matches[0]);
        var renderer = RequiredString(profile, "renderer");
        if (!renderer.Equals(expectedRenderer, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The materialized renderer differs from the tracked profile owner.");
        }
        ValidateNativeGraphics(
            RequiredObject(profile, "nativeGraphics"),
            RequiredObject(matches[0], "nativeGraphics"));

        var configurationSha256 = RequiredNullableSha256(profile, "configurationSha256");
        if (schemaVersion == 5)
        {
            await ValidateSchema5ProfileFilesAsync(
                contract,
                client,
                profile,
                renderer,
                configurationSha256,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await ValidateSchema7ProfileFilesAsync(
                contract,
                client,
                profile,
                configurationSha256,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
        }

        return new(
            channel,
            profileId,
            profileFile.Identity.Sha256,
            configurationSha256,
            RequiredString(RequiredObject(profile, "nativeGraphics"), "presetId"),
            RequiredString(RequiredObject(profile, "nativeGraphics"), "graphicCtrlSha256"));
    }

    private async Task ValidateSchema5ProfileFilesAsync(
        RuntimeEnvironmentContract contract,
        RuntimeClientContract client,
        JsonElement profile,
        string renderer,
        string? configurationSha256,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        RequiredNullableInt32(profile, "desktopWidth");
        RequiredNullableInt32(profile, "desktopHeight");
        RequiredNullableScalar(profile, "renderWidth", JsonValueKind.Number, JsonValueKind.String);
        RequiredNullableScalar(profile, "renderHeight", JsonValueKind.Number, JsonValueKind.String);
        RequiredNullableString(profile, "aspectPolicy");
        RequiredNullableString(profile, "resamplingFilter");
        RequiredNullableString(profile, "textureFilterPolicy");
        RequiredNullableString(profile, "edgeSmoothingPolicy");
        RequiredNullableBoolean(profile, "bilinear2DOperations");
        RequiredNullableString(profile, "defaultWindowMode");
        RequiredNullableInt32(profile, "resizableClientWidth");
        RequiredNullableInt32(profile, "resizableClientHeight");
        RequiredNullableBoolean(profile, "watermarkEnabled");
        RequiredBoolean(profile, "compatibilityFirst");

        var wrapperSha256 = RequiredNullableSha256(profile, "wrapperSha256");
        var sourceConfigurationSha256 = RequiredNullableSha256(profile, "sourceConfigurationSha256");
        var outputApi = RequiredNullableString(profile, "outputApi");
        var graphicsPreset = RequiredString(profile, "graphicsPreset");
        if (renderer.Equals("Native", StringComparison.Ordinal))
        {
            if (wrapperSha256 is not null
                || sourceConfigurationSha256 is not null
                || configurationSha256 is not null
                || outputApi is not null
                || !graphicsPreset.Equals("Native", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The Native materialized profile contains a proxy or configuration seal.");
            }
            return;
        }

        if (wrapperSha256 is null || configurationSha256 is null || outputApi is null)
        {
            throw new InvalidDataException("The non-Native profile is missing its wrapper or configuration binding.");
        }
        await RequireFileHashAsync(
            Path.Combine(Path.GetDirectoryName(client.ExecutablePath)!, "d3d8.dll"),
            contract.RuntimeRoot,
            wrapperSha256,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        await RequireFileHashAsync(
            Path.Combine(Path.GetDirectoryName(client.ExecutablePath)!, "dgVoodoo.conf"),
            contract.RuntimeRoot,
            configurationSha256,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task ValidateSchema7ProfileFilesAsync(
        RuntimeEnvironmentContract contract,
        RuntimeClientContract client,
        JsonElement profile,
        string? configurationSha256,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        if (configurationSha256 is null)
        {
            throw new InvalidDataException("The schema-7 profile is missing its renderer configuration seal.");
        }
        var clientRoot = Path.GetDirectoryName(client.ExecutablePath)!;
        var renderer = RequiredString(profile, "renderer");
        var configurationName = renderer.Equals("DgVoodooD3D11", StringComparison.Ordinal)
            ? "dgVoodoo.conf"
            : renderer.Equals("DxvkVulkan", StringComparison.Ordinal)
                ? "dxvk.conf"
                : "d3d8to9.ini";
        await RequireFileHashAsync(
            Path.Combine(clientRoot, configurationName),
            contract.RuntimeRoot,
            configurationSha256,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);

        foreach (var pair in new[]
        {
            ("widescreenConfigurationPath", "widescreenConfigurationSha256"),
            ("widescreenIniPath", "widescreenIniSha256"),
            ("enhancementConfigurationPath", "enhancementConfigurationSha256"),
            ("reshadeConfigurationPath", "reshadeConfigurationSha256"),
            ("reshadeTemplatePath", "reshadeTemplateSha256"),
            ("reshadePresetPath", "reshadePresetSha256"),
            ("casShaderPath", "casShaderSha256"),
        })
        {
            var relativePath = RequiredNullableString(profile, pair.Item1);
            var sha256 = RequiredNullableSha256(profile, pair.Item2);
            if ((relativePath is null) != (sha256 is null))
            {
                throw new InvalidDataException($"The schema-7 profile has an incomplete {pair.Item1} binding.");
            }
            if (relativePath is not null)
            {
                await RequireFileHashAsync(
                    SafeRelativePath(clientRoot, relativePath),
                    contract.RuntimeRoot,
                    sha256!,
                    sealedFiles,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        RequiredNullableNumber(profile, "casStrength");
        RequiredInt32(profile, "desktopWidth");
        RequiredInt32(profile, "desktopHeight");
        RequiredNullableScalar(profile, "renderWidth", JsonValueKind.Number, JsonValueKind.String);
        RequiredNullableScalar(profile, "renderHeight", JsonValueKind.Number, JsonValueKind.String);
        RequiredString(profile, "aspectPolicy");
        RequiredString(profile, "defaultWindowMode");
        RequiredString(profile, "presentationOwner");
        RequiredInt32(profile, "resizableClientWidth");
        RequiredInt32(profile, "resizableClientHeight");
        RequiredString(profile, "scalingFilter");
        RequiredScalar(profile, "msaa", JsonValueKind.Number, JsonValueKind.String);
        RequiredNullableInt32(profile, "virtualVramMb");
        RequiredString(profile, "vsyncOwner");
        RequiredNullableNumber(profile, "hudScale");
        if (RequiredBoolean(profile, "watermarkEnabled"))
        {
            throw new InvalidDataException("The schema-7 profile unexpectedly enables a watermark.");
        }
        RequiredString(profile, "redistributionClass");
        RequiredNullableString(profile, "rollbackProfileId");
    }

    private async Task<string> ValidateCombatClientBindingAsync(
        RuntimeEnvironmentContract contract,
        ApprovedFileIdentity approvedClient,
        ClientProfileSeal profile,
        CombatInstallationSeal installation,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var bindingFile = await ReadJsonFileAsync(
            contract.ClientBindingPath,
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken).ConfigureAwait(false);
        var binding = bindingFile.Document.RootElement;
        RequireExactProperties(
            binding,
            [
                "schemaVersion", "environment", "environmentId", "profile", "renderer",
                "serverAddress", "patchPort", "gamePorts", "clientExecutablePath",
                "clientExecutableSize", "clientExecutableSha256", "clientProfileSha256",
                "baseClientManifestSha256", "createdAtUtc",
            ],
            "combat-canary client binding");
        RequiredDateTimeOffset(binding, "createdAtUtc");
        if (bindingFile.Identity.Sha256 != installation.ClientBindingSha256
            || RequiredInt32(binding, "schemaVersion") != 1
            || !RequiredString(binding, "environment").Equals("CombatCanary", StringComparison.Ordinal)
            || !RequiredString(binding, "environmentId").Equals("combat-canary", StringComparison.Ordinal)
            || !RequiredString(binding, "profile").Equals("baseline", StringComparison.Ordinal)
            || !RequiredString(binding, "renderer").Equals("Native", StringComparison.Ordinal)
            || !RequiredString(binding, "serverAddress").Equals("127.0.0.1", StringComparison.Ordinal)
            || RequiredInt32(binding, "patchPort") != 11000
            || !ExactGamePorts(binding)
            || !RequiredString(binding, "clientExecutablePath").Equals("runtime/client/Psobb.exe", StringComparison.Ordinal)
            || RequiredInt64(binding, "clientExecutableSize") != approvedClient.Size
            || !RequiredString(binding, "clientExecutableSha256").Equals(approvedClient.Sha256, StringComparison.Ordinal)
            || !RequiredString(binding, "clientProfileSha256").Equals(profile.ProfileSha256, StringComparison.Ordinal)
            || !RequiredString(binding, "baseClientManifestSha256").Equals(
                installation.BaseClientManifestSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The combat-canary client binding is not exact or installation-sealed.");
        }
        return bindingFile.Identity.Sha256;
    }

    private async Task ValidateClientStartupReceiptAsync(
        RuntimeEnvironmentContract contract,
        RuntimeClientContract client,
        RuntimeProcessIdentity process,
        ApprovedFileIdentity approvedClient,
        ClientProfileSeal profile,
        string? clientBindingSha256,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        var receiptName = process.StartTimeUtc.UtcDateTime.ToString(
            "yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture) + $"-{process.ProcessId}.json";
        var receiptPath = Path.Combine(contract.LogsRoot, "client-startup", receiptName);
        using var receiptFile = await ReadJsonFileAsync(
            receiptPath,
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken,
            protectedAclScope: ProtectedRuntimeAclScope.ExactFileAndProducerBoundary)
            .ConfigureAwait(false);
        var receipt = receiptFile.Document.RootElement;
        RequireExactProperties(
            receipt,
            [
                "schemaVersion", "completedAtUtc", "serverEnvironment", "environmentId",
                "channel", "profileId", "materializedProfileSha256", "configurationSha256",
                "processId", "processStartTimeUtc", "processStartTimeFileTimeUtc",
                "executableSize", "executableSha256",
                "clientBindingSha256", "startupElapsedMilliseconds", "foregroundPreserved",
                "windowMode", "window", "nativeGraphicsPresetId", "graphicCtrlSha256",
            ],
            "client startup receipt");
        RequiredDateTimeOffset(receipt, "completedAtUtc");
        RequiredDateTimeOffset(receipt, "processStartTimeUtc");
        var receiptProfileId = RequiredNullableString(receipt, "profileId");
        var expectedReceiptChannel = profile.Channel switch
        {
            "stable" => "Stable",
            "canary" => "Canary",
            "local-lab" => "LocalLab",
            "combat-canary" => "Native",
            _ => throw new InvalidDataException("The materialized profile channel is unsupported."),
        };
        if (RequiredInt32(receipt, "schemaVersion") != 3
            || !RequiredString(receipt, "serverEnvironment").Equals(contract.EnvironmentName, StringComparison.Ordinal)
            || !RequiredString(receipt, "environmentId").Equals(contract.EnvironmentId, StringComparison.Ordinal)
            || !RequiredString(receipt, "channel").Equals(expectedReceiptChannel, StringComparison.Ordinal)
            || receiptProfileId is null
            || !receiptProfileId.Equals(profile.ProfileId, StringComparison.Ordinal)
            || !RequiredString(receipt, "materializedProfileSha256").Equals(profile.ProfileSha256, StringComparison.Ordinal)
            || !NullableTextEquals(RequiredNullableSha256(receipt, "configurationSha256"), profile.ConfigurationSha256)
            || RequiredInt32(receipt, "processId") != process.ProcessId
            || RequiredInt64(receipt, "processStartTimeFileTimeUtc") !=
                process.StartTimeFileTimeUtc
            || RequiredInt64(receipt, "executableSize") != approvedClient.Size
            || !RequiredString(receipt, "executableSha256").Equals(approvedClient.Sha256, StringComparison.Ordinal)
            || !NullableTextEquals(RequiredNullableSha256(receipt, "clientBindingSha256"), clientBindingSha256)
            || RequiredNumber(receipt, "startupElapsedMilliseconds") < 0
            || !RequiredString(receipt, "nativeGraphicsPresetId").Equals(profile.NativeGraphicsPresetId, StringComparison.Ordinal)
            || !RequiredString(receipt, "graphicCtrlSha256").Equals(profile.GraphicCtrlSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The unique client startup receipt does not bind the live process and materialized profile.");
        }
        RequiredBoolean(receipt, "foregroundPreserved");
        RequiredString(receipt, "windowMode");
        ValidateReceiptWindow(RequiredObject(receipt, "window"));
        _ = client;
    }

    private static string SafeRelativePath(string root, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath)
            || Path.IsPathRooted(relativePath)
            || relativePath.Contains(':', StringComparison.Ordinal))
        {
            throw new InvalidDataException("A materialized profile contains an unsafe relative path.");
        }
        return EnsureSafePath(root, Path.Combine(root, relativePath.Replace('/', '\\')), mustExist: true);
    }

    private static void RequireSchema7Properties(JsonElement profile)
    {
        var actual = profile.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        var required = Schema7ProfileProperties.ToHashSet(StringComparer.Ordinal);
        if (!required.IsSubsetOf(actual)
            || actual.Any(name => !required.Contains(name) && !OptionalSchema7ProfileProperties.Contains(name)))
        {
            throw new InvalidDataException("The schema-7 materialized profile has an incomplete or unknown property set.");
        }
        foreach (var optional in OptionalSchema7ProfileProperties.Where(actual.Contains))
        {
            var kind = profile.GetProperty(optional).ValueKind;
            if (kind is not (JsonValueKind.Object or JsonValueKind.Array))
            {
                throw new InvalidDataException($"The schema-7 optional '{optional}' property has an invalid type.");
            }
        }
    }

    private static string ExpectedRenderer(JsonElement catalogProfile)
    {
        var owner = RequiredObject(RequiredObject(catalogProfile, "renderer"), "d3d8Owner");
        var component = RequiredNullableString(owner, "componentId");
        return component switch
        {
            null => "Native",
            "dgvoodoo2-x86-d3d8" => "DgVoodooD3D11",
            "dxvk-x86-d3d8-d3d9" => "DxvkVulkan",
            "d3d8to9-x86" => "D3D8To9",
            _ => throw new InvalidDataException("The tracked graphics profile has an unknown renderer owner."),
        };
    }

    private static void ValidateNativeGraphics(JsonElement actual, JsonElement expected)
    {
        var properties = new[]
        {
            "presetId", "graphicCtrlDwords", "graphicCtrlSha256", "advancedEffectsPolicy",
            "pixelFogPolicy", "lowResolutionTexturesPolicy", "frameSkipPolicy",
        };
        RequireExactProperties(actual, properties, "materialized native graphics contract");
        RequireExactProperties(expected, properties, "tracked native graphics contract");
        var actualDwords = RequiredUInt32Array(actual, "graphicCtrlDwords", 9);
        var expectedDwords = RequiredUInt32Array(expected, "graphicCtrlDwords", 9);
        var bytes = new byte[36];
        for (var index = 0; index < actualDwords.Length; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(index * 4, 4), actualDwords[index]);
        }
        var actualHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!actualHash.Equals(RequiredSha256(actual, "graphicCtrlSha256"), StringComparison.Ordinal)
            || !actualDwords.SequenceEqual(expectedDwords))
        {
            throw new InvalidDataException("The materialized native graphics DWORD contract is invalid.");
        }
        foreach (var property in properties.Where(property => property != "graphicCtrlDwords"))
        {
            if (!RequiredString(actual, property).Equals(RequiredString(expected, property), StringComparison.Ordinal))
            {
                throw new InvalidDataException($"The materialized native graphics '{property}' value drifted from the tracked catalog.");
            }
        }
    }

    private static void ValidateReceiptWindow(JsonElement window)
    {
        RequireExactProperties(
            window,
            ["x", "y", "width", "height", "clientWidth", "clientHeight"],
            "client startup receipt window");
        foreach (var property in window.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.Null && !property.Value.TryGetInt32(out _))
            {
                throw new InvalidDataException("The client startup receipt window has an invalid coordinate type.");
            }
        }
    }
}
