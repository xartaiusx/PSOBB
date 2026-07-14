using System.Text.Json;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class RuntimeProfileCompatibilityGuard
{
    private const long MaximumProfileBytes = 64 * 1024;
    private const string AshenbubsComponentId = "ashenbubs-hd-psobb-v1.02-local-import";
    private const string AshenbubsArchiveSha256 = "cfe0fd182485e34d05f5d93b08580453a351ad7ba8ad35056d9167a412b2efea";
    private const string BaseExecutableSha256 = "dd3d475916038e8e8e3f230cfad6d8d93a2976b1b42af0014413ff3b737c5535";
    private const string LargeAssetsComponentId = "project-owned-psobb-large-assets";
    private const string LargeAssetsSha256 = "bede4e0a9117a10c0b07a32712a04594604eea586dc779b1f81c34ae8a0b0bcf";
    private const string LargeAssetsConfigurationSha256 = "48f5777ef123c4ae6251727b762015431de422326832b5217ff71938b7e36e30";
    private const string LargeAssetsBuildManifestSha256 = "5efd70efd8e8b013b9a115bcc4cdaac882d24ac5e621f9510610b9142947379c";

    public async Task ValidateAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        ArgumentNullException.ThrowIfNull(selection);

        var relativePath = selection.Channel switch
        {
            ReleaseChannel.Stable => "stable/runtime/client/client-profile.json",
            ReleaseChannel.Canary => "canary/runtime/client/client-profile.json",
            ReleaseChannel.LocalLab => "local-lab/runtime/client/client-profile.json",
            _ => throw new ArgumentOutOfRangeException(nameof(selection)),
        };
        var path = SafePathResolver.ResolveWithinRoot(runtimeRoot, relativePath);
        var file = new FileInfo(path);
        if (!file.Exists)
        {
            throw new FileNotFoundException(
                $"The {selection.Channel} client profile is not materialized. Repair or build it before launch.",
                path);
        }

        if (file.Length is <= 0 or > MaximumProfileBytes)
        {
            throw new InvalidDataException("The materialized client profile has an invalid size.");
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;
        var renderer = RequiredString(root, "renderer");

        if (selection.Profile == GraphicsProfileOption.SafeNative)
        {
            if (!renderer.Equals("Native", StringComparison.Ordinal))
            {
                throw Mismatch(selection, renderer);
            }

            return;
        }

        if (selection.Profile == GraphicsProfileOption.ClarityDgVoodoo)
        {
            var preset = RequiredString(root, "graphicsPreset");
            var aspect = RequiredString(root, "aspectPolicy");
            var watermark = root.TryGetProperty("watermarkEnabled", out var watermarkElement)
                && watermarkElement.ValueKind == JsonValueKind.False;
            var correctDisplay = root.TryGetProperty("desktopWidth", out var width)
                && width.TryGetInt32(out var widthValue)
                && widthValue == 2560
                && root.TryGetProperty("desktopHeight", out var height)
                && height.TryGetInt32(out var heightValue)
                && heightValue == 1600;
            if (!renderer.Equals("DgVoodooD3D11", StringComparison.Ordinal)
                || !preset.Equals("Ultra3840x2880", StringComparison.Ordinal)
                || !aspect.Equals("preserve-4x3", StringComparison.Ordinal)
                || !watermark
                || !correctDisplay)
            {
                throw Mismatch(selection, renderer);
            }

            return;
        }

        var materializedId = root.TryGetProperty("profileId", out var profileId)
            ? profileId.GetString()
            : null;
        var materializedChannel = root.TryGetProperty("channel", out var channelElement)
            ? channelElement.GetString()
            : null;
        var expectedMaterializedChannel = selection.Channel switch
        {
            ReleaseChannel.LocalLab => "local-lab",
            ReleaseChannel.Canary => "canary",
            ReleaseChannel.Stable => "stable",
            _ => throw new ArgumentOutOfRangeException(nameof(selection)),
        };
        if (!selection.Profile.Id.Equals(materializedId, StringComparison.Ordinal)
            || !expectedMaterializedChannel.Equals(materializedChannel, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"Selected profile '{selection.Profile.Id}' is not materialized for {selection.Channel}; "
                + $"runtime reports profile '{materializedId ?? "no profile id"}' "
                + $"on channel '{materializedChannel ?? "no channel"}'.");
        }

        if (selection.Profile == GraphicsProfileOption.LocalLabWidescreenHd)
        {
            ValidateLocalLabHdProfile(root, renderer, selection);
        }
    }

    private static void ValidateLocalLabHdProfile(
        JsonElement root,
        string renderer,
        LifecycleSelection selection)
    {
        var exactDisplay = IntegerEquals(root, "desktopWidth", 2560)
            && IntegerEquals(root, "desktopHeight", 1600);
        var watermarkDisabled = root.TryGetProperty("watermarkEnabled", out var watermark)
            && watermark.ValueKind == JsonValueKind.False;
        var noCas = NullProperty(root, "casStrength")
            && NullProperty(root, "reshadeConfigurationPath")
            && NullProperty(root, "reshadeConfigurationSha256")
            && NullProperty(root, "reshadeTemplatePath")
            && NullProperty(root, "reshadeTemplateSha256")
            && NullProperty(root, "reshadePresetPath")
            && NullProperty(root, "reshadePresetSha256")
            && NullProperty(root, "casShaderPath")
            && NullProperty(root, "casShaderSha256");
        if (!renderer.Equals("DgVoodooD3D11", StringComparison.Ordinal)
            || !RequiredString(root, "outputApi").Equals("d3d11_fl11_0", StringComparison.Ordinal)
            || !RequiredString(root, "baseExecutableSha256").Equals(BaseExecutableSha256, StringComparison.Ordinal)
            || !RequiredString(root, "aspectPolicy").Equals("expand-horizontal-16x10", StringComparison.Ordinal)
            || !RequiredString(root, "rollbackProfileId").Equals("lab-widescreen-16x10", StringComparison.Ordinal)
            || !RequiredString(root, "redistributionClass").Equals("local-only", StringComparison.Ordinal)
            || !exactDisplay
            || !watermarkDisabled
            || !noCas
            || !ValidateLocalAssetOverlay(root)
            || !ValidateLargeAssetsModule(root))
        {
            throw Mismatch(selection, renderer);
        }
    }

    private static bool ValidateLocalAssetOverlay(JsonElement root)
    {
        if (!root.TryGetProperty("localAssetOverlay", out var overlay)
            || overlay.ValueKind != JsonValueKind.Object
            || !HasExactProperties(
                overlay,
                "schemaVersion",
                "componentId",
                "version",
                "distributionClass",
                "selection",
                "baseProfileId",
                "activationManifestPath",
                "activationManifestSha256",
                "sourceArchiveSha256",
                "stagedManifestSha256",
                "snapshotId",
                "sourceEntryCount",
                "composedFileCount",
                "sourceExpandedAssetBytes",
                "composedAssetBytes"))
        {
            return false;
        }

        var selection = RequiredString(overlay, "selection");
        return IntegerEquals(overlay, "schemaVersion", 1)
            && RequiredString(overlay, "componentId").Equals(AshenbubsComponentId, StringComparison.Ordinal)
            && RequiredString(overlay, "version").Equals("1.02", StringComparison.Ordinal)
            && RequiredString(overlay, "distributionClass").Equals("local-only", StringComparison.Ordinal)
            && selection is "Characters" or "Objects" or "Monsters" or "Maps" or "All"
            && RequiredString(overlay, "baseProfileId").Equals("lab-widescreen-16x10", StringComparison.Ordinal)
            && RequiredString(overlay, "activationManifestPath").Equals(
                "asset-activations/ashenbubs-hd-psobb-v1.02/current/activation.json",
                StringComparison.Ordinal)
            && RequiredString(overlay, "sourceArchiveSha256").Equals(AshenbubsArchiveSha256, StringComparison.Ordinal)
            && IsLowerSha256(RequiredString(overlay, "activationManifestSha256"))
            && IsLowerSha256(RequiredString(overlay, "stagedManifestSha256"))
            && IsActivationSnapshotId(RequiredString(overlay, "snapshotId"))
            && PositiveInteger(overlay, "sourceEntryCount")
            && PositiveInteger(overlay, "composedFileCount")
            && PositiveInt64(overlay, "sourceExpandedAssetBytes")
            && PositiveInt64(overlay, "composedAssetBytes");
    }

    private static bool ValidateLargeAssetsModule(JsonElement root)
    {
        if (!root.TryGetProperty("localModules", out var modules)
            || modules.ValueKind != JsonValueKind.Array
            || modules.GetArrayLength() != 1)
        {
            return false;
        }

        var module = modules[0];
        return module.ValueKind == JsonValueKind.Object
            && HasExactProperties(
                module,
                "componentId",
                "capability",
                "relativePath",
                "size",
                "sha256",
                "configurationPath",
                "configurationSha256",
                "buildManifestSha256")
            && RequiredString(module, "componentId").Equals(LargeAssetsComponentId, StringComparison.Ordinal)
            && RequiredString(module, "capability").Equals("large-assets-59nl", StringComparison.Ordinal)
            && RequiredString(module, "relativePath").Equals("plugins/PSOBB.LargeAssets.asi", StringComparison.Ordinal)
            && IntegerEquals(module, "size", 230400)
            && RequiredString(module, "sha256").Equals(LargeAssetsSha256, StringComparison.Ordinal)
            && RequiredString(module, "configurationPath").Equals("plugins/PSOBB.LargeAssets.ini", StringComparison.Ordinal)
            && RequiredString(module, "configurationSha256").Equals(LargeAssetsConfigurationSha256, StringComparison.Ordinal)
            && RequiredString(module, "buildManifestSha256").Equals(LargeAssetsBuildManifestSha256, StringComparison.Ordinal);
    }

    private static bool HasExactProperties(JsonElement element, params string[] expectedNames)
    {
        var actual = element.EnumerateObject().Select(property => property.Name).ToArray();
        return actual.Length == expectedNames.Length
            && actual.ToHashSet(StringComparer.Ordinal).SetEquals(expectedNames);
    }

    private static bool IntegerEquals(JsonElement root, string propertyName, int expected) =>
        root.TryGetProperty(propertyName, out var element)
        && element.ValueKind == JsonValueKind.Number
        && element.TryGetInt32(out var value)
        && value == expected;

    private static bool PositiveInteger(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var element)
        && element.ValueKind == JsonValueKind.Number
        && element.TryGetInt32(out var value)
        && value > 0;

    private static bool PositiveInt64(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var element)
        && element.ValueKind == JsonValueKind.Number
        && element.TryGetInt64(out var value)
        && value > 0;

    private static bool NullProperty(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var element) && element.ValueKind == JsonValueKind.Null;

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsActivationSnapshotId(string value) =>
        value.Length == 39
        && value.StartsWith("activation-", StringComparison.Ordinal)
        && value[19] == 'T'
        && value[29] == 'Z'
        && value[30] == '-'
        && value[11..19].All(char.IsDigit)
        && value[20..29].All(char.IsDigit)
        && value[31..].All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string RequiredString(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var element)
            || element.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(element.GetString()))
        {
            throw new InvalidDataException($"The materialized client profile is missing '{propertyName}'.");
        }

        return element.GetString()!;
    }

    private static InvalidDataException Mismatch(LifecycleSelection selection, string renderer) =>
        new(
            $"Selected profile '{selection.Profile.Id}' does not match the materialized {selection.Channel} "
            + $"client profile (renderer '{renderer}').");
}
