using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class RendererProfileGuard
{
    private static readonly string[] ProxyFileNames = ["d3d8.dll", "d3d9.dll", "ddraw.dll", "dxgi.dll"];

    public void Validate(ReleaseManifest manifest, string runtimeRoot, LaunchProfile profile)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        ArgumentNullException.ThrowIfNull(profile);

        var normalized = LaunchProfile.Create(profile.Channel, profile.Renderer, profile.Display, profile.SafeMode);
        var clientExecutable = SafePathResolver.ResolveWithinRoot(runtimeRoot, manifest.Launch.ClientExecutable);
        var clientDirectory = Path.GetDirectoryName(clientExecutable)
            ?? throw new InvalidDataException("The client executable has no parent directory.");
        var presentProxies = ProxyFileNames
            .Where(fileName => File.Exists(Path.Combine(clientDirectory, fileName)))
            .ToArray();

        if (normalized.Renderer.Kind == RendererKind.NativeSafe)
        {
            if (presentProxies.Length != 0)
            {
                throw new InvalidDataException(
                    $"Native safe mode rejects renderer proxy DLLs: {string.Join(", ", presentProxies)}.");
            }

            return;
        }

        if (normalized.Renderer.Kind == RendererKind.DxvkVulkan)
        {
            throw new NotSupportedException(
                "DXVK is not an acquired, manifest-approved PSOBB renderer and remains canary-only.");
        }

        if (normalized.Renderer.Kind == RendererKind.DgVoodooD3D12
            && normalized.Channel != ReleaseChannel.Canary)
        {
            throw new InvalidDataException("The dgVoodoo D3D12 backend is canary-only.");
        }

        if (presentProxies.Length != 1
            || !presentProxies[0].Equals("d3d8.dll", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "A dgVoodoo profile requires exactly one local renderer proxy: d3d8.dll.");
        }

        var wrapperPath = Path.Combine(clientDirectory, "d3d8.dll");
        var configurationPath = Path.Combine(clientDirectory, "dgVoodoo.conf");
        if (!File.Exists(configurationPath))
        {
            throw new FileNotFoundException("The manifest-approved dgVoodoo configuration is missing.", configurationPath);
        }

        var clientDestination = NormalizeRelativePath(manifest.Launch.ClientExecutable);
        var wrapperDestination = NormalizeRelativePath(Path.GetRelativePath(runtimeRoot, wrapperPath));
        var configurationDestination = NormalizeRelativePath(Path.GetRelativePath(runtimeRoot, configurationPath));
        var clientArtifact = FindSingleArtifact(manifest, clientDestination, "client executable");
        var wrapperArtifact = FindSingleArtifact(manifest, wrapperDestination, "dgVoodoo wrapper");
        var configurationArtifact = FindSingleArtifact(manifest, configurationDestination, "dgVoodoo configuration");

        var approvedBase = clientArtifact.RequiredBase ?? new RequiredBaseFile
        {
            Path = clientArtifact.Destination,
            Sha256 = clientArtifact.Sha256,
            ByteSize = clientArtifact.ByteSize,
        };
        ValidateRequiredBase(wrapperArtifact, approvedBase, "dgVoodoo wrapper");
        ValidateRequiredBase(configurationArtifact, approvedBase, "dgVoodoo configuration");

        var expectedOutputApi = normalized.Renderer.Kind switch
        {
            RendererKind.DgVoodooD3D11 => "d3d11_fl11_0",
            RendererKind.DgVoodooD3D12 => "d3d12_fl11_0",
            _ => throw new NotSupportedException($"Unsupported renderer profile {normalized.Renderer.Kind}."),
        };
        ValidateIniValue(configurationPath, "General", "OutputAPI", expectedOutputApi);
        ValidateIniValue(configurationPath, "DirectX", "dgVoodooWatermark", "false");

        if (normalized.Display.Id == DisplayProfile.Primary.Id)
        {
            ValidateIniValue(configurationPath, "General", "ScalingMode", "stretched_ar");
            ValidateIniValue(configurationPath, "General", "FullScreenMode", "false");
            ValidateIniValue(configurationPath, "General", "KeepWindowAspectRatio", "true");
            ValidateIniValue(configurationPath, "General", "CenterAppWindow", "true");
            ValidateIniValue(configurationPath, "GeneralExt", "DesktopResolution", "2560x1600");
            ValidateIniValue(configurationPath, "GeneralExt", "Resampling", "lanczos-3");
            ValidateIniValue(configurationPath, "GeneralExt", "WindowedAttributes", "borderless, fullscreensize");
            ValidateIniValue(configurationPath, "DirectX", "Resolution", "3840x2880");
            ValidateIniValue(configurationPath, "DirectX", "Filtering", "16");
            ValidateIniValue(configurationPath, "DirectX", "KeepFilterIfPointSampled", "true");
            ValidateIniValue(configurationPath, "DirectX", "Antialiasing", "off");
            ValidateIniValue(configurationPath, "DirectX", "AppControlledScreenMode", "false");
            ValidateIniValue(configurationPath, "DirectX", "Bilinear2DOperations", "false");
        }
    }

    private static ReleaseArtifact FindSingleArtifact(
        ReleaseManifest manifest,
        string destination,
        string description)
    {
        var matches = manifest.Artifacts
            .Where(artifact => NormalizeRelativePath(artifact.Destination)
                .Equals(destination, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return matches.Length == 1
            ? matches[0]
            : throw new InvalidDataException(
                $"The release manifest must declare exactly one {description} artifact at {destination}.");
    }

    private static void ValidateRequiredBase(
        ReleaseArtifact artifact,
        RequiredBaseFile approvedBase,
        string description)
    {
        var requiredBase = artifact.RequiredBase;
        if (requiredBase is null
            || !NormalizeRelativePath(requiredBase.Path).Equals(
                NormalizeRelativePath(approvedBase.Path),
                StringComparison.OrdinalIgnoreCase)
            || !requiredBase.Sha256.Equals(approvedBase.Sha256, StringComparison.OrdinalIgnoreCase)
            || requiredBase.ByteSize != approvedBase.ByteSize)
        {
            throw new InvalidDataException(
                $"The {description} artifact is not bound to the exact approved client base.");
        }
    }

    private static void ValidateIniValue(
        string configurationPath,
        string section,
        string key,
        string expectedValue)
    {
        var currentSection = string.Empty;
        var values = new List<string>();
        foreach (var rawLine in File.ReadLines(configurationPath))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = line[1..^1];
                continue;
            }
            if (!currentSection.Equals(section, StringComparison.Ordinal)
                || line.Length == 0
                || line.StartsWith(';'))
            {
                continue;
            }
            var parts = line.Split('=', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && parts[0].Equals(key, StringComparison.Ordinal))
            {
                values.Add(parts[1]);
            }
        }

        if (values.Count != 1 || !values[0].Equals(expectedValue, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"dgVoodoo.conf must set exactly one approved {section}/{key} value: {expectedValue}.");
        }
    }

    private static string NormalizeRelativePath(string path) => path.Replace('\\', '/').Trim('/');
}
