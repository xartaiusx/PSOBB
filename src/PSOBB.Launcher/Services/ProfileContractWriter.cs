using System.Text.Json;
using System.Text.Json.Serialization;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class ProfileContractWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public async Task<string> WriteAsync(
        string runtimeRoot,
        LaunchProfile profile,
        LifecycleSelection? selection = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        ArgumentNullException.ThrowIfNull(profile);

        var normalized = LaunchProfile.Create(profile.Channel, profile.Renderer, profile.Display, profile.SafeMode);
        var destination = SafePathResolver.ResolveWithinRoot(runtimeRoot, ".launcher/active-profile.json");
        var directory = Path.GetDirectoryName(destination)
            ?? throw new InvalidDataException("The active profile path has no parent directory.");
        Directory.CreateDirectory(directory);

        var contract = new ActiveProfileContract(
            SchemaVersion: 2,
            Channel: normalized.Channel,
            ProfileId: selection?.Profile.Id,
            Renderer: normalized.Renderer.Kind,
            Width: normalized.Display.Width,
            Height: normalized.Display.Height,
            HudScale: normalized.Display.HudScale,
            MonitorId: selection?.Monitor.Id,
            WindowMode: selection?.WindowMode ?? LauncherWindowMode.Borderless,
            SafeMode: normalized.SafeMode);

        var temporaryPath = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, contract, SerializerOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, destination, overwrite: true);
            return destination;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private sealed record ActiveProfileContract(
        int SchemaVersion,
        ReleaseChannel Channel,
        string? ProfileId,
        RendererKind Renderer,
        int Width,
        int Height,
        decimal HudScale,
        string? MonitorId,
        LauncherWindowMode WindowMode,
        bool SafeMode);
}
