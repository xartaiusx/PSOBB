using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed partial class DiagnosticReportBuilder
{
    public string Build(
        ReleaseManifest manifest,
        LaunchProfile profile,
        ReleaseVerification verification,
        IReadOnlyList<PortHealth> portHealth,
        IEnumerable<string> serverLogLines,
        LifecycleSelection? selection = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(verification);
        ArgumentNullException.ThrowIfNull(portHealth);
        ArgumentNullException.ThrowIfNull(serverLogLines);

        var normalized = LaunchProfile.Create(profile.Channel, profile.Renderer, profile.Display, profile.SafeMode);
        var report = new StringBuilder();
        report.AppendLine("PSOBB Launcher sanitized diagnostic");
        report.Append("GeneratedUtc: ").AppendLine(DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        report.Append("LauncherRuntime: ").AppendLine(RuntimeInformation.FrameworkDescription);
        report.Append("OperatingSystem: ").AppendLine(RuntimeInformation.OSDescription);
        report.Append("Architecture: ").AppendLine(RuntimeInformation.ProcessArchitecture.ToString());
        report.Append("ReleaseId: ").AppendLine(manifest.ReleaseId);
        report.Append("Channel: ").AppendLine(manifest.Channel.ToString());
        report.Append("ProtocolRevision: ").AppendLine(manifest.ProtocolRevision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        report.Append("Renderer: ").AppendLine(normalized.Renderer.Kind.ToString());
        report.Append("Display: ")
            .Append(normalized.Display.Width)
            .Append('x')
            .Append(normalized.Display.Height)
            .Append(" HUD ")
            .AppendLine(normalized.Display.HudScale.ToString(System.Globalization.CultureInfo.InvariantCulture));
        report.Append("SafeMode: ").AppendLine(normalized.SafeMode ? "true" : "false");
        if (selection is not null)
        {
            report.Append("GraphicsProfile: ").AppendLine(selection.Profile.Id);
            report.Append("MonitorTarget: ").AppendLine(selection.Monitor.Id);
            report.Append("WindowMode: ").AppendLine(selection.WindowMode.ToString());
        }
        report.AppendLine();
        report.AppendLine("ArtifactVerification:");

        foreach (var file in verification.Files)
        {
            report.Append("- ")
                .Append(file.Id)
                .Append(": ")
                .Append(file.Status)
                .Append(" - ")
                .AppendLine(Sanitize(file.Detail));
        }

        report.AppendLine("LoopbackHealth:");
        foreach (var port in portHealth)
        {
            report.Append("- 127.0.0.1:")
                .Append(port.Port)
                .Append(": ")
                .Append(port.IsHealthy ? "healthy" : "unhealthy")
                .Append(" - ")
                .AppendLine(Sanitize(port.Detail));
        }

        report.AppendLine("ServerLogTail:");
        var anyLogLines = false;
        foreach (var line in serverLogLines.TakeLast(200))
        {
            anyLogLines = true;
            report.Append("- ").AppendLine(Sanitize(line));
        }

        if (!anyLogLines)
        {
            report.AppendLine("- No server log lines captured.");
        }

        return Sanitize(report.ToString());
    }

    public async Task ExportAsync(string destinationPath, string report, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        ArgumentNullException.ThrowIfNull(report);

        var fullPath = Path.GetFullPath(destinationPath);
        var parent = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("The diagnostic destination has no parent directory.");
        Directory.CreateDirectory(parent);

        await File.WriteAllTextAsync(fullPath, Sanitize(report), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken)
            .ConfigureAwait(false);
    }

    public string Sanitize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sanitized = SecretAssignment().Replace(value, match =>
            $"{match.Groups["keyquote"].Value}{match.Groups["key"].Value}{match.Groups["keyquote"].Value}" +
            $"{match.Groups["separator"].Value}{match.Groups["valuequote"].Value}[REDACTED]{match.Groups["valuequote"].Value}");
        sanitized = GuildCardNumber().Replace(sanitized, "[GUILD-CARD-REDACTED]");

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            sanitized = sanitized.Replace(userProfile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        }

        return sanitized;
    }

    [GeneratedRegex(
        "(?<keyquote>[\"'])?(?<key>(?i:password|passwd|token|secret|credential|username|account(?:\\s*id)?|license|guild\\s*card|guildcard))(?(keyquote)\\k<keyquote>)\\s*(?<separator>[:=])\\s*(?:(?<valuequote>\")[^\"\\r\\n]*\"|(?<valuequote>')[^'\\r\\n]*'|[^\\s,;}\\r\\n]+)",
        RegexOptions.CultureInvariant)]
    private static partial Regex SecretAssignment();

    [GeneratedRegex("(?i)(?:guild\\s*card|guildcard)\\D{0,8}\\d{6,16}", RegexOptions.CultureInvariant)]
    private static partial Regex GuildCardNumber();
}
