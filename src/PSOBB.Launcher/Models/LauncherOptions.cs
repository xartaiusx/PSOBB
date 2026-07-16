using System.Text.RegularExpressions;

namespace PSOBB.Launcher.Models;

public enum LauncherOperation
{
    Gui,
    Play,
    SafePlay,
    StartServer,
    StopServer,
    StartClient,
    StopClient,
    StopAll,
}

public sealed record LauncherOptions(
    LauncherOperation Operation,
    string RuntimeRoot,
    string ManifestPath,
    LifecycleSelection Selection)
{
    public static LauncherOptions Defaults()
    {
        return Defaults(ResolveDefaultRuntimeRoot());
    }

    internal static LauncherOptions Defaults(string runtimeRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);

        var profile = GraphicsProfileOption.SafeNative;
        return new(
            LauncherOperation.Gui,
            Path.GetFullPath(runtimeRoot),
            Path.Combine(Path.GetFullPath(runtimeRoot), "stable", "release-manifest.json"),
            LifecycleSelection.Create(
                ReleaseChannel.Stable,
                profile,
                MonitorOption.PrimaryPhysical,
                LauncherWindowMode.ProfileDefault));
    }

    internal static string ResolveDefaultRuntimeRoot(
        string? configured = null,
        IEnumerable<string>? origins = null)
    {
        configured ??= Environment.GetEnvironmentVariable("PSOBB_RUNTIME_ROOT");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured);
        }

        origins ??= [AppContext.BaseDirectory, Environment.CurrentDirectory];
        foreach (var origin in origins)
        {
            var cursor = new DirectoryInfo(Path.GetFullPath(origin));
            for (var depth = 0; cursor is not null && depth < 12; depth++, cursor = cursor.Parent)
            {
                if (string.Equals(cursor.Name, "PSOBB-Runtime", StringComparison.OrdinalIgnoreCase))
                {
                    return cursor.FullName;
                }

                if (File.Exists(Path.Combine(cursor.FullName, "scripts", "Start-PSOBB.ps1")))
                {
                    return Path.Combine(
                        cursor.Parent?.FullName ?? cursor.FullName,
                        "PSOBB-Runtime");
                }
            }
        }

        throw new InvalidOperationException(
            "Could not locate the adjacent PSOBB-Runtime directory. Use --runtime-root " +
            "or set PSOBB_RUNTIME_ROOT explicitly.");
    }
}

public static partial class LauncherCommandLine
{
    public static LauncherOptions Parse(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        var explicitRuntimeRoot = FindExplicitRuntimeRoot(arguments);
        var defaults = explicitRuntimeRoot is null
            ? LauncherOptions.Defaults()
            : LauncherOptions.Defaults(explicitRuntimeRoot);
        var operation = LauncherOperation.Gui;
        var operationWasSet = false;
        var runtimeRoot = defaults.RuntimeRoot;
        var manifestPath = defaults.ManifestPath;
        ReleaseChannel? channel = null;
        string? profileId = null;
        string? monitorId = null;
        LauncherWindowMode? windowMode = null;
        var preserveForeground = false;

        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (string.IsNullOrWhiteSpace(argument) || !argument.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException("Launcher arguments must use named --options; positional values are not accepted.");
            }

            var separator = argument.IndexOf('=');
            var option = (separator < 0 ? argument : argument[..separator]).ToLowerInvariant();
            var inlineValue = separator < 0 ? null : argument[(separator + 1)..];
            if (SensitiveOption().IsMatch(option))
            {
                throw new ArgumentException("Credentials and identity values are never valid launcher arguments.");
            }

            switch (option)
            {
                case "--play":
                    SetOperation(LauncherOperation.Play);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--safe-play":
                    SetOperation(LauncherOperation.SafePlay);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--start-server":
                    SetOperation(LauncherOperation.StartServer);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--stop-server":
                    SetOperation(LauncherOperation.StopServer);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--start-client":
                    SetOperation(LauncherOperation.StartClient);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--stop-client":
                    SetOperation(LauncherOperation.StopClient);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--stop-all":
                    SetOperation(LauncherOperation.StopAll);
                    RequireNoValue(option, inlineValue);
                    break;
                case "--runtime-root":
                    runtimeRoot = ReadValue(option, inlineValue, arguments, ref index);
                    break;
                case "--manifest":
                    manifestPath = ReadValue(option, inlineValue, arguments, ref index);
                    break;
                case "--channel":
                    channel = ParseChannel(ReadValue(option, inlineValue, arguments, ref index));
                    break;
                case "--profile":
                    profileId = ReadIdentifier(option, inlineValue, arguments, ref index);
                    break;
                case "--monitor":
                    monitorId = ReadIdentifier(option, inlineValue, arguments, ref index);
                    break;
                case "--window-mode":
                    windowMode = ParseWindowMode(ReadValue(option, inlineValue, arguments, ref index));
                    break;
                case "--preserve-foreground":
                    preserveForeground = true;
                    RequireNoValue(option, inlineValue);
                    break;
                default:
                    throw new ArgumentException($"Unknown launcher option '{option}'.");
            }
        }

        if (operation == LauncherOperation.SafePlay)
        {
            if ((channel is not null && channel != ReleaseChannel.Stable)
                || (profileId is not null
                    && !profileId.Equals(GraphicsProfileOption.SafeNative.Id, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("--safe-play cannot be combined with a non-stable channel or non-safe profile.");
            }

            channel = ReleaseChannel.Stable;
            profileId = GraphicsProfileOption.SafeNative.Id;
            windowMode = LauncherWindowMode.ProfileDefault;
        }

        var selectedChannel = channel ?? defaults.Selection.Channel;
        var selectedProfile = profileId is null
            ? DefaultProfile(selectedChannel)
            : GraphicsProfileOption.Supported.SingleOrDefault(
                candidate => candidate.Id.Equals(profileId, StringComparison.OrdinalIgnoreCase))
                ?? throw new ArgumentException($"Unknown graphics profile '{profileId}'.");
        var selectedMonitor = monitorId is null
            ? MonitorOption.PrimaryPhysical
            : MonitorOption.Supported.SingleOrDefault(
                candidate => candidate.Id.Equals(monitorId, StringComparison.OrdinalIgnoreCase))
                ?? throw new ArgumentException($"Unknown or ineligible monitor target '{monitorId}'.");

        return new(
            operation,
            Path.GetFullPath(runtimeRoot),
            Path.GetFullPath(manifestPath),
            LifecycleSelection.Create(
                selectedChannel,
                selectedProfile,
                selectedMonitor,
                windowMode ?? defaults.Selection.WindowMode,
                preserveForeground));

        void SetOperation(LauncherOperation selected)
        {
            if (operationWasSet)
            {
                throw new ArgumentException("Choose exactly one launcher operation.");
            }

            operation = selected;
            operationWasSet = true;
        }
    }

    private static GraphicsProfileOption DefaultProfile(ReleaseChannel channel) => channel switch
    {
        ReleaseChannel.Stable => GraphicsProfileOption.SafeNative,
        ReleaseChannel.Canary => GraphicsProfileOption.ClarityDgVoodoo,
        ReleaseChannel.LocalLab => GraphicsProfileOption.LocalLabWidescreen,
        _ => throw new ArgumentOutOfRangeException(nameof(channel)),
    };

    private static ReleaseChannel ParseChannel(string value) => value.ToLowerInvariant() switch
    {
        "stable" => ReleaseChannel.Stable,
        "canary" => ReleaseChannel.Canary,
        "local-lab" => ReleaseChannel.LocalLab,
        _ => throw new ArgumentException("--channel must be stable, canary, or local-lab."),
    };

    private static LauncherWindowMode ParseWindowMode(string value) => value.ToLowerInvariant() switch
    {
        "profile-default" => LauncherWindowMode.ProfileDefault,
        "borderless" => LauncherWindowMode.Borderless,
        "resizable" => LauncherWindowMode.Resizable,
        _ => throw new ArgumentException("--window-mode must be profile-default, borderless, or resizable."),
    };

    private static string ReadIdentifier(
        string option,
        string? inlineValue,
        IReadOnlyList<string> arguments,
        ref int index)
    {
        var value = ReadValue(option, inlineValue, arguments, ref index);
        return Identifier().IsMatch(value)
            ? value
            : throw new ArgumentException($"{option} must contain only ASCII letters, numbers, periods, underscores, or hyphens.");
    }

    private static string? FindExplicitRuntimeRoot(IReadOnlyList<string> arguments)
    {
        string? value = null;
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (string.Equals(argument, "--runtime-root", StringComparison.OrdinalIgnoreCase))
            {
                if (index + 1 < arguments.Count)
                {
                    value = arguments[index + 1];
                    index++;
                }
                continue;
            }

            const string prefix = "--runtime-root=";
            if (argument.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                value = argument[prefix.Length..];
            }
        }

        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string ReadValue(
        string option,
        string? inlineValue,
        IReadOnlyList<string> arguments,
        ref int index)
    {
        var value = inlineValue;
        if (value is null)
        {
            if (++index >= arguments.Count)
            {
                throw new ArgumentException($"{option} requires a value.");
            }

            value = arguments[index];
        }

        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))
        {
            throw new ArgumentException($"{option} requires one non-empty value without control characters.");
        }

        return value;
    }

    private static void RequireNoValue(string option, string? inlineValue)
    {
        if (inlineValue is not null)
        {
            throw new ArgumentException($"{option} does not accept a value.");
        }
    }

    [GeneratedRegex("(?i)^--(?:password|passwd|token|secret|credential|username|account|license|guildcard)")]
    private static partial Regex SensitiveOption();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    private static partial Regex Identifier();
}
