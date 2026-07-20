using System.Text.RegularExpressions;
using PSOBB.Launcher.Services;

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
    ServerEnvironmentKind ServerEnvironment,
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
            ServerEnvironmentKind.Stable,
            LifecycleSelection.Create(
                ReleaseChannel.Stable,
                profile,
                MonitorOption.PrimaryPhysical,
                LauncherWindowMode.ProfileDefault));
    }

    internal static string ResolveDefaultRuntimeRoot()
    {
        var layout = new CanonicalLifecycleInstallationResolver().Resolve();
        return RequireExactConfiguredRuntimeRoot(
            layout.RuntimeRoot,
            Environment.GetEnvironmentVariable("PSOBB_RUNTIME_ROOT"));
    }

    internal static string ResolveDefaultRuntimeRoot(
        string installationOrigin,
        string? configuredRuntimeRoot)
    {
        var layout = new CanonicalLifecycleInstallationResolver()
            .ResolveFromOrigin(installationOrigin);
        return RequireExactConfiguredRuntimeRoot(layout.RuntimeRoot, configuredRuntimeRoot);
    }

    internal static string RequireExactConfiguredRuntimeRoot(
        string canonicalRuntimeRoot,
        string? configuredRuntimeRoot)
    {
        if (string.IsNullOrWhiteSpace(configuredRuntimeRoot))
        {
            return canonicalRuntimeRoot;
        }

        var configured = Path.GetFullPath(configuredRuntimeRoot);
        if (!configured.Equals(canonicalRuntimeRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "PSOBB_RUNTIME_ROOT does not exactly match the launcher's canonical nested runtime.");
        }

        return canonicalRuntimeRoot;
    }
}

public static partial class LauncherCommandLine
{
    public static LauncherOptions Parse(IReadOnlyList<string> arguments)
    {
        return ParseWithCanonicalRuntime(
            arguments,
            LauncherOptions.ResolveDefaultRuntimeRoot());
    }

    internal static LauncherOptions ParseFromInstallationOrigin(
        IReadOnlyList<string> arguments,
        string installationOrigin,
        string? configuredRuntimeRoot = null)
    {
        return ParseWithCanonicalRuntime(
            arguments,
            LauncherOptions.ResolveDefaultRuntimeRoot(
                installationOrigin,
                configuredRuntimeRoot));
    }

    private static LauncherOptions ParseWithCanonicalRuntime(
        IReadOnlyList<string> arguments,
        string canonicalRuntimeRoot)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        var defaults = LauncherOptions.Defaults(canonicalRuntimeRoot);
        var operation = LauncherOperation.Gui;
        var operationWasSet = false;
        var runtimeRoot = defaults.RuntimeRoot;
        var manifestPath = defaults.ManifestPath;
        var serverEnvironment = defaults.ServerEnvironment;
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
                    runtimeRoot = RequireExactRuntimeRoot(
                        ReadValue(option, inlineValue, arguments, ref index),
                        canonicalRuntimeRoot);
                    break;
                case "--manifest":
                    manifestPath = ReadValue(option, inlineValue, arguments, ref index);
                    break;
                case "--server-environment":
                    serverEnvironment = ParseServerEnvironment(
                        ReadValue(option, inlineValue, arguments, ref index));
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
            if (serverEnvironment != ServerEnvironmentKind.Stable
                || (channel is not null && channel != ReleaseChannel.Stable)
                || (profileId is not null
                    && !profileId.Equals(GraphicsProfileOption.SafeNative.Id, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException(
                    "--safe-play requires the Stable server environment, Stable channel, and safe native profile.");
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
        var selectedWindowMode = windowMode ?? defaults.Selection.WindowMode;

        if (serverEnvironment == ServerEnvironmentKind.CombatCanary
            && (selectedChannel != ReleaseChannel.Stable
                || selectedProfile != GraphicsProfileOption.SafeNative
                || selectedWindowMode != LauncherWindowMode.ProfileDefault))
        {
            throw new ArgumentException(
                "The CombatCanary server environment uses only its sealed Native client with profile-default presentation.");
        }

        return new(
            operation,
            Path.GetFullPath(runtimeRoot),
            Path.GetFullPath(manifestPath),
            serverEnvironment,
            LifecycleSelection.Create(
                selectedChannel,
                selectedProfile,
                selectedMonitor,
                selectedWindowMode,
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

    private static ServerEnvironmentKind ParseServerEnvironment(string value) => value.ToLowerInvariant() switch
    {
        "stable" => ServerEnvironmentKind.Stable,
        "combat-canary" => ServerEnvironmentKind.CombatCanary,
        _ => throw new ArgumentException("--server-environment must be stable or combat-canary."),
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

    private static string RequireExactRuntimeRoot(
        string requestedRuntimeRoot,
        string canonicalRuntimeRoot)
    {
        var requested = Path.GetFullPath(requestedRuntimeRoot);
        if (!requested.Equals(canonicalRuntimeRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "--runtime-root must exactly match the launcher's canonical nested runtime.");
        }

        return canonicalRuntimeRoot;
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
