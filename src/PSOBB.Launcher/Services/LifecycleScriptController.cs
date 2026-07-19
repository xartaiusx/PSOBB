using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public interface ILifecycleStateObserver
{
    Task<LifecycleSnapshot> ObserveAsync(string runtimeRoot, CancellationToken cancellationToken = default);
}

public interface ILifecycleScriptExecutor
{
    IReadOnlyList<string> LogTail { get; }

    Task ExecuteAsync(
        string scriptName,
        string runtimeRoot,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default);
}

public sealed class RuntimeLifecycleObserver : ILifecycleStateObserver
{
    private static readonly int[] RequiredServerPorts = [11000, 12000, 12001];
    private readonly LoopbackHealthProbe _healthProbe;

    public RuntimeLifecycleObserver(LoopbackHealthProbe healthProbe)
    {
        _healthProbe = healthProbe;
    }

    internal static (string ControlStatePath, string ProcessRecordPath) GetLifecycleFilePaths(
        string runtimeRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var controlRoot = Path.Combine(Path.GetFullPath(runtimeRoot), "stable", "control");
        return (
            Path.Combine(controlRoot, "newserv-control.json"),
            Path.Combine(controlRoot, "newserv.process.json"));
    }

    public async Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var root = Path.GetFullPath(runtimeRoot);
        var clientResult = ObserveClients(root);
        if (clientResult.Unverifiable)
        {
            return new(
                LauncherLifecycleState.Faulted,
                ServerRunning: false,
                ClientRunning: true,
                "A PSOBB process exists but Windows did not provide an executable path; lifecycle actions fail closed.");
        }
        if (clientResult.Unapproved)
        {
            return new(
                LauncherLifecycleState.Faulted,
                ServerRunning: false,
                ClientRunning: true,
                "A PSOBB process is running outside every approved runtime path; lifecycle actions fail closed.");
        }

        var health = await _healthProbe.ProbeAsync(
            RequiredServerPorts,
            TimeSpan.FromMilliseconds(350),
            cancellationToken).ConfigureAwait(false);
        var serverReady = health.Count == RequiredServerPorts.Length && health.All(port => port.IsHealthy);
        var lifecyclePaths = GetLifecycleFilePaths(root);
        var serverRecorded = File.Exists(lifecyclePaths.ProcessRecordPath);
        var stateText = await ReadLifecycleStateAsync(
            lifecyclePaths.ControlStatePath,
            cancellationToken).ConfigureAwait(false);

        if (clientResult.Running && !serverReady)
        {
            return new(
                LauncherLifecycleState.Faulted,
                serverRecorded,
                ClientRunning: true,
                "An approved PSOBB client is running while the required local server ports are not healthy.");
        }

        if (clientResult.Running)
        {
            return new(LauncherLifecycleState.Running, true, true, "Local server and approved PSOBB client are running.");
        }

        if (serverReady)
        {
            return new(LauncherLifecycleState.ServerReady, true, false, "Local server is ready; no approved client is running.");
        }

        if (serverRecorded || stateText.Equals("starting", StringComparison.OrdinalIgnoreCase))
        {
            return new(LauncherLifecycleState.ServerStarting, true, false, "Local server startup is in progress.");
        }

        return new(LauncherLifecycleState.Stopped, false, false, "Local server and approved PSOBB clients are stopped.");
    }

    private static ClientObservation ObserveClients(string runtimeRoot)
    {
        var approvedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetFullPath(Path.Combine(runtimeRoot, "stable", "runtime", "client", "Psobb.exe")),
            Path.GetFullPath(Path.Combine(runtimeRoot, "canary", "runtime", "client", "Psobb.exe")),
            Path.GetFullPath(Path.Combine(runtimeRoot, "local-lab", "runtime", "client", "Psobb.exe")),
        };

        var running = false;
        var unverifiable = false;
        var unapproved = false;
        foreach (var process in Process.GetProcessesByName("Psobb"))
        {
            using (process)
            {
                string? executablePath;
                try
                {
                    executablePath = process.MainModule?.FileName;
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException
                        or System.ComponentModel.Win32Exception
                        or NotSupportedException)
                {
                    unverifiable = true;
                    continue;
                }

                if (string.IsNullOrWhiteSpace(executablePath))
                {
                    unverifiable = true;
                }
                else if (approvedPaths.Contains(Path.GetFullPath(executablePath)))
                {
                    running = true;
                }
                else
                {
                    unapproved = true;
                }
            }
        }

        return new(running, unverifiable, unapproved);
    }

    private static async Task<string> ReadLifecycleStateAsync(
        string path,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return document.RootElement.TryGetProperty("state", out var state)
                ? state.GetString() ?? string.Empty
                : string.Empty;
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return string.Empty;
        }
    }

    private sealed record ClientObservation(bool Running, bool Unverifiable, bool Unapproved);
}

public sealed class PowerShellLifecycleScriptExecutor : ILifecycleScriptExecutor
{
    private const int MaximumLogLines = 200;
    private static readonly Regex TerminalControlSequence = new(
        "\\x1B(?:\\[[0-?]*[ -/]*[@-~]|\\][^\\x07\\x1B]*(?:\\x07|\\x1B\\\\|$))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly HashSet<string> AllowedScripts = new(StringComparer.OrdinalIgnoreCase)
    {
        "Reset-PSOBBClientRuntime.ps1",
        "New-PSOBBGraphicsLabRuntime.ps1",
        "Set-PSOBBAshenbubsHDClientActivation.ps1",
        "Start-PSOBB.ps1",
        "Start-PSOBBClient.ps1",
        "Start-PSOBBSession.ps1",
        "Stop-PSOBB.ps1",
        "Stop-PSOBBClient.ps1",
        "Stop-PSOBBSession.ps1",
    };

    private readonly ConcurrentQueue<string> _log = new();
    private readonly DiagnosticReportBuilder _sanitizer = new();
    private readonly string _scriptRoot;
    private readonly string _powerShellExecutable;

    public PowerShellLifecycleScriptExecutor(string? scriptRoot = null, string powerShellExecutable = "pwsh.exe")
    {
        _scriptRoot = LifecycleScriptLocator.Resolve(scriptRoot);
        _powerShellExecutable = powerShellExecutable;
    }

    public IReadOnlyList<string> LogTail => _log.ToArray();

    public async Task ExecuteAsync(
        string scriptName,
        string runtimeRoot,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default)
    {
        if (!AllowedScripts.Contains(scriptName))
        {
            throw new InvalidOperationException($"Lifecycle script '{scriptName}' is not allowlisted.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        ArgumentNullException.ThrowIfNull(arguments);
        var scriptPath = Path.GetFullPath(Path.Combine(_scriptRoot, scriptName));
        if (!scriptPath.StartsWith(_scriptRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase)
            || !File.Exists(scriptPath))
        {
            throw new FileNotFoundException($"The required lifecycle script is missing: {scriptName}", scriptPath);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = _powerShellExecutable,
            WorkingDirectory = Path.GetDirectoryName(_scriptRoot)
                ?? throw new InvalidDataException("The lifecycle script root has no parent directory."),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var fixedArgument in new[]
        {
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            scriptPath,
        })
        {
            startInfo.ArgumentList.Add(fixedArgument);
        }

        foreach (var argument in arguments)
        {
            if (argument.Any(char.IsControl))
            {
                throw new InvalidOperationException("Lifecycle script arguments may not contain control characters.");
            }

            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException($"Windows did not start the {scriptName} lifecycle command.");
        }

        var standardOutput = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var standardError = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }

            throw;
        }
        var output = await standardOutput.ConfigureAwait(false);
        var error = await standardError.ConfigureAwait(false);
        AddLog(output);
        AddLog(error);

        if (process.ExitCode != 0)
        {
            var detail = FirstMeaningfulLine(error) ?? FirstMeaningfulLine(output) ?? "No diagnostic was returned.";
            throw new InvalidOperationException($"{scriptName} failed with exit code {process.ExitCode}: {detail}");
        }
    }

    internal void AddLog(string value)
    {
        foreach (var rawLine in value.Split(
                     ['\r', '\n'],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var line = NormalizeDiagnosticLine(rawLine);
            if (line.Length == 0)
            {
                continue;
            }

            _log.Enqueue(line);
            while (_log.Count > MaximumLogLines && _log.TryDequeue(out _))
            {
            }
        }
    }

    internal string? FirstMeaningfulLine(string value)
    {
        string? fallback = null;
        var inPowerShellSourceGutter = false;
        foreach (var rawLine in value.Split(
                     ['\r', '\n'],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var line = NormalizeDiagnosticLine(rawLine);
            if (line.Length == 0)
            {
                continue;
            }

            fallback ??= line;
            if (line.Equals("Line |", StringComparison.OrdinalIgnoreCase))
            {
                inPowerShellSourceGutter = true;
                continue;
            }

            if (IsPowerShellLocationHeader(line))
            {
                continue;
            }

            var separator = inPowerShellSourceGutter ? line.IndexOf('|') : -1;
            if (separator >= 0)
            {
                var prefix = line[..separator].Trim();
                if (prefix.Length > 0 && prefix.All(char.IsAsciiDigit))
                {
                    continue;
                }

                if (prefix.Length == 0)
                {
                    line = line[(separator + 1)..].Trim();
                    if (line.Length == 0 || line.All(character => character is '~' or '^' or '-'))
                    {
                        continue;
                    }
                }
            }

            return line;
        }

        return fallback;
    }

    internal string NormalizeDiagnosticLine(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var withoutTerminalSequences = TerminalControlSequence.Replace(value, string.Empty);
        var normalized = new StringBuilder(withoutTerminalSequences.Length);
        foreach (var character in withoutTerminalSequences)
        {
            if (!char.IsControl(character) || character == '\t')
            {
                normalized.Append(character);
            }
        }

        return _sanitizer.Sanitize(normalized.ToString()).Trim();
    }

    private static bool IsPowerShellLocationHeader(string line)
    {
        var marker = line.LastIndexOf(".ps1:", StringComparison.OrdinalIgnoreCase);
        return marker >= 0
            && line[(marker + ".ps1:".Length)..].All(char.IsAsciiDigit);
    }
}

public static class LifecycleScriptLocator
{
    public static string Resolve(string? requestedRoot = null) => Resolve(
        requestedRoot,
        Environment.GetEnvironmentVariable("PSOBB_SCRIPT_ROOT"),
        [AppContext.BaseDirectory, Environment.CurrentDirectory]);

    internal static string Resolve(
        string? requestedRoot,
        string? configuredRoot,
        IEnumerable<string> origins)
    {
        foreach (var candidate in Candidates(requestedRoot, configuredRoot, origins))
        {
            var scripts = NormalizeCandidate(candidate);
            if (scripts is not null && File.Exists(Path.Combine(scripts, "Start-PSOBB.ps1")))
            {
                return scripts;
            }
        }

        throw new DirectoryNotFoundException(
            "Could not locate the PSOBB lifecycle scripts. Set PSOBB_SCRIPT_ROOT to the repository scripts directory.");
    }

    private static IEnumerable<string?> Candidates(
        string? requestedRoot,
        string? configuredRoot,
        IEnumerable<string> origins)
    {
        yield return requestedRoot;
        yield return configuredRoot;

        foreach (var origin in origins)
        {
            var cursor = new DirectoryInfo(Path.GetFullPath(origin));
            for (var depth = 0; cursor is not null && depth < 10; depth++, cursor = cursor.Parent)
            {
                yield return cursor.FullName;
            }
        }
    }

    private static string? NormalizeCandidate(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        var fullPath = Path.GetFullPath(candidate);
        if (string.Equals(new DirectoryInfo(fullPath).Name, "scripts", StringComparison.OrdinalIgnoreCase))
        {
            return fullPath.TrimEnd(Path.DirectorySeparatorChar);
        }

        return Path.Combine(fullPath, "scripts");
    }
}

public sealed class LifecycleScriptController
{
    private static readonly TimeSpan StateTransitionTimeout = TimeSpan.FromSeconds(35);
    private readonly ILifecycleStateObserver _observer;
    private readonly ILifecycleScriptExecutor _executor;

    public LifecycleScriptController(ILifecycleStateObserver observer, ILifecycleScriptExecutor executor)
    {
        _observer = observer;
        _executor = executor;
    }

    public IReadOnlyList<string> LogTail => _executor.LogTail;

    public Task<LifecycleSnapshot> ObserveAsync(string runtimeRoot, CancellationToken cancellationToken = default) =>
        _observer.ObserveAsync(runtimeRoot, cancellationToken);

    public async Task<LifecycleSnapshot> StartServerAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (current.State is LauncherLifecycleState.ServerReady or LauncherLifecycleState.Running)
        {
            return current;
        }

        if (current.State == LauncherLifecycleState.ServerStarting)
        {
            return await WaitForAsync(
                runtimeRoot,
                state => state.State is LauncherLifecycleState.ServerReady or LauncherLifecycleState.Running,
                cancellationToken).ConfigureAwait(false);
        }

        if (current.State == LauncherLifecycleState.Faulted)
        {
            throw new InvalidOperationException(current.Detail);
        }

        await _executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            runtimeRoot,
            ["-RuntimeRoot", Path.GetFullPath(runtimeRoot)],
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot,
            state => state.State is LauncherLifecycleState.ServerReady or LauncherLifecycleState.Running,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<LifecycleSnapshot> StartClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selection);
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (current.ClientRunning && current.State != LauncherLifecycleState.Faulted)
        {
            return current;
        }

        if (current.State != LauncherLifecycleState.ServerReady)
        {
            throw new InvalidOperationException("The local server must be healthy before starting the client.");
        }

        var arguments = ClientLaunchArguments(runtimeRoot, selection);
        await _executor.ExecuteAsync(
            "Start-PSOBBClient.ps1",
            runtimeRoot,
            arguments,
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(runtimeRoot, state => state.ClientRunning, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LifecycleSnapshot> PlayAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selection);
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (current.ClientRunning && current.State != LauncherLifecycleState.Faulted)
        {
            return current;
        }
        if (current.State == LauncherLifecycleState.Faulted)
        {
            throw new InvalidOperationException(current.Detail);
        }

        var arguments = ClientLaunchArguments(runtimeRoot, selection);
        await _executor.ExecuteAsync(
            "Start-PSOBBSession.ps1",
            runtimeRoot,
            arguments,
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(runtimeRoot, state => state.ClientRunning, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LifecycleSnapshot> StopClientAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (!current.ClientRunning)
        {
            return current;
        }

        await _executor.ExecuteAsync(
            "Stop-PSOBBClient.ps1",
            runtimeRoot,
            ["-RuntimeRoot", Path.GetFullPath(runtimeRoot)],
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(runtimeRoot, state => !state.ClientRunning, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LifecycleSnapshot> StopServerAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (current.ClientRunning)
        {
            throw new InvalidOperationException("Stop the client first, or use Stop all.");
        }

        if (!current.ServerRunning)
        {
            return current;
        }

        await _executor.ExecuteAsync(
            "Stop-PSOBB.ps1",
            runtimeRoot,
            ["-RuntimeRoot", Path.GetFullPath(runtimeRoot)],
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(runtimeRoot, state => !state.ServerRunning, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LifecycleSnapshot> StopAllAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default)
    {
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (!current.ServerRunning && !current.ClientRunning)
        {
            return current;
        }

        await _executor.ExecuteAsync(
            "Stop-PSOBBSession.ps1",
            runtimeRoot,
            ["-Target", "All", "-RuntimeRoot", Path.GetFullPath(runtimeRoot)],
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot,
            state => !state.ServerRunning && !state.ClientRunning,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<LifecycleSnapshot> RepairClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default)
    {
        var current = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
        if (current.ServerRunning || current.ClientRunning)
        {
            throw new InvalidOperationException("Stop both the server and client before repairing a client profile.");
        }

        var repair = RepairCommand(runtimeRoot, selection);
        await _executor.ExecuteAsync(
            repair.Script,
            runtimeRoot,
            repair.Arguments,
            cancellationToken).ConfigureAwait(false);
        return await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
    }

    private static RepairScript RepairCommand(string runtimeRoot, LifecycleSelection selection)
    {
        if (selection.Profile == GraphicsProfileOption.SafeNative)
        {
            return new(
                "Reset-PSOBBClientRuntime.ps1",
                ["-Renderer", "Native", "-Channel", "Stable", "-RuntimeRoot", Path.GetFullPath(runtimeRoot), "-Confirm:$false"]);
        }

        if (selection.Profile == GraphicsProfileOption.ClarityDgVoodoo)
        {
            return new(
                "Reset-PSOBBClientRuntime.ps1",
                [
                    "-Renderer", "DgVoodooD3D11",
                    "-Channel", "Canary",
                    "-GraphicsPreset", "Ultra3840x2880",
                    "-DefaultWindowMode", selection.WindowMode == LauncherWindowMode.Resizable ? "Resizable" : "Borderless",
                    "-RuntimeRoot", Path.GetFullPath(runtimeRoot),
                    "-Confirm:$false",
                ]);
        }

        if (selection.Profile == GraphicsProfileOption.LocalLabWidescreenHd)
        {
            return new(
                "Set-PSOBBAshenbubsHDClientActivation.ps1",
                ["-Action", "Verify", "-RuntimeRoot", Path.GetFullPath(runtimeRoot)]);
        }

        if (selection.Channel == ReleaseChannel.LocalLab
            && selection.Profile.Id is "lab-widescreen-16x10"
                or "dxvk-canary"
                or "d3d8to9-canary")
        {
            var arguments = new List<string>
            {
                "-ProfileId", selection.Profile.Id,
                "-WindowMode", selection.WindowMode == LauncherWindowMode.Resizable ? "Resizable" : "Borderless",
            };
            arguments.Add("-RuntimeRoot");
            arguments.Add(Path.GetFullPath(runtimeRoot));
            arguments.Add("-Confirm:$false");
            return new(
                "New-PSOBBGraphicsLabRuntime.ps1",
                arguments);
        }

        throw new NotSupportedException(
            $"Profile '{selection.Profile.Id}' is not repairable until its signed overlay and runtime builder are installed.");
    }

    private async Task<LifecycleSnapshot> WaitForAsync(
        string runtimeRoot,
        Func<LifecycleSnapshot, bool> predicate,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + StateTransitionTimeout;
        LifecycleSnapshot? latest = null;
        do
        {
            latest = await _observer.ObserveAsync(runtimeRoot, cancellationToken).ConfigureAwait(false);
            if (predicate(latest))
            {
                return latest;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        throw new TimeoutException($"Lifecycle transition did not complete: {latest?.Detail ?? "no state was observed"}");
    }

    private static string ToScriptWindowMode(LauncherWindowMode windowMode) => windowMode switch
    {
        LauncherWindowMode.ProfileDefault => "ProfileDefault",
        LauncherWindowMode.Borderless => "Borderless",
        LauncherWindowMode.Resizable => "Resizable",
        _ => throw new ArgumentOutOfRangeException(nameof(windowMode)),
    };

    private static List<string> ClientLaunchArguments(
        string runtimeRoot,
        LifecycleSelection selection)
    {
        var arguments = new List<string>
        {
            "-Channel", selection.Channel.ToString(),
            "-WindowMode", ToScriptWindowMode(selection.WindowMode),
            "-RuntimeRoot", Path.GetFullPath(runtimeRoot),
        };
        if (selection.PreserveForeground)
        {
            arguments.Add("-PreserveForeground");
        }

        return arguments;
    }

    private sealed record RepairScript(string Script, IReadOnlyList<string> Arguments);
}
