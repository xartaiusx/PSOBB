using System.Collections.Concurrent;
using System.Diagnostics;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public interface ILifecycleStateObserver
{
    Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default);

    Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);
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

internal interface ICanonicalLifecycleRootAuthority
{
    string? ExpectedRepositoryRoot { get; }

    CanonicalLifecycleLayout ValidateLifecycleRoot(string runtimeRoot);
}

public sealed class RuntimeLifecycleObserver : ILifecycleStateObserver, ICanonicalLifecycleRootAuthority
{
    private readonly CanonicalLifecycleRepositoryGuard _rootGuard;
    private readonly IRuntimeIdentityProbe _identityProbe;

    public RuntimeLifecycleObserver(LoopbackHealthProbe healthProbe)
    {
        ArgumentNullException.ThrowIfNull(healthProbe);
        var layout = new CanonicalLifecycleInstallationResolver().Resolve();
        _rootGuard = new CanonicalLifecycleRepositoryGuard(layout.RepositoryRoot);
        _identityProbe = new ExactRuntimeIdentityProbe(
            _rootGuard,
            new WindowsRuntimePlatformProbe(),
            new PowerShellRuntimeContractVerifier(_rootGuard));
    }

    internal RuntimeLifecycleObserver(
        IRuntimeIdentityProbe identityProbe,
        CanonicalLifecycleRepositoryGuard? rootGuard = null)
    {
        _identityProbe = identityProbe ?? throw new ArgumentNullException(nameof(identityProbe));
        _rootGuard = rootGuard ?? new CanonicalLifecycleRepositoryGuard();
    }

    string? ICanonicalLifecycleRootAuthority.ExpectedRepositoryRoot =>
        _rootGuard.ExpectedRepositoryRoot;

    CanonicalLifecycleLayout ICanonicalLifecycleRootAuthority.ValidateLifecycleRoot(string runtimeRoot) =>
        _rootGuard.Validate(runtimeRoot);

    internal static (string ControlStatePath, string ProcessRecordPath) GetLifecycleFilePaths(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var environmentRoot = serverEnvironment switch
        {
            ServerEnvironmentKind.Stable => "stable",
            ServerEnvironmentKind.CombatCanary => "combat-canary",
            _ => throw new ArgumentOutOfRangeException(nameof(serverEnvironment)),
        };
        var controlRoot = Path.Combine(Path.GetFullPath(runtimeRoot), environmentRoot, "control");
        return (
            Path.Combine(controlRoot, "newserv-control.json"),
            Path.Combine(controlRoot, "newserv.process.json"));
    }

    internal static IReadOnlySet<string> GetApprovedClientPaths(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var root = Path.GetFullPath(runtimeRoot);
        return serverEnvironment switch
        {
            ServerEnvironmentKind.Stable => new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Path.GetFullPath(Path.Combine(root, "stable", "runtime", "client", "Psobb.exe")),
                Path.GetFullPath(Path.Combine(root, "canary", "runtime", "client", "Psobb.exe")),
                Path.GetFullPath(Path.Combine(root, "local-lab", "runtime", "client", "Psobb.exe")),
            },
            ServerEnvironmentKind.CombatCanary => new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Path.GetFullPath(Path.Combine(root, "combat-canary", "runtime", "client", "Psobb.exe")),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(serverEnvironment)),
        };
    }

    public Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        ObserveAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _rootGuard.Validate(runtimeRoot);
        return _identityProbe.ObserveAsync(runtimeRoot, serverEnvironment, cancellationToken);
    }

}

public sealed class PowerShellLifecycleScriptExecutor : ILifecycleScriptExecutor, ICanonicalLifecycleRootAuthority
{
    private const int MaximumLogLines = 200;
    private static readonly TimeSpan DefaultExecutionTimeout = TimeSpan.FromMinutes(5);
    private readonly ConcurrentQueue<string> _log = new();
    private readonly DiagnosticLineSanitizer _diagnosticSanitizer = new();
    private readonly IPowerShellExecutableAuthority _powerShellAuthority;
    private readonly LifecycleInvocationProcessStopCoordinator _processStopCoordinator;
    private readonly CanonicalLifecycleRepositoryGuard _rootGuard;
    private readonly Action? _afterSecondValidation;
    private readonly Func<Process, bool> _processStarter;
    private readonly TimeSpan _executionTimeout;

    public PowerShellLifecycleScriptExecutor()
        : this(
            CreateProductionRootGuard(),
            TrustedPowerShellExecutableAuthority.CreateProduction())
    {
    }

    internal PowerShellLifecycleScriptExecutor(
        CanonicalLifecycleRepositoryGuard rootGuard,
        IPowerShellExecutableAuthority? powerShellAuthority = null,
        Action? afterSecondValidation = null,
        Func<Process, bool>? processStarter = null,
        LifecycleInvocationProcessStopCoordinator? processStopCoordinator = null,
        TimeSpan? executionTimeout = null)
    {
        _rootGuard = rootGuard ?? throw new ArgumentNullException(nameof(rootGuard));
        _powerShellAuthority = powerShellAuthority
            ?? TrustedPowerShellExecutableAuthority.CreateProduction();
        _afterSecondValidation = afterSecondValidation;
        _processStarter = processStarter ?? (static process => process.Start());
        _processStopCoordinator = processStopCoordinator
            ?? new LifecycleInvocationProcessStopCoordinator();
        _executionTimeout = executionTimeout ?? DefaultExecutionTimeout;
        if (_executionTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(executionTimeout),
                "The lifecycle-command execution timeout must be positive.");
        }
    }

    string? ICanonicalLifecycleRootAuthority.ExpectedRepositoryRoot =>
        _rootGuard.ExpectedRepositoryRoot;

    CanonicalLifecycleLayout ICanonicalLifecycleRootAuthority.ValidateLifecycleRoot(string runtimeRoot) =>
        _rootGuard.Validate(runtimeRoot);

    public IReadOnlyList<string> LogTail => _log.ToArray();

    public async Task ExecuteAsync(
        string scriptName,
        string runtimeRoot,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        ArgumentNullException.ThrowIfNull(arguments);
        using var executionTimeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        executionTimeout.CancelAfter(_executionTimeout);
        var executionToken = executionTimeout.Token;
        CanonicalLifecycleInvocationLease? scriptLease = null;
        PowerShellExecutableLease? powerShellLease = null;
        Process? process = null;
        var releaseOwnedResources = true;
        try
        {
            scriptLease = _rootGuard.AcquireScriptInvocation(runtimeRoot, scriptName);
            powerShellLease = _powerShellAuthority.Acquire();
            var layout = scriptLease.Layout;
            var scriptPath = scriptLease.ScriptPath;
            var powerShellIdentity = powerShellLease.Identity;

            var startInfo = new ProcessStartInfo
            {
                FileName = powerShellIdentity.FullPath,
                WorkingDirectory = layout.RepositoryRoot,
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
                    throw new InvalidOperationException(
                        "Lifecycle script arguments may not contain control characters.");
                }

                startInfo.ArgumentList.Add(argument);
            }

            process = new Process { StartInfo = startInfo };
            executionToken.ThrowIfCancellationRequested();
            scriptLease.Revalidate();
            powerShellLease.Revalidate();
            _afterSecondValidation?.Invoke();
            executionToken.ThrowIfCancellationRequested();
            scriptLease.Revalidate();
            powerShellLease.Revalidate();
            if (!_processStarter(process))
            {
                throw new InvalidOperationException(
                    $"Windows did not start the {scriptName} lifecycle command.");
            }

            var standardOutput = process.StandardOutput.ReadToEndAsync(executionToken);
            var standardError = process.StandardError.ReadToEndAsync(executionToken);
            await process.WaitForExitAsync(executionToken).ConfigureAwait(false);
            var output = await standardOutput.ConfigureAwait(false);
            var error = await standardError.ConfigureAwait(false);
            AddLog(output);
            AddLog(error);

            if (process.ExitCode != 0)
            {
                var detail = FirstMeaningfulLine(error)
                    ?? FirstMeaningfulLine(output)
                    ?? "No diagnostic was returned.";
                throw new InvalidOperationException(
                    $"{scriptName} failed with exit code {process.ExitCode}: {detail}");
            }
        }
        catch (Exception exception) when (
            process is not null
            && scriptLease is not null
            && powerShellLease is not null)
        {
            var stop = await _processStopCoordinator.StopOrQuarantineAsync(
                process,
                scriptLease,
                powerShellLease).ConfigureAwait(false);
            if (!stop.ExitConfirmed)
            {
                releaseOwnedResources = false;
                throw new UnconfirmedLifecycleChildExitException(
                    "lifecycle command",
                    stop.Failure,
                    stop.QuarantineIncidentId
                        ?? throw new InvalidOperationException(
                            "An unconfirmed child exit did not receive a quarantine identifier."));
            }
            if (exception is OperationCanceledException
                && !cancellationToken.IsCancellationRequested
                && executionTimeout.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"The lifecycle command exceeded its " +
                    $"{_executionTimeout.TotalSeconds:0.###}-second limit.");
            }
            throw;
        }
        finally
        {
            if (releaseOwnedResources)
            {
                process?.Dispose();
                powerShellLease?.Dispose();
                scriptLease?.Dispose();
            }
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
        return _diagnosticSanitizer.Normalize(value);
    }

    private static bool IsPowerShellLocationHeader(string line)
    {
        var marker = line.LastIndexOf(".ps1:", StringComparison.OrdinalIgnoreCase);
        return marker >= 0
            && line[(marker + ".ps1:".Length)..].All(char.IsAsciiDigit);
    }

    private static CanonicalLifecycleRepositoryGuard CreateProductionRootGuard()
    {
        var layout = new CanonicalLifecycleInstallationResolver().Resolve();
        return new CanonicalLifecycleRepositoryGuard(layout.RepositoryRoot);
    }
}

public sealed class LifecycleScriptController
{
    private static readonly TimeSpan StateTransitionTimeout = TimeSpan.FromSeconds(35);
    private readonly ILifecycleStateObserver _observer;
    private readonly ILifecycleScriptExecutor _executor;

    public LifecycleScriptController(ILifecycleStateObserver observer, ILifecycleScriptExecutor executor)
    {
        _observer = observer ?? throw new ArgumentNullException(nameof(observer));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        if (observer is ICanonicalLifecycleRootAuthority observerAuthority
            && executor is ICanonicalLifecycleRootAuthority executorAuthority
            && observerAuthority.ExpectedRepositoryRoot is not null
            && executorAuthority.ExpectedRepositoryRoot is not null
            && !observerAuthority.ExpectedRepositoryRoot.Equals(
                executorAuthority.ExpectedRepositoryRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The lifecycle observer and executor are bound to different repository roots.");
        }
    }

    public IReadOnlyList<string> LogTail => _executor.LogTail;

    public Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        ObserveAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalRootAgreement(runtimeRoot);
        return _observer.ObserveAsync(runtimeRoot, serverEnvironment, cancellationToken);
    }

    public Task<LifecycleSnapshot> StartServerAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StartServerAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StartServerAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalRootAgreement(runtimeRoot);
        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
        if (current.State is LauncherLifecycleState.ServerReady or LauncherLifecycleState.Running)
        {
            RequireAuthenticated(current);
            return current;
        }

        if (current.State == LauncherLifecycleState.ServerStarting)
        {
            RequireAuthenticated(current);
            return await WaitForAsync(
                runtimeRoot,
                serverEnvironment,
                state => state.IdentityAuthenticated
                    && state.State is LauncherLifecycleState.ServerReady or LauncherLifecycleState.Running,
                cancellationToken).ConfigureAwait(false);
        }

        if (current.State != LauncherLifecycleState.Stopped || !current.IdentityAuthenticated)
        {
            throw new InvalidOperationException(current.Detail);
        }

        await _executor.ExecuteAsync(
            "Start-PSOBB.ps1",
            runtimeRoot,
            EnvironmentArguments(runtimeRoot, serverEnvironment),
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot,
            serverEnvironment,
            state => state.IdentityAuthenticated
                && state.State is LauncherLifecycleState.ServerReady or LauncherLifecycleState.Running,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> StartClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default) =>
        StartClientAsync(runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StartClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ValidateCanonicalRootAgreement(runtimeRoot);
        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
        if (current.ClientRunning && current.State == LauncherLifecycleState.Running)
        {
            RequireAuthenticated(current);
            return current;
        }

        if (current.State != LauncherLifecycleState.ServerReady || !current.IdentityAuthenticated)
        {
            throw new InvalidOperationException("The local server must be healthy before starting the client.");
        }

        var arguments = ClientLaunchArguments(runtimeRoot, selection, serverEnvironment);
        await _executor.ExecuteAsync(
            "Start-PSOBBClient.ps1",
            runtimeRoot,
            arguments,
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot,
            serverEnvironment,
            state => state.IdentityAuthenticated
                && state.State == LauncherLifecycleState.Running
                && state.ClientRunning,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> PlayAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default) =>
        PlayAsync(runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> PlayAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ValidateCanonicalRootAgreement(runtimeRoot);
        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
        if (current.ClientRunning && current.State == LauncherLifecycleState.Running)
        {
            RequireAuthenticated(current);
            return current;
        }
        if (!current.IdentityAuthenticated
            || current.State is not (LauncherLifecycleState.Stopped or LauncherLifecycleState.ServerReady))
        {
            throw new InvalidOperationException(current.Detail);
        }

        var arguments = ClientLaunchArguments(runtimeRoot, selection, serverEnvironment);
        await _executor.ExecuteAsync(
            "Start-PSOBBSession.ps1",
            runtimeRoot,
            arguments,
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot,
            serverEnvironment,
            state => state.IdentityAuthenticated
                && state.State == LauncherLifecycleState.Running
                && state.ClientRunning,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> StopClientAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StopClientAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StopClientAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalRootAgreement(runtimeRoot);
        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
        if (!current.ClientRunning)
        {
            return current;
        }

        await _executor.ExecuteAsync(
            "Stop-PSOBBClient.ps1",
            runtimeRoot,
            EnvironmentArguments(runtimeRoot, serverEnvironment),
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot, serverEnvironment, state => !state.ClientRunning, cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> StopServerAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StopServerAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StopServerAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalRootAgreement(runtimeRoot);
        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
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
            EnvironmentArguments(runtimeRoot, serverEnvironment),
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot, serverEnvironment, state => !state.ServerRunning, cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> StopAllAsync(
        string runtimeRoot,
        CancellationToken cancellationToken = default) =>
        StopAllAsync(runtimeRoot, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> StopAllAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalRootAgreement(runtimeRoot);
        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
        if (!current.ServerRunning && !current.ClientRunning)
        {
            return current;
        }

        await _executor.ExecuteAsync(
            "Stop-PSOBBSession.ps1",
            runtimeRoot,
            [
                "-Target", "All",
                "-ServerEnvironment", ToScriptServerEnvironment(serverEnvironment),
                "-RuntimeRoot", Path.GetFullPath(runtimeRoot),
            ],
            cancellationToken).ConfigureAwait(false);
        return await WaitForAsync(
            runtimeRoot,
            serverEnvironment,
            state => !state.ServerRunning && !state.ClientRunning,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<LifecycleSnapshot> RepairClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        CancellationToken cancellationToken = default) =>
        RepairClientAsync(runtimeRoot, selection, ServerEnvironmentKind.Stable, cancellationToken);

    public async Task<LifecycleSnapshot> RepairClientAsync(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        ValidateCanonicalRootAgreement(runtimeRoot);
        if (serverEnvironment == ServerEnvironmentKind.CombatCanary)
        {
            throw new NotSupportedException(
                "CombatCanary client repair is owned by its sealed initialization and reset workflow.");
        }

        var current = await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
        if (current.State != LauncherLifecycleState.Stopped
            || !current.IdentityAuthenticated
            || current.ServerRunning
            || current.ClientRunning)
        {
            throw new InvalidOperationException(
                "Client repair requires an identity-authenticated exact Stopped state for the complete runtime.");
        }

        var repair = RepairCommand(runtimeRoot, selection);
        await _executor.ExecuteAsync(
            repair.Script,
            runtimeRoot,
            repair.Arguments,
            cancellationToken).ConfigureAwait(false);
        return await _observer.ObserveAsync(
            runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
    }

    private void ValidateCanonicalRootAgreement(string runtimeRoot)
    {
        if (_observer is not ICanonicalLifecycleRootAuthority observerAuthority
            || _executor is not ICanonicalLifecycleRootAuthority executorAuthority)
        {
            return;
        }

        var observerLayout = observerAuthority.ValidateLifecycleRoot(runtimeRoot);
        var executorLayout = executorAuthority.ValidateLifecycleRoot(runtimeRoot);
        if (!observerLayout.RepositoryRoot.Equals(
                executorLayout.RepositoryRoot,
                StringComparison.OrdinalIgnoreCase)
            || !observerLayout.RuntimeRoot.Equals(
                executorLayout.RuntimeRoot,
                StringComparison.OrdinalIgnoreCase)
            || !observerLayout.ScriptsRoot.Equals(
                executorLayout.ScriptsRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The lifecycle observer and executor did not derive one canonical repository layout.");
        }
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
        ServerEnvironmentKind serverEnvironment,
        Func<LifecycleSnapshot, bool> predicate,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + StateTransitionTimeout;
        LifecycleSnapshot? latest = null;
        do
        {
            latest = await _observer.ObserveAsync(
                runtimeRoot, serverEnvironment, cancellationToken).ConfigureAwait(false);
            if (predicate(latest))
            {
                return latest;
            }
            if (latest.State == LauncherLifecycleState.Faulted)
            {
                throw new InvalidOperationException(latest.Detail);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        throw new TimeoutException($"Lifecycle transition did not complete: {latest?.Detail ?? "no state was observed"}");
    }

    private static void RequireAuthenticated(LifecycleSnapshot snapshot)
    {
        if (!snapshot.IdentityAuthenticated)
        {
            throw new InvalidOperationException(
                "Lifecycle evidence was advisory and did not pass exact process, executable, binding, and listener authentication.");
        }
    }

    private static string ToScriptWindowMode(LauncherWindowMode windowMode) => windowMode switch
    {
        LauncherWindowMode.ProfileDefault => "ProfileDefault",
        LauncherWindowMode.Borderless => "Borderless",
        LauncherWindowMode.Resizable => "Resizable",
        _ => throw new ArgumentOutOfRangeException(nameof(windowMode)),
    };

    private static string ToScriptServerEnvironment(ServerEnvironmentKind serverEnvironment) =>
        serverEnvironment switch
        {
            ServerEnvironmentKind.Stable => "Stable",
            ServerEnvironmentKind.CombatCanary => "CombatCanary",
            _ => throw new ArgumentOutOfRangeException(nameof(serverEnvironment)),
        };

    private static List<string> EnvironmentArguments(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment) =>
    [
        "-ServerEnvironment", ToScriptServerEnvironment(serverEnvironment),
        "-RuntimeRoot", Path.GetFullPath(runtimeRoot),
    ];

    private static List<string> ClientLaunchArguments(
        string runtimeRoot,
        LifecycleSelection selection,
        ServerEnvironmentKind serverEnvironment)
    {
        var arguments = new List<string>();
        if (serverEnvironment == ServerEnvironmentKind.Stable)
        {
            arguments.Add("-Channel");
            arguments.Add(selection.Channel.ToString());
            arguments.Add("-WindowMode");
            arguments.Add(ToScriptWindowMode(selection.WindowMode));
        }
        else if (serverEnvironment != ServerEnvironmentKind.CombatCanary)
        {
            throw new ArgumentOutOfRangeException(nameof(serverEnvironment));
        }

        arguments.Add("-ServerEnvironment");
        arguments.Add(ToScriptServerEnvironment(serverEnvironment));
        arguments.Add("-RuntimeRoot");
        arguments.Add(Path.GetFullPath(runtimeRoot));
        if (selection.PreserveForeground)
        {
            arguments.Add("-PreserveForeground");
        }

        return arguments;
    }

    private sealed record RepairScript(string Script, IReadOnlyList<string> Arguments);
}
