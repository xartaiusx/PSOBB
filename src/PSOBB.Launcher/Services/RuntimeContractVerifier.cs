using System.Diagnostics;

namespace PSOBB.Launcher.Services;

internal sealed record RuntimeContractVerificationRequest(
    string RuntimeRoot,
    string Channel,
    string? BuildContractSha256 = null,
    string? TwillsContractSha256 = null,
    string? SigningPublicKeySpkiSha256 = null);

internal interface IRuntimeContractVerifier
{
    Task VerifyAsync(
        RuntimeContractVerificationRequest request,
        CancellationToken cancellationToken = default);
}

internal sealed class PowerShellRuntimeContractVerifier : IRuntimeContractVerifier
{
    private static readonly TimeSpan DefaultVerificationTimeout = TimeSpan.FromSeconds(60);
    private readonly IPowerShellExecutableAuthority _powerShellAuthority;
    private readonly LifecycleInvocationProcessStopCoordinator _processStopCoordinator;
    private readonly CanonicalLifecycleRepositoryGuard _rootGuard;
    private readonly Action<CancellationTokenSource>? _afterSecondValidation;
    private readonly Func<Process, bool> _processStarter;
    private readonly TimeSpan _verificationTimeout;

    public PowerShellRuntimeContractVerifier(string repositoryRoot)
        : this(
            new CanonicalLifecycleRepositoryGuard(repositoryRoot),
            TrustedPowerShellExecutableAuthority.CreateProduction())
    {
    }

    internal PowerShellRuntimeContractVerifier(
        CanonicalLifecycleRepositoryGuard rootGuard,
        IPowerShellExecutableAuthority? powerShellAuthority = null,
        Action<CancellationTokenSource>? afterSecondValidation = null,
        Func<Process, bool>? processStarter = null,
        TimeSpan? verificationTimeout = null,
        LifecycleInvocationProcessStopCoordinator? processStopCoordinator = null)
    {
        _rootGuard = rootGuard ?? throw new ArgumentNullException(nameof(rootGuard));
        _powerShellAuthority = powerShellAuthority
            ?? TrustedPowerShellExecutableAuthority.CreateProduction();
        _afterSecondValidation = afterSecondValidation;
        _processStarter = processStarter ?? (static process => process.Start());
        _processStopCoordinator = processStopCoordinator
            ?? new LifecycleInvocationProcessStopCoordinator();
        _verificationTimeout = verificationTimeout ?? DefaultVerificationTimeout;
        if (_verificationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(verificationTimeout),
                "The runtime verification timeout must be positive.");
        }
    }

    public async Task VerifyAsync(
        RuntimeContractVerificationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_verificationTimeout);
        var executionToken = timeout.Token;
        var (scriptName, arguments) = CreateInvocation(request);
        CanonicalLifecycleInvocationLease? scriptLease = null;
        PowerShellExecutableLease? powerShellLease = null;
        Process? process = null;
        var releaseOwnedResources = true;
        try
        {
            scriptLease = _rootGuard.AcquireScriptInvocation(request.RuntimeRoot, scriptName);
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
                startInfo.ArgumentList.Add(argument);
            }

            process = new Process { StartInfo = startInfo };
            cancellationToken.ThrowIfCancellationRequested();
            executionToken.ThrowIfCancellationRequested();
            scriptLease.Revalidate();
            powerShellLease.Revalidate();
            _afterSecondValidation?.Invoke(timeout);
            cancellationToken.ThrowIfCancellationRequested();
            executionToken.ThrowIfCancellationRequested();
            scriptLease.Revalidate();
            powerShellLease.Revalidate();
            if (!_processStarter(process))
            {
                throw new InvalidOperationException(
                    "Windows did not start the authoritative runtime verifier.");
            }
            var standardOutput = process.StandardOutput.ReadToEndAsync(executionToken);
            var standardError = process.StandardError.ReadToEndAsync(executionToken);
            await process.WaitForExitAsync(executionToken).ConfigureAwait(false);
            var output = await standardOutput.ConfigureAwait(false);
            var error = await standardError.ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new InvalidDataException(
                    $"The authoritative runtime contract verifier rejected the environment: " +
                    FirstBoundedDiagnostic(error, output));
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
                    "authoritative runtime verifier",
                    stop.Failure,
                    stop.QuarantineIncidentId
                        ?? throw new InvalidOperationException(
                            "An unconfirmed verifier exit did not receive a quarantine identifier."));
            }
            if (exception is OperationCanceledException
                && !cancellationToken.IsCancellationRequested
                && timeout.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"The authoritative runtime verifier exceeded its " +
                    $"{_verificationTimeout.TotalSeconds:0.###}-second limit.");
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

    private static (string ScriptName, string[] Arguments) CreateInvocation(
        RuntimeContractVerificationRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(request.RuntimeRoot);
        return request.Channel switch
        {
            "Stable" or "Canary" or "LocalLab" =>
                ("Test-PSOBBClientGraphics.ps1",
                ["-Channel", request.Channel, "-RuntimeRoot", Path.GetFullPath(request.RuntimeRoot)]),
            "CombatCanary" when request.BuildContractSha256 is not null
                && request.TwillsContractSha256 is not null
                && request.SigningPublicKeySpkiSha256 is not null =>
                ("Test-PSOBBCombatCanary.ps1",
                [
                    "-RuntimeRoot", Path.GetFullPath(request.RuntimeRoot),
                    "-Target", "Installed",
                    "-ExpectedBuildContractSha256", request.BuildContractSha256,
                    "-ExpectedTwillsContractSha256", request.TwillsContractSha256,
                    "-ExpectedSigningPublicKeySpkiSha256", request.SigningPublicKeySpkiSha256,
                ]),
            _ => throw new InvalidDataException("The authoritative runtime verifier request is incomplete or unsupported."),
        };
    }

    internal static string FirstBoundedDiagnostic(string standardError, string standardOutput)
    {
        var sanitizer = new DiagnosticLineSanitizer();
        var source = string.IsNullOrWhiteSpace(standardError) ? standardOutput : standardError;
        var line = source.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(sanitizer.Normalize)
            .FirstOrDefault(candidate => candidate.Length > 0)
            ?? "No diagnostic was returned.";
        return line.Length <= 512 ? line : line[..512];
    }
}
