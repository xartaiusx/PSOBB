using System.Collections.Concurrent;
using System.Diagnostics;

namespace PSOBB.Launcher.Services;

internal enum ChildProcessTerminationFailure
{
    None,
    AssociationCheckFailed,
    KillFailed,
    WaitTimedOut,
    WaitFailed,
    ExitCheckFailed,
    ExitUnconfirmed,
}

internal readonly record struct ChildProcessTerminationResult(
    bool ExitConfirmed,
    ChildProcessTerminationFailure Failure);

internal sealed class BoundedChildProcessTerminator
{
    private static readonly TimeSpan DefaultTerminationTimeout = TimeSpan.FromSeconds(5);
    private readonly Func<Process, bool> _hasAssociatedProcess;
    private readonly Func<Process, bool> _hasExited;
    private readonly Action<Process> _kill;
    private readonly Func<Process, CancellationToken, Task> _waitForExitAsync;
    private readonly TimeSpan _terminationTimeout;

    public BoundedChildProcessTerminator()
        : this(DefaultTerminationTimeout)
    {
    }

    internal BoundedChildProcessTerminator(
        TimeSpan terminationTimeout,
        Func<Process, bool>? hasAssociatedProcess = null,
        Func<Process, bool>? hasExited = null,
        Action<Process>? kill = null,
        Func<Process, CancellationToken, Task>? waitForExitAsync = null)
    {
        if (terminationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(terminationTimeout),
                "The child-process termination timeout must be positive.");
        }

        _terminationTimeout = terminationTimeout;
        _hasAssociatedProcess = hasAssociatedProcess ?? HasAssociatedProcess;
        _hasExited = hasExited ?? (static process => process.HasExited);
        _kill = kill ?? (static process => process.Kill(entireProcessTree: true));
        _waitForExitAsync = waitForExitAsync
            ?? (static (process, cancellationToken) => process.WaitForExitAsync(cancellationToken));
    }

    public async Task<ChildProcessTerminationResult> TryTerminateAsync(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        bool associated;
        try
        {
            associated = _hasAssociatedProcess(process);
        }
        catch (Exception exception) when (IsProcessControlException(exception))
        {
            return new(false, ChildProcessTerminationFailure.AssociationCheckFailed);
        }

        if (!associated)
        {
            return new(true, ChildProcessTerminationFailure.None);
        }

        var initialExit = TryReadExitState(process);
        if (initialExit is true)
        {
            return new(true, ChildProcessTerminationFailure.None);
        }

        try
        {
            _kill(process);
        }
        catch (Exception exception) when (IsProcessControlException(exception))
        {
            return TryReadExitState(process) is true
                ? new(true, ChildProcessTerminationFailure.None)
                : new(false, ChildProcessTerminationFailure.KillFailed);
        }

        using var timeout = new CancellationTokenSource(_terminationTimeout);
        try
        {
            await _waitForExitAsync(process, timeout.Token)
                .WaitAsync(_terminationTimeout)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            return TryReadExitState(process) is true
                ? new(true, ChildProcessTerminationFailure.None)
                : new(false, ChildProcessTerminationFailure.WaitTimedOut);
        }
        catch (TimeoutException)
        {
            timeout.Cancel();
            return TryReadExitState(process) is true
                ? new(true, ChildProcessTerminationFailure.None)
                : new(false, ChildProcessTerminationFailure.WaitTimedOut);
        }
        catch (Exception exception) when (IsProcessControlException(exception))
        {
            return TryReadExitState(process) is true
                ? new(true, ChildProcessTerminationFailure.None)
                : new(false, ChildProcessTerminationFailure.WaitFailed);
        }

        var finalExit = TryReadExitState(process);
        return finalExit switch
        {
            true => new(true, ChildProcessTerminationFailure.None),
            false => new(false, ChildProcessTerminationFailure.ExitUnconfirmed),
            null => new(false, ChildProcessTerminationFailure.ExitCheckFailed),
        };
    }

    private bool? TryReadExitState(Process process)
    {
        try
        {
            return _hasExited(process);
        }
        catch (Exception exception) when (IsProcessControlException(exception))
        {
            return null;
        }
    }

    private static bool HasAssociatedProcess(Process process)
    {
        try
        {
            _ = process.Id;
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsProcessControlException(Exception exception) =>
        exception is InvalidOperationException
            or NotSupportedException
            or System.ComponentModel.Win32Exception;
}

internal sealed class LifecycleInvocationQuarantine
{
    private readonly ConcurrentDictionary<Guid, QuarantinedInvocation> _entries = new();
    private readonly bool _observeExitEvents;
    private int _releaseCount;

    internal LifecycleInvocationQuarantine(bool observeExitEvents = true)
    {
        _observeExitEvents = observeExitEvents;
    }

    public static LifecycleInvocationQuarantine Shared { get; } = new();

    internal int Count => _entries.Count;

    internal int ReleaseCount => Volatile.Read(ref _releaseCount);

    public Guid Retain(
        Process process,
        CanonicalLifecycleInvocationLease scriptLease,
        PowerShellExecutableLease powerShellLease)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(scriptLease);
        ArgumentNullException.ThrowIfNull(powerShellLease);
        var incidentId = Guid.NewGuid();
        var entry = new QuarantinedInvocation(
            process,
            scriptLease,
            powerShellLease);
        if (!_entries.TryAdd(incidentId, entry))
        {
            throw new InvalidOperationException(
                "A unique lifecycle-process quarantine identifier could not be allocated.");
        }

        if (_observeExitEvents)
        {
            TryObserveExit(incidentId, entry);
        }
        return incidentId;
    }

    internal bool IsRetained(Guid incidentId) => _entries.ContainsKey(incidentId);

    internal bool TryReleaseExited(Guid incidentId)
    {
        if (!_entries.TryGetValue(incidentId, out var entry))
        {
            return true;
        }

        try
        {
            if (!entry.Process.HasExited)
            {
                return false;
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or NotSupportedException
                or System.ComponentModel.Win32Exception)
        {
            return false;
        }

        if (!_entries.TryRemove(incidentId, out var removed))
        {
            return !_entries.ContainsKey(incidentId);
        }
        try
        {
            removed.Dispose();
        }
        finally
        {
            Interlocked.Increment(ref _releaseCount);
        }
        return true;
    }

    private void TryObserveExit(Guid incidentId, QuarantinedInvocation entry)
    {
        try
        {
            entry.ExitHandler = (_, _) => TryReleaseExited(incidentId);
            entry.Process.EnableRaisingEvents = true;
            entry.Process.Exited += entry.ExitHandler;
            _ = TryReleaseExited(incidentId);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or NotSupportedException
                or System.ComponentModel.Win32Exception)
        {
            // Retention is the fail-closed state when exit observation is unavailable.
        }
    }

    private sealed class QuarantinedInvocation(
        Process process,
        CanonicalLifecycleInvocationLease scriptLease,
        PowerShellExecutableLease powerShellLease) : IDisposable
    {
        public Process Process { get; } = process;

        public EventHandler? ExitHandler { get; set; }

        public void Dispose()
        {
            if (ExitHandler is not null)
            {
                try
                {
                    Process.Exited -= ExitHandler;
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException
                        or NotSupportedException
                        or System.ComponentModel.Win32Exception)
                {
                }
            }
            Process.Dispose();
            powerShellLease.Dispose();
            scriptLease.Dispose();
        }
    }
}

internal sealed record InvocationProcessStopResult(
    bool ExitConfirmed,
    ChildProcessTerminationFailure Failure,
    Guid? QuarantineIncidentId);

internal sealed class LifecycleInvocationProcessStopCoordinator
{
    private readonly LifecycleInvocationQuarantine _quarantine;
    private readonly BoundedChildProcessTerminator _terminator;

    public LifecycleInvocationProcessStopCoordinator()
        : this(
            new BoundedChildProcessTerminator(),
            LifecycleInvocationQuarantine.Shared)
    {
    }

    internal LifecycleInvocationProcessStopCoordinator(
        BoundedChildProcessTerminator terminator,
        LifecycleInvocationQuarantine quarantine)
    {
        _terminator = terminator ?? throw new ArgumentNullException(nameof(terminator));
        _quarantine = quarantine ?? throw new ArgumentNullException(nameof(quarantine));
    }

    public async Task<InvocationProcessStopResult> StopOrQuarantineAsync(
        Process process,
        CanonicalLifecycleInvocationLease scriptLease,
        PowerShellExecutableLease powerShellLease)
    {
        var termination = await _terminator.TryTerminateAsync(process).ConfigureAwait(false);
        if (termination.ExitConfirmed)
        {
            return new(true, ChildProcessTerminationFailure.None, null);
        }

        var incidentId = _quarantine.Retain(process, scriptLease, powerShellLease);
        return new(false, termination.Failure, incidentId);
    }
}

internal sealed class UnconfirmedLifecycleChildExitException : InvalidOperationException
{
    public UnconfirmedLifecycleChildExitException(
        string operation,
        ChildProcessTerminationFailure failure,
        Guid quarantineIncidentId)
        : base(
            $"The {operation} child process could not be confirmed stopped ({failure}). " +
            $"Its exact process handle and all trusted invocation leases were quarantined " +
            $"under incident {quarantineIncidentId:D}; no lease will be released until " +
            "that exact process is confirmed exited.")
    {
        QuarantineIncidentId = quarantineIncidentId;
        Failure = failure;
    }

    public Guid QuarantineIncidentId { get; }

    public ChildProcessTerminationFailure Failure { get; }
}
