namespace PSOBB.Launcher.Services;

/// <summary>
/// Keeps the interactive Control Center single-instance within the current
/// Windows logon session. Headless lifecycle commands intentionally do not use
/// this guard; the PowerShell lifecycle scripts provide their own operation
/// locks and remain the sole process authority.
/// </summary>
public sealed class LauncherSingleInstanceGuard : IDisposable
{
    internal const string ControlCenterInstanceName = @"Local\PSOBB.ControlCenter";

    private Mutex? _ownedMutex;

    private LauncherSingleInstanceGuard(Mutex? ownedMutex)
    {
        _ownedMutex = ownedMutex;
    }

    public bool IsPrimaryInstance => _ownedMutex is not null;

    public static LauncherSingleInstanceGuard AcquireControlCenter() =>
        Acquire(ControlCenterInstanceName);

    internal static LauncherSingleInstanceGuard Acquire(string instanceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(instanceName);

        Mutex? candidate = null;
        try
        {
            candidate = new Mutex(initiallyOwned: true, instanceName, out var createdNew);
            if (createdNew)
            {
                return new LauncherSingleInstanceGuard(candidate);
            }

            candidate.Dispose();
            return new LauncherSingleInstanceGuard(ownedMutex: null);
        }
        catch
        {
            candidate?.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        var ownedMutex = Interlocked.Exchange(ref _ownedMutex, null);
        if (ownedMutex is null)
        {
            return;
        }

        try
        {
            ownedMutex.ReleaseMutex();
        }
        finally
        {
            ownedMutex.Dispose();
        }
    }
}
