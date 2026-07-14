namespace PSOBB.Portal.Accounts;

public sealed class AccountOperationLock
{
    private sealed class Entry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public int References { get; set; }
    }

    private readonly object sync = new();
    private readonly Dictionary<Guid, Entry> locks = [];

    public async ValueTask<IAsyncDisposable> AcquireAsync(
        Guid portalUserId,
        CancellationToken cancellationToken)
    {
        Entry entry;
        lock (sync)
        {
            if (!locks.TryGetValue(portalUserId, out entry!))
            {
                entry = new Entry();
                locks.Add(portalUserId, entry);
            }

            entry.References++;
        }

        try
        {
            await entry.Gate.WaitAsync(cancellationToken);
            return new Releaser(this, portalUserId, entry);
        }
        catch
        {
            ReleaseReference(portalUserId, entry);
            throw;
        }
    }

    private void Release(Guid portalUserId, Entry entry)
    {
        entry.Gate.Release();
        ReleaseReference(portalUserId, entry);
    }

    private void ReleaseReference(Guid portalUserId, Entry entry)
    {
        lock (sync)
        {
            entry.References--;
            if (entry.References == 0)
            {
                locks.Remove(portalUserId);
                entry.Gate.Dispose();
            }
        }
    }

    private sealed class Releaser(
        AccountOperationLock owner,
        Guid portalUserId,
        Entry entry) : IAsyncDisposable
    {
        private int released;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
            {
                owner.Release(portalUserId, entry);
            }

            return ValueTask.CompletedTask;
        }
    }
}
