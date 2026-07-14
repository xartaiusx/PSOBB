using PSOBB.Portal.Accounts;

namespace PSOBB.Accounts.Tests;

public sealed class AccountOperationLockTests
{
    [Fact]
    public async Task SameAccountOperationsAreSerialized()
    {
        var accountLock = new AccountOperationLock();
        var userId = Guid.NewGuid();
        await using var first = await accountLock.AcquireAsync(userId, CancellationToken.None);
        var secondTask = accountLock.AcquireAsync(userId, CancellationToken.None).AsTask();

        await Task.Delay(25);
        Assert.False(secondTask.IsCompleted);
        await first.DisposeAsync();
        await using var second = await secondTask.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CancelledWaiterDoesNotPoisonFutureAcquisition()
    {
        var accountLock = new AccountOperationLock();
        var userId = Guid.NewGuid();
        await using var first = await accountLock.AcquireAsync(userId, CancellationToken.None);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(25));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await accountLock.AcquireAsync(userId, cancellation.Token));
        await first.DisposeAsync();
        await using var next = await accountLock.AcquireAsync(userId, CancellationToken.None);
    }
}
