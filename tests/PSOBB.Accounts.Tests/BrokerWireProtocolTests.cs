using PSOBB.AccountBroker.Contracts;

namespace PSOBB.Accounts.Tests;

public sealed class BrokerWireProtocolTests
{
    [Fact]
    public async Task RoundTripUsesBoundedLengthPrefix()
    {
        var payload = "hello broker"u8.ToArray();
        await using var stream = new MemoryStream();
        await BrokerWireProtocol.WriteAsync(stream, payload, 1024, CancellationToken.None);
        stream.Position = 0;

        var result = await BrokerWireProtocol.ReadAsync(stream, 1024, CancellationToken.None);

        Assert.Equal(payload, result);
    }

    [Fact]
    public async Task OversizedFrameIsRejectedBeforeAllocation()
    {
        await using var stream = new MemoryStream([0, 1, 0, 0]);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            BrokerWireProtocol.ReadAsync(stream, 4096, CancellationToken.None));
    }

    [Fact]
    public async Task TruncatedFrameIsRejected()
    {
        await using var stream = new MemoryStream([0, 0, 0, 4, 1, 2]);

        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            BrokerWireProtocol.ReadAsync(stream, 4096, CancellationToken.None));
    }
}
