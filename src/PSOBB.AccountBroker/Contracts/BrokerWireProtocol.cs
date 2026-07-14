using System.Buffers.Binary;

namespace PSOBB.AccountBroker.Contracts;

public static class BrokerWireProtocol
{
    private const int HeaderBytes = sizeof(int);

    public static async Task WriteAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ValidateLength(payload.Length, maximumBytes);
        var header = new byte[HeaderBytes];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    public static async Task<byte[]> ReadAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var header = new byte[HeaderBytes];
        await stream.ReadExactlyAsync(header, cancellationToken);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        ValidateLength(length, maximumBytes);
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken);
        return payload;
    }

    private static void ValidateLength(int length, int maximumBytes)
    {
        if (length <= 0 || length > maximumBytes)
        {
            throw new InvalidDataException("The broker message length is invalid.");
        }
    }
}
