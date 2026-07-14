using System.Net;
using System.Net.Sockets;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

public sealed class LoopbackHealthProbe
{
    public async Task<IReadOnlyList<PortHealth>> ProbeAsync(
        IEnumerable<int> ports,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ports);
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "The timeout must be positive.");
        }

        var distinctPorts = ports.Distinct().ToArray();
        if (distinctPorts.Any(port => port is < 1 or > 65535))
        {
            throw new ArgumentOutOfRangeException(nameof(ports), "Ports must be between 1 and 65535.");
        }

        var probes = distinctPorts.Select(port => ProbePortAsync(port, timeout, cancellationToken));
        return await Task.WhenAll(probes).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PortHealth>> WaitUntilHealthyAsync(
        IEnumerable<int> ports,
        TimeSpan startupTimeout,
        CancellationToken cancellationToken = default)
    {
        var expectedPorts = ports.Distinct().ToArray();
        var deadline = DateTimeOffset.UtcNow + startupTimeout;
        IReadOnlyList<PortHealth> latest = [];

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            latest = await ProbeAsync(expectedPorts, TimeSpan.FromMilliseconds(750), cancellationToken).ConfigureAwait(false);
            if (latest.Count > 0 && latest.All(port => port.IsHealthy))
            {
                return latest;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
        }

        return latest.Count > 0
            ? latest
            : expectedPorts.Select(port => new PortHealth(port, false, "Startup timeout elapsed.")).ToArray();
    }

    private static async Task<PortHealth> ProbePortAsync(int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            await client.ConnectAsync(IPAddress.Loopback, port, timeoutSource.Token).ConfigureAwait(false);
            return new(port, true, "Listening on IPv4 loopback.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(port, false, "Connection timed out.");
        }
        catch (SocketException)
        {
            return new(port, false, "Not listening on IPv4 loopback.");
        }
    }
}
