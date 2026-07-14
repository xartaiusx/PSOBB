using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LoopbackHealthProbeTests
{
    [TestMethod]
    public async Task ProbeAsync_ReportsLoopbackListenerHealthy()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var result = await new LoopbackHealthProbe().ProbeAsync([port], TimeSpan.FromSeconds(2));

        Assert.HasCount(1, result);
        Assert.IsTrue(result[0].IsHealthy);
        Assert.AreEqual(port, result[0].Port);
    }

    [TestMethod]
    public async Task ProbeAsync_RejectsInvalidPort()
    {
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            () => new LoopbackHealthProbe().ProbeAsync([0], TimeSpan.FromSeconds(1)));
    }
}
