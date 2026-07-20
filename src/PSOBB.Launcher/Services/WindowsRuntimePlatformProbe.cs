using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PSOBB.Launcher.Services;

internal sealed class WindowsRuntimePlatformProbe : IRuntimePlatformProbe
{
    private const int AddressFamilyInternet = 2;
    private const int AddressFamilyInternetV6 = 23;
    private const uint ErrorNoData = 232;
    private const uint ErrorInsufficientBuffer = 122;
    private const int TcpTableOwnerPidListener = 3;

    public IReadOnlyList<RuntimeProcessIdentity> GetProcessesByName(string processName)
    {
        var results = new List<RuntimeProcessIdentity>();
        foreach (var process in Process.GetProcessesByName(processName))
        {
            using (process)
            {
                results.Add(InspectProcess(process, processName));
            }
        }
        return results;
    }

    public RuntimeProcessIdentity? GetProcessById(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return InspectProcess(process, $"PID {processId}");
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    public IReadOnlyList<RuntimeTcpListener> GetTcpListeners() =>
        [.. GetIpv4TcpListeners(), .. GetIpv6TcpListeners()];

    public async Task<string> ComputeSha256Async(
        string path,
        CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(
            await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();
    }

    private static RuntimeProcessIdentity InspectProcess(Process process, string label)
    {
        try
        {
            var path = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new InvalidOperationException("Windows returned no process image path.");
            }
            return new(
                process.Id,
                process.ProcessName,
                Path.GetFullPath(path),
                new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero));
        }
        catch (Exception exception) when (exception is InvalidOperationException
            or System.ComponentModel.Win32Exception
            or NotSupportedException)
        {
            throw new InvalidOperationException($"The named {label} process could not be identity-inspected.", exception);
        }
    }

    private static List<RuntimeTcpListener> GetIpv4TcpListeners()
    {
        var (buffer, count) = ReadListenerTable(AddressFamilyInternet);
        if (buffer == IntPtr.Zero)
        {
            return [];
        }
        try
        {
            var rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
            var cursor = IntPtr.Add(buffer, sizeof(int));
            var listeners = new List<RuntimeTcpListener>(count);
            for (var index = 0; index < count; index++)
            {
                var row = Marshal.PtrToStructure<TcpRowOwnerPid>(cursor);
                listeners.Add(new(
                    new IPAddress(BitConverter.GetBytes(row.LocalAddress)),
                    NetworkPort(row.LocalPort),
                    checked((int)row.OwningProcessId)));
                cursor = IntPtr.Add(cursor, rowSize);
            }
            return listeners;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static List<RuntimeTcpListener> GetIpv6TcpListeners()
    {
        var (buffer, count) = ReadListenerTable(AddressFamilyInternetV6);
        if (buffer == IntPtr.Zero)
        {
            return [];
        }
        try
        {
            var rowSize = Marshal.SizeOf<Tcp6RowOwnerPid>();
            var cursor = IntPtr.Add(buffer, sizeof(int));
            var listeners = new List<RuntimeTcpListener>(count);
            for (var index = 0; index < count; index++)
            {
                var row = Marshal.PtrToStructure<Tcp6RowOwnerPid>(cursor);
                listeners.Add(new(
                    new IPAddress(row.LocalAddress, row.LocalScopeId),
                    NetworkPort(row.LocalPort),
                    checked((int)row.OwningProcessId)));
                cursor = IntPtr.Add(cursor, rowSize);
            }
            return listeners;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static (IntPtr Buffer, int Count) ReadListenerTable(int addressFamily)
    {
        var size = 0;
        var result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            order: true,
            addressFamily,
            TcpTableOwnerPidListener,
            reserved: 0);
        if (result == ErrorNoData)
        {
            return (IntPtr.Zero, 0);
        }
        if (result != ErrorInsufficientBuffer || size <= 0)
        {
            throw new InvalidOperationException($"Windows could not size the TCP listener table (error {result}).");
        }

        var buffer = Marshal.AllocHGlobal(size);
        result = GetExtendedTcpTable(
            buffer,
            ref size,
            order: true,
            addressFamily,
            TcpTableOwnerPidListener,
            reserved: 0);
        if (result != 0)
        {
            Marshal.FreeHGlobal(buffer);
            throw new InvalidOperationException($"Windows could not read the TCP listener table (error {result}).");
        }
        return (buffer, Marshal.ReadInt32(buffer));
    }

    private static int NetworkPort(uint port)
    {
        var bytes = BitConverter.GetBytes(port);
        return (bytes[0] << 8) | bytes[1];
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Tcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddress;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningProcessId;
    }
}
