using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

internal interface IRuntimeIdentityProbe
{
    Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default);
}

internal interface IRuntimePlatformProbe
{
    IReadOnlyList<RuntimeProcessIdentity> GetProcessesByName(string processName);

    RuntimeProcessIdentity? GetProcessById(int processId);

    IReadOnlyList<RuntimeTcpListener> GetTcpListeners();

    Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken = default);
}

internal sealed record RuntimeProcessIdentity(
    int ProcessId,
    string ProcessName,
    string ExecutablePath,
    DateTimeOffset StartTimeUtc)
{
    public long StartTimeFileTimeUtc => StartTimeUtc.UtcDateTime.ToFileTimeUtc();
}

internal sealed record RuntimeTcpListener(IPAddress LocalAddress, int LocalPort, int OwningProcessId);

internal sealed partial class ExactRuntimeIdentityProbe : IRuntimeIdentityProbe
{
    private static readonly int[] ReservedPorts = [11000, 12000, 12001];
    private readonly IRuntimeContractVerifier _contractVerifier;
    private readonly string _repositoryRoot;
    private readonly CanonicalLifecycleRepositoryGuard _rootGuard;
    private readonly IRuntimePlatformProbe _platform;

    public ExactRuntimeIdentityProbe(
        string repositoryRoot,
        IRuntimePlatformProbe? platform = null,
        IRuntimeContractVerifier? contractVerifier = null)
        : this(
            new CanonicalLifecycleRepositoryGuard(repositoryRoot),
            platform,
            contractVerifier)
    {
    }

    internal ExactRuntimeIdentityProbe(
        CanonicalLifecycleRepositoryGuard rootGuard,
        IRuntimePlatformProbe? platform = null,
        IRuntimeContractVerifier? contractVerifier = null)
    {
        _rootGuard = rootGuard ?? throw new ArgumentNullException(nameof(rootGuard));
        _repositoryRoot = rootGuard.ExpectedRepositoryRoot
            ?? throw new ArgumentException(
                "The exact runtime identity probe requires one repository-bound root guard.",
                nameof(rootGuard));
        _platform = platform ?? new WindowsRuntimePlatformProbe();
        _contractVerifier = contractVerifier ?? new PowerShellRuntimeContractVerifier(rootGuard);
    }

    public async Task<LifecycleSnapshot> ObserveAsync(
        string runtimeRoot,
        ServerEnvironmentKind serverEnvironment,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(runtimeRoot);
        var root = Path.GetFullPath(runtimeRoot);
        var sealedFiles = new Dictionary<string, SealedFileIdentity>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var canonicalLayout = _rootGuard.Validate(root);
            if (!canonicalLayout.RepositoryRoot.Equals(_repositoryRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    "The runtime identity observer resolved a different repository root.");
            }
            EnsureSafePath(_repositoryRoot, _repositoryRoot, mustExist: true);
            EnsureSafePath(root, root, mustExist: true);
            var contract = RuntimeEnvironmentContract.Create(root, serverEnvironment);
            var marker = await ReadRuntimeMarkerAsync(root, sealedFiles, cancellationToken)
                .ConfigureAwait(false);
            var initial = CaptureCensus();
            var reservedListeners = RelevantListeners(initial.Listeners, serverProcessId: null);
            var lifecyclePresence = contract.LifecycleEvidencePaths.ToDictionary(
                path => path,
                path =>
                {
                    EnsureSafePath(contract.RuntimeRoot, path, mustExist: false);
                    var present = TryCheckExistingPath(path);
                    if (present)
                    {
                        ProtectedRuntimeFileAcl.Require(
                            path,
                            contract.RuntimeRoot,
                            ProtectedRuntimeAclScope.ExactFileAndProducerBoundary);
                    }
                    return present;
                },
                StringComparer.OrdinalIgnoreCase);
            var processRecordPresent = lifecyclePresence[contract.ProcessRecordPath];
            var incompleteLifecycleEvidence = lifecyclePresence.Values.Any(present => present);

            if (!processRecordPresent)
            {
                if (incompleteLifecycleEvidence
                    || initial.Servers.Count > 0
                    || initial.Clients.Count > 0
                    || reservedListeners.Length > 0)
                {
                    return Faulted(
                        initial.Servers.Count > 0,
                        initial.Clients.Count > 0,
                        $"The selected {serverEnvironment} environment has incomplete or unbound lifecycle evidence.");
                }

                await RequireStableObservationAsync(
                    initial,
                    serverProcessId: null,
                    initialHost: null,
                    sealedFiles,
                    cancellationToken).ConfigureAwait(false);
                return new(
                    LauncherLifecycleState.Stopped,
                    ServerRunning: false,
                    ClientRunning: false,
                    $"The selected server environment and all approved clients are stopped for runtime installation {marker.InstallationId}.",
                    IdentityAuthenticated: true);
            }

            var approvedClient = await ReadApprovedIdentityAsync(
                "tethealla-59nl-english",
                "Psobb.exe",
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            var combatSeal = serverEnvironment == ServerEnvironmentKind.CombatCanary
                ? await ReadCombatInstallationSealAsync(
                    contract,
                    approvedClient,
                     sealedFiles,
                     cancellationToken).ConfigureAwait(false)
                : null;
            if (combatSeal is not null)
            {
                contract = contract with { ServerComponentId = combatSeal.ServerComponentId };
            }
            var approvedServer = await ReadApprovedIdentityAsync(
                contract.ServerComponentId,
                "release/newserv-windows.exe",
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            if (combatSeal is not null
                && (approvedServer.Size != combatSeal.ServerExecutable.Size
                    || !approvedServer.Sha256.Equals(
                        combatSeal.ServerExecutable.Sha256,
                        StringComparison.Ordinal)))
            {
                throw new InvalidDataException(
                    "The selected combat-canary build contract executable does not match its approved source-lock identity.");
            }
            var record = await ReadServerRecordAsync(
                contract,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);

            ValidateServerRecord(record, contract, marker, approvedServer, combatSeal);
            if (initial.Servers.Count != 1
                || !ProcessMatches(
                    initial.Servers[0],
                    record.ProcessId,
                    contract.ServerExecutablePath,
                    record.StartTimeFileTimeUtc))
            {
                return Faulted(
                    initial.Servers.Count > 0,
                    initial.Clients.Count > 0,
                    "The selected server record does not identify exactly one live child process with its recorded image and creation time.");
            }

            var host = _platform.GetProcessById(record.HostProcessId);
            ValidateSupervisorHost(record, host);
            await ValidateHostPidFileAsync(
                contract,
                record,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            await ValidateReadyControlStateAsync(
                contract,
                marker,
                record,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            await RequireFileIdentityAsync(
                contract.ServerExecutablePath,
                contract.EnvironmentRoot,
                approvedServer,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            ValidateServerLogs(contract, record);

            if (!HasExactListeners(initial.Listeners, record.ProcessId))
            {
                return Faulted(
                    true,
                    initial.Clients.Count > 0,
                    "The selected server does not own exactly the three approved loopback listeners.");
            }

            var client = await ValidateClientsAsync(
                contract,
                initial.Clients,
                approvedClient,
                combatSeal,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            if (!client.Valid)
            {
                return Faulted(true, initial.Clients.Count > 0, client.Detail);
            }

            await RequireStableObservationAsync(
                initial,
                record.ProcessId,
                host,
                sealedFiles,
                cancellationToken).ConfigureAwait(false);
            return client.Running
                ? new(
                    LauncherLifecycleState.Running,
                    ServerRunning: true,
                    ClientRunning: true,
                    "The selected supervised server and its exact receipt-bound client are running.",
                    IdentityAuthenticated: true)
                : new(
                    LauncherLifecycleState.ServerReady,
                    ServerRunning: true,
                    ClientRunning: false,
                    "The selected supervised server owns the exact approved loopback listener set; no client is running.",
                    IdentityAuthenticated: true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Faulted(false, false, $"Runtime identity authentication failed closed: {exception.Message}");
        }
    }

    private RuntimeCensus CaptureCensus()
    {
        return new(
            _platform.GetProcessesByName("newserv-windows").ToArray(),
            _platform.GetProcessesByName("Psobb").ToArray(),
            _platform.GetTcpListeners().ToArray());
    }

    private async Task RequireStableObservationAsync(
        RuntimeCensus initial,
        int? serverProcessId,
        RuntimeProcessIdentity? initialHost,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        await RequireSealedFilesUnchangedAsync(sealedFiles, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var final = CaptureCensus();
        if (!ProcessSetsEqual(initial.Servers, final.Servers)
            || !ProcessSetsEqual(initial.Clients, final.Clients)
            || !ListenerSetsEqual(
                RelevantListeners(initial.Listeners, serverProcessId),
                RelevantListeners(final.Listeners, serverProcessId)))
        {
            throw new InvalidDataException("The process or listener identity census changed during observation.");
        }
        if (initialHost is not null)
        {
            var finalHost = _platform.GetProcessById(initialHost.ProcessId);
            if (finalHost is null || !ProcessIdentitiesEqual(initialHost, finalHost))
            {
                throw new InvalidDataException("The supervisor host identity changed during observation.");
            }
        }
        await RequireSealedFilesUnchangedAsync(sealedFiles, cancellationToken).ConfigureAwait(false);
    }

    private static bool HasExactListeners(IReadOnlyList<RuntimeTcpListener> listeners, int processId)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "127.0.0.1:11000",
            "127.0.0.1:12000",
            "127.0.0.1:12001",
        };
        var relevant = RelevantListeners(listeners, processId);
        var actual = relevant.Select(listener => $"{listener.LocalAddress}:{listener.LocalPort}")
            .ToHashSet(StringComparer.Ordinal);
        return relevant.Length == expected.Count
            && relevant.All(listener => listener.OwningProcessId == processId)
            && actual.SetEquals(expected);
    }

    private static RuntimeTcpListener[] RelevantListeners(
        IReadOnlyList<RuntimeTcpListener> listeners,
        int? serverProcessId) => listeners
        .Where(listener => ReservedPorts.Contains(listener.LocalPort)
            || (serverProcessId.HasValue && listener.OwningProcessId == serverProcessId.Value))
        .OrderBy(listener => listener.LocalAddress.ToString(), StringComparer.Ordinal)
        .ThenBy(listener => listener.LocalPort)
        .ThenBy(listener => listener.OwningProcessId)
        .ToArray();

    private static bool ProcessSetsEqual(
        IReadOnlyList<RuntimeProcessIdentity> left,
        IReadOnlyList<RuntimeProcessIdentity> right)
    {
        var orderedLeft = left.OrderBy(process => process.ProcessId).ToArray();
        var orderedRight = right.OrderBy(process => process.ProcessId).ToArray();
        return orderedLeft.Length == orderedRight.Length
            && orderedLeft.Zip(orderedRight).All(pair => ProcessIdentitiesEqual(pair.First, pair.Second));
    }

    private static bool ProcessIdentitiesEqual(RuntimeProcessIdentity left, RuntimeProcessIdentity right) =>
        left.ProcessId == right.ProcessId
        && left.ProcessName.Equals(right.ProcessName, StringComparison.OrdinalIgnoreCase)
        && PathsEqual(left.ExecutablePath, right.ExecutablePath)
        && left.StartTimeFileTimeUtc == right.StartTimeFileTimeUtc;

    private static bool ListenerSetsEqual(
        IReadOnlyList<RuntimeTcpListener> left,
        IReadOnlyList<RuntimeTcpListener> right) => left.SequenceEqual(right);

    private static bool ProcessMatches(
        RuntimeProcessIdentity process,
        int processId,
        string executablePath,
        long startTimeFileTimeUtc) => process.ProcessId == processId
        && PathsEqual(process.ExecutablePath, executablePath)
        && process.StartTimeFileTimeUtc == startTimeFileTimeUtc;

    private static string ComputeControlIdentity(
        string installationId,
        string environmentId,
        string componentId,
        string startupRequestId,
        string executableSha256)
    {
        var canonical = string.Join(
            '\n',
            "psobb-newserv-control-v2",
            installationId.ToLowerInvariant(),
            environmentId,
            componentId,
            startupRequestId,
            executableSha256);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static bool FixedTimeTextEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length
            && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static bool ExactGamePorts(JsonElement binding)
    {
        if (!binding.TryGetProperty("gamePorts", out var ports)
            || ports.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        var values = ports.EnumerateArray().Select(value => value.GetInt32()).ToArray();
        return values.SequenceEqual([12000, 12001]);
    }

    private static void ValidateNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException($"Identity JSON contains a duplicate '{property.Name}' property.");
                }
                ValidateNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item);
            }
        }
    }

    private static void RequireExactProperties(
        JsonElement element,
        IEnumerable<string> expectedProperties,
        string label)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"The {label} is not an object.");
        }
        var actual = element.EnumerateObject().Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);
        var expected = expectedProperties.ToHashSet(StringComparer.Ordinal);
        if (!actual.SetEquals(expected))
        {
            throw new InvalidDataException($"The {label} does not have its exact property set.");
        }
    }

    private static JsonElement RequiredObject(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"Identity JSON is missing the required '{propertyName}' object.");
        }
        return value;
    }

    private static string RequiredString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || value.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException($"Identity JSON is missing the required '{propertyName}' string.");
        }
        return value.GetString()!;
    }

    private static string RequiredSha256(JsonElement element, string propertyName)
    {
        var value = RequiredString(element, propertyName);
        if (!IsLowerHex(value, 64))
        {
            throw new InvalidDataException($"Identity JSON has an invalid '{propertyName}' SHA-256.");
        }
        return value;
    }

    private static string? RequiredNullableString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            throw new InvalidDataException($"Identity JSON is missing '{propertyName}'.");
        }
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new InvalidDataException($"Identity JSON has an invalid nullable '{propertyName}' string.");
        }
        return value.GetString();
    }

    private static string? RequiredNullableSha256(JsonElement element, string propertyName)
    {
        var value = RequiredNullableString(element, propertyName);
        if (value is not null && !IsLowerHex(value, 64))
        {
            throw new InvalidDataException($"Identity JSON has an invalid nullable '{propertyName}' SHA-256.");
        }
        return value;
    }

    private static int RequiredInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || !value.TryGetInt32(out var result))
        {
            throw new InvalidDataException($"Identity JSON is missing the required '{propertyName}' integer.");
        }
        return result;
    }

    private static long RequiredInt64(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || !value.TryGetInt64(out var result))
        {
            throw new InvalidDataException($"Identity JSON is missing the required '{propertyName}' integer.");
        }
        return result;
    }

    private static double RequiredNumber(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) || !value.TryGetDouble(out var result))
        {
            throw new InvalidDataException($"Identity JSON is missing the required '{propertyName}' number.");
        }
        return result;
    }

    private static bool RequiredBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException($"Identity JSON is missing the required '{propertyName}' Boolean.");
        }
        return value.GetBoolean();
    }

    private static void RequiredNullableBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || value.ValueKind is not (JsonValueKind.Null or JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException($"Identity JSON has an invalid nullable '{propertyName}' Boolean.");
        }
    }

    private static void RequiredNullableInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || (value.ValueKind != JsonValueKind.Null && !value.TryGetInt32(out _)))
        {
            throw new InvalidDataException($"Identity JSON has an invalid nullable '{propertyName}' integer.");
        }
    }

    private static void RequiredNullableNumber(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || (value.ValueKind != JsonValueKind.Null && !value.TryGetDouble(out _)))
        {
            throw new InvalidDataException($"Identity JSON has an invalid nullable '{propertyName}' number.");
        }
    }

    private static void RequiredNullableScalar(
        JsonElement element,
        string propertyName,
        params JsonValueKind[] allowedKinds)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || (value.ValueKind != JsonValueKind.Null && !allowedKinds.Contains(value.ValueKind)))
        {
            throw new InvalidDataException($"Identity JSON has an invalid nullable '{propertyName}' scalar.");
        }
    }

    private static void RequiredScalar(
        JsonElement element,
        string propertyName,
        params JsonValueKind[] allowedKinds)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || !allowedKinds.Contains(value.ValueKind))
        {
            throw new InvalidDataException($"Identity JSON has an invalid '{propertyName}' scalar.");
        }
    }

    private static uint[] RequiredUInt32Array(JsonElement element, string propertyName, int count)
    {
        if (!element.TryGetProperty(propertyName, out var value)
            || value.ValueKind != JsonValueKind.Array
            || value.GetArrayLength() != count)
        {
            throw new InvalidDataException($"Identity JSON has an invalid '{propertyName}' array.");
        }
        return value.EnumerateArray().Select(item =>
        {
            if (!item.TryGetUInt32(out var result))
            {
                throw new InvalidDataException($"Identity JSON '{propertyName}' contains a non-UInt32 value.");
            }
            return result;
        }).ToArray();
    }

    private static DateTimeOffset RequiredDateTimeOffset(JsonElement element, string propertyName)
    {
        var text = RequiredString(element, propertyName);
        if (!DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var result))
        {
            throw new InvalidDataException($"Identity JSON has an invalid '{propertyName}' timestamp.");
        }
        return result;
    }

    private static bool IsLowerHex(string value, int length) =>
        value.Length == length && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsControlToken(string value) => value.Length == 43
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-');

    private static bool NullableTextEquals(string? left, string? right) =>
        left is null ? right is null : left.Equals(right, StringComparison.Ordinal);

    private static bool PathsEqual(string left, string right)
    {
        try
        {
            return Path.GetFullPath(left).Equals(Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException
            or NotSupportedException
            or PathTooLongException)
        {
            return false;
        }
    }

    private static LifecycleSnapshot Faulted(bool serverRunning, bool clientRunning, string detail) =>
        new(LauncherLifecycleState.Faulted, serverRunning, clientRunning, detail, IdentityAuthenticated: false);

}
