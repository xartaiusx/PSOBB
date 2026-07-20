using System.Globalization;
using System.Text;
using System.Text.Json;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

internal sealed partial class ExactRuntimeIdentityProbe
{
    private static readonly string[] ServerRecordProperties =
    [
        "schemaVersion", "serverEnvironment", "environmentId", "componentId",
        "controlIdentity", "pid", "executablePath", "executableSha256",
        "startTimeUtc", "startTimeFileTimeUtc", "hostPid", "hostStartTimeUtc",
        "hostStartTimeFileTimeUtc",
        "hostExecutablePath", "startupRequestId", "controlToken", "controlProtocol",
        "buildContractSha256", "clientBindingSha256", "stateBindingSha256",
        "stdoutLog", "stderrLog",
    ];
    private static readonly string[] ReadyStateProperties =
    [
        "schemaVersion", "state", "installationId", "serverEnvironment",
        "environmentId", "componentId", "controlIdentity", "pid", "hostPid",
        "startTimeFileTimeUtc", "hostStartTimeFileTimeUtc", "startupRequestId",
        "startTimeUtc", "updatedAtUtc",
    ];

    private static void ValidateServerRecord(
        ServerProcessRecord record,
        RuntimeEnvironmentContract contract,
        RuntimeMarker marker,
        ApprovedFileIdentity approvedServer,
        CombatInstallationSeal? combatSeal)
    {
        if (record.SchemaVersion != 3
            || !record.ServerEnvironment.Equals(contract.EnvironmentName, StringComparison.Ordinal)
            || !record.EnvironmentId.Equals(contract.EnvironmentId, StringComparison.Ordinal)
            || !record.ComponentId.Equals(contract.ServerComponentId, StringComparison.Ordinal)
            || record.ProcessId <= 0
            || record.HostProcessId <= 0
            || !PathsEqual(record.ExecutablePath, contract.ServerExecutablePath)
            || !record.ExecutableSha256.Equals(approvedServer.Sha256, StringComparison.Ordinal)
            || !record.ControlProtocol.Equals("protected-filesystem-exit-v2", StringComparison.Ordinal)
            || !IsLowerHex(record.StartupRequestId, 32)
            || !IsControlToken(record.ControlToken))
        {
            throw new InvalidDataException("The selected server record does not match its exact environment and executable identity.");
        }
        var expectedControlIdentity = ComputeControlIdentity(
            marker.InstallationId,
            contract.EnvironmentId,
            contract.ServerComponentId,
            record.StartupRequestId,
            record.ExecutableSha256);
        if (!FixedTimeTextEquals(expectedControlIdentity, record.ControlIdentity))
        {
            throw new InvalidDataException("The selected server record control identity is not bound to this runtime installation.");
        }

        if (contract.ServerEnvironment == ServerEnvironmentKind.Stable)
        {
            if (record.BuildContractSha256 is not null
                || record.ClientBindingSha256 is not null
                || record.StateBindingSha256 is not null)
            {
                throw new InvalidDataException("The Stable server record contains an unexpected combat-canary seal.");
            }
        }
        else if (combatSeal is null
            || !record.BuildContractSha256!.Equals(combatSeal.BuildContractSha256, StringComparison.Ordinal)
            || !record.ClientBindingSha256!.Equals(combatSeal.ClientBindingSha256, StringComparison.Ordinal)
            || !record.StateBindingSha256!.Equals(combatSeal.StateBindingSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The combat-canary server record does not retain its signed installation bindings.");
        }
    }

    private static void ValidateSupervisorHost(
        ServerProcessRecord record,
        RuntimeProcessIdentity? host)
    {
        if (host is null
            || host.ProcessId != record.HostProcessId
            || !host.ProcessName.Equals("pwsh", StringComparison.OrdinalIgnoreCase)
            || !Path.GetFileName(host.ExecutablePath).Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)
            || !PathsEqual(host.ExecutablePath, record.HostExecutablePath)
            || host.StartTimeFileTimeUtc != record.HostStartTimeFileTimeUtc)
        {
            throw new InvalidDataException("The exact live PowerShell supervisor host identity is absent or changed.");
        }
        var hostItem = new FileInfo(host.ExecutablePath);
        if (!hostItem.Exists || hostItem.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException("The supervisor host executable is missing or a reparse point.");
        }
    }

    private async Task ValidateHostPidFileAsync(
        RuntimeEnvironmentContract contract,
        ServerProcessRecord record,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        var content = await ReadFileAndTrackAsync(
            contract.HostPidPath,
            contract.RuntimeRoot,
            32,
            sealedFiles,
            cancellationToken,
            protectedAclScope: ProtectedRuntimeAclScope.ExactFileAndProducerBoundary)
            .ConfigureAwait(false);
        var text = Encoding.ASCII.GetString(content.Bytes);
        if (!text.Equals(record.HostProcessId.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
        {
            throw new InvalidDataException("The protected supervisor host-PID file does not match the live host.");
        }
    }

    private async Task ValidateReadyControlStateAsync(
        RuntimeEnvironmentContract contract,
        RuntimeMarker marker,
        ServerProcessRecord record,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var stateFile = await ReadJsonFileAsync(
            contract.ControlStatePath,
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken,
            protectedAclScope: ProtectedRuntimeAclScope.ExactFileAndProducerBoundary)
            .ConfigureAwait(false);
        var state = stateFile.Document.RootElement;
        RequireExactProperties(state, ReadyStateProperties, "child-started supervisor control state");
        RequiredDateTimeOffset(state, "startTimeUtc");
        RequiredDateTimeOffset(state, "updatedAtUtc");
        if (RequiredInt32(state, "schemaVersion") != 3
            || !RequiredString(state, "state").Equals("child-started", StringComparison.Ordinal)
            || !RequiredString(state, "installationId").Equals(marker.InstallationId, StringComparison.OrdinalIgnoreCase)
            || !RequiredString(state, "serverEnvironment").Equals(contract.EnvironmentName, StringComparison.Ordinal)
            || !RequiredString(state, "environmentId").Equals(contract.EnvironmentId, StringComparison.Ordinal)
            || !RequiredString(state, "componentId").Equals(contract.ServerComponentId, StringComparison.Ordinal)
            || !FixedTimeTextEquals(RequiredString(state, "controlIdentity"), record.ControlIdentity)
            || RequiredInt32(state, "pid") != record.ProcessId
            || RequiredInt64(state, "startTimeFileTimeUtc") != record.StartTimeFileTimeUtc
            || RequiredInt32(state, "hostPid") != record.HostProcessId
            || RequiredInt64(state, "hostStartTimeFileTimeUtc") != record.HostStartTimeFileTimeUtc
            || !RequiredString(state, "startupRequestId").Equals(record.StartupRequestId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The protected child-started control state does not match the supervised server record.");
        }
    }

    private static void ValidateServerLogs(RuntimeEnvironmentContract contract, ServerProcessRecord record)
    {
        foreach (var (path, suffix) in new[]
        {
            (record.StandardOutputLog, ".stdout.log"),
            (record.StandardErrorLog, ".stderr.log"),
        })
        {
            EnsureSafePath(contract.LogsRoot, path, mustExist: true);
            var name = Path.GetFileName(path);
            if (!name.StartsWith("newserv-", StringComparison.Ordinal)
                || !name.EndsWith(suffix, StringComparison.Ordinal)
                || new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidDataException("A supervised server log path is not exact or safe.");
            }
        }
    }

    private async Task<RuntimeMarker> ReadRuntimeMarkerAsync(
        string runtimeRoot,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var markerFile = await ReadJsonFileAsync(
            Path.Combine(runtimeRoot, ".psobb-runtime.json"),
            runtimeRoot,
            sealedFiles,
            cancellationToken,
            protectedAclScope: ProtectedRuntimeAclScope.ExactFileWithTrustedOwner).ConfigureAwait(false);
        var marker = markerFile.Document.RootElement;
        RequireExactProperties(
            marker,
            ["schemaVersion", "installationId", "runtimeRoot", "createdAtUtc"],
            "runtime ownership marker");
        var installationId = RequiredString(marker, "installationId");
        RequiredDateTimeOffset(marker, "createdAtUtc");
        if (RequiredInt32(marker, "schemaVersion") != 1
            || !Guid.TryParseExact(installationId, "D", out _)
            || !PathsEqual(RequiredString(marker, "runtimeRoot"), runtimeRoot))
        {
            throw new InvalidDataException("The runtime ownership marker is invalid or belongs to another root.");
        }
        return new(installationId.ToLowerInvariant());
    }

    private async Task<ServerProcessRecord> ReadServerRecordAsync(
        RuntimeEnvironmentContract contract,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var recordFile = await ReadJsonFileAsync(
            contract.ProcessRecordPath,
            contract.RuntimeRoot,
            sealedFiles,
            cancellationToken,
            protectedAclScope: ProtectedRuntimeAclScope.ExactFileAndProducerBoundary)
            .ConfigureAwait(false);
        var record = recordFile.Document.RootElement;
        RequireExactProperties(record, ServerRecordProperties, "schema-3 supervised server process record");
        return new(
            RequiredInt32(record, "schemaVersion"),
            RequiredString(record, "serverEnvironment"),
            RequiredString(record, "environmentId"),
            RequiredString(record, "componentId"),
            RequiredString(record, "controlIdentity"),
            RequiredInt32(record, "pid"),
            RequiredString(record, "executablePath"),
            RequiredSha256(record, "executableSha256"),
            RequiredDateTimeOffset(record, "startTimeUtc"),
            RequiredInt64(record, "startTimeFileTimeUtc"),
            RequiredInt32(record, "hostPid"),
            RequiredDateTimeOffset(record, "hostStartTimeUtc"),
            RequiredInt64(record, "hostStartTimeFileTimeUtc"),
            RequiredString(record, "hostExecutablePath"),
            RequiredString(record, "startupRequestId"),
            RequiredString(record, "controlToken"),
            RequiredString(record, "controlProtocol"),
            RequiredNullableSha256(record, "buildContractSha256"),
            RequiredNullableSha256(record, "clientBindingSha256"),
            RequiredNullableSha256(record, "stateBindingSha256"),
            RequiredString(record, "stdoutLog"),
            RequiredString(record, "stderrLog"));
    }

    private async Task<ApprovedFileIdentity> ReadApprovedIdentityAsync(
        string componentId,
        string memberPath,
        Dictionary<string, SealedFileIdentity> sealedFiles,
        CancellationToken cancellationToken)
    {
        using var sourcesFile = await ReadJsonFileAsync(
            Path.Combine(_repositoryRoot, "config", "sources.lock.json"),
            _repositoryRoot,
            sealedFiles,
            cancellationToken,
            allowTrailingCommas: true).ConfigureAwait(false);
        var sources = sourcesFile.Document.RootElement;
        if (!sources.TryGetProperty("components", out var components)
            || components.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The tracked source lock does not contain a components array.");
        }
        var matches = components.EnumerateArray()
            .Where(component => RequiredString(component, "id").Equals(componentId, StringComparison.Ordinal))
            .ToArray();
        if (matches.Length != 1
            || !matches[0].TryGetProperty("members", out var members)
            || members.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"The tracked source lock does not contain one '{componentId}' member set.");
        }
        var memberMatches = members.EnumerateArray()
            .Where(member => RequiredString(member, "path").Equals(memberPath, StringComparison.Ordinal))
            .ToArray();
        if (memberMatches.Length != 1)
        {
            throw new InvalidDataException($"The tracked source lock does not contain one '{memberPath}' member.");
        }
        var size = RequiredInt64(memberMatches[0], "size");
        var sha256 = RequiredSha256(memberMatches[0], "sha256");
        if (size <= 0)
        {
            throw new InvalidDataException("The tracked executable identity has an invalid size.");
        }
        return new(size, sha256);
    }
}
