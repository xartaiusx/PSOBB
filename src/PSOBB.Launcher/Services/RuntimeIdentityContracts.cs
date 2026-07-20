using System.Text.Json;
using PSOBB.Launcher.Models;

namespace PSOBB.Launcher.Services;

internal sealed partial class ExactRuntimeIdentityProbe
{
    private sealed record RuntimeMarker(string InstallationId);

    private sealed record ApprovedFileIdentity(long Size, string Sha256);

    private sealed record ClientValidation(bool Valid, bool Running, string Detail);

    private sealed record ClientProfileSeal(
        string Channel,
        string ProfileId,
        string ProfileSha256,
        string? ConfigurationSha256,
        string NativeGraphicsPresetId,
        string GraphicCtrlSha256);

    private sealed record CombatInstallationSeal(
        string ServerArtifact,
        string ServerComponentId,
        ApprovedFileIdentity ServerExecutable,
        string BuildContractSha256,
        string ClientBindingSha256,
        string StateBindingSha256,
        string BaseClientManifestSha256,
        string TwillsContractSha256,
        string SigningPublicKeySpkiSha256);

    private sealed record CombatBuildContractSelection(
        string Artifact,
        string ContractPath,
        string ProfileId,
        string ServerComponentId,
        ApprovedFileIdentity ServerExecutable);

    private sealed record ServerProcessRecord(
        int SchemaVersion,
        string ServerEnvironment,
        string EnvironmentId,
        string ComponentId,
        string ControlIdentity,
        int ProcessId,
        string ExecutablePath,
        string ExecutableSha256,
        DateTimeOffset StartTimeUtc,
        long StartTimeFileTimeUtc,
        int HostProcessId,
        DateTimeOffset HostStartTimeUtc,
        long HostStartTimeFileTimeUtc,
        string HostExecutablePath,
        string StartupRequestId,
        string ControlToken,
        string ControlProtocol,
        string? BuildContractSha256,
        string? ClientBindingSha256,
        string? StateBindingSha256,
        string StandardOutputLog,
        string StandardErrorLog);

    private sealed record RuntimeCensus(
        IReadOnlyList<RuntimeProcessIdentity> Servers,
        IReadOnlyList<RuntimeProcessIdentity> Clients,
        IReadOnlyList<RuntimeTcpListener> Listeners);

    private sealed record RuntimeClientContract(string Channel, string ExecutablePath, string ProfilePath);

    private sealed record RuntimeEnvironmentContract(
        string RuntimeRoot,
        ServerEnvironmentKind ServerEnvironment,
        string EnvironmentName,
        string EnvironmentId,
        string ServerComponentId,
        string EnvironmentRoot,
        string ServerRoot,
        string ServerBaseRoot,
        string ServerExecutablePath,
        string ProcessRecordPath,
        string HostPidPath,
        string ControlStatePath,
        string InstallationPath,
        string ClientBindingPath,
        string LogsRoot,
        IReadOnlyList<string> LifecycleEvidencePaths,
        IReadOnlyList<RuntimeClientContract> Clients)
    {
        public static RuntimeEnvironmentContract Create(
            string runtimeRoot,
            ServerEnvironmentKind serverEnvironment)
        {
            var root = Path.GetFullPath(runtimeRoot);
            var environmentRoot = serverEnvironment switch
            {
                ServerEnvironmentKind.Stable => Path.Combine(root, "stable"),
                ServerEnvironmentKind.CombatCanary => Path.Combine(root, "combat-canary"),
                _ => throw new ArgumentOutOfRangeException(nameof(serverEnvironment)),
            };
            var controlRoot = Path.Combine(environmentRoot, "control");
            var clients = serverEnvironment == ServerEnvironmentKind.CombatCanary
                ? new[]
                {
                    new RuntimeClientContract(
                        "combat-canary",
                        Path.Combine(environmentRoot, "runtime", "client", "Psobb.exe"),
                        Path.Combine(environmentRoot, "runtime", "client", "client-profile.json")),
                }
                : new[]
                {
                    new RuntimeClientContract(
                        "stable",
                        Path.Combine(root, "stable", "runtime", "client", "Psobb.exe"),
                        Path.Combine(root, "stable", "runtime", "client", "client-profile.json")),
                    new RuntimeClientContract(
                        "canary",
                        Path.Combine(root, "canary", "runtime", "client", "Psobb.exe"),
                        Path.Combine(root, "canary", "runtime", "client", "client-profile.json")),
                    new RuntimeClientContract(
                        "local-lab",
                        Path.Combine(root, "local-lab", "runtime", "client", "Psobb.exe"),
                        Path.Combine(root, "local-lab", "runtime", "client", "client-profile.json")),
                };
            var serverRoot = Path.Combine(environmentRoot, "server", "release");
            return new(
                root,
                serverEnvironment,
                serverEnvironment == ServerEnvironmentKind.Stable ? "Stable" : "CombatCanary",
                serverEnvironment == ServerEnvironmentKind.Stable ? "stable" : "combat-canary",
                serverEnvironment == ServerEnvironmentKind.Stable
                    ? "newserv-stable-release"
                    : "newserv-combat-canary-build",
                environmentRoot,
                serverRoot,
                Path.Combine(environmentRoot, "server-base", "release"),
                Path.Combine(serverRoot, "newserv-windows.exe"),
                Path.Combine(controlRoot, "newserv.process.json"),
                Path.Combine(controlRoot, "newserv-host.pid"),
                Path.Combine(controlRoot, "newserv-control.json"),
                Path.Combine(environmentRoot, "installation.json"),
                Path.Combine(environmentRoot, "client-binding.json"),
                serverEnvironment == ServerEnvironmentKind.Stable
                    ? Path.Combine(root, "logs")
                    : Path.Combine(environmentRoot, "logs"),
                [
                    Path.Combine(controlRoot, "newserv.process.json"),
                    Path.Combine(controlRoot, "newserv.pid"),
                    Path.Combine(controlRoot, "newserv-host.pid"),
                    Path.Combine(controlRoot, "newserv-control.json"),
                    Path.Combine(controlRoot, "newserv-control.request.json"),
                ],
                clients);
        }
    }

    private sealed record SealedFileIdentity(
        string Path,
        string ContainmentRoot,
        long MaximumBytes,
        ProtectedRuntimeAclScope? ProtectedAclScope,
        long Size,
        string Sha256);

    private sealed record FileContent(byte[] Bytes, SealedFileIdentity Identity);

    private sealed class JsonFileContent(JsonDocument document, SealedFileIdentity identity) : IDisposable
    {
        public JsonDocument Document { get; } = document;

        public SealedFileIdentity Identity { get; } = identity;

        public void Dispose() => Document.Dispose();
    }
}
