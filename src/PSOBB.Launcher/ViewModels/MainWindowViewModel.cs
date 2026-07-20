using System.Windows.Input;
using Microsoft.Win32;
using PSOBB.Launcher.Infrastructure;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.ViewModels;

public sealed class MainWindowViewModel : ObservableObject, IAsyncDisposable
{
    private readonly LauncherManifestLoader _manifestLoader;
    private readonly DiagnosticReportBuilder _diagnostics = new();
    private readonly ILauncherCoordinator _coordinator;
    private string _manifestPath;
    private string _runtimeRoot;
    private ServerEnvironmentKind _selectedServerEnvironment;
    private ReleaseChannel _selectedChannel;
    private GraphicsProfileOption _selectedGraphicsProfile;
    private MonitorOption _selectedMonitor;
    private LauncherWindowMode _selectedWindowMode;
    private bool _preserveForeground;
    private bool _safeMode;
    private LauncherLifecycleState _lifecycleState = LauncherLifecycleState.Stopped;
    private string _manifestSummary = "No manifest loaded.";
    private string _verificationSummary = "Not verified.";
    private string _status = "Ready to observe the script-managed local runtime.";
    private ReleaseManifest? _manifest;
    private ReleaseVerification? _verification;
    private IReadOnlyList<PortHealth> _portHealth = [];
    private long _environmentGeneration;

    public MainWindowViewModel() : this(LauncherOptions.Defaults())
    {
    }

    public MainWindowViewModel(LauncherOptions options) : this(
        options,
        new LauncherManifestLoader(new ReleaseManifestService()),
        LauncherServices.CreateCoordinator(options.RuntimeRoot))
    {
    }

    internal MainWindowViewModel(
        LauncherOptions options,
        LauncherManifestLoader manifestLoader,
        ILauncherCoordinator coordinator)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(manifestLoader);
        ArgumentNullException.ThrowIfNull(coordinator);
        _manifestPath = options.ManifestPath;
        _runtimeRoot = options.RuntimeRoot;
        _selectedServerEnvironment = options.ServerEnvironment;
        _selectedChannel = options.ServerEnvironment == ServerEnvironmentKind.CombatCanary
            ? ReleaseChannel.Stable
            : options.Selection.Channel;
        _selectedGraphicsProfile = options.ServerEnvironment == ServerEnvironmentKind.CombatCanary
            ? GraphicsProfileOption.SafeNative
            : options.Selection.Profile;
        _selectedMonitor = options.Selection.Monitor;
        _selectedWindowMode = options.ServerEnvironment == ServerEnvironmentKind.CombatCanary
            ? LauncherWindowMode.ProfileDefault
            : options.Selection.WindowMode;
        _preserveForeground = options.Selection.PreserveForeground;
        _safeMode = _selectedGraphicsProfile.SafeMode;

        _manifestLoader = manifestLoader;
        _coordinator = coordinator;

        BrowseManifestCommand = new RelayCommand(BrowseManifest);
        BrowseRuntimeCommand = new RelayCommand(BrowseRuntime);
        LoadManifestCommand = new AsyncRelayCommand(() => RunGuardedAsync(LoadManifestAsync));
        VerifyCommand = new AsyncRelayCommand(() => RunGuardedAsync(VerifyAsync));
        RefreshStateCommand = new AsyncRelayCommand(
            () => RunEnvironmentGuardedAsync(RefreshStateAsync));
        StartSessionCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.ServerStarting, StartSessionAsync));
        StartServerCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.ServerStarting, StartServerAsync));
        StartClientCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.ClientStarting, StartClientAsync));
        StopClientCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.Stopping, StopClientAsync));
        StopServerCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.Stopping, StopServerAsync));
        StopAllCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.Stopping, StopAllAsync));
        RepairCommand = new AsyncRelayCommand(
            () => RunLifecycleAsync(LauncherLifecycleState.Stopping, RepairAsync));
        ExportDiagnosticsCommand = new AsyncRelayCommand(() => RunGuardedAsync(ExportDiagnosticsAsync));
    }

    public IReadOnlyList<ReleaseChannel> Channels { get; } = Enum.GetValues<ReleaseChannel>();

    public IReadOnlyList<ServerEnvironmentKind> ServerEnvironments { get; } =
        Enum.GetValues<ServerEnvironmentKind>();

    public IReadOnlyList<GraphicsProfileOption> GraphicsProfiles { get; } = GraphicsProfileOption.Supported;

    public IReadOnlyList<MonitorOption> Monitors { get; } = MonitorOption.Supported;

    public IReadOnlyList<LauncherWindowMode> WindowModes { get; } = Enum.GetValues<LauncherWindowMode>();

    public string ManifestPath
    {
        get => _manifestPath;
        set => SetProperty(ref _manifestPath, value);
    }

    public string RuntimeRoot
    {
        get => _runtimeRoot;
        set
        {
            if (SetProperty(ref _runtimeRoot, value))
            {
                Interlocked.Increment(ref _environmentGeneration);
                InvalidateEnvironmentStatus();
            }
        }
    }

    public ServerEnvironmentKind SelectedServerEnvironment
    {
        get => _selectedServerEnvironment;
        set
        {
            if (!SetProperty(ref _selectedServerEnvironment, value))
            {
                return;
            }

            OnPropertyChanged(nameof(StableGraphicsSelectionEnabled));
            if (value == ServerEnvironmentKind.CombatCanary)
            {
                SelectedChannel = ReleaseChannel.Stable;
                SelectedGraphicsProfile = GraphicsProfileOption.SafeNative;
                SelectedWindowMode = LauncherWindowMode.ProfileDefault;
            }
            Interlocked.Increment(ref _environmentGeneration);
            InvalidateEnvironmentStatus();
        }
    }

    public bool StableGraphicsSelectionEnabled =>
        SelectedServerEnvironment == ServerEnvironmentKind.Stable;

    public ReleaseChannel SelectedChannel
    {
        get => _selectedChannel;
        set
        {
            if (SelectedServerEnvironment == ServerEnvironmentKind.CombatCanary)
            {
                value = ReleaseChannel.Stable;
            }
            if (!SetProperty(ref _selectedChannel, value) || _selectedGraphicsProfile.Channel == value)
            {
                return;
            }

            SelectedGraphicsProfile = value switch
            {
                ReleaseChannel.Stable => GraphicsProfileOption.SafeNative,
                ReleaseChannel.Canary => GraphicsProfileOption.ClarityDgVoodoo,
                ReleaseChannel.LocalLab => GraphicsProfileOption.LocalLabWidescreen,
                _ => throw new ArgumentOutOfRangeException(nameof(value)),
            };
        }
    }

    public GraphicsProfileOption SelectedGraphicsProfile
    {
        get => _selectedGraphicsProfile;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            if (SelectedServerEnvironment == ServerEnvironmentKind.CombatCanary)
            {
                value = GraphicsProfileOption.SafeNative;
            }
            if (!SetProperty(ref _selectedGraphicsProfile, value))
            {
                return;
            }

            SetProperty(ref _selectedChannel, value.Channel, nameof(SelectedChannel));
            SetProperty(ref _safeMode, value.SafeMode, nameof(SafeMode));
        }
    }

    public MonitorOption SelectedMonitor
    {
        get => _selectedMonitor;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            SetProperty(ref _selectedMonitor, value);
        }
    }

    public LauncherWindowMode SelectedWindowMode
    {
        get => _selectedWindowMode;
        set => SetProperty(
            ref _selectedWindowMode,
            SelectedServerEnvironment == ServerEnvironmentKind.CombatCanary
                ? LauncherWindowMode.ProfileDefault
                : value);
    }

    public bool PreserveForeground
    {
        get => _preserveForeground;
        set => SetProperty(ref _preserveForeground, value);
    }

    public bool SafeMode
    {
        get => _safeMode;
        set
        {
            if (SelectedServerEnvironment == ServerEnvironmentKind.CombatCanary)
            {
                SetProperty(ref _safeMode, true);
                SelectedGraphicsProfile = GraphicsProfileOption.SafeNative;
                return;
            }
            if (!SetProperty(ref _safeMode, value))
            {
                return;
            }

            SelectedGraphicsProfile = value
                ? GraphicsProfileOption.SafeNative
                : GraphicsProfileOption.ClarityDgVoodoo;
        }
    }

    public LauncherLifecycleState LifecycleState
    {
        get => _lifecycleState;
        private set
        {
            if (SetProperty(ref _lifecycleState, value))
            {
                OnPropertyChanged(nameof(LifecycleStateText));
            }
        }
    }

    public string LifecycleStateText => LifecycleState switch
    {
        LauncherLifecycleState.Unknown => "Not observed",
        LauncherLifecycleState.Stopped => "Stopped",
        LauncherLifecycleState.ServerStarting => "Server starting",
        LauncherLifecycleState.ServerReady => "Server ready",
        LauncherLifecycleState.ClientStarting => "Client starting",
        LauncherLifecycleState.Running => "Running",
        LauncherLifecycleState.Stopping => "Stopping",
        LauncherLifecycleState.Faulted => "Faulted",
        _ => LifecycleState.ToString(),
    };

    public string ManifestSummary
    {
        get => _manifestSummary;
        private set => SetProperty(ref _manifestSummary, value);
    }

    public string VerificationSummary
    {
        get => _verificationSummary;
        private set => SetProperty(ref _verificationSummary, value);
    }

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public ICommand BrowseManifestCommand { get; }

    public ICommand BrowseRuntimeCommand { get; }

    public ICommand LoadManifestCommand { get; }

    public ICommand VerifyCommand { get; }

    public ICommand RefreshStateCommand { get; }

    public ICommand StartSessionCommand { get; }

    public ICommand StartServerCommand { get; }

    public ICommand StartClientCommand { get; }

    public ICommand StopClientCommand { get; }

    public ICommand StopServerCommand { get; }

    public ICommand StopAllCommand { get; }

    public ICommand RepairCommand { get; }

    public ICommand ExportDiagnosticsCommand { get; }

    public ValueTask DisposeAsync() => _coordinator.DisposeAsync();

    public Task InitializeAsync() => RunEnvironmentGuardedAsync(RefreshStateAsync);

    private void BrowseManifest()
    {
        var dialog = new OpenFileDialog
        {
            CheckFileExists = true,
            DefaultExt = ".json",
            Filter = "PSOBB release manifest (*.json)|*.json|All files (*.*)|*.*",
            Multiselect = false,
            Title = "Choose release-manifest.json",
        };
        if (dialog.ShowDialog() == true)
        {
            ManifestPath = dialog.FileName;
        }
    }

    private void BrowseRuntime()
    {
        var dialog = new OpenFolderDialog
        {
            Multiselect = false,
            Title = "Choose the PSOBB runtime root",
        };
        if (dialog.ShowDialog() == true)
        {
            RuntimeRoot = dialog.FolderName;
        }
    }

    private async Task LoadManifestAsync()
    {
        var loaded = await _manifestLoader.LoadAsync(ManifestPath, AppContext.BaseDirectory);
        ApplyLoadedManifest(loaded);
    }

    internal void ApplyLoadedManifest(LoadedReleaseManifest loaded)
    {
        ArgumentNullException.ThrowIfNull(loaded);
        _manifest = loaded.Manifest;
        _verification = null;
        _portHealth = [];
        if (SelectedServerEnvironment == ServerEnvironmentKind.Stable)
        {
            SelectedChannel = _manifest.Channel;
        }
        else
        {
            SelectedChannel = ReleaseChannel.Stable;
            SelectedGraphicsProfile = GraphicsProfileOption.SafeNative;
            SelectedWindowMode = LauncherWindowMode.ProfileDefault;
        }
        ManifestSummary = FormatManifestSummary(_manifest, loaded.TrustMode);
        VerificationSummary = "Not verified.";
        Status = loaded.TrustMode == ManifestTrustMode.VerifiedDetachedSignature
            ? "Detached signature, manifest schema, and security constraints passed."
            : "Unsigned local-development manifest passed schema validation. Production packaging must include release-public-key.pem.";
    }

    private async Task VerifyAsync()
    {
        var manifest = await EnsureCurrentManifestAsync();
        _verification = await _coordinator.VerifyAsync(manifest, RuntimeRoot);
        VerificationSummary = FormatVerification(_verification);
        Status = _verification.IsSuccess
            ? "Every artifact and required base hash passed SHA-256 verification."
            : "Verification failed. Launch remains blocked.";
    }

    private async Task RefreshStateAsync(EnvironmentRequest request)
    {
        var snapshot = await _coordinator.ObserveAsync(
            request.RuntimeRoot, request.ServerEnvironment);
        TryApplySnapshot(snapshot, request);
    }

    private async Task StartSessionAsync(EnvironmentRequest request) =>
        TryApplySnapshot(await _coordinator.StartSessionAsync(
            request.RuntimeRoot, request.Selection, request.ServerEnvironment), request);

    private async Task StartServerAsync(EnvironmentRequest request) =>
        TryApplySnapshot(await _coordinator.StartServerAsync(
            request.RuntimeRoot, request.ServerEnvironment), request);

    private async Task StartClientAsync(EnvironmentRequest request) =>
        TryApplySnapshot(await _coordinator.StartClientAsync(
            request.RuntimeRoot, request.Selection, request.ServerEnvironment), request);

    private async Task StopClientAsync(EnvironmentRequest request) =>
        TryApplySnapshot(await _coordinator.StopClientAsync(
            request.RuntimeRoot, request.ServerEnvironment), request);

    private async Task StopServerAsync(EnvironmentRequest request) =>
        TryApplySnapshot(await _coordinator.StopServerAsync(
            request.RuntimeRoot, request.ServerEnvironment), request);

    private async Task StopAllAsync(EnvironmentRequest request) =>
        TryApplySnapshot(await _coordinator.StopAllAsync(
            request.RuntimeRoot, request.ServerEnvironment), request);

    private async Task RepairAsync(EnvironmentRequest request)
    {
        var applied = TryApplySnapshot(await _coordinator.RepairClientAsync(
            request.RuntimeRoot, request.Selection, request.ServerEnvironment), request);
        if (applied)
        {
            Status = $"Profile '{request.Selection.Profile.Id}' was verified or repaired through its approved runtime script.";
        }
    }

    private async Task ExportDiagnosticsAsync()
    {
        var manifest = await EnsureCurrentManifestAsync();
        _verification ??= await _coordinator.VerifyAsync(manifest, RuntimeRoot);
        _portHealth = await _coordinator.CheckHealthAsync(manifest);
        var report = _diagnostics.Build(
            manifest,
            CurrentSelection().ToLaunchProfile(),
            _verification,
            _portHealth,
            _coordinator.ServerLogLines,
            CurrentSelection());

        var dialog = new SaveFileDialog
        {
            AddExtension = true,
            DefaultExt = ".txt",
            FileName = $"psobb-diagnostic-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.txt",
            Filter = "Text diagnostic (*.txt)|*.txt",
            OverwritePrompt = true,
            Title = "Export sanitized PSOBB diagnostic",
        };
        if (dialog.ShowDialog() != true)
        {
            Status = "Diagnostic export cancelled.";
            return;
        }

        await _diagnostics.ExportAsync(dialog.FileName, report);
        Status = "Sanitized diagnostic exported. It contains no account files, launch arguments, or absolute runtime paths.";
    }

    private async Task<ReleaseManifest> EnsureCurrentManifestAsync()
    {
        var loaded = await _manifestLoader.LoadAsync(ManifestPath, AppContext.BaseDirectory);
        _manifest = loaded.Manifest;
        ManifestSummary = FormatManifestSummary(_manifest, loaded.TrustMode);
        return _manifest;
    }

    private LifecycleSelection CurrentSelection() => LifecycleSelection.Create(
        SelectedChannel,
        SelectedGraphicsProfile,
        SelectedMonitor,
        SelectedWindowMode,
        PreserveForeground);

    private bool TryApplySnapshot(LifecycleSnapshot snapshot, EnvironmentRequest request)
    {
        if (!IsCurrent(request))
        {
            return false;
        }
        LifecycleState = snapshot.State;
        Status = snapshot.Detail;
        return true;
    }

    private async Task RunLifecycleAsync(
        LauncherLifecycleState transitionalState,
        Func<EnvironmentRequest, Task> operation)
    {
        var request = CaptureEnvironmentRequest();
        LifecycleState = transitionalState;
        Status = "Working...";
        try
        {
            await operation(request);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            if (IsCurrent(request))
            {
                LifecycleState = LauncherLifecycleState.Faulted;
                Status = exception.Message;
            }
        }
    }

    private async Task RunEnvironmentGuardedAsync(Func<EnvironmentRequest, Task> operation)
    {
        var request = CaptureEnvironmentRequest();
        Status = "Working...";
        try
        {
            await operation(request);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            if (IsCurrent(request))
            {
                LifecycleState = LauncherLifecycleState.Faulted;
                Status = exception.Message;
            }
        }
    }

    private async Task RunGuardedAsync(Func<Task> operation)
    {
        try
        {
            Status = "Working...";
            await operation();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            LifecycleState = LauncherLifecycleState.Faulted;
            Status = exception.Message;
        }
    }

    private EnvironmentRequest CaptureEnvironmentRequest() => new(
        Interlocked.Read(ref _environmentGeneration),
        RuntimeRoot,
        SelectedServerEnvironment,
        CurrentSelection());

    private bool IsCurrent(EnvironmentRequest request) =>
        Interlocked.Read(ref _environmentGeneration) == request.Generation
        && SelectedServerEnvironment == request.ServerEnvironment
        && RuntimeRoot.Equals(
            request.RuntimeRoot, StringComparison.OrdinalIgnoreCase);

    private void InvalidateEnvironmentStatus()
    {
        LifecycleState = LauncherLifecycleState.Unknown;
        Status = "Server environment changed; refresh is required before lifecycle status is accepted.";
    }

    private static string FormatVerification(ReleaseVerification verification) => string.Join(
        Environment.NewLine,
        verification.Files.Select(file => $"{file.Status,-12} {file.Id}: {file.Detail}"));

    private static string FormatManifestSummary(ReleaseManifest manifest, ManifestTrustMode trustMode) =>
        $"{manifest.ReleaseId} | {manifest.Channel} | protocol {manifest.ProtocolRevision} | {manifest.Artifacts.Count} artifacts | "
        + (trustMode == ManifestTrustMode.VerifiedDetachedSignature ? "signature verified" : "unsigned local");

    private sealed record EnvironmentRequest(
        long Generation,
        string RuntimeRoot,
        ServerEnvironmentKind ServerEnvironment,
        LifecycleSelection Selection);
}
