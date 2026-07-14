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
    private readonly LauncherCoordinator _coordinator;
    private string _manifestPath;
    private string _runtimeRoot;
    private ReleaseChannel _selectedChannel;
    private GraphicsProfileOption _selectedGraphicsProfile;
    private MonitorOption _selectedMonitor;
    private LauncherWindowMode _selectedWindowMode;
    private bool _safeMode;
    private LauncherLifecycleState _lifecycleState = LauncherLifecycleState.Stopped;
    private string _manifestSummary = "No manifest loaded.";
    private string _verificationSummary = "Not verified.";
    private string _status = "Ready to observe the script-managed local runtime.";
    private ReleaseManifest? _manifest;
    private ReleaseVerification? _verification;
    private IReadOnlyList<PortHealth> _portHealth = [];

    public MainWindowViewModel() : this(LauncherOptions.Defaults())
    {
    }

    public MainWindowViewModel(LauncherOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _manifestPath = options.ManifestPath;
        _runtimeRoot = options.RuntimeRoot;
        _selectedChannel = options.Selection.Channel;
        _selectedGraphicsProfile = options.Selection.Profile;
        _selectedMonitor = options.Selection.Monitor;
        _selectedWindowMode = options.Selection.WindowMode;
        _safeMode = options.Selection.Profile.SafeMode;

        _manifestLoader = new LauncherManifestLoader(new ReleaseManifestService());
        _coordinator = LauncherServices.CreateCoordinator();

        BrowseManifestCommand = new RelayCommand(BrowseManifest);
        BrowseRuntimeCommand = new RelayCommand(BrowseRuntime);
        LoadManifestCommand = new AsyncRelayCommand(() => RunGuardedAsync(LoadManifestAsync));
        VerifyCommand = new AsyncRelayCommand(() => RunGuardedAsync(VerifyAsync));
        RefreshStateCommand = new AsyncRelayCommand(() => RunGuardedAsync(RefreshStateAsync));
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
        set => SetProperty(ref _runtimeRoot, value);
    }

    public ReleaseChannel SelectedChannel
    {
        get => _selectedChannel;
        set
        {
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
        set => SetProperty(ref _selectedWindowMode, value);
    }

    public bool SafeMode
    {
        get => _safeMode;
        set
        {
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

    public Task InitializeAsync() => RunGuardedAsync(RefreshStateAsync);

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
        _manifest = loaded.Manifest;
        _verification = null;
        _portHealth = [];
        SelectedChannel = _manifest.Channel;
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

    private async Task RefreshStateAsync() => ApplySnapshot(await _coordinator.ObserveAsync(RuntimeRoot));

    private async Task StartSessionAsync() =>
        ApplySnapshot(await _coordinator.StartSessionAsync(RuntimeRoot, CurrentSelection()));

    private async Task StartServerAsync() =>
        ApplySnapshot(await _coordinator.StartServerAsync(RuntimeRoot));

    private async Task StartClientAsync() =>
        ApplySnapshot(await _coordinator.StartClientAsync(RuntimeRoot, CurrentSelection()));

    private async Task StopClientAsync() =>
        ApplySnapshot(await _coordinator.StopClientAsync(RuntimeRoot));

    private async Task StopServerAsync() =>
        ApplySnapshot(await _coordinator.StopServerAsync(RuntimeRoot));

    private async Task StopAllAsync() =>
        ApplySnapshot(await _coordinator.StopAllAsync(RuntimeRoot));

    private async Task RepairAsync()
    {
        ApplySnapshot(await _coordinator.RepairClientAsync(RuntimeRoot, CurrentSelection()));
        Status = $"Profile '{SelectedGraphicsProfile.Id}' was verified or repaired through its approved runtime script.";
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
        SelectedWindowMode);

    private void ApplySnapshot(LifecycleSnapshot snapshot)
    {
        LifecycleState = snapshot.State;
        Status = snapshot.Detail;
    }

    private async Task RunLifecycleAsync(LauncherLifecycleState transitionalState, Func<Task> operation)
    {
        LifecycleState = transitionalState;
        await RunGuardedAsync(operation);
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

    private static string FormatVerification(ReleaseVerification verification) => string.Join(
        Environment.NewLine,
        verification.Files.Select(file => $"{file.Status,-12} {file.Id}: {file.Detail}"));

    private static string FormatManifestSummary(ReleaseManifest manifest, ManifestTrustMode trustMode) =>
        $"{manifest.ReleaseId} | {manifest.Channel} | protocol {manifest.ProtocolRevision} | {manifest.Artifacts.Count} artifacts | "
        + (trustMode == ManifestTrustMode.VerifiedDetachedSignature ? "signature verified" : "unsigned local");
}
