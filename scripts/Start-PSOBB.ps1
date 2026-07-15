[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [switch]$Background,
    [ValidateRange(5, 120)][int]$StartupTimeoutSeconds = 45
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

if (-not ('PSOBBLifecycle.NativeSupervisorLauncher' -as [type])) {
    $nativeSupervisorLauncherSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace PSOBBLifecycle
{
    public sealed class SupervisorLaunchIdentity
    {
        public int ProcessId { get; }
        public long StartTimeFileTimeUtc { get; }

        internal SupervisorLaunchIdentity(int processId, long startTimeFileTimeUtc)
        {
            ProcessId = processId;
            StartTimeFileTimeUtc = startTimeFileTimeUtc;
        }
    }

    public static class NativeSupervisorLauncher
    {
        private const uint CreateNoWindow = 0x08000000;
        private const uint CreateSuspended = 0x00000004;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint LowDateTime;
            public uint HighDateTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        private static string QuoteArgument(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.Length > 0 && value.IndexOf('"') < 0)
            {
                bool needsQuotes = false;
                foreach (char character in value)
                {
                    if (char.IsWhiteSpace(character))
                    {
                        needsQuotes = true;
                        break;
                    }
                }
                if (!needsQuotes)
                {
                    return value;
                }
            }

            StringBuilder result = new StringBuilder(value.Length + 2);
            result.Append('"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    result.Append('\\', (backslashes * 2) + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }
                result.Append('\\', backslashes);
                backslashes = 0;
                result.Append(character);
            }
            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }

        public static SupervisorLaunchIdentity Start(
            string applicationName,
            string currentDirectory,
            string[] arguments)
        {
            if (string.IsNullOrWhiteSpace(applicationName))
            {
                throw new ArgumentException("An executable path is required.", nameof(applicationName));
            }
            if (string.IsNullOrWhiteSpace(currentDirectory))
            {
                throw new ArgumentException("A working directory is required.", nameof(currentDirectory));
            }

            StringBuilder commandLine = new StringBuilder(QuoteArgument(applicationName));
            foreach (string argument in arguments ?? Array.Empty<string>())
            {
                commandLine.Append(' ');
                commandLine.Append(QuoteArgument(argument));
            }
            if (commandLine.Length >= 32767)
            {
                throw new ArgumentException("The supervisor command line is too long.", nameof(arguments));
            }

            StartupInfo startupInfo = new StartupInfo();
            startupInfo.cb = Marshal.SizeOf<StartupInfo>();
            ProcessInformation processInformation;
            if (!CreateProcessW(
                applicationName,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CreateNoWindow | CreateSuspended,
                IntPtr.Zero,
                currentDirectory,
                ref startupInfo,
                out processInformation))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Failed to create the hidden newserv supervisor process");
            }

            try
            {
                FileTime creationTime;
                FileTime exitTime;
                FileTime kernelTime;
                FileTime userTime;
                if (!GetProcessTimes(
                    processInformation.hProcess,
                    out creationTime,
                    out exitTime,
                    out kernelTime,
                    out userTime))
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(processInformation.hProcess, 1);
                    throw new Win32Exception(error,
                        "Failed to capture the newserv supervisor creation identity");
                }
                long creationFileTime = unchecked(
                    ((long)creationTime.HighDateTime << 32) | creationTime.LowDateTime);
                if (ResumeThread(processInformation.hThread) == uint.MaxValue)
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(processInformation.hProcess, 1);
                    throw new Win32Exception(error,
                        "Failed to resume the verified newserv supervisor process");
                }
                return new SupervisorLaunchIdentity(
                    unchecked((int)processInformation.dwProcessId),
                    creationFileTime);
            }
            finally
            {
                if (processInformation.hThread != IntPtr.Zero)
                {
                    CloseHandle(processInformation.hThread);
                }
                if (processInformation.hProcess != IntPtr.Zero)
                {
                    CloseHandle(processInformation.hProcess);
                }
            }
        }
    }
}
'@
    Add-Type -TypeDefinition $nativeSupervisorLauncherSource -Language CSharp
}

function Get-ApprovedNewservExecutable {
    $lockPath = Join-Path $script:PSOBBRepositoryRoot 'config\sources.lock.json'
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
    $components = @($lock.components | Where-Object { $_.id -eq 'newserv-stable-release' })
    if ($components.Count -ne 1) {
        throw 'sources.lock.json must contain exactly one newserv-stable-release component'
    }
    $members = @($components[0].members | Where-Object { $_.path -eq 'release/newserv-windows.exe' })
    if ($members.Count -ne 1 -or [string]$members[0].sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'sources.lock.json does not contain one valid approved newserv executable member'
    }
    [pscustomobject]@{
        Sha256 = [string]$members[0].sha256
        Size = [long]$members[0].size
    }
}

function Set-LifecycleFileAcl {
    param([Parameter(Mandatory)][string]$Path)

    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $sids = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    )
    foreach ($sid in $sids) {
        $security.AddAccessRule(
            [System.Security.AccessControl.FileSystemAccessRule]::new($sid, $fullControl, $allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Assert-LifecycleFileAcl {
    param([Parameter(Mandatory)][string]$Path)

    $allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
        [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    ) | ForEach-Object { $allowed.Add($_.Value) | Out-Null }

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Lifecycle file inherits permissions: $Path"
    }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            -not $allowed.Contains($sid)) {
            throw "Lifecycle file grants access outside the runtime identities: $Path"
        }
    }
}

function Write-ProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Root
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $temporary = $safePath + '.' + [Guid]::NewGuid().ToString('N') + '.new'
    Assert-PathWithinRoot -Path $temporary -Root $Root | Out-Null
    [System.IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false))
    try {
        Set-LifecycleFileAcl -Path $temporary
        [System.IO.File]::Move($temporary, $safePath, $true)
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-ExactLaunchedSupervisor {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Identity)

    $candidate = Get-Process -Id ([int]$Identity.Pid) -ErrorAction SilentlyContinue
    if (-not $candidate) {
        return $null
    }
    try {
        $actualPath = [System.IO.Path]::GetFullPath($candidate.Path)
        $actualStartFileTime = $candidate.StartTime.ToUniversalTime().ToFileTimeUtc()
        if (-not $actualPath.Equals(
                [string]$Identity.ExecutablePath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            [long]$actualStartFileTime -ne [long]$Identity.StartTimeFileTimeUtc) {
            $candidate.Dispose()
            return $null
        }
        return $candidate
    } catch {
        $candidate.Dispose()
        return $null
    }
}

function Stop-ExactLaunchedSupervisorAfterFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ControlToken,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$StartupRequestId
    )

    $candidate = Get-ExactLaunchedSupervisor -Identity $Identity
    if ($candidate) {
        try {
            $request = [ordered]@{
                schemaVersion = 1
                action = 'cancel-start'
                hostPid = [int]$Identity.Pid
                hostStartTimeFileTimeUtc = [long]$Identity.StartTimeFileTimeUtc
                startupRequestId = $StartupRequestId
                controlToken = $ControlToken
                requestedAtUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-ProtectedJson -Path $Layout.ControlRequest -Value $request -Root $Layout.Root

            $deadline = [DateTime]::UtcNow.AddSeconds(5)
            while ([DateTime]::UtcNow -lt $deadline) {
                $candidate.Refresh()
                if ($candidate.HasExited) {
                    break
                }
                Start-Sleep -Milliseconds 100
            }
        } finally {
            $candidate.Dispose()
        }
    }

    # Reopen and revalidate immediately before the only forceful operation.
    # Killing the verified supervisor's process tree also prevents a child that
    # started just before cancellation from becoming an orphan.
    $revalidated = Get-ExactLaunchedSupervisor -Identity $Identity
    if ($revalidated) {
        try {
            $revalidated.Kill($true)
            $revalidated.WaitForExit(5000) | Out-Null
        } finally {
            $revalidated.Dispose()
        }
    }

    $stillRunning = Get-ExactLaunchedSupervisor -Identity $Identity
    if ($stillRunning) {
        $stillRunning.Dispose()
        throw 'The exact launched newserv supervisor could not be stopped after startup failed'
    }

    $serverDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $remainingServers = @(Get-NewservProcessesAtPath -Layout $Layout)
        if ($remainingServers.Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $serverDeadline)
    if ($remainingServers.Count -gt 0) {
        throw "A newserv process remains after supervisor cleanup (PID(s): $($remainingServers.Id -join ', '))"
    }

    @(
        $Layout.PidFile,
        $Layout.LegacyPidFile,
        $Layout.HostPidFile,
        $Layout.ControlState,
        $Layout.ControlRequest
    ) | ForEach-Object {
        $safePath = Assert-PathWithinRoot -Path $_ -Root $Layout.Root
        Remove-Item -LiteralPath $safePath -Force -ErrorAction SilentlyContinue
    }
}

function Test-ExactLoopbackListeners {
    param([Parameter(Mandatory)][int]$ProcessId)

    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $_.OwningProcess -eq $ProcessId })
    $actual = @($listeners | ForEach-Object {
        '{0}:{1}' -f $_.LocalAddress, $_.LocalPort
    } | Sort-Object -Unique)
    $expected = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
    if ($actual.Count -ne $expected.Count) {
        return $false
    }
    -not (Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $layout
$approved = Get-ApprovedNewservExecutable
$executable = Assert-PathWithinRoot -Path (Join-Path $layout.Server 'newserv-windows.exe') -Root $layout.Root
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Server executable is missing; run Initialize-PSOBB.ps1 first: $executable"
}
$executableItem = Get-Item -LiteralPath $executable
if ($executableItem.Length -ne $approved.Size -or (Get-LowerSha256 $executable) -ne $approved.Sha256) {
    throw 'The runtime newserv executable does not match the approved sources.lock member'
}

# Background is retained for command-line compatibility. Supervised operation is
# always hidden because the controller, rather than a console window, owns stdin.
$null = $Background

$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
$hostProcess = $null
$hostIdentity = $null
$controlToken = $null
$startupRequestId = $null
$startupCompleted = $false
try {
    $ownsMutex = $mutex.WaitOne(0)
    if (-not $ownsMutex) {
        throw 'Another PSOBB start or stop operation is already in progress'
    }

    $running = @(Get-NewservProcessesAtPath -Layout $layout)
    if ($running.Count -gt 0) {
        throw "The approved newserv executable is already running (PID(s): $($running.Id -join ', '))"
    }

    $lifecycleFiles = @(
        $layout.PidFile,
        $layout.LegacyPidFile,
        $layout.HostPidFile,
        $layout.ControlState,
        $layout.ControlRequest
    )
    foreach ($path in $lifecycleFiles) {
        $safePath = Assert-PathWithinRoot -Path $path -Root $layout.Root
        Remove-Item -LiteralPath $safePath -Force -ErrorAction SilentlyContinue
    }

    $tokenBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    $controlToken = [Convert]::ToBase64String($tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)
    $startupRequestId = [Guid]::NewGuid().ToString('N')

    $startupState = [ordered]@{
        schemaVersion = 1
        state = 'starting'
        installationId = [string]$marker.installationId
        executablePath = $executable
        executableSha256 = $approved.Sha256
        startupRequestId = $startupRequestId
        controlToken = $controlToken
        requestedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-ProtectedJson -Path $layout.ControlState -Value $startupState -Root $layout.Root

    $hostExecutable = Join-Path $PSHOME 'pwsh.exe'
    $hostArguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', (Join-Path $PSScriptRoot 'Invoke-NewservSupervisor.ps1'),
        '-RuntimeRoot', $layout.Root
    )
    # CreateProcessW is used directly so the long-lived supervisor receives no
    # inheritable handles from a captured caller. Redirecting standard streams
    # through ProcessStartInfo requires handle inheritance and can therefore
    # keep an unrelated pipeline open until the server exits.
    $nativeHostIdentity = [PSOBBLifecycle.NativeSupervisorLauncher]::Start(
        $hostExecutable,
        $script:PSOBBRepositoryRoot,
        $hostArguments)
    $hostProcessId = [int]$nativeHostIdentity.ProcessId
    $expectedHostPath = [System.IO.Path]::GetFullPath($hostExecutable)
    $hostIdentity = [pscustomobject]@{
        Pid = $hostProcessId
        ExecutablePath = $expectedHostPath
        StartTimeFileTimeUtc = [long]$nativeHostIdentity.StartTimeFileTimeUtc
    }
    try {
        $hostProcess = Get-Process -Id $hostProcessId -ErrorAction Stop
    } catch {
        throw 'Failed to create the hidden newserv supervisor process'
    }
    $observedHostPath = [System.IO.Path]::GetFullPath($hostProcess.Path)
    $observedHostStartFileTime = $hostProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    if ($hostProcess.Id -ne $hostProcessId -or
        -not $observedHostPath.Equals($expectedHostPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        [long]$observedHostStartFileTime -ne [long]$hostIdentity.StartTimeFileTimeUtc) {
        throw 'The hidden newserv supervisor identity did not match the launched executable'
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    $serverProcess = $null
    $startResult = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $hostProcess.Refresh()
        if ($hostProcess.HasExited) {
            $detail = 'The newserv supervisor exited during startup'
            if (Test-Path -LiteralPath $layout.ControlState -PathType Leaf) {
                Assert-LifecycleFileAcl -Path $layout.ControlState
                try {
                    $state = Get-Content -Raw -LiteralPath $layout.ControlState | ConvertFrom-Json
                    if (-not [string]::IsNullOrWhiteSpace([string]$state.message)) {
                        $detail += ': ' + [string]$state.message
                    }
                } catch { }
            }
            throw $detail
        }

        if (Test-Path -LiteralPath $layout.PidFile -PathType Leaf) {
            Assert-LifecycleFileAcl -Path $layout.PidFile
            $serverProcess = Get-NewservProcess -Layout $layout
            if ($serverProcess) {
                $record = Get-Content -Raw -LiteralPath $layout.PidFile | ConvertFrom-Json
                $recordedHostPath = [System.IO.Path]::GetFullPath([string]$record.hostExecutablePath)
                if ([int]$record.hostPid -ne $hostProcess.Id -or
                    [long]$record.hostStartTimeFileTimeUtc -ne [long]$hostIdentity.StartTimeFileTimeUtc -or
                    -not $recordedHostPath.Equals(
                        [string]$hostIdentity.ExecutablePath,
                        [System.StringComparison]::OrdinalIgnoreCase) -or
                    [string]$record.startupRequestId -ne $startupRequestId -or
                    [string]$record.executablePath -ne $executable -or
                    [string]$record.executableSha256 -ne $approved.Sha256 -or
                    [string]$record.controlToken -ne $controlToken) {
                    throw 'The supervisor process record did not match this start request'
                }
                if (Test-ExactLoopbackListeners -ProcessId $serverProcess.Id) {
                    $controlToken = $null
                    $startupCompleted = $true
                    $startResult = [pscustomobject]@{
                        Pid = $serverProcess.Id
                        HostPid = $hostProcess.Id
                        Supervised = $true
                        ExecutableSha256 = $approved.Sha256
                        Listeners = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
                    }
                    break
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }

    if ($startResult) {
        Write-Output -NoEnumerate $startResult
    } else {
        throw 'newserv did not reach the exact approved loopback listener set before the startup timeout'
    }
} catch {
    $startupFailure = $_
    $cleanupFailure = $null
    if (-not $startupCompleted -and $hostIdentity -and $controlToken -and $startupRequestId) {
        try {
            Stop-ExactLaunchedSupervisorAfterFailure `
                -Layout $layout `
                -Identity $hostIdentity `
                -ControlToken $controlToken `
                -StartupRequestId $startupRequestId
        } catch {
            $cleanupFailure = $_.Exception.Message
        }
    }
    if ($cleanupFailure) {
        throw "$($startupFailure.Exception.Message) Supervisor cleanup also failed: $cleanupFailure"
    }
    throw $startupFailure
} finally {
    $controlToken = $null
    if ($hostProcess) {
        $hostProcess.Dispose()
    }
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
