[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [ValidateSet('Stable', 'CombatCanary')]
    [string]$ServerEnvironment = 'Stable',
    [switch]$Background,
    [ValidateRange(5, 120)][int]$StartupTimeoutSeconds = 45,
    [ValidateRange(5, 300)][int]$VerificationTimeoutSeconds = 120,
    [Parameter(DontShow)][switch]$ClientOperationLockHeld
)

. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')
. (Join-Path $PSScriptRoot 'PSOBB.RuntimeAclPolicy.ps1')

if (-not ('PSOBBLifecycle.NativeSupervisorLauncher' -as [type])) {
    $nativeSupervisorLauncherSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PSOBBLifecycle
{
    public enum SupervisorProbeState
    {
        Absent,
        Mismatch,
        Verified,
        Uninspectable,
    }

    public sealed class SupervisorProcessProbe
    {
        public SupervisorProbeState State { get; }
        public string Detail { get; }

        internal SupervisorProcessProbe(SupervisorProbeState state, string detail)
        {
            State = state;
            Detail = detail;
        }
    }

    internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeJobHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }

    public sealed class SupervisorLaunchIdentity : IDisposable
    {
        private const uint WaitObject0 = 0;
        private const uint WaitTimeout = 258;
        private const uint WaitFailed = 0xFFFFFFFF;
        private readonly SafeProcessHandle processHandle;
        private readonly SafeJobHandle jobHandle;

        public int ProcessId { get; }
        public long StartTimeFileTimeUtc { get; }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint LowDateTime;
            public uint HighDateTime;

            public long ToInt64()
            {
                return unchecked(((long)HighDateTime << 32) | LowDateTime);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(SafeProcessHandle process);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "QueryFullProcessImageNameW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            uint flags,
            StringBuilder imagePath,
            ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            SafeProcessHandle process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(
            SafeProcessHandle handle,
            uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(
            SafeJobHandle job,
            uint exitCode);

        internal SupervisorLaunchIdentity(
            int processId,
            long startTimeFileTimeUtc,
            SafeProcessHandle processHandle,
            SafeJobHandle jobHandle)
        {
            ProcessId = processId;
            StartTimeFileTimeUtc = startTimeFileTimeUtc;
            this.processHandle = processHandle;
            this.jobHandle = jobHandle;
        }

        public SupervisorProcessProbe Probe(
            string expectedExecutablePath,
            long expectedStartTimeFileTimeUtc)
        {
            try
            {
                ThrowIfDisposed();
                uint waitResult = WaitForSingleObject(processHandle, 0);
                if (waitResult == WaitObject0)
                {
                    return new SupervisorProcessProbe(
                        SupervisorProbeState.Absent,
                        "The launched supervisor has exited.");
                }
                if (waitResult == WaitFailed)
                {
                    return Uninspectable("WaitForSingleObject");
                }
                if (waitResult != WaitTimeout)
                {
                    return new SupervisorProcessProbe(
                        SupervisorProbeState.Uninspectable,
                        "WaitForSingleObject returned an unexpected supervisor probe state.");
                }

                uint handleProcessId = GetProcessId(processHandle);
                if (handleProcessId == 0)
                {
                    return Uninspectable("GetProcessId");
                }
                if (handleProcessId != (uint)ProcessId)
                {
                    return new SupervisorProcessProbe(
                        SupervisorProbeState.Mismatch,
                        "The retained supervisor handle does not match its captured PID.");
                }

                FileTime creationTime;
                FileTime exitTime;
                FileTime kernelTime;
                FileTime userTime;
                if (!GetProcessTimes(
                    processHandle,
                    out creationTime,
                    out exitTime,
                    out kernelTime,
                    out userTime))
                {
                    return Uninspectable("GetProcessTimes");
                }
                if (creationTime.ToInt64() != expectedStartTimeFileTimeUtc)
                {
                    return new SupervisorProcessProbe(
                        SupervisorProbeState.Mismatch,
                        "The retained supervisor handle does not match the captured creation time.");
                }

                StringBuilder imagePath = new StringBuilder(32768);
                int size = imagePath.Capacity;
                if (!QueryFullProcessImageName(processHandle, 0, imagePath, ref size))
                {
                    return Uninspectable("QueryFullProcessImageNameW");
                }
                string actualPath = Path.GetFullPath(imagePath.ToString());
                string expectedPath = Path.GetFullPath(expectedExecutablePath);
                if (!actualPath.Equals(expectedPath, StringComparison.OrdinalIgnoreCase))
                {
                    return new SupervisorProcessProbe(
                        SupervisorProbeState.Mismatch,
                        "The retained supervisor handle does not match the expected executable path.");
                }

                return new SupervisorProcessProbe(
                    SupervisorProbeState.Verified,
                    "The retained supervisor handle matches the captured launch identity.");
            }
            catch (Exception exception)
            {
                return new SupervisorProcessProbe(
                    SupervisorProbeState.Uninspectable,
                    exception.Message);
            }
        }

        public bool WaitForExit(int milliseconds)
        {
            if (milliseconds < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(milliseconds));
            }
            ThrowIfDisposed();
            uint result = WaitForSingleObject(processHandle, unchecked((uint)milliseconds));
            if (result == WaitObject0)
            {
                return true;
            }
            if (result == WaitTimeout)
            {
                return false;
            }
            if (result == WaitFailed)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "WaitForSingleObject failed for the launched supervisor.");
            }
            throw new InvalidOperationException(
                "WaitForSingleObject returned an unexpected supervisor wait state.");
        }

        public void TerminateTree(uint exitCode)
        {
            ThrowIfDisposed();
            if (!TerminateJobObject(jobHandle, exitCode))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "TerminateJobObject failed for the launched supervisor tree.");
            }
        }

        public void Dispose()
        {
            processHandle.Dispose();
            jobHandle.Dispose();
        }

        private SupervisorProcessProbe Uninspectable(string operation)
        {
            return new SupervisorProcessProbe(
                SupervisorProbeState.Uninspectable,
                new Win32Exception(Marshal.GetLastWin32Error(),
                    operation + " failed for the launched supervisor.").Message);
        }

        private void ThrowIfDisposed()
        {
            if (processHandle.IsClosed || jobHandle.IsClosed)
            {
                throw new ObjectDisposedException(nameof(SupervisorLaunchIdentity));
            }
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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(
            IntPtr jobAttributes,
            string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(
            SafeJobHandle job,
            SafeProcessHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(
            SafeJobHandle job,
            uint exitCode);

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

            SafeProcessHandle retainedProcessHandle = null;
            SafeJobHandle retainedJobHandle = null;
            bool ownershipTransferred = false;
            try
            {
                retainedProcessHandle = new SafeProcessHandle(
                    processInformation.hProcess,
                    true);
                processInformation.hProcess = IntPtr.Zero;
                IntPtr rawJobHandle = CreateJobObjectW(IntPtr.Zero, null);
                if (rawJobHandle == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(retainedProcessHandle.DangerousGetHandle(), 1);
                    throw new Win32Exception(error,
                        "Failed to create the newserv supervisor job object");
                }
                retainedJobHandle = new SafeJobHandle(rawJobHandle);
                if (!AssignProcessToJobObject(retainedJobHandle, retainedProcessHandle))
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(retainedProcessHandle.DangerousGetHandle(), 1);
                    throw new Win32Exception(error,
                        "Failed to assign the newserv supervisor to its job object");
                }

                FileTime creationTime;
                FileTime exitTime;
                FileTime kernelTime;
                FileTime userTime;
                if (!GetProcessTimes(
                    retainedProcessHandle.DangerousGetHandle(),
                    out creationTime,
                    out exitTime,
                    out kernelTime,
                    out userTime))
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateJobObject(retainedJobHandle, 1);
                    throw new Win32Exception(error,
                        "Failed to capture the newserv supervisor creation identity");
                }
                long creationFileTime = unchecked(
                    ((long)creationTime.HighDateTime << 32) | creationTime.LowDateTime);
                if (ResumeThread(processInformation.hThread) == uint.MaxValue)
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateJobObject(retainedJobHandle, 1);
                    throw new Win32Exception(error,
                        "Failed to resume the verified newserv supervisor process");
                }
                SupervisorLaunchIdentity identity = new SupervisorLaunchIdentity(
                    unchecked((int)processInformation.dwProcessId),
                    creationFileTime,
                    retainedProcessHandle,
                    retainedJobHandle);
                ownershipTransferred = true;
                return identity;
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
                if (!ownershipTransferred)
                {
                    if (retainedJobHandle != null && !retainedJobHandle.IsInvalid)
                    {
                        TerminateJobObject(retainedJobHandle, 1);
                    }
                    retainedJobHandle?.Dispose();
                    retainedProcessHandle?.Dispose();
                }
            }
        }
    }
}
'@
    Add-Type -TypeDefinition $nativeSupervisorLauncherSource -Language CSharp
}

function Set-LifecycleFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Set-PSOBBLifecyclePathAcl -Path $Path -Root $Root | Out-Null
}

function Assert-LifecycleFileAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    Assert-PSOBBLifecyclePathAcl `
        -Path $Path -Root $Root -IsContainer $false | Out-Null
}

function Write-ProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Root,
        [switch]$CreateOnly
    )

    $safePath = Assert-PathWithinRoot -Path $Path -Root $Root
    $temporary = $safePath + '.' + [Guid]::NewGuid().ToString('N') + '.new'
    Assert-PathWithinRoot -Path $temporary -Root $Root | Out-Null
    $jsonBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 6))
    $temporaryStream = $null
    try {
        $temporaryStream = [System.IO.FileStream]::new(
            $temporary,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
        $temporaryStream.Write($jsonBytes, 0, $jsonBytes.Length)
        $temporaryStream.Flush($true)
        $temporaryStream.Dispose()
        $temporaryStream = $null
        Set-LifecycleFileAcl -Path $temporary -Root $Root
        if ($CreateOnly) {
            [System.IO.File]::Move($temporary, $safePath)
        } else {
            [System.IO.File]::Move($temporary, $safePath, $true)
        }
    } finally {
        if ($temporaryStream) { $temporaryStream.Dispose() }
        [Array]::Clear($jsonBytes, 0, $jsonBytes.Length)
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-PSOBBSafeLifecycleDiagnostic {
    [CmdletBinding()]
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'Windows returned no additional process diagnostic.'
    }
    $safe = -join @($Value.ToCharArray() | Where-Object {
        -not [char]::IsControl($_) -or $_ -eq "`t"
    })
    $safe = [regex]::Replace(
        $safe,
        '(?i)(?<keyquote>["''])?(?<key>password|passwd|token|secret|credential|username|account(?:\s*id)?|license|guild\s*card|guildcard)(?(keyquote)\k<keyquote>)\s*(?<separator>[:=])\s*(?:(?<valuequote>")[^"\r\n]*"|(?<valuequote>'')[^''\r\n]*''|[^\s,;}\r\n]+)',
        '${keyquote}${key}${keyquote}${separator}${valuequote}[REDACTED]${valuequote}')
    $safe = [regex]::Replace(
        $safe,
        '(?i)(?:guild\s*card|guildcard)\D{0,8}\d{6,16}',
        '[GUILD-CARD-REDACTED]')
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $safe = $safe.Replace(
            $env:USERPROFILE,
            '%USERPROFILE%',
            [System.StringComparison]::OrdinalIgnoreCase)
    }
    $safe = $safe.Trim()
    if ($safe.Length -gt 1000) {
        $safe = $safe.Substring(0, 1000) + '...'
    }
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'Windows returned no additional process diagnostic.'
    }
    $safe
}

function Get-LaunchedSupervisorProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Identity,
        [ValidateRange(1, 20)][int]$ProbeAttempts = 5,
        [ValidateRange(0, 1000)][int]$ProbeDelayMilliseconds = 50
    )

    if ($null -eq $Identity) {
        return [pscustomobject]@{
            State = 'Uninspectable'
            Detail = 'The supervisor launch identity is unavailable.'
        }
    }

    $nativeIdentityProperty = $Identity.PSObject.Properties['NativeIdentity']
    if ($null -eq $nativeIdentityProperty -or $null -eq $nativeIdentityProperty.Value) {
        return [pscustomobject]@{
            State = 'Uninspectable'
            Detail = 'The stable native supervisor identity handle is unavailable.'
        }
    }

    $nativeIdentity = $nativeIdentityProperty.Value
    try {
        $identityPidProperty = $Identity.PSObject.Properties['Pid']
        $executablePathProperty = $Identity.PSObject.Properties['ExecutablePath']
        $startTimeProperty = $Identity.PSObject.Properties['StartTimeFileTimeUtc']
        if ($null -eq $identityPidProperty -or
            $null -eq $executablePathProperty -or
            $null -eq $startTimeProperty) {
            throw 'The supervisor launch identity is incomplete.'
        }

        $nativePid = [int]$nativeIdentity.ProcessId
        $identityPid = [int]$identityPidProperty.Value
        $expectedPath = [System.IO.Path]::GetFullPath([string]$executablePathProperty.Value)
        $expectedStartTime = [long]$startTimeProperty.Value
    } catch {
        return [pscustomobject]@{
            State = 'Uninspectable'
            Detail = ConvertTo-PSOBBSafeLifecycleDiagnostic -Value $_.Exception.Message
        }
    }

    if ($nativePid -ne $identityPid) {
        return [pscustomobject]@{
            State = 'Mismatch'
            Detail = 'The stable native supervisor handle does not match the captured PID.'
        }
    }

    $lastFailure = $null
    for ($attempt = 1; $attempt -le $ProbeAttempts; $attempt++) {
        try {
            $nativeProbe = $nativeIdentity.Probe(
                $expectedPath,
                $expectedStartTime)
            $state = [string]$nativeProbe.State
            $detail = ConvertTo-PSOBBSafeLifecycleDiagnostic -Value ([string]$nativeProbe.Detail)
            if ($state -in @('Absent', 'Mismatch', 'Verified')) {
                return [pscustomobject]@{
                    State = $state
                    Detail = $detail
                }
            }
            $lastFailure = $detail
        } catch {
            $lastFailure = ConvertTo-PSOBBSafeLifecycleDiagnostic -Value $_.Exception.Message
        }

        if ($attempt -lt $ProbeAttempts -and $ProbeDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $ProbeDelayMilliseconds
        }
    }

    [pscustomobject]@{
        State = 'Uninspectable'
        Detail = if ($lastFailure) {
            $lastFailure
        } else {
            'The stable supervisor handle could not be inspected.'
        }
    }
}

function Stop-ExactLaunchedSupervisorAfterFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout,
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{43}$')][string]$ControlToken,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$StartupRequestId,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ControlIdentity,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+$')][string]$ComponentId
    )

    $probe = Get-LaunchedSupervisorProbe -Identity $Identity
    $cooperativeCancelFailure = $null
    $jobTerminationFailure = $null
    $retainedHostExited = $false
    if ($probe.State -eq 'Verified') {
        try {
            $request = [ordered]@{
                schemaVersion = 3
                action = 'cancel-start'
                serverEnvironment = [string]$Layout.Environment
                environmentId = [string]$Layout.EnvironmentId
                componentId = $ComponentId
                controlIdentity = $ControlIdentity
                hostPid = [int]$Identity.Pid
                hostStartTimeFileTimeUtc = [long]$Identity.StartTimeFileTimeUtc
                startupRequestId = $StartupRequestId
                controlToken = $ControlToken
                requestedAtUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-ProtectedJson `
                -Path $Layout.ControlRequest -Value $request -Root $Layout.Root -CreateOnly

            $deadline = [DateTime]::UtcNow.AddSeconds(5)
            while ([DateTime]::UtcNow -lt $deadline) {
                if ($Identity.NativeIdentity.WaitForExit(100)) {
                    break
                }
            }
        } catch {
            $cooperativeCancelFailure = ConvertTo-PSOBBSafeLifecycleDiagnostic `
                -Value $_.Exception.Message
        }

    }

    # The job was attached before the supervisor's first instruction and the
    # caller verified that launch identity before monitoring startup. Always
    # terminate the retained job regardless of probe classification, including
    # when the supervisor has already exited but a child may remain. The
    # assigned job handle—not a guessed PID—is authoritative even when image or
    # creation-time inspection is mismatched or unavailable.
    try {
        $Identity.NativeIdentity.TerminateTree(1)
    } catch {
        $jobTerminationFailure = ConvertTo-PSOBBSafeLifecycleDiagnostic `
            -Value $_.Exception.Message
    }
    try {
        $retainedHostExited = [bool](
            $Identity.NativeIdentity.WaitForExit(5000))
    } catch {
        $waitFailure = ConvertTo-PSOBBSafeLifecycleDiagnostic `
            -Value $_.Exception.Message
        $jobTerminationFailure = if ($jobTerminationFailure) {
            "$jobTerminationFailure Wait: $waitFailure"
        } else {
            "Wait: $waitFailure"
        }
    }

    $finalProbe = Get-LaunchedSupervisorProbe -Identity $Identity
    if (-not $retainedHostExited -and $finalProbe.State -ne 'Absent') {
        throw "The launched supervisor cleanup did not reach Absent ($($finalProbe.State)): $($finalProbe.Detail)"
    }

    $serverDeadline = [DateTime]::UtcNow.AddSeconds(5)
    $remainingServers = @()
    $remainingListeners = @()
    do {
        $remainingServers = @(Get-NewservProcessesAtPath -Layout $Layout)
        $remainingListeners = @(Get-PSOBBReservedServerPortListeners)
        if ($remainingServers.Count -eq 0 -and
            $remainingListeners.Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $serverDeadline)
    if ($remainingServers.Count -gt 0) {
        throw "A newserv process remains after supervisor cleanup (PID(s): $($remainingServers.Id -join ', '))"
    }
    if ($remainingListeners.Count -gt 0) {
        $listenerDetails = @($remainingListeners | ForEach-Object {
                '{0}:{1} PID {2}' -f $_.LocalAddress, $_.LocalPort,
                    $_.OwningProcess
            })
        throw "A reserved PSOBB listener remains after supervisor cleanup ($($listenerDetails -join ', '))"
    }
    $rootLayout = Get-PSOBBLayout -RuntimeRoot ([string]$Layout.Root)
    $remainingGlobalServers = @(
        Get-PSOBBServerEnvironmentProcessRecords -Layout $rootLayout)
    if ($remainingGlobalServers.Count -gt 0) {
        $globalDetails = @($remainingGlobalServers | ForEach-Object {
                'PID {0} ({1})' -f $_.ProcessId, $_.Classification
            })
        throw "A named newserv process remains after retained-job cleanup ($($globalDetails -join ', ')); no guessed PID action was attempted"
    }

    Remove-PSOBBLifecycleFilesVerified -Layout $Layout | Out-Null

    if ($jobTerminationFailure) {
        throw "The retained supervisor job reported a termination failure after exact process and listener absence was verified: $jobTerminationFailure"
    }
    if ($cooperativeCancelFailure) {
        throw "Cooperative failed-start cancellation failed after exact process and listener absence was verified: $cooperativeCancelFailure"
    }
}

$rootLayout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
$marker = Assert-PSOBBRuntimeMarker -Layout $rootLayout
$serverEnvironmentName = Resolve-PSOBBServerEnvironmentName `
    -Environment $ServerEnvironment
$layout = Get-PSOBBServerEnvironmentLayout `
    -Layout $rootLayout -Environment $serverEnvironmentName
$approved = Get-PSOBBApprovedNewservExecutableIdentity `
    -Layout $rootLayout -ServerEnvironment $serverEnvironmentName
$executable = Assert-PathWithinRoot `
    -Path $approved.ExecutablePath -Root $layout.EnvironmentRoot

# Background is retained for command-line compatibility. Supervised operation is
# always hidden because the controller, rather than a console window, owns stdin.
$null = $Background

$mutexName = 'Local\PSOBB.Newserv.Start.' + ([string]$marker.installationId).Replace('-', '')
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
$nativeHostIdentity = $null
$hostIdentity = $null
$controlToken = $null
$startupRequestId = $null
$controlIdentity = $null
$startupCompleted = $false
$startupStateWritten = $false
$clientOperationMutex = if ($ClientOperationLockHeld) {
    $null
} else {
    Enter-PSOBBClientOperationLock -Layout $rootLayout
}
try {
    Assert-PSOBBNoRunningClients -Layout $rootLayout | Out-Null
    $ownsMutex = $mutex.WaitOne(0)
    if (-not $ownsMutex) {
        throw 'Another PSOBB start or stop operation is already in progress'
    }

    Assert-PSOBBServerEnvironmentIsolation -Layout $rootLayout | Out-Null
    $bindingExpectations = if ($serverEnvironmentName -ceq 'CombatCanary') {
        Get-PSOBBCombatCanaryInstallationBindingExpectations -Layout $rootLayout
    } else {
        $null
    }
    $approved = Get-PSOBBApprovedNewservExecutableIdentity `
        -Layout $rootLayout -ServerEnvironment $serverEnvironmentName
    $executable = Assert-PathWithinRoot `
        -Path $approved.ExecutablePath -Root $layout.EnvironmentRoot
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "The $serverEnvironmentName server executable is missing: $executable"
    }
    $executableItem = Get-Item -LiteralPath $executable
    if ($executableItem.Length -ne $approved.Size -or
        (Get-LowerSha256 $executable) -cne $approved.Sha256) {
        throw "The $serverEnvironmentName newserv executable does not match its exact approved component"
    }
    Assert-PSOBBExclusiveServerStartBoundary `
        -ServerEnvironment $serverEnvironmentName `
        -ServerProcesses @(Get-PSOBBServerEnvironmentProcessRecords -Layout $rootLayout) `
        -ReservedPortListeners @(Get-PSOBBReservedServerPortListeners) | Out-Null

    Initialize-PSOBBLifecycleControlDirectory -Layout $layout | Out-Null
    if (Test-Path -LiteralPath $layout.PidFile -PathType Leaf) {
        Assert-LifecycleFileAcl -Path $layout.PidFile -Root $layout.Root
    }
    Wait-PSOBBRecordedSupervisorHostQuiescence -Layout $layout | Out-Null

    if ($serverEnvironmentName -ceq 'Stable') {
        Remove-PSOBBRetiredLifecycleFiles -Layout $rootLayout
        $remainingRetired = @(Get-PSOBBRetiredLifecyclePaths `
            -Layout $rootLayout | Where-Object { Test-Path -LiteralPath $_ })
        if ($remainingRetired.Count -gt 0) {
            throw 'Retired lifecycle file removal could not be verified'
        }
    }
    Remove-PSOBBLifecycleFilesVerified -Layout $layout | Out-Null

    $tokenBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($tokenBytes)
    $controlToken = [Convert]::ToBase64String($tokenBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)
    $startupRequestId = [Guid]::NewGuid().ToString('N')
    $controlIdentity = Get-PSOBBServerControlIdentity `
        -InstallationId ([string]$marker.installationId) `
        -EnvironmentId $layout.EnvironmentId `
        -ComponentId $approved.ComponentId `
        -StartupRequestId $startupRequestId `
        -ExecutableSha256 $approved.Sha256

    $startupState = [ordered]@{
        schemaVersion = 3
        state = 'starting'
        installationId = [string]$marker.installationId
        serverEnvironment = $serverEnvironmentName
        environmentId = $layout.EnvironmentId
        componentId = $approved.ComponentId
        controlIdentity = $controlIdentity
        executablePath = $executable
        executableSha256 = $approved.Sha256
        buildContractSha256 = if ($bindingExpectations) {
            [string]$bindingExpectations.BuildContractSha256
        } else { $null }
        clientBindingSha256 = if ($bindingExpectations) {
            [string]$bindingExpectations.ClientBindingSha256
        } else { $null }
        stateBindingSha256 = if ($bindingExpectations) {
            [string]$bindingExpectations.StateBindingSha256
        } else { $null }
        startupRequestId = $startupRequestId
        controlToken = $controlToken
        requestedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-ProtectedJson -Path $layout.ControlState -Value $startupState -Root $layout.Root
    $startupStateWritten = $true

    $hostExecutable = Join-Path $PSHOME 'pwsh.exe'
    $hostArguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', (Join-Path $PSScriptRoot 'Invoke-NewservSupervisor.ps1'),
        '-RuntimeRoot', $layout.Root,
        '-ServerEnvironment', $serverEnvironmentName
    )
    # CreateProcessW is used directly so the long-lived supervisor receives no
    # inheritable handles from a captured caller. Redirecting standard streams
    # through ProcessStartInfo requires handle inheritance and can therefore
    # keep an unrelated pipeline open until the server exits.
    Assert-PSOBBNoRunningClients -Layout $rootLayout | Out-Null
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
        NativeIdentity = $nativeHostIdentity
    }
    $hostProbe = Get-LaunchedSupervisorProbe `
        -Identity $hostIdentity `
        -ProbeAttempts 10 `
        -ProbeDelayMilliseconds 50
    if ($hostProbe.State -ne 'Verified') {
        throw "The hidden newserv supervisor launch was $($hostProbe.State): $($hostProbe.Detail)"
    }

    $verificationDeadline = if ($serverEnvironmentName -ceq 'CombatCanary') {
        [DateTime]::UtcNow.AddSeconds($VerificationTimeoutSeconds)
    } else {
        $null
    }
    $listenerDeadline = if ($serverEnvironmentName -ceq 'Stable') {
        [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    } else {
        $null
    }
    $serverProcess = $null
    $startResult = $null
    while ($true) {
        $hostProbe = Get-LaunchedSupervisorProbe `
            -Identity $hostIdentity `
            -ProbeAttempts 3 `
            -ProbeDelayMilliseconds 25
        if ($hostProbe.State -eq 'Absent') {
            $detail = 'The newserv supervisor exited during startup'
            if (Test-Path -LiteralPath $layout.ControlState -PathType Leaf) {
            Assert-LifecycleFileAcl -Path $layout.ControlState -Root $layout.Root
                try {
                    $state = Read-PSOBBStrictLifecycleJson `
                        -Path $layout.ControlState `
                        -Root $layout.Root `
                        -Contract ServerControlState
                    if ([string]$state.state -ceq 'failed' -and
                        -not [string]::IsNullOrWhiteSpace([string]$state.message)) {
                        $detail += ': ' + [string]$state.message
                    }
                } catch { }
            }
            throw $detail
        }
        if ($hostProbe.State -ne 'Verified') {
            throw "The newserv supervisor became $($hostProbe.State) during startup: $($hostProbe.Detail)"
        }

        if (Test-Path -LiteralPath $layout.PidFile -PathType Leaf) {
            Assert-LifecycleFileAcl -Path $layout.PidFile -Root $layout.Root
            if ($serverProcess) {
                $serverProcess.Dispose()
                $serverProcess = $null
            }
            $serverIdentity = Get-NewservProcess -Layout $layout -PassThruIdentity
            $serverProcess = if ($serverIdentity) { $serverIdentity.Process } else { $null }
            if ($serverProcess) {
                $record = $serverIdentity.Record
                $recordedHostPath = [System.IO.Path]::GetFullPath([string]$record.hostExecutablePath)
                if ([int]$record.hostPid -ne $hostProcessId -or
                    [long]$record.startTimeFileTimeUtc -ne
                        [long]$serverIdentity.StartTimeFileTimeUtc -or
                    [long]$record.hostStartTimeFileTimeUtc -ne [long]$hostIdentity.StartTimeFileTimeUtc -or
                    -not $recordedHostPath.Equals(
                        [string]$hostIdentity.ExecutablePath,
                        [System.StringComparison]::OrdinalIgnoreCase) -or
                    [string]$record.startupRequestId -ne $startupRequestId -or
                    [string]$record.serverEnvironment -cne $serverEnvironmentName -or
                    [string]$record.environmentId -cne $layout.EnvironmentId -or
                    [string]$record.componentId -cne $approved.ComponentId -or
                    -not (Test-PSOBBFixedTimeTextEquals `
                        -Expected $controlIdentity `
                        -Actual ([string]$record.controlIdentity)) -or
                    [string]$record.executablePath -ne $executable -or
                    [string]$record.executableSha256 -ne $approved.Sha256 -or
                    -not (Test-PSOBBFixedTimeTextEquals `
                        -Expected $controlToken `
                        -Actual ([string]$record.controlToken))) {
                    throw 'The supervisor process record did not match this start request'
                }
                if ($bindingExpectations) {
                    if ([string]$record.buildContractSha256 -cne
                            [string]$bindingExpectations.BuildContractSha256 -or
                        [string]$record.clientBindingSha256 -cne
                            [string]$bindingExpectations.ClientBindingSha256 -or
                        [string]$record.stateBindingSha256 -cne
                            [string]$bindingExpectations.StateBindingSha256) {
                        throw 'The supervisor process record did not retain the sealed combat-canary bindings'
                    }
                } elseif ($null -ne $record.buildContractSha256 -or
                    $null -ne $record.clientBindingSha256 -or
                    $null -ne $record.stateBindingSha256) {
                    throw 'The Stable supervisor process record contains unexpected combat-canary bindings'
                }
                if ($null -eq $listenerDeadline) {
                    $listenerDeadline = [DateTime]::UtcNow.AddSeconds(
                        $StartupTimeoutSeconds)
                }
                if (Test-PSOBBExactLoopbackServerListeners `
                        -ProcessId $serverProcess.Id) {
                    $readyProbe = Get-LaunchedSupervisorProbe `
                        -Identity $hostIdentity `
                        -ProbeAttempts 3 `
                        -ProbeDelayMilliseconds 25
                    if ($readyProbe.State -ne 'Verified') {
                        throw "The supervisor was $($readyProbe.State) at readiness: $($readyProbe.Detail)"
                    }
                    Assert-PSOBBNoRunningClients -Layout $rootLayout | Out-Null
                    $readyServerCensus = @(
                        Get-PSOBBServerEnvironmentProcessRecords -Layout $rootLayout)
                    $readyRecordedProcess = Get-NewservProcess -Layout $layout
                    try {
                        if (-not $readyRecordedProcess -or
                            $readyRecordedProcess.Id -ne $serverProcess.Id -or
                            $readyServerCensus.Count -ne 1 -or
                            [string]$readyServerCensus[0].Classification -cne
                                'ApprovedExactPath' -or
                            [string]$readyServerCensus[0].ServerEnvironment -cne
                                $serverEnvironmentName -or
                            [int]$readyServerCensus[0].ProcessId -ne
                                $serverProcess.Id -or
                            [long]$readyServerCensus[0].StartTimeFileTimeUtc -ne
                                [long]$serverIdentity.StartTimeFileTimeUtc -or
                            -not (Test-PSOBBExactLoopbackServerListeners `
                                -ProcessId $serverProcess.Id)) {
                            throw 'The final ready census no longer contains exactly the selected approved server and listener set'
                        }
                    } finally {
                        if ($readyRecordedProcess) { $readyRecordedProcess.Dispose() }
                    }
                    $controlToken = $null
                    $startupCompleted = $true
                    $startResult = [pscustomobject]@{
                        Pid = $serverProcess.Id
                        HostPid = $hostProcessId
                        Supervised = $true
                        ServerEnvironment = $serverEnvironmentName
                        EnvironmentId = $layout.EnvironmentId
                        ComponentId = $approved.ComponentId
                        ControlIdentity = $controlIdentity
                        ExecutableSha256 = $approved.Sha256
                        Listeners = @('127.0.0.1:11000', '127.0.0.1:12000', '127.0.0.1:12001')
                    }
                    break
                }
            }
        }
        $now = [DateTime]::UtcNow
        if ($null -eq $listenerDeadline) {
            if ($now -ge $verificationDeadline) {
                throw "The combat-canary installation verification and child creation did not complete within $VerificationTimeoutSeconds seconds"
            }
        } elseif ($now -ge $listenerDeadline) {
            break
        }
        Start-Sleep -Milliseconds 250
    }

    if ($startResult) {
        Write-Output -NoEnumerate $startResult
    } elseif ($serverEnvironmentName -ceq 'CombatCanary') {
        throw "newserv did not reach the exact approved loopback listener set within $StartupTimeoutSeconds seconds after verified child creation"
    } else {
        throw 'newserv did not reach the exact approved loopback listener set before the startup timeout'
    }
} catch {
    $startupFailure = $_
    $cleanupFailure = $null
    if (-not $hostIdentity -and $nativeHostIdentity) {
        $hostIdentity = [pscustomobject]@{
            Pid = [int]$nativeHostIdentity.ProcessId
            ExecutablePath = [System.IO.Path]::GetFullPath(
                (Join-Path $PSHOME 'pwsh.exe'))
            StartTimeFileTimeUtc = [long]$nativeHostIdentity.StartTimeFileTimeUtc
            NativeIdentity = $nativeHostIdentity
        }
    }
    if (-not $startupCompleted -and $hostIdentity -and $controlToken -and
        $startupRequestId -and $controlIdentity) {
        try {
            Stop-ExactLaunchedSupervisorAfterFailure `
                -Layout $layout `
                -Identity $hostIdentity `
                -ControlToken $controlToken `
                -StartupRequestId $startupRequestId `
                -ControlIdentity $controlIdentity `
                -ComponentId $approved.ComponentId
        } catch {
            $cleanupFailure = $_.Exception.Message
        }
    } elseif (-not $startupCompleted -and -not $nativeHostIdentity -and
        $startupStateWritten) {
        try {
            Remove-PSOBBLifecycleFilesVerified -Layout $layout | Out-Null
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
    if ($serverProcess) { $serverProcess.Dispose() }
    if ($nativeHostIdentity) {
        $nativeHostIdentity.Dispose()
    }
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
    if ($clientOperationMutex) {
        Exit-PSOBBClientOperationLock -Mutex $clientOperationMutex
    }
}
