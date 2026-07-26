Set-StrictMode -Version Latest

if (-not ('PSOBBCombatCanary.NativeFiles' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PSOBBCombatCanary {
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileDispositionInformation {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    public static class NativeFiles {
        public const uint GenericRead = 0x80000000;
        public const uint GenericWrite = 0x40000000;
        public const uint Delete = 0x00010000;
        public const uint FileReadAttributes = 0x00000080;
        public const uint FileShareRead = 0x00000001;
        public const uint FileShareWrite = 0x00000002;
        public const uint OpenExisting = 3;
        public const uint CreateNew = 1;
        public const uint FileFlagOpenReparsePoint = 0x00200000;
        public const uint FileFlagBackupSemantics = 0x02000000;
        public const uint FileFlagSequentialScan = 0x08000000;
        public const uint FileFlagWriteThrough = 0x80000000;
        public const uint FileAttributeDirectory = 0x00000010;
        public const uint FileAttributeReparsePoint = 0x00000400;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateDirectoryW(
            string path,
            IntPtr securityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            ref FileDispositionInformation information,
            uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle",
            SetLastError = true)]
        private static extern bool SetFileInformationByHandleBuffer(
            SafeFileHandle file,
            int informationClass,
            IntPtr information,
            uint bufferSize);

        public static ByHandleFileInformation GetInformation(SafeFileHandle file) {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(file, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return information;
        }

        public static string GetFinalPath(SafeFileHandle file) {
            uint required = GetFinalPathNameByHandleW(file, null, 0, 0);
            if (required == 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            StringBuilder path = new StringBuilder(checked((int)required + 1));
            uint written = GetFinalPathNameByHandleW(
                file, path, (uint)path.Capacity, 0);
            if (written == 0 || written >= path.Capacity) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return path.ToString();
        }

        public static void MarkDelete(SafeFileHandle file) {
            FileDispositionInformation information =
                new FileDispositionInformation { DeleteFile = true };
            if (!SetFileInformationByHandle(
                    file, 4, ref information,
                    (uint)Marshal.SizeOf<FileDispositionInformation>())) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static void Rename(SafeFileHandle file, string destination) {
            if (file == null || file.IsInvalid || file.IsClosed) {
                throw new ArgumentException("The source handle is not open.", "file");
            }
            if (String.IsNullOrWhiteSpace(destination)) {
                throw new ArgumentException("The destination is empty.", "destination");
            }
            byte[] nameBytes = Encoding.Unicode.GetBytes(destination);
            int rootOffset = IntPtr.Size == 8 ? 8 : 4;
            int lengthOffset = checked(rootOffset + IntPtr.Size);
            int nameOffset = checked(lengthOffset + sizeof(uint));
            int bufferSize = checked(nameOffset + nameBytes.Length + sizeof(char));
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try {
                byte[] cleared = new byte[bufferSize];
                Marshal.Copy(cleared, 0, buffer, bufferSize);
                Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
                Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
                Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset),
                    nameBytes.Length);
                if (!SetFileInformationByHandleBuffer(
                        file, 3, buffer, checked((uint)bufferSize))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally {
                Array.Clear(nameBytes, 0, nameBytes.Length);
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    public sealed class BoundedMemoryStream : MemoryStream {
        private readonly long maximumLength;

        public BoundedMemoryStream(long maximumLength) {
            if (maximumLength < 1 || maximumLength > 1048576) {
                throw new ArgumentOutOfRangeException("maximumLength");
            }
            this.maximumLength = maximumLength;
        }

        private void EnsureWriteFits(int count) {
            if (count < 0 || Position > maximumLength - count) {
                throw new InvalidDataException(
                    "The redirected process output exceeded its byte bound.");
            }
        }

        public override void Write(byte[] buffer, int offset, int count) {
            EnsureWriteFits(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer) {
            EnsureWriteFits(buffer.Length);
            base.Write(buffer);
        }

        public override void WriteByte(byte value) {
            EnsureWriteFits(1);
            base.WriteByte(value);
        }

        public override System.Threading.Tasks.Task WriteAsync(
                byte[] buffer, int offset, int count,
                System.Threading.CancellationToken cancellationToken) {
            EnsureWriteFits(count);
            return base.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override System.Threading.Tasks.ValueTask WriteAsync(
                ReadOnlyMemory<byte> buffer,
                System.Threading.CancellationToken cancellationToken = default) {
            EnsureWriteFits(buffer.Length);
            return base.WriteAsync(buffer, cancellationToken);
        }

        public string ReadUtf8AndClear() {
            byte[] bytes = ToArray();
            try {
                return new UTF8Encoding(false, true).GetString(bytes);
            } finally {
                Array.Clear(bytes, 0, bytes.Length);
                SetLength(0);
            }
        }

        protected override void Dispose(bool disposing) {
            if (disposing && TryGetBuffer(out ArraySegment<byte> buffer) &&
                    buffer.Array != null) {
                Array.Clear(buffer.Array, 0, buffer.Array.Length);
            }
            base.Dispose(disposing);
        }
    }
}
'@
}

function ConvertFrom-PSOBBCombatCanaryNativeFinalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $ordinary = if ($Path.StartsWith(
            '\\?\UNC\', [System.StringComparison]::OrdinalIgnoreCase)) {
        '\\' + $Path.Substring(8)
    } elseif ($Path.StartsWith(
            '\\?\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $Path.Substring(4)
    } else {
        $Path
    }
    [System.IO.Path]::GetFullPath($ordinary).TrimEnd('\')
}

function Get-PSOBBCombatCanaryNativeHandleIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle
    )

    if ($Handle.IsInvalid -or $Handle.IsClosed) {
        throw 'The combat-canary native file handle is not open'
    }
    $information = [PSOBBCombatCanary.NativeFiles]::GetInformation($Handle)
    $fileId = ([uint64]$information.FileIndexHigh -shl 32) -bor
        [uint64]$information.FileIndexLow
    $length = ([uint64]$information.FileSizeHigh -shl 32) -bor
        [uint64]$information.FileSizeLow
    [pscustomobject]@{
        VolumeSerialNumber = [uint32]$information.VolumeSerialNumber
        FileId = [uint64]$fileId
        Length = [uint64]$length
        NumberOfLinks = [uint32]$information.NumberOfLinks
        Attributes = [uint32]$information.FileAttributes
        FinalPath = ConvertFrom-PSOBBCombatCanaryNativeFinalPath `
            -Path ([PSOBBCombatCanary.NativeFiles]::GetFinalPath($Handle))
    }
}

function Test-PSOBBCombatCanaryNativeIdentityEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    [uint32]$Left.VolumeSerialNumber -eq [uint32]$Right.VolumeSerialNumber -and
        [uint64]$Left.FileId -eq [uint64]$Right.FileId -and
        [uint32]$Left.Attributes -eq [uint32]$Right.Attributes -and
        [string]$Left.FinalPath -ieq [string]$Right.FinalPath
}

function Open-PSOBBCombatCanaryNativePathHandle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][bool]$Directory,
        [switch]$Read,
        [switch]$Delete,
        [switch]$AllowWriteShare
    )

    $access = [uint32][PSOBBCombatCanary.NativeFiles]::FileReadAttributes
    if ($Read) {
        $access = $access -bor
            [uint32][PSOBBCombatCanary.NativeFiles]::GenericRead
    }
    if ($Delete) {
        $access = $access -bor [uint32][PSOBBCombatCanary.NativeFiles]::Delete
    }
    $flags = [uint32][PSOBBCombatCanary.NativeFiles]::FileFlagOpenReparsePoint
    if ($Directory) {
        $flags = $flags -bor
            [uint32][PSOBBCombatCanary.NativeFiles]::FileFlagBackupSemantics
    } elseif ($Read) {
        $flags = $flags -bor
            [uint32][PSOBBCombatCanary.NativeFiles]::FileFlagSequentialScan
    }
    $shareMode = [uint32][PSOBBCombatCanary.NativeFiles]::FileShareRead
    if ($Directory -or $AllowWriteShare) {
        $shareMode = $shareMode -bor
            [uint32][PSOBBCombatCanary.NativeFiles]::FileShareWrite
    }
    $handle = [PSOBBCombatCanary.NativeFiles]::CreateFileW(
        $Path,
        $access,
        $shareMode,
        [IntPtr]::Zero,
        [uint32][PSOBBCombatCanary.NativeFiles]::OpenExisting,
        $flags,
        [IntPtr]::Zero)
    if ($handle.IsInvalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $handle.Dispose()
        throw [System.ComponentModel.Win32Exception]::new($errorCode)
    }
    $handle
}

function Assert-PSOBBCombatCanaryNativeHandlePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle,
        [Parameter(Mandatory)][string]$ExpectedPath,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$Directory,
        [Parameter(Mandatory)][string]$RoleLabel,
        [switch]$RequireSingleLink
    )

    $identity = Get-PSOBBCombatCanaryNativeHandleIdentity -Handle $Handle
    $expected = [System.IO.Path]::GetFullPath($ExpectedPath).TrimEnd('\')
    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $directoryAttribute = [uint32][PSOBBCombatCanary.NativeFiles]::
        FileAttributeDirectory
    $reparseAttribute = [uint32][PSOBBCombatCanary.NativeFiles]::
        FileAttributeReparsePoint
    $isDirectory = ([uint32]$identity.Attributes -band $directoryAttribute) -ne 0
    if (([uint32]$identity.Attributes -band $reparseAttribute) -ne 0 -or
        $isDirectory -ne $Directory -or
        [string]$identity.FinalPath -ine $expected -or
        ($identity.FinalPath -ine $safeRoot -and
            -not ($identity.FinalPath + '\').StartsWith(
                $safeRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($RequireSingleLink -and [uint32]$identity.NumberOfLinks -ne 1)) {
        throw "The $RoleLabel handle identity is not one contained ordinary path"
    }
    $identity
}

function Close-PSOBBCombatCanaryOrdinaryFileLease {
    [CmdletBinding()]
    param($Context)

    if ($null -eq $Context) { return }
    if ($null -ne $Context.Stream) {
        $Context.Stream.Dispose()
    }
    foreach ($ancestor in @($Context.Ancestors)) {
        if ($null -ne $ancestor.Handle) {
            $ancestor.Handle.Dispose()
        }
    }
}

function Open-PSOBBCombatCanaryOrdinaryFileLease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RoleLabel,
        [switch]$AllowWriteShare
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PathWithinRoot -Path $LiteralPath -Root $safeRoot
    $relative = [System.IO.Path]::GetRelativePath($safeRoot, $safePath)
    if ($relative -eq '.' -or $relative -eq '..' -or
        $relative.StartsWith('..\', [System.StringComparison]::Ordinal)) {
        throw "The $RoleLabel path is not one contained file"
    }
    $segments = @($relative.Split('\'))
    $directoryPaths = [System.Collections.Generic.List[string]]::new()
    $directoryPaths.Add($safeRoot)
    $current = $safeRoot
    for ($index = 0; $index -lt $segments.Count - 1; $index++) {
        $current = Join-Path $current $segments[$index]
        $directoryPaths.Add([System.IO.Path]::GetFullPath($current).TrimEnd('\'))
    }

    $ancestors = [System.Collections.Generic.List[object]]::new()
    $fileHandle = $null
    $stream = $null
    $completed = $false
    try {
        foreach ($directoryPath in $directoryPaths) {
            $handle = Open-PSOBBCombatCanaryNativePathHandle `
                -Path $directoryPath -Directory $true
            try {
                $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
                    -Handle $handle -ExpectedPath $directoryPath -Root $safeRoot `
                    -Directory $true -RoleLabel "$RoleLabel ancestor"
                $ancestors.Add([pscustomobject]@{
                        Path = $directoryPath
                        Handle = $handle
                        Identity = $identity
                    })
                $handle = $null
            } finally {
                if ($null -ne $handle) { $handle.Dispose() }
            }
        }
        $fileHandle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $safePath -Directory $false -Read `
            -AllowWriteShare:$AllowWriteShare
        $fileIdentity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $fileHandle -ExpectedPath $safePath -Root $safeRoot `
            -Directory $false -RoleLabel $RoleLabel -RequireSingleLink
        $stream = [System.IO.FileStream]::new(
            $fileHandle, [System.IO.FileAccess]::Read, 65536, $false)
        $fileHandle = $null
        if ([uint64]$stream.Length -ne [uint64]$fileIdentity.Length) {
            throw "The $RoleLabel handle length changed during lease creation"
        }
        foreach ($ancestor in $ancestors) {
            $currentIdentity = Assert-PSOBBCombatCanaryNativeHandlePath `
                -Handle $ancestor.Handle -ExpectedPath $ancestor.Path `
                -Root $safeRoot -Directory $true `
                -RoleLabel "$RoleLabel ancestor"
            if (-not (Test-PSOBBCombatCanaryNativeIdentityEqual `
                    -Left $ancestor.Identity -Right $currentIdentity)) {
                throw "The $RoleLabel ancestor identity changed during lease creation"
            }
        }
        $context = [pscustomobject]@{
            Path = $safePath
            Root = $safeRoot
            Stream = $stream
            Identity = $fileIdentity
            Ancestors = $ancestors.ToArray()
        }
        $stream = $null
        $completed = $true
        $context
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $fileHandle) { $fileHandle.Dispose() }
        if (-not $completed) {
            foreach ($ancestor in $ancestors) {
                if ($null -ne $ancestor.Handle) { $ancestor.Handle.Dispose() }
            }
        }
    }
}

function Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $currentFile = Assert-PSOBBCombatCanaryNativeHandlePath `
        -Handle $Context.Stream.SafeFileHandle -ExpectedPath $Context.Path `
        -Root $Context.Root -Directory $false -RoleLabel $RoleLabel `
        -RequireSingleLink
    if (-not (Test-PSOBBCombatCanaryNativeIdentityEqual `
            -Left $Context.Identity -Right $currentFile) -or
        [uint64]$currentFile.Length -ne [uint64]$Context.Identity.Length) {
        throw "The $RoleLabel leased file identity changed"
    }
    foreach ($ancestor in @($Context.Ancestors)) {
        $currentAncestor = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $ancestor.Handle -ExpectedPath $ancestor.Path `
            -Root $Context.Root -Directory $true `
            -RoleLabel "$RoleLabel ancestor"
        if (-not (Test-PSOBBCombatCanaryNativeIdentityEqual `
                -Left $ancestor.Identity -Right $currentAncestor)) {
            throw "The $RoleLabel leased ancestor identity changed"
        }
    }
    $true
}

function Invoke-PSOBBCombatCanaryBoundedFileSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [ValidateRange(1, 67108864)]
        [long]$MaximumBytes,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel,

        [ValidatePattern('^$|^[a-f0-9]{64}$')]
        [string]$ExpectedSha256 = '',

        [ValidateRange(-1, 67108864)]
        [long]$ExpectedLength = -1,

        [Parameter(Mandatory)]
        [scriptblock]$Consumer,

        [Parameter(DontShow = $true)]
        [scriptblock]$InternalTestAfterInitialValidation,

        [Parameter(DontShow = $true)]
        [scriptblock]$InternalTestAfterIdentity,

        [switch]$RequireProtectedAcl,

        [Parameter(DontShow = $true)]
        [switch]$AllowWriteShare
    )

    $lease = $null
    $bytes = $null
    $hashBytes = $null
    try {
        $lease = Open-PSOBBCombatCanaryOrdinaryFileLease `
            -LiteralPath $LiteralPath -Root $Root -RoleLabel $RoleLabel `
            -AllowWriteShare:$AllowWriteShare
        if ($InternalTestAfterInitialValidation) {
            & $InternalTestAfterInitialValidation $lease.Path
        }
        [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                -Context $lease -RoleLabel $RoleLabel)
        $length = [long]$lease.Stream.Length
        if ($length -le 0 -or $length -gt $MaximumBytes -or
            $length -gt [int]::MaxValue -or
            ($ExpectedLength -ge 0 -and $length -ne $ExpectedLength)) {
            throw "The $RoleLabel has an invalid bounded size"
        }
        $bytes = [byte[]]::new([int]$length)
        $lease.Stream.Position = 0
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $lease.Stream.Read(
                $bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw "The $RoleLabel changed or ended while its locked bytes were read"
            }
            $offset += $read
        }
        if ($lease.Stream.ReadByte() -ne -1) {
            throw "The $RoleLabel grew while its locked bytes were read"
        }
        $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $sha256 = ([Convert]::ToHexString($hashBytes)).ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and
            $sha256 -cne $ExpectedSha256) {
            throw "The $RoleLabel does not match its expected digest"
        }
        if ($InternalTestAfterIdentity) {
            & $InternalTestAfterIdentity $lease.Path
        }
        [void](Assert-PSOBBCombatCanaryOrdinaryFileLeaseIdentity `
                -Context $lease -RoleLabel $RoleLabel)
        if ([long]$lease.Stream.Length -ne $length) {
            throw "The $RoleLabel changed while its locked bytes were consumed"
        }
        if ($RequireProtectedAcl -and
            -not (Test-PSOBBProtectedAcl -Path $lease.Path)) {
            throw "The $RoleLabel does not have its protected file ACL"
        }
        $value = & $Consumer ([byte[]]$bytes)
        [pscustomobject]@{
            Value = $value
            Path = $lease.Path
            Length = $length
            Sha256 = $sha256
            VolumeSerialNumber = [uint32]$lease.Identity.VolumeSerialNumber
            FileId = [uint64]$lease.Identity.FileId
        }
    } finally {
        if ($null -ne $hashBytes) {
            [Array]::Clear($hashBytes, 0, $hashBytes.Length)
        }
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
        Close-PSOBBCombatCanaryOrdinaryFileLease -Context $lease
    }
}

function Get-PSOBBCombatCanaryPayloadRolePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('twills-contract', 'signing-public-key', 'license-state',
            'twills-character', 'twills-bank', 'twills-system', 'twills-card',
            'team-state')]
        [string]$Role
    )

    switch -CaseSensitive ($Role) {
        'twills-contract' {
            [pscustomobject]@{ MaximumBytes = 128KB; MinimumCount = 1; MaximumCount = 1 }
        }
        'signing-public-key' {
            [pscustomobject]@{ MaximumBytes = 16KB; MinimumCount = 1; MaximumCount = 1 }
        }
        'license-state' {
            [pscustomobject]@{ MaximumBytes = 256KB; MinimumCount = 1; MaximumCount = 32 }
        }
        'twills-character' {
            [pscustomobject]@{ MaximumBytes = 1MB; MinimumCount = 1; MaximumCount = 1 }
        }
        'twills-bank' {
            [pscustomobject]@{ MaximumBytes = 1MB; MinimumCount = 1; MaximumCount = 1 }
        }
        'twills-system' {
            [pscustomobject]@{ MaximumBytes = 1MB; MinimumCount = 1; MaximumCount = 1 }
        }
        'twills-card' {
            [pscustomobject]@{ MaximumBytes = 1MB; MinimumCount = 1; MaximumCount = 1 }
        }
        'team-state' {
            [pscustomobject]@{ MaximumBytes = 1MB; MinimumCount = 1; MaximumCount = 1 }
        }
    }
}

function Assert-PSOBBCombatCanaryPayloadSetPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries,
        [Parameter(Mandatory)][ValidateSet('Snapshot', 'State')]
        [string]$Scope,
        [string]$RoleProperty = 'role',
        [string]$SizeProperty = 'size'
    )

    $roles = if ($Scope -ceq 'Snapshot') {
        @('twills-contract', 'signing-public-key', 'license-state',
            'twills-character', 'twills-bank', 'twills-system', 'twills-card',
            'team-state')
    } else {
        @('license-state', 'twills-character', 'twills-bank', 'twills-system',
            'twills-card', 'team-state')
    }
    $counts = @{}
    foreach ($role in $roles) { $counts[$role] = 0 }
    $aggregate = [uint64]0
    foreach ($entry in $Entries) {
        if ($null -eq $entry) {
            throw 'The combat-canary payload policy received an incomplete entry'
        }
        $roleToken = $null
        $sizeToken = $null
        if ($entry -is [System.Collections.IDictionary]) {
            $keys = @($entry.Keys | ForEach-Object { [string]$_ })
            if ($keys -cnotcontains $RoleProperty -or
                $keys -cnotcontains $SizeProperty) {
                throw 'The combat-canary payload policy received an incomplete entry'
            }
            $roleToken = $entry[$RoleProperty]
            $sizeToken = $entry[$SizeProperty]
        } else {
            $roleProperties = @($entry.PSObject.Properties | Where-Object {
                    $_.Name -ceq $RoleProperty
                })
            $sizeProperties = @($entry.PSObject.Properties | Where-Object {
                    $_.Name -ceq $SizeProperty
                })
            if ($roleProperties.Count -ne 1 -or
                $sizeProperties.Count -ne 1) {
                throw 'The combat-canary payload policy received an incomplete entry'
            }
            $roleToken = $roleProperties[0].Value
            $sizeToken = $sizeProperties[0].Value
        }
        if ($roleToken -isnot [string] -or $sizeToken -isnot [long]) {
            throw 'The combat-canary payload policy received an invalid role or size type'
        }
        $role = [string]$roleToken
        if (-not $counts.ContainsKey($role)) {
            throw 'The combat-canary payload policy received an unsupported role'
        }
        $size = [uint64]$sizeToken
        $policy = Get-PSOBBCombatCanaryPayloadRolePolicy -Role $role
        if ($size -lt 1 -or $size -gt [uint64]$policy.MaximumBytes) {
            throw "The combat-canary '$role' payload exceeds its exact role bound"
        }
        if ([uint64]::MaxValue - $aggregate -lt $size) {
            throw 'The combat-canary payload aggregate overflowed'
        }
        $aggregate += $size
        $counts[$role]++
        if ($counts[$role] -gt [int]$policy.MaximumCount) {
            throw "The combat-canary '$role' payload count exceeds its exact bound"
        }
    }
    foreach ($role in $roles) {
        $policy = Get-PSOBBCombatCanaryPayloadRolePolicy -Role $role
        if ($counts[$role] -lt [int]$policy.MinimumCount -or
            $counts[$role] -gt [int]$policy.MaximumCount) {
            throw "The combat-canary '$role' payload count is outside its exact bound"
        }
    }
    $maximumFiles = if ($Scope -ceq 'Snapshot') { 39 } else { 37 }
    $maximumAggregate = if ($Scope -ceq 'Snapshot') { 16MB } else { 15MB }
    if ($Entries.Count -gt $maximumFiles -or
        $aggregate -gt [uint64]$maximumAggregate) {
        throw 'The combat-canary payload set exceeds its exact count or aggregate bound'
    }
    [pscustomobject]@{
        Files = $Entries.Count
        Bytes = [uint64]$aggregate
        Scope = $Scope
    }
}

function Test-PSOBBCombatCanaryRuntimeClientManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BaseEntries,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ActualEntries,

        [Parameter(Mandatory)]
        $ClientProfileEntry,

        [AllowEmptyCollection()]
        [object[]]$GameplayOverlayEntries = @()
    )

    if ($BaseEntries.Count -lt 1 -or $BaseEntries.Count -gt 65536 -or
        $ActualEntries.Count -gt ($BaseEntries.Count + 43) -or
        $GameplayOverlayEntries.Count -notin @(0, 3)) {
        return $false
    }

    $baseByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $actualByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $overlayByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($set in @(
            [pscustomobject]@{ Entries = $BaseEntries; Map = $baseByPath },
            [pscustomobject]@{ Entries = $ActualEntries; Map = $actualByPath },
            [pscustomobject]@{
                Entries = $GameplayOverlayEntries
                Map = $overlayByPath
            })) {
        foreach ($entry in @($set.Entries)) {
            if ($null -eq $entry) { return $false }
            $properties = @($entry.PSObject.Properties.Name | Sort-Object)
            if ([string]::Join("`n", $properties) -cne
                [string]::Join("`n", @('path', 'sha256', 'size'))) {
                return $false
            }
            $path = [string]$entry.path
            $size = [int64]0
            if ($entry.path -isnot [string] -or
                [string]::IsNullOrWhiteSpace($path) -or
                $path -cnotmatch '^(?!/)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*[\\:])[ -~]+$' -or
                $entry.size -isnot [long] -or
                -not [int64]::TryParse(
                    ([string]$entry.size),
                    [Globalization.NumberStyles]::None,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$size) -or
                $size -lt 0 -or
                $entry.sha256 -isnot [string] -or
                [string]$entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $set.Map.ContainsKey($path)) {
                return $false
            }
            $set.Map.Add($path, $entry)
        }
    }

    $overlayLimits = [ordered]@{
        'dinput8.dll' = 16MB
        'plugins/PSOBB.Gameplay.asi' = 4MB
        'plugins/PSOBB.Gameplay.ini' = 4KB
    }
    if ($GameplayOverlayEntries.Count -eq 3) {
        foreach ($expectedPath in $overlayLimits.Keys) {
            if (-not $overlayByPath.ContainsKey($expectedPath) -or
                [string]$overlayByPath[$expectedPath].path -cne $expectedPath -or
                [int64]$overlayByPath[$expectedPath].size -lt 1 -or
                [int64]$overlayByPath[$expectedPath].size -gt
                    [int64]$overlayLimits[$expectedPath] -or
                $baseByPath.ContainsKey($expectedPath)) {
                return $false
            }
        }
    }

    if ($null -eq $ClientProfileEntry) { return $false }
    $profileProperties = @(
        $ClientProfileEntry.PSObject.Properties.Name | Sort-Object)
    if ([string]::Join("`n", $profileProperties) -cne
        [string]::Join("`n", @('path', 'sha256', 'size')) -or
        $ClientProfileEntry.path -isnot [string] -or
        [string]$ClientProfileEntry.path -cne 'client-profile.json' -or
        $ClientProfileEntry.size -isnot [long] -or
        [int64]$ClientProfileEntry.size -lt 1 -or
        [int64]$ClientProfileEntry.size -gt 256KB -or
        $ClientProfileEntry.sha256 -isnot [string] -or
        [string]$ClientProfileEntry.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        return $false
    }

    $mutableBytes = [uint64]0
    $chatLogs = 0
    $mutableGameGuard = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($path in @(
            'GameGuard/0npgg.erl',
            'GameGuard/0npgl.erl',
            'GameGuard/0npgm.erl',
            'GameGuard/0npgmup.erl',
            'GameGuard/0npsc.erl',
            'GameGuard/npgl.erl')) {
        [void]$mutableGameGuard.Add($path)
    }
    $generatedGameGuard = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($path in @(
            'GameGuard/1npgg.erl',
            'GameGuard/1npgl.erl',
            'GameGuard/1npgm.erl',
            'GameGuard/1npgmup.erl',
            'GameGuard/1npsc.erl')) {
        [void]$generatedGameGuard.Add($path)
    }

    foreach ($baseEntry in $BaseEntries) {
        $path = [string]$baseEntry.path
        $mutable = $mutableGameGuard.Contains($path) -or
            $path -cmatch '^log/(?:spec|error|generic)\.log$'
        if (-not $actualByPath.ContainsKey($path)) {
            if ($mutable) { continue }
            return $false
        }
        $actual = $actualByPath[$path]
        if ([string]$actual.path -cne $path) { return $false }
        if (-not $mutable) {
            if ([int64]$actual.size -ne [int64]$baseEntry.size -or
                [string]$actual.sha256 -cne [string]$baseEntry.sha256) {
                return $false
            }
            continue
        }

        $maximum = if ($mutableGameGuard.Contains($path)) { 1MB } else { 16MB }
        $minimum = if ($mutableGameGuard.Contains($path)) { 1 } else { 0 }
        $size = [uint64][int64]$actual.size
        if ($size -lt [uint64]$minimum -or $size -gt [uint64]$maximum -or
            [uint64]::MaxValue - $mutableBytes -lt $size) {
            return $false
        }
        $mutableBytes += $size
    }

    foreach ($actual in $ActualEntries) {
        $path = [string]$actual.path
        if ($baseByPath.ContainsKey($path)) {
            if ([string]$baseByPath[$path].path -cne $path) { return $false }
            continue
        }
        if ($path -ceq 'client-profile.json') {
            if ([int64]$actual.size -ne [int64]$ClientProfileEntry.size -or
                [string]$actual.sha256 -cne
                    [string]$ClientProfileEntry.sha256) {
                return $false
            }
            continue
        }
        if ($overlayByPath.ContainsKey($path)) {
            $expectedOverlay = $overlayByPath[$path]
            if ([string]$expectedOverlay.path -cne $path -or
                [int64]$actual.size -ne [int64]$expectedOverlay.size -or
                [string]$actual.sha256 -cne
                    [string]$expectedOverlay.sha256) {
                return $false
            }
            continue
        }

        $maximum = [int64]0
        if ($generatedGameGuard.Contains($path)) {
            $maximum = 1MB
        } elseif ($path -cmatch '^log/chat[0-9]{8}\.txt$') {
            $chatLogs++
            if ($chatLogs -gt 32) { return $false }
            $maximum = 16MB
        } else {
            return $false
        }
        $size = [uint64][int64]$actual.size
        if ($size -gt [uint64]$maximum -or
            ($generatedGameGuard.Contains($path) -and $size -lt 1) -or
            [uint64]::MaxValue - $mutableBytes -lt $size) {
            return $false
        }
        $mutableBytes += $size
    }

    $overlayPresent = $true
    foreach ($expectedPath in $overlayByPath.Keys) {
        if (-not $actualByPath.ContainsKey($expectedPath) -or
            [string]$actualByPath[$expectedPath].path -cne $expectedPath) {
            $overlayPresent = $false
            break
        }
    }

    $actualByPath.ContainsKey('client-profile.json') -and
        [string]$actualByPath['client-profile.json'].path -ceq
            'client-profile.json' -and
        $overlayPresent -and
        $mutableBytes -le [uint64](64MB)
}

function Open-PSOBBCombatCanaryDirectoryLeaseChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PathWithinRoot -Path $Path -Root $safeRoot
    $relative = [System.IO.Path]::GetRelativePath($safeRoot, $safePath)
    if ($relative -eq '..' -or
        $relative.StartsWith('..\', [System.StringComparison]::Ordinal)) {
        throw "The $RoleLabel directory is outside its approved root"
    }
    $paths = [System.Collections.Generic.List[string]]::new()
    $paths.Add($safeRoot)
    if ($relative -ne '.') {
        $current = $safeRoot
        foreach ($segment in @($relative.Split('\'))) {
            $current = Join-Path $current $segment
            $paths.Add([System.IO.Path]::GetFullPath($current).TrimEnd('\'))
        }
    }
    $leases = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($directoryPath in $paths) {
            $handle = Open-PSOBBCombatCanaryNativePathHandle `
                -Path $directoryPath -Directory $true
            try {
                $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
                    -Handle $handle -ExpectedPath $directoryPath -Root $safeRoot `
                    -Directory $true -RoleLabel "$RoleLabel ancestor"
                $leases.Add([pscustomobject]@{
                        Path = $directoryPath
                        Handle = $handle
                        Identity = $identity
                    })
                $handle = $null
            } finally {
                if ($null -ne $handle) { $handle.Dispose() }
            }
        }
        $result = $leases.ToArray()
        $leases.Clear()
        $result
    } finally {
        foreach ($lease in $leases) {
            if ($null -ne $lease.Handle) { $lease.Handle.Dispose() }
        }
    }
}

function Close-PSOBBCombatCanaryDirectoryLeaseChain {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Leases)

    foreach ($lease in @($Leases)) {
        if ($null -ne $lease.Handle) { $lease.Handle.Dispose() }
    }
}

function Write-PSOBBCombatCanaryNoClobberBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $safeRoot = [System.IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\')
    $safeDestination = Assert-PathWithinRoot `
        -Path $Destination -Root $safeRoot
    $parent = Split-Path -Parent $safeDestination
    $parentLeases = @()
    $handle = $null
    $stream = $null
    try {
        $parentLeases = @(Open-PSOBBCombatCanaryDirectoryLeaseChain `
                -Path $parent -Root $safeRoot -RoleLabel "$RoleLabel destination")
        $handle = [PSOBBCombatCanary.NativeFiles]::CreateFileW(
            $safeDestination,
            ([uint32][PSOBBCombatCanary.NativeFiles]::GenericWrite -bor
                [uint32][PSOBBCombatCanary.NativeFiles]::FileReadAttributes),
            [uint32][PSOBBCombatCanary.NativeFiles]::FileShareRead,
            [IntPtr]::Zero,
            [uint32][PSOBBCombatCanary.NativeFiles]::CreateNew,
            ([uint32][PSOBBCombatCanary.NativeFiles]::FileFlagWriteThrough -bor
                [uint32][PSOBBCombatCanary.NativeFiles]::FileFlagOpenReparsePoint),
            [IntPtr]::Zero)
        if ($handle.IsInvalid) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $handle.Dispose()
            $handle = $null
            throw [System.ComponentModel.Win32Exception]::new($errorCode)
        }
        $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $handle -ExpectedPath $safeDestination -Root $safeRoot `
            -Directory $false -RoleLabel "$RoleLabel destination" `
            -RequireSingleLink
        $stream = [System.IO.FileStream]::new(
            $handle, [System.IO.FileAccess]::Write, 65536, $false)
        $handle = $null
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $writtenIdentity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $stream.SafeFileHandle -ExpectedPath $safeDestination `
            -Root $safeRoot -Directory $false `
            -RoleLabel "$RoleLabel destination" -RequireSingleLink
        if (-not (Test-PSOBBCombatCanaryNativeIdentityEqual `
                -Left $identity -Right $writtenIdentity) -or
            [uint64]$writtenIdentity.Length -ne [uint64]$Bytes.Length) {
            throw "The $RoleLabel destination changed while written"
        }
        $readback = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
            -LiteralPath $safeDestination -Root $safeRoot `
            -MaximumBytes ([Math]::Max(1, $Bytes.Length)) `
            -ExpectedLength $Bytes.Length -ExpectedSha256 $ExpectedSha256 `
            -RoleLabel "$RoleLabel destination readback" `
            -AllowWriteShare `
            -Consumer { param([byte[]]$ReadbackBytes) $ReadbackBytes.Length }
        [pscustomobject]@{
            Path = $safeDestination
            Length = [long]$readback.Length
            Sha256 = [string]$readback.Sha256
            VolumeSerialNumber = [uint32]$identity.VolumeSerialNumber
            FileId = [uint64]$identity.FileId
        }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $handle) { $handle.Dispose() }
        Close-PSOBBCombatCanaryDirectoryLeaseChain -Leases $parentLeases
    }
}

function Copy-PSOBBCombatCanaryBoundedFileSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][ValidateRange(1, 67108864)]
        [long]$MaximumBytes,
        [Parameter(Mandatory)][ValidateRange(1, 67108864)]
        [long]$ExpectedLength,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$RoleLabel,
        [Parameter(DontShow = $true)][scriptblock]$InternalTestAfterSourceLease
    )

    $sourceSnapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $Source -Root $SourceRoot -MaximumBytes $MaximumBytes `
        -ExpectedLength $ExpectedLength -ExpectedSha256 $ExpectedSha256 `
        -RoleLabel $RoleLabel `
        -InternalTestAfterIdentity $InternalTestAfterSourceLease `
        -Consumer {
            param([byte[]]$SourceBytes)
            Write-PSOBBCombatCanaryNoClobberBytes `
                -Destination $Destination -DestinationRoot $DestinationRoot `
                -Bytes $SourceBytes -ExpectedSha256 $ExpectedSha256 `
                -RoleLabel $RoleLabel
        }
    [pscustomobject]@{
        SourcePath = [string]$sourceSnapshot.Path
        SourceVolumeSerialNumber = [uint32]$sourceSnapshot.VolumeSerialNumber
        SourceFileId = [uint64]$sourceSnapshot.FileId
        DestinationPath = [string]$sourceSnapshot.Value.Path
        DestinationVolumeSerialNumber =
            [uint32]$sourceSnapshot.Value.VolumeSerialNumber
        DestinationFileId = [uint64]$sourceSnapshot.Value.FileId
        Length = [long]$sourceSnapshot.Length
        Sha256 = [string]$sourceSnapshot.Sha256
    }
}

$script:PSOBBCombatCanaryTransactionMarkerName =
    '.psobb-combat-canary-transaction.json'

function Get-PSOBBCombatCanaryOwnedPathIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$Directory,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $handle = $null
    try {
        $handle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $Path -Directory $Directory
        Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $handle -ExpectedPath $Path -Root $Root `
            -Directory $Directory -RoleLabel $RoleLabel `
            -RequireSingleLink:(-not $Directory)
    } finally {
        if ($null -ne $handle) { $handle.Dispose() }
    }
}

function Assert-PSOBBCombatCanaryTransactionMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Transaction,
        [Parameter(Mandatory)]
        [Newtonsoft.Json.Linq.JObject]$Marker
    )

    $properties = @($Marker.Properties())
    $expected = @('schemaVersion', 'transactionId', 'purpose',
        'rootVolumeSerialNumber', 'rootFileId')
    if ($properties.Count -ne $expected.Count -or
        @(Compare-Object -ReferenceObject @($expected | Sort-Object) `
            -DifferenceObject @($properties.Name | Sort-Object)).Count -ne 0) {
        throw 'The combat-canary transaction marker has an inexact shape'
    }
    $schemaVersion = $Marker['schemaVersion']
    $transactionId = $Marker['transactionId']
    $purpose = $Marker['purpose']
    $volume = $Marker['rootVolumeSerialNumber']
    $fileId = $Marker['rootFileId']
    if ($schemaVersion.Type -ne [Newtonsoft.Json.Linq.JTokenType]::Integer -or
        [System.Numerics.BigInteger]$schemaVersion.Value -ne 1 -or
        $transactionId.Type -ne [Newtonsoft.Json.Linq.JTokenType]::String -or
        [string]$transactionId.Value -cne [string]$Transaction.TransactionId -or
        $purpose.Type -ne [Newtonsoft.Json.Linq.JTokenType]::String -or
        [string]$purpose.Value -cne [string]$Transaction.Purpose -or
        $volume.Type -ne [Newtonsoft.Json.Linq.JTokenType]::Integer -or
        [uint64]$volume.Value -ne [uint32]$Transaction.VolumeSerialNumber -or
        $fileId.Type -ne [Newtonsoft.Json.Linq.JTokenType]::String -or
        [string]$fileId.Value -cne ('{0:x16}' -f
            [uint64]$Transaction.FileId)) {
        throw 'The combat-canary transaction marker is not identity-bound'
    }
    $true
}

function New-PSOBBCombatCanaryTransactionTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')]
        [string]$TransactionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9-]{2,63}$')]
        [string]$Purpose
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safePath = Assert-PathWithinRoot -Path $Path -Root $safeRoot
    $parent = Split-Path -Parent $safePath
    $parentLeases = @()
    $created = $false
    $identity = $null
    $markerBytes = $null
    $markerDigestBytes = $null
    try {
        $parentLeases = @(Open-PSOBBCombatCanaryDirectoryLeaseChain `
                -Path $parent -Root $safeRoot `
                -RoleLabel 'combat canary transaction tree')
        if (-not [PSOBBCombatCanary.NativeFiles]::CreateDirectoryW(
                $safePath, [IntPtr]::Zero)) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw [System.ComponentModel.Win32Exception]::new($errorCode)
        }
        $created = $true
        $identity = Get-PSOBBCombatCanaryOwnedPathIdentity `
            -Path $safePath -Root $safeRoot -Directory $true `
            -RoleLabel 'combat canary transaction tree'
        $marker = [ordered]@{
            schemaVersion = 1
            transactionId = $TransactionId
            purpose = $Purpose
            rootVolumeSerialNumber = [uint64]$identity.VolumeSerialNumber
            rootFileId = ('{0:x16}' -f [uint64]$identity.FileId)
        }
        $markerText = ($marker | ConvertTo-Json -Depth 3 -Compress) + "`n"
        $markerBytes = [System.Text.UTF8Encoding]::new(
            $false, $true).GetBytes($markerText)
        $markerDigestBytes =
            [System.Security.Cryptography.SHA256]::HashData($markerBytes)
        $markerSha256 = ([Convert]::ToHexString(
                $markerDigestBytes)).ToLowerInvariant()
        $markerPath = Join-Path $safePath `
            $script:PSOBBCombatCanaryTransactionMarkerName
        $markerPublication = Write-PSOBBCombatCanaryNoClobberBytes `
            -Destination $markerPath -DestinationRoot $safePath `
            -Bytes $markerBytes -ExpectedSha256 $markerSha256 `
            -RoleLabel 'combat canary transaction marker'
        [pscustomobject]@{
            Path = $safePath
            Root = $safeRoot
            TransactionId = $TransactionId
            Purpose = $Purpose
            VolumeSerialNumber = [uint32]$identity.VolumeSerialNumber
            FileId = [uint64]$identity.FileId
            MarkerPath = $markerPath
            MarkerLength = [long]$markerPublication.Length
            MarkerSha256 = $markerSha256
            MarkerVolumeSerialNumber =
                [uint32]$markerPublication.VolumeSerialNumber
            MarkerFileId = [uint64]$markerPublication.FileId
        }
        $created = $false
    } finally {
        if ($null -ne $markerDigestBytes) {
            [Array]::Clear(
                $markerDigestBytes, 0, $markerDigestBytes.Length)
        }
        if ($null -ne $markerBytes) {
            [Array]::Clear($markerBytes, 0, $markerBytes.Length)
        }
        Close-PSOBBCombatCanaryDirectoryLeaseChain -Leases $parentLeases
        if ($created -and $null -ne $identity) {
            try {
                Remove-PSOBBCombatCanaryOwnedTree `
                    -Path $safePath -Root $safeRoot `
                    -ExpectedVolumeSerialNumber $identity.VolumeSerialNumber `
                    -ExpectedFileId $identity.FileId `
                    -RoleLabel 'failed combat canary transaction tree'
            } catch {
                throw 'Combat-canary transaction-tree creation failed and retained evidence'
            }
        }
    }
}

function Remove-PSOBBCombatCanaryOwnedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][uint32]$ExpectedVolumeSerialNumber,
        [Parameter(Mandatory)][uint64]$ExpectedFileId,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $handle = $null
    try {
        $handle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $Path -Directory $false -Delete
        $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $handle -ExpectedPath $Path -Root $Root `
            -Directory $false -RoleLabel $RoleLabel -RequireSingleLink
        if ([uint32]$identity.VolumeSerialNumber -ne
                $ExpectedVolumeSerialNumber -or
            [uint64]$identity.FileId -ne $ExpectedFileId) {
            throw "The $RoleLabel identity mismatched; evidence was retained"
        }
        [PSOBBCombatCanary.NativeFiles]::MarkDelete($handle)
    } finally {
        if ($null -ne $handle) { $handle.Dispose() }
    }
    if (Test-Path -LiteralPath $Path) {
        throw "The $RoleLabel constrained deletion was incomplete"
    }
}

function Remove-PSOBBCombatCanaryOwnedTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][uint32]$ExpectedVolumeSerialNumber,
        [Parameter(Mandatory)][uint64]$ExpectedFileId,
        [Parameter(Mandatory)][string]$RoleLabel,
        [ValidateRange(1, 65536)]
        [int]$MaximumEntries = 4096,
        [ValidateRange(1, 4294967296)]
        [long]$MaximumAggregateBytes = 256MB,
        $Transaction
    )

    $safeRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $safeTree = Assert-PathWithinRoot -Path $Path -Root $safeRoot
    $directoryContexts = [System.Collections.Generic.List[object]]::new()
    $fileContexts = [System.Collections.Generic.List[object]]::new()
    $allHandles = [System.Collections.Generic.List[object]]::new()
    $markerSnapshot = $null
    try {
        $rootHandle = Open-PSOBBCombatCanaryNativePathHandle `
            -Path $safeTree -Directory $true -Delete
        $rootIdentity = Assert-PSOBBCombatCanaryNativeHandlePath `
            -Handle $rootHandle -ExpectedPath $safeTree -Root $safeRoot `
            -Directory $true -RoleLabel $RoleLabel
        if ([uint32]$rootIdentity.VolumeSerialNumber -ne
                $ExpectedVolumeSerialNumber -or
            [uint64]$rootIdentity.FileId -ne $ExpectedFileId) {
            $rootHandle.Dispose()
            throw "The $RoleLabel root identity mismatched; evidence was retained"
        }
        $rootContext = [pscustomobject]@{
            Path = $safeTree
            Handle = $rootHandle
            Identity = $rootIdentity
        }
        $directoryContexts.Add($rootContext)
        $allHandles.Add($rootHandle)

        if ($null -ne $Transaction) {
            $markerSnapshot = Read-PSOBBCombatCanaryStrictJsonObject `
                -LiteralPath $Transaction.MarkerPath -Root $safeTree `
                -MaximumBytes 4KB -ExpectedLength $Transaction.MarkerLength `
                -ExpectedSha256 $Transaction.MarkerSha256 -PassThruSnapshot `
                -RoleLabel 'combat canary transaction marker'
            [void](Assert-PSOBBCombatCanaryTransactionMarker `
                    -Transaction $Transaction -Marker $markerSnapshot.Value)
        }

        $pending = [System.Collections.Generic.Queue[string]]::new()
        $pending.Enqueue($safeTree)
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        [void]$seen.Add(('{0:x8}:{1:x16}' -f
                [uint32]$rootIdentity.VolumeSerialNumber,
                [uint64]$rootIdentity.FileId))
        $entries = 0
        $aggregate = [uint64]0
        while ($pending.Count -gt 0) {
            $directory = $pending.Dequeue()
            foreach ($child in @(Get-ChildItem -Force -LiteralPath $directory `
                        -ErrorAction Stop)) {
                $entries++
                if ($entries -gt $MaximumEntries) {
                    throw "The $RoleLabel cleanup inventory exceeds its count bound"
                }
                $childPath = Assert-PathWithinRoot `
                    -Path $child.FullName -Root $safeTree
                $isDirectory = [bool]$child.PSIsContainer
                $handle = Open-PSOBBCombatCanaryNativePathHandle `
                    -Path $childPath -Directory $isDirectory -Delete
                try {
                    $identity = Assert-PSOBBCombatCanaryNativeHandlePath `
                        -Handle $handle -ExpectedPath $childPath -Root $safeTree `
                        -Directory $isDirectory -RoleLabel $RoleLabel `
                        -RequireSingleLink:(-not $isDirectory)
                    $key = '{0:x8}:{1:x16}' -f
                        [uint32]$identity.VolumeSerialNumber,
                        [uint64]$identity.FileId
                    if (-not $seen.Add($key)) {
                        throw "The $RoleLabel cleanup inventory repeats an identity"
                    }
                    if (-not $isDirectory) {
                        if ([uint64]::MaxValue - $aggregate -lt
                            [uint64]$identity.Length) {
                            throw "The $RoleLabel cleanup aggregate overflowed"
                        }
                        $aggregate += [uint64]$identity.Length
                        if ($aggregate -gt [uint64]$MaximumAggregateBytes) {
                            throw "The $RoleLabel cleanup aggregate exceeds its bound"
                        }
                    }
                    $context = [pscustomobject]@{
                        Path = $childPath
                        Handle = $handle
                        Identity = $identity
                    }
                    if ($isDirectory) {
                        $directoryContexts.Add($context)
                        $pending.Enqueue($childPath)
                    } else {
                        $fileContexts.Add($context)
                    }
                    $allHandles.Add($handle)
                    $handle = $null
                } finally {
                    if ($null -ne $handle) { $handle.Dispose() }
                }
            }
        }
        if ($null -ne $Transaction) {
            $markerContexts = @($fileContexts | Where-Object {
                    [string]$_.Path -ieq [string]$Transaction.MarkerPath
                })
            if ($markerContexts.Count -ne 1 -or
                [uint32]$markerContexts[0].Identity.VolumeSerialNumber -ne
                    [uint32]$Transaction.MarkerVolumeSerialNumber -or
                [uint64]$markerContexts[0].Identity.FileId -ne
                    [uint64]$Transaction.MarkerFileId -or
                [uint32]$markerSnapshot.VolumeSerialNumber -ne
                    [uint32]$Transaction.MarkerVolumeSerialNumber -or
                [uint64]$markerSnapshot.FileId -ne
                    [uint64]$Transaction.MarkerFileId) {
                throw "The $RoleLabel transaction marker identity changed; evidence was retained"
            }
        }

        foreach ($file in @($fileContexts | Sort-Object { $_.Path.Length } `
                    -Descending)) {
            [PSOBBCombatCanary.NativeFiles]::MarkDelete($file.Handle)
            $file.Handle.Dispose()
        }
        foreach ($directory in @($directoryContexts | Sort-Object {
                    $_.Path.Length } -Descending)) {
            [PSOBBCombatCanary.NativeFiles]::MarkDelete($directory.Handle)
            $directory.Handle.Dispose()
        }
    } finally {
        foreach ($handle in $allHandles) {
            if ($null -ne $handle) { $handle.Dispose() }
        }
    }
    if (Test-Path -LiteralPath $safeTree) {
        throw "The $RoleLabel constrained deletion was incomplete"
    }
}

function Get-PSOBBCombatCanaryTransactionCleanupPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z][a-z0-9-]{2,63}$')]
        [string]$Purpose
    )

    if ($Purpose -in @('initialize-stage', 'initialize-rollback')) {
        return [pscustomobject]@{
            MaximumEntries = 16384
            MaximumAggregateBytes = [long]1GB
        }
    }
    [pscustomobject]@{
        MaximumEntries = 4096
        MaximumAggregateBytes = [long]256MB
    }
}

function Remove-PSOBBCombatCanaryTransactionTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Transaction,
        [Parameter(Mandatory)][string]$RoleLabel
    )

    $policy = Get-PSOBBCombatCanaryTransactionCleanupPolicy `
        -Purpose ([string]$Transaction.Purpose)
    Remove-PSOBBCombatCanaryOwnedTree `
        -Path $Transaction.Path -Root $Transaction.Root `
        -ExpectedVolumeSerialNumber $Transaction.VolumeSerialNumber `
        -ExpectedFileId $Transaction.FileId -RoleLabel $RoleLabel `
        -MaximumEntries ([int]$policy.MaximumEntries) `
        -MaximumAggregateBytes ([long]$policy.MaximumAggregateBytes) `
        -Transaction $Transaction
}

function Remove-PSOBBCombatCanaryTransactionMarker {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Transaction)

    $snapshot = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $Transaction.MarkerPath -Root $Transaction.Path `
        -MaximumBytes 4KB -ExpectedLength $Transaction.MarkerLength `
        -ExpectedSha256 $Transaction.MarkerSha256 -PassThruSnapshot `
        -RoleLabel 'combat canary transaction marker removal'
    [void](Assert-PSOBBCombatCanaryTransactionMarker `
            -Transaction $Transaction -Marker $snapshot.Value)
    if ([uint32]$snapshot.VolumeSerialNumber -ne
            [uint32]$Transaction.MarkerVolumeSerialNumber -or
        [uint64]$snapshot.FileId -ne [uint64]$Transaction.MarkerFileId) {
        throw 'The combat-canary transaction marker identity changed'
    }
    Remove-PSOBBCombatCanaryOwnedFile `
        -Path $Transaction.MarkerPath -Root $Transaction.Path `
        -ExpectedVolumeSerialNumber $Transaction.MarkerVolumeSerialNumber `
        -ExpectedFileId $Transaction.MarkerFileId `
        -RoleLabel 'combat canary transaction marker'
}

function Read-PSOBBCombatCanaryStrictUtf8Text {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath,

        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [ValidateRange(1, 67108864)]
        [long]$MaximumBytes,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel,

        [ValidatePattern('^$|^[a-f0-9]{64}$')]
        [string]$ExpectedSha256 = '',

        [ValidateRange(-1, 67108864)]
        [long]$ExpectedLength = -1,

        [switch]$PassThruSnapshot,

        [Parameter(DontShow = $true)]
        [scriptblock]$InternalTestAfterInitialValidation,

        [Parameter(DontShow = $true)]
        [scriptblock]$InternalTestAfterIdentity
    )

    $snapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $LiteralPath -Root $Root -MaximumBytes $MaximumBytes `
        -RoleLabel $RoleLabel -ExpectedSha256 $ExpectedSha256 `
        -ExpectedLength $ExpectedLength `
        -InternalTestAfterInitialValidation $InternalTestAfterInitialValidation `
        -InternalTestAfterIdentity $InternalTestAfterIdentity `
        -Consumer {
            param([byte[]]$Bytes)
            try {
                if ($Bytes.Length -ge 3 -and
                    $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and
                    $Bytes[2] -eq 0xBF) {
                    throw 'UTF-8 BOM is not permitted'
                }
                [System.Text.UTF8Encoding]::new(
                    $false, $true).GetString($Bytes)
            } catch {
                throw "The $RoleLabel is not a valid UTF-8 document"
            }
        }
    if ($PassThruSnapshot) {
        return $snapshot
    }
    [string]$snapshot.Value
}

function Get-PSOBBCombatCanaryJsonResourcePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RoleLabel)

    if ($RoleLabel -ceq 'Stable server base manifest') {
        return [pscustomobject]@{
            MaximumCharacters = 4MB
            MaximumTokens = 262144
            MaximumProperties = 65536
            MaximumItems = 65536
            MaximumDepth = 32
            MaximumNormalizedWork = 16MB
        }
    }
    if ($RoleLabel -match '(?i)license|credential') {
        return [pscustomobject]@{
            MaximumCharacters = 256KB
            MaximumTokens = 16384
            MaximumProperties = 4096
            MaximumItems = 4096
            MaximumDepth = 24
            MaximumNormalizedWork = 1MB
        }
    }
    if ($RoleLabel -match '(?i)snapshot manifest|binding|marker|profile|contract|policy|trust') {
        return [pscustomobject]@{
            MaximumCharacters = 512KB
            MaximumTokens = 32768
            MaximumProperties = 8192
            MaximumItems = 8192
            MaximumDepth = 32
            MaximumNormalizedWork = 2MB
        }
    }
    if ($RoleLabel -match '(?i)configuration|release manifest|base client manifest|source lock') {
        return [pscustomobject]@{
            MaximumCharacters = 4MB
            MaximumTokens = 131072
            MaximumProperties = 32768
            MaximumItems = 65536
            MaximumDepth = 32
            MaximumNormalizedWork = 8MB
        }
    }
    [pscustomobject]@{
        MaximumCharacters = 1MB
        MaximumTokens = 65536
        MaximumProperties = 16384
        MaximumItems = 32768
        MaximumDepth = 32
        MaximumNormalizedWork = 4MB
    }
}

function Add-PSOBBCombatCanaryJsonTokenBudget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Budget,
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][ValidateRange(0, 67108864)]
        [int]$NormalizedCharacters
    )

    if ([int]$Budget.Tokens -ge [int]$Policy.MaximumTokens -or
        [int64]$Budget.TokenNormalizedCharacters + $NormalizedCharacters -gt
            [int64]$Policy.MaximumNormalizedWork) {
        throw 'The JSON token or normalized-output budget was exceeded'
    }
    $Budget.Tokens = [int]$Budget.Tokens + 1
    $Budget.TokenNormalizedCharacters =
        [int64]$Budget.TokenNormalizedCharacters + $NormalizedCharacters
}

function Add-PSOBBCombatCanaryJsonPropertyBudget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Budget,
        [Parameter(Mandatory)]$Policy
    )

    if ([int]$Budget.Properties -ge [int]$Policy.MaximumProperties) {
        throw 'The JSON property budget was exceeded'
    }
    $Budget.Properties = [int]$Budget.Properties + 1
}

function Add-PSOBBCombatCanaryJsonItemBudget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Budget,
        [Parameter(Mandatory)]$Policy
    )

    if ([int]$Budget.Items -ge [int]$Policy.MaximumItems) {
        throw 'The JSON array-item budget was exceeded'
    }
    $Budget.Items = [int]$Budget.Items + 1
}

function Add-PSOBBCombatCanaryJsonNormalizedWork {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Budget,
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][ValidateRange(0, 67108864)]
        [int]$Characters
    )

    if ([int64]$Budget.NormalizedWork + $Characters -gt
        [int64]$Policy.MaximumNormalizedWork) {
        throw 'The JSON normalized-output work budget was exceeded'
    }
    $Budget.NormalizedWork = [int64]$Budget.NormalizedWork + $Characters
}

function Get-PSOBBCombatCanaryPhosgJsonTokens {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory)]$Policy,

        [Parameter(Mandatory)]$Budget
    )

    $tokens = [System.Collections.Generic.List[object]]::new()
    $index = 0
    while ($index -lt $Text.Length) {
        $character = $Text[$index]
        if ($character -eq ' ' -or $character -eq "`t" -or
            $character -eq "`r" -or $character -eq "`n") {
            $index++
            continue
        }
        if ($character -eq '/') {
            if ($index + 1 -ge $Text.Length -or $Text[$index + 1] -ne '/') {
                throw 'Unsupported JSON comment syntax'
            }
            $index += 2
            while ($index -lt $Text.Length -and $Text[$index] -ne "`r" -and
                $Text[$index] -ne "`n") {
                $index++
            }
            continue
        }
        if ($character -eq "'") {
            throw 'Single-quoted JSON is unsupported'
        }
        $punctuationKind = switch ($character) {
            '{' { 'LeftBrace' }
            '}' { 'RightBrace' }
            '[' { 'LeftBracket' }
            ']' { 'RightBracket' }
            ':' { 'Colon' }
            ',' { 'Comma' }
            default { $null }
        }
        if ($null -ne $punctuationKind) {
            Add-PSOBBCombatCanaryJsonTokenBudget `
                -Budget $Budget -Policy $Policy -NormalizedCharacters 1
            $tokens.Add([pscustomobject]@{
                    Kind = $punctuationKind
                    Raw = [string]$character
                    Decoded = $null
                    Normalized = [string]$character
                })
            $index++
            continue
        }
        if ($character -eq '"') {
            $start = $index
            $index++
            $closed = $false
            while ($index -lt $Text.Length) {
                $stringCharacter = $Text[$index]
                if ([int]$stringCharacter -lt 0x20) {
                    throw 'Unescaped control character in JSON string'
                }
                if ($stringCharacter -eq '"') {
                    $index++
                    $closed = $true
                    break
                }
                if ($stringCharacter -eq '\') {
                    $index++
                    if ($index -ge $Text.Length) {
                        throw 'Incomplete JSON string escape'
                    }
                    $escapeCharacter = $Text[$index]
                    if ('"\/bfnrt'.IndexOf($escapeCharacter) -lt 0) {
                        if ($escapeCharacter -ne 'u') {
                            throw 'Unsupported JSON string escape'
                        }
                        if ($index + 4 -ge $Text.Length) {
                            throw 'Incomplete JSON unicode escape'
                        }
                        $unicodeByte = 0
                        for ($offset = 1; $offset -le 4; $offset++) {
                            $digit = $Text[$index + $offset]
                            $nibble = if ($digit -ge '0' -and $digit -le '9') {
                                [int]$digit - [int][char]'0'
                            } elseif ($digit -ge 'a' -and $digit -le 'f') {
                                10 + [int]$digit - [int][char]'a'
                            } elseif ($digit -ge 'A' -and $digit -le 'F') {
                                10 + [int]$digit - [int][char]'A'
                            } else {
                                throw 'Invalid JSON unicode escape'
                            }
                            $unicodeByte = ($unicodeByte -shl 4) -bor $nibble
                        }
                        if ($unicodeByte -gt 0xFF) {
                            throw 'JSON unicode escape is not one phosg byte'
                        }
                        $index += 4
                    }
                } elseif ([char]::IsHighSurrogate($stringCharacter)) {
                    if ($index + 1 -ge $Text.Length -or
                        -not [char]::IsLowSurrogate($Text[$index + 1])) {
                        throw 'Unpaired surrogate in JSON string'
                    }
                    $index++
                } elseif ([char]::IsLowSurrogate($stringCharacter)) {
                    throw 'Unpaired surrogate in JSON string'
                }
                $index++
            }
            if (-not $closed) { throw 'Unterminated JSON string' }
            $rawLength = $index - $start
            Add-PSOBBCombatCanaryJsonTokenBudget `
                -Budget $Budget -Policy $Policy `
                -NormalizedCharacters $rawLength
            $raw = $Text.Substring($start, $rawLength)
            $tokens.Add([pscustomobject]@{
                    Kind = 'String'
                    Raw = $raw
                    Decoded = $null
                    Normalized = $raw
                })
            continue
        }
        if ($character -eq '-' -or [char]::IsDigit($character)) {
            $start = $index
            $negative = $false
            if ($character -eq '-') {
                $negative = $true
                $index++
                if ($index -ge $Text.Length -or
                    -not [char]::IsDigit($Text[$index])) {
                    throw 'Invalid JSON number'
                }
            }
            if ($Text[$index] -eq '0' -and $index + 1 -lt $Text.Length -and
                $Text[$index + 1] -ceq 'x') {
                $index += 2
                $hexStart = $index
                while ($index -lt $Text.Length -and
                    '0123456789abcdefABCDEF'.IndexOf($Text[$index]) -ge 0) {
                    $index++
                }
                if ($index -eq $hexStart) { throw 'Invalid hexadecimal JSON integer' }
                $hexDigitCount = $index - $hexStart
                $maximumNormalizedCharacters = [int][Math]::Ceiling(
                    $hexDigitCount * [Math]::Log10(16.0))
                if ($negative) { $maximumNormalizedCharacters++ }
                Add-PSOBBCombatCanaryJsonTokenBudget `
                    -Budget $Budget -Policy $Policy `
                    -NormalizedCharacters $maximumNormalizedCharacters
                $hexDigits = $Text.Substring($hexStart, $hexDigitCount)
                try {
                    $integer = [System.Numerics.BigInteger]::Parse(
                        '0' + $hexDigits,
                        [System.Globalization.NumberStyles]::AllowHexSpecifier,
                        [System.Globalization.CultureInfo]::InvariantCulture)
                } catch {
                    throw 'Invalid hexadecimal JSON integer'
                }
                if ($negative) { $integer = -$integer }
                $normalizedInteger = $integer.ToString(
                    [System.Globalization.CultureInfo]::InvariantCulture)
                $tokens.Add([pscustomobject]@{
                        Kind = 'Number'
                        Raw = $Text.Substring($start, $index - $start)
                        Decoded = $integer
                        Normalized = $normalizedInteger
                    })
                continue
            }
            if ($Text[$index] -eq '0') {
                $index++
                if ($index -lt $Text.Length -and
                    [char]::IsDigit($Text[$index])) {
                    throw 'Invalid leading zero in JSON number'
                }
            } else {
                while ($index -lt $Text.Length -and
                    [char]::IsDigit($Text[$index])) {
                    $index++
                }
            }
            if ($index -lt $Text.Length -and $Text[$index] -eq '.') {
                $index++
                $fractionStart = $index
                while ($index -lt $Text.Length -and
                    [char]::IsDigit($Text[$index])) {
                    $index++
                }
                if ($index -eq $fractionStart) { throw 'Invalid JSON fraction' }
            }
            if ($index -lt $Text.Length -and
                ($Text[$index] -eq 'e' -or $Text[$index] -eq 'E')) {
                $index++
                if ($index -lt $Text.Length -and
                    ($Text[$index] -eq '+' -or $Text[$index] -eq '-')) {
                    $index++
                }
                $exponentStart = $index
                while ($index -lt $Text.Length -and
                    [char]::IsDigit($Text[$index])) {
                    $index++
                }
                if ($index -eq $exponentStart) { throw 'Invalid JSON exponent' }
            }
            $rawLength = $index - $start
            Add-PSOBBCombatCanaryJsonTokenBudget `
                -Budget $Budget -Policy $Policy `
                -NormalizedCharacters $rawLength
            $raw = $Text.Substring($start, $rawLength)
            $tokens.Add([pscustomobject]@{
                    Kind = 'Number'
                    Raw = $raw
                    Decoded = $null
                    Normalized = $raw
                })
            continue
        }
        $literal = $null
        foreach ($candidate in @('true', 'false', 'null')) {
            if ($index + $candidate.Length -le $Text.Length -and
                $Text.Substring($index, $candidate.Length) -ceq $candidate) {
                $literal = $candidate
                break
            }
        }
        if ($null -ne $literal) {
            $kind = if ($literal -ceq 'null') { 'Null' } else { 'Boolean' }
            Add-PSOBBCombatCanaryJsonTokenBudget `
                -Budget $Budget -Policy $Policy `
                -NormalizedCharacters $literal.Length
            $tokens.Add([pscustomobject]@{
                    Kind = $kind
                    Raw = $literal
                    Decoded = $null
                    Normalized = $literal
                })
            $index += $literal.Length
            continue
        }
        throw 'Unsupported JSON token'
    }
    $tokens.ToArray()
}

function Read-PSOBBCombatCanaryPhosgJsonValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Tokens,

        [Parameter(Mandatory)]
        [ref]$Index,

        [Parameter(Mandatory)]
        [int]$Depth,

        [Parameter(Mandatory)]$Policy,

        [Parameter(Mandatory)]$Budget
    )

    if ($Depth -gt [int]$Policy.MaximumDepth -or
        $Index.Value -ge $Tokens.Count) {
        throw 'Invalid JSON nesting or missing value'
    }
    $token = $Tokens[$Index.Value]
    if ($token.Kind -in @('String', 'Number', 'Boolean', 'Null')) {
        $Index.Value++
        return [pscustomobject]@{
            Kind = [string]$token.Kind
            Raw = [string]$token.Raw
            Decoded = $token.Decoded
            Normalized = [string]$token.Normalized
            Properties = $null
            Items = $null
        }
    }
    if ($token.Kind -ceq 'LeftBrace') {
        $Index.Value++
        $objectLength = 2
        Add-PSOBBCombatCanaryJsonNormalizedWork `
            -Budget $Budget -Policy $Policy -Characters $objectLength
        $properties = [System.Collections.Generic.List[object]]::new()
        $normalizedProperties = [System.Collections.Generic.List[string]]::new()
        $keyIdentities = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal)
        if ($Index.Value -lt $Tokens.Count -and
            $Tokens[$Index.Value].Kind -ceq 'RightBrace') {
            $Index.Value++
        } else {
            while ($true) {
                if ($Index.Value -ge $Tokens.Count -or
                    $Tokens[$Index.Value].Kind -cne 'String') {
                    throw 'JSON object key is not a double-quoted string'
                }
                $key = $Tokens[$Index.Value]
                $Index.Value++
                Add-PSOBBCombatCanaryJsonPropertyBudget `
                    -Budget $Budget -Policy $Policy
                $keyInfo = $null
                if (-not $Budget.KeyCache.TryGetValue(
                        [string]$key.Raw, [ref]$keyInfo)) {
                    $keyBytes = $null
                    try {
                        $keyBytes = [byte[]](
                            ConvertFrom-PSOBBCombatCanaryPhosgStringBytes `
                                -RawToken ([string]$key.Raw))
                        $normalizedKeyBuilder =
                            [System.Text.StringBuilder]::new(
                                2 + (6 * $keyBytes.Length))
                        [void]$normalizedKeyBuilder.Append('"')
                        foreach ($keyByte in $keyBytes) {
                            [void]$normalizedKeyBuilder.Append(
                                '\u00' + $keyByte.ToString('X2',
                                    [System.Globalization.CultureInfo]::InvariantCulture))
                        }
                        [void]$normalizedKeyBuilder.Append('"')
                        $keyInfo = [pscustomobject]@{
                            Identity = [Convert]::ToHexString($keyBytes)
                            Normalized = $normalizedKeyBuilder.ToString()
                            Name = [System.Text.Encoding]::Latin1.GetString(
                                $keyBytes)
                        }
                    } finally {
                        if ($null -ne $keyBytes) {
                            [Array]::Clear($keyBytes, 0, $keyBytes.Length)
                        }
                    }
                    $Budget.KeyCache.Add([string]$key.Raw, $keyInfo)
                }
                $normalizedKey = [string]$keyInfo.Normalized
                $normalizedKeyLength = $normalizedKey.Length
                Add-PSOBBCombatCanaryJsonNormalizedWork `
                    -Budget $Budget -Policy $Policy `
                    -Characters $normalizedKeyLength
                $keyIdentity = [string]$keyInfo.Identity
                if (-not $keyIdentities.Add($keyIdentity)) {
                    throw 'Duplicate phosg byte object key'
                }
                $phosgName = [string]$keyInfo.Name
                if ($Index.Value -ge $Tokens.Count -or
                    $Tokens[$Index.Value].Kind -cne 'Colon') {
                    throw 'JSON object property is missing a colon'
                }
                $Index.Value++
                $value = Read-PSOBBCombatCanaryPhosgJsonValue `
                    -Tokens $Tokens -Index $Index -Depth ($Depth + 1) `
                    -Policy $Policy -Budget $Budget
                $propertyLength = $normalizedKey.Length + 1 +
                    ([string]$value.Normalized).Length
                if ($normalizedProperties.Count -gt 0) { $propertyLength++ }
                if ($objectLength + $propertyLength -gt
                    [int]$Policy.MaximumNormalizedWork) {
                    throw 'The JSON object normalized output exceeded its bound'
                }
                Add-PSOBBCombatCanaryJsonNormalizedWork `
                    -Budget $Budget -Policy $Policy `
                    -Characters $propertyLength
                $objectLength += $propertyLength
                $properties.Add([pscustomobject]@{
                        Name = $phosgName
                        RawName = [string]$key.Raw
                        Value = $value
                    })
                $normalizedProperties.Add([string]::Concat(
                        $normalizedKey, ':', [string]$value.Normalized))
                if ($Index.Value -ge $Tokens.Count) {
                    throw 'Unterminated JSON object'
                }
                if ($Tokens[$Index.Value].Kind -ceq 'RightBrace') {
                    $Index.Value++
                    break
                }
                if ($Tokens[$Index.Value].Kind -cne 'Comma') {
                    throw 'JSON object is missing a comma'
                }
                $Index.Value++
                if ($Index.Value -lt $Tokens.Count -and
                    $Tokens[$Index.Value].Kind -ceq 'RightBrace') {
                    $Index.Value++
                    break
                }
            }
        }
        $objectBuilder = [System.Text.StringBuilder]::new($objectLength)
        [void]$objectBuilder.Append('{')
        for ($propertyIndex = 0;
            $propertyIndex -lt $normalizedProperties.Count;
            $propertyIndex++) {
            if ($propertyIndex -gt 0) { [void]$objectBuilder.Append(',') }
            [void]$objectBuilder.Append($normalizedProperties[$propertyIndex])
        }
        [void]$objectBuilder.Append('}')
        return [pscustomobject]@{
            Kind = 'Object'
            Raw = $null
            Decoded = $null
            Normalized = $objectBuilder.ToString()
            Properties = $properties.ToArray()
            Items = $null
        }
    }
    if ($token.Kind -ceq 'LeftBracket') {
        $Index.Value++
        $arrayLength = 2
        Add-PSOBBCombatCanaryJsonNormalizedWork `
            -Budget $Budget -Policy $Policy -Characters $arrayLength
        $items = [System.Collections.Generic.List[object]]::new()
        $normalizedItems = [System.Collections.Generic.List[string]]::new()
        if ($Index.Value -lt $Tokens.Count -and
            $Tokens[$Index.Value].Kind -ceq 'RightBracket') {
            $Index.Value++
        } else {
            while ($true) {
                Add-PSOBBCombatCanaryJsonItemBudget `
                    -Budget $Budget -Policy $Policy
                $value = Read-PSOBBCombatCanaryPhosgJsonValue `
                    -Tokens $Tokens -Index $Index -Depth ($Depth + 1) `
                    -Policy $Policy -Budget $Budget
                $itemLength = ([string]$value.Normalized).Length
                if ($normalizedItems.Count -gt 0) { $itemLength++ }
                if ($arrayLength + $itemLength -gt
                    [int]$Policy.MaximumNormalizedWork) {
                    throw 'The JSON array normalized output exceeded its bound'
                }
                Add-PSOBBCombatCanaryJsonNormalizedWork `
                    -Budget $Budget -Policy $Policy -Characters $itemLength
                $arrayLength += $itemLength
                $items.Add($value)
                $normalizedItems.Add([string]$value.Normalized)
                if ($Index.Value -ge $Tokens.Count) {
                    throw 'Unterminated JSON array'
                }
                if ($Tokens[$Index.Value].Kind -ceq 'RightBracket') {
                    $Index.Value++
                    break
                }
                if ($Tokens[$Index.Value].Kind -cne 'Comma') {
                    throw 'JSON array is missing a comma'
                }
                $Index.Value++
                if ($Index.Value -lt $Tokens.Count -and
                    $Tokens[$Index.Value].Kind -ceq 'RightBracket') {
                    $Index.Value++
                    break
                }
            }
        }
        $arrayBuilder = [System.Text.StringBuilder]::new($arrayLength)
        [void]$arrayBuilder.Append('[')
        for ($itemIndex = 0;
            $itemIndex -lt $normalizedItems.Count;
            $itemIndex++) {
            if ($itemIndex -gt 0) { [void]$arrayBuilder.Append(',') }
            [void]$arrayBuilder.Append($normalizedItems[$itemIndex])
        }
        [void]$arrayBuilder.Append(']')
        return [pscustomobject]@{
            Kind = 'Array'
            Raw = $null
            Decoded = $null
            Normalized = $arrayBuilder.ToString()
            Properties = $null
            Items = $items.ToArray()
        }
    }
    throw 'Unsupported JSON value'
}

function ConvertTo-PSOBBCombatCanaryPhosgJsonPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$RoleLabel
    )

    $policy = Get-PSOBBCombatCanaryJsonResourcePolicy -RoleLabel $RoleLabel
    if ($Text.Length -le 0 -or
        $Text.Length -gt [int]$policy.MaximumCharacters -or
        ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF)) {
        throw 'The JSON character budget or encoding preamble policy was exceeded'
    }
    $budget = [pscustomobject]@{
        Tokens = 0
        TokenNormalizedCharacters = [int64]0
        Properties = 0
        Items = 0
        NormalizedWork = [int64]0
        KeyCache = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::Ordinal)
    }
    $tokens = @(Get-PSOBBCombatCanaryPhosgJsonTokens `
            -Text $Text -Policy $policy -Budget $budget)
    $index = 0
    $root = Read-PSOBBCombatCanaryPhosgJsonValue `
        -Tokens $tokens -Index ([ref]$index) -Depth 0 `
        -Policy $policy -Budget $budget
    if ($index -ne $tokens.Count) { throw 'Extra top-level JSON content' }
    if (([string]$root.Normalized).Length -gt
        [int]$policy.MaximumNormalizedWork) {
        throw 'The JSON normalized root exceeded its exact bound'
    }
    [pscustomobject]@{
        NormalizedText = [string]$root.Normalized
        Root = $root
        ResourceUsage = [pscustomobject]@{
            Characters = $Text.Length
            Tokens = [int]$budget.Tokens
            Properties = [int]$budget.Properties
            Items = [int]$budget.Items
            NormalizedWork = [int64]$budget.NormalizedWork
        }
    }
}

function ConvertFrom-PSOBBCombatCanaryStrictJsonText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel
    )

    $stringReader = $null
    $jsonReader = $null
    try {
        $preflight = ConvertTo-PSOBBCombatCanaryPhosgJsonPreflight `
            -Text $Text -RoleLabel $RoleLabel
        $stringReader = [System.IO.StringReader]::new($preflight.NormalizedText)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($stringReader)
        $jsonReader.SupportMultipleContent = $false
        $jsonReader.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
        $jsonReader.FloatParseHandling = [Newtonsoft.Json.FloatParseHandling]::Decimal
        $jsonReader.MaxDepth = 100
        $settings = [Newtonsoft.Json.Linq.JsonLoadSettings]::new()
        $settings.DuplicatePropertyNameHandling =
            [Newtonsoft.Json.Linq.DuplicatePropertyNameHandling]::Error
        $result = [Newtonsoft.Json.Linq.JObject]::Load($jsonReader, $settings)
        while ($jsonReader.Read()) {
            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::Comment) {
                throw 'Trailing JSON content'
            }
        }
        Write-Output -NoEnumerate $result
    } catch {
        throw "The $RoleLabel is not a valid strict JSON object"
    } finally {
        if ($null -ne $jsonReader) { $jsonReader.Close() }
        if ($null -ne $stringReader) { $stringReader.Dispose() }
    }
}

function Read-PSOBBCombatCanaryStrictJsonObject {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$LiteralPath,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Root,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateRange(1, 67108864)]
        [long]$MaximumBytes,

        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel,

        [Parameter(ParameterSetName = 'Path')]
        [ValidatePattern('^$|^[a-f0-9]{64}$')]
        [string]$ExpectedSha256 = '',

        [Parameter(ParameterSetName = 'Path')]
        [ValidateRange(-1, 67108864)]
        [long]$ExpectedLength = -1,

        [Parameter(ParameterSetName = 'Path')]
        [switch]$PassThruSnapshot,

        [Parameter(ParameterSetName = 'Path')]
        [switch]$RequireProtectedAcl,

        [Parameter(DontShow = $true, ParameterSetName = 'Path')]
        [scriptblock]$InternalTestAfterInitialValidation,

        [Parameter(DontShow = $true, ParameterSetName = 'Path')]
        [scriptblock]$InternalTestAfterIdentity
    )

    if ($PSCmdlet.ParameterSetName -ceq 'Text') {
        return ConvertFrom-PSOBBCombatCanaryStrictJsonText `
            -Text $Text -RoleLabel $RoleLabel
    }

    $snapshot = Invoke-PSOBBCombatCanaryBoundedFileSnapshot `
        -LiteralPath $LiteralPath -Root $Root -MaximumBytes $MaximumBytes `
        -RoleLabel $RoleLabel -ExpectedSha256 $ExpectedSha256 `
        -ExpectedLength $ExpectedLength `
        -RequireProtectedAcl:$RequireProtectedAcl `
        -InternalTestAfterInitialValidation $InternalTestAfterInitialValidation `
        -InternalTestAfterIdentity $InternalTestAfterIdentity `
        -Consumer {
            param([byte[]]$Bytes)
            $strictText = $null
            try {
                if ($Bytes.Length -ge 3 -and
                    $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and
                    $Bytes[2] -eq 0xBF) {
                    throw 'UTF-8 BOM is not permitted'
                }
                $strictText = [System.Text.UTF8Encoding]::new(
                    $false, $true).GetString($Bytes)
            } catch {
                throw "The $RoleLabel is not a valid UTF-8 document"
            }
            ConvertFrom-PSOBBCombatCanaryStrictJsonText `
                -Text $strictText -RoleLabel $RoleLabel
        }
    if ($PassThruSnapshot) {
        return $snapshot
    }
    Write-Output -NoEnumerate $snapshot.Value
}

function ConvertTo-PSOBBCombatCanaryPowerShellObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Newtonsoft.Json.Linq.JObject]$JsonObject,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel
    )

    try {
        $JsonObject.ToString([Newtonsoft.Json.Formatting]::None) |
            ConvertFrom-Json -Depth 100 -DateKind String
    } catch {
        throw "The $RoleLabel could not be materialized from strict JSON"
    }
}

function Assert-PSOBBCombatCanaryExactProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel
    )

    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw "The $RoleLabel does not have the exact combat-canary schema"
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $expectedSorted = @($Expected | Sort-Object -CaseSensitive)
    if ($actual.Count -ne $expectedSorted.Count -or
        @(Compare-Object -ReferenceObject $expectedSorted `
                -DifferenceObject $actual -CaseSensitive).Count -ne 0) {
        throw "The $RoleLabel does not have the exact combat-canary schema"
    }
    $true
}

function Assert-PSOBBCombatCanaryBuildContractShape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Build
    )

    $invalid = 'The combat-canary build contract does not have the exact combat-canary schema'
    try {
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Build `
                -RoleLabel 'combat-canary build contract' `
                -Expected @('$schema', 'schemaVersion', 'profileId',
                    'generatedAtUtc', 'source', 'patchSeries', 'dependencies',
                    'signatureVerification', 'toolchain', 'reproducibility',
                    'validation', 'output'))
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Build.source `
                -RoleLabel 'combat-canary build source' `
                -Expected @('componentId', 'commit', 'revision'))
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Build.patchSeries `
                -RoleLabel 'combat-canary build patch series' `
                -Expected @('path', 'sha256'))
        if ($Build.dependencies -isnot [System.Array] -or
            @($Build.dependencies).Count -ne 5) {
            throw $invalid
        }
        foreach ($dependency in @($Build.dependencies)) {
            [void](Assert-PSOBBCombatCanaryExactProperties -Value $dependency `
                    -RoleLabel 'combat-canary build dependency' `
                    -Expected @('id', 'kind', 'source', 'size', 'sha256',
                        'signature', 'commit'))
            if ($null -ne $dependency.signature) {
                [void](Assert-PSOBBCombatCanaryExactProperties `
                        -Value $dependency.signature `
                        -RoleLabel 'combat-canary dependency signature' `
                        -Expected @('path', 'size', 'sha256',
                            'signerFingerprint'))
            }
        }
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Build.signatureVerification `
                -RoleLabel 'combat-canary signature verification' `
                -Expected @('toolId', 'keyring'))
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Build.signatureVerification.keyring `
                -RoleLabel 'combat-canary signature keyring' `
                -Expected @('source', 'size', 'sha256', 'readOnly'))
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Build.toolchain `
                -RoleLabel 'combat-canary build toolchain' `
                -Expected @('target', 'generator', 'buildType', 'staticRuntime',
                    'nativeExecutionManifest', 'tools'))
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Build.toolchain.nativeExecutionManifest `
                -RoleLabel 'combat-canary native execution manifest' `
                -Expected @('path', 'size', 'sha256', 'schemaPath',
                    'schemaSize', 'schemaSha256'))
        $expectedToolIds = @(
            'cmd',
            'gcc',
            'g++',
            'objdump',
            'cmake',
            'ctest',
            'ninja',
            'mingw32-make',
            'git',
            'gpgv',
            'tar',
            'bash',
            'sh',
            'subst'
        )
        if ($Build.toolchain.tools -isnot [System.Array] -or
            @($Build.toolchain.tools).Count -ne $expectedToolIds.Count) {
            throw $invalid
        }
        for ($toolIndex = 0; $toolIndex -lt $expectedToolIds.Count; $toolIndex++) {
            $tool = @($Build.toolchain.tools)[$toolIndex]
            [void](Assert-PSOBBCombatCanaryExactProperties -Value $tool `
                    -RoleLabel 'combat-canary build tool' `
                    -Expected @('id', 'command', 'pathRoot', 'relativePath',
                        'versionMode', 'versionArguments', 'version',
                        'executableSize', 'sha256'))
            if ([string]$tool.id -cne $expectedToolIds[$toolIndex] -or
                $tool.versionArguments -isnot [System.Array]) {
                throw $invalid
            }
        }
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Build.reproducibility `
                -RoleLabel 'combat-canary build reproducibility' `
                -Expected @('sourceDateEpoch', 'cleanBuildCount',
                    'pathNormalization', 'linkerFlags', 'builds'))
        if ($Build.reproducibility.pathNormalization -isnot [System.Array] -or
            $Build.reproducibility.linkerFlags -isnot [System.Array] -or
            $Build.reproducibility.builds -isnot [System.Array] -or
            @($Build.reproducibility.builds).Count -ne 2) {
            throw $invalid
        }
        foreach ($buildResult in @($Build.reproducibility.builds)) {
            [void](Assert-PSOBBCombatCanaryExactProperties `
                    -Value $buildResult -RoleLabel 'combat-canary build result' `
                    -Expected @('run', 'size', 'sha256'))
        }
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Build.validation `
                -RoleLabel 'combat-canary build validation' `
                -Expected @('dependencyTests', 'newservCTest', 'deterministic',
                    'packageReparseFree'))
        if ($Build.validation.dependencyTests -isnot [System.Array]) {
            throw $invalid
        }
        foreach ($dependencyTest in @($Build.validation.dependencyTests)) {
            [void](Assert-PSOBBCombatCanaryExactProperties `
                    -Value $dependencyTest `
                    -RoleLabel 'combat-canary dependency test' `
                    -Expected @('name', 'passed', 'failed'))
        }
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Build.output `
                -RoleLabel 'combat-canary build output' `
                -Expected @('rootRelative', 'executable', 'releaseManifest',
                    'requiredDirectories', 'fileCount', 'totalBytes',
                    'versionOutput', 'runtimeImports'))
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Build.output.executable `
                -RoleLabel 'combat-canary executable output' `
                -Expected @('path', 'size', 'sha256', 'authenticode'))
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Build.output.releaseManifest `
                -RoleLabel 'combat-canary release manifest output' `
                -Expected @('path', 'size', 'sha256', 'authenticode'))
        if ($Build.output.requiredDirectories -isnot [System.Array] -or
            @($Build.output.requiredDirectories).Count -ne 1 -or
            $Build.output.runtimeImports -isnot [System.Array]) {
            throw $invalid
        }
        $true
    } catch {
        throw $invalid
    }
}

function Assert-PSOBBCombatCanaryBuildContractIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Build
    )

    [void](Assert-PSOBBCombatCanaryBuildContractShape -Build $Build)
    $objdump = @($Build.toolchain.tools)[3]
    if ($Build.schemaVersion -isnot [long] -or
        [long]$Build.schemaVersion -ne 1 -or
        [string]$Build.profileId -cne 'newserv-combat-canary-build' -or
        [string]$Build.signatureVerification.toolId -cne 'gpgv' -or
        [string]$Build.signatureVerification.keyring.source -cne
            'trust/newserv-build-signers.gpg' -or
        $Build.signatureVerification.keyring.size -isnot [long] -or
        [long]$Build.signatureVerification.keyring.size -le 0 -or
        [string]$Build.signatureVerification.keyring.sha256 -cnotmatch
            '^[a-f0-9]{64}$' -or
        $Build.signatureVerification.keyring.readOnly -isnot [bool] -or
        -not [bool]$Build.signatureVerification.keyring.readOnly -or
        [string]$Build.output.rootRelative -cne
            'combat-canary/server-base/release' -or
        [string]$Build.output.executable.path -cne 'newserv-windows.exe' -or
        [string]$Build.output.executable.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Build.output.executable.size -isnot [long] -or
        [long]$Build.output.executable.size -le 0 -or
        [string]$Build.output.executable.authenticode -cne 'NotSigned' -or
        [string]$Build.output.releaseManifest.path -cne
            'release-manifest.json' -or
        [string]$Build.output.releaseManifest.sha256 -cnotmatch
            '^[a-f0-9]{64}$' -or
        $Build.output.releaseManifest.size -isnot [long] -or
        [long]$Build.output.releaseManifest.size -le 0 -or
        [string]$Build.output.releaseManifest.authenticode -cne
            'NotApplicable' -or
        [string]$Build.output.requiredDirectories[0] -cne
            'system/ep3/maps' -or
        $Build.output.fileCount -isnot [long] -or
        [long]$Build.output.fileCount -le 0 -or
        $Build.output.totalBytes -isnot [long] -or
        [long]$Build.output.totalBytes -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$Build.output.versionOutput) -or
        [string]$objdump.id -cne 'objdump' -or
        [string]$objdump.command -cne 'objdump' -or
        [string]$objdump.pathRoot -cne 'LOCALAPPDATA' -or
        [string]$objdump.relativePath -cne
            ('Microsoft\WinGet\Packages\' +
                'BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_' +
                '8wekyb3d8bbwe\mingw64\bin\objdump.exe') -or
        [string]$objdump.versionMode -cne 'command' -or
        @($objdump.versionArguments).Count -ne 1 -or
        [string]($objdump.versionArguments[0]) -cne '--version' -or
        [string]$objdump.version -cne
            ('GNU objdump (Binutils for MinGW-W64 x86_64, built by ' +
                'Brecht Sanders, r2) 2.46.0.20260210') -or
        $objdump.executableSize -isnot [long] -or
        [long]$objdump.executableSize -ne 2562062 -or
        [string]$objdump.sha256 -cne
            '726acab4db3267478f323bee4092824c29e583c036e93aaef7e8846f7107b9bf') {
        throw 'The combat-canary build contract has an invalid fixed identity'
    }
    $true
}

function Assert-PSOBBCombatCanaryRequiredReleaseDirectories {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Build,
        [Parameter(Mandatory)][string]$Root,
        [switch]$AllowMissing
    )

    [void](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $Build)
    $safeRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
        [System.IO.Path]::GetFullPath($Root))
    $rootItem = Get-Item -Force -LiteralPath $safeRoot -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not [string]::IsNullOrWhiteSpace([string]$rootItem.LinkType)) {
        throw 'The combat-canary release root is not an ordinary directory'
    }

    $resolved = [System.Collections.Generic.List[string]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in @($Build.output.requiredDirectories)) {
        $current = $safeRoot
        $pathMissing = $false
        foreach ($part in @(([string]$relative).Split('/'))) {
            $current = Assert-PathWithinRoot `
                -Path (Join-Path $current $part) -Root $safeRoot
            if (-not (Test-Path -LiteralPath $current)) {
                $pathMissing = $true
                break
            }
            $item = Get-Item -Force -LiteralPath $current -ErrorAction Stop
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                -not [string]::IsNullOrWhiteSpace([string]$item.LinkType)) {
                throw "Required combat-canary release directory is not ordinary: $relative"
            }
        }
        if ($pathMissing) {
            if (-not $AllowMissing.IsPresent) {
                throw "Required combat-canary release directory is missing: $relative"
            }
            $missing.Add([string]$relative)
            continue
        }
        if (@(Get-ChildItem -Force -LiteralPath $current `
                    -ErrorAction Stop).Count -ne 0) {
            throw "Required combat-canary release directory is not empty: $relative"
        }
        $resolved.Add($current)
    }

    [pscustomobject]@{
        RequiredDirectories = @($resolved)
        MissingDirectories = @($missing)
    }
}

function Get-PSOBBCombatCanaryStrictRuntimeMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Layout
    )

    try {
        $markerPath = Assert-PathWithinRoot `
            -Path ([string]$Layout.RuntimeMarker) -Root ([string]$Layout.Root)
        $markerItem = Get-Item -Force -LiteralPath $markerPath -ErrorAction Stop
        if ($markerItem.PSIsContainer -or
            ($markerItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $markerItem.Length -le 0 -or $markerItem.Length -gt 16KB) {
            throw 'Unsafe runtime ownership marker'
        }
        $markerJson = Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $markerPath -Root ([string]$Layout.Root) `
            -MaximumBytes 16KB -ExpectedLength ([long]$markerItem.Length) `
            -RoleLabel 'PSOBB runtime ownership marker'
        $marker = ConvertTo-PSOBBCombatCanaryPowerShellObject `
            -JsonObject $markerJson -RoleLabel 'PSOBB runtime ownership marker'
        $expectedProperties = @(
            'schemaVersion', 'installationId', 'runtimeRoot', 'createdAtUtc')
        $actualProperties = @($marker.PSObject.Properties.Name | Sort-Object)
        $installationId = [Guid]::Empty
        $createdAt = [DateTimeOffset]::MinValue
        if ($actualProperties.Count -ne $expectedProperties.Count -or
            @(Compare-Object `
                    -ReferenceObject @($expectedProperties | Sort-Object) `
                    -DifferenceObject $actualProperties).Count -ne 0 -or
            [int]$marker.schemaVersion -ne 1 -or
            -not [Guid]::TryParseExact(
                [string]$marker.installationId, 'D', [ref]$installationId) -or
            -not [DateTimeOffset]::TryParse(
                [string]$marker.createdAtUtc, [ref]$createdAt) -or
            -not [System.IO.Path]::GetFullPath(
                [string]$marker.runtimeRoot).TrimEnd('\').Equals(
                [System.IO.Path]::GetFullPath(
                    [string]$Layout.Root).TrimEnd('\'),
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Invalid runtime ownership marker'
        }
        $marker
    } catch {
        throw 'The PSOBB runtime ownership marker is not an exact strict binding'
    }
}

function Get-PSOBBCombatCanaryApprovedClientIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot
    )

    $sourcesPath = Join-Path $RepositoryRoot 'config\sources.lock.json'
    $sourcesJson = Read-PSOBBCombatCanaryStrictJsonObject `
        -LiteralPath $sourcesPath -Root $RepositoryRoot -MaximumBytes 16MB `
        -RoleLabel 'tracked source lock'
    $sources = ConvertTo-PSOBBCombatCanaryPowerShellObject `
        -JsonObject $sourcesJson -RoleLabel 'tracked source lock'
    $components = @($sources.components | Where-Object {
            [string]$_.id -ceq 'tethealla-59nl-english'
        })
    $members = if ($components.Count -eq 1) {
        @($components[0].members | Where-Object {
                [string]$_.path -ceq 'Psobb.exe'
            })
    } else {
        @()
    }
    if ($members.Count -ne 1 -or
        [string]$members[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [int64]$members[0].size -le 0) {
        throw 'The tracked source lock does not identify one approved 59NL client'
    }
    [pscustomobject]@{
        Sha256 = [string]$members[0].sha256
        Size = [int64]$members[0].size
    }
}

function Get-PSOBBCombatCanaryRawObjectProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$ObjectNode,
        [Parameter(Mandatory)][string]$Name
    )

    if ([string]$ObjectNode.Kind -cne 'Object') {
        throw 'Expected a raw JSON object node'
    }
    @($ObjectNode.Properties | Where-Object { [string]$_.Name -ceq $Name })
}

function ConvertFrom-PSOBBCombatCanaryPhosgStringBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RawToken,

        [Parameter(DontShow = $true)]
        [scriptblock]$InternalTestAfterBufferClear
    )

    if ($RawToken.Length -lt 2 -or $RawToken[0] -ne '"' -or
        $RawToken[$RawToken.Length - 1] -ne '"') {
        throw 'Invalid raw JSON string token'
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $workBytes = [byte[]]::new(
        $utf8.GetMaxByteCount([Math]::Max(0, $RawToken.Length - 2)))
    $result = $null
    $count = 0
    try {
        $index = 1
        while ($index -lt $RawToken.Length - 1) {
            $character = $RawToken[$index]
            if ($character -eq '\') {
                $index++
                if ($index -ge $RawToken.Length - 1) {
                    throw 'Incomplete raw JSON string escape'
                }
                $escapeCharacter = $RawToken[$index]
                $escapedByte = switch ($escapeCharacter) {
                    '"' { [byte]0x22 }
                    '\' { [byte]0x5C }
                    '/' { [byte]0x2F }
                    'b' { [byte]0x08 }
                    'f' { [byte]0x0C }
                    'n' { [byte]0x0A }
                    'r' { [byte]0x0D }
                    't' { [byte]0x09 }
                    'u' {
                        if ($index + 4 -ge $RawToken.Length) {
                            throw 'Incomplete raw JSON unicode escape'
                        }
                        $value = 0
                        for ($offset = 1; $offset -le 4; $offset++) {
                            $digit = $RawToken[$index + $offset]
                            $nibble = if ($digit -ge '0' -and $digit -le '9') {
                                [int]$digit - [int][char]'0'
                            } elseif ($digit -ge 'a' -and $digit -le 'f') {
                                10 + [int]$digit - [int][char]'a'
                            } elseif ($digit -ge 'A' -and $digit -le 'F') {
                                10 + [int]$digit - [int][char]'A'
                            } else {
                                throw 'Invalid raw JSON unicode escape'
                            }
                            $value = ($value -shl 4) -bor $nibble
                        }
                        if ($value -gt 0xFF) {
                            throw 'JSON unicode escape is not one phosg byte'
                        }
                        $index += 4
                        [byte]$value
                    }
                    default { throw 'Unsupported raw JSON string escape' }
                }
                $workBytes[$count] = [byte]$escapedByte
                $count++
                $index++
                continue
            }
            $segmentStart = $index
            while ($index -lt $RawToken.Length - 1 -and
                $RawToken[$index] -ne '\') {
                $index++
            }
            $segmentLength = $index - $segmentStart
            $count += $utf8.GetBytes(
                $RawToken, $segmentStart, $segmentLength, $workBytes, $count)
        }
        $result = [byte[]]::new($count)
        if ($count -gt 0) {
            [System.Buffer]::BlockCopy($workBytes, 0, $result, 0, $count)
        }
        Write-Output -NoEnumerate $result
        $result = $null
    } finally {
        if ($null -ne $result) {
            [Array]::Clear($result, 0, $result.Length)
        }
        [Array]::Clear($workBytes, 0, $workBytes.Length)
        if ($null -ne $InternalTestAfterBufferClear) {
            & $InternalTestAfterBufferClear 'phosg-work' $workBytes
        }
    }
}

function Get-PSOBBCombatCanaryBBLicenseIdentities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Newtonsoft.Json.Linq.JObject]$State,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RawText,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z][a-z0-9_-]{2,15}$')]
        [string]$ExpectedAccountName,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel,

        [Parameter(DontShow = $true)]
        [scriptblock]$InternalTestAfterBufferClear
    )

    $invalid = "The $RoleLabel has an invalid BB credential shape"
    $credentialPairs = [System.Collections.Generic.List[object]]::new()
    $rawUserBytes = $null
    $rawPasswordBytes = $null
    $expectedBytes = $null
    $expectedDigest = $null
    $digest = $null
    try {
        $preflight = ConvertTo-PSOBBCombatCanaryPhosgJsonPreflight `
            -Text $RawText -RoleLabel $RoleLabel
        if ([string]$preflight.Root.Kind -cne 'Object') { throw $invalid }
        $rawRoot = $preflight.Root

        $autoPatches = @($State.Properties() |
            Where-Object Name -CEQ 'AutoPatchesEnabled')
        if ($autoPatches.Count -gt 1 -or
            ($autoPatches.Count -eq 1 -and
                ($autoPatches[0].Value -isnot [Newtonsoft.Json.Linq.JArray] -or
                    $autoPatches[0].Value.Count -ne 0))) {
            throw $invalid
        }

        $formatProperties = @($State.Properties() |
            Where-Object Name -CEQ 'FormatVersion')
        $formatVersion = [System.Numerics.BigInteger]::Zero
        if ($formatProperties.Count -gt 1) { throw $invalid }
        if ($formatProperties.Count -eq 1) {
            $formatToken = $formatProperties[0].Value
            if ($formatToken -isnot [Newtonsoft.Json.Linq.JValue] -or
                $formatToken.Type -ne [Newtonsoft.Json.Linq.JTokenType]::Integer) {
                throw $invalid
            }
            try {
                $formatVersion = [System.Numerics.BigInteger]::Parse(
                    [string]$formatToken.Value,
                    [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                throw $invalid
            }
            if ($formatVersion -lt [System.Numerics.BigInteger]::Zero -or
                $formatVersion -gt
                    [System.Numerics.BigInteger]::new([long]::MaxValue)) {
                throw $invalid
            }
        }

        $legacyUser = @($State.Properties() |
            Where-Object Name -CEQ 'BBUsername')
        $legacyPassword = @($State.Properties() |
            Where-Object Name -CEQ 'BBPassword')
        $current = @($State.Properties() | Where-Object Name -CEQ 'BBLicenses')
        $rawLegacyUser = @(Get-PSOBBCombatCanaryRawObjectProperties `
                -ObjectNode $rawRoot -Name 'BBUsername')
        $rawLegacyPassword = @(Get-PSOBBCombatCanaryRawObjectProperties `
                -ObjectNode $rawRoot -Name 'BBPassword')
        $rawCurrent = @(Get-PSOBBCombatCanaryRawObjectProperties `
                -ObjectNode $rawRoot -Name 'BBLicenses')
        if ($formatVersion -eq [System.Numerics.BigInteger]::Zero) {
            if ($current.Count -ne 0 -or $rawCurrent.Count -ne 0 -or
                $legacyUser.Count -gt 1 -or $legacyPassword.Count -gt 1 -or
                $rawLegacyUser.Count -ne $legacyUser.Count -or
                $rawLegacyPassword.Count -ne $legacyPassword.Count) {
                throw $invalid
            }
            foreach ($property in @($legacyUser + $legacyPassword)) {
                if ($property.Value -isnot [Newtonsoft.Json.Linq.JValue] -or
                    $property.Value.Value -isnot [string]) {
                    throw $invalid
                }
            }
            foreach ($rawProperty in @($rawLegacyUser + $rawLegacyPassword)) {
                if ([string]$rawProperty.Value.Kind -cne 'String') {
                    throw $invalid
                }
            }
            if ($legacyUser.Count -eq 1 -and $legacyPassword.Count -eq 1) {
                $rawUserBytes = [byte[]](
                    ConvertFrom-PSOBBCombatCanaryPhosgStringBytes `
                        -RawToken ([string]$rawLegacyUser[0].Value.Raw) `
                        -InternalTestAfterBufferClear `
                            $InternalTestAfterBufferClear)
                $rawPasswordBytes = [byte[]](
                    ConvertFrom-PSOBBCombatCanaryPhosgStringBytes `
                        -RawToken ([string]$rawLegacyPassword[0].Value.Raw) `
                        -InternalTestAfterBufferClear `
                            $InternalTestAfterBufferClear)
                if ($rawUserBytes.Count -gt 0 -and $rawPasswordBytes.Count -gt 0) {
                    $credentialPairs.Add([pscustomobject]@{
                            UserNameBytes = $rawUserBytes
                            PasswordBytes = $rawPasswordBytes
                            EnforceCurrentLimits = $false
                        })
                    $rawUserBytes = $null
                    $rawPasswordBytes = $null
                }
            }
        } else {
            if ($legacyUser.Count -ne 0 -or $legacyPassword.Count -ne 0 -or
                $rawLegacyUser.Count -ne 0 -or $rawLegacyPassword.Count -ne 0 -or
                $current.Count -ne 1 -or $rawCurrent.Count -ne 1 -or
                $current[0].Value -isnot [Newtonsoft.Json.Linq.JArray] -or
                [string]$rawCurrent[0].Value.Kind -cne 'Array' -or
                $rawCurrent[0].Value.Items.Count -ne $current[0].Value.Count) {
                throw $invalid
            }
            for ($licenseIndex = 0;
                $licenseIndex -lt $current[0].Value.Count;
                $licenseIndex++) {
                $bbLicense = $current[0].Value[$licenseIndex]
                $rawLicense = $rawCurrent[0].Value.Items[$licenseIndex]
                if ($bbLicense -isnot [Newtonsoft.Json.Linq.JObject] -or
                    [string]$rawLicense.Kind -cne 'Object') {
                    throw $invalid
                }
                $userProperties = @($bbLicense.Properties() |
                    Where-Object Name -CEQ 'UserName')
                $passwordProperties = @($bbLicense.Properties() |
                    Where-Object Name -CEQ 'Password')
                $rawUserProperties = @(Get-PSOBBCombatCanaryRawObjectProperties `
                        -ObjectNode $rawLicense -Name 'UserName')
                $rawPasswordProperties = @(Get-PSOBBCombatCanaryRawObjectProperties `
                        -ObjectNode $rawLicense -Name 'Password')
                if ($userProperties.Count -ne 1 -or
                    $passwordProperties.Count -ne 1 -or
                    $rawUserProperties.Count -ne 1 -or
                    $rawPasswordProperties.Count -ne 1 -or
                    $userProperties[0].Value -isnot
                        [Newtonsoft.Json.Linq.JValue] -or
                    $passwordProperties[0].Value -isnot
                        [Newtonsoft.Json.Linq.JValue] -or
                    $userProperties[0].Value.Value -isnot [string] -or
                    $passwordProperties[0].Value.Value -isnot [string] -or
                    [string]$rawUserProperties[0].Value.Kind -cne 'String' -or
                    [string]$rawPasswordProperties[0].Value.Kind -cne 'String') {
                    throw $invalid
                }
                $rawUserBytes = [byte[]](
                    ConvertFrom-PSOBBCombatCanaryPhosgStringBytes `
                        -RawToken ([string]$rawUserProperties[0].Value.Raw) `
                        -InternalTestAfterBufferClear `
                            $InternalTestAfterBufferClear)
                $rawPasswordBytes = [byte[]](
                    ConvertFrom-PSOBBCombatCanaryPhosgStringBytes `
                        -RawToken ([string]$rawPasswordProperties[0].Value.Raw) `
                        -InternalTestAfterBufferClear `
                            $InternalTestAfterBufferClear)
                if ($rawUserBytes.Count -lt 1 -or $rawUserBytes.Count -gt 16 -or
                    $rawPasswordBytes.Count -lt 1 -or
                    $rawPasswordBytes.Count -gt 16) {
                    throw $invalid
                }
                $credentialPairs.Add([pscustomobject]@{
                        UserNameBytes = $rawUserBytes
                        PasswordBytes = $rawPasswordBytes
                        EnforceCurrentLimits = $true
                    })
                $rawUserBytes = $null
                $rawPasswordBytes = $null
            }
        }

        $expectedBytes = [System.Text.UTF8Encoding]::new(
            $false, $true).GetBytes($ExpectedAccountName)
        $expectedDigest = [System.Security.Cryptography.SHA256]::HashData(
            $expectedBytes)
        $identities = [System.Collections.Generic.List[object]]::new()
        foreach ($pair in $credentialPairs) {
            $userBytes = [byte[]]$pair.UserNameBytes
            $passwordBytes = [byte[]]$pair.PasswordBytes
            try {
                $asciiSafe = $userBytes.Count -ge 3 -and $userBytes.Count -le 16
                foreach ($byte in $userBytes) {
                    if ($byte -gt 0x7F) { $asciiSafe = $false; break }
                }
                $accountText = if ($asciiSafe) {
                    [System.Text.Encoding]::ASCII.GetString($userBytes)
                } else { '' }
                if ($asciiSafe -and
                    $accountText -cnotmatch '^[a-z][a-z0-9_-]{2,15}$') {
                    $asciiSafe = $false
                }
                $digest = [System.Security.Cryptography.SHA256]::HashData(
                    $userBytes)
                $identities.Add([pscustomobject]@{
                        IdentitySha256 = ([Convert]::ToHexString(
                                $digest)).ToLowerInvariant()
                        IsSafeAccountName = $asciiSafe
                        MatchesExpectedAccount =
                            [System.Security.Cryptography.CryptographicOperations]::
                                FixedTimeEquals($digest, $expectedDigest)
                    })
                if (-not $asciiSafe) {
                    throw $invalid
                }
            } finally {
                if ($null -ne $digest) {
                    [Array]::Clear($digest, 0, $digest.Length)
                    if ($null -ne $InternalTestAfterBufferClear) {
                        & $InternalTestAfterBufferClear 'digest' $digest
                    }
                    $digest = $null
                }
            }
        }
        $identities.ToArray()
    } catch {
        throw $invalid
    } finally {
        if ($null -ne $digest) {
            [Array]::Clear($digest, 0, $digest.Length)
            if ($null -ne $InternalTestAfterBufferClear) {
                & $InternalTestAfterBufferClear 'digest' $digest
            }
        }
        if ($null -ne $expectedDigest) {
            [Array]::Clear($expectedDigest, 0, $expectedDigest.Length)
            if ($null -ne $InternalTestAfterBufferClear) {
                & $InternalTestAfterBufferClear 'expected-digest' $expectedDigest
            }
        }
        if ($null -ne $expectedBytes) {
            [Array]::Clear($expectedBytes, 0, $expectedBytes.Length)
            if ($null -ne $InternalTestAfterBufferClear) {
                & $InternalTestAfterBufferClear 'expected-account' $expectedBytes
            }
        }
        if ($null -ne $rawPasswordBytes) {
            [Array]::Clear($rawPasswordBytes, 0, $rawPasswordBytes.Length)
            if ($null -ne $InternalTestAfterBufferClear) {
                & $InternalTestAfterBufferClear 'pending-password' $rawPasswordBytes
            }
        }
        if ($null -ne $rawUserBytes) {
            [Array]::Clear($rawUserBytes, 0, $rawUserBytes.Length)
            if ($null -ne $InternalTestAfterBufferClear) {
                & $InternalTestAfterBufferClear 'pending-username' $rawUserBytes
            }
        }
        foreach ($pair in $credentialPairs) {
            $pairPasswordBytes = [byte[]]$pair.PasswordBytes
            $pairUserBytes = [byte[]]$pair.UserNameBytes
            if ($null -ne $pairPasswordBytes) {
                [Array]::Clear(
                    $pairPasswordBytes, 0, $pairPasswordBytes.Length)
                if ($null -ne $InternalTestAfterBufferClear) {
                    & $InternalTestAfterBufferClear `
                        'credential-password' $pairPasswordBytes
                }
            }
            if ($null -ne $pairUserBytes) {
                [Array]::Clear($pairUserBytes, 0, $pairUserBytes.Length)
                if ($null -ne $InternalTestAfterBufferClear) {
                    & $InternalTestAfterBufferClear `
                        'credential-username' $pairUserBytes
                }
            }
        }
    }
}

function Get-PSOBBCombatCanaryExpectedDirectories {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$FilePaths,
        [string[]]$RequiredDirectories = @()
    )

    $expected = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($required in $RequiredDirectories) {
        if (-not [string]::IsNullOrWhiteSpace($required)) {
            [void]$expected.Add($required.Replace('\', '/').Trim('/'))
        }
    }
    foreach ($filePath in $FilePaths) {
        $parent = [System.IO.Path]::GetDirectoryName(
            $filePath.Replace('/', '\'))
        while (-not [string]::IsNullOrWhiteSpace($parent)) {
            $relative = $parent.Replace('\', '/').Trim('/')
            if ([string]::IsNullOrWhiteSpace($relative)) { break }
            [void]$expected.Add($relative)
            $parent = [System.IO.Path]::GetDirectoryName($parent)
        }
    }
    Write-Output -NoEnumerate $expected
}

function Assert-PSOBBCombatCanaryExactDirectoryInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$ExpectedDirectories,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9 -]{0,63}$')]
        [string]$RoleLabel,
        [switch]$RequireProtected
    )

    try {
        $safeRoot = Assert-PathWithinRoot -Path $Root -Root $Root
        $rootItem = Get-Item -Force -LiteralPath $safeRoot -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or
            ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($RequireProtected.IsPresent -and
                -not (Test-PSOBBProtectedAcl -Path $safeRoot))) {
            throw 'Unsafe directory root'
        }
        $actual = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($directory in @(Get-ChildItem -Force -LiteralPath $safeRoot `
                    -Recurse -Directory -ErrorAction Stop)) {
            [void](Assert-PathWithinRoot -Path $directory.FullName -Root $safeRoot)
            if (($directory.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($RequireProtected.IsPresent -and
                    -not (Test-PSOBBProtectedAcl -Path $directory.FullName))) {
                throw 'Unsafe directory inventory item'
            }
            $relative = [System.IO.Path]::GetRelativePath(
                $safeRoot, $directory.FullName).Replace('\', '/')
            if (-not $actual.Add($relative)) {
                throw 'Colliding directory inventory item'
            }
        }
        if ($actual.Count -ne $ExpectedDirectories.Count) {
            throw 'Directory inventory count mismatch'
        }
        foreach ($directory in $actual) {
            if (-not $ExpectedDirectories.Contains($directory)) {
                throw 'Unexpected directory inventory item'
            }
        }
        $true
    } catch {
        throw "The $RoleLabel directory inventory is unreadable or inexact"
    }
}

function Assert-PSOBBCombatStableShadowContractIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Contract)

    $invalid = 'The StableShadow assembly contract is not exact'
    try {
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Contract `
                -RoleLabel 'StableShadow assembly contract' `
                -Expected @('$schema', 'schemaVersion', 'profileId',
                    'source', 'output'))
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Contract.source `
                -RoleLabel 'StableShadow source contract' `
                -Expected @('serverComponentId', 'serverCommit',
                    'serverArchiveSha256', 'serverExecutable',
                    'clientComponentId', 'serverBaseManifestRelativePath',
                    'patchManifestRelativePath', 'patchDataRelativePath',
                    'patchDataTargetRelativePath', 'patchDataFileCount'))
        [void](Assert-PSOBBCombatCanaryExactProperties `
                -Value $Contract.source.serverExecutable `
                -RoleLabel 'StableShadow executable contract' `
                -Expected @('path', 'size', 'sha256'))
        [void](Assert-PSOBBCombatCanaryExactProperties -Value $Contract.output `
                -RoleLabel 'StableShadow output contract' `
                -Expected @('rootRelative', 'releaseManifestName',
                    'generatedMetadataCaches'))
        if ($Contract.output.generatedMetadataCaches -isnot [System.Array] -or
            @($Contract.output.generatedMetadataCaches).Count -ne 2) {
            throw $invalid
        }
        foreach ($cache in @($Contract.output.generatedMetadataCaches)) {
            [void](Assert-PSOBBCombatCanaryExactProperties -Value $cache `
                    -RoleLabel 'StableShadow metadata cache contract' `
                    -Expected @('path', 'maximumBytes', 'keyPrefix'))
        }
        $caches = @($Contract.output.generatedMetadataCaches)
        if ([int]$Contract.schemaVersion -ne 1 -or
            [string]$Contract.'$schema' -cne
                './schemas/combat-stable-shadow.schema.json' -or
            [string]$Contract.profileId -cne 'newserv-stable-shadow' -or
            [string]$Contract.source.serverComponentId -cne
                'newserv-stable-release' -or
            [string]$Contract.source.serverCommit -cne
                'a649a4a146d04dba320bb579ac291527db0febb5' -or
            [string]$Contract.source.serverArchiveSha256 -cne
                'aee0696b4392407d46ef584e1b8117307474b791ef09a02282458d1444655869' -or
            [string]$Contract.source.serverExecutable.path -cne
                'newserv-windows.exe' -or
            [int64]$Contract.source.serverExecutable.size -ne 31162999 -or
            [string]$Contract.source.serverExecutable.sha256 -cne
                '7e82732ca1dd84fa7cd5bd8261f8bb9f42e3a704c66cef83c0fb51a9802eb1cd' -or
            [string]$Contract.source.clientComponentId -cne
                'tethealla-59nl-english' -or
            [string]$Contract.source.serverBaseManifestRelativePath -cne
                'stable/server-base.manifest.json' -or
            [string]$Contract.source.patchManifestRelativePath -cne
                'stable/patch-bb-data.manifest.json' -or
            [string]$Contract.source.patchDataRelativePath -cne
                'stable/server/release/system/patch-bb/data' -or
            [string]$Contract.source.patchDataTargetRelativePath -cne
                'system/patch-bb/data' -or
            [int]$Contract.source.patchDataFileCount -ne 108 -or
            [string]$Contract.output.rootRelative -cne
                'combat-canary/server-base/release' -or
            [string]$Contract.output.releaseManifestName -cne
                'release-manifest.json' -or
            [string]$caches[0].path -cne
                'system/patch-bb/.metadata-cache.json' -or
            [int64]$caches[0].maximumBytes -ne 4MB -or
            [string]$caches[0].keyPrefix -cne './data/' -or
            [string]$caches[1].path -cne
                'system/patch-pc/.metadata-cache.json' -or
            [int64]$caches[1].maximumBytes -ne 1MB -or
            [string]$caches[1].keyPrefix -cne './Media/PSO/') {
            throw $invalid
        }
        $true
    } catch {
        throw $invalid
    }
}

function Get-PSOBBCombatCanaryBuildContractSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [ValidatePattern('^[a-fA-F0-9]{64}$')]
        [string]$ExpectedSha256
    )

    $root = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
    $candidates = @(
        [pscustomobject]@{
            Artifact = 'CurrentUpstream'
            ComponentId = 'newserv-combat-canary-build'
            RelativePath = 'config/combat-canary-build.json'
            MaximumBytes = 512KB
        },
        [pscustomobject]@{
            Artifact = 'StableShadow'
            ComponentId = 'newserv-stable-release'
            RelativePath = 'config/combat-stable-shadow.json'
            MaximumBytes = 64KB
        })
    $expected = if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        ''
    } else {
        $ExpectedSha256.ToLowerInvariant()
    }
    $matches = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in $candidates) {
        $path = Assert-PathWithinRoot `
            -Path (Join-Path $root $candidate.RelativePath.Replace('/', '\')) `
            -Root $root
        $snapshot = Read-PSOBBCombatCanaryStrictJsonObject `
            -LiteralPath $path -Root $root `
            -MaximumBytes ([int64]$candidate.MaximumBytes) `
            -PassThruSnapshot `
            -RoleLabel ($candidate.Artifact + ' build contract')
        if (-not [string]::IsNullOrEmpty($expected) -and
            [string]$snapshot.Sha256 -cne $expected) {
            continue
        }
        $value = ConvertTo-PSOBBCombatCanaryPowerShellObject `
            -JsonObject $snapshot.Value `
            -RoleLabel ($candidate.Artifact + ' build contract')
        if ($candidate.Artifact -ceq 'CurrentUpstream') {
            [void](Assert-PSOBBCombatCanaryBuildContractIdentity -Build $value)
        } else {
            [void](Assert-PSOBBCombatStableShadowContractIdentity `
                    -Contract $value)
        }
        $matches.Add([pscustomobject]@{
                Artifact = [string]$candidate.Artifact
                ComponentId = [string]$candidate.ComponentId
                Path = $path
                Hash = [string]$snapshot.Sha256
                Value = $value
            })
    }
    if ([string]::IsNullOrEmpty($expected)) {
        return @($matches)
    }
    if ($matches.Count -ne 1) {
        throw 'The installed combat-canary build contract is unknown or ambiguous'
    }
    $matches[0]
}
