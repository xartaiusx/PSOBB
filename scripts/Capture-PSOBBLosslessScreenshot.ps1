[CmdletBinding()]
param(
    [ValidateSet('Stable', 'Canary', 'LocalLab')]
    [string]$Channel = 'LocalLab',

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$RuntimeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PSOBB.Common.ps1')

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')

function Initialize-PSOBBLosslessCaptureType {
    if ($null -ne ('PSOBBLosslessCapture' -as [type])) {
        return
    }

    Add-Type -AssemblyName System.Drawing.Common
    $drawingAssembly = [System.Drawing.Bitmap].Assembly.Location
    $drawingPrimitivesAssembly = [System.Drawing.Size].Assembly.Location
    $powerShellRuntimeDirectory = [System.IO.Path]::GetDirectoryName($drawingAssembly)
    $windowsCoreAssembly = Join-Path $powerShellRuntimeDirectory 'System.Private.Windows.Core.dll'
    $gdiPlusAssembly = Join-Path $powerShellRuntimeDirectory 'System.Private.Windows.GdiPlus.dll'
    Add-Type -ReferencedAssemblies @(
        $drawingAssembly,
        $drawingPrimitivesAssembly,
        $windowsCoreAssembly,
        $gdiPlusAssembly) -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

public static class PSOBBLosslessCapture
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point { public int X, Y; }

    public sealed class Result
    {
        public int X { get; set; }
        public int Y { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int ProcessId { get; set; }
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetClientRect(IntPtr window, out Rect rectangle);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ClientToScreen(IntPtr window, ref Point point);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr window);

    public static Result Capture(
        IntPtr window,
        int expectedProcessId,
        int expectedWidth,
        int expectedHeight,
        string outputPath)
    {
        if (window == IntPtr.Zero || expectedProcessId <= 0)
            throw new InvalidOperationException("The approved PSOBB window is unavailable");
        if (IsIconic(window))
            throw new InvalidOperationException("The approved PSOBB window is minimized");
        if (GetForegroundWindow() != window)
            throw new InvalidOperationException("PSOBB must be the foreground window for a lossless screen capture");

        uint ownerProcessId;
        if (GetWindowThreadProcessId(window, out ownerProcessId) == 0 ||
            ownerProcessId != (uint)expectedProcessId)
            throw new InvalidOperationException(
                $"The PSOBB window owner changed before capture (Win32={Marshal.GetLastWin32Error()})");

        Rect client;
        if (!GetClientRect(window, out client))
            throw new InvalidOperationException($"GetClientRect failed (Win32={Marshal.GetLastWin32Error()})");
        var width = client.Right - client.Left;
        var height = client.Bottom - client.Top;
        if (width != expectedWidth || height != expectedHeight)
            throw new InvalidOperationException(
                $"The PSOBB client area is {width}x{height}, expected {expectedWidth}x{expectedHeight}");

        var origin = new Point { X = 0, Y = 0 };
        if (!ClientToScreen(window, ref origin))
            throw new InvalidOperationException($"ClientToScreen failed (Win32={Marshal.GetLastWin32Error()})");

        using (var bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb))
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.CopyFromScreen(
                origin.X,
                origin.Y,
                0,
                0,
                new Size(width, height),
                CopyPixelOperation.SourceCopy);
            bitmap.Save(outputPath, ImageFormat.Png);
        }

        return new Result {
            X = origin.X,
            Y = origin.Y,
            Width = width,
            Height = height,
            ProcessId = expectedProcessId,
        };
    }
}
'@
}

$layout = Get-PSOBBLayout -RuntimeRoot $RuntimeRoot
Assert-PSOBBRuntimeMarker -Layout $layout | Out-Null
$fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$evidenceRoot = [System.IO.Path]::GetFullPath((Join-Path $layout.Root 'graphics-evidence')).TrimEnd('\')
$evidencePrefix = $evidenceRoot + '\'
if (-not $fullOutputPath.StartsWith($evidencePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.IO.Path]::GetExtension($fullOutputPath) -ine '.png') {
    throw "Lossless screenshots must be new PNG files under the private runtime graphics-evidence tree: $evidenceRoot"
}
if ($fullOutputPath.Equals($repositoryRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $fullOutputPath.StartsWith($repositoryRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Raw screenshots cannot be written inside the Git repository'
}
if (Test-Path -LiteralPath $fullOutputPath) {
    throw "Refusing to overwrite an existing screenshot: $fullOutputPath"
}

$records = @(Get-PSOBBClientProcessRecords -Layout $layout -Channel All)
if ($records.Count -ne 1 -or [string]$records[0].Channel -cne $Channel) {
    throw "Lossless capture requires exactly one approved $Channel PSOBB client"
}
$record = $records[0]
$process = Get-Process -Id ([int]$record.ProcessId) -ErrorAction SilentlyContinue
if (-not $process -or
    -not (Test-PSOBBProcessAtExactPath `
        -Process $process `
        -Name 'Psobb' `
        -ExpectedPath ([string]$record.ExecutablePath))) {
    throw 'The approved PSOBB process identity cannot be revalidated'
}
$identity = Assert-PSOBBApprovedClientExecutable -Path ([string]$record.ExecutablePath)
if (-not $identity.Sha256.Equals(
    [string]$record.ExecutableSha256,
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The approved PSOBB executable changed before capture'
}

$clientRoot = Split-Path -Parent ([string]$record.ExecutablePath)
$profilePath = Join-Path $clientRoot 'client-profile.json'
$profile = if ($Channel -eq 'LocalLab') {
    Assert-PSOBBLocalLabClientRuntimeContract -Layout $layout
} else {
    & (Join-Path $PSScriptRoot 'Test-PSOBBClientGraphics.ps1') `
        -Channel $Channel `
        -RuntimeRoot $layout.Root | Out-Null
    Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -Depth 30
}
if ([int]$profile.desktopWidth -ne 2560 -or [int]$profile.desktopHeight -ne 1600) {
    throw 'Lossless acceptance captures currently require the approved 2560x1600 output profile'
}

$outputDirectory = Split-Path -Parent $fullOutputPath
[void][System.IO.Directory]::CreateDirectory($outputDirectory)
$temporaryPath = Join-Path $outputDirectory (
    '.capture-' + [Guid]::NewGuid().ToString('N') + '.png')
Initialize-PSOBBLosslessCaptureType
try {
    $process.Refresh()
    $result = [PSOBBLosslessCapture]::Capture(
        $process.MainWindowHandle,
        $process.Id,
        [int]$profile.desktopWidth,
        [int]$profile.desktopHeight,
        $temporaryPath)
    $bytes = [System.IO.File]::ReadAllBytes($temporaryPath)
    $pngSignature = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    if ($bytes.Length -le $pngSignature.Length -or
        -not [System.Linq.Enumerable]::SequenceEqual(
            [byte[]]$bytes[0..7],
            $pngSignature)) {
        throw 'The captured evidence file does not have the PNG signature'
    }
    Move-Item -LiteralPath $temporaryPath -Destination $fullOutputPath
} finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

[pscustomobject]@{
    Captured = $true
    Channel = $Channel
    ProfileId = if ($profile.PSObject.Properties.Name -contains 'profileId') {
        [string]$profile.profileId
    } else {
        $null
    }
    ProcessId = $result.ProcessId
    X = $result.X
    Y = $result.Y
    Width = $result.Width
    Height = $result.Height
    ByteSize = (Get-Item -LiteralPath $fullOutputPath -Force).Length
    Sha256 = Get-LowerSha256 -Path $fullOutputPath
    OutputPath = $fullOutputPath
}
