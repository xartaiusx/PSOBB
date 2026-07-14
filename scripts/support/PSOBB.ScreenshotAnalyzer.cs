using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PSOBB.GraphicsEvidence
{
    public sealed class ScreenshotAnalysis
    {
        public string Sha256 { get; set; } = string.Empty;
        public long ByteSize { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public long NonOpaquePixelCount { get; set; }
        public EdgeBandAnalysis EdgeBands { get; set; } = new EdgeBandAnalysis();
        public SharpnessAnalysis Sharpness { get; set; } = new SharpnessAnalysis();
        public ToneAnalysis Tone { get; set; } = new ToneAnalysis();
    }

    public sealed class EdgeBandAnalysis
    {
        public int BandWidthPixels { get; set; }
        public int NearBlackThreshold { get; set; }
        public double PillarColumnNearBlackMinimumPercent { get; set; }
        public double LeftBandMeanLuma { get; set; }
        public double RightBandMeanLuma { get; set; }
        public double LeftBandNearBlackPercent { get; set; }
        public double RightBandNearBlackPercent { get; set; }
        public int DetectedLeftPillarWidthPixels { get; set; }
        public int DetectedRightPillarWidthPixels { get; set; }
        public int PillarSymmetryDeltaPixels { get; set; }
        public bool EntireFrameNearBlack { get; set; }
        public int ActiveContentWidthPixels { get; set; }
        public double ActiveContentAspectRatio { get; set; }
    }

    public sealed class SharpnessAnalysis
    {
        public string Region { get; set; } = "detected-active-content";
        public long SampleCount { get; set; }
        public int EdgeThreshold { get; set; }
        public double MeanAbsoluteGradient { get; set; }
        public double P95AbsoluteGradient { get; set; }
        public double LaplacianVariance { get; set; }
        public double EdgeDensityPercent { get; set; }
    }

    public sealed class ToneAnalysis
    {
        public long PixelCount { get; set; }
        public long ExactBlackPixelCount { get; set; }
        public long ExactWhitePixelCount { get; set; }
        public double ExactBlackPixelPercent { get; set; }
        public double ExactWhitePixelPercent { get; set; }
    }

    public sealed class ScreenshotComparison
    {
        public long PixelCount { get; set; }
        public double MeanAbsoluteLumaDifference { get; set; }
        public double RootMeanSquareLumaDifference { get; set; }
        public double PsnrDb { get; set; }
        public long IntroducedBlackClipPixelCount { get; set; }
        public long IntroducedWhiteClipPixelCount { get; set; }
        public double IntroducedBlackClipPixelPercent { get; set; }
        public double IntroducedWhiteClipPixelPercent { get; set; }
        public int ReferenceEdgeThreshold { get; set; }
        public long ReferenceEdgeSampleCount { get; set; }
        public long HaloOvershootPixelCount { get; set; }
        public double HaloOvershootAffectedEdgePercent { get; set; }
        public double MeanHaloOvershootPercent { get; set; }
        public double P95HaloOvershootPercent { get; set; }
        public double MaximumHaloOvershootPercent { get; set; }
    }

    public static class ScreenshotAnalyzer
    {
        private static readonly byte[] PngSignature =
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        };

        private const int MaximumDimension = 16384;
        private const long MaximumPixelCount = 100000000;
        private const long MaximumFileSize = 256L * 1024L * 1024L;

        public static ScreenshotAnalysis Analyze(
            string path,
            int edgeBandWidth,
            int nearBlackThreshold,
            double pillarColumnNearBlackMinimumPercent,
            int sharpnessEdgeThreshold)
        {
            using (DecodedImage image = Load(path))
            {
                EdgeBandAnalysis edgeBands = AnalyzeEdgeBands(
                    image,
                    edgeBandWidth,
                    nearBlackThreshold,
                    pillarColumnNearBlackMinimumPercent);

                return new ScreenshotAnalysis
                {
                    Sha256 = image.Sha256,
                    ByteSize = image.ByteSize,
                    Width = image.Width,
                    Height = image.Height,
                    NonOpaquePixelCount = CountNonOpaquePixels(image),
                    EdgeBands = edgeBands,
                    Sharpness = AnalyzeSharpness(image, edgeBands, sharpnessEdgeThreshold),
                    Tone = AnalyzeTone(image)
                };
            }
        }

        public static ScreenshotComparison Compare(
            string referencePath,
            string candidatePath,
            int referenceEdgeThreshold)
        {
            using (DecodedImage reference = Load(referencePath))
            using (DecodedImage candidate = Load(candidatePath))
            {
                if (reference.Width != candidate.Width || reference.Height != candidate.Height)
                {
                    throw new InvalidDataException(
                        "Reference and candidate PNG dimensions must match exactly");
                }

                long pixelCount = reference.PixelCount;
                double absoluteDifferenceTotal = 0.0;
                double squaredDifferenceTotal = 0.0;
                long introducedBlack = 0;
                long introducedWhite = 0;
                long edgeSamples = 0;
                long overshootPixels = 0;
                long overshootTotal = 0;
                int maximumOvershoot = 0;
                long[] overshootHistogram = new long[256];

                for (int y = 0; y < reference.Height; y++)
                {
                    int row = y * reference.Width;
                    for (int x = 0; x < reference.Width; x++)
                    {
                        int pixelIndex = row + x;
                        int byteIndex = pixelIndex * 4;
                        int referenceLuma = reference.Luma[pixelIndex];
                        int candidateLuma = candidate.Luma[pixelIndex];
                        int difference = candidateLuma - referenceLuma;
                        int absoluteDifference = Math.Abs(difference);
                        absoluteDifferenceTotal += absoluteDifference;
                        squaredDifferenceTotal += difference * difference;

                        bool referenceBlack =
                            reference.Bgra[byteIndex] == 0 &&
                            reference.Bgra[byteIndex + 1] == 0 &&
                            reference.Bgra[byteIndex + 2] == 0;
                        bool candidateBlack =
                            candidate.Bgra[byteIndex] == 0 &&
                            candidate.Bgra[byteIndex + 1] == 0 &&
                            candidate.Bgra[byteIndex + 2] == 0;
                        bool referenceWhite =
                            reference.Bgra[byteIndex] == 255 &&
                            reference.Bgra[byteIndex + 1] == 255 &&
                            reference.Bgra[byteIndex + 2] == 255;
                        bool candidateWhite =
                            candidate.Bgra[byteIndex] == 255 &&
                            candidate.Bgra[byteIndex + 1] == 255 &&
                            candidate.Bgra[byteIndex + 2] == 255;

                        if (candidateBlack && !referenceBlack)
                        {
                            introducedBlack++;
                        }
                        if (candidateWhite && !referenceWhite)
                        {
                            introducedWhite++;
                        }

                        if (x == 0 || y == 0 || x == reference.Width - 1 ||
                            y == reference.Height - 1)
                        {
                            continue;
                        }

                        int gradient =
                            Math.Abs(reference.Luma[pixelIndex + 1] -
                                     reference.Luma[pixelIndex - 1]) +
                            Math.Abs(reference.Luma[pixelIndex + reference.Width] -
                                     reference.Luma[pixelIndex - reference.Width]);
                        if (gradient < referenceEdgeThreshold)
                        {
                            continue;
                        }

                        edgeSamples++;
                        int localMinimum = 255;
                        int localMaximum = 0;
                        for (int localY = y - 1; localY <= y + 1; localY++)
                        {
                            int localRow = localY * reference.Width;
                            for (int localX = x - 1; localX <= x + 1; localX++)
                            {
                                int value = reference.Luma[localRow + localX];
                                if (value < localMinimum) localMinimum = value;
                                if (value > localMaximum) localMaximum = value;
                            }
                        }

                        int overshoot = candidateLuma < localMinimum
                            ? localMinimum - candidateLuma
                            : candidateLuma > localMaximum
                                ? candidateLuma - localMaximum
                                : 0;
                        overshootHistogram[overshoot]++;
                        if (overshoot > 0)
                        {
                            overshootPixels++;
                            overshootTotal += overshoot;
                            if (overshoot > maximumOvershoot) maximumOvershoot = overshoot;
                        }
                    }
                }

                double meanSquaredDifference = squaredDifferenceTotal / pixelCount;
                double p95Overshoot = PercentileFromHistogram(
                    overshootHistogram,
                    overshootPixels,
                    0.95,
                    excludeZero: true);

                return new ScreenshotComparison
                {
                    PixelCount = pixelCount,
                    MeanAbsoluteLumaDifference = Round(absoluteDifferenceTotal / pixelCount),
                    RootMeanSquareLumaDifference = Round(Math.Sqrt(meanSquaredDifference)),
                    PsnrDb = meanSquaredDifference == 0.0
                        ? double.PositiveInfinity
                        : Round(10.0 * Math.Log10((255.0 * 255.0) / meanSquaredDifference)),
                    IntroducedBlackClipPixelCount = introducedBlack,
                    IntroducedWhiteClipPixelCount = introducedWhite,
                    IntroducedBlackClipPixelPercent = Percent(introducedBlack, pixelCount),
                    IntroducedWhiteClipPixelPercent = Percent(introducedWhite, pixelCount),
                    ReferenceEdgeThreshold = referenceEdgeThreshold,
                    ReferenceEdgeSampleCount = edgeSamples,
                    HaloOvershootPixelCount = overshootPixels,
                    HaloOvershootAffectedEdgePercent = Percent(overshootPixels, edgeSamples),
                    MeanHaloOvershootPercent = overshootPixels == 0
                        ? 0.0
                        : Round(100.0 * overshootTotal / overshootPixels / 255.0),
                    P95HaloOvershootPercent = Round(100.0 * p95Overshoot / 255.0),
                    MaximumHaloOvershootPercent = Round(100.0 * maximumOvershoot / 255.0)
                };
            }
        }

        private static EdgeBandAnalysis AnalyzeEdgeBands(
            DecodedImage image,
            int requestedBandWidth,
            int nearBlackThreshold,
            double pillarColumnNearBlackMinimumPercent)
        {
            int bandWidth = Math.Min(requestedBandWidth, Math.Max(1, image.Width / 2));
            long[] nearBlackByColumn = new long[image.Width];
            long leftNearBlack = 0;
            long rightNearBlack = 0;
            long leftLuma = 0;
            long rightLuma = 0;

            for (int y = 0; y < image.Height; y++)
            {
                int row = y * image.Width;
                for (int x = 0; x < image.Width; x++)
                {
                    int pixelIndex = row + x;
                    int byteIndex = pixelIndex * 4;
                    bool nearBlack =
                        image.Bgra[byteIndex] <= nearBlackThreshold &&
                        image.Bgra[byteIndex + 1] <= nearBlackThreshold &&
                        image.Bgra[byteIndex + 2] <= nearBlackThreshold;
                    if (nearBlack) nearBlackByColumn[x]++;

                    if (x < bandWidth)
                    {
                        leftLuma += image.Luma[pixelIndex];
                        if (nearBlack) leftNearBlack++;
                    }
                    if (x >= image.Width - bandWidth)
                    {
                        rightLuma += image.Luma[pixelIndex];
                        if (nearBlack) rightNearBlack++;
                    }
                }
            }

            double columnRatioMinimum = pillarColumnNearBlackMinimumPercent / 100.0;
            int leftPillar = 0;
            while (leftPillar < image.Width &&
                   nearBlackByColumn[leftPillar] / (double)image.Height >= columnRatioMinimum)
            {
                leftPillar++;
            }

            int rightPillar = 0;
            while (rightPillar < image.Width &&
                   nearBlackByColumn[image.Width - 1 - rightPillar] /
                       (double)image.Height >= columnRatioMinimum)
            {
                rightPillar++;
            }

            bool entireFrameNearBlack = leftPillar == image.Width && rightPillar == image.Width;
            int activeWidth = entireFrameNearBlack
                ? 0
                : Math.Max(0, image.Width - leftPillar - rightPillar);
            long bandPixelCount = (long)bandWidth * image.Height;

            return new EdgeBandAnalysis
            {
                BandWidthPixels = bandWidth,
                NearBlackThreshold = nearBlackThreshold,
                PillarColumnNearBlackMinimumPercent =
                    Round(pillarColumnNearBlackMinimumPercent),
                LeftBandMeanLuma = Round(leftLuma / (double)bandPixelCount),
                RightBandMeanLuma = Round(rightLuma / (double)bandPixelCount),
                LeftBandNearBlackPercent = Percent(leftNearBlack, bandPixelCount),
                RightBandNearBlackPercent = Percent(rightNearBlack, bandPixelCount),
                DetectedLeftPillarWidthPixels = leftPillar,
                DetectedRightPillarWidthPixels = rightPillar,
                PillarSymmetryDeltaPixels = Math.Abs(leftPillar - rightPillar),
                EntireFrameNearBlack = entireFrameNearBlack,
                ActiveContentWidthPixels = activeWidth,
                ActiveContentAspectRatio = activeWidth == 0
                    ? 0.0
                    : Round(activeWidth / (double)image.Height)
            };
        }

        private static SharpnessAnalysis AnalyzeSharpness(
            DecodedImage image,
            EdgeBandAnalysis edgeBands,
            int edgeThreshold)
        {
            int left = edgeBands.EntireFrameNearBlack
                ? 0
                : edgeBands.DetectedLeftPillarWidthPixels;
            int rightExclusive = edgeBands.EntireFrameNearBlack
                ? image.Width
                : image.Width - edgeBands.DetectedRightPillarWidthPixels;
            if (rightExclusive - left < 3 || image.Height < 3)
            {
                return new SharpnessAnalysis { EdgeThreshold = edgeThreshold };
            }

            long sampleCount = 0;
            long edgeCount = 0;
            double gradientTotal = 0.0;
            double laplacianTotal = 0.0;
            double laplacianSquaredTotal = 0.0;
            long[] gradientHistogram = new long[1021];

            int startX = Math.Max(1, left + 1);
            int endX = Math.Min(image.Width - 1, rightExclusive - 1);
            for (int y = 1; y < image.Height - 1; y++)
            {
                int row = y * image.Width;
                for (int x = startX; x < endX; x++)
                {
                    int index = row + x;
                    int leftValue = image.Luma[index - 1];
                    int rightValue = image.Luma[index + 1];
                    int upValue = image.Luma[index - image.Width];
                    int downValue = image.Luma[index + image.Width];
                    int center = image.Luma[index];
                    int gradient =
                        Math.Abs(rightValue - leftValue) +
                        Math.Abs(downValue - upValue);
                    int laplacian =
                        (4 * center) - leftValue - rightValue - upValue - downValue;

                    sampleCount++;
                    gradientTotal += gradient;
                    gradientHistogram[gradient]++;
                    if (gradient >= edgeThreshold) edgeCount++;
                    laplacianTotal += laplacian;
                    laplacianSquaredTotal += laplacian * laplacian;
                }
            }

            if (sampleCount == 0)
            {
                return new SharpnessAnalysis { EdgeThreshold = edgeThreshold };
            }

            double laplacianMean = laplacianTotal / sampleCount;
            double laplacianVariance =
                (laplacianSquaredTotal / sampleCount) - (laplacianMean * laplacianMean);

            return new SharpnessAnalysis
            {
                SampleCount = sampleCount,
                EdgeThreshold = edgeThreshold,
                MeanAbsoluteGradient = Round(gradientTotal / sampleCount),
                P95AbsoluteGradient = Round(PercentileFromHistogram(
                    gradientHistogram,
                    sampleCount,
                    0.95,
                    excludeZero: false)),
                LaplacianVariance = Round(Math.Max(0.0, laplacianVariance)),
                EdgeDensityPercent = Percent(edgeCount, sampleCount)
            };
        }

        private static ToneAnalysis AnalyzeTone(DecodedImage image)
        {
            long black = 0;
            long white = 0;
            for (int index = 0; index < image.Luma.Length; index++)
            {
                int byteIndex = index * 4;
                bool isBlack =
                    image.Bgra[byteIndex] == 0 &&
                    image.Bgra[byteIndex + 1] == 0 &&
                    image.Bgra[byteIndex + 2] == 0;
                bool isWhite =
                    image.Bgra[byteIndex] == 255 &&
                    image.Bgra[byteIndex + 1] == 255 &&
                    image.Bgra[byteIndex + 2] == 255;
                if (isBlack) black++;
                if (isWhite) white++;
            }

            return new ToneAnalysis
            {
                PixelCount = image.PixelCount,
                ExactBlackPixelCount = black,
                ExactWhitePixelCount = white,
                ExactBlackPixelPercent = Percent(black, image.PixelCount),
                ExactWhitePixelPercent = Percent(white, image.PixelCount)
            };
        }

        private static long CountNonOpaquePixels(DecodedImage image)
        {
            long nonOpaque = 0;
            for (int index = 3; index < image.Bgra.Length; index += 4)
            {
                if (image.Bgra[index] != 255) nonOpaque++;
            }
            return nonOpaque;
        }

        private static DecodedImage Load(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("PNG path is required", nameof(path));
            }

            FileInfo file = new FileInfo(path);
            if (!file.Exists)
            {
                throw new FileNotFoundException("PNG does not exist", path);
            }
            if (!file.Extension.Equals(".png", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Only .png screenshot evidence is supported");
            }
            if (file.Length <= 0 || file.Length > MaximumFileSize)
            {
                throw new InvalidDataException("PNG byte size is outside the accepted evidence bounds");
            }

            byte[] encoded = File.ReadAllBytes(file.FullName);
            ValidatePngHeader(encoded, out int headerWidth, out int headerHeight);
            string sha256;
            using (SHA256 hash = SHA256.Create())
            {
                sha256 = BitConverter.ToString(hash.ComputeHash(encoded))
                    .Replace("-", string.Empty)
                    .ToLowerInvariant();
            }

            using (MemoryStream stream = new MemoryStream(encoded, writable: false))
            using (Image source = Image.FromStream(
                stream,
                useEmbeddedColorManagement: false,
                validateImageData: true))
            {
                if (!source.RawFormat.Guid.Equals(ImageFormat.Png.Guid) ||
                    source.Width != headerWidth || source.Height != headerHeight)
                {
                    throw new InvalidDataException("PNG decoder metadata does not match the IHDR contract");
                }

                using (Bitmap normalized = new Bitmap(
                    source.Width,
                    source.Height,
                    PixelFormat.Format32bppArgb))
                {
                    using (Graphics graphics = Graphics.FromImage(normalized))
                    {
                        graphics.CompositingMode = CompositingMode.SourceCopy;
                        graphics.DrawImage(
                            source,
                            new Rectangle(0, 0, source.Width, source.Height),
                            0,
                            0,
                            source.Width,
                            source.Height,
                            GraphicsUnit.Pixel);
                    }

                    Rectangle bounds = new Rectangle(0, 0, normalized.Width, normalized.Height);
                    BitmapData data = normalized.LockBits(
                        bounds,
                        ImageLockMode.ReadOnly,
                        PixelFormat.Format32bppArgb);
                    try
                    {
                        int rowBytes = normalized.Width * 4;
                        byte[] pixels = new byte[rowBytes * normalized.Height];
                        for (int y = 0; y < normalized.Height; y++)
                        {
                            IntPtr rowPointer = IntPtr.Add(
                                data.Scan0,
                                data.Stride >= 0
                                    ? y * data.Stride
                                    : (normalized.Height - 1 - y) * -data.Stride);
                            Marshal.Copy(rowPointer, pixels, y * rowBytes, rowBytes);
                        }

                        int[] luma = new int[normalized.Width * normalized.Height];
                        for (int pixelIndex = 0; pixelIndex < luma.Length; pixelIndex++)
                        {
                            int byteIndex = pixelIndex * 4;
                            int blue = pixels[byteIndex];
                            int green = pixels[byteIndex + 1];
                            int red = pixels[byteIndex + 2];
                            luma[pixelIndex] =
                                ((77 * red) + (150 * green) + (29 * blue) + 128) >> 8;
                        }

                        return new DecodedImage(
                            sha256,
                            encoded.LongLength,
                            normalized.Width,
                            normalized.Height,
                            pixels,
                            luma);
                    }
                    finally
                    {
                        normalized.UnlockBits(data);
                    }
                }
            }
        }

        private static void ValidatePngHeader(
            byte[] encoded,
            out int width,
            out int height)
        {
            if (encoded.Length < 33)
            {
                throw new InvalidDataException("PNG is too short to contain a complete IHDR chunk");
            }
            for (int index = 0; index < PngSignature.Length; index++)
            {
                if (encoded[index] != PngSignature[index])
                {
                    throw new InvalidDataException("File does not have the PNG signature");
                }
            }
            if (ReadBigEndianInt32(encoded, 8) != 13 ||
                encoded[12] != (byte)'I' || encoded[13] != (byte)'H' ||
                encoded[14] != (byte)'D' || encoded[15] != (byte)'R')
            {
                throw new InvalidDataException("PNG does not begin with a canonical IHDR chunk");
            }

            width = ReadBigEndianInt32(encoded, 16);
            height = ReadBigEndianInt32(encoded, 20);
            long pixelCount = (long)width * height;
            if (width <= 0 || height <= 0 || width > MaximumDimension ||
                height > MaximumDimension || pixelCount > MaximumPixelCount)
            {
                throw new InvalidDataException("PNG dimensions exceed the accepted evidence bounds");
            }
        }

        private static int ReadBigEndianInt32(byte[] data, int offset)
        {
            uint value =
                ((uint)data[offset] << 24) |
                ((uint)data[offset + 1] << 16) |
                ((uint)data[offset + 2] << 8) |
                data[offset + 3];
            if (value > int.MaxValue)
            {
                throw new InvalidDataException("PNG dimension is outside the signed integer range");
            }
            return (int)value;
        }

        private static double PercentileFromHistogram(
            long[] histogram,
            long sampleCount,
            double probability,
            bool excludeZero)
        {
            if (sampleCount <= 0) return 0.0;
            long rank = Math.Max(1L, (long)Math.Ceiling(sampleCount * probability));
            long cumulative = 0;
            int start = excludeZero ? 1 : 0;
            for (int index = start; index < histogram.Length; index++)
            {
                cumulative += histogram[index];
                if (cumulative >= rank) return index;
            }
            return histogram.Length - 1;
        }

        private static double Percent(long count, long total)
        {
            return total <= 0 ? 0.0 : Round(100.0 * count / total);
        }

        private static double Round(double value)
        {
            return Math.Round(value, 6, MidpointRounding.AwayFromZero);
        }

        private sealed class DecodedImage : IDisposable
        {
            public DecodedImage(
                string sha256,
                long byteSize,
                int width,
                int height,
                byte[] bgra,
                int[] luma)
            {
                Sha256 = sha256;
                ByteSize = byteSize;
                Width = width;
                Height = height;
                Bgra = bgra;
                Luma = luma;
            }

            public string Sha256 { get; }
            public long ByteSize { get; }
            public int Width { get; }
            public int Height { get; }
            public long PixelCount => (long)Width * Height;
            public byte[] Bgra { get; private set; }
            public int[] Luma { get; private set; }

            public void Dispose()
            {
                Bgra = Array.Empty<byte>();
                Luma = Array.Empty<int>();
            }
        }
    }
}
