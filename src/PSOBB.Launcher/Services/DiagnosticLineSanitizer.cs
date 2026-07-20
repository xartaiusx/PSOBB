using System.Text;
using System.Text.RegularExpressions;

namespace PSOBB.Launcher.Services;

internal sealed class DiagnosticLineSanitizer
{
    private static readonly Regex TerminalControlSequence = new(
        "\\x1B(?:\\[[0-?]*[ -/]*[@-~]|\\][^\\x07\\x1B]*(?:\\x07|\\x1B\\\\|$))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly DiagnosticReportBuilder _reportSanitizer = new();

    public string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var withoutTerminalSequences = TerminalControlSequence.Replace(value, string.Empty);
        var normalized = new StringBuilder(withoutTerminalSequences.Length);
        foreach (var character in withoutTerminalSequences)
        {
            if (!char.IsControl(character) || character == '\t')
            {
                normalized.Append(character);
            }
        }

        return _reportSanitizer.Sanitize(normalized.ToString()).Trim();
    }
}
