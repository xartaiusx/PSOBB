using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PSOBB.AccountBroker.Security;

public static partial class GameUsernamePolicy
{
    public const int MinimumLength = 3;
    public const int MaximumLength = 16;

    public static bool IsValid(string? value) =>
        value is not null && GameUsernameRegex().IsMatch(value);

    [GeneratedRegex(@"\A[a-z0-9]{3,16}\z", RegexOptions.CultureInvariant)]
    private static partial Regex GameUsernameRegex();
}

public static partial class GamePasswordPolicy
{
    public const int MinimumLength = 1;
    public const int MaximumLength = 16;

    public static bool IsValid(string? value) =>
        value is not null && GamePasswordRegex().IsMatch(value);

    [GeneratedRegex(@"\A[A-Za-z0-9]{1,16}\z", RegexOptions.CultureInvariant)]
    private static partial Regex GamePasswordRegex();
}

public interface IGamePasswordGenerator
{
    string Generate();
}

public sealed class CrockfordGamePasswordGenerator : IGamePasswordGenerator
{
    // Generate at the protocol maximum by default, but do not require players
    // to use this exact length when a user-selected password flow is added.
    public const int PasswordLength = GamePasswordPolicy.MaximumLength;
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public string Generate()
    {
        Span<char> value = stackalloc char[PasswordLength];
        for (var index = 0; index < value.Length; index++)
        {
            value[index] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }

        return new string(value);
    }
}
