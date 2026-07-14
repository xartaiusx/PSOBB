using PSOBB.AccountBroker.Contracts;
using PSOBB.AccountBroker.Provisioning;
using PSOBB.AccountBroker.Security;

namespace PSOBB.Accounts.Tests;

public sealed class CredentialPolicyTests
{
    private const string CrockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    [Theory]
    [InlineData("player01")]
    [InlineData("abc")]
    [InlineData("0123456789abcdef")]
    public void UsernamePolicyAcceptsThreeToSixteenLowercaseAsciiCharacters(
        string username)
    {
        Assert.True(GameUsernamePolicy.IsValid(username));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ab")]
    [InlineData("Player01")]
    [InlineData("player01\n")]
    [InlineData("pläyer")]
    [InlineData("0123456789abcdefg")]
    public void UsernamePolicyRejectsInvalidOrControlCharacterValues(string? username)
    {
        Assert.False(GameUsernamePolicy.IsValid(username));
    }

    [Theory]
    [InlineData("a")]
    [InlineData("Abc123")]
    [InlineData("0123456789ABCDEF")]
    public void PasswordPolicyAcceptsOneToSixteenAsciiAlphanumericCharacters(
        string password)
    {
        Assert.True(GamePasswordPolicy.IsValid(password));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("password with space")]
    [InlineData("password-with-dash")]
    [InlineData("0123456789ABCDEFG")]
    [InlineData("abc\n")]
    [InlineData("abc\r\n")]
    [InlineData("abc\t")]
    [InlineData("pässword")]
    public void PasswordPolicyRejectsEmptyLongOrShellAmbiguousValues(string? password)
    {
        Assert.False(GamePasswordPolicy.IsValid(password));
    }

    [Fact]
    public void GeneratedPasswordsUseSecureSixteenCharacterDefault()
    {
        var generator = new CrockfordGamePasswordGenerator();
        var passwords = Enumerable.Range(0, 128).Select(_ => generator.Generate()).ToArray();

        Assert.All(passwords, password =>
        {
            Assert.Equal(16, password.Length);
            Assert.All(password, character => Assert.Contains(character, CrockfordAlphabet));
        });
        Assert.Equal(passwords.Length, passwords.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void IdempotencyStoreRefusesToPersistASecret()
    {
        var store = new InMemoryIdempotencyStore();
        var requestId = Guid.NewGuid();
        _ = store.TryBegin(requestId, "fingerprint");
        var response = new BrokerResponse(
            1,
            requestId,
            BrokerResponseStatus.Succeeded,
            GamePassword: "SECRET");

        Assert.Throws<ArgumentException>(() => store.Complete(requestId, response));
    }
}
