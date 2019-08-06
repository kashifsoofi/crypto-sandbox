using FluentAssertions;
using Xunit;

namespace Sandbox.Crypto.Tests
{
    public class AesCryptoTest
    {
        private readonly string _key = "ibZ7u4TZ7/NAI+8AvMeo46Y9Hzfnxraw0LfeKb9T6WU=";
        private readonly string _plainText = "Here is some data to encrypt!";
        private readonly string _cipherText = "EIZC8KgE3IHcRjPU2KtYmegYcaE5AqUwF4MBzMMMA3wHkHqAFYpiTTKGQ4QOUKFmGg==";

        [Fact]
        public void Encrypt_should_encrypt_plainText()
        {
            var aesCrypto = new AesCrypto();

            var encrypted = aesCrypto.Encrypt(_plainText, _key);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);

            var decrypted = aesCrypto.Decrypt(encrypted, _key);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Fact]
        public void Decrypt_should_decrypt_cipherText()
        {
            var aesCrypto = new AesCrypto();

            var decrypted = aesCrypto.Decrypt(_cipherText, _key);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }
    }
}
