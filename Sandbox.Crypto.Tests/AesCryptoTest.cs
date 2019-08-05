using FluentAssertions;
using Xunit;

namespace Sandbox.Crypto.Tests
{
    public class AesCryptoTest
    {
        private readonly string _key = "56625DFA-A5DD-49F8-B640-75070C94D8BC";
        private readonly string _plainText = "Here is some data to encrypt!";
        private readonly string _cipherText = "";

        [Fact]
        public void Encrypt_should_encrypt_plainText()
        {
            var aesCrypto = new AesCrypto();

            var encrypted = aesCrypto.Encrypt(_plainText, _key);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);
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
