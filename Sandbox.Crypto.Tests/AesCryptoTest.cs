using System;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Sandbox.Crypto.Tests
{
    public class AesCryptoTest
    {
        private readonly string _plainText = "Here is some data to encrypt!";

        [Fact]
        public void Encrypt_should_encrypt_plainText()
        {
            var aesCrypto = new AesCrypto();

            var key = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N"));
            var encrypted = aesCrypto.Encrypt(_plainText, key);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);
            

            var decrypted = aesCrypto.Decrypt(encrypted, key);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Theory]
        [InlineData("EFb6BdUqhHJQRsVxnD53sSDfflNfWjntak2paSCpgJCsp0u46vIbHsK4mwX3g32UeA==", "B963FDC3-4580-468B-88BE-04F6630EF700")]
        public void Decrypt_should_decrypt_cipherText(string cipherText, string key)
        {
            var aesCrypto = new AesCrypto();

            var encodedKey = Encoding.UTF8.GetBytes(Guid.Parse(key).ToString("N"));
            var decrypted = aesCrypto.Decrypt(cipherText, encodedKey);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }
    }
}
