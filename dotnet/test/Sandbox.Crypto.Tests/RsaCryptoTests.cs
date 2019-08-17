using FluentAssertions;
using Xunit;

namespace Sandbox.Crypto.Tests
{
    public class RsaCryptoTests
    {
        private readonly string _plainText = "Here is some data to encrypt!";

        [Fact]
        public void GenerateXmlKeyPair_should_generate_key_pair()
        {
            var rsaCrypto = new RsaCrypto();

            var (privateKeyXml, publicKeyXml) = rsaCrypto.GenerateXmlKeyPair(2048);

            privateKeyXml.Should().NotBeNullOrWhiteSpace();
            publicKeyXml.Should().NotBeNullOrWhiteSpace();
        }

        [Fact]
        public void Crypto_should_encrypt_decrypt_with_new_key()
        {
            var rsaCrypto = new RsaCrypto();
            var (privateKeyXml, publicKeyXml) = rsaCrypto.GenerateXmlKeyPair(2048);

            var encrypted = rsaCrypto.Encrypt(_plainText, publicKeyXml);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);

            var decrypted = rsaCrypto.Decrypt(encrypted, privateKeyXml);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }

        [Theory]
        [InlineData("<RSAKeyValue><Modulus>jYYtkZhh9tTpvb1QaZs0QojwyrQWV6eXn5G5yTOH6YtDDimY4t1+QNi731AYV7qBd0l7ggd3Cb47Sb4b/z6cgc+jE8C2f0xrMzJepMGbUHq4w7knh0DTs7UXeVogl6cGnD0UvjJgaNlhOUhzgEy6ZuEtY0bVMjq2e57Yt0wXBys=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>")]
        public void Encrypt_should_encrypt_plainText(string publicKeyXml)
        {
            var rsaCrypto = new RsaCrypto();

            var encrypted = rsaCrypto.Encrypt(_plainText, publicKeyXml);

            encrypted.Should().NotBeNullOrWhiteSpace();
            encrypted.Should().NotBe(_plainText);
        }

        [Theory]
        [InlineData("Zt6LuDuZQidT/W9pgjERS+XLeK9Mb8wX2mCj7q4Cy3mUgzQ2/5DjHcYAZiqwO+1tXRFoVeT3MIJfnjYb4W8Tw8lz/0/8iVJmIkX3lBYzvtG4/Aum6hk1VCV+Vy3Z3aQabdJdXh7XeyZ719uPUi/pujEMbTbUT8Felj2FF6aDs2A=", "<RSAKeyValue><Modulus>jYYtkZhh9tTpvb1QaZs0QojwyrQWV6eXn5G5yTOH6YtDDimY4t1+QNi731AYV7qBd0l7ggd3Cb47Sb4b/z6cgc+jE8C2f0xrMzJepMGbUHq4w7knh0DTs7UXeVogl6cGnD0UvjJgaNlhOUhzgEy6ZuEtY0bVMjq2e57Yt0wXBys=</Modulus><Exponent>AQAB</Exponent><P>pLxw/fodDaG4OhYe5aFeaIinKusrQ73VdPfPDr/eusXDlQo7LgBfjWTXISNujDYu3PtSc4XkCV8LQ8T2PmcpFw==</P><Q>2+24ExRYbmlvjSHCUKNtz75NQtnRgxMY4FhdfTiheOKDG+uoJLOQHHaKB2lvd7DXy1TOxc/41upudhtB2Oo3DQ==</Q><DP>SIVYrMZV0fF2u8OPOIHwoM4/4WoD8t94P/Tz50daUxjKwCrv4JFzfzh8aG9DtGAKA2h0ZLz1pZZ8zAnCabhaYw==</DP><DQ>qKHG8cI46DgqE5IeF4yoZ5EoVqkDj7h165d1380rarBsDV2NaM7SIjD2NyauFJ1haYQWo/CKgefxWNgfjj5QhQ==</DQ><InverseQ>jvZZ8hX8WAVsV3r3o+gFg5XGENTeF+OK5hDEFLUa7LvDppF+uTGjFW7qyEVJkFZ5NHtVmpEf8NUqlLCGMThalA==</InverseQ><D>Jq6rG+WTuTy+2r65EPR8F0eI0U7h4HmNZu8U4dq05m/LFz7la/Twglb7GvGwhaITqwApwwO5VK9rUx+kVWLOsf9j5/m1K2GKLvTNtpsKPcJPi0Jmn8TzpvEj72lV6fr9qNJQyLBkWwdTRRyLFIZlSCKiz2ATEshRjTgBd/t7nsk=</D></RSAKeyValue>")]
        public void Decrypt_should_decrypt_cipherText(string cipherText, string privateKeyXml)
        {
            var rsaCrypto = new RsaCrypto();

            var decrypted = rsaCrypto.Decrypt(cipherText, privateKeyXml);

            decrypted.Should().NotBeNullOrWhiteSpace();
            decrypted.Should().Be(_plainText);
        }
    }
}
