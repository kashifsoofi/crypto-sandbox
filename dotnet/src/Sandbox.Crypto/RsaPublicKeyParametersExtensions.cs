using System.Security.Cryptography;

namespace Sandbox.Crypto
{
    public static class RsaPublicKeyParametersExtensions
    {
        public static RSAParameters ToRSAParameters(this RsaPublicKeyParameters rsaPublicKeyParameters)
        {
            return new RSAParameters
            {
                Modulus = rsaPublicKeyParameters.Modulus,
                Exponent = rsaPublicKeyParameters.Exponent,
            };
        }
    }
}
