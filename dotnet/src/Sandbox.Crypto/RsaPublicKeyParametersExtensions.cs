using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

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

        public static RsaKeyParameters ToRsaKeyParameters(this RsaPublicKeyParameters rsaPublicKeyParameters)
        {
            return new RsaKeyParameters(
                false,
                new BigInteger(1, rsaPublicKeyParameters.Modulus),
                new BigInteger(1, rsaPublicKeyParameters.Exponent));
        }
    }
}
