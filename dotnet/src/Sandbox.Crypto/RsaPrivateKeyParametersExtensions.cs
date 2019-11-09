using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Sandbox.Crypto
{
    public static class RsaPrivateKeyParametersExtensions
    {
        public static RSAParameters ToRSAParameters(this RsaPrivateKeyParameters rsaPrivateKeyParameters)
        {
            return new RSAParameters
            {
                D = rsaPrivateKeyParameters.D,
                P = rsaPrivateKeyParameters.P,
                Q = rsaPrivateKeyParameters.Q,
                DP = rsaPrivateKeyParameters.DP,
                DQ = rsaPrivateKeyParameters.DQ,
                InverseQ = rsaPrivateKeyParameters.InverseQ,
                Modulus = rsaPrivateKeyParameters.Modulus,
                Exponent = rsaPrivateKeyParameters.Exponent,
            };
        }

        public static RsaPrivateCrtKeyParameters ToRsaPrivateCrtKeyParameters(this RsaPrivateKeyParameters rsaPrivateKeyParameters)
        {
        // ref: https://src-bin.com/en/q/e7ddf
            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rsaPrivateKeyParameters.Modulus),
                new BigInteger(1, rsaPrivateKeyParameters.Exponent),
                new BigInteger(1, rsaPrivateKeyParameters.D),
                new BigInteger(1, rsaPrivateKeyParameters.P),
                new BigInteger(1, rsaPrivateKeyParameters.Q),
                new BigInteger(1, rsaPrivateKeyParameters.DP),
                new BigInteger(1, rsaPrivateKeyParameters.DQ),
                new BigInteger(1, rsaPrivateKeyParameters.InverseQ));
        }
    }
}
