using System.Security.Cryptography;

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
    }
}
