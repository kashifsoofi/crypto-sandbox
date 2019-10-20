using System.Security.Cryptography;

namespace Sandbox.Crypto
{
    public static class RSAParametersExtensions
    {
        public static RsaPrivateKeyParameters ToPrivateKeyParameters(this RSAParameters rsaParameters)
        {
            return new RsaPrivateKeyParameters
            {
                D = rsaParameters.D,
                P = rsaParameters.P,
                Q = rsaParameters.Q,
                DP = rsaParameters.DP,
                DQ = rsaParameters.DQ,
                InverseQ = rsaParameters.InverseQ,
                Modulus = rsaParameters.Modulus,
                Exponent = rsaParameters.Exponent,
            };
        }

        public static RsaPublicKeyParameters ToPublicKeyParameters(this RSAParameters rsaParameters)
        {
            return new RsaPublicKeyParameters
            {
                Modulus = rsaParameters.Modulus,
                Exponent = rsaParameters.Exponent,
            };
        }
    }
}
