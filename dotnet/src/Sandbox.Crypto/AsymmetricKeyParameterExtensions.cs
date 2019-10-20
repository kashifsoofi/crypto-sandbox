using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Sandbox.Crypto
{
    public static class AsymmetricKeyParameterExtensions
    {
        public static RsaPrivateKeyParameters ToPrivateKeyParameters(this AsymmetricKeyParameter keyParameters)
        {
            var rsaParameters = keyParameters as RsaPrivateCrtKeyParameters;
            return new RsaPrivateKeyParameters
            {
                D = rsaParameters.Exponent.ToByteArrayUnsigned(),
                P = rsaParameters.P.ToByteArrayUnsigned(),
                Q = rsaParameters.Q.ToByteArrayUnsigned(),
                DP = rsaParameters.DP.ToByteArrayUnsigned(),
                DQ = rsaParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaParameters.QInv.ToByteArrayUnsigned(),
                Modulus = rsaParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaParameters.PublicExponent.ToByteArrayUnsigned(),
            };
        }

        public static RsaPublicKeyParameters ToPublicKeyParameters(this AsymmetricKeyParameter keyParameters)
        {
            var rsaParameters = keyParameters as RsaKeyParameters;
            return new RsaPublicKeyParameters
            {
                Modulus = rsaParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaParameters.Exponent.ToByteArrayUnsigned(),
            };
        }
    }
}
