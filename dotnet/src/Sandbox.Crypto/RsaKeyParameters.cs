using System;
using Org.BouncyCastle.Math;

namespace Sandbox.Crypto
{
    public class RsaPrivateKeyParameters
    {
        public byte[] D { get; set; }
        public byte[] P { get; set; }
        public byte[] Q { get; set; }
        public byte[] DP { get; set; }
        public byte[] DQ { get; set; }
        public byte[] InverseQ { get; set; }
        public byte[] Modulus { get; set; }
        public byte[] Exponent { get; set; }
    }

    public class RsaPublicKeyParameters
    {
        public byte[] Modulus { get; set; }
        public byte[] Exponent { get; set; }
    }
}
