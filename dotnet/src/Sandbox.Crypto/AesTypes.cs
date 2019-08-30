using System;
namespace Sandbox.Crypto
{
    public enum CipherMode
    {
        CBC,
        GCM
    }

    public enum Padding
    {
        NoPadding,
        PKCS7
    }
}
