using System.IO;
using System.Security.Cryptography;

namespace FileEncryptionAndDecryption.Cryptography
{
    public abstract class CryptographicOperator
    {
        protected FileInfo fileToProcess;
        protected string outputFileName;
        protected const int bufferSize = 1024;

        protected CipherMode GetCipherMode(string mode)
        {
            switch (mode)
            {
                case "ECB":
                    return CipherMode.ECB;
                case "CBC":
                    return CipherMode.CBC;
                case "CFB":
                    return CipherMode.CFB;
                case "OFB":
                    return CipherMode.OFB;
                default:
                    return CipherMode.ECB;
            }
        }
    }
}
