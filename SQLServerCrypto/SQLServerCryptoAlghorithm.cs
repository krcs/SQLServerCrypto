using System;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace SQLServerCrypto
{
    public class SQLServerCryptoAlgorithm
    {
        public readonly SQLServerCryptoVersion Version;

        public readonly HashAlgorithm Hash;

        public readonly SymmetricAlgorithm Symmetric;

        public readonly int KeySize;

        public SQLServerCryptoAlgorithm(SQLServerCryptoVersion sqlCryptoVersion)
        {
            Version = sqlCryptoVersion;
            switch (Version)
            {
                case SQLServerCryptoVersion.V1:
                    Hash = SHA1.Create();
                    Symmetric = TripleDES.Create();
                    KeySize = 16;
                    break;
                case SQLServerCryptoVersion.V2:
                    Hash = SHA256.Create();
                    Symmetric = Aes.Create();
                    KeySize = 32;
                    break;
                default:
                    throw new Exception("Unsupported SQLServerCryptoVersion");
            }
            Symmetric.Padding = PaddingMode.PKCS7;
            Symmetric.Mode = CipherMode.CBC;
        }

        public void SetKeyFromPassPhrase(string passphrase)
            => Symmetric.Key = Hash
                .ComputeHash(Encoding.Unicode.GetBytes(passphrase))
                .Take(KeySize)
                .ToArray();
    }
}