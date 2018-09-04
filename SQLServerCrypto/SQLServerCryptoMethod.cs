using System;
using System.Linq;

namespace SQLServerCrypto
{
    public static class SQLServerCryptoMethod
    {
        // SQL Server: https://docs.microsoft.com/en-us/sql/t-sql/functions/encryptbypassphrase-transact-sql
        public static HexString EncryptByPassPhrase(string passphrase, string cleartext, int add_authenticator, string authenticator)
            => EncryptByPassPhrase(passphrase, cleartext, add_authenticator, authenticator, SQLServerCryptoVersion.V1);

        public static HexString EncryptByPassPhrase(string passphrase, string cleartext, SQLServerCryptoVersion sqlServerCryptoVersion)
             => EncryptByPassPhrase(passphrase, cleartext, 0, string.Empty, sqlServerCryptoVersion);

        public static HexString EncryptByPassPhrase(string passphrase, string cleartext)
             => EncryptByPassPhrase(passphrase, cleartext, 0, string.Empty, SQLServerCryptoVersion.V1);

        public static HexString EncryptByPassPhrase(string passphrase, string cleartext, int add_authenticator, string authenticator, SQLServerCryptoVersion sqlServerCryptoVersion)
        {
            var sqlServerCryptoAlgorithm = new SQLServerCryptoAlgorithm(sqlServerCryptoVersion);
            sqlServerCryptoAlgorithm.SetKeyFromPassPhrase(passphrase);

            byte[] header = new SQLServerCryptoHeader() {
                Version = sqlServerCryptoVersion,
                InitializationVector = sqlServerCryptoAlgorithm.Symmetric.IV
            };
            var sqlServerCryptoMessage = new SQLServerCryptoMessage()
            {
                AddAuthenticator = add_authenticator > 0,
                Authenticator = authenticator
            };
            sqlServerCryptoMessage.CreateFromClearText(cleartext);

            byte[] message = sqlServerCryptoMessage;
            
            var encryptedMessage = sqlServerCryptoAlgorithm.Symmetric
                .CreateEncryptor()
                .TransformFinalBlock(message, 0, message.Length);

            return new HexString(header.Concat(encryptedMessage).ToArray());
        }

        // SQL Server: https://docs.microsoft.com/en-us/sql/t-sql/functions/decryptbypassphrase-transact-sql
        public static string DecryptByPassPhrase(string passphrase, string ciphertext) 
            => DecryptByPassPhrase(passphrase, new HexString(ciphertext), 0, string.Empty, true);

        public static string DecryptByPassPhrase(string passphrase, string ciphertext, int add_authenticator, string authenticator)   
            => DecryptByPassPhrase(passphrase, new HexString(ciphertext), add_authenticator, authenticator, true);

        public static string DecryptByPassPhraseWithoutVerification(string passphrase, string ciphertext)
          => DecryptByPassPhrase(passphrase, new HexString(ciphertext), 0, string.Empty, false);

        public static string DecryptByPassPhrase(string passphrase, HexString ciphertext, int add_authenticator, string authenticator, bool verify)
        {
            byte[] ciphertextBytes = ciphertext.ToByteArray();
            var version = (SQLServerCryptoVersion)ciphertextBytes[0];

            var sqlServerCryptoAlgorithm = new SQLServerCryptoAlgorithm(version);
            sqlServerCryptoAlgorithm.SetKeyFromPassPhrase(passphrase);

            var versionAndReservedSize = 4;
            var ivSize = sqlServerCryptoAlgorithm.KeySize / 2;

            var header = new SQLServerCryptoHeader
            {
                Version = version,
                InitializationVector = ciphertextBytes.Skip(versionAndReservedSize).Take(ivSize).ToArray()
            };
            sqlServerCryptoAlgorithm.Symmetric.IV = header.InitializationVector;

            var encryptedMessage = ciphertextBytes.Skip(versionAndReservedSize+ivSize).ToArray();
                       
            var decryptedMessage = sqlServerCryptoAlgorithm.Symmetric
                .CreateDecryptor()
                .TransformFinalBlock(encryptedMessage, 0, encryptedMessage.Length);

            // Message
            var sqlServerCryptoMessage = new SQLServerCryptoMessage()
            {
                AddAuthenticator = add_authenticator > 0,
                Authenticator = authenticator
            };
            sqlServerCryptoMessage.CreateFromDecryptedMessage(decryptedMessage, verify);
            
            return ByteArray2String(sqlServerCryptoMessage.MessageBytes);
        }
              
        private static string ByteArray2String(byte[] array)
            => array.Aggregate(string.Empty, (a, b) => a + Convert.ToChar(b));
    }
}