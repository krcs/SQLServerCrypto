using System.Data.SqlClient;
using System.Data;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLServerCrypto.Tests
{
    [TestClass]
    [Ignore] // Set instance of SQL Server and remove this attribute.
    public class SQLServerCryptoMethodsTestsWithSqlServer
    {
        private const string SQLSERVERINSTANCE = ".";

        public static string EncryptByPassPhrase_SQLServer(string passphrase, string cleartext)
        {
            var result = string.Empty;
            using (var sqlConnection = new SqlConnection($"Server={SQLSERVERINSTANCE};Trusted_Connection=yes"))
            {
                using (var sqlCommand = new SqlCommand { Connection = sqlConnection })
                {
                    sqlCommand.Parameters.Add("@PassPhrase", SqlDbType.VarChar).Value = passphrase;
                    sqlCommand.Parameters.Add("@ClearText", SqlDbType.VarChar, 8000).Value = cleartext;
                    sqlCommand.CommandText = "SELECT EncryptByPassPhrase(@PassPhrase, @ClearText)";
                    sqlConnection.Open();
                    result = new HexString((byte[])sqlCommand.ExecuteScalar());
                }
            }
            return result;
        }

        public static string DecryptPassPhrase_SQLServer(string passphrase, HexString cipher)
        {
            var result = string.Empty;
            using (var sqlConnection = new SqlConnection($"Server={SQLSERVERINSTANCE};Trusted_Connection=yes"))
            {
                using (var sqlCommand = new SqlCommand { Connection = sqlConnection })
                {
                    sqlCommand.Parameters.Add("@PassPhrase", SqlDbType.VarChar).Value = passphrase;
                    sqlCommand.Parameters.Add("@Cipher", SqlDbType.VarBinary).Value = (byte[])cipher;
                    sqlCommand.CommandText = "SELECT cast(DecryptByPassPhrase(@PassPhrase, @Cipher) as varchar)";
                    sqlConnection.Open();
                    result = (string)sqlCommand.ExecuteScalar();
                }
            }
            return result;
        }

        [TestMethod]
        public void SQLServerCryptoMethodsTestsWithSQLServer_EncryptByPassPhraseOnSQLServer_DecryptByPassPhrase_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var cipherFromSqlServer = EncryptByPassPhrase_SQLServer(passphrase, cleartext);
            var decryptedText = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, cipherFromSqlServer);
            Assert.AreEqual(cleartext, decryptedText);
        }

        [TestMethod]
        public void SQLServerCryptoMethodsTestsWithSqlServer_EncryptByPassPhrase_DecryptByPassPhraseOnSQLServer_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var cipher = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext);
            var decryptedText = DecryptPassPhrase_SQLServer(passphrase, cipher);
            Assert.AreEqual(cleartext, decryptedText);
        }
    }
}