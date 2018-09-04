using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLServerCrypto.Tests
{
    [TestClass]
    public class SQLServerCryptoMethodsTests
    {
        [TestMethod]
        public void SQLServerCryptoMethods_EncryptByPassPhrase_DecryptByPassPhrase_Same_Passwords_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var ciphertext = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext, SQLServerCryptoVersion.V1);
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_EncryptByPassPhrase_DecryptByPassPhrase_Same_Passwords_And_Authenticator_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var authenticator = "authenticator";
            var ciphertext = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext, 1, authenticator, SQLServerCryptoVersion.V1);
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext, 1, authenticator);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void SQLServerCryptoMethods_EncryptByPassPhrase_DecryptByPassPhrase_Same_Passwords_And_Different_Authenticators_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var encryptionAuthenticator = "encryptionAuthenticator";
            var decryptionAuthenticator = "decryptionAuthenticator";
            var ciphertext = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext, 1, encryptionAuthenticator, SQLServerCryptoVersion.V1);
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext, 1, decryptionAuthenticator);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_EncryptByPassPhrase_DecryptByPassPhrase_Same_Passwords_AddAuthenticator_Equals_0_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var encryptionAuthenticator = "encryptionAuthenticator";
            var decryptionAuthenticator = "decryptionAuthenticator";
            var ciphertext = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext, 0, encryptionAuthenticator, SQLServerCryptoVersion.V1);
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext, 0, decryptionAuthenticator);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_Ciphertext_From_SQLServer_DecryptByPassPhrase_Same_Passwords_And_Authenticators_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var ciphertext = "0x01000000C73EB93FCAB01B36C46D7AC0C965B8F60DECDBD52FD03019924A7AF5D584D95B54E049B7642151B36466DA8554743112867FA4B402B61309";
            var authenticator = "authenticator";
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext, 1, authenticator);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_DecryptByPassPhrase_Ciphertext_From_SQLServer_V1()
        {
            var passphrase = "tEst1234";
            var cleartext = "Hello world.";
            var ciphertext = "0x010000001E8E7DCDBD4061B951999E25D18445D2305474D2D71EEE98A241C755246F58AB";
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext);
            Assert.AreEqual(cleartext, decryptionResult);
        }
               
        [TestMethod]
        public void SQLServerCryptoMethods_DecryptByPassPhrase_Ciphertext_From_SQLServer_V2()
        {
            var passphrase = "tEst1234";
            var cleartext = "Hello world.";
            var ciphertext = "0x02000000FFE880C0354780481E64EF25B6197A02E2A854A4BA9D8D9BDDFDAB27EB56537ABDA0B1D9C4D1050C91B313550DECF429";
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_DecryptByPassPhrase_With_Authenticator_Ciphertext_From_SQLServer_V2()
        {
            var passphrase = "tEst1234";
            var cleartext = "Hello world.";
            var authenticator = "authenticator";
            var ciphertext = "0x02000000E920E0F4BDD60C4151FDE26351A1E6CC6C40DA16BBD1338FD66103F616D86D5A4BD8138821D0D849A320C9A5AEAEB28E50CCAAD8961888AF01D593472EEAA744";
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext, 1, authenticator);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        [ExpectedException (typeof(ArgumentOutOfRangeException))]
        public void SQLServerCryptoMethods_EncryptByPassPhrase_Length_Of_ClearText_GreaterThan_8000()
        {
            var passphrase = "tEst1234";
            var cleartext = Enumerable.Repeat("Encryption", 800).Aggregate(string.Empty, (a, b) => a + b) + "Error";
            var ciphertext = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext);
        }
    }
}
