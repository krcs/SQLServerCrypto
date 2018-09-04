using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SQLServerCrypto.Tests
{
    [TestClass]
    public class SQLServerCryptoMethodsTests
    {
        [TestMethod]
        public void SQLServerCryptoMethods_EncryptByPassPhrase_DecryptByPassPhrase_Same_Password_V1()
        {
            var passphrase = "test1234";
            var cleartext = "Hello world.";
            var ciphertext = SQLServerCryptoMethod.EncryptByPassPhrase(passphrase, cleartext, SQLServerCryptoVersion.V1);
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_DecryptByPassPhrase_Cipher_From_SQLServer_V1()
        {
            var passphrase = "tEst1234";
            var cleartext = "Hello world.";
            var ciphertext = "0x010000001E8E7DCDBD4061B951999E25D18445D2305474D2D71EEE98A241C755246F58AB";
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext);
            Assert.AreEqual(cleartext, decryptionResult);
        }

        [TestMethod]
        public void SQLServerCryptoMethods_DecryptByPassPhrase_Cipher_From_SQLServer_V2()
        {
            var passphrase = "tEst1234";
            var cleartext = "Hello world.";
            var ciphertext = "0x02000000FFE880C0354780481E64EF25B6197A02E2A854A4BA9D8D9BDDFDAB27EB56537ABDA0B1D9C4D1050C91B313550DECF429";
            var decryptionResult = SQLServerCryptoMethod.DecryptByPassPhrase(passphrase, ciphertext);
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
