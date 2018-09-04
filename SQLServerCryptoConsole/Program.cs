using System;
using SQLServerCrypto;

namespace SQLServerCryptoConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            // Example 3
            var ciphertext = "0x0100000038C94F7223E0BA2F772B611857F9D45DAF781607CC77F4A856CF08CC2DB9DF14A0593259CB3A4A2BFEDB485C002CA04B6A98BEB1B47EB107";
            var password = "test1234";
            var decrypted = SQLServerCryptoMethod.DecryptByPassPhraseWithoutVerification(password, ciphertext);
           
            Console.WriteLine(decrypted);
        }
    }
}