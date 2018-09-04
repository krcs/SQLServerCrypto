using System;
using SQLServerCrypto;

namespace SQLServerCrypto.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            // Example 1
            System.Console.WriteLine("Example 1");
            var passphrase = "password1234";
            var decryptedText = SQLServerCryptoMethod.DecryptByPassPhrase(@passphrase, "0x010000003296649D6782CFD72B8145A07F2C7D7FE3D8B80CF48DA419E94FABC90EEB928D");

            System.Console.WriteLine($" Result: {decryptedText}");
            
            // Example 2
            System.Console.WriteLine("Example 2");

            passphrase = "password1234";
            var encrypted = SQLServerCryptoMethod.EncryptByPassPhrase(@passphrase, "Hello World.");

            Console.WriteLine($" Result: {encrypted}");
        }
    }
}
