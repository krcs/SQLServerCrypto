using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace SQLServerCrypto
{
    public class SQLServerCryptoMessage
    {
        private const uint MAGIC_NUMBER = 0xbaad_f00d;

        public uint MagicNumber { get; private set; }

        public ushort IntegrityBytesLength { get; private set; }

        public ushort PlainTextLength { get; private set; }

        public byte[] IntegrityBytes;

        public byte[] MessageBytes;

        public bool AddAuthenticator = false;

        private string _authenticator;

        public string Authenticator
        {
            get => _authenticator;

            set =>
                _authenticator = value.Length > 128 ?
                    throw new ArgumentOutOfRangeException("The size of the authenticator string should not exceed 128 bytes.")
                    : value;
        }
        
        public SQLServerCryptoMessage() =>  MagicNumber = MAGIC_NUMBER;
        
        public void CreateFromClearText(string cleartext)
        {
            MessageBytes = Encoding.ASCII.GetBytes(cleartext);

            if (MessageBytes.Length > 8000)
                throw new ArgumentOutOfRangeException("The size of the cleartext string should not exceed 8000 bytes.");

            MagicNumber = MAGIC_NUMBER;
            IntegrityBytesLength = 0;

            PlainTextLength = (ushort)MessageBytes.Length;

            if (AddAuthenticator)
            {
                var integrityMessage = MessageBytes.Concat(Encoding.ASCII.GetBytes(Authenticator)).ToArray();
                IntegrityBytes = SHA1.Create().ComputeHash(integrityMessage);
                IntegrityBytesLength = (ushort)IntegrityBytes.Length;
            }
        }

        public void CreateFromDecryptedMessage(byte[] decryptedMessage, bool verify = true)
        {
            MagicNumber = BitConverter.ToUInt32(decryptedMessage, 0);
            IntegrityBytesLength = BitConverter.ToUInt16(decryptedMessage, 4);
            PlainTextLength = BitConverter.ToUInt16(decryptedMessage, 6);

            var messageWithoutHeader = decryptedMessage.Skip(8);

            if (IntegrityBytesLength > 0 || IntegrityBytesLength < 0xffff)
                IntegrityBytes = messageWithoutHeader.Take(IntegrityBytesLength).ToArray();

            if (IntegrityBytesLength != 0xffff)
                MessageBytes = messageWithoutHeader.Skip(IntegrityBytesLength).ToArray();
            else
                MessageBytes = messageWithoutHeader.ToArray();

            if (verify)
                VerifyMessage();
        }
        
        private void VerifyMessage()
        {
            if (MagicNumber != MAGIC_NUMBER)
                throw new Exception("Message integrity error. Magic numbers are different.");

            var integrityMessage = MessageBytes.Concat(Encoding.ASCII.GetBytes(Authenticator)).ToArray();
            var hash = SHA1.Create().ComputeHash(integrityMessage);

            if (IntegrityBytes.Length > 0 && !hash.SequenceEqual(IntegrityBytes))
                throw new Exception("Message integrity error. Invalid authenticator.");
            
            if (PlainTextLength != MessageBytes.Length)
                throw new Exception("Message integrity error. Invalid message length.");
        }

        public static implicit operator byte[](SQLServerCryptoMessage sqlServerCryptoMessage) => sqlServerCryptoMessage.ToByteArray();
        
        public byte[] ToByteArray()
        {
            byte[] result;
            using (var memoryStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(memoryStream))
                {
                    binaryWriter.Write(MagicNumber);
                    binaryWriter.Write(IntegrityBytesLength);
                    binaryWriter.Write(PlainTextLength);

                    if (IntegrityBytes != null)
                        binaryWriter.Write(IntegrityBytes);

                    if (MessageBytes != null)
                        binaryWriter.Write(MessageBytes);
                }
                result = memoryStream.ToArray();
            }
            return result;
        }
    }
}