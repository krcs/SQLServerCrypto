using System.Collections.Generic;

namespace SQLServerCrypto
{
    public class SQLServerCryptoHeader
    {
        public SQLServerCryptoVersion Version = SQLServerCryptoVersion.V1;
        public byte[] Reserved = { 0, 0, 0 };
        public byte[] InitializationVector = { };

        public SQLServerCryptoHeader(SQLServerCryptoVersion sqlServerCryptoVersion = SQLServerCryptoVersion.V1)
            => Version = sqlServerCryptoVersion;

        public static implicit operator byte[] (SQLServerCryptoHeader sqlServerCryptoHeader) => sqlServerCryptoHeader.ToByteArray();

        public byte[] ToByteArray()
        {
            var result = new List<byte>();
            result.Add((byte)Version);
            result.AddRange(Reserved);
            result.AddRange(InitializationVector);
            return result.ToArray();
        }
    }
}