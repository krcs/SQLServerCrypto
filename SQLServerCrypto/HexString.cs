using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace SQLServerCrypto
{
    public sealed class HexString
    {
        private readonly byte[] _byteArray;

        private readonly Regex RegExValidation = new Regex("^[0-9a-fA-F]+$", RegexOptions.Compiled);
        private const string PREFIX = "0x";

        public HexString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("Input string is null or empty.");

            hexString = RemovePrefix(hexString);

            if (hexString.Length % 2 != 0)
                throw new ArgumentException("Invalid number of hexcharacters.");

            if (!RegExValidation.IsMatch(hexString))
                throw new ArgumentException("Input string does not contain hexadecimal characters.");

            _byteArray = HexStringToByteArray(hexString);
        }

        public HexString(byte[] byteArray)
        {
            if (byteArray == null)
                throw new ArgumentException("Input array is null.");

            if (byteArray.Length == 0)
                throw new ArgumentException("Input array is empty.");

            _byteArray = byteArray;
        }

        public string ValueWithoutPrefix => ByteArrayToHexString(_byteArray);
        
        public string ValueWithPrefix => PREFIX + ValueWithoutPrefix;
        
        public override string ToString() => ValueWithPrefix;

        public byte[] ToByteArray() => _byteArray;

        public static implicit operator string(HexString hexString) => hexString.ToString();

        public static implicit operator byte[](HexString hexString) => hexString._byteArray;

        private static string RemovePrefix(string input) => input.StartsWith(PREFIX) ? input.Remove(0, 2) : input;
        
        // https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array#321404
        // Looks nice but could be faster.
        private static byte[] HexStringToByteArray(string hexString) => Enumerable.Range(0, hexString.Length) 
               .Where(x => x % 2 == 0)
               .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
               .ToArray();

        private static string ByteArrayToHexString(byte[] byteArray) =>
            BitConverter.ToString(byteArray).Replace("-", string.Empty).ToLower();
    }
}