using System.Security.Cryptography;
using System.Text;

namespace OPENSSL
{
    public static class Hasher
    {
        public static string CreateMD5(string input)
        {
            // Use input string to calculate MD5 hash
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = MD5.HashData(inputBytes);

            return Convert.ToHexString(hashBytes);
        }
    }
}
