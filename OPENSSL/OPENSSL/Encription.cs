using System.Text;
using System.Security.Cryptography;

namespace OPENSSL
{
    public class Encription
    {
        public static string ComputeHash(string input)
        {
            var algorithm = SHA256.Create();
            byte[] inputeBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashedBytes = algorithm.ComputeHash(inputeBytes);
            return BitConverter.ToString(hashedBytes);
        }
    }
}