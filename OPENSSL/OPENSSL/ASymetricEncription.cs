using System.Security.Cryptography;
using System.Text;

namespace OPENSSL
{
    // esta classe é feita com base em https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa?view=net-8.0
    //https://learn.microsoft.com/en-us/dotnet/standard/security/decrypting-data



    public static class ASymetricEncription
    {
        public static (RSAParameters, string, string) EncryptAesKey()
        {
            RSA rsa = RSA.Create();
            // busca da chave privada
            var publickey = rsa.ExportParameters(true);
            using Aes aes = Aes.Create();
            // aqui poderiamos usar o IV tamb[em para depois enviar pela Rede
            var eBuffer = rsa.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);
            return (publickey, Convert.ToBase64String(eBuffer), Convert.ToBase64String(aes.Key));
        }

        public static string DecryptDataB64(string inName, RSAParameters parameters)
        {
            RSA rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            var eBuffer = rsa.Decrypt(Convert.FromBase64String(inName), RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(eBuffer);
        }
    }
}