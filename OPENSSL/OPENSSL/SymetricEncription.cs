using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OPENSSL
{
    // esta classe é feita com base em https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-8.0
    //https://learn.microsoft.com/en-us/dotnet/standard/security/decrypting-data
    //https://stackoverflow.com/questions/8583112/padding-is-invalid-and-cannot-be-removed

    public static class SymetricEncription
    {
        private const int DerivationIterations = 10000;

        public static (byte[], byte[]) GenerateKeyAndVector()
        {

            Aes aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();

            var key = aes.Key;
            var IV = aes.IV;

            return (key, IV);
        }

        public static string EncryptDataB64(string inName, byte[] aesKey, byte[] aesIV)
        {
            // bufffer de ajudar com o tamanho do texto de entrada
            byte[] bytesBuff = Encoding.Unicode.GetBytes(inName);
            // criação objeto de criptografia aes
            using Aes aes = Aes.Create();
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = aesKey;
            aes.IV = aesIV;
            using var memoryStream = new MemoryStream(); ;// stream auxiliar para escrever os dados no novo buffer
            //stream de criptografia usando a chave aes e vetor aes do método
            using CryptoStream encStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

            Console.WriteLine("Encrypting...");
            // escreve o novo buffer gerado pelo criptografia aes no buffer original
            encStream.Write(bytesBuff, 0, bytesBuff.Length);
            encStream.FlushFinalBlock();

            // tranforma para base 64
            string encryptedText = Convert.ToBase64String(memoryStream.ToArray());
            return encryptedText;
        }

        public static string DepcryptB64(string cipherText, byte[] aesKey, byte[] aesIV)
        {
            byte[] bytesBuff = Convert.FromBase64String(cipherText);
            string plainText;

            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = aesKey;
                aes.IV = aesIV;

                using (var memoryStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cStream.Write(bytesBuff, 0, bytesBuff.Length);
                        cStream.FlushFinalBlock();
                    }

                    plainText = Encoding.Unicode.GetString(memoryStream.ToArray());
                    memoryStream.Close();
                }

                aes.Clear();
            }

            return plainText;
        }
    }
}