using System.Security.Cryptography;
using System.Text;

namespace OPENSSL
{
    // esta classe foi feita com base em https://learn.microsoft.com/en-us/dotnet/standard/security/cryptographic-signatures

    public static class Signature
    {
        public static RSAParameters Sign(string filePath)
        {
            using SHA256 alg = SHA256.Create();
            using var fStream = File.OpenRead(filePath);
            byte[] hash = alg.ComputeHash(fStream);

            RSAParameters sharedParameters;
            byte[] signedHash;

            // Generate signature
            using (RSA rsa = RSA.Create())
            {
                sharedParameters = rsa.ExportParameters(false);

                RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
                rsaFormatter.SetHashAlgorithm(nameof(SHA256));

                signedHash = rsaFormatter.CreateSignature(hash);
            }
            string text = $"\n{Convert.ToBase64String(hash)}\n{Convert.ToBase64String(signedHash)}";
            fStream.Flush();
            fStream.Close();
            using var stream = File.AppendText(filePath);
            stream.WriteLine(text);
            return sharedParameters;
        }

        public static bool VerifySign(string filePath, RSAParameters RSAParameters)
        {
            using SHA256 alg = SHA256.Create();
            var lines = File.ReadAllLines(filePath);
            byte[] hash = Convert.FromBase64String(lines[lines.Length - 2]);
            byte[] signedHash = Convert.FromBase64String(lines[lines.Length - 1]);

            // Verify signature
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(RSAParameters);

                RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
                rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

                return rsaDeformatter.VerifySignature(hash, signedHash);
            }
        }

    }
}
