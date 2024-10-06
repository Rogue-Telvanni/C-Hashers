// See https://aka.ms/new-console-template for more information

using System.Security.Cryptography;
using OPENSSL;

// Hash

Console.WriteLine("HASH MD5");
string hashed = Hasher.CreateMD5("Hello MD5");
Console.WriteLine(hashed);
Console.WriteLine();

// Symetric Keys
Console.WriteLine("Simétrico");
(byte[] key, byte[] IV) = SymetricEncription.GenerateKeyAndVector();
string cryptedMessage = SymetricEncription.EncryptDataB64("Linux é legal", key, IV);
Console.WriteLine(cryptedMessage);
string plainMessage = SymetricEncription.DepcryptB64(cryptedMessage, key, IV);
Console.WriteLine(plainMessage);
Console.WriteLine();

// Asymetric Keys
Console.WriteLine("Asimétrico");
(RSAParameters public_key, string rsa_string, string aeskey) = ASymetricEncription.EncryptAesKey();
Console.WriteLine(rsa_string);
var plainText = ASymetricEncription.DecryptDataB64(rsa_string, public_key);
Console.WriteLine($"rsa = funcionou {plainText == aeskey}");
Console.WriteLine();

//Digital Sign
Console.WriteLine("Assinatura Digital");
string file = "teste.txt";
var data = Signature.Sign(file);
Console.WriteLine(File.ReadAllText(file));
Console.WriteLine($"Assinatura Válida: {Signature.VerifySign(file, data)}");

// mantém o terminal ativo
Console.ReadKey();