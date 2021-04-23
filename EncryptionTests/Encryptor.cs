using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionTests
{
    public class Encryptor
    {
        private readonly AesCryptoServiceProvider _cryptoProvider;
        private ICryptoTransform _crypto;

        public Encryptor()
        {
            _cryptoProvider = new AesCryptoServiceProvider
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };
        }

        public string AesEncrypt(string vat, string key, string vector)
        {
            _crypto = _cryptoProvider.CreateEncryptor(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(vector));
            var encrypted = _crypto.TransformFinalBlock(Encoding.ASCII.GetBytes(vat), 0, Encoding.ASCII.GetBytes(vat).Length);
            _crypto.Dispose();

            return Convert.ToBase64String(encrypted);

            //return $"{str}".Base64Encode();
        }
        
        public string AesDecrypt(string message, string key, string vector)
        {
            _crypto = _cryptoProvider.CreateDecryptor(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(vector));
            var decrypted = _crypto.TransformFinalBlock(Convert.FromBase64String(message), 0, Convert.FromBase64String(message).Length);
            _crypto.Dispose();
            return Encoding.ASCII.GetString(decrypted);
        }


        public string RsaEncryptFromXMLKey(string textToEncrypt, string publicKeyString)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString.ToString());
                    var encryptedData = rsa.Encrypt(bytesToEncrypt, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public string RsaDecryptFromXMLKey(string textToDecrypt, string privateKeyString)
        {
            var bytesToDescrypt = Encoding.UTF8.GetBytes(textToDecrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {

                    // server decrypting data with private key                    
                    rsa.FromXmlString(privateKeyString);

                    var resultBytes = Convert.FromBase64String(textToDecrypt);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }


        public string RsaDecrypt(string encryptedText, string decryptKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    var byteArray = Convert.FromBase64String(decryptKey);
                    rsa.ImportRSAPrivateKey(byteArray, out _);

                    var resultBytes = Convert.FromBase64String(encryptedText);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public string RsaEncrypt(string text, string encryptKey)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(text);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    var byteArray = Convert.FromBase64String(encryptKey);
                    rsa.ImportSubjectPublicKeyInfo(byteArray, out _);

                    var encryptedData = rsa.Encrypt(bytesToEncrypt, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

    }
}
