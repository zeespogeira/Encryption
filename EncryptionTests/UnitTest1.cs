using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace EncryptionTests
{
    [TestFixture]
    public class Tests
    {
        [SetUp]
        public void Setup()
        {

        }

        [Test]
        public void Test_AES_Encryption()
        {
            //arrange
            var key = "phee8wieH4eebeem";
            var vector = "eech1iedo4aiLah3";
            var str = "123456789";

            var encryptor = new Encryptor();

            //act
            var encryptorResult = encryptor.AesEncrypt(str, key, vector);
            var decryptorResult = encryptor.AesDecrypt(encryptorResult, key, vector);

            //assert
            Assert.AreEqual(str, decryptorResult);
        }

        [Test]
        public void Test_RSA_Encryption()
        {
            //arrange
            var str = "123456789";

            var encryptor = new Encryptor();

            //act
            var encryptResult = encryptor.RsaEncrypt(str, File.ReadAllText("public-key.xml"));
            var decryptResult = encryptor.RsaDecrypt(encryptResult, File.ReadAllText("private-key.xml"));

            //assert
            Assert.AreEqual(encryptResult, decryptResult);
        }
    }
}