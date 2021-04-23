using System.IO;
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
            var encryptResult = encryptor.RsaEncryptFromXMLKey(str, File.ReadAllText("public-key.xml"));
            var decryptResult = encryptor.RsaDecryptFromXMLKey(encryptResult, File.ReadAllText("private-key.xml"));

            //assert
            Assert.AreEqual(str, decryptResult);
        }

        [Test]
        public void EncryptionDecryptionTest()
        {
            var publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqry3I4Sw+FmIKK2C3WApRl5mZnWuEkyrvAIWLL9x7UKqZePliSMCUXRE1aj/9fwJs/avQF2OkpYllhZ2VrgbbxqSDdxKSFXwCiZ2geYTrrRoX/YSXlYiC3kI+7ShnMqHqKKhZ5vrwzKYK/ZpBMlX3JHm2KhuQQig4mgoQisMKXIDKALIpZNIFexJBMdr5OY5EOOoq3PnTv7L0zWyhoYH7xONGJXF+BGUk+okkeoibQ1A+RrQmlb2aH5AK76qpB9TaK0CDxlZO6OHFusRr/FQSoPqgCCFENSbLdOQnIY00qsZe2QsxfNeFHmhls/WgmIiW0FAuHEj81ZGEBzqSJOZQIDAQAB";
            var privateKey = "MIIEowIBAAKCAQEAyqry3I4Sw+FmIKK2C3WApRl5mZnWuEkyrvAIWLL9x7UKqZePliSMCUXRE1aj/9fwJs/avQF2OkpYllhZ2VrgbbxqSDdxKSFXwCiZ2geYTrrRoX/YSXlYiC3kI+7ShnMqHqKKhZ5vrwzKYK/ZpBMlX3JHm2KhuQQig4mgoQisMKXIDKALIpZNIFexJBMdr5OY5EOOoq3PnTv7L0zWyhoYH7xONGJXF+BGUk+okkeoibQ1A+RrQmlb2aH5AK76qpB9TaK0CDxlZO6OHFusRr/FQSoPqgCCFENSbLdOQnIY00qsZe2QsxfNeFHmhls/WgmIiW0FAuHEj81ZGEBzqSJOZQIDAQABAoIBADMeHxeGNjF13p6Iq8YEIyiBXmxhowjkXYZGQLSuoNgIT+IquiqymSeVloB8L+1N9+KyNofJoJpfOizhp/fstgK3rU79vOsU39813mhh1ga1lD5Z0qHlm3Dtskdl62/CCHOlp67AIYdTgJAWipyZv6ltV6ZXoFbcNiBbTEqRt2ylUHROQEUhzGMpV0ws+se+6lyz9EKkFVxuC2Ysr2FrzoIZms7SQpEiJNEm7qkX/PEr5xvMo9G/HuZSSu1WguZZB2jI5OAd3mvGMVPKrqesVqtdqlcLKvAw2/48y6B1nhRtyXJmFLfvLsnoknlay3y8FB4PZWAI9L6wv4eAGtGVtUECgYEA+02aj5NO9ukUJoe3onfjlnL9KWByfMi2THDDJVrJD+2JQ4lVwlXMITbw3rEXjphQNV61uSH9AqdHEKJWHPhLwqD3u4XXQNYjB7r+o8W+mT9TlFmrywiPnl7+/9bkMwOFutjtmLvvmkV8hFFhkFY6UQ2zVnBHWdqpqP5LldKj8c0CgYEAznSkVt10uJr5KnGrwEc9vq1j/eOprxAQO1zgJf0BDus8eYR4UW4Y4n4mcybuZ6twMrHqpuCKUjx3Ex5NN1JfxfOvvvmaOVDeVw1kjZAK5HY7ncbgQMwFyBOnnQssyTDf9G2xRwLGGBxDbaMxLQ4pVnxx/GNc3AQRqFqix9H2lvkCgYBirnOeI6Njc91U0AB9TQTSxG7DO7tZYturIrCOz5qapZU8Lwa9HEHfXRqy5+mvNgJxIrLLcxxOWW+fiY+1Ko9dayY8ve7r5+qzk2uA1hrlRKfGXnwGa2MyNm19+1165swxthN+4XXSJ60grHBaZHHb+DxPGiH6l9H9qXX27FMylQKBgGFE6UyXx+9V7IDHz3Cm3/tfO9YZlg+J1OvzBRRA0GfUAskJ1Zof8g97+eeU9wvW5OStmG2JKwI1xLA4PY8L+12LQ0kJ1lScujRvdemQbOFYpxvd4DgHJ84tHHJMGoyrv0gtCjH3p5cicc5M7dVZb7Z0qUuNEOoD7MHR+hGE5dYZAoGBAIgnf1aMvOw4glV9fNNU6zcQku5wy+USRqjjho6ulQkeNib8gpYV+lHU+vfuJ7iSWEljgMz1VIUTlYOIXiN86fo5gslFKDcJpQTVs0EgLO6l+0wm6E3V3CWTliRM2q/2D7RGNw6QqZH2uQtF92Q3ZnKp3oY0BtjP2n588+qMdjf3";
            
            var str = "123456789";

            var encryptor = new Encryptor();
            
            var encryptResult = encryptor.RsaEncrypt(str, publicKey);
            var decryptResult = encryptor.RsaDecrypt(encryptResult, privateKey);

            Assert.AreEqual(str, decryptResult);

        }
    }
}