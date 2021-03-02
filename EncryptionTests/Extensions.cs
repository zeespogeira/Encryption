using System;
using System.Text;

namespace EncryptionTests
{
    public static class Extensions
    {
        public static string Base64Encode(this string plainText) => Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));

        public static string Base64Decode(this string base64Text) => Encoding.UTF8.GetString(Convert.FromBase64String(base64Text));
    }
}
