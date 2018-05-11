using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace Encryptor
{
    /// <summary>
    /// 加密和解密函数
    /// </summary>
    public static class Encipher
    {
        /// <summary>
        /// 生成RSA秘钥对
        /// </summary>
        /// <param name="publicKey">获得的公钥</param>
        /// <param name="privateKey">获得的私钥</param>
        public static void GenerateRSAKeyPair(out string publicKey, out string privateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            publicKey = rsa.ToXmlString(false);
            privateKey = rsa.ToXmlString(true);
        }

        /// <summary>
        /// 用RSA加密AES秘钥 再用AES加密文件
        /// </summary>
        /// <param name="plainFilePath">完整路径的要加密文件</param>
        /// <param name="encryptedFilePath">完整路径的加密后文件</param>
        /// <param name="manifestFilePath">完整路径的生成的manifest文件</param>
        /// <param name="rsaKey">用于加密的RSA公钥</param>
        /// <returns>包含对称秘钥的加密信息</returns>
        public static string Encrypt(string plainFilePath, 
            string encryptedFilePath, 
            string manifestFilePath, 
            string rsaKey)
        {
            byte[] signatureKey = GenerateRandom(64);
            byte[] encryptionKey = GenerateRandom(16);
            byte[] encryptionIV = GenerateRandom(16);

            EncryptFile(plainFilePath, encryptedFilePath, encryptionKey, encryptionIV);

            byte[] signature = CalculateSignature(encryptedFilePath, signatureKey);

            CreateManifest(signature, signatureKey, encryptionKey, encryptionIV, rsaKey, manifestFilePath);

            return CreateEncryptionInfoXml(signatureKey, encryptionKey, encryptionIV);
        }

        /// <summary>
        /// 创建xml字符串格式的加密信息
        /// </summary>
        /// <param name="signatureKey">签名密钥</param>
        /// <param name="encryptionKey">AES秘钥</param>
        /// <param name="encryptionIV">AES密钥向量</param>
        /// <returns>包含加密信息的xml字符串</returns>
        private static string CreateEncryptionInfoXml(byte[] signatureKey, byte[] encryptionKey, byte[] encryptionIV)
        {
            string template = "<EncryptionInfo>" +
                "<AESKeyValue>" +
                "<Key/>" +
                "<IV/>" +
                "</AESKeyValue>" +
                "<HMACSHAKeyValue/>" +
                "</EncryptionInfo>";

            XDocument doc = XDocument.Parse(template);
            doc.Descendants("AESKeyValue").Single().Descendants("Key").Single().Value = Convert.ToBase64String(encryptionKey);
            doc.Descendants("AESKeyValue").Single().Descendants("IV").Single().Value = Convert.ToBase64String(encryptionIV);
            doc.Descendants("HMACSHAKeyValue").Single().Value = Convert.ToBase64String(signatureKey);
            return doc.ToString();
        }

        /// <summary>
        /// 生成随机字节数组
        /// </summary>
        /// <param name="length">array length</param>
        /// <returns>随机字节数组</returns>
        private static byte[] GenerateRandom(int length)
        {
            byte[] bytes = new byte[length];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(bytes);
            }

            return bytes;
        }

        /// <summary>
        /// AES加密文件
        /// </summary>
        /// <param name="plainFilePath">完整路径的要加密文件</param>
        /// <param name="encryptedFilePath">完整路径的加密后文件</param>
        /// <param name="key">AES 秘钥</param>
        /// <param name="iv">AES初始向量</param>
        private static void EncryptFile(string plainFilePath, 
            string encryptedFilePath, 
            byte[] key, 
            byte[] iv)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = iv;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (FileStream plain = File.Open(plainFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    using (FileStream encrypted = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        using (CryptoStream cs = new CryptoStream(encrypted, encryptor, CryptoStreamMode.Write))
                        {
                            plain.CopyTo(cs);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// AES解密文件
        /// </summary>
        /// <param name="plainFilePath">完整路径的加密后文件</param>
        /// <param name="encryptedFilePath">完整路径的解密后文件</param>
        /// <param name="key">AES秘钥</param>
        /// <param name="iv">AES向量</param>
        public static void DecryptFile(string plainFilePath, string encryptedFilePath, byte[] key, byte[] iv)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (FileStream plain = File.Open(plainFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    using (FileStream encrypted = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        using (CryptoStream cs = new CryptoStream(plain, decryptor, CryptoStreamMode.Write))
                        {
                            encrypted.CopyTo(cs);
                        }
                    }
                }
            }
        }
        

        /// <summary>
        /// 用RSA加密字节数组
        /// </summary>
        /// <param name="datas">要被加密的字节数组</param>
        /// <param name="keyXml">RSA公钥</param>
        /// <returns>加密后的数组</returns>
        public static byte[] RSAEncryptBytes(byte[] datas, string keyXml)
        {
            byte[] encrypted = null;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(keyXml);
                encrypted = rsa.Encrypt(datas, true);
            }

            return encrypted;
        }

        /// <summary>
        /// RSA解密字节数组
        /// </summary>
        /// <param name="datas">加密后的字节数组</param>
        /// <param name="keyXml">RSA私钥</param>
        /// <returns>解密后的字节数组</returns>
        public static byte[] RSADescryptBytes(byte[] datas, string keyXml)
        {
            byte[] decrypted = null;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(keyXml);
                decrypted = rsa.Decrypt(datas, true);
            }

            return decrypted;
        }

        /// <summary>
        /// 计算文件签名
        /// </summary>
        /// <param name="filePath">要计算签名的完整路径文件</param>
        /// <param name="key">计算签名秘钥</param>
        /// <returns>签名数组</returns>
        private static byte[] CalculateSignature(string filePath, byte[] key)
        {
            byte[] sig = null;
            using (HMACSHA256 sha = new HMACSHA256(key))
            {
                using (FileStream f = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    sig = sha.ComputeHash(f);
                }
            }

            return sig;
        }

        /// <summary>
        ///创建manifest文件
        /// </summary>
        /// <param name="signature">数据签名</param>
        /// <param name="signatureKey">数据签名秘钥</param>
        /// <param name="encryptionKey">AES加密秘钥</param>
        /// <param name="encryptionIv">AES加密向量</param>
        /// <param name="rsaKey">RSA公钥</param>
        /// <param name="manifestFilePath">输出manifest文件路径</param>
        private static void CreateManifest(byte[] signature, 
            byte[] signatureKey, 
            byte[] encryptionKey, 
            byte[] encryptionIv, 
            string rsaKey,
            string manifestFilePath)
        {
            string template = "<DataInfo>" +
                "<Encrypted>True</Encrypted>" + 
                "<KeyEncryption algorithm='RSA2048'>" + 
                "</KeyEncryption>" + 
                "<DataEncryption algorithm='AES128'>" + 
                "<AESEncryptedKeyValue>" + 
                "<Key/>" + 
                "<IV/>" +
                "</AESEncryptedKeyValue>" +
                "</DataEncryption>" + 
                "<DataSignature algorithm='HMACSHA256'>" + 
                "<Value />" +
                "<EncryptedKey />" + 
                "</DataSignature>" + 
                "</DataInfo>";

            XDocument doc = XDocument.Parse(template);
            doc.Descendants("DataEncryption").Single().Descendants("AESEncryptedKeyValue").Single().Descendants("Key").Single().Value = System.Convert.ToBase64String(RSAEncryptBytes(encryptionKey, rsaKey));
            doc.Descendants("DataEncryption").Single().Descendants("AESEncryptedKeyValue").Single().Descendants("IV").Single().Value = System.Convert.ToBase64String(RSAEncryptBytes(encryptionIv, rsaKey));
            doc.Descendants("DataSignature").Single().Descendants("Value").Single().Value = System.Convert.ToBase64String(signature);
            doc.Descendants("DataSignature").Single().Descendants("EncryptedKey").Single().Value = System.Convert.ToBase64String(RSAEncryptBytes(signatureKey, rsaKey));

            doc.Save(manifestFilePath);
        }
    }
}
