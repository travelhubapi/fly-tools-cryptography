using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Flytour.Tools.Cryptography
{
    public static class AsymmetricProvider
    {
        public static string Encrypt(string text, string pem)
        {
            using var provider = GetRSAProviderFromPemFile(pem);

            var encoded = Encoding.UTF8.GetBytes(text);
            var encrypted = provider.Encrypt(encoded, false);

            return Convert.ToBase64String(encrypted);
        }

        private static RSACryptoServiceProvider GetRSAProviderFromPemFile(string pem)
        {
            byte[] key = DecodeOpenSSLPublicKey(pem);

            return DecodeX509PublicKey(key);
        }

        private static byte[] DecodeOpenSSLPublicKey(String instr)
        {
            const string pemPubHeader = "-----BEGIN PUBLIC KEY-----";
            const string pemPubFooter = "-----END PUBLIC KEY-----";
            string pemstr = instr.Trim();
            byte[] binkey;

            if (!pemstr.StartsWith(pemPubHeader) || !pemstr.EndsWith(pemPubFooter))
            {
                return null;
            }

            var sb = new StringBuilder(pemstr);

            sb.Replace(pemPubHeader, "");
            sb.Replace(pemPubFooter, "");

            string pubstr = sb.ToString().Trim();


            try
            {
                binkey = Convert.FromBase64String(pubstr);
            }
            catch (System.FormatException)
            {
                return null;
            }

            return binkey;
        }

        private static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int i = 0;

            foreach (byte c in a)
            {
                if (c != b[i])
                {
                    return false;
                }

                i++;
            }

            return true;
        }

        private static RSACryptoServiceProvider DecodeX509PublicKey(byte[] key)
        {
            byte[] seqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            var memory = new MemoryStream(key);
            var reader = new BinaryReader(memory);

            try
            {
                var twoBytes = reader.ReadUInt16();

                if (twoBytes == 0x8130)
                {
                    reader.ReadByte();
                }
                else if (twoBytes == 0x8230)
                {
                    reader.ReadInt16();
                }
                else
                {
                    return null;
                }

                var seq = reader.ReadBytes(15);

                if (!CompareByteArrays(seq, seqOID))
                {
                    return null;
                }

                twoBytes = reader.ReadUInt16();

                if (twoBytes == 0x8103)
                {
                    reader.ReadByte();
                }
                else if (twoBytes == 0x8203)
                {
                    reader.ReadInt16();
                }
                else
                {
                    return null;
                }

                var bt = reader.ReadByte();

                if (bt != 0x00)
                {
                    return null;
                }

                twoBytes = reader.ReadUInt16();

                if (twoBytes == 0x8130)
                {
                    reader.ReadByte();
                }
                else if (twoBytes == 0x8230)
                {
                    reader.ReadInt16();
                }
                else
                {
                    return null;
                }

                twoBytes = reader.ReadUInt16();

                byte lowByte = 0x00;
                byte highByte = 0x00;

                if (twoBytes == 0x8102)
                {
                    lowByte = reader.ReadByte();
                }
                else if (twoBytes == 0x8202)
                {
                    highByte = reader.ReadByte();
                    lowByte = reader.ReadByte();
                }
                else
                {
                    return null;
                }
                byte[] modInt = { lowByte, highByte, 0x00, 0x00 };
                int modSize = BitConverter.ToInt32(modInt, 0);

                byte firstByte = reader.ReadByte();

                reader.BaseStream.Seek(-1, SeekOrigin.Current);

                if (firstByte == 0x00)
                {
                    reader.ReadByte();
                    modSize -= 1;
                }

                byte[] modulus = reader.ReadBytes(modSize);

                if (reader.ReadByte() != 0x02)
                {
                    return null;
                }

                int expBytes = (int)reader.ReadByte();
                byte[] exponent = reader.ReadBytes(expBytes);
                var provider = new RSACryptoServiceProvider();
                var parameters = new RSAParameters();

                parameters.Modulus = modulus;
                parameters.Exponent = exponent;

                provider.ImportParameters(parameters);

                return provider;
            }
            catch
            {
                return null;
            }
            finally
            {
                reader.Close();
            }
        }
    }
}
