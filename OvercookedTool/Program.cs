using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OvercookedTool
{
    public class CRC32
    {
        public const uint c_HashSize = 4u;

        private const uint poly = 1491524015u;

        private const uint seed = 3605721660u;

        private static uint[] s_table;

        private CRC32()
        {
            if (s_table == null)
            {
                MakeTable();
            }
        }

        protected void MakeTable()
        {
            s_table = new uint[256];
            for (uint num = 0u; num < 256; num++)
            {
                uint num2 = num;
                for (uint num3 = 0u; num3 < 8; num3++)
                {
                    num2 = (((num2 & 1) != 1) ? (num2 >> 1) : (num2 ^ 0x58E6D9AF));
                }
                s_table[num] = num2;
            }
        }

        public static uint Calculate(byte[] _data)
        {
            return new CRC32().CalculateHash(_data);
        }

        public uint CalculateHash(byte[] _data)
        {
            return CalculateHash(_data, 0u, (uint)_data.Length);
        }

        public static uint Calculate(byte[] _data, uint _size)
        {
            return new CRC32().CalculateHash(_data, _size);
        }

        public uint CalculateHash(byte[] _data, uint _size)
        {
            return CalculateHash(_data, 0u, _size);
        }

        public static uint Calculate(byte[] _data, uint _start, uint _size)
        {
            return new CRC32().CalculateHash(_data, _start, _size);
        }

        public uint CalculateHash(byte[] _data, uint _start, uint _size)
        {
            uint num = 3605721660u;
            for (uint num2 = _start; num2 < _start + _size; num2++)
            {
                num = ((num >> 8) ^ s_table[_data[num2] ^ (num & 0xFF)]);
            }
            return num;
        }

        public static void Append(ref byte[] _buffer)
        {
            new CRC32().AppendHash(ref _buffer);
        }

        public void AppendHash(ref byte[] _buffer)
        {
            AppendHash(ref _buffer, 0u, (uint)_buffer.Length);
        }

        public static void Append(ref byte[] _buffer, uint _start, uint _size)
        {
            new CRC32().AppendHash(ref _buffer, _start, _size);
        }

        public void AppendHash(ref byte[] _buffer, uint _start, uint _size)
        {
            AppendHash(ref _buffer, 0u, _size, CalculateHash(_buffer, _start, _size));
        }

        public static void Append(ref byte[] _buffer, uint _start, uint _size, uint _hash)
        {
            new CRC32().AppendHash(ref _buffer, _start, _size, _hash);
        }

        public void AppendHash(ref byte[] _buffer, uint _start, uint _size, uint _hash)
        {
            byte[] bytes = BitConverter.GetBytes(_hash);
            if (_buffer.Length < (int)(_start + _size + 4))
            {
                byte[] new_buffer = new byte[_start + _size + 4];
                Array.Copy(_buffer, new_buffer, _buffer.Length);
                _buffer = new_buffer;
            }
            int num2 = (int)_size;
            for (int i = 0; i < bytes.Length; i++)
            {
                _buffer[i + num2] = bytes[i];
            }
        }

        public static bool Validate(byte[] _buffer, uint _size)
        {
            return new CRC32().HasValidHash(_buffer, _size);
        }

        public bool HasValidHash(byte[] _buffer, uint _size)
        {
            return HasValidHash(_buffer, 0u, _size);
        }

        public static bool Validate(byte[] _buffer, uint _start, uint _size)
        {
            return new CRC32().HasValidHash(_buffer, _start, _size);
        }

        public bool HasValidHash(byte[] _buffer, uint _start, uint _size)
        {
            return HasValidHash(_buffer, _start, _size, _start + _size);
        }

        public static bool Validate(byte[] _buffer, uint _start, uint _size, uint _hashStar)
        {
            return new CRC32().HasValidHash(_buffer, _start, _size, _hashStar);
        }

        public bool HasValidHash(byte[] _buffer, uint _start, uint _size, uint _hashStart)
        {
            if (_hashStart + 4 > _buffer.Length)
            {
                return false;
            }
            uint num = CalculateHash(_buffer, _start, _size);
            uint num2 = BitConverter.ToUInt32(_buffer, (int)_hashStart);
            if (num != num2)
            {
                return false;
            }
            return true;
        }
    }

    class Program
    {
        private static byte[] Deobfuscate(byte[] obfuscatedText, int size, string pwd, int start = 0, string salt = "jjo+Ffqil5bdpo5VG82kLj8Ng1sK7L/rCqFTa39Zkom2/baqf5j9HMmsuCr0ipjYsPrsaNIOESWy7bDDGYWx1eA==", string hashFunction = "SHA1", int keySize = 256)
        {
            if (obfuscatedText == null || obfuscatedText.Length == 0 || obfuscatedText.Length <= start + size || obfuscatedText.Length <= 16)
            {
                return null;
            }
            byte[] array = new byte[16];
            Array.Copy(obfuscatedText, start, array, 0, 16);
            byte[] array2 = new byte[size - 16 - start];
            Array.Copy(obfuscatedText, 16, array2, 0, array2.Length);
            byte[] bytes = new PasswordDeriveBytes(pwd, Encoding.ASCII.GetBytes(salt), hashFunction, 2).GetBytes(keySize / 8);
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.Mode = CipherMode.CBC;
            byte[] array3 = new byte[array2.Length];
            try
            {
                using (ICryptoTransform transform = rijndaelManaged.CreateDecryptor(bytes, array))
                {
                    using (MemoryStream memoryStream = new MemoryStream(array2))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
                        {
                            cryptoStream.Read(array3, 0, array3.Length);
                            memoryStream.Close();
                            cryptoStream.Close();
                            return array3;
                        }
                    }
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Decryption failed");
                return null;
            }
            finally
            {
                rijndaelManaged.Clear();
            }
        }

        private static byte[] Obfuscate(byte[] deobfuscatedText, int size, string pwd, int start = 0, string salt = "jjo+Ffqil5bdpo5VG82kLj8Ng1sK7L/rCqFTa39Zkom2/baqf5j9HMmsuCr0ipjYsPrsaNIOESWy7bDDGYWx1eA==", string hashFunction = "SHA1", int keySize = 256)
        {
            if (deobfuscatedText == null || deobfuscatedText.Length == 0 || start + size > deobfuscatedText.Length)
            {
                return null;
            }
            byte[] array = new byte[16];
            System.Random random = new System.Random();
            random.NextBytes(array);
            byte[] bytes = new PasswordDeriveBytes(pwd, Encoding.ASCII.GetBytes(salt), hashFunction, 2).GetBytes(keySize / 8);
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.Mode = CipherMode.CBC;
            byte[] array2 = null;
            try
            {
                using (ICryptoTransform transform = rijndaelManaged.CreateEncryptor(bytes, array))
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(deobfuscatedText, start, size);
                            cryptoStream.FlushFinalBlock();
                            array2 = memoryStream.ToArray();
                            memoryStream.Close();
                            cryptoStream.Close();
                        }
                    }
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Encryption failed");
                return null;
            }
            finally
            {
                rijndaelManaged.Clear();
            }
            byte[] array3 = new byte[16 + array2.Length];
            Array.Copy(array, array3, 16);
            Array.Copy(array2, 0, array3, 16, array2.Length);
            return array3;
        }


        static void Decrypt(string source_filename, string dest_filename, string pwd)
        {
            byte[] data = File.ReadAllBytes(source_filename);
            if (!CRC32.Validate(data, (uint)data.Length - 4))
            {
                Console.WriteLine("Invalid CRC");
                return;
            }
            byte[] data2 = Deobfuscate(data, data.Length - 4, pwd);
            if (data2 == null)
            {
                Console.WriteLine("Wrong key?");
                return;
            }
            File.WriteAllBytes(dest_filename, data2);
        }

        static void Encrypt(string source_filename, string dest_filename, string pwd)
        {
            byte[] data = File.ReadAllBytes(source_filename);
            byte[] data2 = Obfuscate(data, data.Length, pwd);
            CRC32.Append(ref data2);
            File.WriteAllBytes(dest_filename, data2);
        }

        const string s_USAGE_MESSAGE = "Usage: .\\OvercookedTool.exe encrypt/decrypt inputFile outputFile userId";
        static void Main(string[] args)
        {
            if(args.Length == 0)
            {
                Console.WriteLine(s_USAGE_MESSAGE);
                return;
            }

            if(args.Length == 1)
            {
                string extension = Path.GetExtension(args[0]);
                if(extension != ".json" && extension != ".save")
                {
                    Console.WriteLine(s_USAGE_MESSAGE);
                    return;
                }
                
                Console.WriteLine("Enter userId: ");
                string userId = Console.ReadLine();

                if(extension == ".json")
                {
                    string outputFile = $"{Path.GetFileNameWithoutExtension(args[0])}.save";
                    Encrypt(args[0], outputFile, userId);
                }
                else
                {
                    string outputFile = $"{Path.GetFileNameWithoutExtension(args[0])}.json";
                    Decrypt(args[0], outputFile, userId);
                }
                return;
            }
            if(args.Length != 4)
            {
                Console.WriteLine(s_USAGE_MESSAGE);
                return;
            }

            if (args[0] == "decrypt")
            {
                Decrypt(args[1], args[2], args[3]);
            }
            else if (args[0] == "encrypt")
            {
                Encrypt(args[1], args[2], args[3]);
            }
            else
            {
                Console.WriteLine(s_USAGE_MESSAGE);
                return;
            }
        }
    }
}
