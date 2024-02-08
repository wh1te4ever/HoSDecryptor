using System;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.IO;

namespace HosDecryptor
{
    public class Program
    {
        public static RSACryptoServiceProvider rsa;

        public static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[*] Usage: HoSDecryptor.exe <file path>");

                return;
            }
            string encfile = args[0];

            CspParameters cspp = new CspParameters();
            cspp.KeyContainerName = "HoS";
            rsa = new RSACryptoServiceProvider(cspp);

            DecryptFile(encfile);
        }

        public static void DecryptFile(string inFile)
        {
            checked
            {
                try
                {
                    bool flag = Path.GetExtension(inFile).Equals(".hos", StringComparison.OrdinalIgnoreCase);
                    if (flag)
                    {
                        RijndaelManaged rijndaelManaged = new RijndaelManaged();
                        rijndaelManaged.KeySize = 256;
                        rijndaelManaged.BlockSize = 256;
                        rijndaelManaged.Mode = CipherMode.CBC;
                        byte[] array = new byte[4];
                        byte[] array2 = new byte[4];
                        string text = inFile.Substring(0, inFile.LastIndexOf("."));
                        using (FileStream fileStream = new FileStream(inFile, FileMode.Open))
                        {
                            fileStream.Seek(0L, SeekOrigin.Begin);
                            fileStream.Read(array, 0, 3);
                            fileStream.Seek(4L, SeekOrigin.Begin);
                            fileStream.Read(array2, 0, 3);
                            int num = BitConverter.ToInt32(array, 0);
                            int num2 = BitConverter.ToInt32(array2, 0);
                            int num3 = num + num2 + 8;
                            int num4 = (int)fileStream.Length - num3;
                            byte[] array3 = new byte[num - 1 + 1];
                            byte[] array4 = new byte[num2 - 1 + 1];
                            fileStream.Seek(8L, SeekOrigin.Begin);
                            fileStream.Read(array3, 0, num);
                            fileStream.Seek(unchecked((long)(checked(8 + num))), SeekOrigin.Begin);
                            fileStream.Read(array4, 0, num2);
                            byte[] rgbKey = rsa.Decrypt(array3, false);
                            ICryptoTransform transform = rijndaelManaged.CreateDecryptor(rgbKey, array4);
                            using (FileStream fileStream2 = new FileStream(text, FileMode.Create))
                            {
                                int num5 = 0;
                                int num6 = (int)Math.Round((double)rijndaelManaged.BlockSize / 8.0);
                                byte[] array5 = new byte[num6 - 1 + 1];
                                fileStream.Seek(unchecked((long)num3), SeekOrigin.Begin);
                                using (CryptoStream cryptoStream = new CryptoStream(fileStream2, transform, CryptoStreamMode.Write))
                                {
                                    bool flag2;
                                    do
                                    {
                                        int num7 = fileStream.Read(array5, 0, num6);
                                        num5 += num7;
                                        cryptoStream.Write(array5, 0, num7);
                                        flag2 = (num7 == 0);
                                    }
                                    while (!flag2);
                                    cryptoStream.FlushFinalBlock();
                                    cryptoStream.Close();
                                }
                                fileStream2.Close();
                            }
                            fileStream.Close();
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
        }
    }
}