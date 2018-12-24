using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigSign
{
    class Program
    {
       
        static void Main(string[] args)
        {
            string mSourceFilePath = null;
            string mKeyPath = null;
            string mDirectoryPath = null;
            string mSignaturePath=null;
            string mHeightCodeStr = null;
            string mWidthCodeStr = null;
            OperationType opType = OperationType.None;
            bool newKeyRequires = false;

            if(args.Count() < 3)
            {
                Console.WriteLine("Too little arguments");
                Console.ReadKey();
                return;
            }
            else if(args.Count() >= 3)
            {
                if (args[0] != null)
                    mSourceFilePath = args[0];
                else
                {
                    Console.WriteLine("File path is missed");
                    Console.ReadKey();
                    return;
                }
                mDirectoryPath = mSourceFilePath.Substring(0, mSourceFilePath.LastIndexOf('\\') + 1);
                if (args[1] != null)
                {
                    switch (args[1])
                    {
                        case "-sign": opType = OperationType.Sign; break;
                        case "-verify": opType = OperationType.Verify; break;
                        case "-enc": opType = OperationType.Encrypt; break;
                        case "-dec": opType = OperationType.Decrypt; break;
                        default: Console.WriteLine("Invailid argument: " + args[1]); Console.ReadKey(); return;
                    }
                }
                else
                {
                    Console.WriteLine("Argument -sign / -verify is missed");
                    Console.ReadKey();
                    return;
                }

                if (args[2] != null)
                    switch (args[2])
                    {
                        case "-n":
                            if (opType == OperationType.Sign)
                                newKeyRequires = true;
                            else
                            {
                                Console.WriteLine("Invailid parameter -n in the verify query");
                                Console.ReadKey();
                                return;
                            }
                            break;
                        default:
                            if (opType == OperationType.Verify || opType == OperationType.Sign)
                            {
                                mKeyPath = args[2]; break;
                            }
                            else
                            {
                                mHeightCodeStr = args[2]; break;
                            }
                    }
                else
                {
                    Console.WriteLine("Key path or -n flag is missed");
                    Console.ReadKey();
                    return;
                }

                if (args.Count() == 4)
                {
                    if (args[3] != null && opType == OperationType.Verify)
                    {
                        mSignaturePath = args[3];
                    }
                    else if(args[3] != null && (opType == OperationType.Encrypt || opType == OperationType.Decrypt))
                    {
                        mWidthCodeStr = args[3];
                    }
                    else
                    {
                        Console.WriteLine("Too many parameters in the sign query");
                        Console.ReadKey();
                        return;
                    }
                }
            }

            
            int[]mHeightCode= mHeightCodeStr?.Split(',').Select(n => Convert.ToInt32(n)).ToArray();
            int[]mWidthCode = mWidthCodeStr?.Split(',').Select(n => Convert.ToInt32(n)).ToArray();
            
            

            switch (opType)
            {
                case OperationType.Sign:
                    if(Sign(mSourceFilePath, mDirectoryPath, newKeyRequires, newKeyRequires ? null : mKeyPath))
                    {
                        Console.WriteLine("The e-Signature is successfully created at the path: " + mSourceFilePath.Substring(0, mSourceFilePath.LastIndexOf('.')) + @"_sign.txt");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("An error occured while creating e-Signature!");
                        break;
                    }
                    
                case OperationType.Verify:
                    if (Verify(mSourceFilePath, mSignaturePath, mKeyPath))
                    {
                        Console.WriteLine("The e-Signature is valid");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("The e-Signature is invailid!"); break;
                    }
                case OperationType.Encrypt:
                    if(Encrypt(mSourceFilePath, mDirectoryPath, mHeightCode, mWidthCode))
                    {
                        Console.WriteLine("The file is successfully encrypted at path: " + mSourceFilePath.Substring(0, mSourceFilePath.LastIndexOf('.')) + @"_encr.txt");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("An error occured while encrypting this file!");
                        break;
                    }

                case OperationType.Decrypt:
                    if (Decrypt(mSourceFilePath, mDirectoryPath, mHeightCode, mWidthCode))
                    {
                        Console.WriteLine("The file is successfully decrypted at path: " + mSourceFilePath.Substring(0, mSourceFilePath.LastIndexOf('.')) + @"_decr.txt");
                        break;
                    }
                    else
                    {
                        Console.WriteLine("An error occured while decrypting this file!");
                        break;
                    }

                default: break;
            }

            Console.ReadKey();
        }

        private static bool Sign(string sourceFilePath, string directoryPath, bool isNewKeyRequires = false, string privateKeyPath = null)
        {
           
            if (isNewKeyRequires)
                Cryptography.AssignNewKey(directoryPath);
            
            byte[] inData = null;
            try
            {
                using (FileStream fs = File.OpenRead(sourceFilePath))
                {

                    using (BinaryReader br = new BinaryReader(fs))
                    {
                        inData = br.ReadBytes((int)new FileInfo(sourceFilePath).Length);
                    }

                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot read this file: ");
                Console.WriteLine(e.Message);
                return false;
            }
            

            byte[] signature = null;
            if (inData != null)
            {
                signature = Cryptography.CreateSignature(inData,  isNewKeyRequires ? directoryPath + @"privateKey.xml" : privateKeyPath);

                if (File.Exists(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_sign.txt"))
                    File.Delete(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_sign.txt");

                using (FileStream fs = File.Open(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_sign.txt",
                                                FileMode.OpenOrCreate))
                {
                    using (BinaryWriter br = new BinaryWriter(fs))
                    {
                        br.Write(signature);
                    }
                }
            }
            else
            {
                Console.WriteLine("There is no data to sign");
                return false;
            }

            return true;
        }

        private static bool Verify(string sourceFilePath, string signatureFilePath, string publicKeyPath)
        {
            byte[] inData = null;
            try
            {
                using (FileStream fs = File.OpenRead(sourceFilePath))
                {

                    using (BinaryReader br = new BinaryReader(fs))
                    {
                        inData = br.ReadBytes((int)new FileInfo(sourceFilePath).Length);
                    }

                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot read this file: ");
                Console.WriteLine(e.Message);
            }

            byte[] signature = null;
            try
            {
                using (FileStream fs = File.OpenRead(signatureFilePath))
                {

                    using (BinaryReader br = new BinaryReader(fs))
                    {
                        signature = br.ReadBytes((int)new FileInfo(signatureFilePath).Length);
                    }

                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Cannot read this file: ");
                Console.WriteLine(e.Message);
            }

            return Cryptography.VerifySignature(inData, signature, publicKeyPath);
        }


        private static bool Encrypt(string sourceFilePath, string directoryPath, int[] heightCode, int[] widthCode)
        {
            if (!Directory.Exists(directoryPath))
                Directory.CreateDirectory(directoryPath);

            string inDataStr = null;
            char[] inDataChar = null;

            using(FileStream fs = File.Open(sourceFilePath, FileMode.OpenOrCreate))
            {
                using(StreamReader sr = new StreamReader(fs))
                {
                    inDataStr = sr.ReadToEnd();
                }
            }

            if(inDataStr == null)
            {
                Console.WriteLine("There is no data to encrypt");
                return false;
            }

            inDataChar = inDataStr.ToCharArray();

            char[] outDataChar = Cryptography.Encrypt(inDataChar, heightCode, widthCode);

            if (outDataChar == null)
                return false;
            if (File.Exists(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_encr.txt"))
                File.Delete(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_encr.txt");

            using (FileStream fs = File.Open(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.'))+@"_encr.txt", FileMode.OpenOrCreate))
            {
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.Write(outDataChar);
                }
            }

            return true;
            
        }

        private static bool Decrypt(string sourceFilePath, string directoryPath, int[] heightCode, int[] widthCode)
        {
            if (!Directory.Exists(directoryPath))
                Directory.CreateDirectory(directoryPath);

            string inDataStr = null;
            char[] inDataChar = null;

            using (FileStream fs = File.Open(sourceFilePath, FileMode.OpenOrCreate))
            {
                using (StreamReader sr = new StreamReader(fs))
                {
                    inDataStr = sr.ReadToEnd();
                }
            }

            if (inDataStr == null)
            {
                Console.WriteLine("There is no data to decrypt");
                return false;
            }

            inDataChar = inDataStr.ToCharArray();

            char[] outDataChar = Cryptography.Decrypt(inDataChar, heightCode, widthCode);

            if (outDataChar == null)
                return false;

            if (File.Exists(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_decr.txt"))
                File.Delete(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_decr.txt");

            using (FileStream fs = File.Open(sourceFilePath.Substring(0, sourceFilePath.LastIndexOf('.')) + @"_decr.txt", FileMode.OpenOrCreate))
            {
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.Write(outDataChar);
                }
            }

            return true;

        }
    }
}
