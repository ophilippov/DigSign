using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigSign
{
    public static class Cryptography
    {
        private const string mContainerName = "DigSign";
        
        private static RSACryptoServiceProvider mRsa;

        private static SHA256 mSha;

        static Cryptography()
        {
            mSha = SHA256.Create();
        }

        private static void AssignParameter()
        {
            CspParameters cspParams = new CspParameters();
            cspParams.KeyContainerName = mContainerName;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;

            mRsa = new RSACryptoServiceProvider(cspParams);
        }

        public static void AssignNewKey(string directory)
        {
            AssignParameter();

            string privateKeyPath = directory + @"privateKey.xml";
            string publicKeyPath = directory + @"publicKey.xml";

            if (!Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            if(File.Exists(privateKeyPath))
                File.Delete(privateKeyPath);

            if (File.Exists(publicKeyPath))
                File.Delete(publicKeyPath);

            using (FileStream fs = File.Create(privateKeyPath))
            {
                using (StreamWriter writer = new StreamWriter(fs))
                {
                    string privateKeyXML = mRsa.ToXmlString(true);
                    writer.Write(privateKeyXML);
                }
                

            }

            using (FileStream fs = File.Create(publicKeyPath))
            {
                using (StreamWriter writer = new StreamWriter(fs))
                {
                    string publicKeyXML = mRsa.ToXmlString(false);
                    writer.Write(publicKeyXML);
                }
                    
            }


           
        }

        public static byte[] CreateSignature (byte[] inData, string privateKeyPath)
        {
            AssignParameter();

            string privateKeyXML;
            
            using (FileStream fs = File.Open(privateKeyPath, FileMode.Open))
            {
                StreamReader reader = new StreamReader(fs);
                privateKeyXML = reader.ReadToEnd();
                mRsa.FromXmlString(privateKeyXML);
                reader.Close();
            }

            RSAPKCS1SignatureFormatter RSAform = new RSAPKCS1SignatureFormatter(mRsa);
            RSAform.SetHashAlgorithm("SHA256");

            byte[] hashData = mSha.ComputeHash(inData);

            return RSAform.CreateSignature(hashData);
        }

        public static bool VerifySignature(byte[] inData, byte[] signature, string publicKeyPath)
        {
            AssignParameter();
            string publicKeyXML;

            using (FileStream fs = File.Open(publicKeyPath, FileMode.Open))
            {
                StreamReader reader = new StreamReader(fs);
                publicKeyXML = reader.ReadToEnd();
                mRsa.FromXmlString(publicKeyXML);
                reader.Close();
            }

            RSAPKCS1SignatureDeformatter RSAdeform = new RSAPKCS1SignatureDeformatter(mRsa);
            RSAdeform.SetHashAlgorithm("SHA256");

            byte[] inDataHash = mSha.ComputeHash(inData);

            return RSAdeform.VerifySignature(inDataHash, signature);

        }

        public static char[] Encrypt(char[] inData,  int[]heightCode, int[] widthCode)
        {
            int inDataSize = inData.Count();
            int heightSize = heightCode.Count();
            int widthSize = widthCode.Count();
           
            if(inDataSize <= heightSize * widthSize)
            {
                //encription table
                char[,] encTable = new char[heightSize, widthSize];
                int k = 0;
                
                //fill the table
                //write by columns
                for(int j=0; j<widthSize; j++)
                {
                    for(int i=0; i<heightSize; i++)
                    {
                        if (k < inDataSize)
                            encTable[i, j] = inData[k++];
                        else
                            encTable[i, j] = ' ';
                    }
                }

                //sort columns
                char[,] temp = new char[heightSize, widthSize];
                for(int j = 0; j<widthSize; j++)
                {
                    for(int i=0; i<heightSize; i++)
                    {
                        temp[i, widthCode[j]] = encTable[i, j];
                    }
                    
                }

                //sort rows
                for (int i = 0; i < heightSize; i++)
                {
                    for (int j = 0; j < widthSize; j++)
                    {
                        encTable[heightCode[i], j] = temp[i, j];
                    }

                }

                //read by rows
                k = 0;
                char[] outData = new char[widthSize * heightSize];
                for(int i=0; i < heightSize; i++)
                {
                    for(int j=0; j<widthSize; j++)
                    {
                        outData[k++] = encTable[i, j];
                    }
                }
                return outData;
            }
            else
            {
                Console.WriteLine("The amount of data is larger than encrypt table size!");
                return null;
            }
        }

        public static char[] Decrypt(char[] inData, int[] heightCode, int[] widthCode)
        {
            int inDataSize = inData.Count();
            int heightSize = heightCode.Count();
            int widthSize = widthCode.Count();

            if (inDataSize == heightSize * widthSize)
            {
                //decription table
                char[,] decTable = new char[heightSize, widthSize];
                int k = 0;

                //fill the table
                //write by rows
                for (int i = 0; i < heightSize; i++)
                {
                    for (int j = 0; j < widthSize; j++)
                    {
                        decTable[i, j] = inData[k++];
                    }
                }

                char[,] temp = new char[heightSize, widthSize];

                //unsort rows
                for (int i = 0; i < heightSize; i++)
                {
                    for (int j = 0; j < widthSize; j++)
                    {
                        temp[i, j] = decTable[heightCode[i], j];
                    }

                }

                //unsort columns
                for (int j = 0; j < widthSize; j++)
                {
                    for (int i = 0; i < heightSize; i++)
                    {
                        decTable[i, j] = temp[i, widthCode[j]];
                    }

                }

                

                //read by columns
                k = 0;
                char[] outData = new char[widthSize * heightSize];
                for (int j = 0; j < widthSize; j++)
                {
                    for (int i = 0; i < heightSize; i++)
                    {
                        outData[k++] = decTable[i, j];
                    }
                }
                return outData;
            }
            else
            {
                Console.WriteLine("The amount of data is larger than decrypt table size!");
                return null;
            }
        }
    }
}
