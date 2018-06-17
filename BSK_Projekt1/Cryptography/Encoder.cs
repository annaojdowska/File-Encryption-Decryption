using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Controls;
using System.Xml.Linq;

namespace FileEncryptionAndDecryption.Cryptography
{
    public class Encoder : CryptographicOperator
    {
        private List<string> receivers = null;
        private event EventHandler StartBackgroundWorkerHandler;
        private readonly CipherMode cipherMode;
        private readonly int feedbackSize;
        private BackgroundWorker bw = new BackgroundWorker();
        public Encoder(List<string> receivers, FileInfo fileToProcess, string cipherMode, string outputFileName, int feedbackSize)
        {
            this.receivers = receivers;
            this.fileToProcess = fileToProcess;
            this.cipherMode = GetCipherMode(cipherMode);
            this.outputFileName = outputFileName;
            this.feedbackSize = feedbackSize;
        }
        public Encoder() { }
        private void Start(object sender, EventArgs e)
        {
            bw.RunWorkerAsync();
        }
        public void EncodeFile(ProgressBar progressBar, Label progressLabel, Button buttonOK)
        {
            byte[] sessionKey = new byte[32];
            byte[][] encryptedSessionKeys = new byte[receivers.Count][];
            var rand = new Random(DateTime.Now.Millisecond);
            rand.NextBytes(sessionKey);
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();
            StartBackgroundWorkerHandler += Start;
            StartBackgroundWorkerHandler.Invoke(this, EventArgs.Empty);
            bw.WorkerReportsProgress = true;
            
            bw.DoWork += ((object senderBW, DoWorkEventArgs args) =>
            {
                var worker = senderBW as BackgroundWorker;
                for (int i = 0; i < receivers.Count; i++)
                {
                    var userPublicKey = new RSACryptoServiceProvider();
                    string publicKeyFromFile = File.ReadAllText(Path.Combine(UsersSingleton.Instance.PublicKeyDirectory, receivers[i] + ".xml"));
                    userPublicKey.FromXmlString(publicKeyFromFile);
                    encryptedSessionKeys[i] = RSAEncrypt(sessionKey, userPublicKey.ExportParameters(false));
                }
                using(Aes AES = Aes.Create())
                {
                    AES.KeySize = 256;
                    AES.Key = sessionKey;
                    AES.Mode = cipherMode;
                    AES.Padding = PaddingMode.None;
                    AES.GenerateIV();
                    if ((cipherMode.Equals(CipherMode.CFB) || cipherMode.Equals(CipherMode.OFB)) && feedbackSize > 0) AES.FeedbackSize = feedbackSize;
                    XDocument doc = GenerateXmlTemplate(AES.IV, encryptedSessionKeys, AES.FeedbackSize);
                    doc.Save(Path.Combine(fileToProcess.DirectoryName, outputFileName + fileToProcess.Extension));
                    using (var encryptor = AES.CreateEncryptor(AES.Key, AES.IV))
                    using (var memoryStream = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var inputStream = new FileStream(fileToProcess.FullName, FileMode.OpenOrCreate, FileAccess.Read))
                    using (var outputStream = new FileStream(Path.Combine(fileToProcess.DirectoryName, outputFileName+ fileToProcess.Extension),
                        FileMode.Append, FileAccess.Write))
                        {
                            long alreadyRead = 0, progressUnit = fileToProcess.Length / 50;
                            double progress;
                            int lastPosition = 0,counter = 0;
                            byte[] dataBlock = Enumerable.Repeat((byte)0x00, bufferSize).ToArray();
                            while ((inputStream.Read(dataBlock, 0, dataBlock.Length)) > 0)
                            {
                                lastPosition = (int)memoryStream.Position;
                                cryptoStream.Write(dataBlock, 0, dataBlock.Length);
                                outputStream.Write(memoryStream.ToArray(), lastPosition, memoryStream.ToArray().Length-lastPosition);
                                alreadyRead += dataBlock.Length;
                                dataBlock = Enumerable.Repeat((byte)0x00, bufferSize).ToArray();
                                if (lastPosition >= progressUnit * counter)
                                {
                                    counter++;
                                    progress = counter * 2;
                                    worker.ReportProgress((int)progress);
                                }
                        }
                            cryptoStream.FlushFinalBlock();
                        }
                }
        });
            bw.ProgressChanged += ((object senderBW, ProgressChangedEventArgs args) =>
            {
                progressBar.Value = args.ProgressPercentage;
            });
            bw.RunWorkerCompleted += ((object senderBW, RunWorkerCompletedEventArgs args) =>
            {
                progressBar.Value = 100;
                progressLabel.Content = "Plik jest gotowy";
                buttonOK.IsEnabled = true;
                stopWatch.Stop();
                TimeSpan ts = stopWatch.Elapsed;
                string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
            ts.Hours, ts.Minutes, ts.Seconds,
            ts.Milliseconds / 10);
                Console.WriteLine("RunTime " + elapsedTime);

            });
        }

        public void EncodePrivateKey(RSA key, byte[] passHash, string directory, string login)
        {
            using (var AES = Aes.Create())
            {
                AES.Key = passHash;
                AES.Mode = CipherMode.ECB;
                AES.Padding = PaddingMode.None;
                AES.GenerateIV();
                var iv = AES.IV;
                var doc = GenerateXmlTemplate(AES.IV);
                doc.Save(Path.Combine(directory, login + ".xml"));
                string privateKey = key.ToXmlString(true);
                byte[] keyInBytes = Encoding.Default.GetBytes(privateKey);
                using (var encryptor = AES.CreateEncryptor(AES.Key, iv))
                using (var cipherStream = new MemoryStream())
                using (var tCryptoStream = new CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write))
                using (FileStream fs = new FileStream(Path.Combine(directory, login + ".xml"),
                        FileMode.Append, FileAccess.Write))
                {
                    int bytesRead = 0, lastPosition = 0, bufferSize = 16;
                    byte[] tmp = Enumerable.Repeat((byte)0x20, bufferSize).ToArray();
                    while (bytesRead < keyInBytes.Length)
                    {
                        if ((keyInBytes.Length - bytesRead) >= bufferSize)
                        {
                            tmp = keyInBytes.SubArray(bytesRead, bufferSize);
                            bytesRead += bufferSize;
                        }
                        else
                        {
                            byte[] partial = keyInBytes.SubArray(bytesRead, (keyInBytes.Length) - bytesRead);
                            partial.CopyTo(tmp, partial.Length);
                            bytesRead += partial.Length;
                        }
                        lastPosition = (int)cipherStream.Position;
                        tCryptoStream.Write(tmp, 0, bufferSize);
                        fs.Write(cipherStream.ToArray(), lastPosition, cipherStream.ToArray().Length - lastPosition);
                        tmp = Enumerable.Repeat((byte)0x00, bufferSize).ToArray();
                    }
                    tCryptoStream.FlushFinalBlock();
                }
            }
        }
        
        private XDocument GenerateXmlTemplate(byte[] iv, byte[][] encryptedSessionKeys=null, int feedbackSize = 0)
        {
            XDocument doc = new XDocument();

            XElement header = new XElement("EncryptedFileHeader");
            doc.Add(header);
            header.Add(new XElement("Algorithm", "AES"));
            header.Add(new XElement("KeySize", 256));
            header.Add(new XElement("CipherMode", cipherMode.ToString()));
            header.Add(new XElement("IV", Convert.ToBase64String(iv)));
            if (feedbackSize > 0) header.Add(new XElement("FeedbackSize", feedbackSize));
            if (receivers != null && encryptedSessionKeys != null)
            {
                XElement users = new XElement("ApprovedUsers");
                for (int i = 0; i < receivers.Count; i++)
                {
                    XElement user = new XElement("User");
                    user.Add(new XElement("Login", receivers[i]));
                    user.Add(new XElement("SessionKey", Convert.ToBase64String(encryptedSessionKeys[i])));
                    users.Add(user);
                }
                header.Add(users);
                header.Add(new XElement("EndOfHeader"));
            }
            return doc;
        }

        private byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo)
        {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKeyInfo);
                    encryptedData = RSA.Encrypt(DataToEncrypt, false);
                }
                return encryptedData;
        }
    }
}
