using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Controls;
using System.Xml;
using System.Xml.Linq;

namespace FileEncryptionAndDecryption.Cryptography
{
    public class Decoder : CryptographicOperator
    {
        private readonly string user;
        private event EventHandler StartBackgroundWorkerHandler;
        private BackgroundWorker backgroundWorker = new BackgroundWorker();

        public Decoder(FileInfo file, string chosenUser, string outputName)
        {
            fileToProcess = file;
            user = chosenUser;
            outputFileName = outputName;
        }
        private void StartBW(object sender, EventArgs e)
        {
                backgroundWorker.RunWorkerAsync();
        }
        public void DecodeFile(ProgressBar progressBar, Label progressLabel, Button buttonOK)
        {
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();
            var approvedUsers = new Dictionary<string, byte[]>();
            StartBackgroundWorkerHandler += StartBW;
            backgroundWorker.WorkerReportsProgress = true;
            backgroundWorker.DoWork += ((object senderBW, DoWorkEventArgs args) =>
            {
                BackgroundWorker worker = senderBW as BackgroundWorker;
                GetVariablesFromHeader(out CipherMode cipherMode, out byte[] iv,out int feedbackSize, approvedUsers);
                if (!cipherMode.Equals(string.Empty) && !iv.Equals(string.Empty) && approvedUsers.Count > 0)
                {
                    byte[] sessionKey = Enumerable.Repeat((byte)0x20, 32).ToArray();
                    if (approvedUsers.Keys.Contains(user))
                    {
                        RSA key = DecodePrivateKey(user, UsersSingleton.Instance.Users[user]);
                        sessionKey = RSADecrypt(approvedUsers[user], key.ExportParameters(true));
                    }
                    using (var AES = Aes.Create())
                    {
                        AES.IV = iv;
                        AES.Mode = cipherMode;
                        AES.Padding = PaddingMode.None;
                        AES.Key = sessionKey;
                        if (feedbackSize > 0) AES.FeedbackSize = feedbackSize;
                        using (var decryptor = AES.CreateDecryptor(AES.Key, AES.IV))
                        using (MemoryStream memoryStream = new MemoryStream())
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                        using (FileStream inputStream = new FileStream(fileToProcess.FullName, FileMode.OpenOrCreate, FileAccess.Read))
                        using (FileStream outputStream = new FileStream(Path.Combine(fileToProcess.DirectoryName, outputFileName + fileToProcess.Extension),
                        FileMode.Create, FileAccess.Write))
                        {
                            const int regexLength = 22;
                            int bytesRead = 0;
                            byte[] regex = Enumerable.Repeat((byte)0x20, regexLength).ToArray();

                            while (inputStream.Read(regex, 0, regex.Length) > 0)
                            {
                                string result = Encoding.Default.GetString(regex);
                                if (Encoding.Default.GetString(regex).Contains("</EncryptedFileHeader>"))
                                {
                                    break;
                                }
                                bytesRead++;
                                inputStream.Position = bytesRead;
                            }

                            long alreadyRead = 0;
                            double progress;
                            int counter = 0;
                            long progressUnit = fileToProcess.Length/50;
                            int lastPosition = 0;
                            byte[] dataBlock = Enumerable.Repeat((byte)0x00, bufferSize).ToArray();
                            while (inputStream.Read(dataBlock, 0, dataBlock.Length) > 0)
                            {
                                lastPosition = (int)memoryStream.Position;
                                cryptoStream.Write(dataBlock, 0, dataBlock.Length);
                                outputStream.Write(memoryStream.ToArray(), lastPosition, memoryStream.ToArray().Length - lastPosition);
                                alreadyRead += dataBlock.Length;
                                dataBlock = Enumerable.Repeat((byte)0x00, bufferSize).ToArray();
                                if (lastPosition >= progressUnit*counter)
                                {
                                    counter++;
                                    progress = counter * 2;
                                    worker.ReportProgress((int)progress);
                                }
                            }
                            cryptoStream.FlushFinalBlock();
                        }
                    }
                }
        });
            backgroundWorker.ProgressChanged += ((object senderBW, ProgressChangedEventArgs args) =>
            {
                progressBar.Value = args.ProgressPercentage;
            }
            );
            backgroundWorker.RunWorkerCompleted += ((object senderBW, RunWorkerCompletedEventArgs args) =>
            {
                if (args.Error != null)
                {
                    var cos = args.Error;
                }
                else
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
                }
            });
            StartBackgroundWorkerHandler.Invoke(this, EventArgs.Empty);
        }

        private void GetVariablesFromHeader(out CipherMode cipherMode, out byte[] iv, out int feedbackSize, Dictionary<string, byte[]> approvedUsers = null)
        {
            cipherMode = CipherMode.ECB;
            iv = new byte[] { };
            feedbackSize = 0;
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse
            };
            XmlReader reader = XmlReader.Create(fileToProcess.FullName, settings);
            reader.MoveToContent();
            XElement tmpElement;
            while (reader.Read())
            {
                if (reader.NodeType.Equals(XmlNodeType.Element))
                {
                    if (reader.Name.Equals("CipherMode"))
                    {
                        tmpElement = XNode.ReadFrom(reader) as XElement;
                        cipherMode = GetCipherMode(tmpElement.Value);
                    }
                    else if (reader.Name.Equals("IV"))
                    {
                        tmpElement = XNode.ReadFrom(reader) as XElement;
                        iv = Convert.FromBase64String(tmpElement.Value);
                    }
                    else if (approvedUsers != null && reader.Name.Equals("User"))
                    {
                        tmpElement = XNode.ReadFrom(reader) as XElement;
                        var credentials = tmpElement.Descendants();
                        approvedUsers.Add(credentials.ElementAt(0).Value, Convert.FromBase64String(credentials.ElementAt(1).Value));
                    }
                    else if (reader.Name.Equals("FeedbackSize"))
                    {
                        tmpElement = XNode.ReadFrom(reader) as XElement;
                        feedbackSize = int.Parse(tmpElement.Value);
                    }
                    else if (reader.Name.Equals("EndOfHeader")) return;
                }
            }
        }

        private byte[] RSADecrypt(byte[] dataToDecrypt, RSAParameters RSAKeyInfo)
        {

                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKeyInfo);
                    decryptedData = RSA.Decrypt(dataToDecrypt, false);
                }
                return decryptedData;

        }

        private RSA DecodePrivateKey(string login, byte[] passHash)
        {
            CipherMode mode;
            byte[] iv;
            GetVariablesFromHeader(out mode, out iv, out int feedbackSize);
            if (!mode.Equals(string.Empty) && !iv.Equals(string.Empty))
            {
                byte[] encryptedPrivateKey = new byte[] { };
                using (var AES = Aes.Create())
                {
                    AES.Key = passHash;
                    AES.Mode = CipherMode.ECB;
                    AES.Padding = PaddingMode.None;
                    AES.IV = iv;
                    using (var decryptor = AES.CreateDecryptor(AES.Key, iv))
                    using (var memoryStream = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    using (var inputStream = new FileStream(Path.Combine(UsersSingleton.Instance.PrivateKeyDirectory, login + ".xml"),
                        FileMode.OpenOrCreate, FileAccess.Read))
                    {
                        const int regexLength = 22;
                        int bytesRead = 0;
                        byte[] regex = Enumerable.Repeat((byte)0x20, regexLength).ToArray();

                        while (inputStream.Read(regex, 0, regex.Length) > 0)
                        {
                            string result = Encoding.Default.GetString(regex);
                            if (Encoding.Default.GetString(regex).Contains("</EncryptedFileHeader>"))
                            {
                                break;
                            }
                            bytesRead++;
                            inputStream.Position = bytesRead;
                        }
                        int lastPosition = 0;
                        StringBuilder sb = new StringBuilder();
                        byte[] tmp = Enumerable.Repeat((byte)0x20, bufferSize).ToArray();
                        byte[] decodedPart;
                        while ((inputStream.Read(tmp, 0, bufferSize)) > 0)
                        {
                            lastPosition = (int)memoryStream.Position;
                            cryptoStream.Write(tmp, 0, bufferSize);
                            decodedPart = memoryStream.ToArray().SubArray(lastPosition, memoryStream.ToArray().Length - lastPosition);
                            sb.Append(Encoding.Default.GetString(decodedPart));
                            tmp = Enumerable.Repeat((byte)0x00, bufferSize).ToArray();
                        }
                        cryptoStream.FlushFinalBlock();
                        string privateKey = sb.ToString();
                        RSA key = new RSACryptoServiceProvider();
                        key.FromXmlString(privateKey);
                        return key;
                    }
                }
            }
            return null;
        }
    }
}
