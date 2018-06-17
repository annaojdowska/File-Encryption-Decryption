using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace FileEncryptionAndDecryption
{
    /// <summary>
    /// Interaction logic for Processing.xaml
    /// </summary>
    public partial class Processing : Window
    {
        public Processing(List<string> receivers, FileInfo fileToEncrypt, string mode, string outputName, int feedbackSize)
        {
            InitializeComponent();
            this.Top = 270;
            this.Left = 480;
            var encoder = new Cryptography.Encoder(receivers, fileToEncrypt, mode, outputName, feedbackSize);
            encoder.EncodeFile(progressBar, processingLabel, buttonOK);
        }

        public Processing(FileInfo fileToDecrypt, string userName, string outputName)
        {
            InitializeComponent();
            this.Top = 270;
            this.Left = 480;
            var decoder = new Cryptography.Decoder(fileToDecrypt, userName, outputName);
            decoder.DecodeFile(progressBar, processingLabel, buttonOK);
        }

        private void CloseAllWindows()
        {
            for (int intCounter = App.Current.Windows.Count - 1; intCounter > 0; intCounter--)
                App.Current.Windows[intCounter].Close();
        }

        private void ButtonOK_Click(object sender, RoutedEventArgs e)
        {
            MainWindow mw = new MainWindow();
            for (int intCounter = App.Current.Windows.Count - 1; intCounter >= 0; intCounter--)
                App.Current.Windows[intCounter].Hide();
            mw.Show();
        }

        private void ButtonCancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
            for (int intCounter = App.Current.Windows.Count - 1; intCounter >= 0; intCounter--)
                App.Current.Windows[intCounter].Hide();
            MainWindow mw = new MainWindow();
            mw.Show();
        }

     
    }
}
