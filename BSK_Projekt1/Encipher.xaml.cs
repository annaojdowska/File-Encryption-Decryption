
using Microsoft.Win32;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace FileEncryptionAndDecryption
{
    /// <summary>
    /// Interaction logic for Encipher.xaml
    /// </summary>
    public partial class Encipher : Window
    {
        List<string> receivers;
        FileInfo fileToEncrypt;
        List<RadioButton> modeButtons;
        public Encipher(List<string> chosenReceivers)
        {
            InitializeComponent();
            receivers = chosenReceivers;
            modeButtons = new List<RadioButton>
            {
                modeRadioButtonCBC,
                modeRadioButtonECB,
                modeRadioButtonCFB,
                modeRadioButtonOFB
            };
            feedbackSize.ItemsSource = new List<string>
            {
                "", "8", "16", "32", "64"
            };
            this.Top = 100;
            this.Left = 350;
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            labelErrorsNoFile.Content = "";
            labelErrorsNoName.Content = "";

            if (textBoxChosenName.Text.Length.Equals(0))
                labelErrorsNoName.Content = "Wpisz nazwę pliku wynikowego!";
            if (textBoxChosenFile.Text.Length.Equals(0))
                labelErrorsNoFile.Content = "Wybierz plik do szyfrowania!";
            else if (!textBoxChosenName.Text.Length.Equals(0) && !textBoxChosenFile.Text.Length.Equals(0) && fileToEncrypt != null)
            {
                RadioButton checkedButton = modeButtons.FirstOrDefault(r => r.IsChecked.Equals(true));
                string modeContent = (string)checkedButton.Content;
                string feedback = (string)feedbackSize.SelectedItem;
                int feedbackInt=0;
                if (!string.IsNullOrEmpty(feedback))
                 feedbackInt = int.Parse(feedback); 
                Processing processing = new Processing(receivers, fileToEncrypt, modeContent, textBoxChosenName.Text, feedbackInt);
                processing.ShowDialog();
            }
        }

        private void ButtonBack_Click(object sender, RoutedEventArgs e)
        {
            Receiver re = new Receiver();
            re.Show();
            this.Close();
        }

        private void ButtonChooseFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog file = new OpenFileDialog();
            file.ShowDialog();
            textBoxChosenFile.Text = file.SafeFileName.ToString();
            if (string.IsNullOrEmpty(file.FileName) == false)
            {
                string path = file.FileName;
                fileToEncrypt = new FileInfo(path);
            }
         }

        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri));
            e.Handled = true;
        }

        private void ModeRadioButtonCFB_Checked(object sender, RoutedEventArgs e)
        {
            feedbackSize.IsEnabled = true;
            feedbackSize.SelectedItem = "8";
        }


        private void ModeRadioButtonECB_Checked(object sender, RoutedEventArgs e)
        {
            if (feedbackSize != null)
            {
                feedbackSize.IsEnabled = false;
                feedbackSize.SelectedItem = "";
            }
        }
    }
}
