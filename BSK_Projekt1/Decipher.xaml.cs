using FileEncryptionAndDecryption.Cryptography;
using Microsoft.Win32;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace FileEncryptionAndDecryption
{
    /// <summary>
    /// Interaction logic for Decipher.xaml
    /// </summary>
    public partial class Decipher : Window
    {
        private FileInfo fileToDecrypt;
        public Decipher()
        {
            InitializeComponent();

            this.Top = 100;
            this.Left = 350;

            listBox.ItemsSource = UsersSingleton.Instance.Users.Keys;
            listBox.SelectedIndex = 0;
        }

        private void ButtonBack_Click(object sender, RoutedEventArgs e)
        {
            MainWindow mw = new MainWindow();
            mw.Show();
            this.Close();
        }

        private void ButtonDecipher_Click(object sender, RoutedEventArgs e)
        {
            labelErrorsNoFile.Content = "";
            labelErrorsNoName.Content = "";
            labelNoPassword.Content = "";
            if (textBoxChosenName.Text.Length.Equals(0))
                labelErrorsNoName.Content = "Wpisz nazwę pliku wynikowego!"; 
            if (textBoxChosenFile.Text.Length.Equals(0))
                labelErrorsNoFile.Content = "Wybierz plik do deszyfrowania!";
            if (textBoxPassword.Password.Length.Equals(0))
                labelNoPassword.Content = "Wpisz hasło!";
            if (!textBoxChosenName.Text.Length.Equals(0) && !textBoxChosenFile.Text.Length.Equals(0) 
                && !textBoxPassword.Password.Length.Equals(0))
            {
                if (fileToDecrypt != null)
                {
                    SHA256 sha256 = SHA256.Create();
                    UsersSingleton.Instance.Users.TryGetValue(listBox.SelectedValue as string, out byte[] usersPassHash);
                    byte[] enteredPassHash = sha256.ComputeHash(Encoding.Default.GetBytes(textBoxPassword.Password));
                    if (enteredPassHash.SequenceEqual(usersPassHash))
                    {
                        Processing processing = new Processing(fileToDecrypt, listBox.SelectedValue as string, textBoxChosenName.Text);
                        processing.ShowDialog();
                    }
                    else
                    {
                        labelNoPassword.Content = "Niepoprawne hasło!";
                    }
                }
            }
        }

        private void ButtonChooseFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog file = new OpenFileDialog();
            file.ShowDialog();
            
            if (string.IsNullOrEmpty(file.FileName) == false)
            {
                textBoxChosenFile.Text = file.SafeFileName.ToString();
                string path = file.FileName;
                fileToDecrypt = new FileInfo(path);
            }
        }

        private void HidePassword(object sender, RoutedEventArgs e)
        {
            textBoxVisiblePassword.Visibility = Visibility.Hidden;
            textBoxPassword.Visibility = Visibility.Visible;
            textBoxVisiblePassword.Text = "";
        }

        private void ShowPassword(object sender, RoutedEventArgs e)
        {
            textBoxVisiblePassword.Visibility = Visibility.Visible;
            textBoxPassword.Visibility = Visibility.Hidden;
            textBoxVisiblePassword.Text = textBoxPassword.Password;
        }

    }
}
