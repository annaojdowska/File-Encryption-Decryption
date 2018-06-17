using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace FileEncryptionAndDecryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public const int encipher = 1;
        public const int decipher = 2;
        int chosenFunctionality;

        public MainWindow()
        {
            InitializeComponent();
            this.Top = 100;
            this.Left = 350;
        }

        private void encipherRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            chosenFunctionality = encipher;
        }

        private void decipherRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            chosenFunctionality = decipher;
        }

        private void buttonExit_Click(object sender, RoutedEventArgs e)
        {
            for (int intCounter = App.Current.Windows.Count - 1; intCounter >= 0; intCounter--)
                App.Current.Windows[intCounter].Close();
        }

        private void buttonNext_Click(object sender, RoutedEventArgs e)
        {
            switch(chosenFunctionality)
            {
                case encipher:
                    Receiver receiverWindow = new Receiver();
                    receiverWindow.Show();
                    break;
                case decipher:
                    Decipher decipherWindow = new Decipher();
                    decipherWindow.Show();
                    break;
            }
            this.Close();
        }
    }
}
