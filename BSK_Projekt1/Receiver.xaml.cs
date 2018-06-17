using FileEncryptionAndDecryption.Cryptography;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace FileEncryptionAndDecryption
{
    /// <summary>
    /// Interaction logic for Receiver.xaml
    /// </summary>
    public partial class Receiver : Window
    {
        List<string> receivers;
        List<string> chosenReceivers;
        public Receiver()
        {
            InitializeComponent();
            
            chosenReceivers = new List<string>();
            this.Top = 100;
            this.Left = 350;
            
            receivers = new List<string>();
            foreach (string login in UsersSingleton.Instance.Users.Keys)
                receivers.Add(login);

            listBox.ItemsSource = receivers;
            listBox.SelectedIndex = 0;
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            if (chosenReceivers.Count().Equals(0))
            {
                labelErrorNoReceivers.Content = "Wybierz odbiorcę!";
            }
            else
            {
                Encipher en = new Encipher(chosenReceivers);
                en.Show();
                this.Close();
            }
        
        }

        private void ButtonBack_Click(object sender, RoutedEventArgs e)
        {
            MainWindow mw = new MainWindow();
            mw.Show();
            this.Close();
        }

        private void ButtonAdd_Click(object sender, RoutedEventArgs e)
        {
            labelError.Content = "";
            if (textBoxLogin.Text.Length.Equals(0) || textBoxPassword.Password.Length<4)
                labelError.Content = "Wpisz login i hasło (co najmniej 4 znaki)!";
            if (!textBoxLogin.Text.Length.Equals(0) && textBoxPassword.Password.Length >=4)
            {
                if (!UsersSingleton.Instance.Users.ContainsKey(textBoxLogin.Text))
                {
                    byte[] password = Encoding.ASCII.GetBytes(textBoxPassword.Password);
                    UsersSingleton.Instance.AddUser(textBoxLogin.Text.ToString(), password);
                    receivers.Add(textBoxLogin.Text.ToString());
                    listBox.ItemsSource = receivers;
                    listBox.Items.Refresh();
                    textBoxLogin.Text = string.Empty;
                    textBoxPassword.Password = string.Empty;
                    setLabels(false);
                }
                else labelError.Content = "Użytkownik o podanym loginie już istnieje!";
            }

        }

        private void setLabels(Boolean val)
        {
            labelLogin.IsEnabled = val;
            labelPassword.IsEnabled = val;
            textBoxLogin.IsEnabled = val;
            textBoxPassword.IsEnabled = val;
            labelNewReceiver.IsEnabled = val;
            checkBoxShowPassword.IsEnabled = val;
            buttonAddReceiver.IsEnabled = val;
            buttonCancelAdding.IsEnabled = val;
        }

        private void buttonAddNewReceiver_Click(object sender, RoutedEventArgs e)
        {
            setLabels(true);
        }

        private void buttonCancelAddingReceiver_Click(object sender, RoutedEventArgs e)
        {
            textBoxLogin.Clear();
            textBoxPassword.Clear();
            setLabels(false);
        }

        private void buttonAddReceiver_Click(object sender, RoutedEventArgs e)
        {
            if (listBox.SelectedItem != null)
            {
                chosenReceivers.Add(listBox.SelectedItem.ToString());
                receivers.Remove(listBox.SelectedItem.ToString());
                listBox.ItemsSource = receivers;
                listBox.Items.Refresh();
                listBoxSelected.ItemsSource = chosenReceivers;
                listBoxSelected.Items.Refresh();
            }

        }

        private void buttonDeleteReceiver_Click(object sender, RoutedEventArgs e)
        {
            if (listBoxSelected.SelectedItem != null)
            {
                receivers.Add(listBoxSelected.SelectedItem.ToString());
                chosenReceivers.Remove(listBoxSelected.SelectedItem.ToString());
                listBox.ItemsSource = receivers;
                listBox.Items.Refresh();
                listBoxSelected.ItemsSource = chosenReceivers;
                listBoxSelected.Items.Refresh();
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