using FileEncryptionAndDecryption.Cryptography;
using Newtonsoft.Json;
using System.IO;
using System.Windows;

namespace FileEncryptionAndDecryption
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private void Application_Exit(object sender, ExitEventArgs e)
        {
            string json = JsonConvert.SerializeObject(UsersSingleton.Instance.Users, Formatting.Indented);
            File.WriteAllText(UsersSingleton.Instance.UsersList, json);
        }
    }
}
