using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace FileEncryptionAndDecryption.Cryptography
{
    public class UsersSingleton
    {
        private static UsersSingleton instance;
        public string UsersList { get; }
        public Dictionary<string, byte[]> Users { get; }
        public string PublicKeyDirectory { get; }
        public string PrivateKeyDirectory { get; }
        public static UsersSingleton Instance
        {
            get
            {
                if (instance == null) instance = new UsersSingleton();
                return instance;
            }
        }

        private UsersSingleton() {
            PublicKeyDirectory = @"..\..\Users";
            PrivateKeyDirectory = @"..\..\.Users";
            UsersList = @"..\..\resources\users.xml";
            Directory.CreateDirectory(PublicKeyDirectory);
            Directory.CreateDirectory(PrivateKeyDirectory).Attributes = FileAttributes.Directory | FileAttributes.Hidden;

            
            Users = new Dictionary<string, byte[]>();
            
            if(File.Exists(UsersList))
            {
                using (StreamReader file = File.OpenText(UsersList))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    Users = (Dictionary<string, byte[]>)serializer.Deserialize(file, typeof(Dictionary<string, byte[]>));
                }
            }
            else
            {
                AddUser("Użytkownik #1", Encoding.Default.GetBytes("1234")); //domyślni użytkownicy do testów
                AddUser("Użytkownik #2", Encoding.Default.GetBytes("12345"));
                AddUser("Użytkownik #3", Encoding.Default.GetBytes("123456"));
            }
        }
        

        public void AddUser(string login, byte[] password)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] passwordHash = sha256.ComputeHash(password);
            Users.Add(login, passwordHash);
            RSA userKeys = new RSACryptoServiceProvider();
            string publicKey = userKeys.ToXmlString(false);
            File.WriteAllText(Path.Combine(PublicKeyDirectory, login+".xml"), publicKey);
            
            Encoder encoder = new Encoder();
            encoder.EncodePrivateKey(userKeys, passwordHash, PrivateKeyDirectory, login);
        }
    }
}
