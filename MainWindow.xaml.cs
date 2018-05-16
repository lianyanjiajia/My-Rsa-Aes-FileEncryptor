using Microsoft.Win32;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Xml.Linq;
using System.Xml.XPath;

namespace FileEncryptor
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            this.publicKey = null;

            this.freeEvent = new EventWaitHandle(true, EventResetMode.ManualReset);
        }
        private void bt_selPlain_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.DefaultExt = ".*";
            ofd.Filter = FileEncryptor.Properties.Resources.All_File_Type;
            ofd.Title = "请选择加密文件";
            Nullable<bool> result = ofd.ShowDialog();
            if (result == true)
            {
                this.tb_plainFilePath.Text = ofd.FileName;
            }
        }

        private void tb_output_TextChanged(object sender, TextChangedEventArgs e)
        {
            this.tb_output.ScrollToEnd();
        }


        private void bt_encrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!this.freeEvent.WaitOne(0))
            {
                MessageBox.Show(Properties.Resources.Backend_Busy);
                return;
            }

            if (string.IsNullOrEmpty(publicKey))
            {
                MessageBox.Show(this, Properties.Resources.Error_Need_PublicKey);
                return;
            }

            string plainFilePath = this.tb_plainFilePath.Text;
            string encryptedFilePath = MakePath(plainFilePath, ".encrypted");
            string manifestFilePath = MakePath(plainFilePath, ".manifest.xml");

            this.tb_output.Text = "加密中...";
            var t = Task.Factory.StartNew(() =>
            {
                freeEvent.Reset();
                string s = Encryptor.Encipher.Encrypt(plainFilePath,
                    encryptedFilePath,
                    manifestFilePath,
                    this.publicKey);

                freeEvent.Set();
                this.UpdateOutput(this.tb_output, "加密完成，密钥信息如下" + "\r\n" + s, true);

            });
        }

        private void UpdateOutput(TextBox tb, string message, bool append)
        {
            this.Dispatcher.Invoke(new Action(() =>
            {
                string newMessage = append ? tb.Text + "\r\n" + message : message;
                tb.Text = newMessage;
            }), null);
        }

        private string publicKey;

        private string privateKey;
        private string manifestFilePath;

        private void bt_setting_Click(object sender, RoutedEventArgs e)
        {
            SettingWindow sw = new SettingWindow();
            sw.PublicKey = this.publicKey;
            Nullable<bool> result = sw.ShowDialog();

            if (result == true)
            {
                this.publicKey = sw.PublicKey;
            }
        }

        private static string MakePath(string plainFilePath, string newSuffix)
        {
            string encryptedFileName = System.IO.Path.GetFileNameWithoutExtension(plainFilePath) + newSuffix;
            return System.IO.Path.Combine(System.IO.Path.GetDirectoryName(plainFilePath), encryptedFileName);
        }

        private void mi_genKeyPair_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.FolderBrowserDialog fbd = new System.Windows.Forms.FolderBrowserDialog();
            fbd.Description = "选择生成密钥对文件夹";
            if (fbd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                string publicKeyPath = System.IO.Path.Combine(fbd.SelectedPath, "publicKey.xml");
                string privateKeyPath = System.IO.Path.Combine(fbd.SelectedPath, "privateKey.xml");

                string publicKey;
                string privateKey;
                Encryptor.Encipher.GenerateRSAKeyPair(out publicKey, out privateKey);
                using (StreamWriter sw = File.CreateText(publicKeyPath))
                {
                    sw.Write(publicKey);
                }

                using (StreamWriter sw = File.CreateText(privateKeyPath))
                {
                    sw.Write(privateKey);
                }
            }
        }

        private EventWaitHandle freeEvent;

        private void mi_switch_Click(object sender, RoutedEventArgs e)
        {
            if (!this.freeEvent.WaitOne(0))
            {
                MessageBox.Show(Properties.Resources.Backend_Busy);
                return;
            }

            if (this.grid_encrypt.Visibility == System.Windows.Visibility.Visible)
            {
                this.grid_encrypt.Visibility = System.Windows.Visibility.Collapsed;
                this.grid_decrypt.Visibility = System.Windows.Visibility.Visible;
            }
            else
            {
                this.grid_encrypt.Visibility = System.Windows.Visibility.Visible;
                this.grid_decrypt.Visibility = System.Windows.Visibility.Collapsed;
            }
        }

        private void bt_selEncrypted_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.DefaultExt = ".*";
            ofd.Filter = FileEncryptor.Properties.Resources.All_File_Type;
            ofd.Title = "请选择解密文件";
            Nullable<bool> result = ofd.ShowDialog();
            if (result == true)
            {
                this.tb_encryptedFilePath.Text = ofd.FileName;
            }
        }

        private void bt_decrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!this.freeEvent.WaitOne(0))
            {
                MessageBox.Show(Properties.Resources.Backend_Busy);
                return;
            }

            string rsaKey = this.privateKey;
            string encryptedFile = this.tb_encryptedFilePath.Text;
            string manifestFile = this.manifestFilePath;
            XDocument doc = XDocument.Load(manifestFile);
            string fileExtention = doc.Root.XPathSelectElement("./FileExtention").Value;
            string plainFile = MakePath(encryptedFile, "解密后"+fileExtention);
            XElement aesKeyElement = doc.Root.XPathSelectElement("./DataEncryption/AESEncryptedKeyValue/Key");
            byte[] aesKey = Encryptor.Encipher.RSADescryptBytes(Convert.FromBase64String(aesKeyElement.Value), rsaKey);
            XElement aesIvElement = doc.Root.XPathSelectElement("./DataEncryption/AESEncryptedKeyValue/IV");
            byte[] aesIv = Encryptor.Encipher.RSADescryptBytes(Convert.FromBase64String(aesIvElement.Value), rsaKey);

            this.tb_outputDecrypt.Text = "解密中...";
            var t = Task.Factory.StartNew(() =>
            {
                freeEvent.Reset();
                Encryptor.Encipher.DecryptFile(plainFile, encryptedFile, aesKey, aesIv);
                freeEvent.Set();
                this.UpdateOutput(this.tb_outputDecrypt, string.Format("解密完成，文件保存在"+ plainFile), true);
            });
        }

        private void bt_settingDecrypt_Click(object sender, RoutedEventArgs e)
        {
            DecryptionSettingWindow dsw = new DecryptionSettingWindow();
            dsw.Key = this.privateKey;
            dsw.ManifestFilePath = this.manifestFilePath;
            Nullable<bool> result = dsw.ShowDialog();
            if (result == true)
            {
                this.privateKey = dsw.Key;
                this.manifestFilePath = dsw.ManifestFilePath;
            }
        }
        private void tb_outputDecrypt_TextChanged(object sender, TextChangedEventArgs e)
        {
            this.tb_outputDecrypt.ScrollToEnd();
        }
    }
}