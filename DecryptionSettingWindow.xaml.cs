using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.IO;
using System.Windows;
namespace FileEncryptor
{
    /// <summary>
    /// Interaction logic for DecryptionSettingWindow.xaml
    /// </summary>
    public partial class DecryptionSettingWindow : Window, INotifyPropertyChanged
    {
        public DecryptionSettingWindow()
        {
            InitializeComponent();
            this.DataContext = this;
        }

        #region INotifyPropertyChanged Members

        public event PropertyChangedEventHandler PropertyChanged;
        void Notify(string propName)
        {
            if (PropertyChanged != null)
                PropertyChanged(this, new PropertyChangedEventArgs(propName));
        }
        #endregion

        private string key;
        private string manifestFilePath;

        public string Key
        {
            get
            {
                return this.key;
            }
            set
            {
                if (value != this.key)
                {
                    this.key = value;
                    Notify("Key");
                }
            }
        }

        public string ManifestFilePath
        {
            get
            {
                return this.manifestFilePath;
            }
            set
            {
                if (value != this.manifestFilePath)
                {
                    this.manifestFilePath = value;
                    Notify("ManifestFilePath");
                }
            }
        }

        private void EnableSelectManifest(bool enable)
        {
            this.tb_manifestPath.IsEnabled = enable;
            this.bt_selManifest.IsEnabled = enable;
        }

        private void bt_selManifest_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.DefaultExt = ".xml";
            ofd.Filter = FileEncryptor.Properties.Resources.XML_File_Type;
            ofd.Title = FileEncryptor.Properties.Resources.DialogTitle_SelectManifest;
            Nullable<bool> result = ofd.ShowDialog();
            if (result == true)
            {
                this.ManifestFilePath = ofd.FileName;
            }
        }

        private void bt_importDescryptKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.DefaultExt = ".xml";
            ofd.Filter = FileEncryptor.Properties.Resources.XML_File_Type;
            ofd.Title = FileEncryptor.Properties.Resources.DialogTitle_SelectKey;
            Nullable<bool> result = ofd.ShowDialog();
            if (result == true)
            {
                using (StreamReader sr = File.OpenText(ofd.FileName))
                {
                    this.Key = sr.ReadToEnd();
                }
            }
        }

        private void bt_OK_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = true;
        }
    }
}
