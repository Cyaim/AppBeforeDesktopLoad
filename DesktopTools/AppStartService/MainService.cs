using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AppStartService
{
    public partial class MainService : ServiceBase
    {
        public MainService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            //StartApplication.ShowMessageBox("2333", "33332");
            //StartApplication.CreateProcess("cmd.exe", @"C:\Windows\System32\");
            //StartApplication.CreateProcess("DesktopTools.exe", @"C:\Project\Release");
            //Thread.Sleep(15000);
            StartApplication.CreateProcess(@"E:\Workspaces\DesktopTools\DesktopTools\bin\Debug\DesktopTools.exe", @"E:\Workspaces\DesktopTools\DesktopTools\bin\Debug");
        }

        protected override void OnStop()
        {
        }
    }
}
