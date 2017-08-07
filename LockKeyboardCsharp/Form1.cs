using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace LockKeyboardCsharp
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        LockInput lockInput = new LockInput();
        private void button1_Click(object sender, EventArgs e)
        {
         
            lockInput.Lock(true);
            //this.Bounds = Screen.PrimaryScreen.Bounds;
            //this.TopMost = true;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            lockInput.Lock(false);
        }

        private void button2_Click_1(object sender, EventArgs e)
        {
            lockInput.Lock(false);
            SendKeys.SendWait("ESC");
            Environment.Exit(0);
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            e.Cancel = true;
        }
    }
}
