// * Copyright (C) Tod Chapman - All Rights Reserved
// * Unauthorized copying of this file, via any medium is strictly prohibited
// * Proprietary and confidential
// * Written by Tod Chapman <pedaln.fast@gmail.com>, October 2018

using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.FileIO;
using System.Net;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Text.RegularExpressions;


namespace WinFWMon
{
    public partial class MainForm : Form
    {
        BackgroundWorker File_Worker;

        int TotalLines;

        string LocalFilePath = @"C:\Windows\System32\LogFiles\Firewall";
        string FileName = "pfirewall.log";

        string App_Log_Filename = "WinFWMon_App.log";
        string Thread_Log_Filename = "WinFWMon_Thread.log";

        string RemoteFilePath = @"\c$\Windows\System32\LogFiles\Firewall";

        string Local_IP_Addr;
        string FilePath;

        DateTime ProgramStart;

        public MainForm()
        {
            InitializeComponent();

            File_Worker = new BackgroundWorker();

            // if (rbLogLive.Checked)
            // {
            //  File_Worker.DoWork += new DoWorkEventHandler(File_Worker_DoWork_Tail);
            // }
            // else
            // {
            // File_Worker.DoWork += new DoWorkEventHandler(File_Worker_DoWork_Existing);
            // }
            // File_Worker.ProgressChanged += new ProgressChangedEventHandler
            // (File_Worker_ProgressChanged);
            // File_Worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler
            // (File_Worker_RunWorkerCompleted);

            File_Worker.WorkerReportsProgress = true;
            File_Worker.WorkerSupportsCancellation = true;
        }

        private void button1_Click(object sender, EventArgs e) // Exit Button
        {
            System.Windows.Forms.Application.Exit();
        }

        private void button2_Click(object sender, EventArgs e) // Start Button
        {
            if (Start_Btn.Text == "Start")
            {
                App_LogFile_Write("Button1_Click:  Start Button is selected.");
                tbStartDate.Text = "Started: " + (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss");
                ProgramStart = DateTime.Now;
                FWLogData TObj = new FWLogData();
                dataGridView2.Rows.Clear();
                ZeroStats();
                // Start the BackGround Thread to Execute
                disable_controls();

                if (rbLogLive.Checked)
                {
                    App_LogFile_Write("Button1_Click:  Live");
                    File_Worker.DoWork += new DoWorkEventHandler(File_Worker_DoWork_Tail);
                    tbStatus.Text = "Waiting for new log entries...";
                }
                else
                {
                    App_LogFile_Write("Button1_Click:  Log File - Lines to Read: " + Lines2Read.ToString());
                    File_Worker.DoWork += new DoWorkEventHandler(File_Worker_DoWork_Existing);
                    tbStatus.Text = "Searching log file for starting point... (Depending on number of lines read and file size this could take several minutes.)";
                }

                File_Worker.ProgressChanged += new ProgressChangedEventHandler
                        (File_Worker_ProgressChanged);
                File_Worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler
                        (File_Worker_RunWorkerCompleted);

                File_Worker.RunWorkerAsync(TObj);
                Exit_Btn.Enabled = true;
                // Start_Btn.Enabled = false;
                Start_Btn.Text = "Stop";
                Start_Btn.BackColor = Color.Green;
            }
            else
            {
                if (File_Worker.IsBusy)
                {
                    enable_controls();
                    App_LogFile_Write("Button1_Click:  Stop Button is selected.");
                    File_Worker.CancelAsync();
                    Start_Btn.Text = "Start";
                    Start_Btn.BackColor = Color.LightGray;
                    tbStatus.Text = "Click Start Button to begin tailing the firewall log.";
                }
            }
            // File_Worker.ReportProgress(100, Obj)
        }

        // ******************************************************************************************************************************************
        // ****************************************************************************************************************************************** 
        private void Form1_Load(object sender, EventArgs e) // Initial Form
        {
            App_LogFile_Check();
            Thread_LogFile_Check();
            App_LogFile_Read();
            Thread_LogFile_Read();
            App_LogFile_Write("Form1_Load:  ********************************************************************");
            App_LogFile_Write("Form1_Load:  Program Started");
            Lines2Read.Text = "50";
            App_LogFile_Write("Form1_Load:  Gettting Local IP Address...");
            Local_IP_Addr = GetLocalIPAddress();

            if (rbMonLocal.Checked)
            {
                tbMonIP.Text = Local_IP_Addr;
                FilePath = LocalFilePath;
            }
            else
            {
                FilePath = @"\\" + tbMonIP.Text + RemoteFilePath;
                // Console.WriteLine(FilePath);
            }

            App_LogFile_Write("Form1_Load:  FilePath ==> " + FilePath);

            TotalLines = GetTotalLines(FilePath, FileName);

            App_LogFile_Write("Form1_Load:  Lines in File ==> " + TotalLines.ToString());

            // TotalLines_LogFile.Text = TotalLines.ToString();

            // tbIPAddr.Text = Local_IP_Addr;
            tbStatus.Text = "Click Start Button to begin tailing the firewall log.";

            // fwstate("advfirewall show allprofiles");
            // fwstate("advfirewall firewall show rule all");
        }

        void File_Worker_DoWork_Tail(object sender, DoWorkEventArgs e)
        {
            // The sender is the BackgroundWorker object we need it to
            // report progress and check for cancellation.
            //NOTE : Never play with the UI thread here...

            Thread_LogFile_Check();
            Thread_LogFile_Read();

            FWLogData Obj = (FWLogData)e.Argument;
            // Console.WriteLine("Starting Record Count");

            Thread_LogFile_Write("File_Worker_DoWork_Tail:  Log file tail started.");

            try
            {
                if (File.Exists(Path.Combine(FilePath, FileName)))
                {
                    if (new FileInfo(Path.Combine(FilePath, FileName)).Length > 0)
                    {
                        // using (TextFieldParser parser = new TextFieldParser(Path.Combine(FilePath, FileName)))
                        using (StreamReader logreader = new StreamReader(new FileStream(Path.Combine(FilePath, FileName), FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                        {
                            long lastMaxOffset = logreader.BaseStream.Length;

                            // parser.Delimiters = new string[] { " " };

                            int LineCount = 0;

                            while (true)
                            {
                                Thread.Sleep(100);

                                if (logreader.BaseStream.Length == lastMaxOffset)
                                    continue;

                                logreader.BaseStream.Seek(lastMaxOffset, SeekOrigin.Begin);

                                string line = "";
                                while ((line = logreader.ReadLine()) != null)
                                {
                                    string[] LineData = line.Split(' ');

                                    lastMaxOffset = logreader.BaseStream.Position;

                                    // while (LineCount <= (TotalLines - Int32.Parse(Lines2Read.Text)))
                                    // {
                                    //     string[] LineData1 = parser.ReadFields();
                                    //     LineCount = LineCount + 1;
                                    // }

                                    // string[] LineData = parser.ReadFields();

                                    LineCount = LineCount + 1;

                                    // if (LineData == null)
                                    // while (parser.EndOfData)
                                    // {
                                    // break;
                                    //  Thread.Sleep(200);
                                    // LineData = parser.ReadFields();
                                    // Console.WriteLine("Waiting");
                                    // }

                                    Thread_LogFile_Write("File_Worker_DoWork_Tail:  New Log Entries: Object Created");

                                    Obj.Local_IP = Local_IP_Addr;
                                    Obj.FW_Date = LineData[0];
                                    Obj.FW_Time = LineData[1];
                                    Obj.Action = LineData[2];
                                    Obj.Protocol = LineData[3];
                                    Obj.Source = LineData[4];
                                    Obj.Destination = LineData[5];
                                    Obj.Src_Port = LineData[6];
                                    Obj.Dst_Port = LineData[7];
                                    Obj.Direction = LineData[16];

                                    // if ((TotalLines - LineCount < 20) && (TotalLines != LineCount))
                                    // {
                                    // TotalLines = GetTotalLines(FilePath, FileName);
                                    // }
                                    // Console.WriteLine(TotalLines - LineCount);
                                    if (File_Worker.CancellationPending)
                                    {
                                        e.Cancel = true;
                                        File_Worker.ReportProgress(0, Obj);
                                        Thread_LogFile_Write("File_Worker_DoWork_Tail:  Tail exit");
                                        return;
                                    }
                                    else
                                    {
                                        Thread_LogFile_Write("File_Worker_DoWork_Tail:  Updating Progress");
                                        File_Worker.ReportProgress(LineCount, Obj);
                                        Thread.Sleep(((dataGridView2.RowCount / 10000) + 1) * 2);
                                    }
                                }
                            }
                        }
                    }
                }
                Thread_LogFile_Write("File_Worker_DoWork_Tail:  Process Complete");
                File_Worker.ReportProgress(100, Obj);
            }
            catch (Exception ex)
            {
                Thread_LogFile_Write("File_Worker_DoWork_Tail:  " + ex.Message);
                MessageBox.Show(ex.Message);
            }
        }

        void File_Worker_DoWork_Existing(object sender, DoWorkEventArgs e)
        {
            // The sender is the BackgroundWorker object we need it to
            // report progress and check for cancellation.
            //NOTE : Never play with the UI thread here...

            Thread_LogFile_Check();
            Thread_LogFile_Read();

            FWLogData Obj_Existing = (FWLogData)e.Argument;

            Thread_LogFile_Write("File_Worker_DoWork_Existing:  Reading of log file started.");

            try
            {
                if (File.Exists(Path.Combine(FilePath, FileName)))
                {
                    if (new FileInfo(Path.Combine(FilePath, FileName)).Length > 0)
                    {
                        using (TextFieldParser parser = new TextFieldParser(Path.Combine(FilePath, FileName)))
                        {
                            parser.Delimiters = new string[] { " " };

                            int LineCount = 1;

                            string[] LineData1 = parser.ReadFields();

                            // Console.WriteLine(TotalLines.ToString());

                            while (LineCount <= TotalLines)
                            {
                                Thread_LogFile_Write("File_Worker_DoWork_Existing:  Searching for starting point.");
                                while ((LineCount < (TotalLines - Int32.Parse(Lines2Read.Text))) && (LineCount <= TotalLines))
                                {
                                    LineData1 = parser.ReadFields();
                                    LineCount = LineCount + 1;
                                    // Console.WriteLine(LineCount.ToString());
                                }

                                string[] LineData = parser.ReadFields();

                                LineCount = LineCount + 1;
                                // Console.WriteLine(LineCount.ToString());
                                // Console.WriteLine(TotalLines.ToString());
                                // Console.WriteLine(LineData[2]);

                                Thread_LogFile_Write("File_Worker_DoWork_Existing:  Creating Object");

                                Obj_Existing.Local_IP = Local_IP_Addr;
                                Obj_Existing.FW_Date = LineData[0];
                                Obj_Existing.FW_Time = LineData[1];
                                Obj_Existing.Action = LineData[2];
                                Obj_Existing.Protocol = LineData[3];
                                Obj_Existing.Source = LineData[4];
                                Obj_Existing.Destination = LineData[5];
                                Obj_Existing.Src_Port = LineData[6];
                                Obj_Existing.Dst_Port = LineData[7];
                                Obj_Existing.Direction = LineData[16];

                                if (File_Worker.CancellationPending)
                                {
                                    e.Cancel = true;
                                    File_Worker.ReportProgress(0, Obj_Existing);
                                    parser.Close();
                                    Thread_LogFile_Write("File_Worker_DoWork_Existing:  Reading of log file exited.");
                                    return;
                                }
                                else
                                {
                                    Thread_LogFile_Write("File_Worker_DoWork_Existing:  Updating Progress");
                                    Thread.Sleep(((dataGridView2.RowCount / 100) + 1) * 2);
                                    File_Worker.ReportProgress(LineCount, Obj_Existing);
                                }
                            }
                            parser.Close();
                        }
                    }
                }
                // Console.WriteLine("Here");
                Thread_LogFile_Write("File_Worker_DoWork_Existing:  Process Complete");
                File_Worker.ReportProgress(100, Obj_Existing);
            }
            catch (Exception ex)
            {
                Thread_LogFile_Write("File_Worker_DoWork_Existing:  " + ex.Message);
                MessageBox.Show(ex.Message);
            }
        }

        /// <summary>
        /// On completed do the appropriate task
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void File_Worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // The background process is complete. We need to inspect
            // our response to see if an error occurred, a cancel was
            // requested or if we completed successfully.  
            if (e.Cancelled)
            {
                App_LogFile_Write("File_Worker_RunWorkerCompleted:  Task Cancelled");
                tbStatus.Text = "Task Cancelled.";
            }

            // Check to see if an error occurred in the background process.

            else if (e.Error != null)
            {
                App_LogFile_Write("File_Worker_RunWorkerCompleted:  Error while performing background operation. " + e.Error);
                tbStatus.Text = "Error while performing background operation. " + e.Error;
            }
            else
            {
                // Everything completed normally.
                App_LogFile_Write("File_Worker_DoWork_RunWorkerCompleted:  Task Completed");
                tbStatus.Text = "Task Completed.";
            }

            //Change the status of the buttons on the UI accordingly
            // btnStartAsyncOperation.Enabled = true;
            // btnCancel.Enabled = false;

            if (dataGridView2.RowCount != 0)
            {
                dataGridView2.FirstDisplayedScrollingRowIndex = dataGridView2.RowCount - 1;
            }

            Start_Btn.Text = "Start";
            Start_Btn.BackColor = Color.LightGray;

        }

        /// <summary>
        /// Notification is performed here to the progress bar
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void File_Worker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {

            // This function fires on the UI thread so it's safe to edit

            // the UI control directly, no funny business with Control.Invoke :)

            // Update the progressBar with the integer supplied to us from the

            // ReportProgress() function.

            // Check search criteria

            App_LogFile_Write("File_Worker_ProgressChanged:  Progress Update Started");

            int Search_Count = 0;
            int RecordsWritten = 0;

            if (cbSearchAction.Text != "")
                Search_Count = Search_Count + 1;

            if (cbSearchProtocol.Text != "")
                Search_Count = Search_Count + 1;

            if (tbSearchSrcIP.Text != "")
                Search_Count = Search_Count + 1;

            if (tbSearchDestIP.Text != "")
                Search_Count = Search_Count + 1;

            if (tbSearchSrcPrt.Text != "")
                Search_Count = Search_Count + 1;

            if (tbSearchDestPrt.Text != "")
                Search_Count = Search_Count + 1;

            if (cbSearchDirection.Text != "")
                Search_Count = Search_Count + 1;

            if (!File_Worker.CancellationPending)
            {
                //Gets the user state that is sent as part of ReportProgress() Method from DoWork Event 
                FWLogData Obj = (FWLogData)e.UserState;
                //Add the data to the dataGridView1
                // Console.WriteLine(e.ProgressPercentage);

                int colon_count = (Obj.Source.ToString()).Split(':').Length - 1;
                // Console.WriteLine(colon_count);

                if ((colon_count == 0 && !ckbxIPv6.Checked) || (ckbxIPv6.Checked))
                {
                    int SCount = 0;

                    tbStatus.Text = "Updating...";

                    if (Obj.Direction.ToString() == "RECEIVE")
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchDirection.Text == "RECEIVE")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }
                    else if (Obj.Direction.ToString() == "SEND")
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchDirection.Text == "SEND")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }

                    if (Obj.Protocol.ToString() == "TCP")
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchProtocol.Text == "TCP")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }
                    else if (Obj.Protocol.ToString() == "UDP")
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchProtocol.Text == "UDP")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }
                    else if (Obj.Protocol.ToString() == "ICMP")
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchProtocol.Text == "ICMP")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }
                    else
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchProtocol.Text == "Other")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }

                    if (Obj.Action.ToString() == "ALLOW")
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchAction.Text == "ALLOW")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }
                    else
                    {
                        if (cbEnableSearch.Checked)
                        {
                            if (cbSearchAction.Text == "DROP")
                            {
                                SCount = SCount + 1;
                            }
                        }
                    }

                    if (cbEnableSearch.Checked)
                    {
                        if (tbSearchSrcIP.Text == Obj.Source.ToString())
                        {
                            SCount = SCount + 1;
                        }
                    }

                    if (cbEnableSearch.Checked)
                    {
                        if (tbSearchDestIP.Text == Obj.Destination.ToString())
                        {
                            SCount = SCount + 1;
                        }
                    }

                    if (cbEnableSearch.Checked)
                    {
                        if (tbSearchSrcPrt.Text == Obj.Src_Port.ToString())
                        {
                            SCount = SCount + 1;
                        }
                    }

                    if (cbEnableSearch.Checked)
                    {
                        if (tbSearchDestPrt.Text == Obj.Dst_Port.ToString())
                        {
                            SCount = SCount + 1;
                        }
                    }

                    // Console.WriteLine("SCount: " + SCount.ToString());
                    // Console.WriteLine("Search_Count: " + Search_Count.ToString());

                    App_LogFile_Write("File_Worker_ProgressChanged:  Implementing Search Criteria");

                    if (((SCount == Search_Count) && (cbEnableSearch.Checked)) || (!(cbEnableSearch.Checked)))
                    {
                        if (Obj.Direction.ToString() == "RECEIVE")
                        {
                            tbTotInb.Text = (Int32.Parse(tbTotInb.Text) + 1).ToString();
                        }
                        else if (Obj.Direction.ToString() == "SEND")
                        {
                            tbTotOutb.Text = (Int32.Parse(tbTotOutb.Text) + 1).ToString();
                        }
                        else
                        {
                            tbTotUnk.Text = (Int32.Parse(tbTotUnk.Text) + 1).ToString();
                        }

                        if (Obj.Protocol.ToString() == "TCP")
                        {
                            tbTotTCP.Text = (Int32.Parse(tbTotTCP.Text) + 1).ToString();
                        }
                        else if (Obj.Protocol.ToString() == "UDP")
                        {
                            tbTotUDP.Text = (Int32.Parse(tbTotUDP.Text) + 1).ToString();
                        }
                        else if (Obj.Protocol.ToString() == "ICMP")
                        {
                            tbTotICMP.Text = (Int32.Parse(tbTotICMP.Text) + 1).ToString();
                        }
                        else
                        {
                            tbTotOth.Text = (Int32.Parse(tbTotOth.Text) + 1).ToString();
                        }

                        if (Obj.Action.ToString() == "ALLOW")
                        {
                            tbTotAllow.Text = (Int32.Parse(tbTotAllow.Text) + 1).ToString();
                        }
                        else
                        {
                            tbTotDrop.Text = (Int32.Parse(tbTotDrop.Text) + 1).ToString();
                        }

                        dataGridView2.Rows.Add(Obj.Local_IP.ToString(), Obj.FW_Date.ToString(), Obj.FW_Time.ToString(), Obj.Action.ToString(), Obj.Protocol.ToString(), Obj.Source.ToString(), Obj.Destination.ToString(), Obj.Src_Port.ToString(), Obj.Dst_Port.ToString(), Obj.Direction.ToString());

                        dataGridView2.Sort(dataGridView2.Columns["FW_Date"], ListSortDirection.Ascending);

                        RecordsWritten = dataGridView2.RowCount - Int32.Parse(tbTotTraf.Text);

                        tbTotTraf.Text = dataGridView2.RowCount.ToString();

                        if (dataGridView2.RowCount != 0)
                        {
                            dataGridView2.FirstDisplayedScrollingRowIndex = dataGridView2.RowCount - 1;
                        }

                        if (dataGridView2.Rows[dataGridView2.RowCount - 1].Cells["FW_Action"].Value.ToString() == "ALLOW")
                        {
                            dataGridView2.Rows[dataGridView2.RowCount - 1].DefaultCellStyle.ForeColor = Color.Green;
                        }
                        else
                        {
                            dataGridView2.Rows[dataGridView2.RowCount - 1].DefaultCellStyle.ForeColor = Color.Red;
                        }

                        tbUpdate.Text = "Last Updated at: " + (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss");

                        tbLogReadDate.Text = (DateTime.Now).ToString("yyyy-MM-dd");
                        tbLogReadTime.Text = (DateTime.Now).ToString("HH:mm:ss");
                        tbLogFileSize.Text = Math.Ceiling((double)(new FileInfo(Path.Combine(FilePath, FileName)).Length / 1000)).ToString() + " KB";

                        TimeSpan Diff = DateTime.Now - ProgramStart;

                        if (((dataGridView2.RowCount / Diff.TotalSeconds) < 1) || (Diff.TotalSeconds < 1))
                        {
                            tbLogRate.Text = "< 1";
                        }
                        else
                        {
                            int LogRate = (dataGridView2.RowCount / (int)Diff.TotalSeconds) + 1;
                            tbLogRate.Text = (LogRate.ToString());
                        }

                        tbDispRecs.Text = dataGridView2.RowCount.ToString();
                    }

                    if (rbLogFile.Checked)
                    {
                        if (dataGridView2.RowCount > 0)
                        {
                            App_LogFile_Write("File_Worker_ProgressChanged:  Reading file...(" + dataGridView2.RowCount.ToString() + " of " + Lines2Read.Text + ")");
                            tbStatus.Text = (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==>  Reading file...(" + dataGridView2.RowCount.ToString() + " of " + Lines2Read.Text + ")";
                        }
                        else
                        {
                            App_LogFile_Write("File_Worker_ProgressChanged:  Reading file...");
                            tbStatus.Text = (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==>  Reading file...";
                        }
                    }
                    else
                    {
                        // if (RecordsWritten > 0)
                        // {
                        //     tbStatus.Text = (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==>  Waiting 100 ms before checking for new log entries... (Records found in last cycle)";
                        // }
                        // else
                        // {
                        //     tbStatus.Text = (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==>  Waiting 100 ms before checking for new log entries... (No records found in last cycle)";
                        // }

                        App_LogFile_Write("File_Worker_ProgressChanged:  Waiting for new log entries");

                        tbStatus.Text = (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==>  Waiting for new log entries...";
                    }
                }
            }

            // progressBar1.Value = e.ProgressPercentage;
            // lblStatus.Text = "Processing......" + progressBar1.Value.ToString() + "%";
        }

        private void App_LogFile_Check()
        {
            try
            {
                if (!File.Exists(App_Log_Filename))
                {
                    var logfile = File.Create(App_Log_Filename);
                    logfile.Close();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void App_LogFile_Write(string LogEntry)
        {
            File.AppendAllText(App_Log_Filename, (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==> " + LogEntry + Environment.NewLine);
            tbApp_Log.AppendText((DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==> " + LogEntry + Environment.NewLine);
        }

        private void App_LogFile_Read()
        {
            tbApp_Log.Text = File.ReadAllText(App_Log_Filename);
        }

        private void Thread_LogFile_Check()
        {
            try
            {
                if (!File.Exists(Thread_Log_Filename))
                {
                    var logfile = File.Create(Thread_Log_Filename);
                    logfile.Close();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void Thread_LogFile_Write(string LogEntry)
        {
            File.AppendAllText(Thread_Log_Filename, (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==> " + LogEntry + Environment.NewLine);
            tbThread_Log.AppendText((DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==> " + LogEntry + Environment.NewLine);
        }

        private void Thread_LogFile_Read()
        {
            tbThread_Log.Text = File.ReadAllText(Thread_Log_Filename);
        }

        private void ZeroStats()
        {
            tbLogRate.Text = "0";
            tbLogFileSize.Text = "0";
            tbLogReadTime.Text = "";
            tbLogReadDate.Text = "";
            tbTotAllow.Text = "0";
            tbTotDrop.Text = "0";
            tbTotICMP.Text = "0";
            tbTotInb.Text = "0";
            tbTotOth.Text = "0";
            tbTotOutb.Text = "0";
            tbTotTCP.Text = "0";
            tbTotUDP.Text = "0";
            tbTotUnk.Text = "0";
            tbTotTraf.Text = "0";
            tbDispRecs.Text = "0";
        }

        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());

            // App_LogFile_Write(host.ToString());

            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    // Console.WriteLine(ni.Name);

                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    {
                        // Console.WriteLine(ni.Name);
                        // Console.WriteLine(ni.NetworkInterfaceType);
                        // Console.WriteLine(System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable());
                        foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            App_LogFile_Write("GetLocalIPAddress:       " + ip.Address.ToString());

                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                string OctetCount = ip.Address.ToString();
                                // Console.WriteLine(OctetCount.Split('.').Length - 1);

                                if (OctetCount.Split('.').Length - 1 == 3)
                                {
                                    // Console.WriteLine(ip.Address.ToString());
                                    return ip.Address.ToString();
                                }
                            }
                        }
                    }
                }
            }

            catch (Exception ex)
            {
                App_LogFile_Write("GetLocalIPAddress:  " + (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==> " + ex.Message);
            }

            App_LogFile_Write("GetLocalIPAddress:  " + (DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss") + " ==> No network adapters with an IPv4 address in the system.");
            throw new Exception("No network adapters with an IPv4 address in the system.");
        }

        private int GetTotalLines(string FP, string FN)
        {
            try
            {

                FileStream logFileStream = new FileStream(Path.Combine(FP, FN), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                using (StreamReader logFileReader = new StreamReader(logFileStream))
                {

                    int i = 0;
                    while (logFileReader.ReadLine() != null) { i++; }
                    TotalLines = i;

                    logFileReader.Close();
                    logFileStream.Close();

                    App_LogFile_Write("GetTotalLines: The firewall log is accessible.");

                    // Console.WriteLine(TotalLines);

                }
            }
            catch (Exception ex)
            {
                App_LogFile_Write(ex.Message);
                MessageBox.Show(ex.Message);
            }
            return TotalLines;

        }
        /// <summary>
        /// Data Class
        /// </summary>
        public class FWLogData
        {
            public string Local_IP;
            public string FW_Date;
            public string FW_Time;
            public string Action;
            public string Protocol;
            public string Source;
            public string Destination;
            public string Src_Port;
            public string Dst_Port;
            public string Direction;
        }

        private void textBox30_TextChanged(object sender, EventArgs e)
        {

        }

        private void btnClearSearch_Click(object sender, EventArgs e)
        {
            cbSearchAction.Text = "";
            cbSearchProtocol.Text = "";
            tbSearchSrcIP.Text = "";
            tbSearchDestIP.Text = "";
            tbSearchSrcPrt.Text = "";
            tbSearchDestPrt.Text = "";
            cbSearchDirection.Text = "";
            cbEnableSearch.Checked = false;
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            tbMonIP.Text = "Local";
        }

        private void rbMonRemote_CheckedChanged(object sender, EventArgs e)
        {
            tbMonIP.Text = "Input IP Here";
            tbMonIP.Focus();
        }

        private void tbApp_Log_TextChanged(object sender, EventArgs e)
        {
            if (tbApp_Log.Visible)
            {
                tbApp_Log.SelectionStart = tbApp_Log.TextLength;
                tbApp_Log.ScrollToCaret();
            }
        }

        private void disable_controls()
        {
            rbLogLive.Enabled = false;
            App_LogFile_Write("rbLogLive: " + rbLogLive.ToString());
            rbLogFile.Enabled = false;
            App_LogFile_Write("rbLogFile: " + rbLogFile.ToString());
            Lines2Read.Enabled = false;
            App_LogFile_Write("Lines2Read: " + Lines2Read.ToString());
            ckbxIPv6.Enabled = false;
            App_LogFile_Write("ckbxIPv6: " + ckbxIPv6.ToString());
            rbMonLocal.Enabled = false;
            App_LogFile_Write("rbMonLocal: " + rbMonLocal.ToString());
            rbMonRemote.Enabled = false;
            App_LogFile_Write("rbMonRemote: " + rbMonRemote.ToString());
            tbMonIP.Enabled = false;
            App_LogFile_Write("tbMonIP: " + tbMonIP.ToString());
        }

        private void enable_controls()
        {
            rbLogLive.Enabled = true;
            // App_LogFile_Write("rbLogLive: " + rbLogLive.ToString());
            rbLogFile.Enabled = true;
            // App_LogFile_Write("rbLogFile: " + rbLogFile.ToString());
            Lines2Read.Enabled = true;
            // App_LogFile_Write("Lines2Read: " + Lines2Read.ToString());
            ckbxIPv6.Enabled = true;
            // App_LogFile_Write("ckbxIPv6: " + ckbxIPv6.ToString());
            rbMonLocal.Enabled = true;
            // App_LogFile_Write("rbMonLocal: " + rbMonLocal.ToString());
            rbMonRemote.Enabled = true;
            // App_LogFile_Write("rbMonRemote: " + rbMonRemote.ToString());
            tbMonIP.Enabled = true;
            // App_LogFile_Write("tbMonIP: " + tbMonIP.ToString());
        }

        private void fwstate(string netshcommand)
        {
            string output = string.Empty;
            string section = string.Empty;
            string FWSetting = string.Empty;
            int temp;

            tbRemFail.Visible = false;
            FWMgt_enable_controls();
            FWMgt_clear_controls();

            ProcessStartInfo procStartInfo = new ProcessStartInfo("netsh", netshcommand);
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;

            Process process = Process.Start(procStartInfo);

            using (StreamReader streamReader = process.StandardOutput)
            {
                output = streamReader.ReadToEnd();
            }

            // Console.WriteLine(output);

            char[] delimiterChars = { '\n' };

            string[] words = output.Split(delimiterChars, StringSplitOptions.RemoveEmptyEntries);

            foreach (var word in words)
            {
                RegexOptions options = RegexOptions.None;
                Regex regex = new Regex("[ ]{2,}", options);
                string test = regex.Replace(word, ">");
                // Console.WriteLine(test);
                char[] delimeterChar2 = { '>' };
                string[] FWField = test.Split(delimeterChar2, StringSplitOptions.RemoveEmptyEntries);
                foreach (var field in FWField)
                {
                    // Console.WriteLine(field.ToString().TrimEnd(' ','\r', '\n'));
                    if (field.ToString().TrimEnd(' ', '\r', '\n') == "Access is denied.")
                    {
                        // MessageBox.Show(field.ToString().TrimEnd(' ', '\r', '\n'));
                        tbRemFail.Visible = true;
                        FWMgt_disable_controls();
                    }

                    if (field.ToString().TrimEnd(' ', '\r', '\n') == "Domain Profile Settings:")
                    {
                        section = field.ToString().TrimEnd(' ', '\r', '\n');
                    }

                    if (field.ToString().TrimEnd(' ', '\r', '\n') == "Private Profile Settings:")
                    {
                        section = field.ToString().TrimEnd(' ', '\r', '\n');
                    }

                    if (field.ToString().TrimEnd(' ', '\r', '\n') == "Public Profile Settings:")
                    {
                        section = field.ToString().TrimEnd(' ', '\r', '\n');
                    }

                    if (section.ToString() == "Domain Profile Settings:")
                    {
                        switch (field.ToString().TrimEnd(' ', '\r', '\n'))
                        {
                            case "State":
                            case "Firewall Policy":
                            case "InboundUserNotification":
                            case "RemoteManagement":
                            case "UnicastResponseToMulticast":
                            case "LogAllowedConnections":
                            case "LogDroppedConnections":
                            case "FileName":
                            case "MaxFileSize":
                                FWSetting = field.ToString().TrimEnd(' ', '\r', '\n');
                                break;
                        }

                        switch (FWSetting.ToString())
                        {
                            case "State":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "OFF" || field.ToString().TrimEnd(' ', '\r', '\n') == "ON")
                                {
                                    cbDomState.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "Firewall Policy":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "BlockInbound,BlockOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "BlockInbound,AllowOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "AllowInbound,BlockOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "AllowInbound,AllowOutbound")
                                {
                                    cbDomFWPol.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "InboundUserNotification":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbDomNotify.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "RemoteManagement":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbDomRemMgt.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "UnicastResponseToMulticast":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbDomUnicast.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "LogAllowedConnections":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbDomLogAllow.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "LogDroppedConnections":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbDomLogDeny.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "FileName":
                                tbDomFileName.Text = field.ToString().TrimEnd(' ', '\r', '\n');
                                break;
                            case "MaxFileSize":
                                if (int.TryParse(field.ToString().TrimEnd(' ', '\r', '\n'), out temp))
                                {
                                    tbDomFileSize.Text = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                        }
                    }

                    if (section.ToString() == "Private Profile Settings:")
                    {
                        switch (field.ToString().TrimEnd(' ', '\r', '\n'))
                        {
                            case "State":
                            case "Firewall Policy":
                            case "InboundUserNotification":
                            case "RemoteManagement":
                            case "UnicastResponseToMulticast":
                            case "LogAllowedConnections":
                            case "LogDroppedConnections":
                            case "FileName":
                            case "MaxFileSize":
                                FWSetting = field.ToString().TrimEnd(' ', '\r', '\n');
                                break;
                        }

                        switch (FWSetting.ToString())
                        {
                            case "State":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "OFF" || field.ToString().TrimEnd(' ', '\r', '\n') == "ON")
                                {
                                    cbPrivState.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "Firewall Policy":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "BlockInbound,BlockOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "BlockInbound,AllowOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "AllowInbound,BlockOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "AllowInbound,AllowOutbound")
                                {
                                    cbPrivFWPol.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "InboundUserNotification":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPrivNotify.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "RemoteManagement":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPrivRemMgt.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "UnicastResponseToMulticast":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPrivUnicast.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "LogAllowedConnections":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPrivLogAllow.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "LogDroppedConnections":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPrivLogDeny.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "FileName":
                                tbPrivFileName.Text = field.ToString().TrimEnd(' ', '\r', '\n');
                                break;
                            case "MaxFileSize":
                                if (int.TryParse(field.ToString().TrimEnd(' ', '\r', '\n'), out temp))
                                {
                                    tbPrivFileSize.Text = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                        }
                    }

                    if (section.ToString() == "Public Profile Settings:")
                    {
                        switch (field.ToString().TrimEnd(' ', '\r', '\n'))
                        {
                            case "State":
                            case "Firewall Policy":
                            case "InboundUserNotification":
                            case "RemoteManagement":
                            case "UnicastResponseToMulticast":
                            case "LogAllowedConnections":
                            case "LogDroppedConnections":
                            case "FileName":
                            case "MaxFileSize":
                                FWSetting = field.ToString().TrimEnd(' ', '\r', '\n');
                                break;
                        }

                        switch (FWSetting.ToString())
                        {
                            case "State":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "OFF" || field.ToString().TrimEnd(' ', '\r', '\n') == "ON")
                                {
                                    cbPubState.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "Firewall Policy":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "BlockInbound,BlockOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "BlockInbound,AllowOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "AllowInbound,BlockOutbound" || field.ToString().TrimEnd(' ', '\r', '\n') == "AllowInbound,AllowOutbound")
                                {
                                    cbPubFWPol.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "InboundUserNotification":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPubNotify.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "RemoteManagement":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPubRemMgt.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "UnicastResponseToMulticast":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPubUnicast.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "LogAllowedConnections":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPubLogAllow.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "LogDroppedConnections":
                                if (field.ToString().TrimEnd(' ', '\r', '\n') == "Disable" || field.ToString().TrimEnd(' ', '\r', '\n') == "Enable")
                                {
                                    cbPubLogDeny.SelectedItem = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                            case "FileName":
                                tbPubFileName.Text = field.ToString().TrimEnd(' ', '\r', '\n');
                                break;
                            case "MaxFileSize":
                                if (int.TryParse(field.ToString().TrimEnd(' ', '\r', '\n'), out temp))
                                {
                                    tbPubFileSize.Text = field.ToString().TrimEnd(' ', '\r', '\n');
                                }
                                break;
                        }
                    }
                }
            }
        }

        private void button1_Click_1(object sender, EventArgs e)
        {
            if (rbMonRemote.Checked)
            {
                fwstate("-r " + tbMonIP.Text + " advfirewall show allprofiles");
            }
            else
            {
                fwstate("advfirewall show allprofiles");
            }
        }

        private void FWMgt_disable_controls()
        {
            cbDomState.Enabled = false;
            cbDomFWPol.Enabled = false;
            cbDomNotify.Enabled = false;
            cbDomRemMgt.Enabled = false;
            cbDomUnicast.Enabled = false;
            cbDomLogAllow.Enabled = false;
            cbDomLogDeny.Enabled = false;
            tbDomFileName.Enabled = false;
            tbDomFileSize.Enabled = false;
            cbPrivState.Enabled = false;
            cbPrivFWPol.Enabled = false;
            cbPrivNotify.Enabled = false;
            cbPrivRemMgt.Enabled = false;
            cbPrivUnicast.Enabled = false;
            cbPrivLogAllow.Enabled = false;
            cbPrivLogDeny.Enabled = false;
            tbPrivFileName.Enabled = false;
            tbPrivFileSize.Enabled = false;
            cbPubState.Enabled = false;
            cbPubFWPol.Enabled = false;
            cbPubNotify.Enabled = false;
            cbPubRemMgt.Enabled = false;
            cbPubUnicast.Enabled = false;
            cbPubLogAllow.Enabled = false;
            cbPubLogDeny.Enabled = false;
            tbPubFileName.Enabled = false;
            tbPubFileSize.Enabled = false;
        }

        private void FWMgt_enable_controls()
        {
            cbDomState.Enabled = true;
            cbDomFWPol.Enabled = true;
            cbDomNotify.Enabled = true;
            cbDomRemMgt.Enabled = true;
            cbDomUnicast.Enabled = true;
            cbDomLogAllow.Enabled = true;
            cbDomLogDeny.Enabled = true;
            tbDomFileName.Enabled = true;
            tbDomFileSize.Enabled = true;
            cbPrivState.Enabled = true;
            cbPrivFWPol.Enabled = true;
            cbPrivNotify.Enabled = true;
            cbPrivRemMgt.Enabled = true;
            cbPrivUnicast.Enabled = true;
            cbPrivLogAllow.Enabled = true;
            cbPrivLogDeny.Enabled = true;
            tbPrivFileName.Enabled = true;
            tbPrivFileSize.Enabled = true;
            cbPubState.Enabled = true;
            cbPubFWPol.Enabled = true;
            cbPubNotify.Enabled = true;
            cbPubRemMgt.Enabled = true;
            cbPubUnicast.Enabled = true;
            cbPubLogAllow.Enabled = true;
            cbPubLogDeny.Enabled = true;
            tbPubFileName.Enabled = true;
            tbPubFileSize.Enabled = true;
        }
        private void FWMgt_clear_controls()
        {
            cbDomState.Text = null;
            cbDomFWPol.Text = null;
            cbDomNotify.Text = null;
            cbDomRemMgt.Text = null;
            cbDomUnicast.Text = null;
            cbDomLogAllow.Text = null;
            cbDomLogDeny.Text = null;
            tbDomFileName.Text = null;
            tbDomFileSize.Text = null;
            cbPrivState.Text = null;
            cbPrivFWPol.Text = null;
            cbPrivNotify.Text = null;
            cbPrivRemMgt.Text = null;
            cbPrivUnicast.Text = null;
            cbPrivLogAllow.Text = null;
            cbPrivLogDeny.Text = null;
            tbPrivFileName.Text = null;
            tbPrivFileSize.Text = null;
            cbPubState.Text = null;
            cbPubFWPol.Text = null;
            cbPubNotify.Text = null;
            cbPubRemMgt.Text = null;
            cbPubUnicast.Text = null;
            cbPubLogAllow.Text = null;
            cbPubLogDeny.Text = null;
            tbPubFileName.Text = null;
            tbPubFileSize.Text = null;
        }

        private void fwrulebase(string netshcommand)
        {
            string output = string.Empty;
            string section = string.Empty;
            string FWSetting = string.Empty;
            int temp;

            tbRemFail2.Visible = false;
            FWRulebase_enable_controls();
            FWRulebase_clear_controls();

            ProcessStartInfo procStartInfo = new ProcessStartInfo("netsh", netshcommand);
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;

            Process process = Process.Start(procStartInfo);

            using (StreamReader streamReader = process.StandardOutput)
            {
                output = streamReader.ReadToEnd();
            }

            // Console.WriteLine(output);

            char[] delimiterChars = { '\n' };

            string[] words = output.Split(delimiterChars, StringSplitOptions.RemoveEmptyEntries);

            foreach (var word in words)
            {
                RegexOptions options = RegexOptions.None;
                Regex regex = new Regex("[ ]{2,}", options);
                string test = regex.Replace(word, ">");
                Console.WriteLine(test);
                if (test.Length > 12)
                {
                    if (test.Substring(0, 11) == "Rule Name:>")
                    {
                        lbRulebase.Items.Add(test.Substring(11, test.Length - 11));
                    }
                }
                char[] delimeterChar2 = { '>' };
                string[] FWField = test.Split(delimeterChar2, StringSplitOptions.RemoveEmptyEntries);
                foreach (var field in FWField)
                {
                    // Console.WriteLine(field.ToString().TrimEnd(' ','\r', '\n'));
                    if (field.ToString().TrimEnd(' ', '\r', '\n') == "Access is denied.")
                    {
                        // MessageBox.Show(field.ToString().TrimEnd(' ', '\r', '\n'));
                        tbRemFail2.Visible = true;
                        FWRulebase_disable_controls();
                    }
                }
            }
        }

        private void btn_Rulebase_Click(object sender, EventArgs e)
        {
            if (rbMonRemote.Checked)
            {
                fwrulebase("-r " + tbMonIP.Text + " advfirewall firewall show rule all");
            }
            else
            {
                fwrulebase("advfirewall firewall show rule all");
            }
        }

        private void FWRulebase_disable_controls()
        {
            tbRuleName.Enabled = false;
            cbRuleEnabled.Enabled = false;
            cbRuleDirection.Enabled = false;
            cbRuleProfile.Enabled = false;
            tbRuleLocalIP.Enabled = false;
            tbRuleRemIP.Enabled = false;
            cbRuleProtocol.Enabled = false;
            tbRuleGrouping.Enabled = false;
            tbRuleProg.Enabled = false;
            tbRuleService.Enabled = false;
            tbRuleLocalPort.Enabled = false;
            tbRuleRemPort.Enabled = false;
            cbRuleAction.Enabled = false;
            tbRuleDesc.Enabled = false;
            tbRuleCompGroup.Enabled = false;
            tbRuleUserGroup.Enabled = false;
            cbRuleIntType.Enabled = false;
            cbRuleEdgeTrav.Enabled = false;
            cbRuleSecurity.Enabled = false;
            lbRulebase.Enabled = false;
        }

        private void FWRulebase_enable_controls()
        {
            tbRuleName.Enabled = true;
            cbRuleEnabled.Enabled = true;
            cbRuleDirection.Enabled = true;
            cbRuleProfile.Enabled = true;
            tbRuleLocalIP.Enabled = true;
            tbRuleRemIP.Enabled = true;
            cbRuleProtocol.Enabled = true;
            tbRuleGrouping.Enabled = true;
            tbRuleProg.Enabled = true;
            tbRuleService.Enabled = true;
            tbRuleLocalPort.Enabled = true;
            tbRuleRemPort.Enabled = true;
            cbRuleAction.Enabled = true;
            tbRuleDesc.Enabled = true;
            tbRuleCompGroup.Enabled = true;
            tbRuleUserGroup.Enabled = true;
            cbRuleIntType.Enabled = true;
            cbRuleEdgeTrav.Enabled = true;
            cbRuleSecurity.Enabled = true;
            lbRulebase.Enabled = true;
        }

        private void FWRulebase_clear_controls()
        {
            tbRuleName.Text = null;
            cbRuleEnabled.Text = null;
            cbRuleDirection.Text = null;
            cbRuleProfile.Text = null;
            tbRuleLocalIP.Text = null;
            tbRuleRemIP.Text = null;
            cbRuleProtocol.Text = null;
            tbRuleGrouping.Text = null;
            tbRuleProg.Text = null;
            tbRuleService.Text = null;
            tbRuleLocalPort.Text = null;
            tbRuleRemPort.Text = null;
            cbRuleAction.Text = null;
            tbRuleDesc.Text = null;
            tbRuleCompGroup.Text = null;
            tbRuleUserGroup.Text = null;
            cbRuleIntType.Text = null;
            cbRuleEdgeTrav.Text = null;
            cbRuleSecurity.Text = null;
            lbRulebase.Text = null;
        }
    }
}
