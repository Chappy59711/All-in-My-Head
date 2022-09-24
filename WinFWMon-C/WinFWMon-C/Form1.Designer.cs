namespace WinFWMon
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle1 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle2 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle3 = new System.Windows.Forms.DataGridViewCellStyle();
            this.Exit_Btn = new System.Windows.Forms.Button();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabStats = new System.Windows.Forms.TabPage();
            this.cbPubFWPol = new System.Windows.Forms.ComboBox();
            this.cbPrivFWPol = new System.Windows.Forms.ComboBox();
            this.cbDomFWPol = new System.Windows.Forms.ComboBox();
            this.cbPubState = new System.Windows.Forms.ComboBox();
            this.cbPrivState = new System.Windows.Forms.ComboBox();
            this.cbDomState = new System.Windows.Forms.ComboBox();
            this.tbPublicProfile = new System.Windows.Forms.TextBox();
            this.tbPrivProfile = new System.Windows.Forms.TextBox();
            this.tbDomainProf = new System.Windows.Forms.TextBox();
            this.tbMaxFileSize = new System.Windows.Forms.TextBox();
            this.tbFWLogName = new System.Windows.Forms.TextBox();
            this.tbLogDropConn = new System.Windows.Forms.TextBox();
            this.tbLogAllowCon = new System.Windows.Forms.TextBox();
            this.tbUnicast = new System.Windows.Forms.TextBox();
            this.tbRemMgt = new System.Windows.Forms.TextBox();
            this.tbInbUsrNotify = new System.Windows.Forms.TextBox();
            this.tbFWPol = new System.Windows.Forms.TextBox();
            this.tbState = new System.Windows.Forms.TextBox();
            this.tabLogs = new System.Windows.Forms.TabPage();
            this.lThreadLogTitle = new System.Windows.Forms.Label();
            this.lAppLogTitle = new System.Windows.Forms.Label();
            this.tbThread_Log = new System.Windows.Forms.TextBox();
            this.tbApp_Log = new System.Windows.Forms.TextBox();
            this.tabLicense = new System.Windows.Forms.TabPage();
            this.tbEULA = new System.Windows.Forms.TextBox();
            this.tabHelp = new System.Windows.Forms.TabPage();
            this.rbMonRemote = new System.Windows.Forms.RadioButton();
            this.rbMonLocal = new System.Windows.Forms.RadioButton();
            this.tbLogRate = new System.Windows.Forms.TextBox();
            this.tbLogRate_Heading = new System.Windows.Forms.TextBox();
            this.tbLogSize_Heading = new System.Windows.Forms.TextBox();
            this.tbLogFileSize = new System.Windows.Forms.TextBox();
            this.tbLogReadTime = new System.Windows.Forms.TextBox();
            this.tbLogReadDate = new System.Windows.Forms.TextBox();
            this.tbLogRead_Heading = new System.Windows.Forms.TextBox();
            this.tbTotDrop = new System.Windows.Forms.TextBox();
            this.tbTotAllow = new System.Windows.Forms.TextBox();
            this.tbTotOth = new System.Windows.Forms.TextBox();
            this.tbTotICMP = new System.Windows.Forms.TextBox();
            this.tbTotUDP = new System.Windows.Forms.TextBox();
            this.tbTotTCP = new System.Windows.Forms.TextBox();
            this.tbTotUnk = new System.Windows.Forms.TextBox();
            this.tbTotOutb = new System.Windows.Forms.TextBox();
            this.tbTotInb = new System.Windows.Forms.TextBox();
            this.tbTotTraf = new System.Windows.Forms.TextBox();
            this.tbTotals_Heading = new System.Windows.Forms.TextBox();
            this.tbFWAct_Heading = new System.Windows.Forms.TextBox();
            this.tbDrop_Heading = new System.Windows.Forms.TextBox();
            this.tbAllow_Heading = new System.Windows.Forms.TextBox();
            this.tbProt_Heading = new System.Windows.Forms.TextBox();
            this.tbOther_Heading = new System.Windows.Forms.TextBox();
            this.tbICMP_Heading = new System.Windows.Forms.TextBox();
            this.tbUDP_Heading = new System.Windows.Forms.TextBox();
            this.tbTCP_Heading = new System.Windows.Forms.TextBox();
            this.tbTrafDir_Heading = new System.Windows.Forms.TextBox();
            this.tbUnk_Heading = new System.Windows.Forms.TextBox();
            this.tbOutB_Heading = new System.Windows.Forms.TextBox();
            this.tbInb_Heading = new System.Windows.Forms.TextBox();
            this.tbTotTraf_Heading = new System.Windows.Forms.TextBox();
            this.tbSysIP_Heading = new System.Windows.Forms.TextBox();
            this.tbNumLogsMon_Heading = new System.Windows.Forms.TextBox();
            this.tbSearchLog_Heading = new System.Windows.Forms.TextBox();
            this.tbMonIP = new System.Windows.Forms.TextBox();
            this.Lines2Read_Label = new System.Windows.Forms.Label();
            this.Lines2Read = new System.Windows.Forms.TextBox();
            this.Start_Btn = new System.Windows.Forms.Button();
            this.FWMgt_Btn = new System.Windows.Forms.Button();
            this.tbStartDate = new System.Windows.Forms.TextBox();
            this.tbUpdate = new System.Windows.Forms.TextBox();
            this.tbTitle = new System.Windows.Forms.TextBox();
            this.textBox4 = new System.Windows.Forms.TextBox();
            this.dataGridView2 = new System.Windows.Forms.DataGridView();
            this.Local_IP = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Date = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Time = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Action = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Protocol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Src = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Dst = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Src_Prt = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FW_Dst_Prt = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Direction = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.tbStatus = new System.Windows.Forms.TextBox();
            this.tbActionHeading = new System.Windows.Forms.TextBox();
            this.tbProtocolHeading = new System.Windows.Forms.TextBox();
            this.tbSrcIPHeading = new System.Windows.Forms.TextBox();
            this.tbDestIPHeading = new System.Windows.Forms.TextBox();
            this.tbSrcPrtHeading = new System.Windows.Forms.TextBox();
            this.tbDestPrtHeading = new System.Windows.Forms.TextBox();
            this.cbSearchAction = new System.Windows.Forms.ComboBox();
            this.cbSearchProtocol = new System.Windows.Forms.ComboBox();
            this.tbSearchSrcIP = new System.Windows.Forms.TextBox();
            this.tbSearchDestIP = new System.Windows.Forms.TextBox();
            this.tbSearchSrcPrt = new System.Windows.Forms.TextBox();
            this.tbSearchDestPrt = new System.Windows.Forms.TextBox();
            this.tbDirectionHeading = new System.Windows.Forms.TextBox();
            this.cbSearchDirection = new System.Windows.Forms.ComboBox();
            this.cbEnableSearch = new System.Windows.Forms.CheckBox();
            this.btnClearSearch = new System.Windows.Forms.Button();
            this.rbLogLive = new System.Windows.Forms.RadioButton();
            this.rbLogFile = new System.Windows.Forms.RadioButton();
            this.Lines2Read_Label2 = new System.Windows.Forms.Label();
            this.tbDispRecs = new System.Windows.Forms.TextBox();
            this.DispRec_Label = new System.Windows.Forms.Label();
            this.ckbxIPv6 = new System.Windows.Forms.CheckBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.cbDomNotify = new System.Windows.Forms.ComboBox();
            this.cbPrivNotify = new System.Windows.Forms.ComboBox();
            this.cbPubNotify = new System.Windows.Forms.ComboBox();
            this.cbDomRemMgt = new System.Windows.Forms.ComboBox();
            this.cbPrivRemMgt = new System.Windows.Forms.ComboBox();
            this.cbPubRemMgt = new System.Windows.Forms.ComboBox();
            this.cbDomUnicast = new System.Windows.Forms.ComboBox();
            this.cbPrivUnicast = new System.Windows.Forms.ComboBox();
            this.cbPubUnicast = new System.Windows.Forms.ComboBox();
            this.cbDomLogAllow = new System.Windows.Forms.ComboBox();
            this.cbPrivLogAllow = new System.Windows.Forms.ComboBox();
            this.cbPubLogAllow = new System.Windows.Forms.ComboBox();
            this.cbDomLogDeny = new System.Windows.Forms.ComboBox();
            this.cbPrivLogDeny = new System.Windows.Forms.ComboBox();
            this.cbPubLogDeny = new System.Windows.Forms.ComboBox();
            this.tbDomFileName = new System.Windows.Forms.TextBox();
            this.tbPrivFileName = new System.Windows.Forms.TextBox();
            this.tbPubFileName = new System.Windows.Forms.TextBox();
            this.tbDomFileSize = new System.Windows.Forms.TextBox();
            this.tbPrivFileSize = new System.Windows.Forms.TextBox();
            this.tbPubFileSize = new System.Windows.Forms.TextBox();
            this.btn_FWConfig = new System.Windows.Forms.Button();
            this.tabRulebase = new System.Windows.Forms.TabPage();
            this.tbRemFail = new System.Windows.Forms.TextBox();
            this.lbRulebase = new System.Windows.Forms.ListBox();
            this.btn_Rulebase = new System.Windows.Forms.Button();
            this.tbRuleName = new System.Windows.Forms.TextBox();
            this.l_RuleName = new System.Windows.Forms.Label();
            this.l_Rule_Enabled = new System.Windows.Forms.Label();
            this.cbRuleEnabled = new System.Windows.Forms.ComboBox();
            this.i_RuleDirection = new System.Windows.Forms.Label();
            this.cbRuleProfile = new System.Windows.Forms.ComboBox();
            this.cbRuleDirection = new System.Windows.Forms.ComboBox();
            this.l_RuleProfile = new System.Windows.Forms.Label();
            this.tbRuleLocalIP = new System.Windows.Forms.TextBox();
            this.l_LocalIP = new System.Windows.Forms.Label();
            this.tbRuleRemIP = new System.Windows.Forms.TextBox();
            this.l_RuleRemIP = new System.Windows.Forms.Label();
            this.cbRuleProtocol = new System.Windows.Forms.ComboBox();
            this.l_RuleProtocol = new System.Windows.Forms.Label();
            this.cbRuleAction = new System.Windows.Forms.ComboBox();
            this.l_RuleAction = new System.Windows.Forms.Label();
            this.tbRuleGrouping = new System.Windows.Forms.TextBox();
            this.l_RuleGrouping = new System.Windows.Forms.Label();
            this.l_RuleProg = new System.Windows.Forms.Label();
            this.tbRuleProg = new System.Windows.Forms.TextBox();
            this.tbRuleService = new System.Windows.Forms.TextBox();
            this.l_RuleService = new System.Windows.Forms.Label();
            this.tbRuleLocalPort = new System.Windows.Forms.TextBox();
            this.tbRuleRemPort = new System.Windows.Forms.TextBox();
            this.l_RuleLocalPort = new System.Windows.Forms.Label();
            this.l_RuleRemPort = new System.Windows.Forms.Label();
            this.l_RuleDesc = new System.Windows.Forms.Label();
            this.tbRuleDesc = new System.Windows.Forms.TextBox();
            this.l_RuleCompGroup = new System.Windows.Forms.Label();
            this.tbRuleCompGroup = new System.Windows.Forms.TextBox();
            this.l_RuleUserGroup = new System.Windows.Forms.Label();
            this.tbRuleUserGroup = new System.Windows.Forms.TextBox();
            this.l_RuleIntType = new System.Windows.Forms.Label();
            this.cbRuleIntType = new System.Windows.Forms.ComboBox();
            this.l_RuleEdgeTrav = new System.Windows.Forms.Label();
            this.cbRuleEdgeTrav = new System.Windows.Forms.ComboBox();
            this.l_RuleSecurity = new System.Windows.Forms.Label();
            this.cbRuleSecurity = new System.Windows.Forms.ComboBox();
            this.tbRemFail2 = new System.Windows.Forms.TextBox();
            this.tabControl1.SuspendLayout();
            this.tabStats.SuspendLayout();
            this.tabLogs.SuspendLayout();
            this.tabLicense.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView2)).BeginInit();
            this.panel1.SuspendLayout();
            this.tabRulebase.SuspendLayout();
            this.SuspendLayout();
            // 
            // Exit_Btn
            // 
            this.Exit_Btn.Location = new System.Drawing.Point(1107, 811);
            this.Exit_Btn.Name = "Exit_Btn";
            this.Exit_Btn.Size = new System.Drawing.Size(84, 23);
            this.Exit_Btn.TabIndex = 0;
            this.Exit_Btn.Text = "Exit";
            this.Exit_Btn.UseVisualStyleBackColor = true;
            this.Exit_Btn.Click += new System.EventHandler(this.button1_Click);
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabStats);
            this.tabControl1.Controls.Add(this.tabRulebase);
            this.tabControl1.Controls.Add(this.tabLogs);
            this.tabControl1.Controls.Add(this.tabLicense);
            this.tabControl1.Controls.Add(this.tabHelp);
            this.tabControl1.Location = new System.Drawing.Point(5, 539);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(1186, 270);
            this.tabControl1.TabIndex = 1;
            // 
            // tabStats
            // 
            this.tabStats.BackColor = System.Drawing.Color.Azure;
            this.tabStats.Controls.Add(this.tbRemFail);
            this.tabStats.Controls.Add(this.btn_FWConfig);
            this.tabStats.Controls.Add(this.tbPubFileSize);
            this.tabStats.Controls.Add(this.tbPrivFileSize);
            this.tabStats.Controls.Add(this.tbDomFileSize);
            this.tabStats.Controls.Add(this.tbPubFileName);
            this.tabStats.Controls.Add(this.tbPrivFileName);
            this.tabStats.Controls.Add(this.tbDomFileName);
            this.tabStats.Controls.Add(this.cbPubLogDeny);
            this.tabStats.Controls.Add(this.cbPrivLogDeny);
            this.tabStats.Controls.Add(this.cbDomLogDeny);
            this.tabStats.Controls.Add(this.cbPubLogAllow);
            this.tabStats.Controls.Add(this.cbPrivLogAllow);
            this.tabStats.Controls.Add(this.cbDomLogAllow);
            this.tabStats.Controls.Add(this.cbPubUnicast);
            this.tabStats.Controls.Add(this.cbPrivUnicast);
            this.tabStats.Controls.Add(this.cbDomUnicast);
            this.tabStats.Controls.Add(this.cbPubRemMgt);
            this.tabStats.Controls.Add(this.cbPrivRemMgt);
            this.tabStats.Controls.Add(this.cbDomRemMgt);
            this.tabStats.Controls.Add(this.cbPubNotify);
            this.tabStats.Controls.Add(this.cbPrivNotify);
            this.tabStats.Controls.Add(this.cbDomNotify);
            this.tabStats.Controls.Add(this.cbPubFWPol);
            this.tabStats.Controls.Add(this.cbPrivFWPol);
            this.tabStats.Controls.Add(this.cbDomFWPol);
            this.tabStats.Controls.Add(this.cbPubState);
            this.tabStats.Controls.Add(this.cbPrivState);
            this.tabStats.Controls.Add(this.cbDomState);
            this.tabStats.Controls.Add(this.tbPublicProfile);
            this.tabStats.Controls.Add(this.tbPrivProfile);
            this.tabStats.Controls.Add(this.tbDomainProf);
            this.tabStats.Controls.Add(this.tbMaxFileSize);
            this.tabStats.Controls.Add(this.tbFWLogName);
            this.tabStats.Controls.Add(this.tbLogDropConn);
            this.tabStats.Controls.Add(this.tbLogAllowCon);
            this.tabStats.Controls.Add(this.tbUnicast);
            this.tabStats.Controls.Add(this.tbRemMgt);
            this.tabStats.Controls.Add(this.tbInbUsrNotify);
            this.tabStats.Controls.Add(this.tbFWPol);
            this.tabStats.Controls.Add(this.tbState);
            this.tabStats.Location = new System.Drawing.Point(4, 22);
            this.tabStats.Name = "tabStats";
            this.tabStats.Padding = new System.Windows.Forms.Padding(3);
            this.tabStats.Size = new System.Drawing.Size(1178, 244);
            this.tabStats.TabIndex = 0;
            this.tabStats.Text = "FW Config";
            // 
            // cbPubFWPol
            // 
            this.cbPubFWPol.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubFWPol.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubFWPol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubFWPol.FormattingEnabled = true;
            this.cbPubFWPol.Items.AddRange(new object[] {
            "AllowInbound,AllowOutbound",
            "AllowInbound,BlockOutbound",
            "BlockInbound,AllowOutbound",
            "BlockInbound,BlockOutbound"});
            this.cbPubFWPol.Location = new System.Drawing.Point(768, 51);
            this.cbPubFWPol.Name = "cbPubFWPol";
            this.cbPubFWPol.Size = new System.Drawing.Size(280, 21);
            this.cbPubFWPol.Sorted = true;
            this.cbPubFWPol.TabIndex = 89;
            // 
            // cbPrivFWPol
            // 
            this.cbPrivFWPol.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivFWPol.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivFWPol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivFWPol.FormattingEnabled = true;
            this.cbPrivFWPol.Items.AddRange(new object[] {
            "AllowInbound,AllowOutbound",
            "AllowInbound,BlockOutbound",
            "BlockInbound,AllowOutbound",
            "BlockInbound,BlockOutbound"});
            this.cbPrivFWPol.Location = new System.Drawing.Point(469, 51);
            this.cbPrivFWPol.Name = "cbPrivFWPol";
            this.cbPrivFWPol.Size = new System.Drawing.Size(280, 21);
            this.cbPrivFWPol.Sorted = true;
            this.cbPrivFWPol.TabIndex = 88;
            // 
            // cbDomFWPol
            // 
            this.cbDomFWPol.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomFWPol.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomFWPol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomFWPol.FormattingEnabled = true;
            this.cbDomFWPol.Items.AddRange(new object[] {
            "AllowInbound,AllowOutbound",
            "AllowInbound,BlockOutbound",
            "BlockInbound,AllowOutbound",
            "BlockInbound,BlockOutbound"});
            this.cbDomFWPol.Location = new System.Drawing.Point(170, 51);
            this.cbDomFWPol.Name = "cbDomFWPol";
            this.cbDomFWPol.Size = new System.Drawing.Size(280, 21);
            this.cbDomFWPol.Sorted = true;
            this.cbDomFWPol.TabIndex = 87;
            // 
            // cbPubState
            // 
            this.cbPubState.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubState.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubState.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubState.FormattingEnabled = true;
            this.cbPubState.Items.AddRange(new object[] {
            "OFF",
            "ON"});
            this.cbPubState.Location = new System.Drawing.Point(768, 27);
            this.cbPubState.Name = "cbPubState";
            this.cbPubState.Size = new System.Drawing.Size(280, 21);
            this.cbPubState.Sorted = true;
            this.cbPubState.TabIndex = 86;
            // 
            // cbPrivState
            // 
            this.cbPrivState.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivState.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivState.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivState.FormattingEnabled = true;
            this.cbPrivState.Items.AddRange(new object[] {
            "OFF",
            "ON"});
            this.cbPrivState.Location = new System.Drawing.Point(469, 27);
            this.cbPrivState.Name = "cbPrivState";
            this.cbPrivState.Size = new System.Drawing.Size(280, 21);
            this.cbPrivState.Sorted = true;
            this.cbPrivState.TabIndex = 85;
            // 
            // cbDomState
            // 
            this.cbDomState.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomState.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomState.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomState.FormattingEnabled = true;
            this.cbDomState.Items.AddRange(new object[] {
            "OFF",
            "ON"});
            this.cbDomState.Location = new System.Drawing.Point(170, 27);
            this.cbDomState.Name = "cbDomState";
            this.cbDomState.Size = new System.Drawing.Size(280, 21);
            this.cbDomState.Sorted = true;
            this.cbDomState.TabIndex = 84;
            // 
            // tbPublicProfile
            // 
            this.tbPublicProfile.BackColor = System.Drawing.Color.SkyBlue;
            this.tbPublicProfile.Location = new System.Drawing.Point(768, 4);
            this.tbPublicProfile.Name = "tbPublicProfile";
            this.tbPublicProfile.Size = new System.Drawing.Size(280, 20);
            this.tbPublicProfile.TabIndex = 83;
            this.tbPublicProfile.Text = "Public Profile";
            this.tbPublicProfile.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbPrivProfile
            // 
            this.tbPrivProfile.BackColor = System.Drawing.Color.SkyBlue;
            this.tbPrivProfile.Location = new System.Drawing.Point(469, 4);
            this.tbPrivProfile.Name = "tbPrivProfile";
            this.tbPrivProfile.Size = new System.Drawing.Size(280, 20);
            this.tbPrivProfile.TabIndex = 82;
            this.tbPrivProfile.Text = "Private Profile";
            this.tbPrivProfile.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbDomainProf
            // 
            this.tbDomainProf.BackColor = System.Drawing.Color.SkyBlue;
            this.tbDomainProf.Location = new System.Drawing.Point(170, 4);
            this.tbDomainProf.Name = "tbDomainProf";
            this.tbDomainProf.Size = new System.Drawing.Size(280, 20);
            this.tbDomainProf.TabIndex = 81;
            this.tbDomainProf.Text = "Domain Profile";
            this.tbDomainProf.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbMaxFileSize
            // 
            this.tbMaxFileSize.BackColor = System.Drawing.Color.SkyBlue;
            this.tbMaxFileSize.Location = new System.Drawing.Point(6, 220);
            this.tbMaxFileSize.Name = "tbMaxFileSize";
            this.tbMaxFileSize.Size = new System.Drawing.Size(158, 20);
            this.tbMaxFileSize.TabIndex = 80;
            this.tbMaxFileSize.Text = "Maximum File Size";
            this.tbMaxFileSize.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbFWLogName
            // 
            this.tbFWLogName.BackColor = System.Drawing.Color.SkyBlue;
            this.tbFWLogName.Location = new System.Drawing.Point(6, 196);
            this.tbFWLogName.Name = "tbFWLogName";
            this.tbFWLogName.Size = new System.Drawing.Size(158, 20);
            this.tbFWLogName.TabIndex = 79;
            this.tbFWLogName.Text = "Filename";
            this.tbFWLogName.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbLogDropConn
            // 
            this.tbLogDropConn.BackColor = System.Drawing.Color.SkyBlue;
            this.tbLogDropConn.Location = new System.Drawing.Point(6, 172);
            this.tbLogDropConn.Name = "tbLogDropConn";
            this.tbLogDropConn.Size = new System.Drawing.Size(158, 20);
            this.tbLogDropConn.TabIndex = 78;
            this.tbLogDropConn.Text = "Log Dropped Connections";
            this.tbLogDropConn.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbLogAllowCon
            // 
            this.tbLogAllowCon.BackColor = System.Drawing.Color.SkyBlue;
            this.tbLogAllowCon.Location = new System.Drawing.Point(6, 148);
            this.tbLogAllowCon.Name = "tbLogAllowCon";
            this.tbLogAllowCon.Size = new System.Drawing.Size(158, 20);
            this.tbLogAllowCon.TabIndex = 77;
            this.tbLogAllowCon.Text = "Log Allowed Connections";
            this.tbLogAllowCon.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbUnicast
            // 
            this.tbUnicast.BackColor = System.Drawing.Color.SkyBlue;
            this.tbUnicast.Location = new System.Drawing.Point(6, 124);
            this.tbUnicast.Name = "tbUnicast";
            this.tbUnicast.Size = new System.Drawing.Size(158, 20);
            this.tbUnicast.TabIndex = 76;
            this.tbUnicast.Text = "Unicast Response to Multicast";
            this.tbUnicast.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbRemMgt
            // 
            this.tbRemMgt.BackColor = System.Drawing.Color.SkyBlue;
            this.tbRemMgt.Location = new System.Drawing.Point(6, 100);
            this.tbRemMgt.Name = "tbRemMgt";
            this.tbRemMgt.Size = new System.Drawing.Size(158, 20);
            this.tbRemMgt.TabIndex = 75;
            this.tbRemMgt.Text = "Remote Management";
            this.tbRemMgt.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbInbUsrNotify
            // 
            this.tbInbUsrNotify.BackColor = System.Drawing.Color.SkyBlue;
            this.tbInbUsrNotify.Location = new System.Drawing.Point(6, 76);
            this.tbInbUsrNotify.Name = "tbInbUsrNotify";
            this.tbInbUsrNotify.Size = new System.Drawing.Size(158, 20);
            this.tbInbUsrNotify.TabIndex = 74;
            this.tbInbUsrNotify.Text = "Inbound User Notification";
            this.tbInbUsrNotify.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbFWPol
            // 
            this.tbFWPol.BackColor = System.Drawing.Color.SkyBlue;
            this.tbFWPol.Location = new System.Drawing.Point(6, 52);
            this.tbFWPol.Name = "tbFWPol";
            this.tbFWPol.Size = new System.Drawing.Size(158, 20);
            this.tbFWPol.TabIndex = 73;
            this.tbFWPol.Text = "FW Policy";
            this.tbFWPol.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbState
            // 
            this.tbState.BackColor = System.Drawing.Color.SkyBlue;
            this.tbState.Location = new System.Drawing.Point(6, 28);
            this.tbState.Name = "tbState";
            this.tbState.Size = new System.Drawing.Size(158, 20);
            this.tbState.TabIndex = 72;
            this.tbState.Text = "State";
            this.tbState.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tabLogs
            // 
            this.tabLogs.BackColor = System.Drawing.Color.Azure;
            this.tabLogs.Controls.Add(this.lThreadLogTitle);
            this.tabLogs.Controls.Add(this.lAppLogTitle);
            this.tabLogs.Controls.Add(this.tbThread_Log);
            this.tabLogs.Controls.Add(this.tbApp_Log);
            this.tabLogs.Location = new System.Drawing.Point(4, 22);
            this.tabLogs.Name = "tabLogs";
            this.tabLogs.Padding = new System.Windows.Forms.Padding(3);
            this.tabLogs.Size = new System.Drawing.Size(1178, 244);
            this.tabLogs.TabIndex = 1;
            this.tabLogs.Text = "App Logs";
            // 
            // lThreadLogTitle
            // 
            this.lThreadLogTitle.Location = new System.Drawing.Point(595, 4);
            this.lThreadLogTitle.Name = "lThreadLogTitle";
            this.lThreadLogTitle.Size = new System.Drawing.Size(575, 13);
            this.lThreadLogTitle.TabIndex = 4;
            this.lThreadLogTitle.Text = "Thread Log";
            this.lThreadLogTitle.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            this.lThreadLogTitle.UseWaitCursor = true;
            // 
            // lAppLogTitle
            // 
            this.lAppLogTitle.Location = new System.Drawing.Point(9, 5);
            this.lAppLogTitle.Name = "lAppLogTitle";
            this.lAppLogTitle.Size = new System.Drawing.Size(575, 13);
            this.lAppLogTitle.TabIndex = 3;
            this.lAppLogTitle.Text = "Applicaton Log";
            this.lAppLogTitle.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            // 
            // tbThread_Log
            // 
            this.tbThread_Log.Location = new System.Drawing.Point(596, 21);
            this.tbThread_Log.Multiline = true;
            this.tbThread_Log.Name = "tbThread_Log";
            this.tbThread_Log.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbThread_Log.Size = new System.Drawing.Size(575, 217);
            this.tbThread_Log.TabIndex = 2;
            // 
            // tbApp_Log
            // 
            this.tbApp_Log.Location = new System.Drawing.Point(6, 21);
            this.tbApp_Log.Multiline = true;
            this.tbApp_Log.Name = "tbApp_Log";
            this.tbApp_Log.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbApp_Log.Size = new System.Drawing.Size(575, 217);
            this.tbApp_Log.TabIndex = 0;
            this.tbApp_Log.TextChanged += new System.EventHandler(this.tbApp_Log_TextChanged);
            // 
            // tabLicense
            // 
            this.tabLicense.BackColor = System.Drawing.Color.Azure;
            this.tabLicense.Controls.Add(this.tbEULA);
            this.tabLicense.Location = new System.Drawing.Point(4, 22);
            this.tabLicense.Name = "tabLicense";
            this.tabLicense.Size = new System.Drawing.Size(1178, 244);
            this.tabLicense.TabIndex = 5;
            this.tabLicense.Text = "Licensing";
            // 
            // tbEULA
            // 
            this.tbEULA.Location = new System.Drawing.Point(264, 3);
            this.tbEULA.Multiline = true;
            this.tbEULA.Name = "tbEULA";
            this.tbEULA.ReadOnly = true;
            this.tbEULA.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.tbEULA.Size = new System.Drawing.Size(909, 238);
            this.tbEULA.TabIndex = 0;
            this.tbEULA.Text = resources.GetString("tbEULA.Text");
            // 
            // tabHelp
            // 
            this.tabHelp.BackColor = System.Drawing.Color.Azure;
            this.tabHelp.Location = new System.Drawing.Point(4, 22);
            this.tabHelp.Name = "tabHelp";
            this.tabHelp.Size = new System.Drawing.Size(1178, 244);
            this.tabHelp.TabIndex = 6;
            this.tabHelp.Text = "Help";
            // 
            // rbMonRemote
            // 
            this.rbMonRemote.AutoSize = true;
            this.rbMonRemote.Location = new System.Drawing.Point(9, 55);
            this.rbMonRemote.Name = "rbMonRemote";
            this.rbMonRemote.Size = new System.Drawing.Size(62, 17);
            this.rbMonRemote.TabIndex = 55;
            this.rbMonRemote.Text = "Remote";
            this.rbMonRemote.UseVisualStyleBackColor = true;
            this.rbMonRemote.CheckedChanged += new System.EventHandler(this.rbMonRemote_CheckedChanged);
            // 
            // rbMonLocal
            // 
            this.rbMonLocal.AutoSize = true;
            this.rbMonLocal.Checked = true;
            this.rbMonLocal.Location = new System.Drawing.Point(9, 32);
            this.rbMonLocal.Name = "rbMonLocal";
            this.rbMonLocal.Size = new System.Drawing.Size(51, 17);
            this.rbMonLocal.TabIndex = 54;
            this.rbMonLocal.TabStop = true;
            this.rbMonLocal.Text = "Local";
            this.rbMonLocal.UseVisualStyleBackColor = true;
            this.rbMonLocal.CheckedChanged += new System.EventHandler(this.radioButton1_CheckedChanged);
            // 
            // tbLogRate
            // 
            this.tbLogRate.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbLogRate.Location = new System.Drawing.Point(1009, 53);
            this.tbLogRate.Name = "tbLogRate";
            this.tbLogRate.Size = new System.Drawing.Size(84, 20);
            this.tbLogRate.TabIndex = 45;
            this.tbLogRate.Text = "0";
            this.tbLogRate.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbLogRate_Heading
            // 
            this.tbLogRate_Heading.BackColor = System.Drawing.Color.CornflowerBlue;
            this.tbLogRate_Heading.Location = new System.Drawing.Point(1010, 6);
            this.tbLogRate_Heading.Name = "tbLogRate_Heading";
            this.tbLogRate_Heading.Size = new System.Drawing.Size(84, 20);
            this.tbLogRate_Heading.TabIndex = 44;
            this.tbLogRate_Heading.Text = "Log Rate (/sec)";
            this.tbLogRate_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbLogSize_Heading
            // 
            this.tbLogSize_Heading.BackColor = System.Drawing.Color.CornflowerBlue;
            this.tbLogSize_Heading.Location = new System.Drawing.Point(938, 6);
            this.tbLogSize_Heading.Name = "tbLogSize_Heading";
            this.tbLogSize_Heading.Size = new System.Drawing.Size(66, 20);
            this.tbLogSize_Heading.TabIndex = 43;
            this.tbLogSize_Heading.Text = "Log File Size";
            this.tbLogSize_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbLogFileSize
            // 
            this.tbLogFileSize.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbLogFileSize.Location = new System.Drawing.Point(938, 53);
            this.tbLogFileSize.Name = "tbLogFileSize";
            this.tbLogFileSize.Size = new System.Drawing.Size(66, 20);
            this.tbLogFileSize.TabIndex = 42;
            this.tbLogFileSize.Text = "0";
            this.tbLogFileSize.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbLogReadTime
            // 
            this.tbLogReadTime.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbLogReadTime.Location = new System.Drawing.Point(866, 53);
            this.tbLogReadTime.Name = "tbLogReadTime";
            this.tbLogReadTime.Size = new System.Drawing.Size(66, 20);
            this.tbLogReadTime.TabIndex = 41;
            this.tbLogReadTime.Text = "0";
            this.tbLogReadTime.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbLogReadDate
            // 
            this.tbLogReadDate.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbLogReadDate.Location = new System.Drawing.Point(794, 53);
            this.tbLogReadDate.Name = "tbLogReadDate";
            this.tbLogReadDate.Size = new System.Drawing.Size(66, 20);
            this.tbLogReadDate.TabIndex = 40;
            this.tbLogReadDate.Text = "0";
            this.tbLogReadDate.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbLogRead_Heading
            // 
            this.tbLogRead_Heading.BackColor = System.Drawing.Color.CornflowerBlue;
            this.tbLogRead_Heading.Location = new System.Drawing.Point(794, 6);
            this.tbLogRead_Heading.Name = "tbLogRead_Heading";
            this.tbLogRead_Heading.Size = new System.Drawing.Size(138, 20);
            this.tbLogRead_Heading.TabIndex = 39;
            this.tbLogRead_Heading.Text = "Log Last Read";
            this.tbLogRead_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotDrop
            // 
            this.tbTotDrop.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotDrop.Location = new System.Drawing.Point(733, 53);
            this.tbTotDrop.Name = "tbTotDrop";
            this.tbTotDrop.Size = new System.Drawing.Size(55, 20);
            this.tbTotDrop.TabIndex = 38;
            this.tbTotDrop.Text = "0";
            this.tbTotDrop.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotAllow
            // 
            this.tbTotAllow.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotAllow.Location = new System.Drawing.Point(672, 53);
            this.tbTotAllow.Name = "tbTotAllow";
            this.tbTotAllow.Size = new System.Drawing.Size(55, 20);
            this.tbTotAllow.TabIndex = 37;
            this.tbTotAllow.Text = "0";
            this.tbTotAllow.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotOth
            // 
            this.tbTotOth.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotOth.Location = new System.Drawing.Point(611, 53);
            this.tbTotOth.Name = "tbTotOth";
            this.tbTotOth.Size = new System.Drawing.Size(55, 20);
            this.tbTotOth.TabIndex = 36;
            this.tbTotOth.Text = "0";
            this.tbTotOth.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotICMP
            // 
            this.tbTotICMP.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotICMP.Location = new System.Drawing.Point(550, 53);
            this.tbTotICMP.Name = "tbTotICMP";
            this.tbTotICMP.Size = new System.Drawing.Size(55, 20);
            this.tbTotICMP.TabIndex = 35;
            this.tbTotICMP.Text = "0";
            this.tbTotICMP.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotUDP
            // 
            this.tbTotUDP.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotUDP.Location = new System.Drawing.Point(489, 53);
            this.tbTotUDP.Name = "tbTotUDP";
            this.tbTotUDP.Size = new System.Drawing.Size(55, 20);
            this.tbTotUDP.TabIndex = 34;
            this.tbTotUDP.Text = "0";
            this.tbTotUDP.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotTCP
            // 
            this.tbTotTCP.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotTCP.Location = new System.Drawing.Point(428, 53);
            this.tbTotTCP.Name = "tbTotTCP";
            this.tbTotTCP.Size = new System.Drawing.Size(55, 20);
            this.tbTotTCP.TabIndex = 33;
            this.tbTotTCP.Text = "0";
            this.tbTotTCP.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotUnk
            // 
            this.tbTotUnk.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotUnk.Location = new System.Drawing.Point(367, 53);
            this.tbTotUnk.Name = "tbTotUnk";
            this.tbTotUnk.Size = new System.Drawing.Size(55, 20);
            this.tbTotUnk.TabIndex = 32;
            this.tbTotUnk.Text = "0";
            this.tbTotUnk.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotOutb
            // 
            this.tbTotOutb.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotOutb.Location = new System.Drawing.Point(306, 53);
            this.tbTotOutb.Name = "tbTotOutb";
            this.tbTotOutb.Size = new System.Drawing.Size(55, 20);
            this.tbTotOutb.TabIndex = 31;
            this.tbTotOutb.Text = "0";
            this.tbTotOutb.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotInb
            // 
            this.tbTotInb.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotInb.Location = new System.Drawing.Point(245, 53);
            this.tbTotInb.Name = "tbTotInb";
            this.tbTotInb.Size = new System.Drawing.Size(55, 20);
            this.tbTotInb.TabIndex = 30;
            this.tbTotInb.Text = "0";
            this.tbTotInb.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotTraf
            // 
            this.tbTotTraf.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotTraf.Location = new System.Drawing.Point(173, 53);
            this.tbTotTraf.Name = "tbTotTraf";
            this.tbTotTraf.Size = new System.Drawing.Size(66, 20);
            this.tbTotTraf.TabIndex = 29;
            this.tbTotTraf.Text = "0";
            this.tbTotTraf.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotals_Heading
            // 
            this.tbTotals_Heading.BackColor = System.Drawing.Color.LemonChiffon;
            this.tbTotals_Heading.Location = new System.Drawing.Point(822, 29);
            this.tbTotals_Heading.Name = "tbTotals_Heading";
            this.tbTotals_Heading.Size = new System.Drawing.Size(88, 20);
            this.tbTotals_Heading.TabIndex = 28;
            this.tbTotals_Heading.Text = "Totals";
            this.tbTotals_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.tbTotals_Heading.Visible = false;
            // 
            // tbFWAct_Heading
            // 
            this.tbFWAct_Heading.BackColor = System.Drawing.Color.CornflowerBlue;
            this.tbFWAct_Heading.Location = new System.Drawing.Point(672, 6);
            this.tbFWAct_Heading.Name = "tbFWAct_Heading";
            this.tbFWAct_Heading.Size = new System.Drawing.Size(116, 20);
            this.tbFWAct_Heading.TabIndex = 27;
            this.tbFWAct_Heading.Text = "Firewall Action";
            this.tbFWAct_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbDrop_Heading
            // 
            this.tbDrop_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbDrop_Heading.Location = new System.Drawing.Point(733, 29);
            this.tbDrop_Heading.Name = "tbDrop_Heading";
            this.tbDrop_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbDrop_Heading.TabIndex = 26;
            this.tbDrop_Heading.Text = "Drop";
            this.tbDrop_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbAllow_Heading
            // 
            this.tbAllow_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbAllow_Heading.Location = new System.Drawing.Point(672, 29);
            this.tbAllow_Heading.Name = "tbAllow_Heading";
            this.tbAllow_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbAllow_Heading.TabIndex = 25;
            this.tbAllow_Heading.Text = "Allow";
            this.tbAllow_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbProt_Heading
            // 
            this.tbProt_Heading.BackColor = System.Drawing.Color.CornflowerBlue;
            this.tbProt_Heading.Location = new System.Drawing.Point(428, 6);
            this.tbProt_Heading.Name = "tbProt_Heading";
            this.tbProt_Heading.Size = new System.Drawing.Size(238, 20);
            this.tbProt_Heading.TabIndex = 24;
            this.tbProt_Heading.Text = "Protocol";
            this.tbProt_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbOther_Heading
            // 
            this.tbOther_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbOther_Heading.Location = new System.Drawing.Point(611, 29);
            this.tbOther_Heading.Name = "tbOther_Heading";
            this.tbOther_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbOther_Heading.TabIndex = 23;
            this.tbOther_Heading.Text = "Other";
            this.tbOther_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbICMP_Heading
            // 
            this.tbICMP_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbICMP_Heading.Location = new System.Drawing.Point(551, 29);
            this.tbICMP_Heading.Name = "tbICMP_Heading";
            this.tbICMP_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbICMP_Heading.TabIndex = 22;
            this.tbICMP_Heading.Text = "ICMP";
            this.tbICMP_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbUDP_Heading
            // 
            this.tbUDP_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbUDP_Heading.Location = new System.Drawing.Point(489, 29);
            this.tbUDP_Heading.Name = "tbUDP_Heading";
            this.tbUDP_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbUDP_Heading.TabIndex = 21;
            this.tbUDP_Heading.Text = "UDP";
            this.tbUDP_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTCP_Heading
            // 
            this.tbTCP_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbTCP_Heading.Location = new System.Drawing.Point(428, 29);
            this.tbTCP_Heading.Name = "tbTCP_Heading";
            this.tbTCP_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbTCP_Heading.TabIndex = 20;
            this.tbTCP_Heading.Text = "TCP";
            this.tbTCP_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTrafDir_Heading
            // 
            this.tbTrafDir_Heading.BackColor = System.Drawing.Color.CornflowerBlue;
            this.tbTrafDir_Heading.Location = new System.Drawing.Point(245, 6);
            this.tbTrafDir_Heading.Name = "tbTrafDir_Heading";
            this.tbTrafDir_Heading.Size = new System.Drawing.Size(177, 20);
            this.tbTrafDir_Heading.TabIndex = 19;
            this.tbTrafDir_Heading.Text = "Traffic Direction";
            this.tbTrafDir_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbUnk_Heading
            // 
            this.tbUnk_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbUnk_Heading.Location = new System.Drawing.Point(367, 29);
            this.tbUnk_Heading.Name = "tbUnk_Heading";
            this.tbUnk_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbUnk_Heading.TabIndex = 18;
            this.tbUnk_Heading.Text = "Unknown";
            this.tbUnk_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbOutB_Heading
            // 
            this.tbOutB_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbOutB_Heading.Location = new System.Drawing.Point(306, 29);
            this.tbOutB_Heading.Name = "tbOutB_Heading";
            this.tbOutB_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbOutB_Heading.TabIndex = 17;
            this.tbOutB_Heading.Text = "Outbound";
            this.tbOutB_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbInb_Heading
            // 
            this.tbInb_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbInb_Heading.Location = new System.Drawing.Point(245, 29);
            this.tbInb_Heading.Name = "tbInb_Heading";
            this.tbInb_Heading.Size = new System.Drawing.Size(55, 20);
            this.tbInb_Heading.TabIndex = 16;
            this.tbInb_Heading.Text = "Inbound";
            this.tbInb_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTotTraf_Heading
            // 
            this.tbTotTraf_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbTotTraf_Heading.Location = new System.Drawing.Point(173, 29);
            this.tbTotTraf_Heading.Name = "tbTotTraf_Heading";
            this.tbTotTraf_Heading.Size = new System.Drawing.Size(66, 20);
            this.tbTotTraf_Heading.TabIndex = 15;
            this.tbTotTraf_Heading.Text = "Total Traffic";
            this.tbTotTraf_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbSysIP_Heading
            // 
            this.tbSysIP_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbSysIP_Heading.Location = new System.Drawing.Point(79, 29);
            this.tbSysIP_Heading.Name = "tbSysIP_Heading";
            this.tbSysIP_Heading.Size = new System.Drawing.Size(88, 20);
            this.tbSysIP_Heading.TabIndex = 14;
            this.tbSysIP_Heading.Text = "System IP";
            this.tbSysIP_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbNumLogsMon_Heading
            // 
            this.tbNumLogsMon_Heading.BackColor = System.Drawing.Color.LightSteelBlue;
            this.tbNumLogsMon_Heading.Location = new System.Drawing.Point(7, 6);
            this.tbNumLogsMon_Heading.Name = "tbNumLogsMon_Heading";
            this.tbNumLogsMon_Heading.Size = new System.Drawing.Size(160, 20);
            this.tbNumLogsMon_Heading.TabIndex = 13;
            this.tbNumLogsMon_Heading.Text = "Monitoring X FW Logs";
            this.tbNumLogsMon_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.tbNumLogsMon_Heading.Visible = false;
            // 
            // tbSearchLog_Heading
            // 
            this.tbSearchLog_Heading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbSearchLog_Heading.Location = new System.Drawing.Point(173, 6);
            this.tbSearchLog_Heading.Name = "tbSearchLog_Heading";
            this.tbSearchLog_Heading.Size = new System.Drawing.Size(66, 20);
            this.tbSearchLog_Heading.TabIndex = 12;
            this.tbSearchLog_Heading.Text = "Search Log";
            this.tbSearchLog_Heading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.tbSearchLog_Heading.Visible = false;
            // 
            // tbMonIP
            // 
            this.tbMonIP.Location = new System.Drawing.Point(79, 53);
            this.tbMonIP.Name = "tbMonIP";
            this.tbMonIP.Size = new System.Drawing.Size(88, 20);
            this.tbMonIP.TabIndex = 11;
            this.tbMonIP.Text = "Local";
            this.tbMonIP.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // Lines2Read_Label
            // 
            this.Lines2Read_Label.AutoSize = true;
            this.Lines2Read_Label.Location = new System.Drawing.Point(154, 151);
            this.Lines2Read_Label.Name = "Lines2Read_Label";
            this.Lines2Read_Label.Size = new System.Drawing.Size(52, 13);
            this.Lines2Read_Label.TabIndex = 3;
            this.Lines2Read_Label.Text = "Read last";
            // 
            // Lines2Read
            // 
            this.Lines2Read.Location = new System.Drawing.Point(206, 148);
            this.Lines2Read.Name = "Lines2Read";
            this.Lines2Read.Size = new System.Drawing.Size(55, 20);
            this.Lines2Read.TabIndex = 2;
            this.Lines2Read.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // Start_Btn
            // 
            this.Start_Btn.FlatStyle = System.Windows.Forms.FlatStyle.Popup;
            this.Start_Btn.Location = new System.Drawing.Point(1114, 86);
            this.Start_Btn.Name = "Start_Btn";
            this.Start_Btn.Size = new System.Drawing.Size(77, 23);
            this.Start_Btn.TabIndex = 2;
            this.Start_Btn.Text = "Start";
            this.Start_Btn.UseVisualStyleBackColor = true;
            this.Start_Btn.Click += new System.EventHandler(this.button2_Click);
            // 
            // FWMgt_Btn
            // 
            this.FWMgt_Btn.Location = new System.Drawing.Point(1114, 40);
            this.FWMgt_Btn.Name = "FWMgt_Btn";
            this.FWMgt_Btn.Size = new System.Drawing.Size(77, 40);
            this.FWMgt_Btn.TabIndex = 3;
            this.FWMgt_Btn.Text = "Firewall Management";
            this.FWMgt_Btn.UseVisualStyleBackColor = true;
            this.FWMgt_Btn.Visible = false;
            // 
            // tbStartDate
            // 
            this.tbStartDate.Location = new System.Drawing.Point(5, 7);
            this.tbStartDate.Name = "tbStartDate";
            this.tbStartDate.Size = new System.Drawing.Size(201, 20);
            this.tbStartDate.TabIndex = 5;
            this.tbStartDate.Text = "Started:";
            this.tbStartDate.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbUpdate
            // 
            this.tbUpdate.Location = new System.Drawing.Point(990, 7);
            this.tbUpdate.Name = "tbUpdate";
            this.tbUpdate.Size = new System.Drawing.Size(201, 20);
            this.tbUpdate.TabIndex = 6;
            this.tbUpdate.Text = "Last Updated at:";
            this.tbUpdate.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbTitle
            // 
            this.tbTitle.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(192)))), ((int)(((byte)(0)))), ((int)(((byte)(0)))));
            this.tbTitle.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tbTitle.ForeColor = System.Drawing.Color.White;
            this.tbTitle.Location = new System.Drawing.Point(427, 2);
            this.tbTitle.Name = "tbTitle";
            this.tbTitle.Size = new System.Drawing.Size(324, 26);
            this.tbTitle.TabIndex = 7;
            this.tbTitle.Text = "Windows Firewall Log Monitor";
            this.tbTitle.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // textBox4
            // 
            this.textBox4.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(192)))), ((int)(((byte)(192)))));
            this.textBox4.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.textBox4.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.textBox4.Location = new System.Drawing.Point(5, 120);
            this.textBox4.Name = "textBox4";
            this.textBox4.Size = new System.Drawing.Size(1186, 26);
            this.textBox4.TabIndex = 8;
            this.textBox4.Text = "Consolidated Firewall Log (includes local system time & date)";
            this.textBox4.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // dataGridView2
            // 
            this.dataGridView2.AllowUserToAddRows = false;
            this.dataGridView2.AllowUserToDeleteRows = false;
            this.dataGridView2.AllowUserToResizeColumns = false;
            this.dataGridView2.AllowUserToResizeRows = false;
            dataGridViewCellStyle1.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle1.BackColor = System.Drawing.SystemColors.Control;
            dataGridViewCellStyle1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle1.ForeColor = System.Drawing.SystemColors.WindowText;
            dataGridViewCellStyle1.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle1.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle1.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.dataGridView2.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle1;
            this.dataGridView2.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView2.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.Local_IP,
            this.FW_Date,
            this.FW_Time,
            this.FW_Action,
            this.Protocol,
            this.FW_Src,
            this.FW_Dst,
            this.FW_Src_Prt,
            this.FW_Dst_Prt,
            this.Direction});
            dataGridViewCellStyle2.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle2.BackColor = System.Drawing.SystemColors.Window;
            dataGridViewCellStyle2.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle2.ForeColor = System.Drawing.SystemColors.ControlText;
            dataGridViewCellStyle2.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle2.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle2.WrapMode = System.Windows.Forms.DataGridViewTriState.False;
            this.dataGridView2.DefaultCellStyle = dataGridViewCellStyle2;
            this.dataGridView2.Location = new System.Drawing.Point(5, 194);
            this.dataGridView2.Name = "dataGridView2";
            dataGridViewCellStyle3.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle3.BackColor = System.Drawing.SystemColors.Control;
            dataGridViewCellStyle3.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            dataGridViewCellStyle3.ForeColor = System.Drawing.SystemColors.WindowText;
            dataGridViewCellStyle3.SelectionBackColor = System.Drawing.SystemColors.Highlight;
            dataGridViewCellStyle3.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle3.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.dataGridView2.RowHeadersDefaultCellStyle = dataGridViewCellStyle3;
            this.dataGridView2.Size = new System.Drawing.Size(1186, 339);
            this.dataGridView2.TabIndex = 9;
            // 
            // Local_IP
            // 
            this.Local_IP.HeaderText = "Log IP";
            this.Local_IP.Name = "Local_IP";
            // 
            // FW_Date
            // 
            this.FW_Date.HeaderText = "FW Date";
            this.FW_Date.Name = "FW_Date";
            // 
            // FW_Time
            // 
            this.FW_Time.HeaderText = "FW Time";
            this.FW_Time.Name = "FW_Time";
            // 
            // FW_Action
            // 
            this.FW_Action.HeaderText = "Action";
            this.FW_Action.Name = "FW_Action";
            // 
            // Protocol
            // 
            this.Protocol.HeaderText = "Protocol";
            this.Protocol.Name = "Protocol";
            // 
            // FW_Src
            // 
            this.FW_Src.HeaderText = "Source";
            this.FW_Src.Name = "FW_Src";
            // 
            // FW_Dst
            // 
            this.FW_Dst.HeaderText = "Destination";
            this.FW_Dst.Name = "FW_Dst";
            // 
            // FW_Src_Prt
            // 
            this.FW_Src_Prt.HeaderText = "Src Port";
            this.FW_Src_Prt.Name = "FW_Src_Prt";
            // 
            // FW_Dst_Prt
            // 
            this.FW_Dst_Prt.HeaderText = "Dst Port";
            this.FW_Dst_Prt.Name = "FW_Dst_Prt";
            // 
            // Direction
            // 
            this.Direction.HeaderText = "Direction";
            this.Direction.Name = "Direction";
            // 
            // tbStatus
            // 
            this.tbStatus.Location = new System.Drawing.Point(5, 814);
            this.tbStatus.Name = "tbStatus";
            this.tbStatus.Size = new System.Drawing.Size(647, 20);
            this.tbStatus.TabIndex = 10;
            // 
            // tbActionHeading
            // 
            this.tbActionHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbActionHeading.Location = new System.Drawing.Point(348, 149);
            this.tbActionHeading.Name = "tbActionHeading";
            this.tbActionHeading.Size = new System.Drawing.Size(98, 20);
            this.tbActionHeading.TabIndex = 39;
            this.tbActionHeading.Text = "Action";
            this.tbActionHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbProtocolHeading
            // 
            this.tbProtocolHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbProtocolHeading.Location = new System.Drawing.Point(448, 149);
            this.tbProtocolHeading.Name = "tbProtocolHeading";
            this.tbProtocolHeading.Size = new System.Drawing.Size(98, 20);
            this.tbProtocolHeading.TabIndex = 40;
            this.tbProtocolHeading.Text = "Protocol";
            this.tbProtocolHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbSrcIPHeading
            // 
            this.tbSrcIPHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbSrcIPHeading.Location = new System.Drawing.Point(548, 149);
            this.tbSrcIPHeading.Name = "tbSrcIPHeading";
            this.tbSrcIPHeading.Size = new System.Drawing.Size(98, 20);
            this.tbSrcIPHeading.TabIndex = 41;
            this.tbSrcIPHeading.Text = "Source IP";
            this.tbSrcIPHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbDestIPHeading
            // 
            this.tbDestIPHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbDestIPHeading.Location = new System.Drawing.Point(648, 149);
            this.tbDestIPHeading.Name = "tbDestIPHeading";
            this.tbDestIPHeading.Size = new System.Drawing.Size(98, 20);
            this.tbDestIPHeading.TabIndex = 42;
            this.tbDestIPHeading.Text = "Destination IP";
            this.tbDestIPHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbSrcPrtHeading
            // 
            this.tbSrcPrtHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbSrcPrtHeading.Location = new System.Drawing.Point(748, 149);
            this.tbSrcPrtHeading.Name = "tbSrcPrtHeading";
            this.tbSrcPrtHeading.Size = new System.Drawing.Size(98, 20);
            this.tbSrcPrtHeading.TabIndex = 43;
            this.tbSrcPrtHeading.Text = "Source Port";
            this.tbSrcPrtHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbDestPrtHeading
            // 
            this.tbDestPrtHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbDestPrtHeading.Location = new System.Drawing.Point(848, 149);
            this.tbDestPrtHeading.Name = "tbDestPrtHeading";
            this.tbDestPrtHeading.Size = new System.Drawing.Size(98, 20);
            this.tbDestPrtHeading.TabIndex = 44;
            this.tbDestPrtHeading.Text = "Destination Port";
            this.tbDestPrtHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // cbSearchAction
            // 
            this.cbSearchAction.AllowDrop = true;
            this.cbSearchAction.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbSearchAction.FormattingEnabled = true;
            this.cbSearchAction.Items.AddRange(new object[] {
            "",
            "ALLOW",
            "DROP"});
            this.cbSearchAction.Location = new System.Drawing.Point(348, 171);
            this.cbSearchAction.MaxDropDownItems = 2;
            this.cbSearchAction.Name = "cbSearchAction";
            this.cbSearchAction.Size = new System.Drawing.Size(98, 21);
            this.cbSearchAction.Sorted = true;
            this.cbSearchAction.TabIndex = 45;
            // 
            // cbSearchProtocol
            // 
            this.cbSearchProtocol.AllowDrop = true;
            this.cbSearchProtocol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbSearchProtocol.FormattingEnabled = true;
            this.cbSearchProtocol.Items.AddRange(new object[] {
            "",
            "ICMP",
            "Other",
            "TCP",
            "UDP"});
            this.cbSearchProtocol.Location = new System.Drawing.Point(448, 171);
            this.cbSearchProtocol.MaxDropDownItems = 2;
            this.cbSearchProtocol.Name = "cbSearchProtocol";
            this.cbSearchProtocol.Size = new System.Drawing.Size(98, 21);
            this.cbSearchProtocol.Sorted = true;
            this.cbSearchProtocol.TabIndex = 46;
            // 
            // tbSearchSrcIP
            // 
            this.tbSearchSrcIP.Location = new System.Drawing.Point(548, 171);
            this.tbSearchSrcIP.Name = "tbSearchSrcIP";
            this.tbSearchSrcIP.Size = new System.Drawing.Size(98, 20);
            this.tbSearchSrcIP.TabIndex = 39;
            this.tbSearchSrcIP.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbSearchDestIP
            // 
            this.tbSearchDestIP.Location = new System.Drawing.Point(648, 171);
            this.tbSearchDestIP.Name = "tbSearchDestIP";
            this.tbSearchDestIP.Size = new System.Drawing.Size(98, 20);
            this.tbSearchDestIP.TabIndex = 47;
            this.tbSearchDestIP.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbSearchSrcPrt
            // 
            this.tbSearchSrcPrt.Location = new System.Drawing.Point(748, 171);
            this.tbSearchSrcPrt.Name = "tbSearchSrcPrt";
            this.tbSearchSrcPrt.Size = new System.Drawing.Size(98, 20);
            this.tbSearchSrcPrt.TabIndex = 48;
            this.tbSearchSrcPrt.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tbSearchDestPrt
            // 
            this.tbSearchDestPrt.Location = new System.Drawing.Point(848, 171);
            this.tbSearchDestPrt.Name = "tbSearchDestPrt";
            this.tbSearchDestPrt.Size = new System.Drawing.Size(98, 20);
            this.tbSearchDestPrt.TabIndex = 49;
            this.tbSearchDestPrt.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.tbSearchDestPrt.TextChanged += new System.EventHandler(this.textBox30_TextChanged);
            // 
            // tbDirectionHeading
            // 
            this.tbDirectionHeading.BackColor = System.Drawing.Color.SkyBlue;
            this.tbDirectionHeading.Location = new System.Drawing.Point(949, 149);
            this.tbDirectionHeading.Name = "tbDirectionHeading";
            this.tbDirectionHeading.Size = new System.Drawing.Size(98, 20);
            this.tbDirectionHeading.TabIndex = 50;
            this.tbDirectionHeading.Text = "Direction";
            this.tbDirectionHeading.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // cbSearchDirection
            // 
            this.cbSearchDirection.AllowDrop = true;
            this.cbSearchDirection.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbSearchDirection.FormattingEnabled = true;
            this.cbSearchDirection.Items.AddRange(new object[] {
            "",
            "RECEIVE",
            "SEND"});
            this.cbSearchDirection.Location = new System.Drawing.Point(949, 171);
            this.cbSearchDirection.MaxDropDownItems = 2;
            this.cbSearchDirection.Name = "cbSearchDirection";
            this.cbSearchDirection.Size = new System.Drawing.Size(98, 21);
            this.cbSearchDirection.Sorted = true;
            this.cbSearchDirection.TabIndex = 51;
            // 
            // cbEnableSearch
            // 
            this.cbEnableSearch.AutoSize = true;
            this.cbEnableSearch.Location = new System.Drawing.Point(1091, 151);
            this.cbEnableSearch.Name = "cbEnableSearch";
            this.cbEnableSearch.Size = new System.Drawing.Size(96, 17);
            this.cbEnableSearch.TabIndex = 52;
            this.cbEnableSearch.Text = "Enable Search";
            this.cbEnableSearch.UseVisualStyleBackColor = true;
            // 
            // btnClearSearch
            // 
            this.btnClearSearch.Location = new System.Drawing.Point(1090, 169);
            this.btnClearSearch.Name = "btnClearSearch";
            this.btnClearSearch.Size = new System.Drawing.Size(101, 23);
            this.btnClearSearch.TabIndex = 53;
            this.btnClearSearch.Text = "Clear Search";
            this.btnClearSearch.UseVisualStyleBackColor = true;
            this.btnClearSearch.Click += new System.EventHandler(this.btnClearSearch_Click);
            // 
            // rbLogLive
            // 
            this.rbLogLive.AutoSize = true;
            this.rbLogLive.Checked = true;
            this.rbLogLive.Location = new System.Drawing.Point(20, 149);
            this.rbLogLive.Name = "rbLogLive";
            this.rbLogLive.Size = new System.Drawing.Size(45, 17);
            this.rbLogLive.TabIndex = 54;
            this.rbLogLive.TabStop = true;
            this.rbLogLive.Text = "Live";
            this.rbLogLive.UseVisualStyleBackColor = true;
            // 
            // rbLogFile
            // 
            this.rbLogFile.AutoSize = true;
            this.rbLogFile.Location = new System.Drawing.Point(89, 149);
            this.rbLogFile.Name = "rbLogFile";
            this.rbLogFile.Size = new System.Drawing.Size(62, 17);
            this.rbLogFile.TabIndex = 55;
            this.rbLogFile.Text = "Log File";
            this.rbLogFile.UseVisualStyleBackColor = true;
            // 
            // Lines2Read_Label2
            // 
            this.Lines2Read_Label2.AutoSize = true;
            this.Lines2Read_Label2.Location = new System.Drawing.Point(262, 152);
            this.Lines2Read_Label2.Name = "Lines2Read_Label2";
            this.Lines2Read_Label2.Size = new System.Drawing.Size(28, 13);
            this.Lines2Read_Label2.TabIndex = 56;
            this.Lines2Read_Label2.Text = "lines";
            // 
            // tbDispRecs
            // 
            this.tbDispRecs.Location = new System.Drawing.Point(1030, 813);
            this.tbDispRecs.Name = "tbDispRecs";
            this.tbDispRecs.Size = new System.Drawing.Size(57, 20);
            this.tbDispRecs.TabIndex = 57;
            this.tbDispRecs.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // DispRec_Label
            // 
            this.DispRec_Label.AutoSize = true;
            this.DispRec_Label.Location = new System.Drawing.Point(928, 817);
            this.DispRec_Label.Name = "DispRec_Label";
            this.DispRec_Label.Size = new System.Drawing.Size(99, 13);
            this.DispRec_Label.TabIndex = 58;
            this.DispRec_Label.Text = "Displayed Records:";
            // 
            // ckbxIPv6
            // 
            this.ckbxIPv6.AutoSize = true;
            this.ckbxIPv6.Location = new System.Drawing.Point(20, 173);
            this.ckbxIPv6.Name = "ckbxIPv6";
            this.ckbxIPv6.Size = new System.Drawing.Size(119, 17);
            this.ckbxIPv6.TabIndex = 59;
            this.ckbxIPv6.Text = "Include IPv6 Traffic";
            this.ckbxIPv6.UseVisualStyleBackColor = true;
            // 
            // panel1
            // 
            this.panel1.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.panel1.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.panel1.Controls.Add(this.tbLogRate);
            this.panel1.Controls.Add(this.rbMonRemote);
            this.panel1.Controls.Add(this.tbLogFileSize);
            this.panel1.Controls.Add(this.tbNumLogsMon_Heading);
            this.panel1.Controls.Add(this.tbLogReadTime);
            this.panel1.Controls.Add(this.rbMonLocal);
            this.panel1.Controls.Add(this.tbLogReadDate);
            this.panel1.Controls.Add(this.tbSearchLog_Heading);
            this.panel1.Controls.Add(this.tbTotDrop);
            this.panel1.Controls.Add(this.tbTrafDir_Heading);
            this.panel1.Controls.Add(this.tbTotAllow);
            this.panel1.Controls.Add(this.tbLogRate_Heading);
            this.panel1.Controls.Add(this.tbTotOth);
            this.panel1.Controls.Add(this.tbProt_Heading);
            this.panel1.Controls.Add(this.tbTotICMP);
            this.panel1.Controls.Add(this.tbLogSize_Heading);
            this.panel1.Controls.Add(this.tbTotUDP);
            this.panel1.Controls.Add(this.tbFWAct_Heading);
            this.panel1.Controls.Add(this.tbTotTCP);
            this.panel1.Controls.Add(this.tbLogRead_Heading);
            this.panel1.Controls.Add(this.tbTotUnk);
            this.panel1.Controls.Add(this.tbSysIP_Heading);
            this.panel1.Controls.Add(this.tbTotOutb);
            this.panel1.Controls.Add(this.tbMonIP);
            this.panel1.Controls.Add(this.tbTotInb);
            this.panel1.Controls.Add(this.tbTotTraf_Heading);
            this.panel1.Controls.Add(this.tbTotTraf);
            this.panel1.Controls.Add(this.tbInb_Heading);
            this.panel1.Controls.Add(this.tbTotals_Heading);
            this.panel1.Controls.Add(this.tbOutB_Heading);
            this.panel1.Controls.Add(this.tbDrop_Heading);
            this.panel1.Controls.Add(this.tbUnk_Heading);
            this.panel1.Controls.Add(this.tbAllow_Heading);
            this.panel1.Controls.Add(this.tbTCP_Heading);
            this.panel1.Controls.Add(this.tbOther_Heading);
            this.panel1.Controls.Add(this.tbUDP_Heading);
            this.panel1.Controls.Add(this.tbICMP_Heading);
            this.panel1.Location = new System.Drawing.Point(5, 34);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(1103, 80);
            this.panel1.TabIndex = 60;
            // 
            // cbDomNotify
            // 
            this.cbDomNotify.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomNotify.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomNotify.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomNotify.FormattingEnabled = true;
            this.cbDomNotify.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbDomNotify.Location = new System.Drawing.Point(170, 76);
            this.cbDomNotify.Name = "cbDomNotify";
            this.cbDomNotify.Size = new System.Drawing.Size(280, 21);
            this.cbDomNotify.Sorted = true;
            this.cbDomNotify.TabIndex = 90;
            // 
            // cbPrivNotify
            // 
            this.cbPrivNotify.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivNotify.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivNotify.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivNotify.FormattingEnabled = true;
            this.cbPrivNotify.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPrivNotify.Location = new System.Drawing.Point(469, 76);
            this.cbPrivNotify.Name = "cbPrivNotify";
            this.cbPrivNotify.Size = new System.Drawing.Size(280, 21);
            this.cbPrivNotify.Sorted = true;
            this.cbPrivNotify.TabIndex = 91;
            // 
            // cbPubNotify
            // 
            this.cbPubNotify.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubNotify.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubNotify.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubNotify.FormattingEnabled = true;
            this.cbPubNotify.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPubNotify.Location = new System.Drawing.Point(768, 76);
            this.cbPubNotify.Name = "cbPubNotify";
            this.cbPubNotify.Size = new System.Drawing.Size(280, 21);
            this.cbPubNotify.Sorted = true;
            this.cbPubNotify.TabIndex = 92;
            // 
            // cbDomRemMgt
            // 
            this.cbDomRemMgt.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomRemMgt.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomRemMgt.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomRemMgt.FormattingEnabled = true;
            this.cbDomRemMgt.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbDomRemMgt.Location = new System.Drawing.Point(170, 100);
            this.cbDomRemMgt.Name = "cbDomRemMgt";
            this.cbDomRemMgt.Size = new System.Drawing.Size(280, 21);
            this.cbDomRemMgt.Sorted = true;
            this.cbDomRemMgt.TabIndex = 93;
            // 
            // cbPrivRemMgt
            // 
            this.cbPrivRemMgt.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivRemMgt.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivRemMgt.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivRemMgt.FormattingEnabled = true;
            this.cbPrivRemMgt.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPrivRemMgt.Location = new System.Drawing.Point(469, 100);
            this.cbPrivRemMgt.Name = "cbPrivRemMgt";
            this.cbPrivRemMgt.Size = new System.Drawing.Size(280, 21);
            this.cbPrivRemMgt.Sorted = true;
            this.cbPrivRemMgt.TabIndex = 94;
            // 
            // cbPubRemMgt
            // 
            this.cbPubRemMgt.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubRemMgt.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubRemMgt.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubRemMgt.FormattingEnabled = true;
            this.cbPubRemMgt.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPubRemMgt.Location = new System.Drawing.Point(768, 100);
            this.cbPubRemMgt.Name = "cbPubRemMgt";
            this.cbPubRemMgt.Size = new System.Drawing.Size(280, 21);
            this.cbPubRemMgt.Sorted = true;
            this.cbPubRemMgt.TabIndex = 95;
            // 
            // cbDomUnicast
            // 
            this.cbDomUnicast.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomUnicast.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomUnicast.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomUnicast.FormattingEnabled = true;
            this.cbDomUnicast.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbDomUnicast.Location = new System.Drawing.Point(170, 124);
            this.cbDomUnicast.Name = "cbDomUnicast";
            this.cbDomUnicast.Size = new System.Drawing.Size(280, 21);
            this.cbDomUnicast.Sorted = true;
            this.cbDomUnicast.TabIndex = 96;
            // 
            // cbPrivUnicast
            // 
            this.cbPrivUnicast.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivUnicast.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivUnicast.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivUnicast.FormattingEnabled = true;
            this.cbPrivUnicast.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPrivUnicast.Location = new System.Drawing.Point(469, 124);
            this.cbPrivUnicast.Name = "cbPrivUnicast";
            this.cbPrivUnicast.Size = new System.Drawing.Size(280, 21);
            this.cbPrivUnicast.Sorted = true;
            this.cbPrivUnicast.TabIndex = 97;
            // 
            // cbPubUnicast
            // 
            this.cbPubUnicast.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubUnicast.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubUnicast.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubUnicast.FormattingEnabled = true;
            this.cbPubUnicast.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPubUnicast.Location = new System.Drawing.Point(768, 124);
            this.cbPubUnicast.Name = "cbPubUnicast";
            this.cbPubUnicast.Size = new System.Drawing.Size(280, 21);
            this.cbPubUnicast.Sorted = true;
            this.cbPubUnicast.TabIndex = 98;
            // 
            // cbDomLogAllow
            // 
            this.cbDomLogAllow.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomLogAllow.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomLogAllow.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomLogAllow.FormattingEnabled = true;
            this.cbDomLogAllow.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbDomLogAllow.Location = new System.Drawing.Point(170, 148);
            this.cbDomLogAllow.Name = "cbDomLogAllow";
            this.cbDomLogAllow.Size = new System.Drawing.Size(280, 21);
            this.cbDomLogAllow.Sorted = true;
            this.cbDomLogAllow.TabIndex = 99;
            // 
            // cbPrivLogAllow
            // 
            this.cbPrivLogAllow.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivLogAllow.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivLogAllow.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivLogAllow.FormattingEnabled = true;
            this.cbPrivLogAllow.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPrivLogAllow.Location = new System.Drawing.Point(469, 148);
            this.cbPrivLogAllow.Name = "cbPrivLogAllow";
            this.cbPrivLogAllow.Size = new System.Drawing.Size(280, 21);
            this.cbPrivLogAllow.Sorted = true;
            this.cbPrivLogAllow.TabIndex = 100;
            // 
            // cbPubLogAllow
            // 
            this.cbPubLogAllow.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubLogAllow.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubLogAllow.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubLogAllow.FormattingEnabled = true;
            this.cbPubLogAllow.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPubLogAllow.Location = new System.Drawing.Point(768, 148);
            this.cbPubLogAllow.Name = "cbPubLogAllow";
            this.cbPubLogAllow.Size = new System.Drawing.Size(280, 21);
            this.cbPubLogAllow.Sorted = true;
            this.cbPubLogAllow.TabIndex = 101;
            // 
            // cbDomLogDeny
            // 
            this.cbDomLogDeny.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbDomLogDeny.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbDomLogDeny.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbDomLogDeny.FormattingEnabled = true;
            this.cbDomLogDeny.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbDomLogDeny.Location = new System.Drawing.Point(170, 172);
            this.cbDomLogDeny.Name = "cbDomLogDeny";
            this.cbDomLogDeny.Size = new System.Drawing.Size(280, 21);
            this.cbDomLogDeny.Sorted = true;
            this.cbDomLogDeny.TabIndex = 102;
            // 
            // cbPrivLogDeny
            // 
            this.cbPrivLogDeny.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPrivLogDeny.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPrivLogDeny.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPrivLogDeny.FormattingEnabled = true;
            this.cbPrivLogDeny.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPrivLogDeny.Location = new System.Drawing.Point(469, 172);
            this.cbPrivLogDeny.Name = "cbPrivLogDeny";
            this.cbPrivLogDeny.Size = new System.Drawing.Size(280, 21);
            this.cbPrivLogDeny.Sorted = true;
            this.cbPrivLogDeny.TabIndex = 103;
            // 
            // cbPubLogDeny
            // 
            this.cbPubLogDeny.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbPubLogDeny.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbPubLogDeny.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbPubLogDeny.FormattingEnabled = true;
            this.cbPubLogDeny.Items.AddRange(new object[] {
            "Disable",
            "Enable"});
            this.cbPubLogDeny.Location = new System.Drawing.Point(768, 172);
            this.cbPubLogDeny.Name = "cbPubLogDeny";
            this.cbPubLogDeny.Size = new System.Drawing.Size(280, 21);
            this.cbPubLogDeny.Sorted = true;
            this.cbPubLogDeny.TabIndex = 104;
            // 
            // tbDomFileName
            // 
            this.tbDomFileName.Location = new System.Drawing.Point(170, 196);
            this.tbDomFileName.Name = "tbDomFileName";
            this.tbDomFileName.Size = new System.Drawing.Size(280, 20);
            this.tbDomFileName.TabIndex = 105;
            // 
            // tbPrivFileName
            // 
            this.tbPrivFileName.Location = new System.Drawing.Point(469, 196);
            this.tbPrivFileName.Name = "tbPrivFileName";
            this.tbPrivFileName.Size = new System.Drawing.Size(280, 20);
            this.tbPrivFileName.TabIndex = 106;
            // 
            // tbPubFileName
            // 
            this.tbPubFileName.Location = new System.Drawing.Point(768, 196);
            this.tbPubFileName.Name = "tbPubFileName";
            this.tbPubFileName.Size = new System.Drawing.Size(280, 20);
            this.tbPubFileName.TabIndex = 107;
            // 
            // tbDomFileSize
            // 
            this.tbDomFileSize.Location = new System.Drawing.Point(170, 220);
            this.tbDomFileSize.Name = "tbDomFileSize";
            this.tbDomFileSize.Size = new System.Drawing.Size(280, 20);
            this.tbDomFileSize.TabIndex = 108;
            // 
            // tbPrivFileSize
            // 
            this.tbPrivFileSize.Location = new System.Drawing.Point(469, 220);
            this.tbPrivFileSize.Name = "tbPrivFileSize";
            this.tbPrivFileSize.Size = new System.Drawing.Size(280, 20);
            this.tbPrivFileSize.TabIndex = 109;
            // 
            // tbPubFileSize
            // 
            this.tbPubFileSize.Location = new System.Drawing.Point(768, 219);
            this.tbPubFileSize.Name = "tbPubFileSize";
            this.tbPubFileSize.Size = new System.Drawing.Size(280, 20);
            this.tbPubFileSize.TabIndex = 110;
            // 
            // btn_FWConfig
            // 
            this.btn_FWConfig.Location = new System.Drawing.Point(1054, 97);
            this.btn_FWConfig.Name = "btn_FWConfig";
            this.btn_FWConfig.Size = new System.Drawing.Size(119, 48);
            this.btn_FWConfig.TabIndex = 111;
            this.btn_FWConfig.Text = "Get Firewall Configuration";
            this.btn_FWConfig.UseVisualStyleBackColor = true;
            this.btn_FWConfig.Click += new System.EventHandler(this.button1_Click_1);
            // 
            // tabRulebase
            // 
            this.tabRulebase.BackColor = System.Drawing.Color.Azure;
            this.tabRulebase.Controls.Add(this.tbRemFail2);
            this.tabRulebase.Controls.Add(this.l_RuleSecurity);
            this.tabRulebase.Controls.Add(this.cbRuleSecurity);
            this.tabRulebase.Controls.Add(this.l_RuleEdgeTrav);
            this.tabRulebase.Controls.Add(this.cbRuleEdgeTrav);
            this.tabRulebase.Controls.Add(this.l_RuleIntType);
            this.tabRulebase.Controls.Add(this.cbRuleIntType);
            this.tabRulebase.Controls.Add(this.l_RuleUserGroup);
            this.tabRulebase.Controls.Add(this.tbRuleUserGroup);
            this.tabRulebase.Controls.Add(this.l_RuleCompGroup);
            this.tabRulebase.Controls.Add(this.tbRuleCompGroup);
            this.tabRulebase.Controls.Add(this.l_RuleDesc);
            this.tabRulebase.Controls.Add(this.tbRuleDesc);
            this.tabRulebase.Controls.Add(this.l_RuleRemPort);
            this.tabRulebase.Controls.Add(this.l_RuleLocalPort);
            this.tabRulebase.Controls.Add(this.tbRuleRemPort);
            this.tabRulebase.Controls.Add(this.tbRuleLocalPort);
            this.tabRulebase.Controls.Add(this.l_RuleService);
            this.tabRulebase.Controls.Add(this.tbRuleService);
            this.tabRulebase.Controls.Add(this.tbRuleProg);
            this.tabRulebase.Controls.Add(this.l_RuleProg);
            this.tabRulebase.Controls.Add(this.l_RuleGrouping);
            this.tabRulebase.Controls.Add(this.tbRuleGrouping);
            this.tabRulebase.Controls.Add(this.l_RuleAction);
            this.tabRulebase.Controls.Add(this.cbRuleAction);
            this.tabRulebase.Controls.Add(this.l_RuleProtocol);
            this.tabRulebase.Controls.Add(this.cbRuleProtocol);
            this.tabRulebase.Controls.Add(this.l_RuleRemIP);
            this.tabRulebase.Controls.Add(this.tbRuleRemIP);
            this.tabRulebase.Controls.Add(this.l_LocalIP);
            this.tabRulebase.Controls.Add(this.tbRuleLocalIP);
            this.tabRulebase.Controls.Add(this.l_RuleProfile);
            this.tabRulebase.Controls.Add(this.cbRuleDirection);
            this.tabRulebase.Controls.Add(this.cbRuleProfile);
            this.tabRulebase.Controls.Add(this.i_RuleDirection);
            this.tabRulebase.Controls.Add(this.cbRuleEnabled);
            this.tabRulebase.Controls.Add(this.l_Rule_Enabled);
            this.tabRulebase.Controls.Add(this.l_RuleName);
            this.tabRulebase.Controls.Add(this.tbRuleName);
            this.tabRulebase.Controls.Add(this.btn_Rulebase);
            this.tabRulebase.Controls.Add(this.lbRulebase);
            this.tabRulebase.Location = new System.Drawing.Point(4, 22);
            this.tabRulebase.Name = "tabRulebase";
            this.tabRulebase.Padding = new System.Windows.Forms.Padding(3);
            this.tabRulebase.Size = new System.Drawing.Size(1178, 244);
            this.tabRulebase.TabIndex = 7;
            this.tabRulebase.Text = "Rulebase";
            // 
            // tbRemFail
            // 
            this.tbRemFail.BackColor = System.Drawing.Color.Red;
            this.tbRemFail.ForeColor = System.Drawing.Color.Yellow;
            this.tbRemFail.Location = new System.Drawing.Point(1054, 219);
            this.tbRemFail.Name = "tbRemFail";
            this.tbRemFail.ReadOnly = true;
            this.tbRemFail.Size = new System.Drawing.Size(118, 20);
            this.tbRemFail.TabIndex = 112;
            this.tbRemFail.Text = "Access is denied.";
            this.tbRemFail.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.tbRemFail.Visible = false;
            // 
            // lbRulebase
            // 
            this.lbRulebase.FormattingEnabled = true;
            this.lbRulebase.Location = new System.Drawing.Point(6, 14);
            this.lbRulebase.Name = "lbRulebase";
            this.lbRulebase.Size = new System.Drawing.Size(264, 225);
            this.lbRulebase.Sorted = true;
            this.lbRulebase.TabIndex = 0;
            // 
            // btn_Rulebase
            // 
            this.btn_Rulebase.Location = new System.Drawing.Point(1105, 99);
            this.btn_Rulebase.Name = "btn_Rulebase";
            this.btn_Rulebase.Size = new System.Drawing.Size(67, 48);
            this.btn_Rulebase.TabIndex = 112;
            this.btn_Rulebase.Text = "Get Firewall Rulebase";
            this.btn_Rulebase.UseVisualStyleBackColor = true;
            this.btn_Rulebase.Click += new System.EventHandler(this.btn_Rulebase_Click);
            // 
            // tbRuleName
            // 
            this.tbRuleName.Location = new System.Drawing.Point(364, 14);
            this.tbRuleName.Name = "tbRuleName";
            this.tbRuleName.Size = new System.Drawing.Size(735, 20);
            this.tbRuleName.TabIndex = 113;
            // 
            // l_RuleName
            // 
            this.l_RuleName.Location = new System.Drawing.Point(293, 15);
            this.l_RuleName.Name = "l_RuleName";
            this.l_RuleName.Size = new System.Drawing.Size(68, 17);
            this.l_RuleName.TabIndex = 114;
            this.l_RuleName.Text = "Rule Name:";
            this.l_RuleName.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // l_Rule_Enabled
            // 
            this.l_Rule_Enabled.Location = new System.Drawing.Point(293, 46);
            this.l_Rule_Enabled.Name = "l_Rule_Enabled";
            this.l_Rule_Enabled.Size = new System.Drawing.Size(68, 17);
            this.l_Rule_Enabled.TabIndex = 115;
            this.l_Rule_Enabled.Text = "Enabled:";
            this.l_Rule_Enabled.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleEnabled
            // 
            this.cbRuleEnabled.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleEnabled.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleEnabled.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleEnabled.FormattingEnabled = true;
            this.cbRuleEnabled.Items.AddRange(new object[] {
            "NO",
            "YES"});
            this.cbRuleEnabled.Location = new System.Drawing.Point(364, 43);
            this.cbRuleEnabled.Name = "cbRuleEnabled";
            this.cbRuleEnabled.Size = new System.Drawing.Size(116, 21);
            this.cbRuleEnabled.Sorted = true;
            this.cbRuleEnabled.TabIndex = 116;
            // 
            // i_RuleDirection
            // 
            this.i_RuleDirection.Location = new System.Drawing.Point(293, 75);
            this.i_RuleDirection.Name = "i_RuleDirection";
            this.i_RuleDirection.Size = new System.Drawing.Size(68, 17);
            this.i_RuleDirection.TabIndex = 117;
            this.i_RuleDirection.Text = "Direction:";
            this.i_RuleDirection.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleProfile
            // 
            this.cbRuleProfile.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleProfile.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleProfile.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleProfile.FormattingEnabled = true;
            this.cbRuleProfile.Items.AddRange(new object[] {
            "Domain",
            "Domain,Private,Public",
            "Domain,Public",
            "Doman,Private",
            "Private",
            "Private,Public",
            "Public"});
            this.cbRuleProfile.Location = new System.Drawing.Point(364, 102);
            this.cbRuleProfile.Name = "cbRuleProfile";
            this.cbRuleProfile.Size = new System.Drawing.Size(116, 21);
            this.cbRuleProfile.Sorted = true;
            this.cbRuleProfile.TabIndex = 118;
            // 
            // cbRuleDirection
            // 
            this.cbRuleDirection.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleDirection.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleDirection.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleDirection.FormattingEnabled = true;
            this.cbRuleDirection.Items.AddRange(new object[] {
            "In",
            "Out"});
            this.cbRuleDirection.Location = new System.Drawing.Point(364, 72);
            this.cbRuleDirection.Name = "cbRuleDirection";
            this.cbRuleDirection.Size = new System.Drawing.Size(116, 21);
            this.cbRuleDirection.Sorted = true;
            this.cbRuleDirection.TabIndex = 119;
            // 
            // l_RuleProfile
            // 
            this.l_RuleProfile.Location = new System.Drawing.Point(293, 105);
            this.l_RuleProfile.Name = "l_RuleProfile";
            this.l_RuleProfile.Size = new System.Drawing.Size(68, 17);
            this.l_RuleProfile.TabIndex = 120;
            this.l_RuleProfile.Text = "Profile:";
            this.l_RuleProfile.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleLocalIP
            // 
            this.tbRuleLocalIP.Location = new System.Drawing.Point(364, 131);
            this.tbRuleLocalIP.Name = "tbRuleLocalIP";
            this.tbRuleLocalIP.Size = new System.Drawing.Size(116, 20);
            this.tbRuleLocalIP.TabIndex = 121;
            // 
            // l_LocalIP
            // 
            this.l_LocalIP.Location = new System.Drawing.Point(293, 132);
            this.l_LocalIP.Name = "l_LocalIP";
            this.l_LocalIP.Size = new System.Drawing.Size(68, 17);
            this.l_LocalIP.TabIndex = 122;
            this.l_LocalIP.Text = "Local IP:";
            this.l_LocalIP.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleRemIP
            // 
            this.tbRuleRemIP.Location = new System.Drawing.Point(364, 157);
            this.tbRuleRemIP.Name = "tbRuleRemIP";
            this.tbRuleRemIP.Size = new System.Drawing.Size(116, 20);
            this.tbRuleRemIP.TabIndex = 123;
            // 
            // l_RuleRemIP
            // 
            this.l_RuleRemIP.Location = new System.Drawing.Point(293, 159);
            this.l_RuleRemIP.Name = "l_RuleRemIP";
            this.l_RuleRemIP.Size = new System.Drawing.Size(68, 17);
            this.l_RuleRemIP.TabIndex = 124;
            this.l_RuleRemIP.Text = "Remote IP:";
            this.l_RuleRemIP.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleProtocol
            // 
            this.cbRuleProtocol.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleProtocol.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleProtocol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleProtocol.FormattingEnabled = true;
            this.cbRuleProtocol.Items.AddRange(new object[] {
            "Any",
            "GRE",
            "HOPOPT",
            "ICMPv4",
            "ICMPv6",
            "IGMP",
            "IPv6",
            "IPv6-Frag",
            "IPv6-NoNxt",
            "IPv6-Opts",
            "IPv6-Route",
            "L2TP",
            "PGM",
            "TCP",
            "UDP",
            "VRRP"});
            this.cbRuleProtocol.Location = new System.Drawing.Point(364, 183);
            this.cbRuleProtocol.Name = "cbRuleProtocol";
            this.cbRuleProtocol.Size = new System.Drawing.Size(116, 21);
            this.cbRuleProtocol.Sorted = true;
            this.cbRuleProtocol.TabIndex = 125;
            // 
            // l_RuleProtocol
            // 
            this.l_RuleProtocol.Location = new System.Drawing.Point(293, 185);
            this.l_RuleProtocol.Name = "l_RuleProtocol";
            this.l_RuleProtocol.Size = new System.Drawing.Size(68, 17);
            this.l_RuleProtocol.TabIndex = 126;
            this.l_RuleProtocol.Text = "Protocol:";
            this.l_RuleProtocol.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleAction
            // 
            this.cbRuleAction.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleAction.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleAction.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleAction.FormattingEnabled = true;
            this.cbRuleAction.Items.AddRange(new object[] {
            "Allow",
            "Block",
            "Bypass"});
            this.cbRuleAction.Location = new System.Drawing.Point(572, 183);
            this.cbRuleAction.Name = "cbRuleAction";
            this.cbRuleAction.Size = new System.Drawing.Size(116, 21);
            this.cbRuleAction.Sorted = true;
            this.cbRuleAction.TabIndex = 127;
            // 
            // l_RuleAction
            // 
            this.l_RuleAction.Location = new System.Drawing.Point(501, 184);
            this.l_RuleAction.Name = "l_RuleAction";
            this.l_RuleAction.Size = new System.Drawing.Size(68, 17);
            this.l_RuleAction.TabIndex = 128;
            this.l_RuleAction.Text = "Action:";
            this.l_RuleAction.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleGrouping
            // 
            this.tbRuleGrouping.Location = new System.Drawing.Point(572, 44);
            this.tbRuleGrouping.Name = "tbRuleGrouping";
            this.tbRuleGrouping.Size = new System.Drawing.Size(116, 20);
            this.tbRuleGrouping.TabIndex = 129;
            // 
            // l_RuleGrouping
            // 
            this.l_RuleGrouping.Location = new System.Drawing.Point(501, 46);
            this.l_RuleGrouping.Name = "l_RuleGrouping";
            this.l_RuleGrouping.Size = new System.Drawing.Size(68, 17);
            this.l_RuleGrouping.TabIndex = 130;
            this.l_RuleGrouping.Text = "Grouping:";
            this.l_RuleGrouping.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // l_RuleProg
            // 
            this.l_RuleProg.Location = new System.Drawing.Point(501, 74);
            this.l_RuleProg.Name = "l_RuleProg";
            this.l_RuleProg.Size = new System.Drawing.Size(68, 17);
            this.l_RuleProg.TabIndex = 131;
            this.l_RuleProg.Text = "Program:";
            this.l_RuleProg.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleProg
            // 
            this.tbRuleProg.Location = new System.Drawing.Point(572, 73);
            this.tbRuleProg.Name = "tbRuleProg";
            this.tbRuleProg.Size = new System.Drawing.Size(116, 20);
            this.tbRuleProg.TabIndex = 132;
            // 
            // tbRuleService
            // 
            this.tbRuleService.Location = new System.Drawing.Point(572, 103);
            this.tbRuleService.Name = "tbRuleService";
            this.tbRuleService.Size = new System.Drawing.Size(116, 20);
            this.tbRuleService.TabIndex = 133;
            // 
            // l_RuleService
            // 
            this.l_RuleService.Location = new System.Drawing.Point(501, 104);
            this.l_RuleService.Name = "l_RuleService";
            this.l_RuleService.Size = new System.Drawing.Size(68, 17);
            this.l_RuleService.TabIndex = 134;
            this.l_RuleService.Text = "Service:";
            this.l_RuleService.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleLocalPort
            // 
            this.tbRuleLocalPort.Location = new System.Drawing.Point(572, 131);
            this.tbRuleLocalPort.Name = "tbRuleLocalPort";
            this.tbRuleLocalPort.Size = new System.Drawing.Size(116, 20);
            this.tbRuleLocalPort.TabIndex = 135;
            // 
            // tbRuleRemPort
            // 
            this.tbRuleRemPort.Location = new System.Drawing.Point(572, 157);
            this.tbRuleRemPort.Name = "tbRuleRemPort";
            this.tbRuleRemPort.Size = new System.Drawing.Size(116, 20);
            this.tbRuleRemPort.TabIndex = 136;
            // 
            // l_RuleLocalPort
            // 
            this.l_RuleLocalPort.Location = new System.Drawing.Point(500, 132);
            this.l_RuleLocalPort.Name = "l_RuleLocalPort";
            this.l_RuleLocalPort.Size = new System.Drawing.Size(68, 17);
            this.l_RuleLocalPort.TabIndex = 137;
            this.l_RuleLocalPort.Text = "Local Port:";
            this.l_RuleLocalPort.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // l_RuleRemPort
            // 
            this.l_RuleRemPort.Location = new System.Drawing.Point(486, 158);
            this.l_RuleRemPort.Name = "l_RuleRemPort";
            this.l_RuleRemPort.Size = new System.Drawing.Size(83, 17);
            this.l_RuleRemPort.TabIndex = 138;
            this.l_RuleRemPort.Text = "Remote Port:";
            this.l_RuleRemPort.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // l_RuleDesc
            // 
            this.l_RuleDesc.Location = new System.Drawing.Point(763, 46);
            this.l_RuleDesc.Name = "l_RuleDesc";
            this.l_RuleDesc.Size = new System.Drawing.Size(68, 17);
            this.l_RuleDesc.TabIndex = 140;
            this.l_RuleDesc.Text = "Description:";
            this.l_RuleDesc.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleDesc
            // 
            this.tbRuleDesc.Location = new System.Drawing.Point(834, 44);
            this.tbRuleDesc.Name = "tbRuleDesc";
            this.tbRuleDesc.Size = new System.Drawing.Size(265, 20);
            this.tbRuleDesc.TabIndex = 139;
            // 
            // l_RuleCompGroup
            // 
            this.l_RuleCompGroup.Location = new System.Drawing.Point(697, 75);
            this.l_RuleCompGroup.Name = "l_RuleCompGroup";
            this.l_RuleCompGroup.Size = new System.Drawing.Size(134, 17);
            this.l_RuleCompGroup.TabIndex = 142;
            this.l_RuleCompGroup.Text = "Remote Computer Group:";
            this.l_RuleCompGroup.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleCompGroup
            // 
            this.tbRuleCompGroup.Location = new System.Drawing.Point(834, 75);
            this.tbRuleCompGroup.Name = "tbRuleCompGroup";
            this.tbRuleCompGroup.Size = new System.Drawing.Size(265, 20);
            this.tbRuleCompGroup.TabIndex = 141;
            // 
            // l_RuleUserGroup
            // 
            this.l_RuleUserGroup.Location = new System.Drawing.Point(713, 104);
            this.l_RuleUserGroup.Name = "l_RuleUserGroup";
            this.l_RuleUserGroup.Size = new System.Drawing.Size(118, 17);
            this.l_RuleUserGroup.TabIndex = 144;
            this.l_RuleUserGroup.Text = "Remote User Group:";
            this.l_RuleUserGroup.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tbRuleUserGroup
            // 
            this.tbRuleUserGroup.Location = new System.Drawing.Point(834, 103);
            this.tbRuleUserGroup.Name = "tbRuleUserGroup";
            this.tbRuleUserGroup.Size = new System.Drawing.Size(265, 20);
            this.tbRuleUserGroup.TabIndex = 143;
            // 
            // l_RuleIntType
            // 
            this.l_RuleIntType.Location = new System.Drawing.Point(739, 132);
            this.l_RuleIntType.Name = "l_RuleIntType";
            this.l_RuleIntType.Size = new System.Drawing.Size(92, 17);
            this.l_RuleIntType.TabIndex = 146;
            this.l_RuleIntType.Text = "Interface Type:";
            this.l_RuleIntType.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleIntType
            // 
            this.cbRuleIntType.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleIntType.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleIntType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleIntType.FormattingEnabled = true;
            this.cbRuleIntType.Items.AddRange(new object[] {
            "Any",
            "LAN",
            "RAS",
            "Wireless"});
            this.cbRuleIntType.Location = new System.Drawing.Point(834, 131);
            this.cbRuleIntType.Name = "cbRuleIntType";
            this.cbRuleIntType.Size = new System.Drawing.Size(116, 21);
            this.cbRuleIntType.Sorted = true;
            this.cbRuleIntType.TabIndex = 145;
            // 
            // l_RuleEdgeTrav
            // 
            this.l_RuleEdgeTrav.Location = new System.Drawing.Point(742, 159);
            this.l_RuleEdgeTrav.Name = "l_RuleEdgeTrav";
            this.l_RuleEdgeTrav.Size = new System.Drawing.Size(89, 17);
            this.l_RuleEdgeTrav.TabIndex = 148;
            this.l_RuleEdgeTrav.Text = "Edge Traversal:";
            this.l_RuleEdgeTrav.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleEdgeTrav
            // 
            this.cbRuleEdgeTrav.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleEdgeTrav.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleEdgeTrav.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleEdgeTrav.FormattingEnabled = true;
            this.cbRuleEdgeTrav.Items.AddRange(new object[] {
            "DeferApp",
            "DeferUser",
            "No",
            "Yes"});
            this.cbRuleEdgeTrav.Location = new System.Drawing.Point(834, 158);
            this.cbRuleEdgeTrav.Name = "cbRuleEdgeTrav";
            this.cbRuleEdgeTrav.Size = new System.Drawing.Size(116, 21);
            this.cbRuleEdgeTrav.Sorted = true;
            this.cbRuleEdgeTrav.TabIndex = 147;
            // 
            // l_RuleSecurity
            // 
            this.l_RuleSecurity.Location = new System.Drawing.Point(763, 186);
            this.l_RuleSecurity.Name = "l_RuleSecurity";
            this.l_RuleSecurity.Size = new System.Drawing.Size(68, 17);
            this.l_RuleSecurity.TabIndex = 150;
            this.l_RuleSecurity.Text = "Security:";
            this.l_RuleSecurity.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cbRuleSecurity
            // 
            this.cbRuleSecurity.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.SuggestAppend;
            this.cbRuleSecurity.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.ListItems;
            this.cbRuleSecurity.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbRuleSecurity.FormattingEnabled = true;
            this.cbRuleSecurity.Items.AddRange(new object[] {
            "Authdynenc",
            "Authenc",
            "Authenticate",
            "NotRequired"});
            this.cbRuleSecurity.Location = new System.Drawing.Point(834, 185);
            this.cbRuleSecurity.Name = "cbRuleSecurity";
            this.cbRuleSecurity.Size = new System.Drawing.Size(116, 21);
            this.cbRuleSecurity.Sorted = true;
            this.cbRuleSecurity.TabIndex = 149;
            // 
            // tbRemFail2
            // 
            this.tbRemFail2.BackColor = System.Drawing.Color.Red;
            this.tbRemFail2.ForeColor = System.Drawing.Color.Yellow;
            this.tbRemFail2.Location = new System.Drawing.Point(1054, 218);
            this.tbRemFail2.Name = "tbRemFail2";
            this.tbRemFail2.ReadOnly = true;
            this.tbRemFail2.Size = new System.Drawing.Size(118, 20);
            this.tbRemFail2.TabIndex = 151;
            this.tbRemFail2.Text = "Access is denied.";
            this.tbRemFail2.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.tbRemFail2.Visible = false;
            // 
            // MainForm
            // 
            this.AllowDrop = true;
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            this.AutoScroll = true;
            this.AutoSize = true;
            this.ClientSize = new System.Drawing.Size(1195, 837);
            this.Controls.Add(this.panel1);
            this.Controls.Add(this.ckbxIPv6);
            this.Controls.Add(this.DispRec_Label);
            this.Controls.Add(this.tbDispRecs);
            this.Controls.Add(this.Lines2Read_Label2);
            this.Controls.Add(this.rbLogFile);
            this.Controls.Add(this.rbLogLive);
            this.Controls.Add(this.Lines2Read);
            this.Controls.Add(this.Lines2Read_Label);
            this.Controls.Add(this.btnClearSearch);
            this.Controls.Add(this.cbEnableSearch);
            this.Controls.Add(this.cbSearchDirection);
            this.Controls.Add(this.tbDirectionHeading);
            this.Controls.Add(this.tbSearchDestPrt);
            this.Controls.Add(this.tbSearchSrcPrt);
            this.Controls.Add(this.tbSearchDestIP);
            this.Controls.Add(this.tbSearchSrcIP);
            this.Controls.Add(this.cbSearchProtocol);
            this.Controls.Add(this.cbSearchAction);
            this.Controls.Add(this.tbDestPrtHeading);
            this.Controls.Add(this.tbSrcPrtHeading);
            this.Controls.Add(this.tbDestIPHeading);
            this.Controls.Add(this.tbSrcIPHeading);
            this.Controls.Add(this.tbProtocolHeading);
            this.Controls.Add(this.tbActionHeading);
            this.Controls.Add(this.tbStatus);
            this.Controls.Add(this.dataGridView2);
            this.Controls.Add(this.textBox4);
            this.Controls.Add(this.tbTitle);
            this.Controls.Add(this.tbUpdate);
            this.Controls.Add(this.tbStartDate);
            this.Controls.Add(this.FWMgt_Btn);
            this.Controls.Add(this.Start_Btn);
            this.Controls.Add(this.tabControl1);
            this.Controls.Add(this.Exit_Btn);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.Fixed3D;
            this.Name = "MainForm";
            this.Text = "Windows Firewall Monitor";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.tabControl1.ResumeLayout(false);
            this.tabStats.ResumeLayout(false);
            this.tabStats.PerformLayout();
            this.tabLogs.ResumeLayout(false);
            this.tabLogs.PerformLayout();
            this.tabLicense.ResumeLayout(false);
            this.tabLicense.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView2)).EndInit();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.tabRulebase.ResumeLayout(false);
            this.tabRulebase.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button Exit_Btn;
        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabStats;
        private System.Windows.Forms.TabPage tabLogs;
        private System.Windows.Forms.Button Start_Btn;
        private System.Windows.Forms.Button FWMgt_Btn;
        private System.Windows.Forms.TextBox tbStartDate;
        private System.Windows.Forms.TextBox tbUpdate;
        private System.Windows.Forms.TextBox tbTitle;
        private System.Windows.Forms.TabPage tabLicense;
        private System.Windows.Forms.TabPage tabHelp;
        private System.Windows.Forms.TextBox textBox4;
        private System.Windows.Forms.DataGridView dataGridView2;
        private System.Windows.Forms.Label Lines2Read_Label;
        private System.Windows.Forms.TextBox Lines2Read;
        private System.Windows.Forms.TextBox tbMonIP;
        private System.Windows.Forms.TextBox tbStatus;
        private System.Windows.Forms.TextBox tbTotTraf_Heading;
        private System.Windows.Forms.TextBox tbSysIP_Heading;
        private System.Windows.Forms.TextBox tbNumLogsMon_Heading;
        private System.Windows.Forms.TextBox tbSearchLog_Heading;
        private System.Windows.Forms.TextBox tbTrafDir_Heading;
        private System.Windows.Forms.TextBox tbUnk_Heading;
        private System.Windows.Forms.TextBox tbOutB_Heading;
        private System.Windows.Forms.TextBox tbInb_Heading;
        private System.Windows.Forms.TextBox tbFWAct_Heading;
        private System.Windows.Forms.TextBox tbDrop_Heading;
        private System.Windows.Forms.TextBox tbAllow_Heading;
        private System.Windows.Forms.TextBox tbProt_Heading;
        private System.Windows.Forms.TextBox tbOther_Heading;
        private System.Windows.Forms.TextBox tbICMP_Heading;
        private System.Windows.Forms.TextBox tbUDP_Heading;
        private System.Windows.Forms.TextBox tbTCP_Heading;
        private System.Windows.Forms.TextBox tbTotTraf;
        private System.Windows.Forms.TextBox tbTotals_Heading;
        private System.Windows.Forms.TextBox tbTotDrop;
        private System.Windows.Forms.TextBox tbTotAllow;
        private System.Windows.Forms.TextBox tbTotOth;
        private System.Windows.Forms.TextBox tbTotICMP;
        private System.Windows.Forms.TextBox tbTotUDP;
        private System.Windows.Forms.TextBox tbTotTCP;
        private System.Windows.Forms.TextBox tbTotUnk;
        private System.Windows.Forms.TextBox tbTotOutb;
        private System.Windows.Forms.TextBox tbTotInb;
        private System.Windows.Forms.DataGridViewTextBoxColumn Local_IP;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Date;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Time;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Action;
        private System.Windows.Forms.DataGridViewTextBoxColumn Protocol;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Src;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Dst;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Src_Prt;
        private System.Windows.Forms.DataGridViewTextBoxColumn FW_Dst_Prt;
        private System.Windows.Forms.DataGridViewTextBoxColumn Direction;
        private System.Windows.Forms.TextBox tbActionHeading;
        private System.Windows.Forms.TextBox tbProtocolHeading;
        private System.Windows.Forms.TextBox tbSrcIPHeading;
        private System.Windows.Forms.TextBox tbDestIPHeading;
        private System.Windows.Forms.TextBox tbSrcPrtHeading;
        private System.Windows.Forms.TextBox tbDestPrtHeading;
        private System.Windows.Forms.ComboBox cbSearchAction;
        private System.Windows.Forms.ComboBox cbSearchProtocol;
        private System.Windows.Forms.TextBox tbSearchSrcIP;
        private System.Windows.Forms.TextBox tbSearchDestIP;
        private System.Windows.Forms.TextBox tbSearchSrcPrt;
        private System.Windows.Forms.TextBox tbSearchDestPrt;
        private System.Windows.Forms.TextBox tbLogSize_Heading;
        private System.Windows.Forms.TextBox tbLogFileSize;
        private System.Windows.Forms.TextBox tbLogReadTime;
        private System.Windows.Forms.TextBox tbLogReadDate;
        private System.Windows.Forms.TextBox tbLogRead_Heading;
        private System.Windows.Forms.TextBox tbDirectionHeading;
        private System.Windows.Forms.ComboBox cbSearchDirection;
        private System.Windows.Forms.TextBox tbLogRate_Heading;
        private System.Windows.Forms.TextBox tbLogRate;
        private System.Windows.Forms.CheckBox cbEnableSearch;
        private System.Windows.Forms.Button btnClearSearch;
        private System.Windows.Forms.RadioButton rbMonLocal;
        private System.Windows.Forms.RadioButton rbMonRemote;
        private System.Windows.Forms.RadioButton rbLogLive;
        private System.Windows.Forms.RadioButton rbLogFile;
        private System.Windows.Forms.Label Lines2Read_Label2;
        private System.Windows.Forms.TextBox tbApp_Log;
        private System.Windows.Forms.TextBox tbDispRecs;
        private System.Windows.Forms.Label DispRec_Label;
        private System.Windows.Forms.TextBox tbEULA;
        private System.Windows.Forms.CheckBox ckbxIPv6;
        private System.Windows.Forms.TextBox tbThread_Log;
        private System.Windows.Forms.Label lThreadLogTitle;
        private System.Windows.Forms.Label lAppLogTitle;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.TextBox tbMaxFileSize;
        private System.Windows.Forms.TextBox tbFWLogName;
        private System.Windows.Forms.TextBox tbLogDropConn;
        private System.Windows.Forms.TextBox tbLogAllowCon;
        private System.Windows.Forms.TextBox tbUnicast;
        private System.Windows.Forms.TextBox tbRemMgt;
        private System.Windows.Forms.TextBox tbInbUsrNotify;
        private System.Windows.Forms.TextBox tbFWPol;
        private System.Windows.Forms.TextBox tbState;
        private System.Windows.Forms.TextBox tbPublicProfile;
        private System.Windows.Forms.TextBox tbPrivProfile;
        private System.Windows.Forms.TextBox tbDomainProf;
        private System.Windows.Forms.ComboBox cbDomState;
        private System.Windows.Forms.ComboBox cbPubState;
        private System.Windows.Forms.ComboBox cbPrivState;
        private System.Windows.Forms.ComboBox cbDomFWPol;
        private System.Windows.Forms.ComboBox cbPubFWPol;
        private System.Windows.Forms.ComboBox cbPrivFWPol;
        private System.Windows.Forms.TextBox tbPubFileName;
        private System.Windows.Forms.TextBox tbPrivFileName;
        private System.Windows.Forms.TextBox tbDomFileName;
        private System.Windows.Forms.ComboBox cbPubLogDeny;
        private System.Windows.Forms.ComboBox cbPrivLogDeny;
        private System.Windows.Forms.ComboBox cbDomLogDeny;
        private System.Windows.Forms.ComboBox cbPubLogAllow;
        private System.Windows.Forms.ComboBox cbPrivLogAllow;
        private System.Windows.Forms.ComboBox cbDomLogAllow;
        private System.Windows.Forms.ComboBox cbPubUnicast;
        private System.Windows.Forms.ComboBox cbPrivUnicast;
        private System.Windows.Forms.ComboBox cbDomUnicast;
        private System.Windows.Forms.ComboBox cbPubRemMgt;
        private System.Windows.Forms.ComboBox cbPrivRemMgt;
        private System.Windows.Forms.ComboBox cbDomRemMgt;
        private System.Windows.Forms.ComboBox cbPubNotify;
        private System.Windows.Forms.ComboBox cbPrivNotify;
        private System.Windows.Forms.ComboBox cbDomNotify;
        private System.Windows.Forms.TextBox tbPubFileSize;
        private System.Windows.Forms.TextBox tbPrivFileSize;
        private System.Windows.Forms.TextBox tbDomFileSize;
        private System.Windows.Forms.Button btn_FWConfig;
        private System.Windows.Forms.TabPage tabRulebase;
        private System.Windows.Forms.TextBox tbRemFail;
        private System.Windows.Forms.Button btn_Rulebase;
        private System.Windows.Forms.ListBox lbRulebase;
        private System.Windows.Forms.Label l_RuleName;
        private System.Windows.Forms.TextBox tbRuleName;
        private System.Windows.Forms.ComboBox cbRuleEnabled;
        private System.Windows.Forms.Label l_Rule_Enabled;
        private System.Windows.Forms.Label l_RuleProfile;
        private System.Windows.Forms.ComboBox cbRuleDirection;
        private System.Windows.Forms.ComboBox cbRuleProfile;
        private System.Windows.Forms.Label i_RuleDirection;
        private System.Windows.Forms.Label l_LocalIP;
        private System.Windows.Forms.TextBox tbRuleLocalIP;
        private System.Windows.Forms.Label l_RuleProtocol;
        private System.Windows.Forms.ComboBox cbRuleProtocol;
        private System.Windows.Forms.Label l_RuleRemIP;
        private System.Windows.Forms.TextBox tbRuleRemIP;
        private System.Windows.Forms.Label l_RuleAction;
        private System.Windows.Forms.ComboBox cbRuleAction;
        private System.Windows.Forms.Label l_RuleRemPort;
        private System.Windows.Forms.Label l_RuleLocalPort;
        private System.Windows.Forms.TextBox tbRuleRemPort;
        private System.Windows.Forms.TextBox tbRuleLocalPort;
        private System.Windows.Forms.Label l_RuleService;
        private System.Windows.Forms.TextBox tbRuleService;
        private System.Windows.Forms.TextBox tbRuleProg;
        private System.Windows.Forms.Label l_RuleProg;
        private System.Windows.Forms.Label l_RuleGrouping;
        private System.Windows.Forms.TextBox tbRuleGrouping;
        private System.Windows.Forms.Label l_RuleCompGroup;
        private System.Windows.Forms.TextBox tbRuleCompGroup;
        private System.Windows.Forms.Label l_RuleDesc;
        private System.Windows.Forms.TextBox tbRuleDesc;
        private System.Windows.Forms.Label l_RuleSecurity;
        private System.Windows.Forms.ComboBox cbRuleSecurity;
        private System.Windows.Forms.Label l_RuleEdgeTrav;
        private System.Windows.Forms.ComboBox cbRuleEdgeTrav;
        private System.Windows.Forms.Label l_RuleIntType;
        private System.Windows.Forms.ComboBox cbRuleIntType;
        private System.Windows.Forms.Label l_RuleUserGroup;
        private System.Windows.Forms.TextBox tbRuleUserGroup;
        private System.Windows.Forms.TextBox tbRemFail2;
    }
}

