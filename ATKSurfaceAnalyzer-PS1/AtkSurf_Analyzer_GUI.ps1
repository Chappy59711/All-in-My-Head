<#
    How to add a new check
        1. Add a button to the form
        2. Create a function to retrieve the appropriate data
        3. Add the new function to the Get-Info function
        4. Add to GetInfo(new function) to the BuildGrid function
        5. Add the validation code to the Check_Module function
        6. Add to Row_Status function
        7. Add Get-Info(new function) to Check_Status
#>

$global:BtnWidth = 150
$global:BtnHeight = 23
$global:BtnHStart = 7
$global:BtnVStart = 50
$global:BtnVSpacing = 25

$global:OSType = "Server"
$global:OSName = "Server 2019"
$global:ValidOS = "False"

$global:Check_Result = "False"

$global:Most_Common_Atkd_Ports = @('20','21','22','23','25','42','53','67','68','69','79','80','88','110','111','119','123','135','137','138','139','143','161','162','389','443','445','514','636','873','993','995','1433','1434','3306','3389','5800','5900','5985')
$global:Most_Common_Atkd_Services = @('FTP','SSH','Telnet','SMTP','DNS','HTTP','POP3','RPC','NetBIOS','ms-sql','TFTP','Finger','Kerberos','SUNRPC','NB Session','NB Name','SNMP','SNMP Trap','LDAP','SSL','HTTPS','SMB','CIFS','Syslog','WINS','DHCP','NNTP','NTP','NB Datagram','IMAP','LDAPS','IMAPS','MySQL','RDP','VNC','WinRM','TermService')
$global:WindowsServices = @('AJRouter','ALG','bthserv','CertPropSvc','DiagTrack','DsmSvc','DPS','WdiServiceHost','WdiSystemHost','MapsBroker','HvHost','vmickvpexchange','vmicguestinterface','vmicshutdown','vmicheartbeat','vmcompute','vmicvmsession','vmicrdv','vmictimesync','vmms','vmicvss','SharedAccess','iphlpsvc','wlidsvc','MSiSCSI','NcaSvc','PhoneSvc','QWAVE','RmSvc','RpcLocator','SCardSvr','ScDeviceEnum','SCPolicySvc','SNMPTRAP','TapiSrv','TabletInputService','WalletService','WbioSrvc','FrameServer','WerSvc','stisvc','icssvc','XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc')

Function GenerateStatusForm {
[Void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

    $Status_Label = New-Object System.Windows.Forms.Label
    $Status_Label.Text = "Initializing..."
    $Status_Label.Location = New-Object Drawing.Point 10,10
    $Status_Label.AutoSize = $True

    $formS = New-Object Windows.Forms.Form
    $formS.text = "Windows OS Attack Surface Analyzer v1.0"
    $formS.Size = New-Object Drawing.Point 400, 100
    $formS.topmost = 1
    $formS.Icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")

    $formS.Controls.Add($Status_Label)
    $formS.ShowDialog()

    getOSType

    write-host $global:OSType, $global:OSName

    $formS.Close()
}

Function GenerateForm {
[Void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

$ButtonNetAdapters = New-Object Windows.Forms.Button
$ButtonNetAdapters.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 0))
$ButtonNetAdapters.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonNetAdapters.Text = "&Network Adapters"
$ButtonNetAdapters.add_click({BuildGrid("NetAdapt")})

$ButtonIPv = New-Object Windows.Forms.Button
$ButtonIPv.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 1))
$ButtonIPv.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonIPv.Text = "&IP Version"
$ButtonIPv.add_click({BuildGrid("IPv?")})

$ButtonNetSrv = New-Object Windows.Forms.Button
$ButtonNetSrv.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 2))
$ButtonNetSrv.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonNetSrv.Text = "&Network Services"
$ButtonNetSrv.add_click({BuildGrid("NetSrv")})

$ButtonNBoIP = New-Object Windows.Forms.Button
$ButtonNBoIP.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 3))
$ButtonNBoIP.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonNBoIP.Text = "&NetBIOS over TCP/IP"
$ButtonNBoIP.add_click({BuildGrid("NetBIOSoIP")})

$ButtonLMHosts = New-Object Windows.Forms.Button
$ButtonLMHosts.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 4))
$ButtonLMHosts.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonLMHosts.Text = "&LMHosts Lookup"
$ButtonLMHosts.add_click({BuildGrid("LMHosts")})

$ButtonFWPRofs = New-Object Windows.Forms.Button
$ButtonFWPRofs.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 5))
$ButtonFWPRofs.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWPRofs.Text = "&Firewall Profiles"
$ButtonFWPRofs.add_click({BuildGrid("FWProfs")})

$ButtonFWIn = New-Object Windows.Forms.Button
$ButtonFWIn.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 6))
$ButtonFWIn.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWIn.Text = "&Firewall Inbound Action"
$ButtonFWIn.add_click({BuildGrid("FWIn")})

$ButtonFWOut = New-Object Windows.Forms.Button
$ButtonFWOut.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 7))
$ButtonFWOut.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWOut.Text = "&Firewall Outbound Action"
$ButtonFWOut.add_click({BuildGrid("FWOut")})

$ButtonFWLogAllowed = New-Object Windows.Forms.Button
$ButtonFWLogAllowed.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 8))
$ButtonFWLogAllowed.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWLogAllowed.Text = "&Firewall Log Allowed"
$ButtonFWLogAllowed.add_click({BuildGrid("FWLogAllowed")})

$ButtonFWLogBlocked = New-Object Windows.Forms.Button
$ButtonFWLogBlocked.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 9))
$ButtonFWLogBlocked.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWLogBlocked.Text = "&Firewall Log Blocked"
$ButtonFWLogBlocked.add_click({BuildGrid("FWLogBlocked")})

$ButtonFWLogIgnored = New-Object Windows.Forms.Button
$ButtonFWLogIgnored.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 10))
$ButtonFWLogIgnored.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWLogIgnored.Text = "&Firewall Log Ignored"
$ButtonFWLogIgnored.add_click({BuildGrid("FWLogIgnored")})

$ButtonFWIPv6Rules = New-Object Windows.Forms.Button
$ButtonFWIPv6Rules.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 11))
$ButtonFWIPv6Rules.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonFWIPv6Rules.Text = "&Firewall IPv6 Rules"
$ButtonFWIPv6Rules.add_click({BuildGrid("FWIPv6Rules")})

$ButtonPortsLisIPv6 = New-Object Windows.Forms.Button
$ButtonPortsLisIPv6.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 12))
$ButtonPortsLisIPv6.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonPortsLisIPv6.Text = "&Listening Ports IPv6"
$ButtonPortsLisIPv6.add_click({BuildGrid("PortsLisIPv6")})

$ButtonPortsLisIPv4 = New-Object Windows.Forms.Button
$ButtonPortsLisIPv4.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 13))
$ButtonPortsLisIPv4.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonPortsLisIPv4.Text = "&Listening Ports IPv4"
$ButtonPortsLisIPv4.add_click({BuildGrid("PortsLisIPv4")})

$ButtonPortsActIPv6 = New-Object Windows.Forms.Button
$ButtonPortsActIPv6.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 14))
$ButtonPortsActIPv6.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonPortsActIPv6.Text = "&Active Ports IPv6"
$ButtonPortsActIPv6.add_click({BuildGrid("PortsActIPv6")})

$ButtonPortsActIPv4 = New-Object Windows.Forms.Button
$ButtonPortsActIPv4.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 15))
$ButtonPortsActIPv4.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonPortsActIPv4.Text = "&Active Ports IPv4"
$ButtonPortsActIPv4.add_click({BuildGrid("PortsActIPv4")})

$ButtonActiveSvc = New-Object Windows.Forms.Button
$ButtonActiveSvc.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 16))
$ButtonActiveSvc.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonActiveSvc.Text = "&Active Services"
$ButtonActiveSvc.add_click({BuildGrid("ActiveSvc")})

$ButtonActiveProc = New-Object Windows.Forms.Button
$ButtonActiveProc.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 20))
$ButtonActiveProc.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonActiveProc.Text = "&Processes"
$ButtonActiveProc.add_click({BuildGrid("ActiveProcs")})

$ButtonInstalledApps = New-Object Windows.Forms.Button
$ButtonInstalledApps.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 17))
$ButtonInstalledApps.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonInstalledApps.Text = "Installed A&pplications"
$ButtonInstalledApps.add_click({BuildGrid("InstallApps")})

$ButtonRemMGT = New-Object Windows.Forms.Button
$ButtonRemMGT.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 18))
$ButtonRemMGT.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonRemMGT.Text = "Rem&ote Management"
$ButtonRemMGT.add_click({BuildGrid("RemMGT")})

$ButtonRDP = New-Object Windows.Forms.Button
$ButtonRDP.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 19))
$ButtonRDP.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonRDP.Text = "Remote &Desktop"
$ButtonRDP.add_click({BuildGrid("RDP")})

$ButtonServices = New-Object Windows.Forms.Button
$ButtonServices.Location = New-Object Drawing.Point $global:BtnHStart,($global:BtnVStart + ($global:BtnVSpacing * 20))
$ButtonServices.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonServices.Text = "&Services"
$ButtonServices.add_click({BuildGrid("Services")})

$ButtonStartExport = New-Object Windows.Forms.Button
$ButtonStartExport.Location = New-Object Drawing.Point 875,25
$ButtonStartExport.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$ButtonStartExport.Text = "Recommended Settings"
$ButtonStartExport.add_click({Row_Status})

$Button_Apply = New-Object Windows.Forms.Button
$Button_Apply.Location = New-Object Drawing.Point 1030,25
$Button_Apply.size = New-Object Drawing.Point $global:BtnWidth,$global:BtnHeight
$Button_Apply.Text = "Apply Changes"
$Button_Apply.add_Click({Apply_Selections})

$dataGridView1 = New-Object System.Windows.Forms.DataGridView
$dataGridView1.Location = New-Object Drawing.Point 160,$global:BtnVStart
$dataGridView1.size = New-Object Drawing.Point 1020,840
$dataGridView1.MultiSelect = $false
$dataGridView1.ColumnHeadersVisible = $true
$dataGridView1.RowHeadersVisible = $false
#$dataGridView1.Visible = $False

$dataGridView2 = New-Object System.Windows.Forms.DataGridView
$dataGridView2.Location = New-Object Drawing.Point 160,720
$dataGridView2.size = New-Object Drawing.Point 1020,170
$dataGridView2.MultiSelect = $false
$dataGridView2.ColumnHeadersVisible = $true
$dataGridView2.RowHeadersVisible = $false
#$dataGridView2.Visible = $False

$DV1_Label = New-Object System.Windows.Forms.Label
$DV1_Label.Text = ""
$DV1_Label.Location = New-Object Drawing.Point 160,30
$DV1_Label.AutoSize = $True

$DV2_Label = New-Object System.Windows.Forms.Label
$DV2_Label.Text = "Firewall Rules"
$DV2_Label.Location = New-Object Drawing.Point 160,703
$DV2_Label.Visible = $false
$DV2_Label.AutoSize = $True

$form = New-Object Windows.Forms.Form
$form.text = "Windows OS Attack Surface Analyzer v1.0"
$form.Size = New-Object Drawing.Point 1210, 940
$form.topmost = 0
$form.Icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")

$form.Controls.Add($DV2_Label)
$form.Controls.Add($DV1_Label)
$form.Controls.Add($dataGridView1)
$form.Controls.Add($dataGridView2)
$form.controls.add($ButtonStartExport)
$form.controls.add($Button_Apply)
$form.controls.add($ButtonNetAdapters)
$form.controls.add($ButtonIPv)
$form.controls.add($ButtonNetSrv)
$form.controls.add($ButtonNBoIP)
$form.controls.add($ButtonLMHosts)
$form.controls.add($ButtonFWProfs)
$form.controls.add($ButtonFWIn)
$form.controls.add($ButtonFWOut)
$form.controls.add($ButtonFWLogAllowed)
$form.controls.add($ButtonFWLogBlocked)
$form.controls.add($ButtonFWLogIgnored)
$form.controls.add($ButtonFWIPv6Rules)
$form.controls.add($ButtonPortsLisIPv6)
$form.controls.add($ButtonPortsLisIPv4)
$form.controls.add($ButtonPortsActIPv6)
$form.controls.add($ButtonPortsActIPv4)
$form.controls.add($ButtonActiveSvc)
$form.controls.add($ButtonActiveProc)
$form.controls.add($ButtonInstalledApps)
$form.controls.add($ButtonRemMGT)
$form.controls.add($ButtonRDP)
$form.controls.add($ButtonServices)
#$form.add_Load($OnLoadForm)
Check-Status | Out-Null
<# Check_Module("Atk1")
Check_Module("Atk2")
Check_Module("Atk3")
Check_Module("Atk4")
Check_Module("Atk5")
Check_Module("Atk6")
Check_Module("Atk7")
Check_Module("Atk8")
Check_Module("Atk9")
Check_Module("Atk10")
Check_Module("Atk11")
Check_Module("Atk12")
Check_Module("Atk13")
Check_Module("Atk14")
Check_Module("Atk15")
Check_Module("Atk16")
Check_Module("Atk18")
Check_Module("Atk19")
Check_Module("Atk20") #>
$form.ShowDialog()

}

function checkSubnet ([string]$addr1, [string]$addr2)
{
    # Separate the network address and lenght
    $network1, [int]$subnetlen1 = $addr1.Split('/')
    $network2, [int]$subnetlen2 = $addr2.Split('/')
 
 
    #Convert network address to binary
    [uint32] $unetwork1 = NetworkToBinary $network1
 
    [uint32] $unetwork2 = NetworkToBinary $network2
 
 
    #Check if subnet length exists and is less then 32(/32 is host, single ip so no calculation needed) if so convert to binary
    if($subnetlen1 -lt 32){
        [uint32] $mask1 = SubToBinary $subnetlen1
    }
 
    if($subnetlen2 -lt 32){
        [uint32] $mask2 = SubToBinary $subnetlen2
    }
 
    #Compare the results
    if($mask1 -and $mask2){
        # If both inputs are subnets check which is smaller and check if it belongs in the larger one
        if($mask1 -lt $mask2){
            return CheckSubnetToNetwork $unetwork1 $mask1 $unetwork2
        }else{
            return CheckNetworkToSubnet $unetwork2 $mask2 $unetwork1
        }
    }ElseIf($mask1){
        # If second input is address and first input is subnet check if it belongs
        return CheckSubnetToNetwork $unetwork1 $mask1 $unetwork2
    }ElseIf($mask2){
        # If first input is address and second input is subnet check if it belongs
        return CheckNetworkToSubnet $unetwork2 $mask2 $unetwork1
    }Else{
        # If both inputs are ip check if they match
        CheckNetworkToNetwork $unetwork1 $unetwork2
    }
}
 
function CheckNetworkToSubnet ([uint32]$un2, [uint32]$ma2, [uint32]$un1)
{
    $ReturnArray = "" | Select-Object -Property Condition
 
    if($un2 -eq ($ma2 -band $un1)){
        $ReturnArray.Condition = $True
        #$ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }else{
        $ReturnArray.Condition = $False
        #$ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }
}
 
function CheckSubnetToNetwork ([uint32]$un1, [uint32]$ma1, [uint32]$un2)
{
    $ReturnArray = "" | Select-Object -Property Condition
 
    if($un1 -eq ($ma1 -band $un2)){
        $ReturnArray.Condition = $True
        #$ReturnArray.Direction = "Addr2ToAddr1"
        return $ReturnArray
    }else{
        $ReturnArray.Condition = $False
        #$ReturnArray.Direction = "Addr2ToAddr1"
        return $ReturnArray
    }
}
 
function CheckNetworkToNetwork ([uint32]$un1, [uint32]$un2)
{
    $ReturnArray = "" | Select-Object -Property Condition
 
    if($un1 -eq $un2){
        $ReturnArray.Condition = $True
        #$ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }else{
        $ReturnArray.Condition = $False
        #$ReturnArray.Direction = "Addr1ToAddr2"
        return $ReturnArray
    }
}
 
function SubToBinary ([int]$sub)
{
    return ((-bnot [uint32]0) -shl (32 - $sub))
}
 
function NetworkToBinary ($network)
{
    $a = [uint32[]]$network.split('.')
    return ($a[0] -shl 24) + ($a[1] -shl 16) + ($a[2] -shl 8) + $a[3]
}

Function Get-Info2{

    $AtkBtn2 = $args[0]

    $array2 = New-Object System.Collections.ArrayList($null)

    If($datagridview2.columncount -gt 0){
        #Remove-Columns
        $dataGridview2.DataSource = $null
    }
    if ($DataGridView2.Columns.Contains("Disable") -eq $false)
    {
        $Column1 = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
        $Column1.width = 60
        $Column1.name = "Disable"
        $DataGridView2.Columns.Add($Column1) 
    }

    if ($DataGridView2.Columns.Contains("Enable") -eq $false)
    {
        $Column2 = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
        $Column2.width = 60
        $Column2.name = "Enable"
        $DataGridView2.Columns.Add($Column2) 
    }

    $Script:GridInfo2 = $null

    switch ($AtkBtn2)
    {
        "RemMGT" { $ButtonRemMGT.Text = "Analyzing..."
                   $GridInfo2 = @(get-NetFirewallRule | Select DisplayName, Enabled | where {$_.DisplayName -like "*Windows Remote Management*" })
                   $ButtonRemMGT.Text = "Re&mote Management"
                 }
        "RDP" { $ButtonRDP.Text = "Analyzing..."
                   $GridInfo2 = @(get-NetFirewallRule | Select DisplayName, Enabled | where {$_.DisplayName -like "*AttackVector20-RDP*" })
                   $GridInfo2 += @(get-NetFirewallRule | Select DisplayName, Enabled | where {$_.DisplayName -like "*Remote Desktop*" })
                   $ButtonRDP.Text = "Remote &Desktop"
                 }

    }
    
    if ($GridInfo2.Count -eq 0)
    {
        $PSObject = new-object -TypeName PSObject -Property @{
                                Scan_Status = "SCAN COMPLETE"
                                Scan_Result = "No Ports Found!"}
        $GridInfo2 += @($PSObject)
    }

    $array2.AddRange($GridInfo2)

    $dataGridview2.DataSource = $array2

    $dataGridview2.Columns | Foreach-Object{
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
}
    $form.refresh() 
}

Function Get-Info
{
    $AtkBtn = $args[0]

    $Script:GridInfo = $null

    switch ($AtkBtn)
    {
        "NetAdapt" { $Script:GridInfo += @(AdapterInfo)
                       #Write-host $GridInfo
                     Check_Module("Check1")
                     Row_Status $AtkBtn
                   }
        "IPv?" { $Script:GridInfo += @(IPvInfo)
                 Check_Module("Check2")
                 Row_Status $AtkBtn
               }
        "NetSrv" { $Script:GridInfo += @(NetSrvInfo)
                 Check_Module("Check3")
                 Row_Status $AtkBtn
               }
        "NetBIOSoIP" { $Script:GridInfo += @(NBoTCPIPInfo)
                       Check_Module("Check4")
                       Row_Status $AtkBtn
                     }
        "LMHosts" { $Script:GridInfo += @(LMHostsInfo)
                    Check_Module("Check5")
                    Row_Status $AtkBtn
                  }
        "FWProfs" { $Script:GridInfo += @(FWProfilesInfo)
                    Check_Module("Check6")
                    Row_Status $AtkBtn
                  }
        "FWIn" { $Script:GridInfo += @(FWInBoundInfo)
                 Check_Module("Check7")
                 Row_Status $AtkBtn
               }
        "FWOut" { $Script:GridInfo += @(FWOutBoundInfo)
                  Check_Module("Check8")
                  Row_Status $AtkBtn
                }
        "FWLogAllowed" { $Script:GridInfo += @(FWLogAllowedInfo)
                  Check_Module("Check9")
                  Row_Status $AtkBtn
                }
        "FWLogBlocked" { $Script:GridInfo += @(FWLogBlockedInfo)
                  Check_Module("Check10")
                  Row_Status $AtkBtn
                }
        "FWLogIgnored" { $Script:GridInfo += @(FWLogIgnoredInfo)
                  Check_Module("Check11")
                  Row_Status $AtkBtn
                }
        "FWIPv6Rules" { $Script:GridInfo += @(FWIPv6RulesInfo)
                  Check_Module("Check12")
                  Row_Status $AtkBtn
                }
        "PortsLisIPv6" { $Script:GridInfo += @(ListenPortIPv6)
                  Check_Module("Check13")
                  Row_Status $AtkBtn
                }
        "PortsLisIPv4" { $Script:GridInfo += @(ListenPortIPv4)
                  Check_Module("Check14")
                  Row_Status $AtkBtn
                }
        "PortsActIPv6" { $Script:GridInfo += @(ActivePortIPv6)
                  Check_Module("Check15")
                  Row_Status $AtkBtn
                }
        "PortsActIPv4" { $Script:GridInfo += @(ActivePortIPv4)
                  Check_Module("Check16")
                  Row_Status $AtkBtn
                }
        "ActiveSvc" { $Script:GridInfo += @(WinServices)
                  Check_Module("Check17")
                  Row_Status $AtkBtn
                }
        "ActiveProcs" { $Script:GridInfo += @(WinProcesses)
                  Check_Module("Check18")
                  Row_Status $AtkBtn
                }
        "InstallApps" { $Script:GridInfo += @(InstalledApps)
                  Check_Module("Check19")
                  Row_Status $AtkBtn
                }
    }
}

function AdapterInfo
{
    get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
        $Adapter_Status = $_.Status
        $IFName = $_.InterfaceAlias
        $IP_Addr = ""
        Get-NetIPAddress -InterfaceAlias $IFName | where { $_.IPAddress -like "*.*.*.*" } | foreach-object {
            if ($IP_Addr.length -lt 3)
            {
                $IP_Addr = $_.IPAddress
                $CIDR = $_.PrefixLength
            }
            else
            {
                $IP_Addr = $IP_Addr + " ," + $_.IPAddress
            }
        }
        $TempVar = [ordered]@{
            Status = $Adapter_Status
            Name = $IFName
            IP_Address = $IP_Addr
            #Subnet = $CIDR
            #DualHomed_Status = $False
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

function IPvInfo
{
    get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
        $Adapter_Status = $_.Status
        $IFName = $_.InterfaceAlias
        get-NetAdapterBinding -InterfaceAlias $IFName | where { $_.ComponentID -Like "ms_tcpip*" -And $_.Enabled -eq $True } | foreach-object {
            $Network_Adapter = $_.Name
            $IP_Version = $_.ComponentID
            $Display_Name = $_.DisplayName
            $IP_Version_Enabled = $_.Enabled

        $TempVar = [ordered]@{
            Version = $IP_Version
            Enabled = $IP_Version_Enabled
            Name = $Network_Adapter
            Status = $Adapter_Status
            Display_Name = $Display_Name
            #IP_v4_v6_Enabled = $False
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
            }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
        }
        }
}

function NetSrvInfo
{
    get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
        $Adapter_Status = $_.Status
        $IFName = $_.InterfaceAlias
        get-NetAdapterBinding -InterfaceAlias $IFName | where { $_.ComponentID -NotLike "ms_tcpip*" } | foreach-object {
            $Interface_Name = $_.Name
            $Srv_Name = $_.ComponentID
            $Display_Name = $_.DisplayName
            $Service_Enabled = $_.Enabled

        $TempVar = [ordered]@{
            Service = $Srv_Name
            Enabled = $Service_Enabled
            Interface = $Interface_Name
            Status = $Adapter_Status
            Display_Name = $Display_Name
            #IP_v4_v6_Enabled = $False
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
        }
    }
}

Function NBoTCPIPInfo
{
    get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
        $Adapter_Status = $_.Status
        $IFIndex = $_.ifIndex
        $IFName = $_.InterfaceAlias
        get-wmiobject win32_networkadapterconfiguration | where { $_.tcpipnetbiosoptions -lt 3 } | foreach-object {
            if ($_.tcpipnetbiosoptions)
            {
                $NetBIOSTCP = $_.tcpipnetbiosoptions
            }
            }
        $IP_Addr = ""
        Get-NetIPAddress -ifIndex $IFIndex | where { $_.IPAddress -like "*.*.*.*" } | foreach-object {
            if ($IP_Addr.length -lt 3)
            {
                $IP_Addr = $_.IPAddress
                $CIDR = $_.PrefixLength
            }
            else
            {
                $IP_Addr = $IP_Addr + " ," + $_.IPAddress
            }
        }
        $TempVar = [ordered]@{
            Status = $Adapter_Status
            Name = $IFName
            IP_Address = $IP_Addr
            NetBIOS_Over_TCPIP = $NetBIOSTCP
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function LMHostsInfo
{
    get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
        $Adapter_Status = $_.Status
        $IFIndex = $_.ifIndex
        $IFName = $_.InterfaceAlias
        get-wmiobject win32_networkadapterconfiguration | foreach-object {
            if ($_.WINSEnableLMHostsLookup -eq $False -Or $_.WINSEnableLMHostsLookup -eq $True )
            {
                $LMHosts_Value = $_.WINSEnableLMHostsLookup
            }
            }
        $IP_Addr = ""
        Get-NetIPAddress -ifIndex $IFIndex | where { $_.IPAddress -like "*.*.*.*" } | foreach-object {
            if ($IP_Addr.length -lt 3)
            {
                $IP_Addr = $_.IPAddress
                $CIDR = $_.PrefixLength
            }
            else
            {
                $IP_Addr = $IP_Addr + " ," + $_.IPAddress
            }
        }
        $TempVar = [ordered]@{
            Status = $Adapter_Status
            Name = $IFName
            IP_Address = $IP_Addr
            LMHosts_Status = $LMHosts_Value
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWProfilesInfo
{
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, Enabled | Sort Profile, Enabled | foreach-object {
        $ProfileName = $_.Profile
        $Enabled_Status = $_.Enabled

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Enabled = $Enabled_Status
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWInBoundInfo
{
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, DefaultInboundAction | Sort Profile, DefaultInboundAction | foreach-object {
        $ProfileName = $_.Profile
        $Def_In_Action = $_.DefaultInboundAction

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Default_Inbound_Action = $Def_In_Action
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWOutBoundInfo
{
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, DefaultOutboundAction | Sort Profile, DefaultOutboundAction | foreach-object {
        $ProfileName = $_.Profile
        $Def_Out_Action = $_.DefaultOutboundAction

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Default_Outbound_Action = $Def_Out_Action
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWLogAllowedInfo
{
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, LogAllowed | Sort Profile, LogAllowed | foreach-object {
        $ProfileName = $_.Profile
        $Log_Allowed = $_.LogAllowed

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Log_Allowed_Enabled = $Log_Allowed
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWLogBlockedInfo
{
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, LogBlocked | Sort Profile, LogBlocked | foreach-object {
        $ProfileName = $_.Profile
        $Log_Blocked = $_.LogBlocked

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Log_Blocked_Enabled = $Log_Blocked
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWLogIgnoredInfo
{
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, LogIgnored | Sort Profile, LogIgnored | foreach-object {
        $ProfileName = $_.Profile
        $Log_Ignored = $_.LogIgnored

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Log_Ignored_Enabled = $Log_Ignored
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function FWIPv6RulesInfo
{
    $IP_Version_Enabled = $False
    $RuleEnabled = $False
    get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
        $Adapter_Status = $_.Status
        $IFName = $_.InterfaceAlias
        get-NetAdapterBinding -InterfaceAlias $IFName | where { $_.ComponentID -eq "ms_tcpip6" } | foreach-object {
            $Network_Adapter = $_.Name
            if ($_.ComponentID -eq "ms_tcpip6" -And $_.Enabled -eq $True)
            {
                $IP_Version = $_.ComponentID
                $IP_Version_Enabled = $_.Enabled
            }
        $TempVar = [ordered]@{
            Adapt_Name = $Network_Adapter
            Name = ""
            Rule_Enabled = $False
            IP_Version = $IP_Version
            IP_Version_Enabled = $IP_Version_Enabled
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
            }
        }
    }

    Get-NetFirewallRule -PolicyStore ActiveStore | Select DisplayName, Enabled | Sort DisplayName, Enabled | where {$_.DisplayName -like "*Pv6*"} | foreach-object {
        $Display_Name = $_.DisplayName
        $RuleEnabled = $_.Enabled

        $TempVar = [ordered]@{
            Name = $Display_Name
            Rule_Enabled = $RuleEnabled
            IPv6_Enabled = $IP_Version_Enabled
            Audit_Finding = "System is correctly configured."
            Recommendation = ""
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function ListenPortIPv6
{
    get-NetTCPConnection | where {$_.State -eq "Listen" -And $_.LocalAddress -notlike "*.*.*.*"} | Sort LocalPort | foreach-object {
                            $PortState = $_.State
                            $Local_IP_Addr = $_.LocalAddress
                            $Local_Port = $_.LocalPort
                            $VulnPort = $False
                            if ($global:Most_Common_Atkd_Ports -contains $_.LocalPort)
                            {
                                $VulnPort = $True
                            }
                            $Proc_ID = $_.OwningProcess
                            $ProcessID = Get-Process -ID $Proc_ID
                            $UserName = Get-Process -IncludeUserName | Where { $_.ID -eq $Proc_ID } | Select Username
                            $SearchCritI = "ImageName eq svchost.exe"
                            $SearchCritP = "PID eq $($Proc_ID)"
                            $TempString = Tasklist /nh /svc /fi $SearchCritI /fi $SearchCritP
                            $SrvNameArray = $TempString.split('',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
                            if ($SrvNameArray[0] -eq "svchost.exe")
                            {
                                $SrvName = $SrvNameArray[2]
                            }
                            else
                            {
                                $SrvName = ""
                            }
                            $VulnSrv = $False
                            if ($global:Most_Common_Atkd_Services -contains $SrvName)
                            {
                                $VulnSrv = $True
                            }

                            $TempVar = [ordered]@{
                                State = $PortState
                                #Local_IP_Address = $Local_IP_Addr
                                Local_Port = $Local_Port
                                Freq_Atkd_Port = $VulnPort
                                #Process_ID = $Proc_ID
                                #Process_Name = $ProcessID.Name
                                Service_Name = $SrvName
                                Freq_Atkd_Service = $VulnSrv
                                User = $Username.Username
                                Audit_Finding = "System is correctly configured."
                                Recommendation = ""
                            }
                            
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function ListenPortIPv4
{
    get-NetTCPConnection | where {$_.State -eq "Listen" -And $_.LocalAddress -like "*.*.*.*"} | Sort LocalPort | foreach-object {
                            $PortState = $_.State
                            $Local_IP_Addr = $_.LocalAddress
                            $Local_Port = $_.LocalPort
                            $VulnPort = $False
                            if ($global:Most_Common_Atkd_Ports -contains $_.LocalPort)
                            {
                                $VulnPort = $True
                            }
                            $Proc_ID = $_.OwningProcess
                            $ProcessID = Get-Process -ID $Proc_ID
                            $UserName = Get-Process -IncludeUserName | Where { $_.ID -eq $Proc_ID } | Select Username
                            $SearchCritI = "ImageName eq svchost.exe"
                            $SearchCritP = "PID eq $($Proc_ID)"
                            $TempString = Tasklist /nh /svc /fi $SearchCritI /fi $SearchCritP
                            $SrvNameArray = $TempString.split('',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
                            if ($SrvNameArray[0] -eq "svchost.exe")
                            {
                                $SrvName = $SrvNameArray[2]
                            }
                            else
                            {
                                $SrvName = ""
                            }
                            $VulnSrv = $False
                            if ($global:Most_Common_Atkd_Services -contains $SrvName)
                            {
                                $VulnSrv = $True
                            }

                            $TempVar = [ordered]@{
                                State = $PortState
                                #Local_IP_Address = $Local_IP_Addr
                                Local_Port = $Local_Port
                                Freq_Atkd_Port = $VulnPort
                                #Process_ID = $Proc_ID
                                #Process_Name = $ProcessID.Name
                                Service_Name = $SrvName
                                Freq_Atkd_Service = $VulnSrv
                                User = $Username.Username
                                Audit_Finding = "System is correctly configured."
                                Recommendation = ""
                            }
                            
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function ActivePortIPv6
{
    get-NetTCPConnection | where {$_.State -ne "Listen" -And $_.LocalAddress -notlike "*.*.*.*"} | Sort LocalPort | foreach-object {
                            $PortState = $_.State
                            $Local_IP_Addr = $_.LocalAddress
                            $Local_Port = $_.LocalPort
                            $VulnPort = $False
                            if ($global:Most_Common_Atkd_Ports -contains $_.LocalPort)
                            {
                                $VulnPort = $True
                            }
                            $Proc_ID = $_.OwningProcess
                            $ProcessID = Get-Process -ID $Proc_ID
                            $UserName = Get-Process -IncludeUserName | Where { $_.ID -eq $Proc_ID } | Select Username
                            $SearchCritI = "ImageName eq svchost.exe"
                            $SearchCritP = "PID eq $($Proc_ID)"
                            $TempString = Tasklist /nh /svc /fi $SearchCritI /fi $SearchCritP
                            $SrvNameArray = $TempString.split('',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
                            if ($SrvNameArray[0] -eq "svchost.exe")
                            {
                                $SrvName = $SrvNameArray[2]
                            }
                            else
                            {
                                $SrvName = ""
                            }
                            $VulnSrv = $False
                            if ($global:Most_Common_Atkd_Services -contains $SrvName)
                            {
                                $VulnSrv = $True
                            }

                            $TempVar = [ordered]@{
                                State = $PortState
                                #Local_IP_Address = $Local_IP_Addr
                                Local_Port = $Local_Port
                                Freq_Atkd_Port = $VulnPort
                                #Process_ID = $Proc_ID
                                #Process_Name = $ProcessID.Name
                                Service_Name = $SrvName
                                Freq_Atkd_Service = $VulnSrv
                                User = $Username.Username
                                Audit_Finding = "System is correctly configured."
                                Recommendation = ""
                            }
                            
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function ActivePortIPv4
{
    get-NetTCPConnection | where {$_.State -ne "Listen" -And $_.LocalAddress -like "*.*.*.*"} | Sort LocalPort | foreach-object {
                            $PortState = $_.State
                            $Local_IP_Addr = $_.LocalAddress
                            $Local_Port = $_.LocalPort
                            $VulnPort = $False
                            if ($global:Most_Common_Atkd_Ports -contains $_.LocalPort)
                            {
                                $VulnPort = $True
                            }
                            $Proc_ID = $_.OwningProcess
                            $ProcessID = Get-Process -ID $Proc_ID
                            $UserName = Get-Process -IncludeUserName | Where { $_.ID -eq $Proc_ID } | Select Username
                            $SearchCritI = "ImageName eq svchost.exe"
                            $SearchCritP = "PID eq $($Proc_ID)"
                            $TempString = Tasklist /nh /svc /fi $SearchCritI /fi $SearchCritP
                            $SrvNameArray = $TempString.split('',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
                            if ($SrvNameArray[0] -eq "svchost.exe")
                            {
                                $SrvName = $SrvNameArray[2]
                            }
                            else
                            {
                                $SrvName = ""
                            }
                            $VulnSrv = $False
                            if ($global:Most_Common_Atkd_Services -contains $SrvName)
                            {
                                $VulnSrv = $True
                            }

                            $TempVar = [ordered]@{
                                State = $PortState
                                #Local_IP_Address = $Local_IP_Addr
                                Local_Port = $Local_Port
                                Freq_Atkd_Port = $VulnPort
                                #Process_ID = $Proc_ID
                                #Process_Name = $ProcessID.Name
                                Service_Name = $SrvName
                                Freq_Atkd_Service = $VulnSrv
                                User = $Username.Username
                                Audit_Finding = "System is correctly configured."
                                Recommendation = ""
                            }
                            
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
    }
}

Function WinServices
{
    get-service | Sort Name, Status, StartType, DisplayName | Sort DisplayName | foreach-object {
                        $SrvName = $_.Name
                        $SrvStatus = $_.Status
                        $SrvStartUp = $_.StartType
                        $SrvDispName = $_.DisplayName
                        $VulnSrv = $False
                        if ($global:WindowsServices -contains $SrvName -And $SrvStartUp -ne "Disabled")
                        {
                            $VulnSrv = $True
                        }
                        $TempVar = [ordered]@{
                            Name = $SrvName
                            Status = $SrvStatus
                            StartUp = $SrvStartUp
                            Display_Name = $SrvDispName
                            Freq_Atkd_Service = $VulnSrv
                            Audit_Finding = "System is correctly configured."
                            Recommendation = ""
                        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
        }
}

Function WinProcesses
{
    $SVCHost_Names = Get-WmiObject Win32_Service  -FIlter "Pathname like '%svchost%'"|
                        ForEach-Object{
                                        $p = Get-Process -PID $_.ProcessID
                                        $p | Add-Member -MemberType NoteProperty -Name ServiceName -Value $_.Caption -PassThru
                                       } | Sort WS -Descending | Select ID, ServiceName

    get-process -IncludeUserName | Sort ID, ProcessName, Name, Username | Sort Name | foreach-object {
                        $ProcProd = $_.Name
                        $ProcName = $_.ProcessName
                        $ProcID = $_.ID
                        $SVC_Name = ""
                        foreach ($proc in $SVCHost_Names)
                        {
                            if ($_.ID -eq $proc.ID )
                            {
                                $SVC_Name = $proc.ServiceName
                            }
                        }
                        $ProcUName = $_.Username
                        $TempVar = [ordered]@{
                            Name = $ProcProd
                            Process_Name = $ProcName
                            Process_ID = $ProcID
                            ProcName = $SVC_Name
                            User = $ProcUName
                            Audit_Finding = "System is correctly configured."
                            Recommendation = ""
                        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        write-host $PSObject
        return $PSObject
        }
}

Function InstalledApps
{
    $64bitApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove) }
    $32bitApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove) }
    $AllApps = $64bitApps + $32bitApps
    $AllApps | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | foreach-object {
                        $DispName = $_.DisplayName
                        $DispVersion = $_.DisplayVersion
                        $AppPublisher = $_.Publisher
                        $AppInstallDate = $_.InstallDate

                        $TempVar = [ordered]@{
                            Name = $DispName
                            Version = $DispVersion
                            Publisher = $AppPublisher
                            Installed_Date = $AppInstallDate
                            Audit_Finding = "System is correctly configured."
                            Recommendation = "Review need for application."
                            }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        return $PSObject
                      }
}

Function ReadRegKey
{
    $RegPath = $args[0]
    $KeyName = $args[1]

    Get-ItemProperty -Path $RegPath -Name $KeyName | ForEach-Object {
                    $PSObject = new-object -TypeName PSObject -Property @{
                                Registry_Key_Value = $_.$KeyName
                                Registry_Key_Name = $KeyName
                                Registry_Key_Path = $_.PSPath
                                }
                    return $PSObject }
}

function Check_Module
{
    $CallingFunction = $args[0]

    $global:Check_Result = "False"

        switch ($CallingFunction)
        {
            "Check1" { $ButtonNetAdapters.BackColor = "Green"
                       $ButtonNetAdapters.ForeColor = "White"

                     for ($i=0; $i -lt $GridInfo.Length; $i++)
                     {
                        for ($j=1; $j -lt $GridInfo.Length; $j++)
                        {
                            if ((checkSubnet $GridInfo.IP_Address[$i] $GridInfo.IP_Address[$j]).Condition -eq $False)
                            {
                                $GridInfo[$i].Audit_Finding = "System is dual homed."
                                $GridInfo[$i].Recommendation = "Each system should only have one IP address."
                                $GridInfo[$j].Audit_Finding = "System is dual homed."
                                $GridInfo[$j].Recommendation = "Each system should only have one IP address."
                                $ButtonNetAdapters.BackColor = "Red"
                            }
                        }
                     }
                   }

            "Check2" { $ButtonIPv.BackColor = "Green"
                     $ButtonIPv.ForeColor = "White"
                     $IPv4Count = 0
                     $IPv6Count = 0
                     for ($i=0; $i -lt $GridInfo.Length; $i++)
                     {
                        $IPv4Count += ($GridInfo[$i].Version | where { $GridInfo[$i].Version -eq "ms_tcpip" -And $GridInfo[$i].Status -eq "Up" -And $GridInfo[$i].Enabled -eq $True }).count
                        $IPv6Count += ($GridInfo[$i].Version | where { $GridInfo[$i].Version -eq "ms_tcpip6" -And $GridInfo[$i].Status -eq "Up" -And $GridInfo[$i].Enabled -eq $True }).count
                     }
                     
                     if ( $IPv4Count -gt 0 -And $IPv6Count -gt 0 )
                     {
                        for ($i=0; $i -lt $GridInfo.Length; $i++)
                        {
                            $GridInfo[$i].Audit_Finding = "System is running 2 IP versions."
                            $GridInfo[$i].Recommendation = "Each system should only run one IP version."
                            $ButtonIPv.BackColor = "Red"
                        }
                     }
                   }

            "Check3" { $ButtonNetSrv.BackColor = "Green"
                       $ButtonNetSrv.ForeColor = "White"

                       $FileShareCount = @(Get-SmbShare | where { $_.Name -ne "IPC$" -And $_.Name -ne "ADMIN$" -And $_.Name -notlike "*$"}).count

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                            if ( $FileShareCount -gt 0 )
                            {
                                if (( $GridInfo[$i].Service -ne "ms_server" -And $GridInfo[$i].Service -ne "ms_msclient" -And $GridInfo[$i].Service -ne "ms_lltdio" -And $GridInfo[$i].Service -ne "ms_rspndr") -And $GridInfo[$i].Enabled -eq $True)
                                {
                                    $GridInfo[$i].Audit_Finding = "Service is not necessary."
                                    $GridInfo[$i].Recommendation = "Disable this network service."
                                    $ButtonNetSrv.BackColor = "Red"
                                }
                                else
                                {
                                    if ($GridInfo[$i].Enabled -eq $False -And $GridInfo[$i].Service -eq "ms_server")
                                    {
                                        $GridInfo[$i].Audit_Finding = "File Shares detected."
                                        $GridInfo[$i].Recommendation = "Enable this network service."
                                        $ButtonNetSrv.BackColor = "Red"
                                    }
                                }
                            }
                            else
                            {
                                if (($GridInfo[$i].Service -ne "ms_msclient" -And $GridInfo[$i].Service -ne "ms_lltdio" -And $GridInfo[$i].Service -ne "ms_rspndr") -And $GridInfo[$i].Enabled -eq $True)
                                {
                                    $GridInfo[$i].Audit_Finding = "Service is not necessary."
                                    $GridInfo[$i].Recommendation = "Disable this network service."
                                    $ButtonNetSrv.BackColor = "Red"
                                }
                            }
                        }
                   }

            "Check4" { $ButtonNBoIP.BackColor = "Green"
                       $ButtonNBoIP.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                            if ( $GridInfo[$i].NetBIOS_Over_TCPIP -ne 2 -And $GridInfo[$i].Status -eq "Up" )
                            {
                                $GridInfo[$i].Audit_Finding = "NetBIOS over TCP/IP is enabled."
                                $GridInfo[$i].Recommendation = "Disable NetBIOS over TCP/IP."
                                $ButtonNBoIP.BackColor = "Red"
                            }
                        }
                     }
            "Check5" { $ButtonLMHosts.BackColor = "Green"
                       $ButtonLMHosts.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                            if ( $GridInfo[$i].LMHosts_Status -eq $True -And $GridInfo[$i].Status -eq "Up" )
                            {
                                $GridInfo[$i].Audit_Finding = "LMHosts Lookup is enabled."
                                $GridInfo[$i].Recommendation = "Disable LMHosts Lookup."
                                $ButtonLMHosts.BackColor = "Red"
                            }
                        }
                   }

            "Check6" { $ButtonFWProfs.BackColor = "Green"
                       $ButtonFWProfs.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Enabled -eq $False )
                          {
                              $GridInfo[$i].Audit_Finding = "Firewall profile is not enabled."
                              $GridInfo[$i].Recommendation = "Enable all firewall profiles."
                              $ButtonFWProfs.BackColor = "Red"
                          }
                       }
                     }

            "Check7" { $ButtonFWIn.BackColor = "Green"
                       $ButtonFWIn.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Default_Inbound_Action -eq "Allow" )
                          {
                              $GridInfo[$i].Audit_Finding = "Firewall default inbound action is allow."
                              $GridInfo[$i].Recommendation = "Default inbound action should be block."
                              $ButtonFWIn.BackColor = "Red"
                          }
                       }
                     }
            "Check8" { $ButtonFWOut.BackColor = "Green"
                       $ButtonFWOut.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Default_Outbound_Action -eq "Allow" )
                          {
                              $GridInfo[$i].Audit_Finding = "Firewall default outbound action is allow."
                              $GridInfo[$i].Recommendation = "Default outbound action should be block."
                              $ButtonFWOut.BackColor = "Red"
                          }
                       }
                   }
            "Check9" { $ButtonFWLogAllowed.BackColor = "Green"
                       $ButtonFWLogAllowed.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Log_Allowed_Enabled -eq $False )
                          {
                              $GridInfo[$i].Audit_Finding = "Firewall is not logging allowed traffic."
                              $GridInfo[$i].Recommendation = "Logging allowed traffic should be enabled."
                              $ButtonFWLogAllowed.BackColor = "Red"
                          }
                       }
                   }
            "Check10" {$ButtonFWLogBlocked.BackColor = "Green"
                       $ButtonFWLogBlocked.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Log_Blocked_Enabled -eq $False )
                          {
                              $GridInfo[$i].Audit_Finding = "Firewall is not logging blocked traffic."
                              $GridInfo[$i].Recommendation = "Logging blocked traffic should be enabled."
                              $ButtonFWLogBlocked.BackColor = "Red"
                          }
                       }
                   }
            "Check11" {$ButtonFWLogIgnored.BackColor = "Green"
                       $ButtonFWLogIgnored.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Log_Ignored_Enabled -eq $False )
                          {
                              $GridInfo[$i].Audit_Finding = "Firewall is not logging ignored traffic."
                              $GridInfo[$i].Recommendation = "Logging ignored traffic should be enabled."
                              $ButtonFWLogIgnored.BackColor = "Red"
                          }
                       }
                   }
            "Check12" {$ButtonFWIPv6Rules.BackColor = "Green"
                       $ButtonFWIPv6Rules.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Rule_Enabled -eq $True -And $GridInfo[$i].IPv6_Enabled -eq $False )
                          {
                              $GridInfo[$i].Audit_Finding = "IPv6 Firewall rule is enabled."
                              $GridInfo[$i].Recommendation = "IPv6 rules should be disabled."
                              $ButtonFWIPv6Rules.BackColor = "Red"
                          }

                          if ( $GridInfo[$i].Rule_Enabled -eq "False" -And $GridInfo[$i].IPv6_Enabled -eq $True)
                          {
                              $GridInfo[$i].Audit_Finding = "IPv6 Firewall rule is enabled."
                              $GridInfo[$i].Recommendation = "IPv6 rules should be disabled."
                              $ButtonFWIPv6Rules.BackColor = "Red"
                          }
                       }
                   }
            "Check13" {$ButtonPortsLisIPv6.BackColor = "Green"
                       $ButtonPortsLisIPv6.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Freq_Atkd_Port -eq $True -Or $GridInfo[$i].Freq_Atkd_Service -eq $True )
                          {
                              $GridInfo[$i].Audit_Finding = "Vulnerable port or service found."
                              $GridInfo[$i].Recommendation = "Review the necessity of the vulnerable port or service."
                              $ButtonPortsLisIPv6.BackColor = "Red"
                          }
                       }
                    }
            "Check14" {$ButtonPortsLisIPv4.BackColor = "Green"
                       $ButtonPortsLisIPv4.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Freq_Atkd_Port -eq $True -Or $GridInfo[$i].Freq_Atkd_Service -eq $True )
                          {
                              $GridInfo[$i].Audit_Finding = "Vulnerable port or service found."
                              $GridInfo[$i].Recommendation = "Review the necessity of the vulnerable port or service."
                              $ButtonPortsLisIPv4.BackColor = "Red"
                          }
                       }
                   }
            "Check15" {$ButtonPortsActIPv6.BackColor = "Green"
                       $ButtonPortsActIPv6.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Freq_Atkd_Port -eq $True -Or $GridInfo[$i].Freq_Atkd_Service -eq $True )
                          {
                              $GridInfo[$i].Audit_Finding = "Vulnerable port or service found."
                              $GridInfo[$i].Recommendation = "Review the necessity of the vulnerable port or service."
                              $ButtonPortsActIPv6.BackColor = "Red"
                          }
                       }
                   }
            "Check16" {$ButtonPortsActIPv4.BackColor = "Green"
                       $ButtonPortsActIPv4.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Freq_Atkd_Port -eq $True -Or $GridInfo[$i].Freq_Atkd_Service -eq $True )
                          {
                              $GridInfo[$i].Audit_Finding = "Vulnerable port or service found."
                              $GridInfo[$i].Recommendation = "Review the necessity of the vulnerable port or service."
                              $ButtonPortsActIPv4.BackColor = "Red"
                          }
                       }
                   }
            "Check17" {$ButtonActiveSvc.BackColor = "Green"
                       $ButtonActiveSvc.ForeColor = "White"

                       for ($i=0; $i -lt $GridInfo.Length; $i++)
                       {
                          if ( $GridInfo[$i].Freq_Atkd_Port -eq $True -Or $GridInfo[$i].Freq_Atkd_Service -eq $True )
                          {
                              $GridInfo[$i].Audit_Finding = "Vulnerable port or service found."
                              $GridInfo[$i].Recommendation = "Review the necessity of the vulnerable service."
                              $ButtonActiveSvc.BackColor = "Red"
                          }
                       }
                }
            "Check18" {$ButtonInstalledApps.BackColor = "Red"
                       $ButtonInstalledApps.ForeColor = "White"
                   }
            "Atk19" {if ($global:OSType -eq "Server")
                     {
                        if ((configure-smremoting -get) -like "*enabled")
                        {
                            $ButtonRemMGT.BackColor = "Green"
                        }
                        else
                        {
                            $ButtonRemMGT.BackColor = "Red"
                        }
                     }
                    else
                     {
                        if ((get-service winrm | Where { $_.Status -eq "Running" }).count -gt 0)
                        {
                            $ButtonRemMGT.BackColor = "Green"
                        }
                        else
                        {
                            $ButtonRemMGT.BackColor = "Red"
                        }
                     }
                     $ButtonRemMGT.ForeColor = "White"
                    }
            "Atk20" {if ($global:OSType -eq "Server")
                     {
                        if ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections -ne 0 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel).MinEncryptionLevel -ne 4 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber -eq 3389 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer).SecurityLayer -ne 2 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication -ne 1)
                        {
                            $ButtonRDP.BackColor = "Green"
                        }
                        else
                        {
                            $ButtonRDP.BackColor = "Red"
                        }
                     }
                    else
                     {
                        if ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections -ne 0 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel).MinEncryptionLevel -ne 4 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber -eq 3389 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer).SecurityLayer -ne 2 `
                        -Or (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication -ne 1)
                        {
                            $ButtonRDP.BackColor = "Green"
                        }
                        else
                        {
                            $ButtonRDP.BackColor = "Red"
                        }
                     }
                     $ButtonRDP.ForeColor = "White"
                    }
            "Atk21" {
                        $TempString = net accounts
                        $SrvNameArray = $TempString.split(':',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
                        if ($SrvNameArray[3] -lt 2 -And $SrvNameArray[5] -lt 180 -And $SrvNameArray[7] -lt 14 -And $SrvNameArray[9] -lt 24 -And $SrvNameArray[11] -lt 4 -And $SrvNameArray[13] -lt 63 -And $SrvNameArray[15] -lt 60)
                        {
                            $global:Check_Result = "True"
                        }
                     }
            }
}

 Function BuildGrid{

    $AtkBtn = $args[0]

    $DV2_Label.Visible = $false
    $dataGridView1.size = New-Object Drawing.Point 1020,840

    $array = New-Object System.Collections.ArrayList($null)

    If($datagridview1.columncount -gt 0){
        #Remove-Columns
        $dataGridview1.DataSource = $null
    }
    if ($DataGridView1.Columns.Contains("Disable") -eq $false)
    {
        $Column1 = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
        $Column1.width = 60
        $Column1.name = "Disable"
        $DataGridView1.Columns.Add($Column1) 
    }

    if ($DataGridView1.Columns.Contains("Enable") -eq $false)
    {
        $Column2 = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
        $Column2.width = 60
        $Column2.name = "Enable"
        $DataGridView1.Columns.Add($Column2) 
    }

    $Script:GridInfo = $null

    switch ($AtkBtn)
    {
        "NetAdapt" { $ButtonNetAdapters.Text = "Analyzing..."
                     $DV1_Label.Text = "Net Adapter settings (Powershell - Get-NetAdapter)"
                     Get-Info("NetAdapt")
                     $ButtonNetAdapters.Text = "&Network Adapters"
                    }

        "IPv?" { $ButtonIPv.Text = "Analyzing..."
                 $DV1_Label.Text = "IP Version(s) (Powershell - Get-NetAdapterBinding)"
                 Get-Info("IPv?")
                 $ButtonIPv.Text = "IP &Version"
               }

        "NetSrv" { $ButtonNetSrv.Text = "Analyzing..."
                   $DV1_Label.Text = "Network Services (Powershell - Get-NetAdapterBinding)"
                   Get-Info("NetSrv")
                   $ButtonNetSrv.Text = "Network &Services"
                 }
        "NetBIOSoIP" { $ButtonNBoIP.Text = "Analyzing..."
                       $DV1_Label.Text = "NetBIOS over TCP/IP setting (Powershell - Get-WMIObject win32_networkadapterconfiguration)"
                       Get-Info("NetBIOSoIP")
                       $ButtonNBoIP.Text = "Net&BIOS over TCP/IP"
                     }
        "LMHosts" { $ButtonLMHosts.Text = "Analyzing..."
                    $DV1_Label.Text = "LMHosts setting (Powershell - Get-WMIObject win32_networkadapterconfiguration)"
                    Get-Info("LMHosts")
                    $ButtonLMHosts.Text = "&LMHosts Lookup"
                  }
        "FWProfs" { $ButtonFWProfs.Text = "Analyzing..."
                    $DV1_Label.Text = "Firewall Profile settings (Powershell - Get-NetFirewallProfile)"
                    Get-Info("FWProfs")
                    $ButtonFWProfs.Text = "&Firewall Profiles"
                  }
        "FWIn" { $ButtonFWIn.Text = "Analyzing..."
                 $DV1_Label.Text = "Default Firewall Inbound Action settings (Powershell - Get-NetFirewallProfile)"
                 Get-Info("FWIn")
                 $ButtonFWIn.Text = "Firewall &Inbound Action"
               }
        "FWOut" { $ButtonFWOut.Text = "Analyzing..."
                  $DV1_Label.Text = "Default Firewall Outbound Action settings (Powershell - Get-NetFirewallProfile)"
                  Get-Info("FWOut")
                  $ButtonFWOut.Text = "&Firewall &Outbound Action"
                }
        "FWLogAllowed" { $ButtonFWLogAllowed.Text = "Analyzing..."
                         $DV1_Label.Text = "Firewall Log Allowed Traffic settings (Powershell - Get-NetFirewallProfile)"
                         Get-Info("FWLogAllowed")
                         $ButtonFWLogAllowed.Text = "Firewall Log &Allowed"
                       }
        "FWLogBlocked" { $ButtonFWLogBlocked.Text = "Analyzing..."
                         $DV1_Label.Text = "Firewall Log Blocked Traffic settings (Powershell - Get-NetFirewallProfile)"
                         Get-Info("FWLogBlocked")
                         $ButtonFWLogBlocked.Text = "Firewall Log &Blocked"
                       }
        "FWLogIgnored" { $ButtonFWLogIgnored.Text = "Analyzing..."
                         $DV1_Label.Text = "Firewall Log Ignored Traffic settings (Powershell - Get-NetFirewallProfile)"
                         Get-Info("FWLogIgnored")
                         $ButtonFWLogIgnored.Text = "Firewall Log I&gnored"
                       }
        "FWIPv6Rules" { $ButtonFWIPv6Rules.Text = "Analyzing..."
                        $DV1_Label.Text = "Enabled IPv6 Firewall Rules (Powershell - Get-NetFirewallRule)"
                        Get-Info ("FWIPv6Rules")
                        $ButtonFWIPv6Rules.Text = "Firewall IPv6 &Rules"
                      }
        "PortsLisIPv6" { $ButtonPortsLisIPv6.Text = "Analyzing..."
                         Get-Info("PortsLisIPv6")
                         $ButtonPortsLisIPv6.Text = "&Listening Ports IPv6"
                       }
        "PortsLisIPv4" { $ButtonPortsLisIPv4.Text = "Analyzing..."
                         Get-Info("PortsLisIPv4")
                         $ButtonPortsLisIPv4.Text = "Lis&tening Ports IPv4"
                       }
        "PortsActIPv6" { $ButtonPortsActIPv6.Text = "Analyzing..."
                         Get-Info("PortsActIPv6")
                         $ButtonPortsActIPv6.Text = "Active Ports IPv6"
                       }
        "PortsActIPv4" { $ButtonPortsActIPv4.Text = "Analyzing..."
                         Get-Info("PortsActIPv4")
                         $ButtonPortsActIPv4.Text = "Active Ports IPv4"
                       }
        "ActiveSvc" { $ButtonActiveSvc.Text = "Analyzing..."
                      Get-Info("ActiveSvc")
                      $ButtonActiveSvc.Text = "Acti&ve Services"
                    }
        "ActiveProcs" { $ButtonActiveProc.Text = "Analyzing..."
                      Get-Info("ActiveProcs")
                      $ButtonActiveProc.Text = "Acti&ve Processes"
                    }
        "InstallApps" { $ButtonInstalledApps.Text = "Analyzing..."
                        Get-Info("InstallApps")
                        $ButtonInstalledApps.Text = "Installed Ap&plications"
                      }
        "RemMGT" { $ButtonRemMGT.Text = "Analyzing..."
                   $dataGridView1.size = New-Object Drawing.Point 1020,650
                   $GridInfo = @(get-service winrm | Select Name, DisplayName, Status, StartType)
                   $DV2_Label.Visible = $true
                   Get-info2("RemMGT")
                   $ButtonRemMGT.Text = "Re&mote Management"
                 }
        "RDP" { $ButtonRDP.Text = "Analyzing..."
                $dataGridView1.size = New-Object Drawing.Point 1020,650

                $GridInfo += @(ReadRegKey 'HKLM:\System\CurrentControlSet\Control\Terminal Server' fDenyTSConnections)
                $GridInfo += @(ReadRegKey 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' MinEncryptionLevel)
                $GridInfo += @(ReadRegKey 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' PortNumber)
                $GridInfo += @(ReadRegKey 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' SecurityLayer)
                $GridInfo += @(ReadRegKey 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication)
                $GridInfo += @(ReadRegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' fPromptForPassword)
                $GridInfo += @(ReadRegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' fWritableTSCCPermTab)
                $GridInfo += @(ReadRegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' fEncryptRPCTraffic)
                $GridInfo += @(ReadRegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' CertTemplateName)

                $DV2_Label.Visible = $true
                Get-info2("RDP")
                $ButtonRDP.Text = "Remote &Desktop"
              }

        "Services" { 
                     $Script:GridInfo = @(get-service | Select-Object StartType, Status, DisplayName, Name | Sort DisplayName)
                   }
    }

    if ($GridInfo.Count -eq 0)
    {
        $PSObject = new-object -TypeName PSObject -Property @{
                                Scan_Status = "SCAN COMPLETE"
                                Scan_Result = "No Ports Found!"}
        $GridInfo += @($PSObject)
    }

    $array.AddRange($GridInfo)

    $dataGridview1.DataSource = $array

    $dataGridview1.Columns | Foreach-Object{
        $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
        }
    Row_Status $AtkBtn

    $form.refresh()
}      

function Find_Ports_Services
{
    $IPVer = $args[0]
    $IPType = $args[1]
    $ConnectionType = $args[2]

    if ($IPVer -eq "4")
    {
        (get-NetTCPConnection | where {$_.State -eq $IPType -And $_.LocalAddress -like $ConnectionType} | Sort LocalPort | foreach-object {
            $PortState = $_.State
            $Local_IP_Addr = $_.LocalAddress
            $Local_Port = $_.LocalPort
            $Proc_ID = $_.OwningProcess
            $ProcessID = Get-Process -ID $Proc_ID
            $SearchCritI = "ImageName eq svchost.exe"
            $SearchCritP = "PID eq $($Proc_ID)"
            $TempString = Tasklist /nh /svc /fi $SearchCritI /fi $SearchCritP
            $SrvNameArray = $TempString.split('',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
            if ($SrvNameArray[0] -eq "svchost.exe")
            {
                $SrvName = $SrvNameArray[2]
            }
            else
            {
                $SrvName = ""
            }

                new-object -TypeName PSObject -Property @{
                    Port_State = $PortState
                    Local_IP_Address = $Local_IP_Addr
                    Local_Port = $Local_Port
                    Process_ID = $Proc_ID
                    Process_Name = $ProcessID.Name
                    Service_Name = $SrvName
                }
        } | ft -AutoSize | Out-String).trim()
    }
    else
    {
        (get-NetTCPConnection | where {$_.State -eq $IPType -And $_.LocalAddress -notlike $ConnectionType} | Sort LocalPort | foreach-object {
            $PortState = $_.State
            $Local_IP_Addr = $_.LocalAddress
            $Local_Port = $_.LocalPort
            $Proc_ID = $_.OwningProcess
            $ProcessID = Get-Process -ID $Proc_ID
            $SearchCritI = "ImageName eq svchost.exe"
            $SearchCritP = "PID eq $($Proc_ID)"
            $TempString = Tasklist /nh /svc /fi $SearchCritI /fi $SearchCritP
            $SrvNameArray = $TempString.split('',3,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
            if ($SrvNameArray[0] -eq "svchost.exe")
            {
                $SrvName = $SrvNameArray[2]
            }
            else
            {
                $SrvName = ""
            }

                new-object -TypeName PSObject -Property @{
                    Port_State = $PortState
                    Local_IP_Address = $Local_IP_Addr
                    Local_Port = $Local_Port
                    Process_ID = $Proc_ID
                    Process_Name = $ProcessID.Name
                    Service_Name = $SrvName
                }
        } | ft -AutoSize | Out-String).trim()
    }
}

Function Apply_Selections{

for($i=0;$i -lt $datagridview1.RowCount;$i++){ 

       if($datagridview1.Rows[$i].Cells['Disable'].Value -eq $true)
       {
         #write-host "cell #$i is checked"
         #uncheck it
         set-service -Name $datagridview1.Rows[$i].Cells['Name'].Value -StartupType Disabled
         BuildGrid
       }
    }
}

Function Row_Status
{

    $AtkBtn = $args[0]

    for($i=0;$i -lt $datagridview1.RowCount;$i++)
    {
       if ($datagridview1.Rows[$i].Cells['Disable'].Value -eq $true)
       {
           write-host "cell #$i is checked"
           #uncheck it
           $datagridview1.Rows[$i].Cells['Disable'].Value=$false
       }

       if ($datagridview1.Rows[$i].Cells['Recommendation'].Value -eq "")
       {
            $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
       }
       else
       {
            $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
       }

<#       switch ($AtkBtn)
       {
            "NetAdapt" { if ($datagridview1.Rows[$i].Cells['Recommendation'].Value -eq "")
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
                         }
                         else
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
                         }
                       }
            "IPv?" { if ($datagridview1.Rows[$i].Cells['Recommendation'].Value -eq "")
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
                         }
                         else
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
                         }
                       }
            "NetSrv" { if ($datagridview1.Rows[$i].Cells['Recommendation'].Value -eq "")
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
                         }
                         else
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
                         }
                       }
            "NetBIOSoIP" { if ($datagridview1.Rows[$i].Cells['Recommendation'].Value -eq "")
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
                         }
                         else
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
                         }
                       }
            "LMHosts" { if ($datagridview1.Rows[$i].Cells['Recommendation'].Value -eq "")
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
                         }
                         else
                         {
                                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
                         }
                       }
            "Services"
            {   switch ($datagridview1.Rows[$i].Cells['Name'].Value)
                {
                    "AJRouter" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "ALG" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "bthserv" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "CertPropSvc" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "DiagTrack" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "bthserv" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "DsmSvc" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "DPS" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "WdiServiceHost" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                    "WdiSystemHost" {$datagridview1.Rows[$i].Cells['Disable'].Value=$true; Break}
                }
            }
       }
#>
       if ($datagridview1.Rows[$i].Cells['StartType'].Value -eq "Disabled" -And $datagridview1.Rows[$i].Cells['Disable'].Value -eq $true)
       {
            $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Green"
       }
       else
       {
            if ($datagridview1.Rows[$i].Cells['Disable'].Value -eq $true)
            {
                $datagridview1.Rows[$i].DefaultCellStyle.ForeColor = "Red"
            }
       }

    }
}

Function Remove-Columns {
    $Columns = $datagridview1.Columns.Count
    for ($c = $Columns-1; $c -ge 0; $c--) {
        $datagridview1.Columns.Remove($datagridview1.Columns[$c].Name)
        #Start-sleep -s 1
    }
}

function getOSType
{
    $SearchCritType = "OS Configuration"
    $TempStringType = systeminfo | findstr /B /C:$SearchCritType
    $OSTypeArray = $TempStringType.split(' ',4,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
    $global:OSType = $OSTypeArray[3]

    $SearchCritName = "OS Name"
    $TempStringName = systeminfo | findstr /B /C:$SearchCritName
    $OSNameArray = $TempStringName.split(' ',4,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
    if ($global:OSType -eq "Server")
    {
        if ($OSNameArray[3] -like "*201*")
        {
            $global:OSName = $OSNameArray
            $global:ValidOS = "True"
        }
    }
    else
    {
        if ($OSNameArray[3] -like "*1*")
        {
            $global:OSName = $OSNameArray
            $global:ValidOS = "True"
        }
    }
}

function Call-OSCheck {

	#----------------------------------------------
	#region Import the Assemblies
	#----------------------------------------------
	[void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	

	#----------------------------------------------
	#region Generated Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$StatusForm = New-Object 'System.Windows.Forms.Form'
	$label1 = New-Object 'System.Windows.Forms.Label'
	$InitializeProgram = New-Object 'System.Windows.Forms.Timer'
	$InitialFormWindowState = New-Object 'System.Windows.Forms.FormWindowState'
	#endregion Generated Form Objects

	#----------------------------------------------
	# User Generated Script
	#----------------------------------------------
		
	$StatusForm_Load = {
		
		$TotalTime = 10 #in seconds
		
			$script:StartTime = (Get-Date).AddSeconds($TotalTime)
			#Start the timer
			$InitializeProgram.Start()
	}
	
	$InitializeProgram_Tick={
			#Use Get-Date for Time Accuracy
			[TimeSpan]$span = $script:StartTime - (Get-Date)
			
			#Update the display
			$StatusForm.Text = "Windows OS Attack Surface Analyzer v1.0"
            $label1.Text = "Getting OS Information..."
            GetOSType

			$InitializeProgram.Stop()
			$StatusForm.Close()
		}
	
	
	# --End User Generated Script--
	#----------------------------------------------
	#region Generated Events
	#----------------------------------------------
	
	$Form_StateCorrection_Load=
	{
		#Correct the initial state of the form to prevent the .Net maximized form issue
		$StatusForm.WindowState = $InitialFormWindowState
	}
	
	$Form_Cleanup_FormClosed=
	{
		#Remove all event handlers from the controls
		try
		{
			$StatusForm.remove_Load($StatusForm_Load)
			$InitializeProgram.remove_Tick($InitializeProgram_Tick)
			$StatusForm.remove_Load($Form_StateCorrection_Load)
			$StatusForm.remove_FormClosed($Form_Cleanup_FormClosed)
		}
		catch [Exception]
		{ }
	}
	#endregion Generated Events

	#----------------------------------------------
	#region Generated Form Code
	#----------------------------------------------
	$StatusForm.SuspendLayout()
	#
	# StatusForm
	#
	$StatusForm.Controls.Add($label1)
	$StatusForm.ClientSize = '420, 100'
	$StatusForm.Name = 'StatusForm'
	$StatusForm.Text = 'Form'
	$StatusForm.add_Load($StatusForm_Load)
	#
	# label1
	#
	$label1.Font = 'Microsoft Sans Serif, 20.25pt'
	$label1.Location = '20, 20'
	$label1.Name = 'label1'
	$label1.Size = '400, 100'
	$label1.TabIndex = 2
	$label1.Text = 'Initializing Program...'
	#
	#
	# timer1
	#
	$InitializeProgram.add_Tick($InitializeProgram_Tick)
	$StatusForm.ResumeLayout()
	#endregion Generated Form Code

	#----------------------------------------------

	#Save the initial state of the form
	$InitialFormWindowState = $StatusForm.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$StatusForm.add_Load($Form_StateCorrection_Load)
	#Clean up the control events
	$StatusForm.add_FormClosed($Form_Cleanup_FormClosed)
	#Show the Form
	return $StatusForm.ShowDialog()

} #End Function

function Check-Status {

	#----------------------------------------------
	#region Import the Assemblies
	#----------------------------------------------
	[void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	

	#----------------------------------------------
	#region Generated Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$StatusForm = New-Object 'System.Windows.Forms.Form'
	$label1 = New-Object 'System.Windows.Forms.Label'
	$InitializeProgram = New-Object 'System.Windows.Forms.Timer'
	$InitialFormWindowState = New-Object 'System.Windows.Forms.FormWindowState'
	#endregion Generated Form Objects

	#----------------------------------------------
	# User Generated Script
	#----------------------------------------------
		
	$StatusForm_Load = {
		
		$TotalTime = 10 #in seconds
		
			$script:StartTime = (Get-Date).AddSeconds($TotalTime)
			#Start the timer
			$InitializeProgram.Start()
	}
	
	$InitializeProgram_Tick={
			#Use Get-Date for Time Accuracy
			[TimeSpan]$span = $script:StartTime - (Get-Date)
			
			#Update the display
			$StatusForm.Text = "Windows OS Attack Surface Analyzer v1.0"
            $label1.Text = "Analyzing..."

            $label1.Text = $label1.Text +"`nNetwork Configuration..."
            Get-Info("NetAdapt")
            Get-Info("IPv?")
            Get-Info("NetSrv")
            Get-Info("NetBIOSoIP")
            Get-Info("LMHosts")
            $label1.Text = $label1.Text + "done`nFirewall Configuration..."
            Get-Info("FWProfs")
            Get-Info("FWIn")
            Get-Info("FWOut")
            Get-Info("FWLogAllowed")
            Get-Info("FWLogBlocked")
            Get-Info("FWLogIgnored")
            $label1.Text = $label1.Text + "done`nListening Ports..."
            $StatusForm.refresh()
            Get-Info("FWIPv6Rules")
            Get-Info("PortsLisIPv6")
            $label1.Text = $label1.Text + "done`nActive Ports..."
            $StatusForm.refresh()
            Get-Info("PortsLisIPv4")
            Get-Info("PortsActIPv6")
            $label1.Text = $label1.Text + "done`nActive Services..."
            $StatusForm.refresh()
            Get-Info("PortsActIPv4")
            $label1.Text = $label1.Text + "done`nWindows Services..."
            $StatusForm.refresh()
            Get-Info("ActiveSvc")
            $label1.Text = $label1.Text + "done`nInstalled Applications..."
            $StatusForm.refresh()
            Get-Info("InstallApps")
            $label1.Text = $label1.Text + "done`nRemote Desktop..."
            $StatusForm.refresh()
            $label1.Text = $label1.Text + "done`nRemote Management..."
            $StatusForm.refresh()
<#            Check_Module("Atk20")
#>
			$InitializeProgram.Stop()
			$StatusForm.Close()
		}
	
	
	# --End User Generated Script--
	#----------------------------------------------
	#region Generated Events
	#----------------------------------------------
	
	$Form_StateCorrection_Load=
	{
		#Correct the initial state of the form to prevent the .Net maximized form issue
		$StatusForm.WindowState = $InitialFormWindowState
	}
	
	$Form_Cleanup_FormClosed=
	{
		#Remove all event handlers from the controls
		try
		{
			$StatusForm.remove_Load($StatusForm_Load)
			$InitializeProgram.remove_Tick($InitializeProgram_Tick)
			$StatusForm.remove_Load($Form_StateCorrection_Load)
			$StatusForm.remove_FormClosed($Form_Cleanup_FormClosed)
		}
		catch [Exception]
		{ }
	}
	#endregion Generated Events

	#----------------------------------------------
	#region Generated Form Code
	#----------------------------------------------
	$StatusForm.SuspendLayout()
	#
	# StatusForm
	#
	$StatusForm.Controls.Add($label1)
	$StatusForm.ClientSize = '420, 500'
	$StatusForm.Name = 'StatusForm'
	$StatusForm.Text = 'Form'
	$StatusForm.add_Load($StatusForm_Load)
	#
	# label1
	#
	$label1.Font = 'Microsoft Sans Serif, 12pt'
	$label1.Location = '20, 20'
	$label1.Name = 'label1'
	$label1.Size = '400, 475'
	$label1.TabIndex = 2
	$label1.Text = 'Initializing Program...'
	#
	#
	# timer1
	#
	$InitializeProgram.add_Tick($InitializeProgram_Tick)
	$StatusForm.ResumeLayout()
	#endregion Generated Form Code

	#----------------------------------------------

	#Save the initial state of the form
	$InitialFormWindowState = $StatusForm.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$StatusForm.add_Load($Form_StateCorrection_Load)
	#Clean up the control events
	$StatusForm.add_FormClosed($Form_Cleanup_FormClosed)
	#Show the Form
	return $StatusForm.ShowDialog()

} #End Function

#Call the form
Call-OSCheck | Out-Null

#[System.Windows.MessageBox]::Show("Please Wait:  Loading Program", "Initializing",0)
#GenerateStatusForm

GenerateForm
# SIG # Begin signature block
# MIITTgYJKoZIhvcNAQcCoIITPzCCEzsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUPbH5XRQJa/49sV74ouc2owZr
# IsagghCxMIIHyjCCBbKgAwIBAgITeAAAAAmHzADLupVfHAACAAAACTANBgkqhkiG
# 9w0BAQsFADBPMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJk/IsZAEZ
# FghTT0NDLUVNUzEcMBoGA1UEAxMTRU1TIElzc3VpbmcgQ0EgR2VuMTAeFw0xOTEw
# MTAxNTQwMzhaFw0yMDEwMDkxNTQwMzhaMFcxFTATBgoJkiaJk/IsZAEZFgVsb2Nh
# bDEYMBYGCgmSJomT8ixkARkWCFNPQ0MtRU1TMQ4wDAYDVQQDEwVVc2VyczEUMBIG
# A1UEAxMLVG9kIENoYXBtYW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDbrSJpNXfR0nrzilrgVFX+hMa/TGNP0PqkE9ysusNmgBObAKB32eu9+5dH2BfL
# 6g4piXfpzax/G1bIHOxBL2RVbOGkkW98Xil6uEBd/SS/shQfgSCppnEHCHba1ahM
# HfdMaF5VQhilILd1qemG7/DkyUJI44if/uL+Vmro8+rUaL8ZOIB7e/XRCiQeTugo
# GENYUzVAcS3NAXGHXYvedW/ZV0W5otob5fNJQuQx7ZXO2/k86QmDenMiaLzSqmYE
# ybH5c4g8xWSoksJMCsrPENuAPOSMZQZfYHf2Q9ANRmRlQdjf6nGLltTjRsp24/1y
# 0SrJONcXYHnxZHwJLi+oqUFTAgMBAAGjggOVMIIDkTA9BgkrBgEEAYI3FQcEMDAu
# BiYrBgEEAYI3FQiB054Fh77Zd4TBkS+ErthyhbvXSXiF0qU4genlNAIBZAIBAjAT
# BgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUK
# BA4wDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU15X9+bFMWwQHkASYs/ubX3yL0MUw
# HwYDVR0jBBgwFoAUG7hV/+lauhG1euiAEZDqQk+BdUgwgZgGA1UdHwSBkDCBjTCB
# iqCBh6CBhIZAaHR0cDovL2VjY2RwLnNvY2MtZW1zLmxvY2FsL2NkcC9FTVMlMjBJ
# c3N1aW5nJTIwQ0ElMjBHZW4xKDIpLmNybIZAaHR0cDovL2ViY2RwLnNvY2MtZW1z
# LmxvY2FsL2NkcC9FTVMlMjBJc3N1aW5nJTIwQ0ElMjBHZW4xKDIpLmNybDCCAf4G
# CCsGAQUFBwEBBIIB8DCCAewwgbsGCCsGAQUFBzAChoGubGRhcDovLy9DTj1FTVMl
# MjBJc3N1aW5nJTIwQ0ElMjBHZW4xLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPVNPQ0MtRU1T
# LERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZp
# Y2F0aW9uQXV0aG9yaXR5MC0GCCsGAQUFBzABhiFodHRwOi8vZWNjZHAuc29jYy1l
# bXMubG9jYWwvb2NzcC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9lYmNkcC5zb2NjLWVt
# cy5sb2NhbC9vY3NwLzBmBggrBgEFBQcwAoZaaHR0cDovL2VjY2RwLnNvY2MtZW1z
# LmxvY2FsL2NkcC9FQ0lQS0lOVjAyLlNPQ0MtRU1TLmxvY2FsX0VNUyUyMElzc3Vp
# bmclMjBDQSUyMEdlbjEoMikuY3J0MGYGCCsGAQUFBzAChlpodHRwOi8vZWJjZHAu
# c29jYy1lbXMubG9jYWwvY2RwL0VDSVBLSU5WMDIuU09DQy1FTVMubG9jYWxfRU1T
# JTIwSXNzdWluZyUyMENBJTIwR2VuMSgyKS5jcnQwMQYDVR0RBCowKKAmBgorBgEE
# AYI3FAIDoBgMFk5XRTc3NzdAU09DQy1FTVMubG9jYWwwDQYJKoZIhvcNAQELBQAD
# ggIBAGdWRXNgHrybXQ1rytYzoaSijvj8O8/GslA7x1/DgJFcELCG1wBuvmAJ0tBn
# W9F4rKDHtyWYHrBf4cilZJc0I68VsJJt1nnQrROH1WO2pyddAOm1I9pig6RYNj9W
# VMQyxiU8xMRCavUVG16X+cjHkpxvZYL/BlNQ9V98UYoVoNf5kNokQJZW/F+gIpcJ
# rl7f3/bJvf+Tvb19J29N6cfEMDoMXTVsjnkeZzVIg+lv2hSp/PmaHmvt6xqRFQLV
# GniGThfgKz95kSIkGd/9WHT6hHqn4fv3ABRurTn1NcG7xI8d1pPqj5x9SBNn+fPf
# TZZmvPZLUjzO75/q3FGNQOHr0fWjN5ZRCSSAILTweu/mwZiAqzcegHTGEVbDAsVY
# kzG25jq8FDIHLufp3a3CbXVmzxA8W5KJaJgXKZAXBsP7eqaUQhu601l1SPPKxCFc
# 6ajQ/gDDTGMeFKgBC+9iNZOwS2ZvTRXrX5z0V1z3QyNd0QcVGe2zmfAmzhqJikrR
# yyAtQ/LBilwxoYI7MO6ybCfWDmPJnrG2OwwGGADcnOiqsrFE9WPrQP/dYGF73K2N
# SR+UowH9E6nech+DnhaSySxsCCfHhklQl/HzYUlASYbFo/NfoqCq5dCiQRMKlaan
# HgfBPv4gIKBE+l5L5ROgVxVJxtjUPQSoh9juv5yfymDGUsUEMIII3zCCBsegAwIB
# AgITPgAAAAe564BMED7UmQABAAAABzANBgkqhkiG9w0BAQsFADBMMRUwEwYKCZIm
# iZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJk/IsZAEZFghTT0NDLUVNUzEZMBcGA1UE
# AxMQRU1TIFJvb3QgQ0EgR2VuMTAeFw0xOTEwMDIyMjI1MTVaFw0yOTEwMDIyMjM1
# MTVaME8xFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEYMBYGCgmSJomT8ixkARkWCFNP
# Q0MtRU1TMRwwGgYDVQQDExNFTVMgSXNzdWluZyBDQSBHZW4xMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAp5XV36Eu72Jz3wzH/R7JN1foh+2HMG7RaLjb
# qHf+Tm1ZvSb1m64C3A+d3exKsv15DiwuCh0khfA9J+4GKEKgoUHJIafEpxYC7W5w
# Cdd12cAPWI0abDK0o3X+ALLHEcMxd0eXWZR+INbBSyVGn8jjf0n7iFQqEaFP5Hao
# 4/wG+Kpna0zD0UEGaJF/gLrkn/i6rbCi7wuuyxrB3t8HDYMTdLjy4q2VZNoMYKdV
# 1dMruGp+YNzSK41ZLG5sgkrLh/TU3Cj8F24fUFmgTU0SI83mfIxdBqLlB5vNoVJ1
# A2PB1vKPtlTcw1NZY+Wd2mD2agTTamekHcQYEKTKI0NpPuHyL6zyZ8xwB3tA2lcZ
# bFnG0MvhfbuJuhRuaEDKB4TrXoERf/MGo8I2xVvv68GeigetOhHU75eG1864U4Q8
# 6v6wYud6dfVX5np7ZbHajRLeDDRneZ0ycFEqRLcutVWVYx/7UlK6EiunM0NDA6OX
# RtYD1nvYcIwnbvdJpAw4JuOOlTZ7Wrwsco0IxA5gakuwxRPlNs5UABXYs6YVjpdu
# S2T3VebGvIIaBydwCpQ9ufc0qCpSV8vHQiS0ppDtlsYo8X2WDICFcEh8EiiZK/Ec
# Af7XB810S4bSYKCegudjZsNjKoXn7ykQDGnMOlhbrTpiPFSioo8lU04LWaN/YDI6
# fX33Y+0CAwEAAaOCA7UwggOxMBIGCSsGAQQBgjcVAQQFAgMCAAIwIwYJKwYBBAGC
# NxUCBBYEFNhhLemcYpLy/D3irwjywet9FMZHMB0GA1UdDgQWBBQbuFX/6Vq6EbV6
# 6IARkOpCT4F1SDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTMU7nS3v4kV5guIEVikW5m
# HgnpwjCCAWAGA1UdHwSCAVcwggFTMIIBT6CCAUugggFHhoHGbGRhcDovLy9DTj1F
# TVMlMjBSb290JTIwQ0ElMjBHZW4xKDEpLENOPUVDSVBLSU5WMDEsQ049Q0RQLENO
# PVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy
# YXRpb24sREM9U09DQy1FTVMsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9u
# TGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hj1odHRw
# Oi8vZWNjZHAuc29jYy1lbXMubG9jYWwvY2RwL0VNUyUyMFJvb3QlMjBDQSUyMEdl
# bjEoMSkuY3Jshj1odHRwOi8vZWJjZHAuc29jYy1lbXMubG9jYWwvY2RwL0VNUyUy
# MFJvb3QlMjBDQSUyMEdlbjEoMSkuY3JsMIIBlwYIKwYBBQUHAQEEggGJMIIBhTCB
# uAYIKwYBBQUHMAKGgatsZGFwOi8vL0NOPUVNUyUyMFJvb3QlMjBDQSUyMEdlbjEs
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9U09DQy1FTVMsREM9bG9jYWw/Y0FDZXJ0aWZpY2F0
# ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwYwYIKwYB
# BQUHMAKGV2h0dHA6Ly9lY2NkcC5zb2NjLWVtcy5sb2NhbC9jZHAvRUNJUEtJTlYw
# MS5TT0NDLUVNUy5sb2NhbF9FTVMlMjBSb290JTIwQ0ElMjBHZW4xKDEpLmNydDBj
# BggrBgEFBQcwAoZXaHR0cDovL2ViY2RwLnNvY2MtZW1zLmxvY2FsL2NkcC9FQ0lQ
# S0lOVjAxLlNPQ0MtRU1TLmxvY2FsX0VNUyUyMFJvb3QlMjBDQSUyMEdlbjEoMSku
# Y3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCSdeNxYm2PBrc+UhVqkLD9TGcfgYHSp3er
# tDZapFwMUqoe5SP/6paRHlguhn5BjqGu0vSutO9eBRWnwy+QZL6JuC3EBa09e7Zk
# ZtYMIgiQQmDBw7pVS/dLPbwYIo2kdtwElMmxwyaXMDUqdWv9RbQJcHUOVRnNUyVQ
# EYuvk3niTtgk9LPSa3hcNbGFD78Q6zrijMTooe4gZwVngpHl2LLWhr7FTTgpJTRE
# 1HWqe/bATXE2h5tn/5ZyDjTvUj3SLWU8zQYDrt6Aw+rOpL2GjHJ6PI85RmQ2zJar
# BM+nDCd89h44m0jkYrQcX94YFq4Yj97IQAC4H7racpQVKxjQnreGxuSvX3S2+Dy3
# ABSw50cn7JF7dm2qZ/lAa1C4fOyx7ZF9x5dkIUSvrqKIoHsZ7LoVsrEguXxTJt9B
# h3Qu7xeqpp7Gqg56CdPKhFrLRrfzS/eJOEx3gDTZCM/s2QZB8fFyQN6A/MY9VpQG
# QtGxTkXNBREcC4pep3f4JXeKt8g/PL3WZaDcx4cUeuX0tRGqh8PckxhBovFuky+f
# O9bEfjuT5SWNFZfTXAjHbOzeHVI5PJEQUrWRTXnWlchl8s6juxLRc30C9k14Bnso
# +EF3DeE5ezu68cKnQMhK0/Js8Uo9Ih7Qaw7+bMlmTLviuy4AKQWXdBpSYokavzGl
# QuXYhYEtXjGCAgcwggIDAgEBMGYwTzEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRgw
# FgYKCZImiZPyLGQBGRYIU09DQy1FTVMxHDAaBgNVBAMTE0VNUyBJc3N1aW5nIENB
# IEdlbjECE3gAAAAJh8wAy7qVXxwAAgAAAAkwCQYFKw4DAhoFAKB4MBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLhIwiq4
# j4uoszqHE94r8V8x7kkUMA0GCSqGSIb3DQEBAQUABIIBAIqm1jWKrScz2IhhNoVT
# vgEdQQn0kjWMrBY0AYANMy9/fVhzS7FOnZ4V1iHnWEGl62BzSV3K+FAEXjYYRn50
# FMtixqIK41N0CPIgLLS1NNXgES9EJRRcjnnkhyPv0TJL8TA7Cy7ulgaHcCpe7L61
# MH3uuGXKB+8IRt5Zyhb3o345NROKZBqhcwVAJ61pzHRoTb32bHgxpJ1LWY0xizBT
# VjAhoNRa/9/mg5mrR0wza53ZCMN/XJvOIG7mBzOwDMP3XztDg8J71PT7872QD3Yn
# xUTErd/8NEAQ2IPucUy9wYlAWkVpznMuiN3rcIbefVau6VBUw9Q+mhUFaNTzSdDH
# 5mg=
# SIG # End signature block
