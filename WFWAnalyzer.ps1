# * Copyright (D) Tod Chapman - All Rights Reserved.
# * Unauthorized copying of this file, via any medium is strictly prohibited.
# * Proprietary and Confidential.
# * Written by Tod Chapman <pedaln.fast@gmail.com>, October 2016-2021

<#

.SYNOPSIS
    This function does the following:
        Reads in the Windows firewall logs (pfirewall.log and pfirewall.log.old)
        Groups the data based on destination port, destination IP, source IP, action, protocol, and Direction
        Allows searching based on the items above
        Displays the current state of the firewall
        Allows user to enable or disable firewall components

.DESCRIPTION
    This is a program that allows the user to analyze traffic logs from the Windows firewall.

.PARAMETER
    None

.PARAMETER
    None

.INPUTS
    c:\windows\system32\logfiles\firewall\pfirewall.log
    c:\windows\system32\logfiles\firewall\pfirewall.log.old

.OUTPUTS
    Firewall logs
    Firewall state
    Firewall log analysis

.EXAMPLE
    None

.EXAMPLE
    None

.LINK
    None

#>

# *********************
# *** DEBUG Tracing ***
# *********************

    # Set the trace option to off.
    Set-PSDebug -Trace 0

    # Set the trace option to on.
    #Set-PSDebug -Trace 1

# *********************
# *** DEBUG Tracing ***
# *********************

# ****************************
# *** CONSTANT Definitions ***
# ****************************

    # Program Versioning Information
    $global:FWMVersion = "1.0.20210912"
    $global:BuildDate = "09/12/2021"

    # Preference setting for continuing after error
    $global:ProgressPreference = 'SilentlyContinue'

    # Debug Flag
    $global:Debug = $True

    # Ports to be scanned during investigation
    $global:TCP_Ports = @('21','22','23','80','443','1433','3389')
    $global:TCP_PortName = @('FTP','SSH','Telnet','HTTP','SSL (HTTPS)','SQL','RDP')

    # Linux Distriutions for OS identification
    $global:LinuxDistros = @('Android','Debian','GNU/Linux','Fedora','openSUSE','Red Hat','Slackware','SUSE','Ubuntu','Arch','CentOS','Gentoo','KNOPPIX','Mint','Mageia','Oracle','Scientific','Raspbian','Kali','ParrotOS','BackBox','BlackArch','CAINE','CensorNet','CLIP OS','Copperhead OS','Cyborg Hawk','DEFT','Security Onion','Sophos')

    # Windows networking services and explantations
    $global:MSClientInfo = ("Client for Microsoft Networks`r`n" +
        			        "`r`nRecommendation: Enabled`r`n" +
        			        "`r`nMost users don’t need most of these protocols except of course for the TCP/IPv4 protocol which is the fundamental protocol for an internet connection.`r`n" +
        			        "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:MSServerInfo = ("File and Printer Sharing for Microsoft Networks`r`n" +
                            "`r`nRecommendation: Enabled if file sharing is needed otherwise Disabled`r`n" +
                            "`r`nThe File and Printer Sharing for Microsoft Networks component allows other computers on a network to access resources on your computer by using a Microsoft network. This component is installed and enabled by default for all VPN connections. However, this component needs to be enabled for PPPoE and dial-up connections. It is enabled per connection and is necessary to share local folders." +
                            "`r`nMost users don’t need most of these protocols except of course for the TCP/IPv4 protocol which is the fundamental protocol for an internet connection. For instance if you don’t have a server and don’t need file and printer sharing you can disable "“File and Printer Sharing over Microsoft Networks”" which will increase your security dramatically.`r`n" +
                            "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:QoSInfo = ("QoS Packet Scheduler`r`n" +
                       "`r`nRecommendation: Disabled`r`n" +
                       "`r`nThe Quality of Service Packet Scheduler is a Windows platform component that is enabled by default and is designed to control the IP traffic for various network services, as a method of network bandwidth management that can monitor the importance of data packets and based on the priority of the packet.`r`n" +
                       "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:IPv4Info = ("Internet Protocol Version 4 (TCP/IPv4)`r`n" +
                        "`r`nRecommendation: Enabled`r`n" +
                        "`r`nMost users don’t need most of these protocols except of course for the TCP/IPv4 protocol which is the fundamental protocol for an internet connection.`r`n" +
                        "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:MultiplexorInfo = ("Microsoft Network Adapter Multiplexor Protocol`r`n" +
                               "`r`nRecommendation: Disabled`r`n" +
                               "`r`nThe Microsoft Network Adapter Multiplexor Protocol service is a kernel mode driver. If the Microsoft Network Adapter Multiplexor Protocol fails to start, the error is logged. Windows 8 startup proceeds, but a message box is displayed informing you that the NdisImPlatform service has failed to start. This protocol is used for Network Interface Card bonding, which is the combining of two ethernet cards to appear as one physical device in order to increase the available bandwidth.`r`n" +
                               "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:LLDPInfo = ("Microsoft LLDP Protocol Driver`r`n" +
                        "`r`nRecommendation: Disabled`r`n" +
                        "`r`nThe Link Layer Discovery Protocol (LLDP) is a link layer protocol used by network devices for advertising their identity, capabilities and neighbors on an IEEE 802 local area network.`r`n" +
                        "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:IPv6Info = ("Internet Protocol Version 6 (TCP/IPv6)`r`n" +
                        "`r`nRecommendation: Disabled, unless IPv6 is used by the system.`r`n" +
                        "`r`nIt is nearly certain that your computer does not use the TCP/IPv6 so you can disable that protocol as well.`r`n" +
                        "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:LLTDInfo = ("Link-Layer Topology Discovery Responder`r`n" +
                        "`r`nRecommendation: Disabled, unless network mapping is needed.`r`n" +
                        "`r`nThe drivers is responsible for displaying and representing computers and devices on a map. It consists of two components, the Mapper I/O Driver and the Responder which work together for the service to exist.`r`n" +
                        "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    $global:LLTDMapperInfo = ("Link-Layer Topology Discovery Mapper I/O Driver`r`n" +
                              "`r`nRecommendation: Disabled, unless network mapping is needed.`r`n" +
                              "`r`nThe drivers is responsible for displaying and representing computers and devices on a map. It consists of two components, the Mapper I/O Driver and the Responder which work together for the service to exist.`r`n" +
                              "`r`nReference: https://social.technet.microsoft.com/Forums/en-US/f933e03b-e157-4a1d-9916-8cfeb11ad2fc/small-network-in-private-household-lldp-topoly-discovery-qos")

    # Program threat descriptions
    $global:Threats = @(@{ThreatName='Local Evasive Port Scan';ThreatDesc='A device on your private (home) network is performing an evasive port scan.  Port scans are used to see what ports are available on a device. A port scan can be valid. This port scan is considered evasive due to the use of random characteristics.'})

# ********************************
# *** END CONSTANT Definitions ***
# ********************************

# ****************************
# *** Initialize Variables ***
# ****************************

    $global:IPInfo = @()
    $global:Dest_port = @()
    $global:Dest_IP = @()
    $global:Source_IP = @()
    $global:Protocol = @()
    $global:Action = @()
    $global:Direction = @()
    $global:GridInfo = @()
    $global:Live_Search = @()
    $global:FWLogInfo = @()
    $global:LicenseKey = @()
    $global:LastWriteTime = ""
    $global:CurrentTab = ""
    $global:Initialize = $True
    $global:response = ""
    $global:VulnPorts = ""
    $global:InternetAvail = @()
    $global:SelectedTab = 0
    $global:LoggingFailed = $False
    $global:HRiskIssues = @()
    $global:MRiskIssues = @()
    $global:LRiskIssues = @()
    $global:PrevLogFile = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log.old"
    $global:CurLogFile = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    $global:PrevFileState = "Available"
    $global:CurFileState = "Available"
    $global:RemIPSelected = $False
    $global:DstPrtSelected = ""
    $global:DstIPSelected = ""
    $global:SrcIPSelected = ""
    $global:ActionSelected = ""
    $global:ProtoSelected = ""

# ************************************
# *** End Initialization Variables ***
# ************************************

# ******************************************************************************************************************************************************
# *** External Functions                                                                                                                             ***
# ******************************************************************************************************************************************************

# ****************************
# *** Function AdapterInfo ***
# ****************************

    function AdapterInfo
    {
        if ($global:Debug)
        {
            write-host "Function AdapterInfo"
        }

        Get-NetIPAddress | where { $_.IPAddress -like "*.*.*.*" -and $_.InterfaceAlias -notlike "*Loopback*"} | foreach-object {
            $IP_Addr = $_.IPAddress
            $IFName = $_.InterfaceAlias
            get-NetAdapter | where { $_.Status -eq "Up" } | foreach-object {
                $Adapter_Status = $_.Status
                $IFIndex = $_.ifIndex
                $MacAddr = $_.MacAddress
        
                $TempVar = [ordered]@{
                    Name = $IFName
                    Status = $Adapter_Status
                    Index = $IFIndex
                    IP_Address = $IP_Addr
                    MAC_Address = $MacAddr
                }
                $PSObject = new-object -TypeName PSObject -Property $TempVar
            }
            return $PSObject
        }
    }

# ********************************
# *** END Function AdapterInfo ***
# ********************************

# *********************************
# *** Function Build_LicenseKey ***
# *********************************

    Function Build_LicenseKey
    {
        if ($global:Debug)
        {
            write-host "Function Build_LicenseKey"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Checking for license...")
        $tbLicenseStatus.Text = "Checking..."
        $tbLicenseStatus.BackColor = "Orange"
        $MAC_Pieces = $global:IPInfo[0].MAC_Address.split("-")
        $Position = 1

        foreach ($Element in $MAC_Pieces)
        {  
            $Temp = 0

            Switch ($Element[0])
            {
                "A" {$Index0 = 10}
                "B" {$Index0 = 11}
                "C" {$Index0 = 12}
                "D" {$Index0 = 13}
                "E" {$Index0 = 14}
                "F" {$Index0 = 15}
                "a" {$Index0 = 10}
                "b" {$Index0 = 11}
                "c" {$Index0 = 12}
                "d" {$Index0 = 13}
                "e" {$Index0 = 14}
                "f" {$Index0 = 15}
                Default {$Index0 = $Element[0]}
            }

            $Temp = [int]$Index0 + 2468 - [int]$Index0 * [int]$Position

            Switch ($Element[1])
            {
                "A" {$Index1 = 10}
                "B" {$Index1 = 11}
                "C" {$Index1 = 12}
                "D" {$Index1 = 13}
                "E" {$Index1 = 14}
                "F" {$Index1 = 15}
                "a" {$Index1 = 10}
                "b" {$Index1 = 11}
                "c" {$Index1 = 12}
                "d" {$Index1 = 13}
                "e" {$Index1 = 14}
                "f" {$Index1 = 15}
                Default {$Index1 = $Element[1]}
            }
            $Temp += [int]$Position + 1357 + [int]$Index1 * 5
            $global:LicenseKey += $Temp
            $Position = $Position + 1
        }

        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\WinFWMon')
        {
            $InstD = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey1 - ($global:LicenseKey[0]+$global:LicenseKey[1])
            $InstM = ($global:LicenseKey[2]+$global:LicenseKey[3]) - (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey2
            $InstY = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey3 - ($global:LicenseKey[4]+$global:LicenseKey[5])

            if ($InstD -lt 10)
            {
                $TempInstD = "0$InstD"
            }
            else
            {
                $TempInstD = $InstD
            }

            if ($InstM -lt 10)
            {
                $TempInstM = "0$InstM"
            }
            else
            {
                $TempInstM = $InstM
            }

            $Temp = "$TempInstM/$TempInstD/$InstY"

            $InstDate=[Datetime]::ParseExact($Temp, 'MM/dd/yy', $null)

            $Temp = Get-date
        
            $LicLife = [int]($Temp - $InstDate).TotalDays

            If ($LicLife -le 365)
            {
                if (($global:LicenseKey[0]+$global:LicenseKey[1]+$InstD).ToString() -eq (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey1 -and ($global:LicenseKey[2]+$global:LicenseKey[3]-$InstM).ToString() -eq (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey2 -and ($global:LicenseKey[4]+$global:LicenseKey[5]+$InstY).ToString() -eq (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey3)
                {
                    if ($LicLife -lt 315)
                    {
                        $mainform.text = "Windows Firewall Analyzer $global:FWMVersion"
                    }
                    else
                    {
                        $LicDaysLeft = 365 - $LicLife
                        $mainform.text = "Windows Firewall Analyzer $global:FWMVersion (License Expires in $LicDaysLeft Days)"
                    }
                    $tbLicOne.text = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey1
                    $tbLicTwo.text = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey2
                    $tbLicThree.text = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\WinFWMon).LicenseKey3
                    $btnValidLic.Text = "License Validated"
                    $btnValidLic.BackColor = "Green"
                    $btnValidLic.ForeColor = "White"
                    $tbLicOne.ReadOnly = $True
                    $tbLicOne.TabStop = $False
                    $tbLicTwo.ReadOnly = $True
                    $tbLicTwo.TabStop = $False
                    $tbLicThree.ReadOnly = $True
                    $tbLicThree.TabStop = $False
                    $InstY = $InstY + 1
                    $lbLicenseKey.text = "License Key (Exp $InstM/$InstD/$InstY)"
                    $ttValidLic.SetToolTip($btnValidLic, "Validate License Key is Valid")
                    $tbAppLog.AppendText("Valid License Found.`r`n")
                    $tbLicenseStatus.Text = "Valid License"
                    $tbLicenseStatus.BackColor = "Green"
                    $tbLicenseStatus.ForeColor = "White"
                }
                else
                {
                    $btnValidLic.Text = "Validate License Key"
                    $btnValidLic.BackColor = "Orange"
                    $btnValidLic.ForeColor = "Black"
                    $ttValidLic.SetToolTip($btnValidLic, "Validate License Key")
                    $mainform.text = "Windows Firewall Analyzer $global:FWMVersion (UNLICENSED)"
                    $tbAppLog.AppendText("NO Valid License Found.`r`n")
                    $tbLicenseStatus.Text = "License NOT found"
                    $tbLicenseStatus.BackColor = "Red"
                    $tbLicenseStatus.ForeColor = "White"
                }
            }
            else
            {
                $btnValidLic.Text = "Validate License Key"
                $btnValidLic.BackColor = "Orange"
                $btnValidLic.ForeColor = "Black"
                $ttValidLic.SetToolTip($btnValidLic, "Validate License Key")
                $mainform.text = "Windows Firewall Analyzer $global:FWMVersion (UNLICENSED)"
                $tbAppLog.AppendText("License is expired.`r`n")
                $tbLicenseStatus.Text = "License Expired"
                $tbLicenseStatus.BackColor = "Red"
                $tbLicenseStatus.ForeColor = "White"
            }
        }
        else
        {
            $btnValidLic.Text = "Validate License Key"
            $btnValidLic.BackColor = "Orange"
            $btnValidLic.ForeColor = "Black"
            $ttValidLic.SetToolTip($btnValidLic, "Validate License Key")
            $mainform.text = "Windows Firewall Analyzer $global:FWMVersion (UNLICENSED)"
            $tbAppLog.AppendText("NO Valid License Found.`r`n")
            $tbLicenseStatus.Text = "License NOT found"
            $tbLicenseStatus.BackColor = "Red"
            $tbLicenseStatus.ForeColor = "White"
        }

        $btnValidLic.Text = "License Validated"
        $tbLicOne.text = "1234"
        $tbLicTwo.text = "5678"
        $tbLicThree.text = "0123"
    }

# *************************************
# *** END Function Build_LicenseKey ***
# *************************************

# ******************************
# *** Function LogFile_Check ***
# ******************************

    Function LogFile_Check
    {
        if ($global:Debug)
        {
            write-host "Function LogFile_Check"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Checking for Firewall log files...")

        if ( (Test-Path $global:PrevLogFile) -and (Test-Path $global:CurLogFile) )
        {
            $tbAppLog.AppendText("Firewall log files do exist!`r`n")
            $tbLogFileStatus.Text = "Log Files Exist"
            $tbLogFileStatus.BackColor = "Green"
            $tbLogFileStatus.ForeColor = "White"
        }
        else
        {
            if (!(Test-Path $global:PrevLogFile) -and !(Test-Path $global:CurLogFile) )
            {
                $tbAppLog.AppendText("Firewall log files do not exist!`r`n")
                $tbAppLog.AppendText((get-date).ToString() + ":    Please use the firewall status to enable logging.`r`n")
                $tbLogFileStatus.Text = "Log files do not exist"
                $tbLogFileStatus.BackColor = "Orange"
                $tbLogFileStatus.ForeColor = "White"
                $cbPrevFile.enabled = $False
                $cbCurFile.enabled = $False
                $global:PrevFileState = "Unavailable"
                $global:CurFileState = "Unavailable"
                Break
            }
            else
            {
                if (!(Test-Path $global:PrevLogFile))
                {
                    $tbAppLog.AppendText("Previous log file does not exist!`r`n")
                    $tbLogFileStatus.Text = "Previous file missing"
                    $tbLogFileStatus.BackColor = "Orange"
                    $tbLogFileStatus.ForeColor = "White"
                    $cbPrevFile.enabled = $False
                    $global:PrevFileState = "Unavailable"
                }
                else
                {
                    $tbAppLog.AppendText("Current log file does not exist!`r`n")
                    $tbLogFileStatus.Text = "Current file missing"
                    $tbLogFileStatus.BackColor = "Orange"
                    $tbLogFileStatus.ForeColor = "White"
                    $cbCurFile.enabled = $False
                    $global:CurFileState = "Unavailable"
                }
            }
        }
    }

# *************************************
# *** END of Function LogFile_Check ***
# *************************************

# *********************************
# *** Function Disable_Controls ***
# *********************************

    Function Disable_Controls
    {
        if ($global:Debug)
        {
            write-host "Function Disable_Controls"
        }

        #$mainform.Refresh()
        # Limits functionality if valid license is not found.
        if ($btnValidLic.Text -eq "License Validated" -and $tbLicOne.text.Length -eq 4 -and $tbLicTwo.text.Length -eq 4 -and $tbLicThree.text.Length -eq 4)
        {
            if ($global:Initialize)
            {
                $cbPrevFile.checked = $False
                $cbCurFile.checked = $True
            }
        }
        else
        {
            $cbPrevFile.checked = $False
            $tbLastLines.text = "25"
        }
    
        # Search Section
        $lstbxDir.enabled = $False
        $lstbxProto.enabled = $False
        $lstbxAction.enabled = $False
        $lstbxSrcIP.enabled = $False
        $lstbxDstIP.enabled = $False
        $lstbxDstPort.enabled = $False
        $btnClearDstPrt.Enabled = $False
        $btnClearDstIP.Enabled = $False
        $btnClearSrcIP.Enabled = $False
        $btnClearAction.Enabled = $False
        $btnClearProto.Enabled = $False

        # Firewall Status
        $btnDomState.enabled = $False
        $btnPrivState.enabled = $False
        $btnPubState.enabled = $False
        $btnDLogAllow.enabled = $False
        $btnPrLogAllow.enabled = $False
        $btnPuLogAllow.enabled = $False
        $btnDLogDrop.enabled = $False
        $btnPrLogDrop.enabled = $False
        $btnPuLogDrop.enabled = $False
        $btnDLogIgnore.enabled = $False
        $btnPrLogIgnore.enabled = $False
        $btnPuLogIgnore.enabled = $False
        $btnDDefInb.enabled = $False
        $btnPrDefInb.enabled = $False
        $btnPuDefInb.enabled = $False
        $btnDDefOutb.enabled = $False
        $btnPrDefOutb.enabled = $False
        $btnPuDefOutb.enabled = $False

        # Log Area
        $FWLog.Enabled = $False

        # Options Section
        $cbIPv6.Enabled = $False
        $cbPrevFile.Enabled = $False
        $cbCurFile.Enabled = $False
        $tbLastLines.Enabled = $False
        $tbLogSize.enabled = $False
        $btnClearSearch.enabled = $False
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $gbSystem.Enabled = $False
        $rbLocal.Enabled = $False
        $rbRemote.Enabled = $False

        # Investigate Tab
        #$lstbxHRiskSrc.Enabled = $False
        #$tbStep2LogSearch.Enabled = $False
        #$tbStep3NetLoc.Enabled = $False
        #$tbStep4DNS.Enabled = $False
        #$lstbxInvestS5.Enabled = $False
        #$tbHRThreatDesc.Enabled = $False
        #$tbHRInvResult.Enabled = $False
        #$tbStep6TraceRt.Enabled = $False

        # License Tab
        $btnValidLic.Enabled = $False

        #$lstbxDstPortInv.enabled = $False

        $mainform.Refresh()
    }

# *************************************
# *** END Function Disable_Controls ***
# *************************************

# ****************************
# *** Function Get_FW_Logs ***
# ****************************

    Function Get_FW_Logs()
    {
        if ($global:Debug)
        {
            write-host "Function Get_FW_Logs"
        }

        $IPv4PrevEvents = 0
        $IPv6PrevEvents = 0
        $EventsImported = 0
        $TempEventsImported = 0
        $LogInfo = @()
        $CurLogInfo = @()

        $tbAppLog.AppendText((get-date).ToString() + ": Importing log files...`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": ******************* Network Information *******************`r`n")
        $IPAddrCount = $global:IPInfo.count
        if ($global:IPInfo.count -gt 1)
        {
            for ($i=0;$i -lt $IPAddrCount; $i++)
            {
                $IPAddr = $global:IPInfo[$i].IP_Address
                $tbAppStats.AppendText((get-date).ToString() + ": Local IP Address: $IPAddr`r`n")
            }
        }
        else
        {
            $IPAddr = $global:IPInfo.IP_Address
            $tbAppStats.AppendText((get-date).ToString() + ": Local IP Address: $IPAddr`r`n")
        }
        $tbAppStats.AppendText((get-date).ToString() + ": ****************** Current Log Statistics ******************`r`n")
        $mainform.refresh()

        if ($cbPrevFile.checked -eq $True -and (Test-Path $global:PrevLogFile))
        {
            if (Test-Path -Path $global:PrevLogFile)
            {
                if ($btnValidLic.Text -eq "License Validated")
                {
                    $timer = [System.Diagnostics.Stopwatch]::StartNew()
                    $tbAppLog.AppendText((get-date).ToString() + ":   Importing previous firewall log...")
                    $PrevLogInfo = @()
                    $PrevLogInfo += import-csv $global:PrevLogFile -Header date,time,action,protocol,src--ip-address,dst--ip-address,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path -Delimiter " "
                    $TotalPrevEvents = $PrevLogInfo.count
                    if ($cbIPv6.Checked)
                    {
                        #$PrevLogInfo = $PrevLogInfo | Select * | where {$_.date -notlike "#*" -and $_.date -notlike " *"}
                        $PrevLogInfo = $PrevLogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *"} | Select *
                    }
                    else
                    {
                        #$PrevLogInfo = $PrevLogInfo | Select * | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"}
                        $PrevLogInfo = $PrevLogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"} | Select *
                    }
                    $IPv4PrevEvents = $PrevLogInfo.Count
                    $IPv6PrevEvents = $TotalPrevEvents - $IPv4PrevEvents
                    $global:LastWriteTime = (Get-item $PrevLogFile).LastWriteTime
                    $timer.Stop()
                    $LoadTime = $timer.Elapsed
                    $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
                    $tbAppLog.AppendText("Completed. ($IPv4PrevEvents events imported in $ElapsedTime seconds)`r`n")
                    $mainform.refresh()
                }
            }
        }
        else
        {
            $PrevLogInfo = @()
        }

        if ($cbCurFile.checked -eq $True -and (Test-Path $global:CurLogFile))
        {
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            $tbAppLog.AppendText((get-date).ToString() + ":   Importing current firewall log...")
            $mainform.refresh()
            $LogInfo += import-csv $global:CurLogFile -Header date,time,action,protocol,src--ip-address,dst--ip-address,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path -Delimiter " "

            if ($btnValidLic.Text -eq "License Validated")
            {
                if ($tbLastLines.Text -eq "0")
                {
                    $TotalCurEvents = $LogInfo.Count
                    if ($cbIPv6.Checked)
                    {
                        #$LogInfo = $LogInfo | Select * | where {$_.date -notlike "#*" -and $_.date -notlike " *"}
                        $LogInfo = $LogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *"} | Select *
                    }
                    else
                    {
                        #$LogInfo = $LogInfo | Select * | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"}
                        $LogInfo = $LogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"} | Select *
                    }
                    $IPv4CurEvents = $LogInfo.Count
                }
                else
                {
                    $LLNum = [Int]($tbLastLines.Text)
                    $PrevLogInfo = @()
                    if ($cbIPv6.Checked)
                    {
                        #$LogInfo = $LogInfo | Select * -Last $LLNum | where {$_.date -notlike "#*" -and $_.date -notlike " *"}
                        $LogInfo = $LogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *"} | Select * -Last $LLNum
                    }
                    else
                    {
                        #$LogInfo = $LogInfo | Select * -Last $LLNum | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"}
                        $LogInfo = $LogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"} | Select * -Last $LLNum
                    }
                    $TotalCurEvents = $LogInfo.Count
                    $IPv4CurEvents = $LogInfo.Count
                }
            }
            else
            {
                $TotalCurEvents = $LogInfo.Count
                #$LogInfo = $LogInfo | Select * -Last 25 | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"}
                $LogInfo = $LogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"} | Select * -Last 25
                $IPv4CurEvents = $LogInfo.Count
            }

            $timer.Stop()
            $LoadTime = $timer.Elapsed
            $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        }

        $LogInfo = $PrevLogInfo + $LogInfo
        $TotalImportedEvents = $IPv4CurEvents + $IPv4PrevEvents
        $IPv6CurEvents = $TotalCurEvents - $IPv4CurEvents
        $TotalIPv6Events = $IPv6CurEvents + $IPv6PrevEvents
        $tbAppLog.AppendText("Completed. ($IPv4CurEvents events imported in $ElapsedTime seconds)`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Previous Dropped IPv6 Log Events => $IPv6PrevEvents`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Previous Log Events => $IPv4PrevEvents`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Current Dropped IPv6 Log Events => $IPv6CurEvents`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Current Log Events => $IPv4CurEvents`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Total Dropped IPv6 Events => $TotalIPv6Events`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Total Log Events => $TotalImportedEvents`r`n")
        $tbAppLog.AppendText((get-date).ToString() + ": Getting File Info...Completed.`r`n")
        $mainform.refresh()
        $BegDate = $LogInfo[4].'date'
        $BegTime = $LogInfo[4].'time'
        $EndDate = $LogInfo[$TempEventsImported-1].'date'
        $EndTime = $LogInfo[$TempEventsImported-1].'time'
        $tbAppLog.AppendText((get-date).ToString() + ": Log data from $BegDate to $EndDate.`r`n")

        if ([datetime]$EndDate -ne (get-date).date)
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Logging appears to be stopped. LOGGING IS FAILED!`r`n")
            $LogTab.backcolor = "red"
            $lbLog.ForeColor = "white"
            $global:LoggingFailed = $True
            $tbLoggingStatus.Text = "Logging is disabled"
            $tbLoggingStatus.BackColor = "Red"
            $tbLoggingStatus.ForeColor = "White"
        }
        else
        {
            $tbLoggingStatus.Text = "Logging is enabled"
            $tbLoggingStatus.BackColor = "Green"
            $tbLoggingStatus.ForeColor = "White"
        }

        $tbAppStats.AppendText((get-date).ToString() + ": Log Beginning Date & Time => $BegDate $BegTime`r`n")
        $tbAppStats.AppendText((get-date).ToString() + ": Log Ending Date & Time => $EndDate $EndTime`r`n")
        $mainform.Refresh()
        return $LogInfo
    }

# ***********************************
# *** End of Function Get_FW_Logs ***
# ***********************************

# ****************************
# *** Function Admin_Check ***
# ****************************

    Function Admin_Check
    {
        if ($global:Debug)
        {
            write-host "Function Admin_Check"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Checking current user permissions...")
        If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            $tbAppLog.AppendText("Administrator rights are required to run this program!`r`n")
            $tbAppLog.AppendText((get-date).ToString() + ":    Please re-run this program as an Administrator!`r`n")
            $tbAdminStatus.Text = "No Admin Rights"
            $tbAdminStatus.BackColor = "Red"
            $tbAdminStatus.ForeColor = "White"
            return $False
            Break
        }

        $tbAppLog.AppendText("Administrator Privileges Verified.`r`n")
        $tbAdminStatus.Text = "Admin Rights Verified"
        $tbAdminStatus.BackColor = "Green"
        $tbAdminStatus.ForeColor = "White"

        Return $True
    }

# ***********************************
# *** End of Function Admin_Check ***
# ***********************************

# *********************************
# *** Function Port_Scan_Detect ***
# *********************************

    Function Port_Scan_Detect
    {
        if ($global:Debug)
        {
            write-host "Function Port_Scan_Detect"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Checking for port scan evidence in the logs...`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()

        $Temp = @()
        $PortScanData = @()
        $TcpFlagsData = @()
        $Prev_Port = 0
        $LoopCount = 0
        $ScanDetected = 0
        $CurIP = "254.254.254.254"
        $global:HRiskIssues = @()
        #$Temp = $global:FWLogInfo | Select * | where { $global:IPInfo.IP_Address -contains $_.'dst--ip-address' -and $_.'dst-port' -ne '-' } | Sort { $_.'src--ip-address',[int]$_.'dst-port'}

        $Temp = $global:FWLogInfo | where { $global:IPInfo.IP_Address -contains $_.'dst--ip-address' -and $_.'dst-port' -ne '-' } | Sort { $_.'src--ip-address',[int]$_.'dst-port'} | Select *

        $PortScanData = $Temp | Group-Object -Property 'src--ip-address','dst-port' | Select Name, Count

        foreach($line in $PortScanData)
        {
            $test = $line.name.split(', ')
        
            $LoopCount++

            foreach ($elmnt in $test)
            {
                if ($elmnt.length -gt 5)
                {
                    if ($elmnt -ne $CurIP -or $PortScanData.count -eq $LoopCount )
                    {
                        $IPType ="Local"
                        $SplitIP = $CurIP.Split('.')
                        if ([int]$SplitIP[0] -ne 10 -and $CurIP -ne '127.0.0.1' -and [int]$SplitIP[0] -ne 224 -and [int]$SplitIP[0] -ne 169)
                        {
                            if ([int]$SplitIP[0] -eq 192 -or [int]$SplitIP[0] -eq 172)
                            {
                                If ([int]$SplitIP[0] -eq 192 -and [int]$SplitIP[1] -ne 168)
                                {
                                    $IPType = "Internet"
                                }
                                else
                                {
                                    If ([int]$SplitIP[0] -eq 172 -and ([int]$SplitIP[1] -lt 12 -and [int]$SplitIP[1] -gt 31))
                                    {
                                        $IPType = "Internet"
                                    }
                                }
                            }
                            else
                            {
                                $IPType = "Internet"
                            }
                        }
                        else
                        {
                            if ([int]$SplitIP[0] -eq 169 -and [int]$SplitIP[1] -ne 254)
                            {
                                $IPType = "Internet"
                            }
                        }

                        if ($ScanType.Length -ne 0 -and $PortScanDetected -ge 6)
                        {
                            $tbAppLog.AppendText((get-date).ToString() + ":   EVASIVE Port scan DETECTED from IP Address $CurIP!`r`n")
                            $LogTab.backcolor = "red"
                            $lbLog.ForeColor = "white"
                            #$btnHRiskWz.BackColor = "red"
                            #$btnHRiskWz.ForeColor = "white"
                            $lbStats.ForeColor = "white"
                            $TempVar = [ordered]@{
                                        Detected_IP = $CurIP
                                        Detected_Offense = "$IPType Evasive Port Scan"
                                        IPType = "Source"
                            }
                            $PSObject = new-object -TypeName PSObject -Property $TempVar
                            $global:HRiskIssues += @($PSObject)
                            $ScanDetected++
                        }

                        if ($ScanType.Length -eq 0 -and $PortScanDetected -ge 6)
                        {
                            $tbAppLog.AppendText((get-date).ToString() + ":   Port scan DETECTED from IP Address $CurIP!`r`n")
                            if ($LogTab.backcolor -ne "red")
                            {
                                $LogTab.backcolor = "red"
                                $lbLog.ForeColor = "white"
                                #$btnHRiskWz.BackColor = "red"
                                #$btnHRiskWz.ForeColor = "white"
                                $lbStats.ForeColor = "white"
                                $TempVar = [ordered]@{
                                            Detected_IP = $CurIP
                                            Detected_Offense = "$IPType Port Scan"
                                            IPType = "Source"
                                }
                                $PSObject = new-object -TypeName PSObject -Property $TempVar
                                $global:HRiskIssues += @($PSObject)
                                $ScanDetected++
                            }
                        }

                        if ($ScanType.Length -ne 0 -and $PortScanDetected -lt 6)
                        {
                            $tbAppLog.AppendText((get-date).ToString() + ":   Possible Evasive port scan DETECTED from IP Address $CurIP!`r`n")
                            if ($LogTab.backcolor -ne "red")
                            {
                                $LogTab.backcolor = "Orange"
                                $lbLog.ForeColor = "Black"
                                #$btnMRiskWz.BackColor = "orange"
                                #$btnMRiskWz.ForeColor = "black"
                                $lbStats.ForeColor = "Black"
                                $TempVar = [ordered]@{
                                            Detected_IP = $CurIP
                                            Detected_Offense = "Possible $IPType Evasive Port Scan"
                                            IPType = "Source"
                                }
                                $PSObject = new-object -TypeName PSObject -Property $TempVar
                                $global:MRiskIssues += @($PSObject)
                                $ScanDetected++
                            }
                        }

                        $TcpFlagsData = @()
                        $CurIP = $elmnt
                        $PortScanDetected = 0
                        $ScanType = ""
                        $TcpFlagsData = $global:FWLogInfo | where { $_.'tcpflags' -ne '-' -and $_.'src--ip-address' -eq $CurIP } | Group-Object -Property 'tcpflags' | Select Name, Count

                        if ($TcpFlagsData.Count -gt 0)
                        {
                            Switch ($TcpFlagsData.Name)
                            {
                                "ACK" {$ScanType = "ACK"}
                                "A" {$ScanType = "ACK"}
                                "S" {$ScanType = "SYN"}
                                "SYN" {$ScanType = "SYN"}
                                "F" {$ScanType = "FIN"}
                                "FIN" {$ScanType = "FIN"}
                                "U" {$ScanType = "URG"}
                                "URG" {$ScanType = "URG"}
                                "R" {$ScanType = "RST"}
                                "RST" {$ScanType = "RST"}
                                "P" {$ScanType = "PSH"}
                                "PSH" {$ScanType = "PSH"}
                            }
                        }
                    }
                }

                if ($elmnt.length -lt 6 -and $elmnt.length -gt 0)
                {
                    if ([int]$elmnt - $Prev_Port -eq 1)
                    {
                        $PortScanDetected += 1
                    }
                    $Prev_Port = [int]$elmnt
                }
            }
        }

        if ($ScanDetected -eq 0 -and $global:LoggingFailed -eq $False)
        {
            $tbAppLog.AppendText((get-date).ToString() + ":   No port scans detected.`r`n")
            $LogTab.backcolor = "gray"
            $lbLog.ForeColor = "white"
            $lbStats.ForeColor = "white"
        }

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText((get-date).ToString() + ": Checking for port scan evidence in the logs...Completed ($ElapsedTime seconds).`r`n")
    }

# ****************************************
# *** END of Function Port_Scan_Detect ***
# ****************************************

# *****************************
# *** Function IP_Rep_Check ***
# *****************************

    Function IP_Rep_Check
    {
        param ( $IPAddress )

        if ($global:Debug)
        {
            write-host "Function IP_Rep_Check($IPAddress)"
        }

        $WebResult = Invoke-WebRequest -Uri "https://www.abuseipdb.com/check/$IPAddress"

        $URLData = @()
        $URLData = @($WebResult.ParsedHtml.IHTMLDocument3_getElementsByTagName("p"))

        $TestData = $URLData

        #$TestData.TextContent

        foreach ($line in $TestData.InnerHTML)
        {
            if ($line -like "*not been reported*")
            {
                $RawData = $TestData.InnerHTML[2].split('<').split('>')
                #$tbStep7IPRep.Text = $RawData[2]
                $Reputation = $RawData[2]
            }

            if ($line -like "*has been reported*")
            {
                $RawData = $TestData.InnerHTML[3].split('<').split('>')
                #$tbStep7IPRep.Text = $RawData[0]+$RawData[2]+$RawData[4]+$RawData[6]+$RawData[8]+$RawData[12]
                $Reputation = $RawData[0]+$RawData[2]+$RawData[4]+$RawData[6]+$RawData[8]+$RawData[12]
            }
        }
        return $Reputation
    }

# ************************************
# *** END of Function IP_Rep_Check ***
# ************************************

# ***************************
# *** Function SearchJobs ***
# ***************************

    Function SearchJobs()
    {
        if ($global:Debug)
        {
            write-host "Function SearchJobs"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Compiling Search Criteria")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $completed = @()

        $DSTJob = {
            param($FWLogInfo1)
            @($FWLogInfo1 | Select * | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count)
            }

        $PROTJob = {
            param($FWLogInfo1)
            @($FWLogInfo1 | Select * | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count)
            }

        $ACTJob = {
            param($FWLogInfo1)
            @($FWLogInfo1 | Select * | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count)
            }

        $SRCIPJob = {
            param($FWLogInfo1)
            @($FWLogInfo1 | Select * | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count)
            }

        $DSTIPJob = {
            param($FWLogInfo1)
            @($FWLogInfo1 | Select * | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count)
            }

    <#    $PATHJob = {
            param($FWLogInfo1)
            #Write-Output "Path"
            @($FWLogInfo1 | Select * | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count)
            } #>

        #$pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS+1)
        $pool = [RunspaceFactory]::CreateRunspacePool(1, 12)
        $pool.ApartmentState = "MTA"
        $pool.Open()
        $runspaces = @()

        $runspace = [PowerShell]::Create()
        $null = $runspace.AddScript($DSTJob)
        $null = $runspace.AddArgument($global:Live_Search)
        $runspace.RunspacePool = $pool
        $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); Name = "DestPort" }

        $runspace = [PowerShell]::Create()
        $null = $runspace.AddScript($DSTIPJob)
        $null = $runspace.AddArgument($global:Live_Search)
        $runspace.RunspacePool = $pool
        $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); Name = "DestIP" }

        $runspace = [PowerShell]::Create()
        $null = $runspace.AddScript($SRCIPJob)
        $null = $runspace.AddArgument($global:Live_Search)
        $runspace.RunspacePool = $pool
        $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); Name = "SrcIP" }

        $runspace = [PowerShell]::Create()
        $null = $runspace.AddScript($PROTJob)
        $null = $runspace.AddArgument($global:Live_Search)
        $runspace.RunspacePool = $pool
        $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); Name = "Proto" }

        $runspace = [PowerShell]::Create()
        $null = $runspace.AddScript($ACTJob)
        $null = $runspace.AddArgument($global:Live_Search)
        $runspace.RunspacePool = $pool
        $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); Name = "Action" }

    <#    $runspace = [PowerShell]::Create()
        $null = $runspace.AddScript($PATHJob)
        $null = $runspace.AddArgument($global:Live_Search)
        $runspace.RunspacePool = $pool
        $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke(); Name = "Direction" }
    #>
        while (@($completed).count -lt 5)
        {
            $tbAppLog.AppendText("-")
            $completed = $runspaces | Where-Object { $_.Status.IsCompleted -eq $true }
            $mainform.refresh()
            start-sleep -Milliseconds 100
        }

        $jobCount = 1
        foreach ($runspace in $completed)
        {
            switch ($runspace.Name)
            {
                "DestPort" {
                    $Job1 = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                    $global:Dest_Port = @($Job1 | Select * | where {$_.Name -match "^\d+$" -or $_.Name -eq "-" })
                    $mainform.refresh()
                    }
                "DestIP" {
                    $Job2 = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                    if ($cbIPv6.Checked)
                    {
                        $global:Dest_IP = @($Job2 | Select *)
                    }
                    else
                    {
                        $global:Dest_IP = @($Job2 | Select * | where {$_.Name -like "*.*.*.*"})
                    }
                    $mainform.refresh()
                    }
                "SrcIP" {
                    $Job3 = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                    if ($cbIPv6.Checked)
                    {
                        $global:Source_IP = @($Job3 | Select *)
                    }
                    else
                    {
                        $global:Source_IP = @($Job3 | Select * | where {$_.Name -like "*.*.*.*"})
                    }
                    $mainform.refresh()
                    }
                "Proto" {
                    $Job4 = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                    $global:Protocol = @($Job4 | Select * | where {$_.Count -gt 0})
                    $mainform.refresh()
                    }
                "Action" {
                    $Job5 = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                    $global:Action = @($Job5 | Select * | where {$_.Name -eq "DROP" -or $_.Name -eq "ALLOW" -or $_.Name -eq "INFO-EVENTS-LOST"})
                    $mainform.refresh()
                    }
    <#            "Direction" {
                    $Job6 = $runspace.Pipe.EndInvoke($runspace.Status)
                    $runspace.Status = $null
                    $global:Direction = @($Job6 | Select * | where {$_.Name -eq "SEND" -or $_.Name -eq "RECEIVE"})
                    $mainform.refresh()
                    } #>
            }
            $jobCount = $jobCount + 1
        }

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $mainform.refresh()

        $runspaces.clear()
        $pool.Close()
        $pool.Dispose()
        $Job1 = $null
        $Job2 = $null
        $Job3 = $null
        $Job4 = $null
        $Job5 = $null
        $Job6 = $null
    }

# **********************************
# *** End of Function SearchJobs ***
# **********************************

# *****************************
# *** Function Internet_IPs ***
# *****************************

    Function Internet_IPs
    {
        Param([string]$IPType)

        if ($global:Debug)
        {
            write-host "Function Internet_IPs($IPType)"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Searching for $IPType Internet IPs...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()

        $global:HRiskIssues = @()
        $global:MRiskIssues = @()

        if ($IPType -eq "Source")
        {
            $Temp_IPs = $global:FWLogInfo | Select * | Group-Object -Property 'src--ip-address' | Sort Name -Descending | Select Name
            $Offense = "Internet Source IP"
        }
        else
        {
            $Temp_IPs = $global:FWLogInfo | where { $_.'dst-port' -eq "21" -or $_.'dst-port' -eq "22" -or $_.'dst-port' -eq "23" -or $_.'dst-port' -eq "3389" } | Select * | Group-Object -Property 'dst--ip-address' | Sort Name -Descending| Select Name
            $Offense = "Internet Destination IP"
        }

        foreach($line in $Temp_IPs)
        {
            $IP_Location = ""
            $SplitIP = $line.Name.split('.')
            if ($global:IPInfo.IP_Address -notcontains $line.Name)
            {
                if ([int]$SplitIP[0] -ne 10 -and $line.Name -ne '127.0.0.1' -and [int]$SplitIP[0] -lt 224 -and [int]$SplitIP[0] -ne 169 )
                {
                    if ([int]$SplitIP[0] -eq 192 -or [int]$SplitIP[0] -eq 172)
                    {
                        If ([int]$SplitIP[0] -eq 192 -and [int]$SplitIP[1] -ne 168)
                        {
                            $IP_Location = $line.Name
                        }
                        else
                        {
                            If ([int]$SplitIP[0] -eq 172 -and ([int]$SplitIP[1] -lt 12 -and [int]$SplitIP[1] -gt 31))
                            {
                                $IP_Location = $line.Name
                            }
                        }
                    }
                    else
                    {
                        $IP_Location = $line.Name
                    }
                }
                else
                {
                    if ([int]$SplitIP[0] -eq 169 -and [int]$SplitIP[1] -ne 254 )
                    {
                        $IP_Location = $line.Name
                    }
                }
            }

            if ($IPType -eq "Source")
            {
                $Temp_NBA = $global:FWLogInfo | Where { $_.'src--ip-address' -eq $IP_Location } | Select * | Group-Object -Property 'src--ip-address','src-port' | Select Name, Count
            }

            $PSObject = @()
            if ($IP_Location.length -gt 0)
            {
                $TempVar = [ordered]@{
                            Detected_IP = $IP_Location
                            Detected_Offense = $Offense
                }
                $PSObject = new-object -TypeName PSObject -Property $TempVar

                if ($IPType -eq "Source")
                {
                    $global:HRiskIssues += @($PSObject)                    
                }
                else
                {
                    $global:MRiskIssues += @($PSObject)
                }
            }
        }

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed ($ElapsedTime seconds).`r`n")

        return $Temp_IPs
    }

# ************************************
# *** END of Function Internet_IPs ***
# ************************************

# ******************************
# *** Function LowRisk_Check ***
# ******************************

    Function LowRisk_Check
    {
        if ($global:Debug)
        {
            write-host "Function LowRisk_Check"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Low Risk Issues...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()

        $global:LRiskIssues = @()

        $LowRisk = $global:FWLogInfo | where { $_.'dst-port' -eq "21" -or $_.'dst-port' -eq "22" -or $_.'dst-port' -eq "23" -or $_.'dst-port' -eq "3389" -or $_.'dst-port' -eq "1900" -or $_.'dst-port' -eq "5353" -or $_.'dst-port' -eq "5355" }| Select * | Group-Object -Property 'src--ip-address','dst-port' | Sort Name -Descending | Select Name
        $Offense = "Risky Network Traffic"

        foreach($line in $LowRisk)
        {
            $PSObject = @()
            $TempVar = [ordered]@{
                        Detected_IP = $line.Name
                        Detected_Offense = $Offense
            }
            $PSObject = new-object -TypeName PSObject -Property $TempVar

            $global:LRiskIssues += @($PSObject)
        }

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed ($ElapsedTime seconds).`r`n")
    }

# *************************************
# *** END of Function LowRisk_Check ***
# *************************************

# ********************************
# *** Function Update_Controls ***
# ********************************

    Function Update_Controls()
    {
        param($LogInfo)

        if ($global:Debug)
        {
            write-host "Function Update_Controls($LogInfo)"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Updating data...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $array = New-Object System.Collections.ArrayList($null)

        If($FWLog.columncount -gt 0){
            #Remove-Columns
            $FWLog.DataSource = $null
        }

        #$global:GridInfo = $null

        $global:GridInfo = $LogInfo
        $array.AddRange($GridInfo)

        $FWLog.DataSource = $array

        $mainform.refresh()
        start-sleep -milliseconds 100

        $lstbxDstPort.Items.Clear()
        foreach($line in $global:Dest_port)
        {
            $lstbxDstPort_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxDstPort_Item.SubItems.Add($Line.Count) | Out-Null
            $lstbxDstPort.Items.AddRange(($lstbxDstPort_Item))
        }
   
        $lstbxDstIP.Items.Clear()
        foreach($line in $global:Dest_IP)
        {
            $lstbxDstIP_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxDstIP_Item.SubItems.Add($Line.Count) | Out-Null
            $lstbxDstIP.Items.AddRange(($lstbxDstIP_Item))
        }

        $mainform.refresh()
        start-sleep -milliseconds 100

        $lstbxSrcIP.Items.Clear()
        foreach($line in $global:Source_IP)
        {
            $lstbxSrcIP_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxSrcIP_Item.SubItems.Add($Line.Count) | Out-Null
            $lstbxSrcIP.Items.AddRange(($lstbxSrcIP_Item))
        }

        $mainform.refresh()
        start-sleep -milliseconds 100

        $lstbxAction.Items.Clear()
        foreach($line in $global:Action)
        {
            $lstbxAction_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxAction_Item.SubItems.Add($Line.Count) | Out-Null
            $lstbxAction.Items.AddRange(($lstbxAction_Item))
        }

        $lstbxProto.Items.Clear()
        foreach($line in $global:Protocol)
        {
            $lstbxProto_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxProto_Item.SubItems.Add($Line.Count) | Out-Null
            $lstbxProto.Items.AddRange(($lstbxProto_Item))
        }

    <#    $lstbxDir.Items.Clear()
        foreach($line in $global:Direction)
        {
            $lstbxDir_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxDir_Item.SubItems.Add($Line.Count) | Out-Null
            $lstbxDir.Items.AddRange(($lstbxDir_Item))
        } #>

        $lstbxNetAdapt.Items.Clear()
        foreach($Line in $global:IPInfo)
        {
            $lstbxNetAdapt_Item = New-Object System.Windows.Forms.ListViewItem($Line.Name)
            $lstbxNetAdapt_Item.SubItems.Add($Line.Status) | Out-Null
            $lstbxNetAdapt_Item.SubItems.Add($Line.Index) | Out-Null
            $lstbxNetAdapt_Item.SubItems.Add($Line.IP_Address) | Out-Null
            $lstbxNetAdapt.Items.AddRange(($lstbxNetAdapt_Item))
        }

        $lstbxDstPort.AutoResizeColumns(1)
        #$lstbxDstPortInv.AutoResizeColumns(1)
        $lstbxDstIP.AutoResizeColumns(1)
        $lstbxSrcIP.AutoResizeColumns(1)
        $lstbxAction.AutoResizeColumns(1)
        $lstbxProto.AutoResizeColumns(1)
        $lstbxDir.AutoResizeColumns(1)
        $lstbxNetAdapt.AutoResizeColumns(1)

        $FWLog.Columns | Foreach-Object{
            $_.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
            }

        #write-host $global:HRiskIssues
        if ($global:HRiskIssues.Count -eq 0)
        {
            $rbHRisk.Enabled = $False
            $tbHighStatus.Text = "0 H"
            $tbHighStatus.ForeColor = "White"
            $tbHighStatus.BackColor = "Green"
        }
        else
        {
            $rbHRisk.Enabled = $True
            $tbHighStatus.Text = [string]$global:HRiskIssues.Count + " H"
            $tbHighStatus.ForeColor = "White"
            $tbHighStatus.BackColor = "Red"
        }

        #write-host $global:MRiskIssues
        if ($global:MRiskIssues.Count -eq 0)
        {
            $rbMRisk.Enabled = $False
            $tbMedStatus.Text = "0 M"
            $tbMedStatus.ForeColor = "White"
            $tbMedStatus.BackColor = "Green"
        }
        else
        {
            $rbMRisk.Enabled = $True
            $tbMedStatus.Text = [string]$global:MRiskIssues.Count + " M"
            $tbMedStatus.ForeColor = "White"
            $tbMedStatus.BackColor = "Orange"
        }

        #write-host $global:LRiskIssues
        if ($global:LRiskIssues.Count -eq 0)
        {
            $rbLRisk.Enabled = $False
            $tbLowStatus.Text = "0 L"
            $tbLowStatus.ForeColor = "White"
            $tbLowStatus.BackColor = "Green"
        }
        else
        {
            $rbLRisk.Enabled = $True
            $tbLowStatus.Text = [string]$global:LRiskIssues.Count + " L"
            $tbLowStatus.ForeColor = "Black"
            $tbLowStatus.BackColor = "Yellow"
        }

        $InvestigateTab.Text = "Investigate (" + [string]$global:HRiskIssues.Count + " High Issues, " + [string]$global:MRiskIssues.Count + " Medium Issues, & " + [string]$global:LRiskIssues.Count + " Low Issues)"

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")

        $mainform.refresh()
    }      

# ***************************************
# *** END of Function Update_Controls ***
# ***************************************

# ********************************
# *** Function Enable_Controls ***
# ********************************

    Function Enable_Controls
    {
        if ($global:Debug)
        {
            write-host "Function Enable_Controls"
        }

        $mainform.Refresh()
        #$tbAppStats
        #$tbAppLog
        $tbDirSelected.enabled = $True
        $tbProtoSelected.enabled = $True
        $tbActionSelected.enabled = $True
        $tbSrcIPSelected.enabled = $True
        $tbDstIPSelected.enabled = $True
        $tbDstPrtSelected.enabled = $True
        $lstbxDir.enabled = $True
        $lstbxProto.enabled = $True
        $lstbxAction.enabled = $True
        $lstbxSrcIP.enabled = $True
        $lstbxDstIP.enabled = $True
        $lstbxDstPort.enabled = $True
        $btnValidLic.Enabled = $True
        $gbSystem.Enabled = $True
        $rbLocal.Enabled = $True
        $rbRemote.Enabled = $True
        Update_ToolTips
        if ($tabControl.SelectedTab.Name -eq "Network Configuration" -or $tabControl.SelectedTab.Name -eq "NetConfig")
        {
            $lstbxNetAdapt.Items[0].Selected = $True
            $lstbxNetAdapt.Items[0].Focused = $True
            $lstbxNetAdapt.HideSelection = $False
        }
    
        Update_NetConfig

        if ($tbDstPrtSelected.Text -eq "")
        {
            $btnClearDstPrt.Enabled = $False
        }
        else
        {
            $btnClearDstPrt.Enabled = $True
        }

        if ($tbDstIPSelected.Text -eq "")
        {
            $btnClearDstIP.Enabled = $False
        }
        else
        {
            $btnClearDstIP.Enabled = $True
        }

        if ($tbSrcIPSelected.Text -eq "")
        {
            $btnClearSrcIP.Enabled = $False
        }
        else
        {
            $btnClearSrcIP.Enabled = $True
        }

        if ($tbActionSelected.Text -eq "")
        {
            $btnClearAction.Enabled = $False
        }
        else
        {
            $btnClearAction.Enabled = $True
        }

        if ($tbProtoSelected.Text -eq "")
        {
            $btnClearProto.Enabled = $False
        }
        else
        {
            $btnClearProto.Enabled = $True
        }

        if ($btnValidLic.Text -eq "License Validated" -and $tbLicOne.text.Length -eq 4 -and $tbLicTwo.text.Length -eq 4 -and $tbLicThree.text.Length -eq 4)
        {
            if ($global:Initialize)
            {
                $cbPrevFile.checked = $False
                $cbCurFile.checked = $True
            }
            $cbIPv6.Enabled = $True
            if ($global:PrevFileState -eq "Available")
            {
                $cbPrevFile.Enabled = $True
            }
            if ($global:CurFileState -eq "Available")
            {
                $cbCurFile.Enabled = $True
            }
            $btnClearSearch.enabled = $True
            $btnDefOutbAll.enabled = $True
            $btnDefInbAll.enabled = $True
            $btnProfAll.enabled = $True
            $btnLogIgnoredAll.enabled = $True
            $btnLogAllowAll.enabled = $True
            $btnLogDropAll.enabled = $True
            $btnAllTrafTo.Enabled = $True
            $btnAllTrafFrom.Enabled = $True
            $btnDomState.enabled = $True
            $btnPrivState.enabled = $True
            $btnPubState.enabled = $True
            $btnDLogAllow.enabled = $True
            $btnPrLogAllow.enabled = $True
            $btnPuLogAllow.enabled = $True
            $btnDLogDrop.enabled = $True
            $btnPrLogDrop.enabled = $True
            $btnPuLogDrop.enabled = $True
            $btnDLogIgnore.enabled = $True
            $btnPrLogIgnore.enabled = $True
            $btnPuLogIgnore.enabled = $True
            $btnDDefInb.enabled = $True
            $btnPrDefInb.enabled = $True
            $btnPuDefInb.enabled = $True
            $btnDDefOutb.enabled = $True
            $btnPrDefOutb.enabled = $True
            $btnPuDefOutb.enabled = $True
            $tbLastLines.Enabled = $True
            $tbLogSize.text = @(get-netfirewallprofile -name public | Select LogMaxSizeKilobytes).LogMaxSizeKilobytes
            $tbLogSize.enabled = $True
        }
        else
        {
            $tbLastLines.text = "25"
            if ($global:PrevFileState -eq "Available")
            {
                $cbPrevFile.Enabled = $False
            }
            if ($global:CurFileState -eq "Available")
            {
                $cbCurFile.Enabled = $True
            }
            $tbLogSize.text = @(get-netfirewallprofile -name public | Select LogMaxSizeKilobytes).LogMaxSizeKilobytes
            $btnDomState.BackColor = "DarkGray"
            $btnPrivState.BackColor = "DarkGray"
            $btnPubState.BackColor = "DarkGray"
            $btnDLogAllow.BackColor = "DarkGray"
            $btnPrLogAllow.BackColor = "DarkGray"
            $btnPuLogAllow.BackColor = "DarkGray"
            $btnDLogDrop.BackColor = "DarkGray"
            $btnPrLogDrop.BackColor = "DarkGray"
            $btnPuLogDrop.BackColor = "DarkGray"
            $btnDLogIgnore.BackColor = "DarkGray"
            $btnPrLogIgnore.BackColor = "DarkGray"
            $btnPuLogIgnore.BackColor = "DarkGray"
            $btnDDefInb.BackColor = "DarkGray"
            $btnPrDefInb.BackColor = "DarkGray"
            $btnPuDefInb.BackColor = "DarkGray"
            $btnDDefOutb.BackColor = "DarkGray"
            $btnPrDefOutb.BackColor = "DarkGray"
            $btnPuDefOutb.BackColor = "DarkGray"
            $btnMSClient.BackColor = "DarkGray"
            $btnMSServer.BackColor = "DarkGray"
            $btnQoS.BackColor = "DarkGray"
            $btnIPv4.BackColor = "DarkGray"
            $btnMultiplexor.BackColor = "DarkGray"
            $btnLLDP.BackColor = "DarkGray"
            $btnIPv6.BackColor = "DarkGray"
            $btnLLTD.BackColor = "DarkGray"
            $btnLLTDMapper.BackColor = "DarkGray"
            $lstbxDstPortInv.enabled = $False
        }
        #$mainform.Refresh()
    }

# ***************************************
# *** END of Function Enable_Controls ***
# ***************************************

# ********************************
# *** Function Update_ToolTips ***
# ********************************

    Function Update_ToolTips
    {
        if ($global:Debug)
        {
            write-host "Function Update_ToolTips"
        }

        if ($btnDomState.Text -eq "YES")
        {
            $ttDomState.SetToolTip($btnDomState, "Click to disable Domain Profile.(NOT Recommended)")
        }
        else
        {
            $ttDomState.SetToolTip($btnDomState, "Click to enable Domain Profile.(Recommended)")
        }

        if ($btnPrivState.Text -eq "YES")
        {
            $ttPrivState.SetToolTip($btnPrivState, "Click to disable Private Profile.(NOT Recommended)")
        }
        else
        {
            $ttPrivState.SetToolTip($btnPrivState, "Click to enable Private Profile.(Recommended)")
        }

        if ($btnPubState.Text -eq "YES")
        {
            $ttPubState.SetToolTip($btnPubState, "Click to disable Public Profile.(NOT Recommended)")
        }
        else
        {
            $ttPubState.SetToolTip($btnPubState, "Click to enable Public Profile.(Recommended)")
        }

        if ($btnDomState.text -eq "YES" -and $btnPrivState.text -eq "YES" -and $btnPubState.text -eq "YES")
        {
            $btnProfAll.text = "DISABLE ALL"
            $ttProfAll.SetToolTip($btnProfAll, "Click to disable the Windows Firewall.(NOT Recommended)")
        }
        else
        {
            $btnProfAll.text = "ENABLE ALL"
            $ttProfAll.SetToolTip($btnProfAll, "Click to enable the Windows Firewall.(Recommended)")
        }

        if ($btnDLogAllow.Text -eq "YES")
        {
            $ttDLogAllow.SetToolTip($btnDLogAllow, "Click to NOT log allowed domain traffic.(NOT Recommended)")
        }
        else
        {
            $ttDLogAllow.SetToolTip($btnDLogAllow, "Click to log allowed domain traffic.(Recommended)")
        }

        if ($btnPrLogAllow.Text -eq "YES")
        {
            $ttPrLogAllow.SetToolTip($btnPrLogAllow, "Click to NOT log allowed private traffic.(NOT Recommended)")
        }
        else
        {
            $ttPrLogAllow.SetToolTip($btnPrLogAllow, "Click to log allowed private traffic.(Recommended)")
        }

        if ($btnPuLogAllow.Text -eq "YES")
        {
            $ttPuLogAllow.SetToolTip($btnPuLogAllow, "Click to NOT log allowed public traffic.(NOT Recommended)")
        }
        else
        {
            $ttPuLogAllow.SetToolTip($btnPuLogAllow, "Click to log allowed public traffic.(Recommended)")
        }

        if ($btnDLogAllow.text -eq "YES" -and $btnPrLogAllow.text -eq "YES" -and $btnPuLogAllow.text -eq "YES")
        {
            $btnLogAllowAll.text = "DISABLE ALL"
            $ttLogAllowAll.SetToolTip($btnLogAllowAll, "Click to NOT log any allowed traffic.(NOT Recommended)")
        }
        else
        {
            $btnLogAllowAll.text = "ENABLE ALL"
            $ttLogAllowAll.SetToolTip($btnLogAllowAll, "Click to log all allowed traffic.(Recommended)")
        }

        if ($btnDLogDrop.Text -eq "YES")
        {
            $ttDLogDrop.SetToolTip($btnDLogDrop, "Click to NOT log dropped domain traffic.(NOT Recommended)")
        }
        else
        {
            $ttDLogDrop.SetToolTip($btnDLogDrop, "Click to log dropped domain traffic.(Recommended)")
        }

        if ($btnPrLogDrop.Text -eq "YES")
        {
            $ttPrLogDrop.SetToolTip($btnPrLogDrop, "Click to NOT log dropped private traffic.(NOT Recommended)")
        }
        else
        {
            $ttPrLogDrop.SetToolTip($btnPrLogDrop, "Click to log dropped private traffic.(Recommended)")
        }

        if ($btnPuLogDrop.Text -eq "YES")
        {
            $ttPuLogDrop.SetToolTip($btnPuLogDrop, "Click to NOT log dropped public traffic.(NOT Recommended)")
        }
        else
        {
            $ttPuLogDrop.SetToolTip($btnPuLogDrop, "Click to log dropped public traffic.(Recommended)")
        }

        if ($btnDLogDrop.text -eq "YES" -and $btnPrLogDrop.text -eq "YES" -and $btnPuLogDrop.text -eq "YES")
        {
            $btnLogDropAll.text = "DISABLE ALL"
            $ttLogDropAll.SetToolTip($btnLogDropAll, "Click to NOT log any dropped traffic.(NOT Recommended)")
        }
        else
        {
            $btnLogDropAll.text = "ENABLE ALL"
            $ttLogDropAll.SetToolTip($btnLogDropAll, "Click to log all dropped traffic.(Recommended)")
        }

        if ($btnDLogIgnore.Text -eq "YES")
        {
            $ttDLogIgnore.SetToolTip($btnDLogIgnore, "Click to NOT log Ignored domain traffic.(NOT Recommended)")
        }
        else
        {
            $ttDLogIgnore.SetToolTip($btnDLogIgnore, "Click to log Ignored domain traffic.(Recommended)")
        }

        if ($btnPrLogIgnore.Text -eq "YES")
        {
            $ttPrLogIgnore.SetToolTip($btnPrLogIgnore, "Click to NOT log Ignored private traffic.(NOT Recommended)")
        }
        else
        {
            $ttPrLogIgnore.SetToolTip($btnPrLogIgnore, "Click to log Ignored private traffic.(Recommended)")
        }

        if ($btnPuLogIgnore.Text -eq "YES")
        {
            $ttPuLogIgnore.SetToolTip($btnPuLogIgnore, "Click to NOT log Ignored public traffic.(NOT Recommended)")
        }
        else
        {
            $ttPuLogIgnore.SetToolTip($btnPuLogIgnore, "Click to log Ignored public traffic.(Recommended)")
        }

        if ($btnDLogIgnore.text -eq "YES" -and $btnPrLogIgnore.text -eq "YES" -and $btnPuLogIgnore.text -eq "YES")
        {
            $btnLogIgnoredAll.text = "DISABLE ALL"
            $ttLogIgnoredAll.SetToolTip($btnLogIgnoredAll, "Click to NOT log any Ignored traffic.(NOT Recommended)")
        }
        else
        {
            $btnLogIgnoredAll.text = "ENABLE ALL"
            $ttLogIgnoredAll.SetToolTip($btnLogIgnoredAll, "Click to log all ignored traffic.(Recommended)")
        }

        if ($btnDDefInb.Text -eq "BLK")
        {
            $ttDDefInb.SetToolTip($btnDDefInb, "Click for default action of ALLOW for inbound domain traffic.(NOT Recommended)")
        }
        else
        {
            $ttDDefInb.SetToolTip($btnDDefInb, "Click for default action of BLOCK for inbound domain traffic.(Recommended)")
        }

        if ($btnPrDefInb.Text -eq "BLK")
        {
            $ttPrDefInb.SetToolTip($btnPrDefInb, "Click for default action of ALLOW for inbound private traffic.(NOT Recommended)")
        }
        else
        {
            $ttPrDefInb.SetToolTip($btnPrDefInb, "Click for default action of BLOCK for inbound private traffic.(Recommended)")
        }

        if ($btnPuDefInb.Text -eq "BLK")
        {
            $ttPuDefInb.SetToolTip($btnPuDefInb, "Click for default action of ALLOW for inbound public traffic.(NOT Recommended)")
        }
        else
        {
            $ttPuDefInb.SetToolTip($btnPuDefInb, "Click for default action of BLOCK for inbound public traffic.(Recommended)")
        }

        if ($btnDDefInb.text -eq "BLK" -and $btnPrDefInb.text -eq "BLK" -and $btnPuDefInb.text -eq "BLK")
        {
            $btnDefInbAll.text = "ALLOW ALL"
            $ttDefInbAll.SetToolTip($btnDefInbAll, "Click for default action of ALLOW for all inbound traffic.(NOT Recommended)")
        }
        else
        {
            $btnDefInbAll.text = "BLOCK ALL"
            $ttDefInbAll.SetToolTip($btnDefInbAll, "Click for default action of BLOCK for all inbound traffic.(Recommended)")
        }

        if ($btnDDefOutb.Text -eq "BLK")
        {
            $ttDDefOutb.SetToolTip($btnDDefOutb, "Click for default action of ALLOW for outbound domain traffic.(NOT Recommended)")
        }
        else
        {
            $ttDDefOutb.SetToolTip($btnDDefOutb, "Click for default action of BLOCK for outbound domain traffic.(Recommended)")
        }

        if ($btnPrDefOutb.Text -eq "BLK")
        {
            $ttPrDefOutb.SetToolTip($btnPrDefOutb, "Click for default action of ALLOW for outbound private traffic.(NOT Recommended)")
        }
        else
        {
            $ttPrDefOutb.SetToolTip($btnPrDefOutb, "Click for default action of BLOCK for outbound private traffic.(Recommended)")
        }

        if ($btnPuDefOutb.Text -eq "BLK")
        {
            $ttPuDefOutb.SetToolTip($btnPuDefOutb, "Click for default action of ALLOW for outbound public traffic.(NOT Recommended)")
        }
        else
        {
            $ttPuDefOutb.SetToolTip($btnPuDefOutb, "Click for default action of BLOCK for outbound public traffic.(Recommended)")
        }

        if ($btnDDefOutb.text -eq "BLK" -and $btnPrDefOutb.text -eq "BLK" -and $btnPuDefOutb.text -eq "BLK")
        {
            $btnDefOutbAll.text = "ALLOW ALL"
            $ttDefOutbAll.SetToolTip($btnDefOutbAll, "Click for default action of ALLOW for all outbound traffic.(NOT Recommended)")
        }
        else
        {
            $btnDefOutbAll.text = "BLOCK ALL"
            $ttDefOutbAll.SetToolTip($btnDefOutbAll, "Click for default action of BLOCK for all outbound traffic.(Recommended)")
        }

    }

# ***************************************
# *** END of Function Update_ToolTips ***
# ***************************************

# *********************************
# *** Function Update_NetConfig ***
# *********************************

    Function Update_NetConfig
    {
        if ($global:Debug)
        {
            write-host "Function Update_NetConfig"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_msclient" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnMSClient.text = "Client for Microsoft Networks: Enabled"
            $btnMSClient.BackColor = "green"
            $btnMSClient.forecolor = "white"
            $ttMSClient.SetToolTip($btnMSClient, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnMSClient.text = "Client for Microsoft Networks: Disabled"
            $btnMSClient.BackColor = "red"
            $btnMSClient.forecolor = "white"
            $ttMSClient.SetToolTip($btnMSClient, "Enable this service => Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_server" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnMSServer.text = "File and Printer Sharing for Microsoft Networks: Enabled"
            $btnMSServer.BackColor = "orange"
            $btnMSServer.forecolor = "white"
            $ttMSServer.SetToolTip($btnMSServer, "Enable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnMSServer.text = "File and Printer Sharing for Microsoft Networks: Disabled"
            $btnMSServer.BackColor = "green"
            $btnMSServer.forecolor = "white"
            $ttMSServer.SetToolTip($btnMSServer, "Disable this service => Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_pacer" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnQoS.text = "QoS Packet Scheduler: Enabled"
            $btnQoS.BackColor = "red"
            $btnQoS.forecolor = "white"
            $ttQoS.SetToolTip($btnQoS, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnQoS.text = "QoS Packet Scheduler: Disabled"
            $btnQoS.BackColor = "green"
            $btnQoS.forecolor = "white"
            $ttQoS.SetToolTip($btnQoS, "Enable this service => Not Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnIPv4.text = "Internet Protocol Version 4 (TCP/IPv4): Enabled"
            $btnIPv4.BackColor = "green"
            $btnIPv4.forecolor = "white"
            $ttIPv4.SetToolTip($btnIPv4, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnIPv4.text = "Internet Protocol Version 4 (TCP/IPv4): Disabled"
            $btnIPv4.BackColor = "red"
            $btnIPv4.forecolor = "white"
            $ttIPv4.SetToolTip($btnIPv4, "Enable this service => Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_implat" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnMultiplexor.text = "Microsoft Network Adapter Multiplexor Protocol: Enabled"
            $btnMultiplexor.BackColor = "red"
            $btnMultiplexor.forecolor = "white"
            $ttMultiplexor.SetToolTip($btnMultiplexor, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnMultiplexor.text = "Microsoft Network Adapter Multiplexor Protocol: Disabled"
            $btnMultiplexor.BackColor = "green"
            $btnMultiplexor.forecolor = "white"
            $ttMultiplexor.SetToolTip($btnMultiplexor, "Enable this service => Not Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_lldp" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnLLDP.text = "Microsoft LLDP Protocol Driver: Enabled"
            $btnLLDP.BackColor = "red"
            $btnLLDP.forecolor = "white"
            $ttLLDP.SetToolTip($btnLLDP, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnLLDP.text = "Microsoft LLDP Protocol Driver: Disabled"
            $btnLLDP.BackColor = "green"
            $btnLLDP.forecolor = "white"
            $ttLLDP.SetToolTip($btnLLDP, "Enable this service => Not Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip6" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnIPv6.text = "Internet Protocol Version 6 (TCP/IPv6): Enabled"
            $btnIPv6.BackColor = "orange"
            $btnIPv6.forecolor = "white"
            $ttIPv6.SetToolTip($btnIPv6, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnIPv6.text = "Internet Protocol Version 6 (TCP/IPv6): Disabled"
            $btnIPv6.BackColor = "green"
            $btnIPv6.forecolor = "white"
            $ttIPv6.SetToolTip($btnIPv6, "Enable this service => Not Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_rspndr" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnLLTD.text = "Link-Layer Topology Discovery Responder: Enabled"
            $btnLLTD.BackColor = "orange"
            $btnLLTD.forecolor = "white"
            $ttLLTD.SetToolTip($btnLLTD, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnLLTD.text = "Link-Layer Topology Discovery Responder: Disabled"
            $btnLLTD.BackColor = "green"
            $btnLLTD.forecolor = "white"
            $ttLLTD.SetToolTip($btnLLTD, "Enable this service => Recommended. See Guidance Button.")
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_lltdio" }
        if ($ServiceState.Enabled -eq $True)
        {
            $btnLLTDMapper.text = "Link-Layer Topology Discovery Mapper I/O Driver: Enabled"
            $btnLLTDMapper.BackColor = "orange"
            $btnLLTDMapper.forecolor = "white"
            $ttLLTDMapper.SetToolTip($btnLLTDMapper, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnLLTDMapper.text = "Link-Layer Topology Discovery Mapper I/O Driver: Disabled"
            $btnLLTDMapper.BackColor = "green"
            $btnLLTDMapper.forecolor = "white"
            $ttLLTDMapper.SetToolTip($btnLLTDMapper, "Enable this service => Recommended. See Guidance Button.")
        }
        $mainform.Refresh()
    }

# ****************************************
# *** END of Function Update_NetConfig ***
# ****************************************

# *******************************
# *** Function Internet_Check ***
# *******************************

    Function Internet_Check
    {
        if ($global:Debug)
        {
            write-host "Function Internet_Check"
        }

        $tbAppLog.AppendText((get-date).ToString() + ": Checking internet availability...")
        $VulnPortsURL = "https://www.abuseipdb.com"
        $global:InternetAvail = @(test-netconnection -computername 8.8.8.8 -Port 53)
        #start-sleep -Milliseconds 5000

        if ($global:InternetAvail.TcpTestSucceeded)
        {
            $tbAppLog.AppendText("Internet connectivity Verified!`r`n")
            $tbAppLog.AppendText((get-date).ToString() + ": Retrieving Port Investigation Information...")
            $tbInternetStatus.Text = "Internet Available"
            $tbInternetStatus.ForeColor = "White"
            $tbInternetStatus.BackColor = "Green"

            try
            {
                $global:response = Invoke-WebRequest -Uri $VulnPortsURL
                $tbAppLog.AppendText("Completed Successfully!`r`n")
            }
            catch
            {
                $tbAppLog.AppendText("FAILED!`r`n")
                $tbAppLog.AppendText((get-date).ToString() + ":  ERROR: Either www.abuseipdb.com is unavailable or Internet Explorer has not completed initial setup!`r`n")
                $tbAppLog.AppendText((get-date).ToString() + "    Open Internet Explorer, select Recommended, and close Internet Explorer.`r`n")
                $tbAppLog.AppendText((get-date).ToString() + "    Close and re-open Windows Firewall Analyzer.`r`n")
            }
        }
        else
        {
            $tbAppLog.AppendText("Internet connectivity is needed for the IP reputation step in the Investigations Tab!`r`n")
            $tbAppLog.AppendText((get-date).ToString() + ":    The IP reputation step on the Investigation tab will be unavailable.`r`n")
            $tbInternetStatus.Text = "Internet Unavailable"
            $tbInternetStatus.ForeColor = "White"
            $tbInternetStatus.BackColor = "Red"
        }
    }

# **************************************
# *** END of Function Internet_Check ***
# **************************************

# *****************************
# *** Function DomProfState ***
# *****************************

    Function DomProfState()
    {
        if ($global:Debug)
        {
            write-host "Function DomProfState"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        if ($btnDomState.Text -eq "YES")
        {
            set-netfirewallprofile -policystore localhost -name domain -Enabled False
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Domain Firewall...")
        }
        else
        {
            set-netfirewallprofile -policystore localhost -name domain -Enabled True
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Domain Firewall...")
        }
        Disable_Controls
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

# ************************************
# *** END of Function DomProfState ***
# ************************************

# ******************************
# *** Function PrivProfState ***
# ******************************

    Function PrivProfState()
    {
        if ($global:Debug)
        {
            write-host "Function PrivProfState"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        if ($btnPrivState.Text -eq "YES")
        {
            set-netfirewallprofile -policystore localhost -name private -Enabled False
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Private Firewall...")
        }
        else
        {
            set-netfirewallprofile -policystore localhost -name Private -Enabled True
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Private Firewall...")
        }
        Disable_Controls
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

# *************************************
# *** END of Function PrivProfState ***
# *************************************

# *********************************
# *** Function PubProfState ***
# *********************************

    Function PubProfState()
    {
        if ($global:Debug)
        {
            write-host "Function PubProfState"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        if ($btnPubState.Text -eq "YES")
        {
            set-netfirewallprofile -policystore localhost -name public -Enabled False
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Public Firewall...")
        }
        else
        {
            set-netfirewallprofile -policystore localhost -name public -Enabled True
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Public Firewall...")
        }
        Disable_Controls
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

# ************************************
# *** END of Function PubProfState ***
# ************************************

# *****************************
# *** Function ProfileState ***
# *****************************

    Function ProfileState()
    {
        if ($global:Debug)
        {
            write-host "Function ProfileState"
        }

        $DomProfState = get-netfirewallprofile -policystore activestore -name domain | Select Enabled
        if ($DomProfState.Enabled -eq $True)
        {
            $btnDomState.BackColor = "green"
            $btnDomState.ForeColor = "white"
            $btnDomState.Text = "YES"
        }
        else
        {
            $btnDomState.BackColor = "red"
            $btnDomState.ForeColor = "white"
            $btnDomState.Text = "NO"
        }

        $PrivProfState = get-netfirewallprofile -policystore activestore -name private | Select Enabled
        if ($PrivProfState.Enabled -eq $True)
        {
            $btnPrivState.BackColor = "green"
            $btnPrivState.ForeColor = "white"
            $btnPrivState.Text = "YES"
        }
        else
        {
            $btnPrivState.BackColor = "red"
            $btnPrivState.ForeColor = "white"
            $btnPrivState.Text = "NO"
        }

        $PubProfState = get-netfirewallprofile -policystore activestore -name public | Select Enabled
        if ($PubProfState.Enabled -eq $True)
        {
            $btnPubState.BackColor = "green"
            $btnPubState.ForeColor = "white"
            $btnPubState.Text = "YES"
        }
        else
        {
            $btnPubState.BackColor = "red"
            $btnPubState.ForeColor = "white"
            $btnPubState.Text = "NO"
        }
    }

# ************************************
# *** END of Function ProfileState ***
# ************************************

# ******************************
# *** Function LogAllowState ***
# ******************************

    Function LogAllowState()
    {
        if ($global:Debug)
        {
            write-host "Function LogAllowState"
        }

        $DLogAllowState = get-netfirewallprofile -policystore activestore -name domain | Select LogAllowed
        if ($DLogAllowState.LogAllowed -eq $True)
        {
            $btnDLogAllow.BackColor = "green"
            $btnDLogAllow.ForeColor = "white"
            $btnDLogAllow.Text = "YES"
        }
        else
        {
            $btnDLogAllow.BackColor = "red"
            $btnDLogAllow.ForeColor = "white"
            $btnDLogAllow.Text = "NO"
        }

        $PrLogAllowState = get-netfirewallprofile -policystore activestore -name private | Select LogAllowed
        if ($PrLogAllowState.LogAllowed -eq $True)
        {
            $btnPrLogAllow.BackColor = "green"
            $btnPrLogAllow.ForeColor = "white"
            $btnPrLogAllow.Text = "YES"
        }
        else
        {
            $btnPrLogAllow.BackColor = "red"
            $btnPrLogAllow.ForeColor = "white"
            $btnPrLogAllow.Text = "NO"
        }

        $PuLogAllowState = get-netfirewallprofile -policystore activestore -name public | Select LogAllowed
        if ($PuLogAllowState.LogAllowed -eq $True)
        {
            $btnPuLogAllow.BackColor = "green"
            $btnPuLogAllow.ForeColor = "white"
            $btnPuLogAllow.Text = "YES"
        }
        else
        {
            $btnPuLogAllow.BackColor = "red"
            $btnPuLogAllow.ForeColor = "white"
            $btnPuLogAllow.Text = "NO"
        }
    }

# *************************************
# *** END of Function LogAllowState ***
# *************************************

# *****************************
# *** Function LogDropState ***
# *****************************

    Function LogDropState()
    {
        if ($global:Debug)
        {
            write-host "Function LogDropState"
        }

        $DLogDropState = get-netfirewallprofile -policystore activestore -name domain | Select LogBlocked
        if ($DLogDropState.LogBlocked -eq $True)
        {
            $btnDLogDrop.BackColor = "green"
            $btnDLogDrop.ForeColor = "white"
            $btnDLogDrop.Text = "YES"
        }
        else
        {
            $btnDLogDrop.BackColor = "red"
            $btnDLogDrop.ForeColor = "white"
            $btnDLogDrop.Text = "NO"
        }

        $PrLogDropState = get-netfirewallprofile -policystore activestore -name private | Select LogBlocked
        if ($PrLogDropState.LogBlocked -eq $True)
        {
            $btnPrLogDrop.BackColor = "green"
            $btnPrLogDrop.ForeColor = "white"
            $btnPrLogDrop.Text = "YES"
        }
        else
        {
            $btnPrLogDrop.BackColor = "red"
            $btnPrLogDrop.ForeColor = "white"
            $btnPrLogDrop.Text = "NO"
        }

        $PuLogDropState = get-netfirewallprofile -policystore activestore -name public | Select LogBlocked
        if ($PuLogDropState.LogBlocked -eq $True)
        {
            $btnPuLogDrop.BackColor = "green"
            $btnPuLogDrop.ForeColor = "white"
            $btnPuLogDrop.Text = "YES"
        }
        else
        {
            $btnPuLogDrop.BackColor = "red"
            $btnPuLogDrop.ForeColor = "white"
            $btnPuLogDrop.Text = "NO"
        }
    }

# ************************************
# *** END of Function LogDropState ***
# ************************************

# *******************************
# *** Function LogIgnoreState ***
# *******************************

    Function LogIgnoreState()
    {
        if ($global:Debug)
        {
            write-host "Function LogIgnoreState"
        }

        $DLogIgnoreState = get-netfirewallprofile -policystore activestore -name domain | Select LogIgnored
        if ($DLogIgnoreState.LogIgnored -eq $True)
        {
            $btnDLogIgnore.BackColor = "green"
            $btnDLogIgnore.ForeColor = "white"
            $btnDLogIgnore.Text = "YES"
        }
        else
        {
            $btnDLogIgnore.BackColor = "red"
            $btnDLogIgnore.ForeColor = "white"
            $btnDLogIgnore.Text = "NO"
        }

        $PrLogIgnoreState = get-netfirewallprofile -policystore activestore -name private | Select LogIgnored
        if ($PrLogIgnoreState.LogIgnored -eq $True)
        {
            $btnPrLogIgnore.BackColor = "green"
            $btnPrLogIgnore.ForeColor = "white"
            $btnPrLogIgnore.Text = "YES"
        }
        else
        {
            $btnPrLogIgnore.BackColor = "red"
            $btnPrLogIgnore.ForeColor = "white"
            $btnPrLogIgnore.Text = "NO"
        }

        $PuLogIgnoreState = get-netfirewallprofile -policystore activestore -name public | Select LogIgnored
        if ($PuLogIgnoreState.LogIgnored -eq $True)
        {
            $btnPuLogIgnore.BackColor = "green"
            $btnPuLogIgnore.ForeColor = "white"
            $btnPuLogIgnore.Text = "YES"
        }
        else
        {
            $btnPuLogIgnore.BackColor = "red"
            $btnPuLogIgnore.ForeColor = "white"
            $btnPuLogIgnore.Text = "NO"
        }
    }

# **************************************
# *** END of Function LogIgnoreState ***
# **************************************

# *****************************
# *** Function DefInbAction ***
# *****************************

    Function DefInbAction()
    {
        if ($global:Debug)
        {
            write-host "Function DefInbAction"
        }

        $DDefInbAct = get-netfirewallprofile -policystore activestore -name domain | Select DefaultInboundAction
        if ($DDefInbAct.DefaultInboundAction -eq "Block")
        {
            $btnDDefInb.BackColor = "green"
            $btnDDefInb.ForeColor = "white"
            $btnDDefInb.Text = "BLK"
        }
        else
        {
            $btnDDefInb.BackColor = "red"
            $btnDDefInb.ForeColor = "white"
            $btnDDefInb.Text = "ALW"
        }

        $PrDefInbAct = get-netfirewallprofile -policystore activestore -name private | Select DefaultInboundAction
        if ($PrDefInbAct.DefaultInboundAction -eq "Block")
        {
            $btnPrDefInb.BackColor = "green"
            $btnPrDefInb.ForeColor = "white"
            $btnPrDefInb.Text = "BLK"
        }
        else
        {
            $btnPrDefInb.BackColor = "red"
            $btnPrDefInb.ForeColor = "white"
            $btnPrDefInb.Text = "ALW"
        }

        $PuDefInbAct = get-netfirewallprofile -policystore activestore -name public | Select DefaultInboundAction
        if ($PuDefInbAct.DefaultInboundAction -eq "Block")
        {
            $btnPuDefInb.BackColor = "green"
            $btnPuDefInb.ForeColor = "white"
            $btnPuDefInb.Text = "BLK"
        }
        else
        {
            $btnPuDefInb.BackColor = "red"
            $btnPuDefInb.ForeColor = "white"
            $btnPuDefInb.Text = "ALW"
        }
    }

# ************************************
# *** END of Function DefInbAction ***
# ************************************

# ******************************
# *** Function DefOutbAction ***
# ******************************

    Function DefOutbAction()
    {
        if ($global:Debug)
        {
            write-host "Function DefOutbAction"
        }

        $DDefOutbAct = get-netfirewallprofile -policystore activestore -name domain | Select DefaultOutboundAction
        if ($DDefOutbAct.DefaultOutboundAction -eq "Block")
        {
            $btnDDefOutb.BackColor = "green"
            $btnDDefOutb.ForeColor = "white"
            $btnDDefOutb.Text = "BLK"
        }
        else
        {
            $btnDDefOutb.BackColor = "orange"
            $btnDDefOutb.ForeColor = "white"
            $btnDDefOutb.Text = "ALW"
        }

        $PrDefOutbAct = get-netfirewallprofile -policystore activestore -name private | Select DefaultOutboundAction
        if ($PrDefOutbAct.DefaultOutboundAction -eq "Block")
        {
            $btnPrDefOutb.BackColor = "green"
            $btnPrDefOutb.ForeColor = "white"
            $btnPrDefOutb.Text = "BLK"
        }
        else
        {
            $btnPrDefOutb.BackColor = "orange"
            $btnPrDefOutb.ForeColor = "white"
            $btnPrDefOutb.Text = "ALW"
        }

        $PuDefOutbAct = get-netfirewallprofile -policystore activestore -name public | Select DefaultOutboundAction
        if ($PuDefOutbAct.DefaultOutboundAction -eq "Block")
        {
            $btnPuDefOutb.BackColor = "green"
            $btnPuDefOutb.ForeColor = "white"
            $btnPuDefOutb.Text = "BLK"
        }
        else
        {
            $btnPuDefOutb.BackColor = "orange"
            $btnPuDefOutb.ForeColor = "white"
            $btnPuDefOutb.Text = "ALW"
        }
    }

# *************************************
# *** END of Function DefOutbAction ***
# *************************************

# *********************************
# *** Function UpdateSearchCrit ***
# *********************************

    Function UpdateSearchCrit()
    {
        if ($global:Debug)
        {
            write-host "Function UpdateSearchCrit"
        }

        if ($global:Dest_port.count -ne 0)
        {
            if ($tbDstPrtSelected.TextLength -eq 0)
            {
                $tbDstPrtSelected.text = "Searching..."
            }
            else
            {
                if ($tbDstPrtSelected.Text -eq "Searching...")
                {
                    $tbDstPrtSelected.text = ""
                }
            }
        }
        else
        {
            $tbDstPrtSelected.text = "No Data Found"
        }
    
        if ($global:Dest_IP.count -ne 0)
        {
            if ($tbDstIPSelected.textlength -eq 0)
            {
                $tbDstIPSelected.text = "Searching..."
            }
            else
            {
                if ($tbDstIPSelected.Text -eq "Searching...")
                {
                    $tbDstIPSelected.text = ""
                }
            }
        }
        else
        {
            $tbDstIPSelected.text = "No Data Found"
        }

        if($global:Source_IP.count -ne 0)
        {
            if ($tbSrcIPSelected.textlength -eq 0)
            {
                $tbSrcIPSelected.text = "Searching..."
            }
            else
            {
                if ($tbSrcIPSelected.Text -eq "Searching...")
                {
                    $tbSrcIPSelected.text = ""
                }
            }
        }
        else
        {
            $tbSrcIPSelected.text = "No Data Found"
        }

        if ($global:Action.count -ne 0)
        {
            if ($tbActionSelected.textlength -eq 0)
            {
                $tbActionSelected.text = "Searching..."
            }
            else
            {
                if ($tbActionSelected.Text -eq "Searching...")
                {
                    $tbActionSelected.text = ""
                }
            }
        }
        else
        {
            $tbActionSelected.text = "No Data Found"
        }

        if ($global:Protocol.count -ne 0)
        {
            if ($tbProtoSelected.textlength -eq 0)
            {
                $tbProtoSelected.text = "Searching..."
            }
            else
            {
                if ($tbProtoSelected.Text -eq "Searching...")
                {
                    $tbProtoSelected.text = ""
                }
            }
        }
        else
        {
            $tbProtoSelected.text = "No Data Found"
        }

    <#    if ($global:Direction.count -ne 0)
        {
            if ($tbDirSelected.textlength -eq 0)
            {
                $tbDirSelected.text = "Searching..."
            }
            else
            {
                if ($tbDirSelected.Text -eq "Searching...")
                {
                    $tbDirSelected.text = ""
                }
            }
        }
        else
        {
            $tbDirSelected.text = "No Data Found"
        } #>
    }

# ****************************************
# *** END of Function UpdateSearchCrit ***
# ****************************************

# ***************************************
# *** Function Verify_Search_Elements ***
# ***************************************

    Function Verify_Search_Elements()
    {
        param($Search_Element)
        
        if ($global:Debug)
        {
            write-host "Function Verify_Search_Elements($Search_Element)"
        }

        foreach($key in $Search_Element)
        {
            Write-host $key.Name " ==> " $key.Count | FT -AutoSize
        }
    }

# **********************************************
# *** END of Function Verify_Search_Elements ***
# **********************************************

# ***************************
# *** Function AssignData ***
# ***************************

    Function AssignData()
    {
        param($Job)

        if ($global:Debug)
        {
            write-host "Function AssignData($Job)"
        }

        foreach($element in $Job)
        {
            if ($element.Name -match "^\d+$") # Dest_Port
            {
                #write-host "Destination Port"
                #write-host $Job
                $global:Dest_Port = $Job | Select * | where {$_.Name -match "^\d+$"}
                #Verify_Search_Elements($global:Dest_Port)
                break
            }

            if ($element.Name -contains "src-ip") # Dest_IP
            {
                #write-host "Destination IP"
                #write-host $Job
                $global:Dest_IP = $Job | Select * | where {$_.Name -like "*.*.*.*"}
                #Verify_Search_Elements($global:Dest_IP)
                break
            }

            if ($element.Name -contains "protocol") # Src_IP
            {
                #write-host "Source IP"
                #write-host $Job
                $global:Source_IP = $Job | Select * | where {$_.Name -like "*.*.*.*" -or $_.Name -contains "protocol"}
                #Verify_Search_Elements($global:Source_IP)
                $global:Source_IP | FT
                break
            }

            if ($element.Name -contains "TCP" -or $element.Name -contains "UDP" -or $element.Name -contains "ICMP") # Protocol
            {
                #write-host "Protocol"
                #write-host $Job
                $global:Protocol = $Job | Select * | where {$_.Count -gt 1}
                #Verify_Search_Elements($global:Protocol)
                break
            }

            if ($element.Name -contains "DROP" -or $element.Name -contains "ALLOW") # Action
            {
                #write-host "Action"
                #write-host $Job
                $global:Action = $Job | Select * | where {$_.Name -eq "DROP" -or $_.Name -eq "ALLOW" -or $_.Name -eq "INFO-EVENTS-LOST"}
                #Verify_Search_Elements($global:Action)
                break
            }

    <#        if ($element.Name -contains "SEND" -or $element.Name -contains "RECEIVE") # Path
            {
                #write-host "Path"
                #write-host $Job
                $global:Direction = $Job | Select * | where {$_.Name -eq "SEND" -or $_.Name -eq "RECEIVE"}
                #Verify_Search_Elements($global:Direction)
                break
            } #>
        }
    }

# **********************************
# *** END of Function AssignData ***
# **********************************

# ******************************************************************************************************************************************************
# *** END of External Functions                                                                                                                      ***
# ******************************************************************************************************************************************************

# ******************************************************************************************************************************************************
# *** Internal Form Functions                                                                                                                        ***
# ******************************************************************************************************************************************************

# ***********************************
# *** Function NetConfigTab_Click ***
# ***********************************

    Function NetConfigTab_Click()
    {
        if ($global:Debug)
        {
            write-host "Function NetConfigTab_Click"
        }

        if ($global:CurrentTab -ne "NetConfig")
        {
            $lstbxNetAdapt.Items[0].Selected = $True
            $lstbxNetAdapt.Items[0].Focused = $True
            $lstbxNetAdapt.HideSelection = $false
            $global:CurrentTab = $tabControl.SelectedTab.Name
        }
        Update_NetConfig
            
        if ($btnValidLic.Text -eq "License Validated" -and $tbLicOne.text.Length -eq 4 -and $tbLicTwo.text.Length -eq 4 -and $tbLicThree.text.Length -eq 4)
        {
            $btnMSClient.Enabled = $True
            $btnMSServer.Enabled = $True
            $btnQoS.Enabled = $True
            $btnIPv4.Enabled = $True
            $btnMultiplexor.Enabled = $True
            $btnLLDP.Enabled = $True
            $btnIPv6.Enabled = $True
            $btnLLTD.Enabled = $True
            $btnLLTDMapper.Enabled = $True
            $btnMSClient_Info.Enabled = $True
            $btnMSServer_Info.Enabled = $True
            $btnQoS_Info.Enabled = $True
            $btnIPv4_Info.Enabled = $True
            $btnMultiplexor_Info.Enabled = $True
            $btnLLDP_Info.Enabled = $True
            $btnIPv6_Info.Enabled = $True
            $btnLLTD_Info.Enabled = $True
            $btnLLTDMapper_Info.Enabled = $True
        }
        else
        {
            $btnMSClient.BackColor = "DarkGray"
            $btnMSServer.BackColor = "DarkGray"
            $btnQoS.BackColor = "DarkGray"
            $btnIPv4.BackColor = "DarkGray"
            $btnMultiplexor.BackColor = "DarkGray"
            $btnLLDP.BackColor = "DarkGray"
            $btnIPv6.BackColor = "DarkGray"
            $btnLLTD.BackColor = "DarkGray"
            $btnLLTDMapper.BackColor = "DarkGray"
        }
    }

# ***********************************
# *** Function NetConfigTab_Click ***
# ***********************************

# *************************************
# *** Function AddLines_textchanged ***
# *************************************

    Function AddLines_textchanged
    {
        if ($global:Debug)
        {
            write-host "Function AddLines_textchanged"
        }

        If ($tbLastLines.Text -ne "0")
        {
            $cbPrevFile.checked = $False
            $cbCurFile.Checked = $True
        }
        else
        {
            $btnAllTrafTo.Enabled = $True
            $btnAllTrafFrom.Enabled = $True
        }
    }

# ********************************************
# *** END of Function AddLines_textchanged ***
# ********************************************

# *******************************
# *** Function AddLines_click ***
# *******************************

    Function AddLines_click
    {
        if ($global:Debug)
        {
            write-host "Function AddLines_click"
        }

        If ($tbLastLines.Text -ne "0")
        {
            $btnAllTrafTo.Enabled = $False
            $btnAllTrafFrom.Enabled = $False
        }
    }

# **************************************
# *** END of Function AddLines_click ***
# **************************************

# **********************************
# *** Function GetPortInfo_Click ***
# **********************************

    Function GetPortInfo_Click()
    {
        if ($global:Debug)
        {
            write-host "Function GetPortInfo_Click"
        }

        $VulnPortsURL = "https://www.speedguide.net/port.php?port=" + $tbDstPrtSelected.Text
        $global:VulnPorts = Invoke-WebRequest -Uri $VulnPortsURL
        #$portURL = 'https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers'
        $LowPortTable = 5
        $HighPortTable = 6
        $VulnPortTable = 2
        #TableNumber 5 is 0-1023
        #TableNumber 6 is 1024-49190
        #$global:response = Invoke-WebRequest -Uri $portURL
        #$global:response | Get-Member
        #$response.tostring() -split "[`r`n]" | select-string "5353"
        $tables = @($global:response.ParsedHtml.IHTMLDocument3_getElementsByTagName("TABLE"))

        $tablesVuln = @($global:VulnPorts.ParsedHtml.IHTMLDocument3_getElementsByTagName("TABLE"))

        if ([int]$tbDstPrtSelected.Text -gt 1023)
        {
            $table = $tables[$HighPortTable]
        }
        else
        {
            $table = $tables[$LowPortTable]
        }

        $titles = @()

        $rows = @($table.Rows)

        ## Go through all of the rows in the table

        foreach($row in $rows)
        {
            $cells = @($row.Cells)
            ## If we've found a table header, remember its titles

            if($cells[0].tagName -eq "TH")
            {
                $titles = @($cells | % { ("" + $_.InnerText).Trim() })
                continue
            }

            ## If we haven't found any table headers, make up names "P1", "P2", etc.
            if(-not $titles)
            {
                $titles = @(1..($cells.Count + 2) | % { "P$_" })
            }

            ## Now go through the cells in the the row. For each, try to find the
            ## title that represents that column and create a hashtable mapping those
            ## titles to content

            $resultObject = [Ordered] @{}

            for($counter = 0; $counter -lt $cells.Count; $counter++)
            {
                $title = $titles[$counter]
                if(-not $title) { continue }
                $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
            }

            ## And finally cast that hashtable to a PSCustomObject

            $Test = $resultObject | where { $_.Port -eq $tbDstPrtSelected.Text}
            if ($Test.Port -eq $tbDstPrtSelected.Text)
            {
                $tbTCPInv.Text = $Test.TCP
                $lbTCPInv.Text = "TCP (" + $tbDstPrtSelected.Text + ")"
                $tbUDPInv.Text = $Test.UDP
                $lbUDPInv.Text = "UDP (" + $tbDstPrtSelected.Text + ")"
                $tbDescInv.Text = $Test.description
                $lbDescInv.Text = "Port " + $tbDstPrtSelected.Text + " Description"
                $tbIANAInv.Text = $Test.'IANA Status[1]'
                Break
            }
            #$resultObject.description
            #[PSCustomObject] $resultObject
        }
        
        if ($tbTCPInv.Text -eq "Searching...")
            {
                $tbTCPInv.Text = "Not Found"
                $tbUDPInv.Text = "Not Found"
                $tbDescInv.Text = "Not Found"
                $tbIANAInv.Text = "Not Found"
            }

        $tablesVuln = @($global:VulnPorts.ParsedHtml.IHTMLDocument3_getElementsByTagName("TABLE"))

        $table = $tablesVuln[$VulnPortTable]

        $titles = @()

        $rows = @($table.Rows)

        ## Go through all of the rows in the table

        foreach($row in $rows)
        {
            $cells = @($row.Cells)
            ## If we've found a table header, remember its titles

            if($cells[0].tagName -eq "TH")
            {
                $titles = @($cells | % { ("" + $_.InnerText).Trim() })
                continue
            }

            ## If we haven't found any table headers, make up names "P1", "P2", etc.
            if(-not $titles)
            {
                $titles = @(1..($cells.Count + 2) | % { "P$_" })
            }

            ## Now go through the cells in the the row. For each, try to find the
            ## title that represents that column and create a hashtable mapping those
            ## titles to content

            $resultObject = [Ordered] @{}

            for($counter = 0; $counter -lt $cells.Count; $counter++)
            {
                $title = $titles[$counter]
                if(-not $title) { continue }
                $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
            }

            ## And finally cast that hashtable to a PSCustomObject

            $Test = $resultObject | where { $_.'Port(s)' -eq $tbDstPrtSelected.Text}

            if ($Test.'Port(s)' -eq $tbDstPrtSelected.Text)
            {
                $tbSecRec.Text = $Test.Details
                $lbSecRec.Text = "Port " + $tbDstPrtSelected.Text + " Security Information"
                Break
            }
            #$resultObject.description
            #[PSCustomObject] $resultObject
        }
        
        if ($tbSecRec.Text -eq "Searching...")
            {
                $tbSecRec.Text = "Not Found"
            }

        #DstPort_Click
        #$tabControl.SelectedIndex = 1
    }

# *****************************************
# *** END of Function GetPortInfo_Click ***
# *****************************************

# *****************************
# *** Function Search_Clear ***
# *****************************

    Function Search_Clear()
    {
        if ($global:Debug)
        {
            write-host "Function Search_Clear"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        #$tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:FWLogInfo | Select * | where { $_.'dst-port' -like $global:DstPrtSelected -and $_.'dst--ip-address' -like $global:DstIPSelected -and $_.'src--ip-address' -like $global:SrcIPSelected -and $_.'action' -like $global:ActionSelected -and $_.'protocol' -like $global:ProtoSelected })
        #write-host $global:Live_Search
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        #GetPortInfo_Click
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
    }

# ************************************
# *** END of Function Search_Clear ***
# ************************************


# ******************************
# *** Function DstPort_Click ***
# ******************************

    Function DstPort_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DstPort_Click"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        $tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
        $global:DstPrtSelected = $lstbxDstPort.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Destination Port: " + $lstbxDstPort.SelectedItems[0].text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $_.'dst-port' -eq $lstbxDstPort.SelectedItems[0].text })
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        #GetPortInfo_Click
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
        $btnClearDstPrt.Enabled = $True
        $btnClearDstPrt.BackColor = "Red"
        $btnClearDstPrt.ForeColor = "White"
    }

    Function ClearDstPort()
    {
        if ($global:Debug)
        {
            write-host "Function ClearDstPort"
        }

        $tbDstPrtSelected.Text = ""
        $global:DstPrtSelected = "*"

        if ($tbDstIPSelected.Text -eq "")
        {
            $tbDstIPSelected.Text = ""
            $global:DstIPSelected = "*"
        }

        if ($tbSrcIPSelected.Text -eq "")
        {
            $tbSrcIPSelected.Text = ""
            $global:SrcIPSelected = "*"
        }

        if ($tbActionSelected.Text -eq "")
        {
            $tbActionSelected.Text = ""
            $global:ActionSelected = "*"
        }

        if ($tbProtoSelected.Text -eq "")
        {
            $tbProtoSelected.Text = ""
            $global:ProtoSelected = "*"
        }

        Search_Clear
    }

# *************************************
# *** END of Function DstPort_Click ***
# *************************************

# ****************************
# *** Function DstIP_Click ***
# ****************************

    Function DstIP_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DstIP_Click"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        $tbDstIPSelected.Text = $lstbxDstIP.SelectedItems[0].text
        $global:DstIPSelected = $lstbxDstIP.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Destination IP: " + $tbDstIPSelected.Text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $_.'dst--ip-address' -eq $lstbxDstIP.SelectedItems[0].text })
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        <#$global:Dest_port = $global:Live_Search | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count
        $global:Dest_IP = $global:Live_Search | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Source_IP = $global:Live_Search | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Protocol = $global:Live_Search | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count
        $global:Action = $global:Live_Search | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count
        $global:Direction = $global:Live_Search | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count#>
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
<#        if ($lstbxDstPort.Items.Count -eq 1)
        {
            $lstbxDstPort.Items[0].Selected = $True
            $tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
            $tbIANAURL.Text = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=" + $tbDstPrtSelected.Text
            $tbSecRecURL.Text = "https://www.speedguide.net/port.php?port=" + $tbDstPrtSelected.Text
            $tbMSListURL.Text = "https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx#:~:text=List%20of%20Ports%20%20%20Port%20%20,SharePoint%20Portal%20Server%20%2043%20more%20rows%20"
            $tbWikiListURL.Text = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
            #GetPortInfo_Click
        } #>
        $Resolvable = Resolve-DnsName $tbDstIPSelected.Text -ErrorAction Ignore |select -exp NameHost
        $Cache = Get-DnsClientCache | select Entry, RecordName, Data | where { $_.Data -eq $tbDstIPSelected.Text}
        #Write-host $Cache
        if ($Resolvable.Length -gt 0)
        {
            $tbDIPHostName.Text = $Resolvable
        }
        else
        {
            $tbDIPHostName.Text = "DNS name not available."
        }
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
        $btnClearDstIP.Enabled = $True
        $btnClearDstIP.BackColor = "Red"
        $btnClearDstIP.ForeColor = "White"
    }

    Function ClearDstIP()
    {
        if ($global:Debug)
        {
            write-host "Function ClearDstIP"
        }

        $tbDstIPSelected.Text = ""
        $global:DstIPSelected = "*"

        if ($tbDstPrtSelected.Text -eq "")
        {
            $tbDstPrtSelected.Text = ""
            $global:DstPrtSelected = "*"
        }

        if ($tbSrcIPSelected.Text -eq "")
        {
            $tbSrcIPSelected.Text = ""
            $global:SrcIPSelected = "*"
        }

        if ($tbActionSelected.Text -eq "")
        {
            $tbActionSelected.Text = ""
            $global:ActionSelected = "*"
        }

        if ($tbProtoSelected.Text -eq "")
        {
            $tbProtoSelected.Text = ""
            $global:ProtoSelected = "*"
        }

        Search_Clear
    }
# ***********************************
# *** END of Function DstIP_Click ***
# ***********************************

# ****************************
# *** Function SrcIP_Click ***
# ****************************

    Function SrcIP_Click()
    {
        if ($global:Debug)
        {
            write-host "Function SrcIP_Click"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        $tbSrcIPSelected.Text = $lstbxSrcIP.SelectedItems[0].text
        $global:SrcIPSelected = $lstbxSrcIP.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Source IP: " + $tbSrcIPSelected.text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $_.'src--ip-address' -eq $lstbxSrcIP.SelectedItems[0].text })
        $tbSrcIPSelected.Text = $lstbxSrcIP.SelectedItems[0].text
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        <#$global:Dest_port = $global:Live_Search | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count
        $global:Dest_IP = $global:Live_Search | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Source_IP = $global:Live_Search | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Protocol = $global:Live_Search | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count
        $global:Action = $global:Live_Search | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count
        $global:Direction = $global:Live_Search | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count#>
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        if ($lstbxDstPort.Items.Count -eq 1)
        {
            $lstbxDstPort.Items[0].Selected = $True
            $tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
            $tbIANAURL.Text = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=" + $tbDstPrtSelected.Text
            $tbSecRecURL.Text = "https://www.speedguide.net/port.php?port=" + $tbDstPrtSelected.Text
            $tbMSListURL.Text = "https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx#:~:text=List%20of%20Ports%20%20%20Port%20%20,SharePoint%20Portal%20Server%20%2043%20more%20rows%20"
            $tbWikiListURL.Text = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
            #GetPortInfo_Click
        }
        $Resolvable = Resolve-DnsName $tbSrcIPSelected.Text -ErrorAction Ignore |select -exp NameHost
        $Cache = Get-DnsClientCache | select Entry, RecordName, Data | where { $_.Data -eq $tbSrcIPSelected.Text}
        #Write-host $Cache
        if ($Resolvable.Length -gt 0)
        {
            $tbSIPHostName.Text = $Resolvable
        }
        else
        {
            $tbSIPHostName.Text = "DNS name not available."
        }
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
        $btnClearSrcIP.Enabled = $True
        $btnClearSrcIP.BackColor = "Red"
        $btnClearSrcIP.ForeColor = "White"
    }

    Function ClearSrcIP()
    {
        if ($global:Debug)
        {
            write-host "Function ClearSrcIP"
        }

        $tbSrcIPSelected.Text = ""
        $global:SrcIPSelected = "*"

        if ($tbDstIPSelected.Text -eq "")
        {
            $tbDstIPSelected.Text = ""
            $global:DstIPSelected = "*"
        }

        if ($tbDstPrtSelected.Text -eq "")
        {
            $tbDstPrtSelected.Text = ""
            $global:DstPrtSelected = "*"
        }

        if ($tbActionSelected.Text -eq "")
        {
            $tbActionSelected.Text = ""
            $global:ActionSelected = "*"
        }

        if ($tbProtoSelected.Text -eq "")
        {
            $tbProtoSelected.Text = ""
            $global:ProtoSelected = "*"
        }

        Search_Clear
    }

# ***********************************
# *** END of Function SrcIP_Click ***
# ***********************************

# *****************************
# *** Function Action_Click ***
# *****************************

    Function Action_Click()
    {
        if ($global:Debug)
        {
            write-host "Function Action_Click"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        $tbActionSelected.Text = $lstbxAction.SelectedItems[0].text
        $global:ActionSelected = $lstbxAction.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Action: " + $tbActionSelected.Text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $_.'action' -eq $lstbxAction.SelectedItems[0].text })
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        <#$global:Dest_port = $global:Live_Search | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count
        $global:Dest_IP = $global:Live_Search | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Source_IP = $global:Live_Search | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Protocol = $global:Live_Search | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count
        $global:Action = $global:Live_Search | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count
        $global:Direction = $global:Live_Search | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count#>
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        if ($lstbxDstPort.Items.Count -eq 1)
        {
            $lstbxDstPort.Items[0].Selected = $True
            $tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
            $tbIANAURL.Text = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=" + $tbDstPrtSelected.Text
            $tbSecRecURL.Text = "https://www.speedguide.net/port.php?port=" + $tbDstPrtSelected.Text
            $tbMSListURL.Text = "https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx#:~:text=List%20of%20Ports%20%20%20Port%20%20,SharePoint%20Portal%20Server%20%2043%20more%20rows%20"
            $tbWikiListURL.Text = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
            #GetPortInfo_Click
        }
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
        $btnClearAction.Enabled = $True
        $btnClearAction.BackColor = "Red"
        $btnClearAction.ForeColor = "White"
    }

    Function ClearAction()
    {
        if ($global:Debug)
        {
            write-host "Function ClearAction"
        }

        $tbActionSelected.Text = ""
        $global:ActionSelected = "*"

        if ($tbDstIPSelected.Text -eq "")
        {
            $tbDstIPSelected.Text = ""
            $global:DstIPSelected = "*"
        }

        if ($tbSrcIPSelected.Text -eq "")
        {
            $tbSrcIPSelected.Text = ""
            $global:SrcIPSelected = "*"
        }

        if ($tbDstPrtSelected.Text -eq "")
        {
            $tbDstPrtSelected.Text = ""
            $global:DstPrtSelected = "*"
        }

        if ($tbProtoSelected.Text -eq "")
        {
            $tbProtoSelected.Text = ""
            $global:ProtoSelected = "*"
        }

        Search_Clear

    }

# ************************************
# *** END of Function Action_Click ***
# ************************************

# ****************************
# *** Function Proto_Click ***
# ****************************

    Function Proto_Click()
    {
        if ($global:Debug)
        {
            write-host "Function Proto_Click"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        $tbProtoSelected.Text = $lstbxProto.SelectedItems[0].text
        $global:ProtoSelected = $lstbxProto.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Protocol: " + $tbProtoSelected.Text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $_.'protocol' -eq $lstbxProto.SelectedItems[0].text })
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        <#$global:Dest_port = $global:Live_Search | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count
        $global:Dest_IP = $global:Live_Search | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Source_IP = $global:Live_Search | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Protocol = $global:Live_Search | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count
        $global:Action = $global:Live_Search | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count
        $global:Direction = $global:Live_Search | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count#>
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        if ($lstbxDstPort.Items.Count -eq 1)
        {
            $lstbxDstPort.Items[0].Selected = $True
            $tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
            $tbIANAURL.Text = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=" + $tbDstPrtSelected.Text
            $tbSecRecURL.Text = "https://www.speedguide.net/port.php?port=" + $tbDstPrtSelected.Text
            $tbMSListURL.Text = "https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx#:~:text=List%20of%20Ports%20%20%20Port%20%20,SharePoint%20Portal%20Server%20%2043%20more%20rows%20"
            $tbWikiListURL.Text = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
            #GetPortInfo_Click
        }
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
        $btnClearProto.Enabled = $True
        $btnClearProto.BackColor = "Red"
        $btnClearProto.ForeColor = "White"
    }

    Function ClearProto()
    {
        if ($global:Debug)
        {
            write-host "Function ClearProto"
        }

        $tbProtoSelected.Text = ""
        $global:ProtoSelected = "*"

        if ($tbDstIPSelected.Text -eq "")
        {
            $tbDstIPSelected.Text = ""
            $global:DstIPSelected = "*"
        }

        if ($tbSrcIPSelected.Text -eq "")
        {
            $tbSrcIPSelected.Text = ""
            $global:SrcIPSelected = "*"
        }

        if ($tbActionSelected.Text -eq "")
        {
            $tbActionSelected.Text = ""
            $global:ActionSelected = "*"
        }

        if ($tbDstPrtSelected.Text -eq "")
        {
            $tbDstPrtSelected.Text = ""
            $global:DstPrtSelected = "*"
        }

        Search_Clear
    }

# ***********************************
# *** END of Function Proto_Click ***
# ***********************************

# **************************
# *** Function Dir_Click ***
# **************************

    Function Dir_Click()
    {
        if ($global:Debug)
        {
            write-host "Function Dir_Click"
        }

        $global:SelectedTab = $tabControl.SelectedIndex
        $tabControl.SelectedIndex = 0
        $tbDirSelected.Text = $lstbxDir.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Direction: " + $tbDirSelected.Text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $_.'path' -eq $lstbxDir.SelectedItems[0].text })
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        <#$global:Dest_port = $global:Live_Search | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count
        $global:Dest_IP = $global:Live_Search | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Source_IP = $global:Live_Search | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Protocol = $global:Live_Search | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count
        $global:Action = $global:Live_Search | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count
        $global:Direction = $global:Live_Search | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count#>
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        if ($lstbxDstPort.Items.Count -eq 1)
        {
            $lstbxDstPort.Items[0].Selected = $True
            $tbDstPrtSelected.Text = $lstbxDstPort.SelectedItems[0].text
            $tbIANAURL.Text = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=" + $tbDstPrtSelected.Text
            $tbSecRecURL.Text = "https://www.speedguide.net/port.php?port=" + $tbDstPrtSelected.Text
            $tbMSListURL.Text = "https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx#:~:text=List%20of%20Ports%20%20%20Port%20%20,SharePoint%20Portal%20Server%20%2043%20more%20rows%20"
            $tbWikiListURL.Text = "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
            #GetPortInfo_Click
        }
        Enable_Controls
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $tabControl.SelectedIndex = $global:SelectedTab
    }

# *********************************
# *** END of Function Dir_Click ***
# *********************************

# *******************************
# *** Function NetAdapt_Click ***
# *******************************

    Function NetAdapt_Click()
    {
        if ($global:Debug)
        {
            write-host "Function NetAdapt_Click"
        }

        #$lstbxNetAdapt.SelectedItems.text
        Update_NetConfig
    }

# **************************************
# *** END of Function NetAdapt_Click ***
# **************************************

# ******************************
# *** Function Get-PublicKey ***
# ******************************

    function Get-PublicKey
    {
        [OutputType([byte[]])]
        PARAM (
            [Uri]$Uri
        )

        if ($global:Debug)
        {
            write-host "Function Get-PublicKey($Uri)"
        }

        if (-Not ($uri.Scheme -eq "https"))
        {
            Write-Error "You can only get keys for https addresses"
            return
        }

        $request = [System.Net.HttpWebRequest]::Create($uri)

        try
        {
            #Make the request but ignore (dispose it) the response, since we only care about the service point
            $request.GetResponse().Dispose()
        }
        catch [System.Net.WebException]
        {
            if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure)
            {
                #We ignore trust failures, since we only want the certificate, and the service point is still populated at this point
            }
            else
            {
                #Let other exceptions bubble up, or write-error the exception and return from this method
                #throw
            }
        }

        #The ServicePoint object should now contain the Certificate for the site.
        $Subject = $request.ServicePoint.Certificate.Subject
        if ($Subject.length -gt 2)
        {
            $Test = @($Subject.Split(','))

            $cnt = 0

            Do
            {
                if ($Test[$cnt] -like "*O=*")
                {
                    Return $Test[$cnt]
                }
                $cnt++
            }
            while ($cnt -le $Test.count)

            $servicePoint = $request.ServicePoint
            $key = $servicePoint.Certificate.GetPublicKey()
        }
    }

# *************************************
# *** END of Function Get-PublicKey ***
# *************************************

    function IPType
    {
        PARAM (
                [string]$IPAddr
              )

        if ($global:Debug)
        {
            write-host "Function IPType($IPAddr)"
        }

        $NetLoc = "Private Network"
        if ([int]$SplitIP[0] -ne 10 -and $IPAddr -ne '127.0.0.1' -and [int]$SplitIP[0] -ne 224 -and [int]$SplitIP[0] -ne 169)
        {
            if ([int]$SplitIP[0] -eq 192 -or [int]$SplitIP[0] -eq 172)
            {
                If ([int]$SplitIP[0] -eq 192 -and [int]$SplitIP[1] -ne 168)
                {
                    $NetLoc = "Internet"
                }
                else
                {
                    If ([int]$SplitIP[0] -eq 172 -and ([int]$SplitIP[1] -lt 12 -or [int]$SplitIP[1] -gt 31))
                    {
                        $NetLoc = "Internet"
                    }
                }
            }
            else
            {
                $NetLoc = "Internet"
            }
        }
        else
        {
            if ([int]$SplitIP[0] -eq 169 -and [int]$SplitIP[1] -ne 254)
            {
                $NetLoc = "Internet"
            }
        }

        Return $NetLoc
    }

    function TelnetDisc
    {
        PARAM ([string]$PortNum,[string]$IPAddr)

        if ($global:Debug)
        {
            write-host "Function TelnetDisc($PortNum, $IPAddr)"
        }

        # Setup the Process startup info
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo 
        $pinfo.FileName = "telnet.exe" 
        $pinfo.Arguments = "-f c:\temp\telnet.log $IPAddr $PortNum" 
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true 
        $pinfo.RedirectStandardOutput = $false
        $pinfo.RedirectStandardError = $false

        # Create a process object using the startup info
        $process= New-Object System.Diagnostics.Process 
        $process.StartInfo = $pinfo

        # Start the process 
        $process.Start() | Out-Null
        # Wait a while for the process to do something 
        sleep -Seconds 5

        # If the process is still active kill it 
        if (!$process.HasExited) 
        { 
	        $process.Kill() 
        }
        $PortFunc = Get-Content -path C:\temp\telnet.log

        #Write-host "    "$PortFunction
                            
        Return $PortFunc
    }

    Function OS_Analysis
    {
        PARAM ([string]$PortFunc)

        if ($global:Debug)
        {
            write-host "Function OS_Analysis($PortFunc)"
        }

        foreach ($Distro in $global:LinuxDistros)
        {
            if ($PortFunc -like "*$Distro*")
            {
                if ($OSAnalysis.length -eq 0)
                {
                    $OSAnalysis = $Distro
                }
                else
                {
                    $OSAnalysis = $OSAnalysis + ", " + $Distro
                }
            }
        }
        Return $OSAnalysis
    }

    Function Prereqs
    {
        if ($global:Debug)
        {
            write-host "Function Prereqs"
        }

        $TelnetInstalled = get-childitem -path C:\windows\system32\ *telnet.exe -file -recurse -erroraction SilentlyContinue

        if ($TelnetInstalled.length -eq 0)
        {
            If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
            {
                #Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
                Write-Host "Administrator rights are required to install the Telnet client!"
                write-Host "Some discovery functions will not work without the Telnet client."
                Write-Host "Please re-run this program as an Administrator!"
            }
            else
            {
                $TelnetExists = Get-WindowsOptionalFeature -online -FeatureName TelnetClient


                if ($TelnetExists.count -eq 0)
                {
                    dism /online /Enable-Feature /FeatureName:TelnetClient
                }
            }
        }

        if (!(Test-Path 'c:\temp\'))
        {
            new-item -itemtype directory c:\temp
        }
        if (Test-Path 'c:\temp\telnet.log')
        {
            Remove-Item 'c:\temp\telnet.log'
        }
    }

# ****************************
# *** Function Step1_Click ***
# ****************************

    Function Step1_Click
    {
        if ($global:Debug)
        {
            write-host "Function Step1_Click"
        }

        if ($rbHRisk.Checked)
        {
            ClearInvestigation
            HighRiskInvestigation
        }
        else
        {
            if ($rbMRisk.Checked)
            {
                ClearInvestigation
            }
            else
            {
                ClearInvestigation
            }
        }
    }

# ***********************************
# *** END of Function Step1_Click ***
# ***********************************

    Function ClearInvestigation
    {
        if ($global:Debug)
        {
            write-host "Function ClearInvestigation"
        }

        $tbDirSelected.text = ""
        $tbProtoSelected.text = ""
        $tbActionSelected.text = ""
        $tbSrcIPSelected.text = ""
        $tbDstIPSelected.text = ""
        $tbDstPrtSelected.text = ""
        $lbHRiskThreatDesc.Visible = $False
        $tbHRThreatDesc.Visible = $False
        $lbHRiskInvestS2.visible = $False
        $lbHRiskInvestS2.ForeColor = "Black"
        $tbStep2LogSearch.visible = $False
        $lbHRiskInvestS3.visible = $False
        $lbHRiskInvestS3.ForeColor = "Black"
        $tbStep3NetLoc.visible = $False
        $lbHRiskInvestS4.visible = $False
        $lbHRiskInvestS4.ForeColor = "Black"
        $tbStep4DNS.visible = $False
        $lstbxInvestS5.Visible = $False
        $lbHRiskInvestS5.visible = $False
        $lbHRiskInvestS5.ForeColor = "Black"
        $lbHRiskInvestS6.Visible = $False
        $tbStep6TraceRt.Visible = $False
        $lbHRiskInvestS7.Visible = $False
        $lbHRiskInvestS7.ForeColor = "Black"
        $tbStep7IPRep.Visible = $False
        $lbHRComplete.Visible = $False
        $tbHRInvResult.Visible = $False
        ClearSearch_Click
    }

# **************************************
# *** Function HighRiskInvestigation ***
# **************************************

    Function HighRiskInvestigation()
    {
        if ($global:Debug)
        {
            write-host "Function HighRiskInvestigation"
        }

        $lbHRiskThreatDesc.Text = $lstbxHRiskSrc.SelectedItems[0].SubItems[1].text
        $lbHRiskThreatDesc.Visible = $True

        foreach ($line in $global:HRiskIssues)
        {
            If ($line.Detected_Offense -eq $lbHRiskThreatDesc.Text)
            {
                if ($line.IPType -eq "Source")
                {
                    $IPLoc = "The offending IP a source IP (High Risk)."
                }
                else
                {
                    $IPLoc = "The offending IP a destination IP (Medium Risk)."
                }
            }
        }

        foreach ($line in $global:Threats)
        {
            If ($line.ThreatName -eq $lbHRiskThreatDesc.Text)
            {
                $tbHRThreatDesc.Text = $line.ThreatDesc
                $tbHRThreatDesc.Visible = $True
            }
        }

        $IPAddr = $lstbxHRiskSrc.SelectedItems[0].text

        $tbStep2LogSearch.Text = "Searching Logs for $IPAddr..."
        $lbHRiskInvestS1.ForeColor = "White"
        $lbHRiskInvestS2.visible = $True
        $tbStep2LogSearch.visible = $True
        $tabControl.SelectedIndex = 0
        $SearchString = @($IPAddr)
        UpdateSearchCrit
        Disable_Controls
        $tbSrcIPSelected.Text = $lstbxHRiskSrc.SelectedItems[0].text
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Source IP: " + $tbSrcIPSelected.text + "...")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        #$global:Live_Search = @($global:Live_Search | Select * | where { $SearchString -contains $_.'src--ip-address' })

        $global:Live_Search = @($global:Live_Search | Select * | where { $SearchString -contains $_.'src--ip-address' })

        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False

        $lbHRiskInvestS3.visible = $True
        $tbStep3NetLoc.visible = $True
        $lbHRiskInvestS2.ForeColor = "White"
        $tbStep2LogSearch.Text = "Search for $IPAddr is complete."
        #$lbHRiskInvestS3Explain.Visible = $True
        $mainform.Refresh()

        $SplitIP = $lstbxHRiskSrc.SelectedItems[0].text.split('.')

        $global:Pingable = test-connection -computername $IPAddr -quiet -count 1

        if ($global:Pingable -eq $True)
        {
            $PingResult = " (Ping is successful.)"
            $PingStatus = "Currently online."
        }
        else
        {
            $PingResult = " (Ping is unsuccessful.)"
            $PingStatus = "Currently not online."
        }

        $NetLoc = IPType($IPAddr)
        
        $tbStep3NetLoc.Text = $NetLoc + $PingResult
        
        $tabControl.SelectedIndex = 2
        $lbHRiskInvestS4.visible = $True
        $tbStep4DNS.visible = $True
        $lbHRiskInvestS3.ForeColor = "White"
        $mainform.Refresh()
        $OffendIP = $lstbxHRiskSrc.SelectedItems[0].text
        $global:TCP_Function = @("From a command prompt, type FTP $OffendIP","Use an SSH client like putty.exe to connect.","From a command prompt, telnet $OffendIP","From a command prompt, telnet $OffendIP 25","From a browser, http://$OffendIP","Use SNMPWalk with community string of public","From a browser, https://$OffendIP","From File Explorer, type \\$OffendIP","Possible Connection Point - SQL Database Server", "From the Remote Desktop client connect to $OffendIP")

        $global:Resolvable = Resolve-DnsName $lstbxHRiskSrc.SelectedItems[0].text -ErrorAction Ignore | select -exp NameHost

        if ($global:Resolvable.Length -gt 0)
        {
            $tbStep4DNS.Text = $global:Resolvable
            $IPName = "Name is $global:Resolvable."
            #$lbHRiskInvestS4Explain.visible = $True
        }
        else
        {
            $tbStep4DNS.Text = "DNS resolution unavailable."
            $IPName = "Name is unavailable."
            #$lbHRiskInvestS4Explain.visible = $False
        }

        $lstbxInvestS5.Items.Clear()
        $lstbxInvestS5.Visible = $True
        $lbHRiskInvestS5.visible = $True
        $lbHRiskInvestS5.text = "Step 5: Scan selected IP: Please Wait: SCANNING..."
        $lbHRiskInvestS5.BackColor = "LightGray"
        #$lbHRiskInvestS5Status.visible = $True
        $lbHRiskInvestS4.ForeColor = "White"
        $LoopCount = 0

        $mainform.Refresh()
        start-sleep -Milliseconds 400

        Prereqs

        $PortAnalysis = ""

        $global:TCP_Ports.split(',') | Foreach-Object {
            
            $PortCount = $global:TCP_Ports.length
            $CurPort = $LoopCount + 1
            #$lbHRiskInvestS5Status.text = "Please Wait: Scanning Port $CurPort of $PortCount..."
            $mainform.Refresh()

            $lstbxInvestS5_Item = New-Object System.Windows.Forms.ListViewItem($_)
            $lstbxInvestS5_Item.SubItems.Add("Checking...") | Out-Null
            $lstbxInvestS5.Items.AddRange(($lstbxInvestS5_Item))

            $lstbxInvestS5.AutoResizeColumns(1)

            $Socket = New-Object Net.Sockets.TcpClient
        
            # Suppress error messages
            $ErrorActionPreference = 'SilentlyContinue'
        
            # Try to connect
            $Socket.Connect($lstbxHRiskSrc.SelectedItems[0].text, $_)
        
            # Make error messages visible again
            $ErrorActionPreference = 'Continue'
        
            # Determine if we are connected.
            if ($Socket.Connected) {
                $PortStatus = "Open"
                $PortFunction = $global:TCP_Function[$LoopCount]
                
                Switch ($_)
                {
                    "21" {
                            $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddr
                            #Write-host "    "$PortFunction -ForegroundColor Yellow
                            $PortAnalysis = OS_Analysis -PortFunc $PortFunction
                            if ($PortFunction.length -eq 0)
                            {
                                $PortFunction = "Nothing Discovered"
                            }
                            }
                    "22" {
                            $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddr
                            #Write-host "    "$PortFunction -ForegroundColor Yellow
                            $PortAnalysis = OS_Analysis -PortFunc $PortFunction
                            if ($PortFunction.length -eq 0)
                            {
                                $PortFunction = "Nothing Discovered"
                            }
                            }
                    "23" {
                            $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddr
                            #Write-host "    "$PortFunction -ForegroundColor Yellow
                            $PortAnalysis = OS_Analysis -PortFunc $PortFunction
                            if ($PortFunction.length -eq 0)
                            {
                                $PortFunction = "Nothing Discovered"
                            }
                            }
                    "25" {
                            $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddr
                            #Write-host "    "$PortFunction -ForegroundColor Yellow
                            $PortAnalysis = OS_Analysis -PortFunc $PortFunction
                            if ($PortFunction.length -eq 0)
                            {
                                $PortFunction = "Nothing Discovered"
                            }
                            }
                    "80" {
                            try
                            {
                                $Response = Invoke-WebRequest -Uri "$IPAddr/bogus.html"
                                # This will only execute if the Invoke-WebRequest is successful.
                                $StatusCode = $Response.StatusCode
                            }
                            catch
                            {
                                $StatusCode = $Error[0].ErrorDetails.Message
                            }

                            $PortFunction = $StatusCode
                            if ($PortFunction.length -eq 0)
                            {
                                $PortFunction = "Nothing Discovered"
                            }

                            $PortAnalysis = OS_Analysis -PortFunc $PortFunction
                            }
                    "443" {
                            $PortFunction = Get-PublicKey -Uri "https://$IPAddr"
                            $PortAnalysis = OS_Analysis -PortFunc $PortFunction
                            if ($PortFunction.length -eq 0)
                            {
                                $PortFunction = "Nothing Discovered"
                            }

                            }
                    "445" {$ScanType = "URG"}
                    "1433" {$ScanType = "URG"}
                    "3389" {$ScanType = "RST"}
                    "50050" {
                                #wget -U "Internet Explorer" http://$IPAddress/vl6D
                                invoke-webrequest -Uri "http://$IPAddr/vl6D"
                            }
                }

                $Socket.Close()
            }
            else {
                $PortStatus = "Closed"
                $PortFunction = ""
                #$PortFunction = $global:TCP_Function[$LoopCount]
            }
        
            # Apparently resetting the variable between iterations is necessary.
            $Socket.Dispose()
            $Socket = $null

            $lstbxInvestS5.Items.RemoveAt($LoopCount)
<#            if (($LoopCount % 2) -eq 0)
            {
                $lbHRiskInvestS5Status.ForeColor = "Yellow"
                $lbHRiskInvestS5Status.BackColor = "Blue"
            }
            else
            {
                $lbHRiskInvestS5Status.ForeColor = "Black"
                $lbHRiskInvestS5Status.BackColor = "Orange"
            }
#>
            $lstbxInvestS5_Item = New-Object System.Windows.Forms.ListViewItem($_)
            $lstbxInvestS5_Item.SubItems.Add($PortStatus) | Out-Null
            $lstbxInvestS5_Item.SubItems.Add("TCP") | Out-Null
            $lstbxInvestS5_Item.SubItems.Add($global:TCP_PortName[$LoopCount]) | Out-Null
            $lstbxInvests5_Item.SubItems.Add($PortFunction) | Out-Null
            $lstbxInvestS5.Items.AddRange(($lstbxInvestS5_Item))

            $LoopCount += 1
            $mainform.Refresh()
            start-sleep -milliseconds 200
        }

        $lstbxInvestS5.AutoResizeColumns(1)
        $lstbxInvestS5.Enabled = $True
        $lbHRiskInvestS5.text = "Step 5: Scan selected IP:"
        #$lbHRiskInvestS5Status.visible = $False
        $lbHRiskInvestS5.ForeColor = "White"
        $lbHRiskInvestS5.BackColor = "Gray"
        $lbHRiskInvestS6.Visible = $True
        $tbStep6TraceRt.Visible = $True
        $tbStep6TraceRt.Text = "Please Wait: Performing Trace Route..."

        get-netneighbor | Select IPAddress, LinkLayerAddress | where { $_.IPAddress -eq $IPAddr }

        $global:TraceRoute = @()
        tracert -d -h 20 $IPAddr | ForEach-Object{
            if ($_.Trim() -match "^\d{1,2}\s+")
            {
                $n,$a1,$a2,$a3,$target,$null = $_.Trim()-split"\s{2,}"
                $TempVar = [ordered]@{
                    Hop    = $n;
                    #First  = $a1;
                    #Second = $a2;
                    #Third  = $a3;
                    Node   = $target
                }
                $PSObject = new-object -TypeName PSObject -Property $TempVar
                $global:TraceRoute += @($PSObject)
            }
        }

        foreach ($line in $global:TraceRoute)
        {
            $NewLine += "Hop: " + $line.Hop + "     Node: " + $line.Node +"`r`n"
        }

        Switch ($global:TraceRoute.Count)
        {
            0 {$TraceData = "Unavailable"}
            1 {$TraceData = "Located on the same network as this system (Medium Risk)."}
            2 {$TraceData = "Located on a different subnet on your home network (Medium Risk)."}
        }

        $tbStep6TraceRt.Text = $NewLine
        $lbHRiskInvestS6.ForeColor = "White"
        $lbHRiskInvestS6.BackColor = "Gray"

        $mainform.Refresh()
        start-sleep -milliseconds 200

        $lbHRiskInvestS7.Visible = $True
        $tbStep7IPRep.Visible = $True
        if ($NetLoc -eq "Internet")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Checking the reputation of $IPAddr...")
            $tbStep7IPRep.Text = IP_Rep_Check -IPAddres $IPAddr
        }
        else
        {
            $tbStep7IPRep.Text = "No IP reputation available for IPs on a private network."
        }

        $lbHRiskInvestS7.ForeColor = "White"
        $lbHRiskInvestS7.BackColor = "Gray"

        $mainform.Refresh()
        start-sleep -milliseconds 100

        $FinalPortAnalysis = "Is a Linux system. Review port discovered information to possibly identify device."

        $AnalysisText = "The offending IP, $IPAddr, has the following attributes:`r`n  $IPLoc`r`n  $NetLoc`r`n  $IPName`r`n  $FinalPortAnalysis`r`n  $TraceData"

        $lbHRComplete.Visible = $True
        $tbHRInvResult.Visible = $True

        $lbHRComplete.Text = "Data Analysis:"
        $tbHRInvResult.Text = $AnalysisText
    }

# *********************************************
# *** END of Function HighRiskInvestigation ***
# *********************************************

    Function ValidLic_Click()
    {
        if ($global:Debug)
        {
            write-host "Function ValidLic_Click"
        }

        if ($tbLicOne.Text -eq ($global:LicenseKey[0]+$global:LicenseKey[1]).ToString() -and $tbLicTwo.text -eq ($global:LicenseKey[2]+$global:LicenseKey[3]).ToString() -and $tbLicThree.text -eq ($global:LicenseKey[4]+$global:LicenseKey[5]).ToString())
        {
            $btnValidLic.Text = "License Validated"
            $btnValidLic.BackColor = "Green"
            $btnValidLic.ForeColor = "White"
            $tbLicOne.ReadOnly = $True
            $tbLicOne.TabStop = $False
            $tbLicTwo.ReadOnly = $True
            $tbLicTwo.TabStop = $False
            $tbLicThree.ReadOnly = $True
            $tbLicThree.TabStop = $False
            New-Item –Path "HKLM:\SOFTWARE\Microsoft" –Name WinFWMon
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WinFWMon" -Name "LicenseKey1" -Value $tbLicOne.Text  -PropertyType "String"
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WinFWMon" -Name "LicenseKey2" -Value $tbLicTwo.Text  -PropertyType "String"
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WinFWMon" -Name "LicenseKey3" -Value $tbLicThree.Text  -PropertyType "String"
            $ttValidLic.SetToolTip($btnValidLic, "Validate License Key is Valid")
        }
        else
        {
            $btnValidLic.Text = "Invalid License Key"
            $btnValidLic.BackColor = "Red"
            $btnValidLic.ForeColor = "White"
            $ttValidLic.SetToolTip($btnValidLic, "Validate License Key")
        }
    }

    Function ClearSearch_Click()
    {
        if ($global:Debug)
        {
            write-host "Function ClearSearch_Click"
        }

        $tabControl.SelectedIndex = 0
        $LogTab.backcolor = "Lightgray"
        $lbLog.ForeColor = "black"
        $lbStats.ForeColor = "black"
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        $global:GridInfo = @()
        $global:Live_Search = @()
        $global:FWLogInfo = @()
        $tbDstPrtSelected.text = "Searching..."
        $tbDstIPSelected.text = "Searching..."
        $tbSrcIPSelected.text = "Searching..."
        $tbActionSelected.text = "Searching..."
        $tbProtoSelected.text = "Searching..."
        $tbDirSelected.text = "Searching..."
        $btnClearSearch.Text = "Searching..."
        Update_Controls($global:Live_Search)
        Disable_controls
        $global:FWLogInfo = Get_FW_Logs
        $global:Live_Search = $global:FWLogInfo
        SearchJobs
        $tbDstPrtSelected.text = ""
        $tbDstIPSelected.text = ""
        $tbSrcIPSelected.text = ""
        $tbActionSelected.text = ""
        $tbProtoSelected.text = ""
        $tbDirSelected.text = ""
        #$tbSecRec.Text = ""
        #$tbTCPInv.Text = ""
        #$tbUDPInv.Text = ""
        #$tbIANAInv.Text = ""
        #$tbDescInv.Text = ""
        #$lbTCPInv.Text = "TCP"
        #$lbUDPInv.Text = "UDP"
        #$lbDescInv.Text = "Port Description"
        #$lbSecRec.Text = "Port Security Information"
        #$tbIANAURL.Text = ""
        #$tbSecRecURL.Text = ""
        #$tbMSListURL.Text = ""
        #$tbWikiListURL.Text = ""
        Port_Scan_Detect
        Internet_IPs -IPType "Source"
        Internet_IPs -IPType "Destination"
        LowRisk_Check
        Update_Controls(@())
        Enable_controls
        #$btnAllTrafTo.Enabled = $False
        #$btnAllTrafFrom.Enabled = $False
        $btnClearSearch.Text = "&Get Latest Log"
        $btnClearDstPrt.Enabled = $False
        $btnClearDstPrt.BackColor = "LightGray"
        $btnClearDstPrt.ForeColor = "Black"
        $btnClearDstIP.Enabled = $False
        $btnClearDstIP.BackColor = "LightGray"
        $btnClearDstIP.ForeColor = "Black"
        $btnClearSrcIP.Enabled = $False
        $btnClearSrcIP.BackColor = "LightGray"
        $btnClearSrcIP.ForeColor = "Black"
        $btnClearAction.Enabled = $False
        $btnClearAction.BackColor = "LightGray"
        $btnClearAction.ForeColor = "Black"
        $btnClearProto.Enabled = $False
        $btnClearProto.BackColor = "LightGray"
        $btnClearProto.ForeColor = "Black"
    }

    Function MSClient_Click()
    {
        if ($global:Debug)
        {
            write-host "Function MSClient_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_msclient" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnMSClient.text = "Enabling Client for Microsoft Networks..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_msclient" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_msclient
            $btnMSClient.text = "Client for Microsoft Networks: Enabled"
            $btnMSClient.BackColor = "green"
            $btnMSClient.forecolor = "white"
            $ttMSClient.SetToolTip($btnMSClient, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnMSClient.text = "Disabling Client for Microsoft Networks..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_msclient" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_msclient
            $btnMSClient.text = "Client for Microsoft Networks: Disabled"
            $btnMSClient.BackColor = "red"
            $btnMSClient.forecolor = "white"
            $ttMSClient.SetToolTip($btnMSClient, "Enable this service => Recommended. See Guidance Button.")
        }
    }

    Function MSClient_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function MSClient_Info_Click"
        }

        $tbNetDecision.Text = $global:MSClientInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function MSServer_Click()
    {
        if ($global:Debug)
        {
            write-host "Function MSServer_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_server" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnMSServer.text = "Enabling File and Printer Sharing for Microsoft Networks..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_server" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_server
            $btnMSServer.text = "File and Printer Sharing for Microsoft Networks: Enabled"
            $btnMSServer.BackColor = "orange"
            $btnMSServer.forecolor = "white"
            $ttMSServer.SetToolTip($btnMSServer, "Enable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnMSServer.text = "Disabling File and Printer Sharing for Microsoft Networks..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_server" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_server
            $btnMSServer.text = "File and Printer Sharing for Microsoft Networks: Disabled"
            $btnMSServer.BackColor = "green"
            $btnMSServer.forecolor = "white"
            $ttMSServer.SetToolTip($btnMSServer, "Disable this service => Recommended. See Guidance Button.")
        }
    }

    Function MSServer_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function MSServer_Info_Click"
        }

        $tbNetDecision.Text = $global:MSServerInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function QoS_Click()
    {
        if ($global:Debug)
        {
            write-host "Function QoS_Click"
        }

        $ServiceState = get-netadapterbinding | Select ComponentID, Enabled | where { $_.Name -eq $lstbxNetAdapt.SelectedItems.text -and $_.ComponentID -eq "ms_pacer" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnQoS.text = "Enabling QoS Packet Scheduler..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select ComponentID, Enabled, Name | where { $_.ComponentID -eq "ms_pacer" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_pacer
            $btnQoS.text = "QoS Packet Scheduler: Enabled"
            $btnQoS.BackColor = "red"
            $btnQoS.forecolor = "white"
            $ttQoS.SetToolTip($btnQoS, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnQoS.text = "Disabling QoS Packet Scheduler..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select ComponentID, Enabled, Name | where { $_.ComponentID -eq "ms_pacer" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_pacer
            $btnQoS.text = "QoS Packet Scheduler: Disabled"
            $btnQoS.BackColor = "green"
            $btnQoS.forecolor = "white"
            $ttQoS.SetToolTip($btnQoS, "Enable this service => Not Recommended. See Guidance Button.")
        }
    }

    Function QoS_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function QoS_Info_Click"
        }

        $tbNetDecision.Text = $global:QoSInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function IPv4_Click()
    {
        if ($global:Debug)
        {
            write-host "Function IPv4_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnIPv4.text = "Enabling Internet Protocol Version 4 (TCP/IPv4)..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_tcpip
            $btnIPv4.text = "Internet Protocol Version 4 (TCP/IPv4): Enabled"
            $btnIPv4.BackColor = "green"
            $btnIPv4.forecolor = "white"
            $ttIPv4.SetToolTip($btnIPv4, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnIPv4.text = "Disabling Internet Protocol Version 4 (TCP/IPv4)..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_tcpip
            $btnIPv4.text = "Internet Protocol Version 4 (TCP/IPv4): Disabled"
            $btnIPv4.BackColor = "red"
            $btnIPv4.forecolor = "white"
            $ttIPv4.SetToolTip($btnIPv4, "Enable this service => Recommended. See Guidance Button.")
        }
    }

    Function IPv4_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function IPv4_Info_Click"
        }

        $tbNetDecision.Text = $global:IPv4Info
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function Multiplexor_Click()
    {
        if ($global:Debug)
        {
            write-host "Function Multiplexor_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_implat" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnMultiplexor.text = "Enabling Microsoft Network Adapter Multiplexor Protocol..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_implat" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_implat
            $btnMultiplexor.text = "Microsoft Network Adapter Multiplexor Protocol: Enabled"
            $btnMultiplexor.BackColor = "red"
            $btnMultiplexor.forecolor = "white"
            $ttMultiplexor.SetToolTip($btnMultiplexor, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnMultiplexor.text = "Disabling Microsoft Network Adapter Multiplexor Protocol..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_implat" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_implat
            $btnMultiplexor.text = "Microsoft Network Adapter Multiplexor Protocol: Disabled"
            $btnMultiplexor.BackColor = "green"
            $btnMultiplexor.forecolor = "white"
            $ttMultiplexor.SetToolTip($btnMultiplexor, "Enable this service => Not Recommended. See Guidance Button.")
        }
    }

    Function Multiplexor_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function Multiplexor_Info_Click"
        }

        $tbNetDecision.Text = $global:MultiplexorInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function LLDP_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LLDP_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled | where { $_.ComponentID -eq "ms_lldp" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnLLDP.text = "Enabling Microsoft LLDP Protocol Driver..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled | where { $_.ComponentID -eq "ms_lldp" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_lldp
            $btnLLDP.text = "Microsoft LLDP Protocol Driver: Enabled"
            $btnLLDP.BackColor = "red"
            $btnLLDP.forecolor = "white"
            $ttLLDP.SetToolTip($btnLLDP, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnLLDP.text = "Disabling Microsoft LLDP Protocol Driver..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled | where { $_.ComponentID -eq "ms_lldp" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_lldp
            $btnLLDP.text = "Microsoft LLDP Protocol Driver: Disabled"
            $btnLLDP.BackColor = "green"
            $btnLLDP.forecolor = "white"
            $ttLLDP.SetToolTip($btnLLDP, "Enable this service => Not Recommended. See Guidance Button.")
        }
    }

    Function LLDP_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LLDP_Info_Click"
        }

        $tbNetDecision.Text = $global:LLDPInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function IPv6_Click()
    {
        if ($global:Debug)
        {
            write-host "Function IPv6_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip6" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnIPv6.text = "Enabling Internet Protocol Version 6 (TCP/IPv6)..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip6" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_tcpip6
            $btnIPv6.text = "Internet Protocol Version 6 (TCP/IPv6): Enabled"
            $btnIPv6.BackColor = "orange"
            $btnIPv6.forecolor = "white"
            $ttIPv6.SetToolTip($btnIPv6, "Disable this service => Recommended. See Guidance Button.")
        }
        else
        {
            $btnIPv6.text = "Disabling Internet Protocol Version 6 (TCP/IPv6)..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_tcpip6" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_tcpip6
            $btnIPv6.text = "Internet Protocol Version 6 (TCP/IPv6): Disabled"
            $btnIPv6.BackColor = "green"
            $btnIPv6.forecolor = "white"
            $ttIPv6.SetToolTip($btnIPv6, "Enable this service => Not Recommended. See Guidance Button.")
        }
    }

    Function IPv6_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function IPv6_Info_Click"
        }

        $tbNetDecision.Text = $global:IPv6Info
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function LLTD_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LLTD_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_rspndr" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnLLTD.text = "Enabling Link-Layer Topology Discovery Responder..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_rspndr" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_rspndr
            $btnLLTD.text = "Link-Layer Topology Discovery Responder: Enabled"
            $btnLLTD.BackColor = "orange"
            $btnLLTD.forecolor = "white"
            $ttLLTD.SetToolTip($btnLLTD, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnLLTD.text = "Disabling Link-Layer Topology Discovery Responder..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_rspndr" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_rspndr
            $btnLLTD.text = "Link-Layer Topology Discovery Responder: Disabled"
            $btnLLTD.BackColor = "green"
            $btnLLTD.forecolor = "white"
            $ttLLTD.SetToolTip($btnLLTD, "Enable this service => Recommended. See Guidance Button.")
        }
    }

    Function LLTD_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LLTD_Info_Click"
        }

        $tbNetDecision.Text = $global:LLTDInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function LLTDMapper_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LLTDMapper_Click"
        }

        $ServiceState = get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_lltdio" }
        if ($ServiceState.Enabled -eq $False)
        {
            $btnLLTDMapper.text = "Enabing Link-Layer Topology Discovery Mapper I/O Driver..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_lltdio" } | Enable-NetAdapterBinding
            Enable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_lltdio
            $btnLLTDMapper.text = "Link-Layer Topology Discovery Mapper I/O Driver: Enabled"
            $btnLLTDMapper.BackColor = "orange"
            $btnLLTDMapper.forecolor = "white"
            $ttLLTDMapper.SetToolTip($btnLLTDMapper, "Disable this service => Not Recommended. See Guidance Button.")
        }
        else
        {
            $btnLLTDMapper.text = "Disabing Link-Layer Topology Discovery Mapper I/O Driver..."
            $mainform.Refresh()
            #get-netadapter | select InterfaceAlias | where { $_.InterfaceAlias -eq $lstbxNetAdapt.SelectedItems.text} | get-netadapterbinding | Select Name, ComponentID, Enabled, DisplayName | where { $_.ComponentID -eq "ms_lltdio" } | Disable-NetAdapterBinding
            Disable-NetAdapterBinding -Name $lstbxNetAdapt.SelectedItems.text -ComponentID ms_lltdio
            $btnLLTDMapper.text = "Link-Layer Topology Discovery Mapper I/O Driver: Disabled"
            $btnLLTDMapper.BackColor = "green"
            $btnLLTDMapper.forecolor = "white"
            $ttLLTDMapper.SetToolTip($btnLLTDMapper, "Enable this service => Recommended. See Guidance Button.")
        }
    }

    Function LLTDMapper_Info_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LLTDMapper_Info_Click"
        }

        $tbNetDecision.Text = $global:LLTDMapperInfo
        $tbNetDecision.SelectionStart = 0
        $tbNetDecision.ScrollToCaret()
    }

    Function btnAllTrafTo_Click()
    {
        if ($global:Debug)
        {
            write-host "Function btnAllTrafTo_Click"
        }

        $tabControl.SelectedIndex = 0
        $IPAddrCount = $global:IPInfo.count
        if ($global:IPInfo.count -gt 1)
        {
            $tbDstIPSelected.Text = ""
            for ($i=0;$i -lt $IPAddrCount; $i++)
            {
                $IPAddr = $global:IPInfo[$i].IP_Address
                if ($i -eq ($IPAddrCount-1))
                {
                    $tbDstIPSelected.Text = $tbDstIPSelected.Text + $IPAddr
                }
                else
                {
                    $tbDstIPSelected.Text = $tbDstIPSelected.Text + $IPAddr + " or "
                }
                $SearchString += @($IPAddr)
            }
        }
        else
        {
            $IPAddr = $global:IPInfo.IP_Address
            $tbDstIPSelected.Text = $IPAddr
            $SearchString = @($IPAddr)
        }
        #$tbDstIPSelected.Text = $lstbxDstIP.SelectedItems[0].text
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Destination IP: " + $tbDstIPSelected.text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        #$global:Live_Search = @($global:Live_Search | Select * | where { $_.'dst--ip-address' -eq $tbDstIPSelected.Text })
        #$global:Live_Search = @($global:Live_Search | Select * | where { $_.'dst--ip-address' -contains $SearchString })
        $global:Live_Search = @($global:Live_Search | Select * | where { $SearchString -contains $_.'dst--ip-address' })
        #$tbSrcIPSelected.Text = $lstbxSrcIP.SelectedItems[0].text
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        <#$global:Dest_port = $global:Live_Search | Group-Object -Property 'dst-port' | Sort Count -Descending | Select Name, Count
        $global:Dest_IP = $global:Live_Search | Group-Object -Property 'dst--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Source_IP = $global:Live_Search | Group-Object -Property 'src--ip-address' | Sort Count -Descending | Select Name, Count
        $global:Protocol = $global:Live_Search | Group-Object -Property 'protocol' | Sort Count -Descending | Select Name, Count
        $global:Action = $global:Live_Search | Group-Object -Property 'action' | Sort Count -Descending | Select Name, Count
        $global:Direction = $global:Live_Search | Group-Object -Property 'path' | Sort Count -Descending | Select Name, Count#>
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $btnClearDstIP.Enabled = $True
        $btnClearDstIP.BackColor = "Red"
        $btnClearDstIP.ForeColor = "White"
    }

    Function btnAllTrafFrom_Click()
    {
        if ($global:Debug)
        {
            write-host "Function btnAllTrafFrom_Click"
        }

        $tabControl.SelectedIndex = 0
        $IPAddrCount = $global:IPInfo.count
        if ($global:IPInfo.count -gt 1)
        {
            $tbSrcIPSelected.Text = ""
            for ($i=0;$i -lt $IPAddrCount; $i++)
            {
                $IPAddr = $global:IPInfo[$i].IP_Address
                if ($i -eq ($IPAddrCount-1))
                {
                    $tbSrcIPSelected.Text = $tbSrcIPSelected.Text + $IPAddr
                }
                else
                {
                    $tbSrcIPSelected.Text = $tbSrcIPSelected.Text + $IPAddr + " or "
                }
                $SearchString += @($IPAddr)
            }
        }
        else
        {
            $IPAddr = $global:IPInfo.IP_Address
            $tbSrcIPSelected.Text = $IPAddr
            $SearchString = @($IPAddr)
        }
        UpdateSearchCrit
        Disable_Controls
        $tbAppLog.AppendText((get-date).ToString() + ": Searching for Source IP: " + $tbSrcIPSelected.text + "...")
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $global:Live_Search = @($global:Live_Search | Select * | where { $SearchString -contains $_.'src--ip-address' })
        $global:Dest_port = @()
        $global:Dest_IP = @()
        $global:Source_IP = @()
        $global:Protocol = @()
        $global:Action = @()
        $global:Direction = @()
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        SearchJobs
        UpdateSearchCrit
        Update_Controls($global:Live_Search)
        $btnClearSearch.Text = "&Clear Search"
        Enable_Controls
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafFrom.Enabled = $False
        $btnClearSrcIP.Enabled = $True
        $btnClearSrcIP.BackColor = "Red"
        $btnClearSrcIP.ForeColor = "White"
    }

    Function DomState_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DomState_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls

        if ($btnDomState.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Domain Firewall...")
            set-netfirewallprofile -policystore localhost -name domain -Enabled False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Domain Firewall...")
            set-netfirewallprofile -policystore localhost -name domain -Enabled True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PrivState_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PrivState_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls

        if ($btnPrivState.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Private Firewall...")
            set-netfirewallprofile -policystore localhost -name private -Enabled False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Private Firewall...")
            set-netfirewallprofile -policystore localhost -name private -Enabled True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PubState_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PubState_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPubState.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Public Firewall...")
            set-netfirewallprofile -policystore localhost -name public -Enabled False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Public Firewall...")
            set-netfirewallprofile -policystore localhost -name public -Enabled True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function ProfAll_Click()
    {
        if ($global:Debug)
        {
            write-host "Function ProfAll_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnProfAll.Text -eq "Disable All")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Firewall...")
            set-netfirewallprofile -policystore localhost -all -Enabled False
            $btnProfAll.Text = "Enable All"
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Firewall...")
            set-netfirewallprofile -policystore localhost -all -Enabled True
            $btnProfAll.Text = "Disable All"
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        ProfileState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DomLogAllow_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DomLogAllow_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDLogAllow.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Domain Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -name domain -LogAllowed False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Domain Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -name domain -LogAllowed True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogAllowState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PrivLogAllow_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PrivLogAllow_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPrLogAllow.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Private Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -name private -LogAllowed False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Private Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -name private -LogAllowed True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogAllowState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PubLogAllow_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PubLogAllow_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPuLogAllow.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Public Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -name public -LogAllowed False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Public Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -name public -LogAllowed True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogAllowState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function LogAllowAll_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LogAllowAll_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnLogAllowAll.Text -eq "DISABLE ALL")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -all -LogAllowed False
            $btnLogAllowAll.Text = "ENABLE ALL"
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Logging of Allowed Communications...")
            set-netfirewallprofile -policystore localhost -all -LogAllowed True
            $btnLogAllowAll.Text = "DISABLE ALL"
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogAllowState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DomLogDrop_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DomLogDrop_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDLogDrop.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Domain Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -name domain -LogBlocked False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Domain Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -name domain -LogBlocked True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogDropState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PrivLogDrop_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PrivLogDrop_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPrLogDrop.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Private Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -name private -LogBlocked False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Private Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -name private -LogBlocked True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogDropState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PubLogDrop_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PubLogDrop_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPuLogDrop.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Public Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -name public -LogBlocked False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Public Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -name public -LogBlocked True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogDropState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function LogDropAll_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LogDropAll_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnLogDropAll.Text -eq "DISABLE ALL")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -all -LogBlocked False
            $btnLogDropAll.Text = "ENABLE ALL"
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Logging of Blocked Communications...")
            set-netfirewallprofile -policystore localhost -all -LogBlocked True
            $btnLogDropAll.Text = "DISABLE ALL"
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogDropState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DomLogIgnore_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DomLogIgnore_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDLogIgnore.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Domain Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -name domain -LogIgnored False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Domain Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -name domain -LogIgnored True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogIgnoreState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PrivLogIgnore_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PrivLogIgnore_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPrLogIgnore.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Private Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -name private -LogIgnored False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Private Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -name private -LogIgnored True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogIgnoreState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PubLogIgnore_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PubLogIgnore_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPuLogIgnore.Text -eq "YES")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Public Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -name public -LogIgnored False
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Public Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -name public -LogIgnored True
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogIgnoreState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function LogIgnoreAll_Click()
    {
        if ($global:Debug)
        {
            write-host "Function LogIgnoreAll_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnLogIgnoredAll.Text -eq "DISABLE ALL")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Disabling Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -all -LogIgnored False
            $btnLogIgnoredAll.Text = "ENABLE ALL"
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Enabling Logging of Ignored Communications...")
            set-netfirewallprofile -policystore localhost -all -LogIgnored True
            $btnLogIgnoredAll.Text = "DISABLE ALL"
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        LogIgnoreState
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DomDefInb_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DomDefInb_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDDefInb.Text -eq "BLK")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Domain Default Inbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -name domain -DefaultInboundAction Allow
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Domain Default Inbound Action to Block...")
            set-netfirewallprofile -policystore localhost -name domain -DefaultInboundAction Block
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefInbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PrivDefInb_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PrivDefInb_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPrDefInb.Text -eq "BLK")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Private Default Inbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -name private -DefaultInboundAction Allow
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Private Default Inbound Action to Block...")
            set-netfirewallprofile -policystore localhost -name private -DefaultInboundAction Block
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefInbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PubDefInb_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PubDefInb_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPuDefInb.Text -eq "BLK")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Public Default Inbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -name public -DefaultInboundAction Allow
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing PublicDefault Inbound Action to Block...")
            set-netfirewallprofile -policystore localhost -name public -DefaultInboundAction Block
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefInbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DefInbAll_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DefInbAll_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDefInbAll.Text -eq "ALLOW ALL")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Default Inbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -all -DefaultInboundAction Allow
            $btnDefInbAll.Text = "ALLOW ALL"
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Default Inbound Action to Block...")
            set-netfirewallprofile -policystore localhost -all -DefaultInboundAction Block
            $btnDefInbAll.Text = "BLOCK ALL"
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefInbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DomDefOutb_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DomDefOutb_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDDefOutb.Text -eq "BLK")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Domain Default Outbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -name domain -DefaultOutboundAction Allow
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Domain Default Outbound Action to Block...")
            set-netfirewallprofile -policystore localhost -name domain -DefaultOutboundAction Block
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefOutbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PrivDefOutb_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PrivDefOutb_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPrDefOutb.Text -eq "BLK")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Private Default Outbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -name private -DefaultOutboundAction Allow
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Private Default Outbound Action to Block...")
            set-netfirewallprofile -policystore localhost -name private -DefaultOutboundAction Block
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefOutbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function PubDefOutb_Click()
    {
        if ($global:Debug)
        {
            write-host "Function PubDefOutb_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnPuDefOutb.Text -eq "BLK")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Public Default Outbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -name public -DefaultOutboundAction Allow
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Public Default Outbound Action to Block...")
            set-netfirewallprofile -policystore localhost -name public -DefaultOutboundAction Block
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefOutbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function DefOutbAll_Click()
    {
        if ($global:Debug)
        {
            write-host "Function DefOutbAll_Click"
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
    
        Disable_Controls
    
        if ($btnDefOutbAll.Text -eq "ALLOW ALL")
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Default Outbound Action to Allow...")
            set-netfirewallprofile -policystore localhost -all -DefaultOutboundAction Allow
            $btnDefOutbAll.Text = "ALLOW ALL"
        }
        else
        {
            $tbAppLog.AppendText((get-date).ToString() + ": Changing Default Outbound Action to Block...")
            set-netfirewallprofile -policystore localhost -all -DefaultOutboundAction Block
            $btnDefOutbAll.Text = "BLOCK ALL"
        }
        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $tbAppLog.AppendText((get-date).ToString() + ": Applying Group Policy...")
        gpupdate /force
        DefOutbAction
        Enable_controls

        $timer.Stop()
        $LoadTime = $timer.Elapsed
        $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
        $tbAppLog.AppendText("Completed. ($ElapsedTime seconds)`r`n")
        $tbAppLog.AppendText("Ready`r`n")
    }

    Function RiskSelected_Click
    {
        if ($global:Debug)
        {
            write-host "Function RiskSelected_Click"
        }

        if ($rbHRisk.Checked)
        {
            ClearInvestigation
            $lstbxHRiskSrc.Items.Clear()
            foreach($line in $global:HRiskIssues)
            {
                $lstbxHRiskSrc_Item = New-Object System.Windows.Forms.ListViewItem($line.Detected_IP)
                $lstbxHRiskSrc_Item.SubItems.Add($line.Detected_Offense) | Out-Null
                $lstbxHRiskSrc.Items.AddRange(($lstbxHRiskSrc_Item))
            }

            $lstbxHRiskSrc.AutoResizeColumns(1)
            $lstbxHRiskSrc.Enabled = $True
            $lstbxHRiskSrc.Visible = $True
            $lbHRiskInvestS1.Visible = $True
        }
        else
        {
            if ($rbMRisk.Checked)
            {
                ClearInvestigation
                $lstbxHRiskSrc.Items.Clear()
                foreach($line in $global:MRiskIssues)
                {
                    $lstbxHRiskSrc_Item = New-Object System.Windows.Forms.ListViewItem($line.Detected_IP)
                    $lstbxHRiskSrc_Item.SubItems.Add($line.Detected_Offense) | Out-Null
                    $lstbxHRiskSrc.Items.AddRange(($lstbxHRiskSrc_Item))
                }

                $lstbxHRiskSrc.AutoResizeColumns(1)
                $lstbxHRiskSrc.Enabled = $True
                $lstbxHRiskSrc.Visible = $True
                $lbHRiskInvestS1.Visible = $True
            }
            else
            {
                
                ClearInvestigation
                if ($rbLRisk.Checked)
                {
                    $lstbxHRiskSrc.Items.Clear()
                    foreach($line in $global:LRiskIssues)
                    {
                        $lstbxHRiskSrc_Item = New-Object System.Windows.Forms.ListViewItem($line.Detected_IP)
                        $lstbxHRiskSrc_Item.SubItems.Add($line.Detected_Offense) | Out-Null
                        $lstbxHRiskSrc.Items.AddRange(($lstbxHRiskSrc_Item))
                    }

                    $lstbxHRiskSrc.AutoResizeColumns(1)
                    $lstbxHRiskSrc.Enabled = $True
                    $lstbxHRiskSrc.Visible = $True
                    $lbHRiskInvestS1.Visible = $True
                }
                else
                {

                }
            }
        }
    }

# ******************************************************************************************************************************************************
# *** END of Internal Form Functions                                                                                                                 ***
# ******************************************************************************************************************************************************

# ***********************************
# *** Generate Main Form Function ***
# ***********************************

    Function GenerateMainForm()
    {
        if ($global:Debug)
        {
            write-host "Function GenerateMainForm"
        }

        #[Void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.Application]::EnableVisualStyles()

    # Form Sizing Variables
        $ListView_Width = 175
        $ListView_Height = 21
        $ListView_HSpace = 180
        $global:BtnWidth = 133
        $global:BtnHeight = 25
        $ListView_Height2 = 134

    # Form Definition
        $mainform = New-Object Windows.Forms.Form
        $mainform.text = "Windows Firewall Analyzer $global:FWMVersion (UNLICENSED)"
        $mainform.Size = New-Object Drawing.Point 1333, 876
        $mainform.topmost = 0
        $mainform.FormBorderStyle = "Sizable"
        $mainform.BackColor = "darkgray"
        $mainform.AutoSize
        $mainform.AutoScroll = $True
        $mainform.StartPosition = "CenterScreen"
        $mainform.Icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")

    # Program Status
        $ProgramStatus_Panel = New-Object Windows.Forms.Panel
        $ProgramStatus_Panel.height = 154
        $ProgramStatus_Panel.width = 133
        $ProgramStatus_Panel.location = New-Object System.Drawing.Point(1180,5)
        $ProgramStatus_Panel.BackColor = "gray"
        #$ProgramStatus_Panel.SendToBack()

        $tbProgStatusTitle = New-Object System.Windows.Forms.TextBox
        $tbProgStatusTitle.Text = "Program Status"
        $tbProgStatusTitle.ForeColor = "Black"
        $tbProgStatusTitle.BackColor = "cyan"
        $tbProgStatusTitle.Location = New-Object Drawing.Point 3,2
        $tbProgStatusTitle.AutoSize = $False
        $tbProgStatusTitle.size = New-Object Drawing.Point 127,20
        $tbProgStatusTitle.IsAccessible = $false
        $tbProgStatusTitle.Font = New-Object Drawing.Font('Arial Bold',10)
        $tbProgStatusTitle.TextAlign = 2
        $tbProgStatusTitle.ReadOnly = $True
        $tbProgStatusTitle.TabStop = $False
        #$tbProgStatusTitle.BringToFront()
        $tbProgStatusTitle.ReadOnly = $True
        $tbProgStatusTitle.TabStop = $False
        #$tbProgStatusTitle.Enabled = $False

        $tbLicenseStatus = New-Object System.Windows.Forms.TextBox
        $tbLicenseStatus.Text = "Verifying Licensing..."
        $tbLicenseStatus.ForeColor = "Black"
        $tbLicenseStatus.BackColor = "Gray"
        $tbLicenseStatus.Location = New-Object Drawing.Point 3,22
        $tbLicenseStatus.AutoSize = $False
        $tbLicenseStatus.size = New-Object Drawing.Point 127,20
        $tbLicenseStatus.IsAccessible = $false
        $tbLicenseStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbLicenseStatus.TextAlign = 2
        $tbLicenseStatus.ReadOnly = $True
        $tbLicenseStatus.TabStop = $False
        #$tbLicenseStatus.BringToFront()
        $tbLicenseStatus.ReadOnly = $True
        $tbLicenseStatus.TabStop = $False
        #$tbLicenseStatus.Enabled = $False
        
        $tbAdminStatus = New-Object System.Windows.Forms.TextBox
        $tbAdminStatus.Text = "Verifying Admin..."
        $tbAdminStatus.ForeColor = "Black"
        $tbAdminStatus.BackColor = "Gray"
        $tbAdminStatus.Location = New-Object Drawing.Point 3,44
        $tbAdminStatus.AutoSize = $False
        $tbAdminStatus.size = New-Object Drawing.Point 127,20
        $tbAdminStatus.IsAccessible = $false
        $tbAdminStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbAdminStatus.TextAlign = 2
        $tbAdminStatus.ReadOnly = $True
        $tbAdminStatus.TabStop = $False
        #$tbAdminStatus.BringToFront()
        $tbAdminStatus.ReadOnly = $True
        $tbAdminStatus.TabStop = $False
        #$tbAdminStatus.Enabled = $False
        
        $tbInternetStatus = New-Object System.Windows.Forms.TextBox
        $tbInternetStatus.Text = "Verifying Internet..."
        $tbInternetStatus.ForeColor = "Black"
        $tbInternetStatus.BackColor = "Gray"
        $tbInternetStatus.Location = New-Object Drawing.Point 3,66
        $tbInternetStatus.AutoSize = $False
        $tbInternetStatus.size = New-Object Drawing.Point 127,20
        $tbInternetStatus.IsAccessible = $false
        $tbInternetStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbInternetStatus.TextAlign = 2
        $tbInternetStatus.ReadOnly = $True
        $tbInternetStatus.TabStop = $False
        #$tbInternetStatus.BringToFront()
        $tbInternetStatus.ReadOnly = $True
        $tbInternetStatus.TabStop = $False
        #$tbInternetStatus.Enabled = $False

        $tbLogFileStatus = New-Object System.Windows.Forms.TextBox
        $tbLogFileStatus.Text = "Verifying Log Files..."
        $tbLogFileStatus.ForeColor = "Black"
        $tbLogFileStatus.BackColor = "Gray"
        $tbLogFileStatus.Location = New-Object Drawing.Point 3,88
        $tbLogFileStatus.AutoSize = $False
        $tbLogFileStatus.size = New-Object Drawing.Point 127,20
        $tbLogFileStatus.IsAccessible = $false
        $tbLogFileStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbLogFileStatus.TextAlign = 2
        $tbLogFileStatus.ReadOnly = $True
        $tbLogFileStatus.TabStop = $False
        #$tbLogFileStatus.BringToFront()
        $tbLogFileStatus.ReadOnly = $True
        $tbLogFileStatus.TabStop = $False
        #$tbLogFileStatus.Enabled = $False
        
        $tbLoggingStatus = New-Object System.Windows.Forms.TextBox
        $tbLoggingStatus.Text = "Verifying Logging..."
        $tbLoggingStatus.ForeColor = "Black"
        $tbLoggingStatus.BackColor = "Gray"
        $tbLoggingStatus.Location = New-Object Drawing.Point 3,110
        $tbLoggingStatus.AutoSize = $False
        $tbLoggingStatus.size = New-Object Drawing.Point 127,20
        $tbLoggingStatus.IsAccessible = $false
        $tbLoggingStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbLoggingStatus.TextAlign = 2
        $tbLoggingStatus.ReadOnly = $True
        $tbLoggingStatus.TabStop = $False
        #$tbLoggingStatus.BringToFront()
        $tbLoggingStatus.ReadOnly = $True
        $tbLoggingStatus.TabStop = $False
        #$tbLoggingStatus.Enabled = $False

        $tbHighStatus = New-Object System.Windows.Forms.TextBox
        $tbHighStatus.Text = "High"
        $tbHighStatus.ForeColor = "Black"
        $tbHighStatus.BackColor = "Gray"
        $tbHighStatus.Location = New-Object Drawing.Point 3,132
        $tbHighStatus.AutoSize = $False
        $tbHighStatus.size = New-Object Drawing.Point 39,20
        $tbHighStatus.IsAccessible = $false
        $tbHighStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbHighStatus.TextAlign = 2
        $tbHighStatus.ReadOnly = $True
        $tbHighStatus.TabStop = $False
        #$tbHighStatus.BringToFront()
        $tbHighStatus.ReadOnly = $True
        $tbHighStatus.TabStop = $False
        #$tbHighStatus.Enabled = $False

        $tbMedStatus = New-Object System.Windows.Forms.TextBox
        $tbMedStatus.Text = "Med"
        $tbMedStatus.ForeColor = "Black"
        $tbMedStatus.BackColor = "Gray"
        $tbMedStatus.Location = New-Object Drawing.Point 45,132
        $tbMedStatus.AutoSize = $False
        $tbMedStatus.size = New-Object Drawing.Point 43,20
        $tbMedStatus.IsAccessible = $false
        $tbMedStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbMedStatus.TextAlign = 2
        $tbMedStatus.ReadOnly = $True
        $tbMedStatus.TabStop = $False
        #$tbMedStatus.BringToFront()
        $tbMedStatus.ReadOnly = $True
        $tbMedStatus.TabStop = $False
        #$tbMedStatus.Enabled = $False

        $tbLowStatus = New-Object System.Windows.Forms.TextBox
        $tbLowStatus.Text = "Low"
        $tbLowStatus.ForeColor = "Black"
        $tbLowStatus.BackColor = "Gray"
        $tbLowStatus.Location = New-Object Drawing.Point 91,132
        $tbLowStatus.AutoSize = $False
        $tbLowStatus.size = New-Object Drawing.Point 39,20
        $tbLowStatus.IsAccessible = $false
        $tbLowStatus.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbLowStatus.TextAlign = 2
        $tbLowStatus.ReadOnly = $True
        $tbLowStatus.TabStop = $False
        #$tbLowStatus.BringToFront()
        $tbLowStatus.ReadOnly = $True
        $tbLowStatus.TabStop = $False
        #$tbHighStatus.Enabled = $False
    # End of Program Status

    # Search Area (Listviews)
        $lstbxDstPort = New-Object System.Windows.Forms.Listview
        $lstbxDstPort.FullRowSelect = $True
        $lstbxDstPort.Location = New-Object Drawing.Point 5,5
        $lstbxDstPort.AutoSize = $False
        $lstbxDstPort.size = New-Object Drawing.Point $ListView_Width,$ListView_Height
        $lstbxDstPort.Scrollable = $True
        $lstbxDstPort.Height = $ListView_Height2
        $lstbxDstPort.columns.add("Destination Port  ") | Out-Null
        $lstbxDstPort.columns.add("Count   ") | Out-Null
        $lstbxDstPort.add_columnclick({if($lstbxDstPort.Sorting -eq "Descending") {$lstbxDstPort.Sorting = "None"; Update_Controls(@())} else {$lstbxDstPort.Sorting = "Descending";$lstbxDstPort.sort()}})
        $lstbxDstPort.view = "Details"
        $lstbxDstPort.Enabled = $False
        $lstbxDstPort.add_Click({DstPort_Click})

        $lstbxDstIP = New-Object System.Windows.Forms.Listview
        $lstbxDstIP.FullRowSelect = $True
        $lstbxDstIP.Location = New-Object Drawing.Point 185,5
        $lstbxDstIP.AutoSize = $False
        $lstbxDstIP.size = New-Object Drawing.Point $ListView_Width,$ListView_Height
        $lstbxDstIP.Scrollable = $True
        $lstbxDstIP.Height = $ListView_Height2
        $lstbxDstIP.columns.add("Destination IP      ") | Out-Null
        $lstbxDstIP.columns.add("Count     ") | Out-Null
        $lstbxDstIP.add_columnclick({if($lstbxDstIP.Sorting -eq "Descending") {$lstbxDstIP.Sorting = "None"; Update_Controls(@())} else {$lstbxDstIP.Sorting = "Descending";$lstbxDstIP.sort()}})
        $lstbxDstIP.view = "Details"
        $lstbxDstIP.Enabled = $False
        $lstbxDstIP.add_Click({DstIP_Click})

        $lstbxSrcIP = New-Object System.Windows.Forms.Listview
        $lstbxSrcIP.FullRowSelect = $True
        $lstbxSrcIP.Location = New-Object Drawing.Point 365,5
        $lstbxSrcIP.AutoSize = $False
        $lstbxSrcIP.size = New-Object Drawing.Point $ListView_Width,$ListView_Height
        $lstbxSrcIP.Scrollable = $True
        $lstbxSrcIP.Height = $ListView_Height2
        $lstbxSrcIP.columns.add("Source IP           ") | Out-Null
        $lstbxSrcIP.columns.add("Count     ") | Out-Null
        $lstbxSrcIP.add_columnclick({if($lstbxSrcIP.Sorting -eq "Descending") {$lstbxSrcIP.Sorting = "None"; Update_Controls(@())} else {$lstbxSrcIP.Sorting = "Descending";$lstbxSrcIP.sort()}})
        $lstbxSrcIP.view = "Details"
        $lstbxSrcIP.Enabled = $False
        $lstbxSrcIP.add_Click({SrcIP_Click})

        $lstbxAction = New-Object System.Windows.Forms.Listview
        $lstbxAction.FullRowSelect = $True
        $lstbxAction.Location = New-Object Drawing.Point 545,5
        $lstbxAction.AutoSize = $False
        $lstbxAction.size = New-Object Drawing.Point 155,$ListView_Height
        $lstbxAction.Scrollable = $True
        $lstbxAction.Height = $ListView_Height2
        $lstbxAction.columns.add("Action       ") | Out-Null
        $lstbxAction.columns.add("Count    ") | Out-Null
        $lstbxAction.view = "Details"
        $lstbxAction.Enabled = $False
        $lstbxAction.add_Click({Action_Click})

        $lstbxProto = New-Object System.Windows.Forms.Listview
        $lstbxProto.FullRowSelect = $True
        $lstbxProto.Location = New-Object Drawing.Point 705,5
        $lstbxProto.AutoSize = $False
        $lstbxProto.size = New-Object Drawing.Point 155,$ListView_Height
        $lstbxProto.Scrollable = $True
        $lstbxProto.Height = $ListView_Height2
        $lstbxProto.columns.add("Protocol      ") | Out-Null
        $lstbxProto.columns.add("Count     ") | Out-Null
        $lstbxProto.view = "Details"
        $lstbxProto.Enabled = $False
        $lstbxProto.add_Click({Proto_Click})

        $lstbxDir = New-Object System.Windows.Forms.Listview
        $lstbxDir.FullRowSelect = $True
        $lstbxDir.Location = New-Object Drawing.Point 998,5
        $lstbxDir.AutoSize = $False
        $lstbxDir.size = New-Object Drawing.Point 155,$ListView_Height
        $lstbxDir.Scrollable = $True
        $lstbxDir.Height = $ListView_Height2
        $lstbxDir.columns.add("Direction       ") | Out-Null
        $lstbxDir.columns.add("Count       ") | Out-Null
        $lstbxDir.view = "Details"
        $lstbxDir.Enabled = $False
        $lstbxDir.add_Click({Dir_Click})

        $tbDstPrtSelected = New-Object System.Windows.Forms.TextBox
        $tbDstPrtSelected.Location = New-Object Drawing.Point 5,140
        $tbDstPrtSelected.AutoSize = $False
        $tbDstPrtSelected.size = New-Object Drawing.Point 153,20
        $tbDstPrtSelected.BackColor = "lightgray"
        $tbDstPrtSelected.TextAlign = 2
        $tbDstPrtSelected.Text = "Searching..."
        $tbDstPrtSelected.ReadOnly = $True
        $tbDstPrtSelected.TabStop = $False
        #$tbDstPrtSelected.Enabled = $False

        $btnClearDstPrt = New-Object Windows.Forms.Button
        $btnClearDstPrt.Location = New-Object Drawing.Point 160,140
        $btnClearDstPrt.size = New-Object Drawing.Point 20,20
        $btnClearDstPrt.Text = "X"
        $btnClearDstPrt.Enabled = $False
        $btnClearDstPrt.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnClearDstPrt.BackColor = "LightGray"
        $btnClearDstPrt.add_click({ClearDstPort_Click})
        #$ttDomState = New-Object Windows.Forms.ToolTip

        Function ClearDstPort_Click
        {
            if ($global:Debug)
            {
                write-host "Function ClearDstPort_Click"
            }

            ClearDstPort

            $btnClearDstPrt.Enabled = $False
            $btnClearDstPrt.BackColor = "LightGray"
            $btnClearDstPrt.ForeColor = "Black"
        }

        $tbDstIPSelected = New-Object System.Windows.Forms.TextBox
        $tbDstIPSelected.Location = New-Object Drawing.Point 185,140
        $tbDstIPSelected.AutoSize = $False
        $tbDstIPSelected.size = New-Object Drawing.Point 153,20
        $tbDstIPSelected.BackColor = "lightgray"
        $tbDstIPSelected.TextAlign = 2
        $tbDstIPSelected.Text = "Searching..."
        $tbDstIPSelected.ReadOnly = $True
        $tbDstIPSelected.TabStop = $False
        #$tbDstIPSelected.Enabled = $False

        $btnClearDstIP = New-Object Windows.Forms.Button
        $btnClearDstIP.Location = New-Object Drawing.Point 340,140
        $btnClearDstIP.size = New-Object Drawing.Point 20,20
        $btnClearDstIP.Text = "X"
        $btnClearDstIP.Enabled = $False
        $btnClearDstIP.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnClearDstIP.BackColor = "LightGray"
        $btnClearDstIP.add_click({ClearDstIP_Click})
        #$ttDomState = New-Object Windows.Forms.ToolTip

        Function ClearDstIP_Click
        {
            if ($global:Debug)
            {
                write-host "Function ClearDstIP_Click"
            }

            ClearDstIP

            $btnClearDstIP.Enabled = $False
            $btnClearDstIP.BackColor = "LightGray"
            $btnClearDstIP.ForeColor = "Black"

        }

        $tbSrcIPSelected = New-Object System.Windows.Forms.TextBox
        $tbSrcIPSelected.Location = New-Object Drawing.Point 365,140
        $tbSrcIPSelected.AutoSize = $False
        $tbSrcIPSelected.size = New-Object Drawing.Point 153,20
        $tbSrcIPSelected.BackColor = "lightgray"
        $tbSrcIPSelected.TextAlign = 2
        $tbSrcIPSelected.Text = "Searching..."
        $tbSrcIPSelected.ReadOnly = $True
        $tbSrcIPSelected.TabStop = $False
        #$tbSrcIPSelected.Enabled = $False

        $btnClearSrcIP = New-Object Windows.Forms.Button
        $btnClearSrcIP.Location = New-Object Drawing.Point 520,140
        $btnClearSrcIP.size = New-Object Drawing.Point 20,20
        $btnClearSrcIP.Text = "X"
        $btnClearSrcIP.Enabled = $False
        $btnClearSrcIP.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnClearSrcIP.BackColor = "LightGray"
        $btnClearSrcIP.add_click({ClearSrcIP_Click})
        #$ttDomState = New-Object Windows.Forms.ToolTip

        Function ClearSrcIP_Click
        {
            if ($global:Debug)
            {
                write-host "Function ClearSrcIP_Click"
            }

            ClearSrcIP

            $btnClearSrcIP.Enabled = $False
            $btnClearSrcIP.BackColor = "LightGray"
            $btnClearSrcIP.ForeColor = "Black"

        }

        $tbActionSelected = New-Object System.Windows.Forms.TextBox
        $tbActionSelected.Location = New-Object Drawing.Point 545,140
        $tbActionSelected.AutoSize = $False
        $tbActionSelected.size = New-Object Drawing.Point 133,20
        $tbActionSelected.BackColor = "lightgray"
        $tbActionSelected.TextAlign = 2
        $tbActionSelected.Text = "Searching..."
        $tbActionSelected.ReadOnly = $True
        $tbActionSelected.TabStop = $False
        #$tbActionSelected.Enabled = $False

        $btnClearAction = New-Object Windows.Forms.Button
        $btnClearAction.Location = New-Object Drawing.Point 680,140
        $btnClearAction.size = New-Object Drawing.Point 20,20
        $btnClearAction.Text = "X"
        $btnClearAction.Enabled = $False
        $btnClearAction.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnClearAction.BackColor = "LightGray"
        $btnClearAction.add_click({ClearAction_Click})
        #$ttDomState = New-Object Windows.Forms.ToolTip

        Function ClearAction_Click
        {
            if ($global:Debug)
            {
                write-host "Function ClearAction_Click"
            }

            ClearAction

            $btnClearAction.Enabled = $False
            $btnClearAction.BackColor = "LightGray"
            $btnClearAction.ForeColor = "Black"

        }

        $tbProtoSelected = New-Object System.Windows.Forms.TextBox
        $tbProtoSelected.Location = New-Object Drawing.Point 705,140
        $tbProtoSelected.AutoSize = $False
        $tbProtoSelected.size = New-Object Drawing.Point 133,20
        $tbProtoSelected.BackColor = "lightgray"
        $tbProtoSelected.TextAlign = 2
        $tbProtoSelected.Text = "Searching..."
        $tbProtoSelected.ReadOnly = $True
        $tbProtoSelected.TabStop = $False
        #$tbProtoSelected.Enabled = $False

        $btnClearProto = New-Object Windows.Forms.Button
        $btnClearProto.Location = New-Object Drawing.Point 840,140
        $btnClearProto.size = New-Object Drawing.Point 20,20
        $btnClearProto.Text = "X"
        $btnClearProto.Enabled = $False
        $btnClearProto.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnClearProto.BackColor = "LightGray"
        $btnClearProto.add_click({ClearProto_Click})
        #$ttDomState = New-Object Windows.Forms.ToolTip

        Function ClearProto_Click
        {
            if ($global:Debug)
            {
                write-host "Function ClearProto_Click"
            }

            ClearProto

            $btnClearProto.Enabled = $False
            $btnClearProto.BackColor = "LightGray"
            $btnClearProto.ForeColor = "Black"

        }

        $tbDirSelected = New-Object System.Windows.Forms.TextBox
        $tbDirSelected.Location = New-Object Drawing.Point 865,140
        $tbDirSelected.AutoSize = $False
        $tbDirSelected.size = New-Object Drawing.Point 155,20
        $tbDirSelected.BackColor = "lightgray"
        $tbDirSelected.TextAlign = 2
        $tbDirSelected.Text = "Searching..."
        $tbDirSelected.ReadOnly = $True
        $tbDirSelected.TabStop = $False
        #$tbDirSelected.Enabled = $False
    # End of Search Area

    # Firewall Status Area
        $FWStatus_Panel = New-Object Windows.Forms.Panel
        $FWStatus_Panel.height = 154
        $FWStatus_Panel.width = 310
        $FWStatus_Panel.location = New-Object System.Drawing.Point(865,5)
        $FWStatus_Panel.BackColor = "lightgray"
        #$FWStatus_Panel.SendToBack()

        $tbFWStatus = New-Object System.Windows.Forms.TextBox
        $tbFWStatus.Text = "Firewall Status"
        $tbFWStatus.ForeColor = "Black"
        $tbFWStatus.BackColor = "cyan"
        $tbFWStatus.Location = New-Object Drawing.Point 3,2
        $tbFWStatus.AutoSize = $False
        $tbFWStatus.size = New-Object Drawing.Point 303,20
        $tbFWStatus.IsAccessible = $false
        $tbFWStatus.Font = New-Object Drawing.Font('Arial Bold',10)
        $tbFWStatus.TextAlign = 2
        $tbFWStatus.ReadOnly = $True
        $tbFWStatus.TabStop = $False
        #$tbFWStatus.BringToFront()
        $tbFWStatus.ReadOnly = $True
        $tbFWStatus.TabStop = $False
        #$tbFWStatus.Enabled = $False

        $lbProfile = New-Object Windows.Forms.Label
        $lbProfile.text = "Profile Enabled:"
        $lbProfile.ForeColor = "black"
        $lbProfile.AutoSize = $false
        $lbProfile.width = 135
        $lbProfile.height = 15
        $lbProfile.location = New-Object Drawing.Point 2,41
        $lbProfile.TextAlign = "MiddleRight"
        $lbProfile.Font = New-Object Drawing.Font('Arial',8)
        #$lbProfile.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbProfile.ReadOnly = $True
        $lbProfile.TabStop = $False

        $lbLogAllow = New-Object Windows.Forms.Label
        $lbLogAllow.text = "Log Allowed:"
        $lbLogAllow.ForeColor = "black"
        $lbLogAllow.AutoSize = $false
        $lbLogAllow.width = 135
        $lbLogAllow.height = 15
        $lbLogAllow.location = New-Object Drawing.Point 2,59
        $lbLogAllow.TextAlign = "MiddleRight"
        $lbLogAllow.Font = New-Object Drawing.Font('Arial',8)
        #$lbLogAllow.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbLogAllow.ReadOnly = $True
        $lbLogAllow.TabStop = $False

        $lbLogDrop = New-Object Windows.Forms.Label
        $lbLogDrop.text = "Log Dropped:"
        $lbLogDrop.ForeColor = "black"
        $lbLogDrop.AutoSize = $false
        $lbLogDrop.width = 135
        $lbLogDrop.height = 15
        $lbLogDrop.location = New-Object Drawing.Point 2,78
        $lbLogDrop.TextAlign = "MiddleRight"
        $lbLogDrop.Font = New-Object Drawing.Font('Arial',8)
        #$lbLogDrop.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbLogDrop.ReadOnly = $True
        $lbLogDrop.TabStop = $False

        $lbLogIgnored = New-Object Windows.Forms.Label
        $lbLogIgnored.text = "Log Ignored:"
        $lbLogIgnored.ForeColor = "black"
        $lbLogIgnored.AutoSize = $false
        $lbLogIgnored.width = 135
        $lbLogIgnored.height = 15
        $lbLogIgnored.location = New-Object Drawing.Point 2,97
        $lbLogIgnored.TextAlign = "MiddleRight"
        $lbLogIgnored.Font = New-Object Drawing.Font('Arial',8)
        #$lbLogIgnored.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbLogIgnored.ReadOnly = $True
        $lbLogIgnored.TabStop = $False

        $lbDefInbAction = New-Object Windows.Forms.Label
        $lbDefInbAction.text = "Default Inbound Action:"
        $lbDefInbAction.ForeColor = "black"
        $lbDefInbAction.AutoSize = $false
        $lbDefInbAction.width = 135
        $lbDefInbAction.height = 15
        $lbDefInbAction.location = New-Object Drawing.Point 2,116
        $lbDefInbAction.TextAlign = "MiddleRight"
        $lbDefInbAction.Font = New-Object Drawing.Font('Arial',8)
        #$lbDefInbAction.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbDefInbAction.ReadOnly = $True
        $lbDefInbAction.TabStop = $False

        $lbDefOutAction = New-Object Windows.Forms.Label
        $lbDefOutAction.text = "Default Outbound Action:"
        $lbDefOutAction.ForeColor = "black"
        $lbDefOutAction.AutoSize = $false
        $lbDefOutAction.width = 135
        $lbDefOutAction.height = 15
        $lbDefOutAction.location = New-Object Drawing.Point 2,136
        $lbDefOutAction.TextAlign = "MiddleRight"
        $lbDefOutAction.Font = New-Object Drawing.Font('Arial',8)
        #$lbDefOutAction.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbDefOutAction.ReadOnly = $True
        $lbDefOutAction.TabStop = $False

        $lbDomProf = New-Object Windows.Forms.Label
        $lbDomProf.text = "DOM"
        $lbDomProf.ForeColor = "black"
        $lbDomProf.AutoSize = $false
        $lbDomProf.width = 32
        $lbDomProf.height = 20
        $lbDomProf.location = New-Object Drawing.Point 138,25
        #$lbDomProf.TextAlign = "MiddleRight"
        $lbDomProf.Font = New-Object Drawing.Font('Arial',8)
        #$lbDomProf.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbDomProf.ReadOnly = $True
        $lbDomProf.TabStop = $False

        $lbPrivProf = New-Object Windows.Forms.Label
        $lbPrivProf.text = "PRIV"
        $lbPrivProf.ForeColor = "black"
        $lbPrivProf.AutoSize = $false
        $lbPrivProf.width = 32
        $lbPrivProf.height = 20
        $lbPrivProf.location = New-Object Drawing.Point 170,25
        #$lbPrivProf.TextAlign = "MiddleRight"
        $lbPrivProf.Font = New-Object Drawing.Font('Arial',8)
        #$lbPrivProf.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbPrivProf.ReadOnly = $True
        $lbPrivProf.TabStop = $False

        $lbPubProf = New-Object Windows.Forms.Label
        $lbPubProf.text = "PUB"
        $lbPubProf.ForeColor = "black"
        $lbPubProf.AutoSize = $false
        $lbPubProf.width = 32
        $lbPubProf.height = 20
        $lbPubProf.location = New-Object Drawing.Point 203,25
        #$lbPubProf.TextAlign = "MiddleRight"
        $lbPubProf.Font = New-Object Drawing.Font('Arial',8)
        #$lbPubProf.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbPubProf.ReadOnly = $True
        $lbPubProf.TabStop = $False

        $lbProfiles = New-Object Windows.Forms.Label
        $lbProfiles.text = "Profiles:"
        $lbProfiles.ForeColor = "black"
        $lbProfiles.AutoSize = $false
        $lbProfiles.width = 109
        $lbProfiles.height = 15
        $lbProfiles.location = New-Object Drawing.Point 27,24
        $lbProfiles.TextAlign = "MiddleRight"
        $lbProfiles.Font = New-Object Drawing.Font('Arial',8)
        #$lbProfiles.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbProfiles.ReadOnly = $True
        $lbProfiles.TabStop = $False

        $btnDomState = New-Object Windows.Forms.Button
        $btnDomState.Location = New-Object Drawing.Point 138,38
        $btnDomState.size = New-Object Drawing.Point 32,20
        $btnDomState.Text = ""
        $btnDomState.Enabled = $False
        $btnDomState.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDomState.add_click({DomState_Click})
        $ttDomState = New-Object Windows.Forms.ToolTip

        $btnPrivState = New-Object Windows.Forms.Button
        $btnPrivState.Location = New-Object Drawing.Point 170,38
        $btnPrivState.size = New-Object Drawing.Point 32,20
        $btnPrivState.Text = ""
        $btnPrivState.Enabled = $False
        $btnPrivState.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPrivState.add_click({PrivState_Click})
        $ttPrivState = New-Object Windows.Forms.ToolTip

        $btnPubState = New-Object Windows.Forms.Button
        $btnPubState.Location = New-Object Drawing.Point 202,38
        $btnPubState.size = New-Object Drawing.Point 32,20
        $btnPubState.Text = ""
        $btnPubState.Enabled = $False
        $btnPubState.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPubState.add_click({PubState_Click})
        $ttPubState = New-Object Windows.Forms.ToolTip

        $btnDLogAllow = New-Object Windows.Forms.Button
        $btnDLogAllow.Location = New-Object Drawing.Point 138,57
        $btnDLogAllow.size = New-Object Drawing.Point 32,20
        $btnDLogAllow.Text = ""
        $btnDLogAllow.Enabled = $False
        $btnDLogAllow.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDLogAllow.add_click({DomLogAllow_Click})
        $ttDLogAllow = New-Object Windows.Forms.ToolTip

        $btnPrLogAllow = New-Object Windows.Forms.Button
        $btnPrLogAllow.Location = New-Object Drawing.Point 170,57
        $btnPrLogAllow.size = New-Object Drawing.Point 32,20
        $btnPrLogAllow.Text = ""
        $btnPrLogAllow.Enabled = $False
        $btnPrLogAllow.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPrLogAllow.add_click({PrivLogAllow_Click})
        $ttPrLogAllow = New-Object Windows.Forms.ToolTip

        $btnPuLogAllow = New-Object Windows.Forms.Button
        $btnPuLogAllow.Location = New-Object Drawing.Point 202,57
        $btnPuLogAllow.size = New-Object Drawing.Point 32,20
        $btnPuLogAllow.Text = ""
        $btnPuLogAllow.Enabled = $False
        $btnPuLogAllow.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPuLogAllow.add_click({PubLogAllow_Click})
        $ttPuLogAllow = New-Object Windows.Forms.ToolTip

        $btnDLogDrop = New-Object Windows.Forms.Button
        $btnDLogDrop.Location = New-Object Drawing.Point 138,76
        $btnDLogDrop.size = New-Object Drawing.Point 32,20
        $btnDLogDrop.Text = ""
        $btnDLogDrop.Enabled = $False
        $btnDLogDrop.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDLogDrop.add_click({DomLogDrop_Click})
        $ttDLogDrop = New-Object Windows.Forms.ToolTip

        $btnPrLogDrop = New-Object Windows.Forms.Button
        $btnPrLogDrop.Location = New-Object Drawing.Point 170,76
        $btnPrLogDrop.size = New-Object Drawing.Point 32,20
        $btnPrLogDrop.Text = ""
        $btnPrLogDrop.Enabled = $False
        $btnPrLogDrop.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPrLogDrop.add_click({PrivLogDrop_Click})
        $ttPrLogDrop = New-Object Windows.Forms.ToolTip

        $btnPuLogDrop = New-Object Windows.Forms.Button
        $btnPuLogDrop.Location = New-Object Drawing.Point 202,76
        $btnPuLogDrop.size = New-Object Drawing.Point 32,20
        $btnPuLogDrop.Text = ""
        $btnPuLogDrop.Enabled = $False
        $btnPuLogDrop.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPuLogDrop.add_click({PubLogDrop_Click})
        $ttPuLogDrop = New-Object Windows.Forms.ToolTip

        $btnDLogIgnore = New-Object Windows.Forms.Button
        $btnDLogIgnore.Location = New-Object Drawing.Point 138,95
        $btnDLogIgnore.size = New-Object Drawing.Point 32,20
        $btnDLogIgnore.Text = ""
        $btnDLogIgnore.Enabled = $False
        $btnDLogIgnore.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDLogIgnore.add_click({DomLogIgnore_Click})
        $ttDLogIgnore = New-Object Windows.Forms.ToolTip

        $btnPrLogIgnore = New-Object Windows.Forms.Button
        $btnPrLogIgnore.Location = New-Object Drawing.Point 170,95
        $btnPrLogIgnore.size = New-Object Drawing.Point 32,20
        $btnPrLogIgnore.Text = ""
        $btnPrLogIgnore.Enabled = $False
        $btnPrLogIgnore.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPrLogIgnore.add_click({PrivLogIgnore_Click})
        $ttPrLogIgnore = New-Object Windows.Forms.ToolTip

        $btnPuLogIgnore = New-Object Windows.Forms.Button
        $btnPuLogIgnore.Location = New-Object Drawing.Point 202,95
        $btnPuLogIgnore.size = New-Object Drawing.Point 32,20
        $btnPuLogIgnore.Text = ""
        $btnPuLogIgnore.Enabled = $False
        $btnPuLogIgnore.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPuLogIgnore.add_click({PubLogIgnore_Click})
        $ttPuLogIgnore = New-Object Windows.Forms.ToolTip

        $btnDDefInb = New-Object Windows.Forms.Button
        $btnDDefInb.Location = New-Object Drawing.Point 138,114
        $btnDDefInb.size = New-Object Drawing.Point 32,20
        $btnDDefInb.Text = ""
        $btnDDefInb.Enabled = $False
        $btnDDefInb.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDDefInb.add_click({DomDefInb_Click})
        $ttDDefInb = New-Object Windows.Forms.ToolTip

        $btnPrDefInb = New-Object Windows.Forms.Button
        $btnPrDefInb.Location = New-Object Drawing.Point 170,114
        $btnPrDefInb.size = New-Object Drawing.Point 32,20
        $btnPrDefInb.Text = ""
        $btnPrDefInb.Enabled = $False
        $btnPrDefInb.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPrDefInb.add_click({PrivDefInb_Click})
        $ttPrDefInb = New-Object Windows.Forms.ToolTip

        $btnPuDefInb = New-Object Windows.Forms.Button
        $btnPuDefInb.Location = New-Object Drawing.Point 202,114
        $btnPuDefInb.size = New-Object Drawing.Point 32,20
        $btnPuDefInb.Text = ""
        $btnPuDefInb.Enabled = $False
        $btnPuDefInb.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPuDefInb.add_click({PubDefInb_Click})
        $ttPuDefInb = New-Object Windows.Forms.ToolTip

        $btnDDefOutb = New-Object Windows.Forms.Button
        $btnDDefOutb.Location = New-Object Drawing.Point 138,133
        $btnDDefOutb.size = New-Object Drawing.Point 32,20
        $btnDDefOutb.Text = ""
        $btnDDefOutb.Enabled = $False
        $btnDDefOutb.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDDefOutb.add_click({DomDefOutb_Click})
        $ttDDefOutb = New-Object Windows.Forms.ToolTip

        $btnPrDefOutb = New-Object Windows.Forms.Button
        $btnPrDefOutb.Location = New-Object Drawing.Point 170,133
        $btnPrDefOutb.size = New-Object Drawing.Point 32,20
        $btnPrDefOutb.Text = ""
        $btnPrDefOutb.Enabled = $False
        $btnPrDefOutb.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPrDefOutb.add_click({PrivDefOutb_Click})
        $ttPrDefOutb = New-Object Windows.Forms.ToolTip

        $btnPuDefOutb = New-Object Windows.Forms.Button
        $btnPuDefOutb.Location = New-Object Drawing.Point 202,133
        $btnPuDefOutb.size = New-Object Drawing.Point 32,20
        $btnPuDefOutb.Text = ""
        $btnPuDefOutb.Enabled = $False
        $btnPuDefOutb.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnPuDefOutb.add_click({PubDefOutb_Click})
        $ttPuDefOutb = New-Object Windows.Forms.ToolTip

        $btnProfAll = New-Object Windows.Forms.Button
        $btnProfAll.Location = New-Object Drawing.Point 235,38
        $btnProfAll.size = New-Object Drawing.Point 72,20
        $btnProfAll.Text = ""
        $btnProfAll.Enabled = $False
        $btnProfAll.BackColor = "darkgray"
        $btnProfAll.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnProfAll.add_click({ProfAll_Click})
        $ttProfAll = New-Object Windows.Forms.ToolTip

        $btnLogAllowAll = New-Object Windows.Forms.Button
        $btnLogAllowAll.Location = New-Object Drawing.Point 235,57
        $btnLogAllowAll.size = New-Object Drawing.Point 72,20
        $btnLogAllowAll.Text = ""
        $btnLogAllowAll.Enabled = $False
        $btnLogAllowAll.BackColor = "darkgray"
        $btnLogAllowAll.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnLogAllowAll.add_click({LogAllowAll_Click})
        $ttLogAllowAll = New-Object Windows.Forms.ToolTip

        $btnLogDropAll = New-Object Windows.Forms.Button
        $btnLogDropAll.Location = New-Object Drawing.Point 235,76
        $btnLogDropAll.size = New-Object Drawing.Point 72,20
        $btnLogDropAll.Text = ""
        $btnLogDropAll.Enabled = $False
        $btnLogDropAll.BackColor = "darkgray"
        $btnLogDropAll.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnLogDropAll.add_click({LogDropAll_Click})
        $ttLogDropAll = New-Object Windows.Forms.ToolTip

        $btnLogIgnoredAll = New-Object Windows.Forms.Button
        $btnLogIgnoredAll.Location = New-Object Drawing.Point 235,95
        $btnLogIgnoredAll.size = New-Object Drawing.Point 72,20
        $btnLogIgnoredAll.Text = ""
        $btnLogIgnoredAll.Enabled = $False
        $btnLogIgnoredAll.BackColor = "darkgray"
        $btnLogIgnoredAll.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnLogIgnoredAll.add_click({LogIgnoreAll_Click})
        $ttLogIgnoredAll = New-Object Windows.Forms.ToolTip

        $btnDefInbAll = New-Object Windows.Forms.Button
        $btnDefInbAll.Location = New-Object Drawing.Point 235,114
        $btnDefInbAll.size = New-Object Drawing.Point 72,20
        $btnDefInbAll.Text = ""
        $btnDefInbAll.Enabled = $False
        $btnDefInbAll.BackColor = "darkgray"
        $btnDefInbAll.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDefInbAll.add_click({DefInbAll_Click})
        $ttDefInbAll = New-Object Windows.Forms.ToolTip

        $btnDefOutbAll = New-Object Windows.Forms.Button
        $btnDefOutbAll.Location = New-Object Drawing.Point 235,133
        $btnDefOutbAll.size = New-Object Drawing.Point 72,20
        $btnDefOutbAll.Text = ""
        $btnDefOutbAll.Enabled = $False
        $btnDefOutbAll.BackColor = "darkgray"
        $btnDefOutbAll.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',7)
        $btnDefOutbAll.add_click({DefOutbAll_Click})
        $ttDefOutbAll = New-Object Windows.Forms.ToolTip
    # End of Firewall Status

    # Log Area
        $tbFWLog = New-Object System.Windows.Forms.TextBox
        $tbFWLog.Text = "Firewall Log"
        $tbFWLog.ForeColor = "Black"
        $tbFWLog.BackColor = "Cyan"
        $tbFWLog.font = "Arial Bold, 14"
        $tbFWLog.Location = New-Object Drawing.Point 5,163
        $tbFWLog.AutoSize = $False
        $tbFWLog.size = New-Object Drawing.Point 1170,30
        $tbFWLog.TextAlign = 2
        $tbFWLog.ReadOnly = $True
        $tbFWLog.TabStop = $False
        #$tbFWLog.Enabled = $False

        $FWLog = New-Object System.Windows.Forms.DataGridView
        $FWLog.Location = New-Object Drawing.Point 5,195
        $FWLog.size = New-Object Drawing.Point 1170,311
        $FWLog.MultiSelect = $false
        $FWLog.ColumnHeadersVisible = $true
        $FWLog.RowHeadersVisible = $false
        #$FWLog.Visible = $False
    # End of Log Area

    # Options Area
        $btnClearSearch = New-Object Windows.Forms.Button
        $btnClearSearch.Location = New-Object Drawing.Point 1180,165
        $btnClearSearch.size = New-Object Drawing.Point 131,$global:BtnHeight
        $btnClearSearch.Text = "&Get Latest Log"
        $btnClearSearch.BackColor = "lightgray"
        $btnClearSearch.Enabled = $False
        $btnClearSearch.Font = New-Object System.Drawing.Font('Arial',10)
        $btnClearSearch.add_click({ClearSearch_Click})
        $ttClearSearch = New-Object Windows.Forms.ToolTip
        $ttClearSearch.SetToolTip($btnClearSearch, "Clear all search fields and get latest logs.")

        $btnAllTrafTo = New-Object Windows.Forms.Button
        $btnAllTrafTo.Location = New-Object Drawing.Point 1180,194
        $btnAllTrafTo.size = New-Object Drawing.Point 131,$global:BtnHeight
        $btnAllTrafTo.Text = "&All Traffic To"
        $btnAllTrafTo.BackColor = "lightgray"
        $btnAllTrafTo.Enabled = $False
        $btnAllTrafTo.Font = New-Object System.Drawing.Font('Arial',10)
        $btnAllTrafTo.add_click({btnAllTrafTo_Click})
        $ttAllTrafTo = New-Object Windows.Forms.ToolTip
        $ttAllTrafTo.SetToolTip($btnAllTrafTo, "Search for all traffic TO this system.")

        $btnAllTrafFrom = New-Object Windows.Forms.Button
        $btnAllTrafFrom.Location = New-Object Drawing.Point 1180,223
        $btnAllTrafFrom.size = New-Object Drawing.Point 131,$global:BtnHeight
        $btnAllTrafFrom.Text = "&All Traffic From"
        $btnAllTrafFrom.BackColor = "lightgray"
        $btnAllTrafFrom.Enabled = $False
        $btnAllTrafFrom.Font = New-Object System.Drawing.Font('Arial',10)
        $btnAllTrafFrom.add_click({btnAllTrafFrom_Click})
        $ttAllTrafFrom = New-Object Windows.Forms.ToolTip
        $ttAllTrafFrom.SetToolTip($btnAllTrafFrom, "Search for all traffic FROM this system.")

        $Options_Panel = New-Object Windows.Forms.Panel
        $Options_Panel.height = 253
        $Options_Panel.width = 133
        $Options_Panel.location = New-Object System.Drawing.Point(1180,253)
        #$Options_Panel.location = New-Object System.Drawing.Point(1180,282)
        $Options_Panel.BackColor = "gray"
        #$Options_Panel.SendToBack()

        $cbIPv6 = New-Object system.Windows.Forms.CheckBox
        $cbIPv6.text = "Include IPv6"
        $cbIPv6.ForeColor = "White"
        $cbIPv6.AutoSize = $false
        $cbIPv6.width = 105
        $cbIPv6.height = 20
        $cbIPv6.location = New-Object System.Drawing.Point(3,25)
        $cbIPv6.Font = New-Object System.Drawing.Font('Arial',9)
        #$cbIPv6.ReadOnly = $True
        $cbIPv6.TabStop = $False
        $cbIPv6.Enabled = $False

        $cbPrevFile = New-Object system.Windows.Forms.CheckBox
        $cbPrevFile.text = "Import Previous Log"
        $cbPrevFile.ForeColor = "White"
        $cbPrevFile.AutoSize = $false
        $cbPrevFile.width = 115
        $cbPrevFile.height = 40
        $cbPrevFile.location = New-Object System.Drawing.Point(3,45)
        $cbPrevFile.Font = New-Object System.Drawing.Font('Arial',9)
        #$cbPrevFile.ReadOnly = $True
        $cbPrevFile.TabStop = $False
        $cbPrevFile.Enabled = $False
        $cbPrevFile.Checked = $False

        $cbCurFile = New-Object system.Windows.Forms.CheckBox
        $cbCurFile.text = "Import Current Log"
        $cbCurFile.ForeColor = "White"
        $cbCurFile.AutoSize = $false
        $cbCurFile.width = 115
        $cbCurFile.height = 40
        $cbCurFile.location = New-Object System.Drawing.Point(3,80)
        $cbCurFile.Font = New-Object System.Drawing.Font('Arial',9)
        #$cbCurFile.ReadOnly = $True
        $cbCurFile.TabStop = $False
        $cbCurFile.Enabled = $False
        $cbCurFile.Checked = $True

        <#$cbUseWiz = New-Object system.Windows.Forms.CheckBox
        $cbUseWiz.text = "Use Wizards"
        $cbUseWiz.AutoSize = $false
        $cbUseWiz.width = 115
        $cbUseWiz.height = 40
        $cbUseWiz.location = New-Object System.Drawing.Point(3,193)
        $cbUseWiz.Font = New-Object System.Drawing.Font('Arial',9)
        #$cbUseWiz.ReadOnly = $True
        $cbUseWiz.TabStop = $False
        $cbUseWiz.Enabled = $False
        $cbUseWiz.Checked = $True #>

        $gbSystem = New-Object system.Windows.Forms.Groupbox
        $gbSystem.height = 57
        $gbSystem.width = 126
        $gbSystem.text = "System Selection"
        $gbSystem.ForeColor = "White"
        $gbSystem.location = New-Object System.Drawing.Point(3,193)
        $gbSystem.Font = New-Object System.Drawing.Font('Arial',9)
        #$gbSystem.ForeColor = "Black"
        $gbSystem.Visible = $true

        $rbLocal = New-Object system.Windows.Forms.RadioButton
        $rbLocal.text = "Local"
        $rbLocal.ForeColor = "White"
        $rbLocal.AutoSize = $true
        $rbLocal.width = 60
        $rbLocal.height = 16
        $rbLocal.location = New-Object System.Drawing.Point(5,17)
        $rbLocal.Font = New-Object System.Drawing.Font('Arial',8)
        $rbLocal.Checked = $True
        $rbLocal.Add_Click({
                If ($rbLocal.Checked -and $global:RemIPSelected -eq $True)
                {
                    #$lbHRiskQ2.Text = "Can you access your home router?"
                    #$lbHRiskQ2.Visible = $True
                    $tbRemIP.text = "Remote IP"
                    $tbFWLog.text = "Firewall Log (Local System)"
                    $global:PrevLogFile = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log.old"
                    $global:CurLogFile = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
                    $tbRemIP.Enabled = $False
                    ClearSearch_Click
                    $global:RemIPSelected = $False
                }
            })

        $rbRemote = New-Object system.Windows.Forms.RadioButton
        $rbRemote.text = "Remote"
        $rbRemote.ForeColor = "White"
        $rbRemote.AutoSize = $true
        $rbRemote.width = 60
        $rbRemote.height = 16
        $rbRemote.location = New-Object System.Drawing.Point(60,17)
        $rbRemote.Font = New-Object System.Drawing.Font('Arial',8)
        $rbRemote.Add_Click({
                If ($rbRemote.Checked -and $global:RemIPSelected -eq $False)
                {
                    #$lbHRiskQ2.Text = "Can you access your home router?"
                    #$lbHRiskQ2.Visible = $True
                    $tbRemIP.Enabled = $True
                    $tbRemIP.text = "Input Remote IP Here"
                    $tbFWLog.text = "Firewall Log (Remote System)"
                    $tbRemIP.Select()
                    $global:RemIPSelected = $True
                }
            })

        $tbRemIP = New-Object System.Windows.Forms.TextBox
        $tbRemIP.Text = "Remote IP"
        #$tbRemIP.ForeColor = "Black"
        #$tbRemIP.BackColor = "White"
        $tbRemIP.Location = New-Object Drawing.Point 8,35
        $tbRemIP.AutoSize = $False
        $tbRemIP.size = New-Object Drawing.Point 109,18
        $tbRemIP.IsAccessible = $false
        $tbRemIP.Font = New-Object Drawing.Font('Arial Bold',8)
        $tbRemIP.TextAlign = 2
        #$tbRemIP.ReadOnly = $True
        $tbRemIP.TabStop = $True
        $tbRemIP.Enabled = $False
        #$tbLogSize.BringToFront()

        $tbRemIP.Add_KeyDown({
            if ($_.KeyCode -eq "Enter") {
                $tbFWLog.text = "Firewall Log (Remote System: " + $tbRemIP.Text + ")"
                $global:PrevLogFile = "\\" + $tbRemIP.Text + "\c$\Windows\System32\LogFiles\Firewall\pfirewall.log.old"
                $global:CurLogFile = "\\" + $tbRemIP.Text + "\c$\Windows\System32\LogFiles\Firewall\pfirewall.log"
                LogFile_Check
                ClearSearch_Click
            }
        })

        $lbNumLines = New-Object Windows.Forms.Label
        $lbNumLines.text = "Import Last"
        $lbNumLines.ForeColor = "white"
        $lbNumLines.AutoSize = $false
        $lbNumLines.width = 67
        $lbNumLines.height = 15
        $lbNumLines.location = New-Object Drawing.Point 3,123
        $lbNumLines.TextAlign = "MiddleLeft"
        $lbNumLines.Font = New-Object Drawing.Font('Arial',9)
        #$lbNumLines.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbNumLines.ReadOnly = $True
        $lbNumLines.TabStop = $False

        $lbSelLog = New-Object Windows.Forms.Label
        $lbSelLog.text = "Lines of Latest File"
        $lbSelLog.ForeColor = "white"
        $lbSelLog.AutoSize = $false
        $lbSelLog.width = 115
        $lbSelLog.height = 15
        $lbSelLog.location = New-Object Drawing.Point 3,143
        $lbSelLog.TextAlign = "MiddleLeft"
        $lbSelLog.Font = New-Object Drawing.Font('Arial',9)
        #$lbSelLog.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbSelLog.ReadOnly = $True
        $lbSelLog.TabStop = $False

        $lbLogSize = New-Object Windows.Forms.Label
        $lbLogSize.text = "Log Size (Kb)"
        $lbLogSize.ForeColor = "white"
        $lbLogSize.AutoSize = $false
        $lbLogSize.width = 81
        $lbLogSize.height = 15
        $lbLogSize.location = New-Object Drawing.Point 3,169
        $lbLogSize.TextAlign = "MiddleLeft"
        $lbLogSize.Font = New-Object Drawing.Font('Arial',9)
        #$lbLogSize.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbLogSize.ReadOnly = $True
        $lbLogSize.TabStop = $False

        $tbLastLines = New-Object System.Windows.Forms.TextBox
        $tbLastLines.Text = "0"
        #$tbLastLines.ForeColor = "Black"
        #$tbLastLines.BackColor = "White"
        $tbLastLines.Location = New-Object Drawing.Point 70,119
        $tbLastLines.AutoSize = $False
        $tbLastLines.size = New-Object Drawing.Point 60,20
        $tbLastLines.IsAccessible = $false
        $tbLastLines.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbLastLines.TextAlign = 2
        #$tbLastLines.ReadOnly = $True
        $tbLastLines.TabStop = $True
        $tbLastLines.Enabled = $False
        #$tbLastLines.BringToFront()
        $tbLastLines.add_textchanged({AddLines_TextChanged})
        $tbLastLines.add_click({AddLines_click})

        $tbLogSize = New-Object System.Windows.Forms.TextBox
        $tbLogSize.Text = "0"
        #$tbLogSize.ForeColor = "Black"
        #$tbLogSize.BackColor = "White"
        $tbLogSize.Location = New-Object Drawing.Point 84,167
        $tbLogSize.AutoSize = $False
        $tbLogSize.size = New-Object Drawing.Point 47,20
        $tbLogSize.IsAccessible = $false
        $tbLogSize.Font = New-Object Drawing.Font('Arial Bold',9)
        $tbLogSize.TextAlign = 2
        #$tbLogSize.ReadOnly = $True
        $tbLogSize.TabStop = $True
        $tbLogSize.Enabled = $False
        #$tbLogSize.BringToFront()

        $lbOptions = New-Object Windows.Forms.Label
        $lbOptions.text = "Options"
        $lbOptions.ForeColor = "Black"
        $lbOptions.BackColor = "lightGray"
        $lbOptions.AutoSize = $false
        $lbOptions.width = 127
        $lbOptions.height = 20
        $lbOptions.location = New-Object Drawing.Point 3,3
        $lbOptions.TextAlign = "MiddleCenter"
        $lbOptions.Font = New-Object Drawing.Font('Microsoft Sans Serif',10)
        #$lbOptions.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
        #$lbOptions.ReadOnly = $True
        $lbOptions.TabStop = $False
    # End of Options Area

    # Tab Control
        $TabControl = New-object System.Windows.Forms.TabControl
        $LogTab = New-Object System.Windows.Forms.TabPage
            $LogTab.Name = "Log"
            $LogTab.Text = "Log"
            $LogTab.BackColor = "Gray"
        $AlertTab = New-Object System.Windows.Forms.TabPage
            $AlertTab.Name = "Alerts"
            $AlertTab.Text = "Alerts"
            $AlertTab.BackColor = "Gray"
        $ProfileTab = New-Object System.Windows.Forms.TabPage
            $ProfileTab.Name = "Profile_Configurations"
            $ProfileTab.Text = "Profile Configurations"
            $ProfileTab.BackColor = "Gray"
        $RulebaseTab = New-Object System.Windows.Forms.TabPage
            $RulebaseTab.Name = "Firewall_Rules"
            $RulebaseTab.Text = "Firewall Rules"
            $RulebaseTab.BackColor = "Gray"
        $NetConfigTab = New-Object System.Windows.Forms.TabPage
            $NetConfigTab.Name = "NetConfig"
            $NetConfigTab.Text = "Network Configuration"
            $NetConfigTab.BackColor = "Gray"
        $InvestigateTab = New-Object System.Windows.Forms.TabPage
            $InvestigateTab.Name = "Investigate"
            $InvestigateTab.Text = "Investigate"
            $InvestigateTab.BackColor = "Gray"
        $AppConfigTab = New-Object System.Windows.Forms.TabPage
            $AppConfigTab.Name = "AppConfig"
            $AppConfigTab.Text = "Monitor Configuration"
            $AppConfigTab.BackColor = "Gray"
        $LicensingTab = New-Object System.Windows.Forms.TabPage
            $LicensingTab.Name = "Licensing"
            $LicensingTab.Text = "Licensing"
            $LicensingTab.BackColor = "Gray"
        $HelpTab = New-Object System.Windows.Forms.TabPage
            $HelpTab.Name = "Help"
            $HelpTab.Text = "Help"
            $HelpTab.BackColor = "Gray"

        $tabControl.DataBindings.DefaultDataSourceUpdateMode = 0
        $tabControl.Location = New-Object Drawing.Point 5,515
        $tabControl.size = New-Object Drawing.Point 1304,315
        $tabControl.Name = "tabControl"
        $tabControl.add_Click({NetConfigTab_Click})
        $tabControl.backcolor = "Gray"

        # Log Tab
            $lbLog = New-Object Windows.Forms.Label
            $lbLog.text = "Application Log"
            $lbLog.ForeColor = "white"
            $lbLog.AutoSize = $false
            $lbLog.width = 131
            $lbLog.height = 15
            $lbLog.location = New-Object Drawing.Point 5,5
            #$lbLog.Font = New-Object Drawing.Font('Microsoft Sans Serif',10)
            #$lbLog.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbLog.ReadOnly = $True
            $lbLog.TabStop = $False

            $tbAppLog = New-Object System.Windows.Forms.TextBox
            $tbAppLog.Text = ""
            $tbAppLog.ForeColor = "Black"
            $tbAppLog.BackColor = "lightgray"
            $tbAppLog.font = "Arial, 10"
            $tbAppLog.Location = New-Object Drawing.Point 5,20
            $tbAppLog.AutoSize = $False
            $tbAppLog.size = New-Object Drawing.Point 785,265
            $tbAppLog.Multiline = $True
            $tbAppLog.AcceptsReturn = $True
            $tbAppLog.ScrollBars = "Vertical"
            #$tbAppLog.TextAlign = 2
            $tbAppLog.ReadOnly = $True
            $tbAppLog.TabStop = $False
            #$tbAppLog.Enabled = $False

            $lbStats = New-Object Windows.Forms.Label
            $lbStats.text = "Application Statistics"
            $lbStats.ForeColor = "white"
            $lbStats.AutoSize = $false
            $lbStats.width = 131
            $lbStats.height = 15
            $lbStats.location = New-Object Drawing.Point 796,5
            #$lbStats.Font = New-Object Drawing.Font('Microsoft Sans Serif',10)
            #$lbStats.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbStats.ReadOnly = $True
            $lbStats.TabStop = $False

            $tbAppStats = New-Object System.Windows.Forms.TextBox
            $tbAppStats.Text = ""
            $tbAppStats.ForeColor = "Black"
            $tbAppStats.BackColor = "lightgray"
            $tbAppStats.font = "Arial, 10"
            $tbAppStats.Location = New-Object Drawing.Point 796,20
            $tbAppStats.AutoSize = $False
            $tbAppStats.size = New-Object Drawing.Point 495,265
            $tbAppStats.Multiline = $True
            $tbAppStats.AcceptsReturn = $True
            $tbAppStats.ScrollBars = "Vertical"
            #$tbAppStats.TextAlign = 2
            $tbAppStats.ReadOnly = $True
            $tbAppStats.TabStop = $False
            #$tbAppStats.Enabled = $False

        # Net Configuration Tab
            $Network_Panel = New-Object Windows.Forms.Panel
            $Network_Panel.height = 180
            $Network_Panel.width = 435
            $Network_Panel.location = New-Object System.Drawing.Point(5,73)
            $Network_Panel.BackColor = "lightgray"
            #$Network_Panel.SendToBack()

            $btnMSClient = New-Object Windows.Forms.Button
            $btnMSClient.Location = New-Object Drawing.Point 452,5
            $btnMSClient.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnMSClient.Text = "Client for Microsoft Networks"
            $btnMSClient.BackColor = "lightgray"
            $btnMSClient.Enabled = $False
            $btnMSClient.add_click({MSClient_Click})
            $ttMSClient = New-Object Windows.Forms.ToolTip
            $ttMSClient.SetToolTip($btnMSClient, "Disable or enable this network component.")

            $btnMSClient_Info = New-Object Windows.Forms.Button
            $btnMSClient_Info.Location = New-Object Drawing.Point 787,5
            $btnMSClient_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnMSClient_Info.Text = "Guidance"
            $btnMSClient_Info.BackColor = "darkgray"
            $btnMSClient_Info.Enabled = $False
            $btnMSClient_Info.add_click({MSClient_Info_Click})
            $ttMSClient_Info = New-Object Windows.Forms.ToolTip
            $ttMSClient_Info.SetToolTip($btnMSClient_Info, "Microsoft Client Recommendation Information")

            $btnMSServer = New-Object Windows.Forms.Button
            $btnMSServer.Location = New-Object Drawing.Point 452,33
            $btnMSServer.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnMSServer.Text = "File and Printer Sharing for Microsoft Networks"
            $btnMSServer.BackColor = "lightgray"
            $btnMSServer.Enabled = $False
            $btnMSServer.add_click({MSServer_Click})
            $ttMSServer = New-Object Windows.Forms.ToolTip
            $ttMSServer.SetToolTip($btnMSServer, "Clear all search fields and get latest logs.")

            $btnMSServer_Info = New-Object Windows.Forms.Button
            $btnMSServer_Info.Location = New-Object Drawing.Point 787,33
            $btnMSServer_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnMSServer_Info.Text = "Guidance"
            $btnMSServer_Info.BackColor = "darkgray"
            $btnMSServer_Info.Enabled = $False
            $btnMSServer_Info.add_click({MSServer_Info_Click})
            $ttMSServer_Info = New-Object Windows.Forms.ToolTip
            $ttMSServer_Info.SetToolTip($btnMSServer_Info, "File and Print Sharing Recommendation Information")

            $btnQoS = New-Object Windows.Forms.Button
            $btnQoS.Location = New-Object Drawing.Point 452,61
            $btnQoS.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnQoS.Text = "QoS Packet Scheduler"
            $btnQoS.BackColor = "lightgray"
            $btnQoS.Enabled = $False
            $btnQoS.add_click({QoS_Click})
            $ttQoS = New-Object Windows.Forms.ToolTip
            $ttQoS.SetToolTip($btnQoS, "Clear all search fields and get latest logs.")

            $btnQoS_Info = New-Object Windows.Forms.Button
            $btnQoS_Info.Location = New-Object Drawing.Point 787,61
            $btnQoS_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnQoS_Info.Text = "Guidance"
            $btnQoS_Info.BackColor = "darkgray"
            $btnQoS_Info.Enabled = $False
            $btnQoS_Info.add_click({QoS_Info_Click})
            $ttQoS_Info = New-Object Windows.Forms.ToolTip
            $ttQoS_Info.SetToolTip($btnQoS_Info, "Packet Scheduler Recommendation Information")

            $btnIPv4 = New-Object Windows.Forms.Button
            $btnIPv4.Location = New-Object Drawing.Point 452,89
            $btnIPv4.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnIPv4.Text = "Internet Protocol Version 4 (TCP/IPv4)"
            $btnIPv4.BackColor = "lightgray"
            $btnIPv4.Enabled = $False
            $btnIPv4.add_click({IPv4_Click})
            $ttIPv4 = New-Object Windows.Forms.ToolTip
            $ttIPv4.SetToolTip($btnIPv4, "Clear all search fields and get latest logs.")

            $btnIPv4_Info = New-Object Windows.Forms.Button
            $btnIPv4_Info.Location = New-Object Drawing.Point 787,89
            $btnIPv4_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnIPv4_Info.Text = "Guidance"
            $btnIPv4_Info.BackColor = "darkgray"
            $btnIPv4_Info.Enabled = $False
            $btnIPv4_Info.add_click({IPv4_Info_Click})
            $ttIPv4_Info = New-Object Windows.Forms.ToolTip
            $ttIPv4_Info.SetToolTip($btnIPv4_Info, "IPv4 Recommendation Information")

            $btnMultiplexor = New-Object Windows.Forms.Button
            $btnMultiplexor.Location = New-Object Drawing.Point 452,117
            $btnMultiplexor.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnMultiplexor.Text = "Microsoft Network Adapter Multiplexor Protocol"
            $btnMultiplexor.BackColor = "lightgray"
            $btnMultiplexor.Enabled = $False
            $btnMultiplexor.add_click({Multiplexor_Click})
            $ttMultiplexor = New-Object Windows.Forms.ToolTip
            $ttMultiplexor.SetToolTip($btnMultiplexor, "Clear all search fields and get latest logs.")

            $btnMultiplexor_Info = New-Object Windows.Forms.Button
            $btnMultiplexor_Info.Location = New-Object Drawing.Point 787,117
            $btnMultiplexor_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnMultiplexor_Info.Text = "Guidance"
            $btnMultiplexor_Info.BackColor = "darkgray"
            $btnMultiplexor_Info.Enabled = $False
            $btnMultiplexor_Info.add_click({Multiplexor_Info_Click})
            $ttMultiplexor_Info = New-Object Windows.Forms.ToolTip
            $ttMultiplexor_Info.SetToolTip($btnMultiplexor_Info, "Multiplexor Protocol Recommendation Information")

            $btnLLDP = New-Object Windows.Forms.Button
            $btnLLDP.Location = New-Object Drawing.Point 452,145
            $btnLLDP.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnLLDP.Text = "Microsoft LLDP Protocol Driver"
            $btnLLDP.BackColor = "lightgray"
            $btnLLDP.Enabled = $False
            $btnLLDP.add_click({LLDP_Click})
            $ttLLDP = New-Object Windows.Forms.ToolTip
            $ttLLDP.SetToolTip($btnLLDP, "Clear all search fields and get latest logs.")

            $btnLLDP_Info = New-Object Windows.Forms.Button
            $btnLLDP_Info.Location = New-Object Drawing.Point 787,145
            $btnLLDP_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnLLDP_Info.Text = "Guidance"
            $btnLLDP_Info.BackColor = "darkgray"
            $btnLLDP_Info.Enabled = $False
            $btnLLDP_Info.add_click({LLDP_Info_Click})
            $ttLLDP_Info = New-Object Windows.Forms.ToolTip
            $ttLLDP_Info.SetToolTip($btnLLDP_Info, "LLDP Protocol Recommendation Information")

            $btnIPv6 = New-Object Windows.Forms.Button
            $btnIPv6.Location = New-Object Drawing.Point 452,173
            $btnIPv6.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnIPv6.Text = "Internet Protocol Version 6 (TCP/IPv6)"
            $btnIPv6.BackColor = "lightgray"
            $btnIPv6.Enabled = $False
            $btnIPv6.add_click({IPv6_Click})
            $ttIPv6 = New-Object Windows.Forms.ToolTip
            $ttIPv6.SetToolTip($btnIPv6, "Clear all search fields and get latest logs.")

            $btnIPv6_Info = New-Object Windows.Forms.Button
            $btnIPv6_Info.Location = New-Object Drawing.Point 787,173
            $btnIPv6_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnIPv6_Info.Text = "Guidance"
            $btnIPv6_Info.BackColor = "darkgray"
            $btnIPv6_Info.Enabled = $False
            $btnIPv6_Info.add_click({IPv6_Info_Click})
            $ttIPv6_Info = New-Object Windows.Forms.ToolTip
            $ttIPv6_Info.SetToolTip($btnIPv6_Info, "IPv6 Recommendation Information")

            $btnLLTD = New-Object Windows.Forms.Button
            $btnLLTD.Location = New-Object Drawing.Point 452,201
            $btnLLTD.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnLLTD.Text = "Link-Layer Topology Discovery Responder"
            $btnLLTD.BackColor = "lightgray"
            $btnLLTD.Enabled = $False
            $btnLLTD.add_click({LLTD_Click})
            $ttLLTD = New-Object Windows.Forms.ToolTip
            $ttLLTD.SetToolTip($btnLLTD, "Clear all search fields and get latest logs.")

            $btnLLTD_Info = New-Object Windows.Forms.Button
            $btnLLTD_Info.Location = New-Object Drawing.Point 787,201
            $btnLLTD_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnLLTD_Info.Text = "Guidance"
            $btnLLTD_Info.BackColor = "darkgray"
            $btnLLTD_Info.Enabled = $False
            $btnLLTD_Info.add_click({LLTD_Info_Click})
            $ttLLTD_Info = New-Object Windows.Forms.ToolTip
            $ttLLTD_Info.SetToolTip($btnLLTD_Info, "Discovery Responder Recommendation Information")

            $btnLLTDMapper = New-Object Windows.Forms.Button
            $btnLLTDMapper.Location = New-Object Drawing.Point 452,229
            $btnLLTDMapper.size = New-Object Drawing.Point 333,$global:BtnHeight
            $btnLLTDMapper.Text = "Link-Layer Topology Discovery Mapper I/O Driver"
            $btnLLTDMapper.BackColor = "lightgray"
            $btnLLTDMapper.Enabled = $False
            $btnLLTDMapper.add_click({LLTDMapper_Click})
            $ttLLTDMapper = New-Object Windows.Forms.ToolTip
            $ttLLTDMapper.SetToolTip($btnLLTDMapper, "Clear all search fields and get latest logs.")

            $btnLLTDMapper_Info = New-Object Windows.Forms.Button
            $btnLLTDMapper_Info.Location = New-Object Drawing.Point 787,229
            $btnLLTDMapper_Info.size = New-Object Drawing.Point 100,$global:BtnHeight
            $btnLLTDMapper_Info.Text = "Guidance"
            $btnLLTDMapper_Info.BackColor = "darkgray"
            $btnLLTDMapper_Info.Enabled = $False
            $btnLLTDMapper_Info.add_click({LLTDMapper_Info_Click})
            $ttLLTDMapper_Info = New-Object Windows.Forms.ToolTip
            $ttLLTDMapper_Info.SetToolTip($btnLLTDMapper_Info, "Discovery Mapper Recommendation Information")

            $lstbxNetAdapt = New-Object System.Windows.Forms.Listview
            $lstbxNetAdapt.FullRowSelect = $True
            $lstbxNetAdapt.Location = New-Object Drawing.Point 5,5
            $lstbxNetAdapt.AutoSize = $False
            $lstbxNetAdapt.size = New-Object Drawing.Point 435,62
            $lstbxNetAdapt.Scrollable = $True
            $lstbxNetAdapt.Height = 62
            $lstbxNetAdapt.columns.add("Interface Alias") | Out-Null
            $lstbxNetAdapt.columns.add("Status") | Out-Null
            $lstbxNetAdapt.columns.add("Interface Index") | Out-Null
            $lstbxNetAdapt.columns.add("IP Address") | Out-Null
            $lstbxNetAdapt.view = "Details"
            $lstbxNetAdapt.Enabled = $False
            $lstbxNetAdapt.add_Click({NetAdapt_Click})

            $tbNetDecision = New-Object System.Windows.Forms.TextBox
            $tbNetDecision.Text = ""
            $tbNetDecision.ForeColor = "Black"
            $tbNetDecision.BackColor = "white"
            $tbNetDecision.font = "Arial, 10"
            $tbNetDecision.Location = New-Object Drawing.Point 891,5
            $tbNetDecision.AutoSize = $False
            $tbNetDecision.size = New-Object Drawing.Point 400,249
            $tbNetDecision.Multiline = $True
            $tbNetDecision.AcceptsReturn = $True
            $tbNetDecision.ScrollBars = "Vertical"
            $tbNetDecision.IsAccessible = $false
            $tbNetDecision.ReadOnly = $True
            $tbNetDecision.TabStop = $False
            #$tbAppStats.TextAlign = 2

            $tbNetAll = New-Object System.Windows.Forms.TextBox
            $tbNetAll.Text = "Network Configuration for All Adapters"
            $tbNetAll.ForeColor = "white"
            $tbNetAll.BackColor = "blue"
            $tbNetAll.Location = New-Object Drawing.Point 4,4
            $tbNetAll.AutoSize = $False
            $tbNetAll.size = New-Object Drawing.Point 427,23
            $tbNetAll.IsAccessible = $false
            $tbNetAll.Font = New-Object Drawing.Font('Arial Bold',10)
            $tbNetAll.TextAlign = 2
            $tbNetAll.ReadOnly = $True
            $tbNetAll.TabStop = $False
            #$tbNetAll.BringToFront()

        # Investigate Tab
            $tbStep2LogSearch = New-Object System.Windows.Forms.TextBox
            $tbStep2LogSearch.Text = "Searching Logs for "
            #$tbStep2LogSearch.Location = New-Object Drawing.Point 220, 110
            $tbStep2LogSearch.Location = New-Object Drawing.Point 5, 175
            $tbStep2LogSearch.AutoSize = $False
            $tbStep2LogSearch.size = New-Object Drawing.Point 260,20
            $tbStep2LogSearch.TextAlign = 2
            $tbStep2LogSearch.ReadOnly = $True
            $tbStep2LogSearch.TabStop = $False
            $tbStep2LogSearch.Font = "Arial, 10"
            $tbStep2LogSearch.BackColor = "white"
            $tbStep2LogSearch.visible = $False

            $tbStep3NetLoc = New-Object System.Windows.Forms.TextBox
            $tbStep3NetLoc.Text = "Private Network"
            #$tbStep3NetLoc.Location = New-Object Drawing.Point 220, 160
            $tbStep3NetLoc.Location = New-Object Drawing.Point 5, 220
            $tbStep3NetLoc.AutoSize = $False
            $tbStep3NetLoc.size = New-Object Drawing.Point 260,20
            $tbStep3NetLoc.TextAlign = 2
            $tbStep3NetLoc.ReadOnly = $True
            $tbStep3NetLoc.TabStop = $False
            $tbStep3NetLoc.Font = "Arial, 10"
            $tbStep3NetLoc.BackColor = "white"
            $tbStep3NetLoc.visible = $False

            $tbStep4DNS = New-Object System.Windows.Forms.TextBox
            $tbStep4DNS.Text = "Please Wait: Resolving Name..."
            #$tbStep4DNS.Location = New-Object Drawing.Point 220, 210
            $tbStep4DNS.Location = New-Object Drawing.Point 5, 265
            $tbStep4DNS.AutoSize = $False
            $tbStep4DNS.size = New-Object Drawing.Point 260,20
            $tbStep4DNS.TextAlign = 2
            $tbStep4DNS.ReadOnly = $True
            $tbStep4DNS.TabStop = $False
            $tbStep4DNS.Font = "Arial, 10"
            $tbStep4DNS.BackColor = "white"
            $tbStep4DNS.visible = $False

            $tbStep6TraceRt = New-Object System.Windows.Forms.TextBox
            $tbStep6TraceRt.Text = "Private Network"
            #$tbStep6TraceRt.Location = New-Object Drawing.Point 220, 160
            $tbStep6TraceRt.Location = New-Object Drawing.Point 280, 160
            $tbStep6TraceRt.AutoSize = $False
            $tbStep6TraceRt.size = New-Object Drawing.Point 505,65
            #$tbStep6TraceRt.TextAlign = 2
            $tbStep6TraceRt.ReadOnly = $True
            $tbStep6TraceRt.TabStop = $False
            $tbStep6TraceRt.Font = "Arial, 10"
            $tbStep6TraceRt.BackColor = "white"
            $tbStep6TraceRt.visible = $False
            $tbStep6TraceRt.Multiline = $True
            $tbStep6TraceRt.ScrollBars = "Vertical"
            $tbStep6TraceRt.Enabled = $True

            $tbStep7IPRep = New-Object System.Windows.Forms.TextBox
            $tbStep7IPRep.Text = "Private Network"
            #$tbStep7IPRep.Location = New-Object Drawing.Point 220, 160
            $tbStep7IPRep.Location = New-Object Drawing.Point 280, 240
            $tbStep7IPRep.AutoSize = $False
            $tbStep7IPRep.size = New-Object Drawing.Point 505,45
            #$tbStep7IPRep.TextAlign = 2
            $tbStep7IPRep.ReadOnly = $True
            $tbStep7IPRep.TabStop = $False
            $tbStep7IPRep.Font = "Arial, 10"
            $tbStep7IPRep.BackColor = "white"
            $tbStep7IPRep.visible = $False
            $tbStep7IPRep.Multiline = $True
            $tbStep7IPRep.ScrollBars = "Vertical"

            $tbHRThreatDesc = New-Object System.Windows.Forms.TextBox
            $tbHRThreatDesc.Text = ""
            #$tbHRThreatDesc.Location = New-Object Drawing.Point 220, 210
            $tbHRThreatDesc.Location = New-Object Drawing.Point 795, 25
            $tbHRThreatDesc.AutoSize = $False
            $tbHRThreatDesc.size = New-Object Drawing.Point 495,80
            #$tbHRThreatDesc.TextAlign = 2
            $tbHRThreatDesc.Multiline = $True
            $tbHRThreatDesc.ReadOnly = $True
            $tbHRThreatDesc.TabStop = $False
            $tbHRThreatDesc.Font = "Arial, 10"
            $tbHRThreatDesc.BackColor = "white"
            $tbHRThreatDesc.visible = $False

            $tbHRInvResult = New-Object System.Windows.Forms.TextBox
            $tbHRInvResult.Text = ""
            #$tbHRInvResult.Location = New-Object Drawing.Point 220, 210
            $tbHRInvResult.Location = New-Object Drawing.Point 795, 130
            $tbHRInvResult.AutoSize = $False
            $tbHRInvResult.size = New-Object Drawing.Point 495,155
            #$tbHRInvResult.TextAlign = 2
            $tbHRInvResult.Multiline = $True
            $tbHRInvResult.ReadOnly = $True
            $tbHRInvResult.TabStop = $False
            $tbHRInvResult.Font = "Arial, 10"
            $tbHRInvResult.BackColor = "white"
            $tbHRInvResult.visible = $False

            $lbHRiskWzTitle = New-Object Windows.Forms.Label
            $lbHRiskWzTitle.text = "HIGH RISK TRAFFIC INVESTIGATION WIZARD"
            $lbHRiskWzTitle.ForeColor = "Red"
            $lbHRiskWzTitle.AutoSize = $false
            $lbHRiskWzTitle.width = 1285
            $lbHRiskWzTitle.height = 20
            $lbHRiskWzTitle.location = New-Object Drawing.Point 5,5
            $lbHRiskWzTitle.TextAlign = "MiddleCenter"
            $lbHRiskWzTitle.Font = New-Object Drawing.Font('Arial Bold',12)
            $lbHRiskWzTitle.BackColor = "LightGray"
            #$lbHRiskWzTitle.ReadOnly = $True
            $lbHRiskWzTitle.TabStop = $False

            $lbHRiskThreatDesc = New-Object Windows.Forms.Label
            $lbHRiskThreatDesc.text = ""
            $lbHRiskThreatDesc.ForeColor = "White"
            $lbHRiskThreatDesc.AutoSize = $false
            $lbHRiskThreatDesc.width = 495
            $lbHRiskThreatDesc.height = 20
            $lbHRiskThreatDesc.location = New-Object Drawing.Point 795,5
            #$lbHRiskThreatDesc.TextAlign = "Left"
            $lbHRiskThreatDesc.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskThreatDesc.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskThreatDesc.ReadOnly = $True
            $lbHRiskThreatDesc.TabStop = $False
            $lbHRiskThreatDesc.visible = $False

            $lbHRComplete = New-Object Windows.Forms.Label
            $lbHRComplete.text = "Investigation Result:"
            $lbHRComplete.ForeColor = "White"
            $lbHRComplete.AutoSize = $false
            $lbHRComplete.width = 495
            $lbHRComplete.height = 20
            $lbHRComplete.location = New-Object Drawing.Point 795,110
            #$lbHRComplete.TextAlign = "Left"
            $lbHRComplete.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRComplete.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRComplete.ReadOnly = $True
            $lbHRComplete.TabStop = $False
            $lbHRComplete.visible = $False

            $lbHRiskInvestS1 = New-Object Windows.Forms.Label
            $lbHRiskInvestS1.text = "Step 1: Select an IP to investigate:"
            $lbHRiskInvestS1.ForeColor = "Black"
            $lbHRiskInvestS1.AutoSize = $false
            $lbHRiskInvestS1.width = 245
            $lbHRiskInvestS1.height = 20
            $lbHRiskInvestS1.location = New-Object Drawing.Point 5,60
            #$lbHRiskInvestS1.TextAlign = "Left"
            $lbHRiskInvestS1.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS1.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS1.ReadOnly = $True
            $lbHRiskInvestS1.TabStop = $False
            $lbHRiskInvestS1.visible = $False

            $lbHRiskInvestS2 = New-Object Windows.Forms.Label
            $lbHRiskInvestS2.text = "Step 2: Search Logs:"
            $lbHRiskInvestS2.ForeColor = "Black"
            $lbHRiskInvestS2.AutoSize = $false
            $lbHRiskInvestS2.width = 245
            $lbHRiskInvestS2.height = 20
            $lbHRiskInvestS2.location = New-Object Drawing.Point 5,155
            $lbHRiskInvestS2.TextAlign = "MiddleLeft"
            $lbHRiskInvestS2.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS2.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS2.ReadOnly = $True
            $lbHRiskInvestS2.TabStop = $False
            $lbHRiskInvestS2.visible = $False

            $lbHRiskInvestS3 = New-Object Windows.Forms.Label
            $lbHRiskInvestS3.text = "Step 3: Network Location & Ping Status:"
            $lbHRiskInvestS3.ForeColor = "Black"
            $lbHRiskInvestS3.AutoSize = $false
            $lbHRiskInvestS3.width = 245
            $lbHRiskInvestS3.height = 20
            $lbHRiskInvestS3.location = New-Object Drawing.Point 5,200
            $lbHRiskInvestS3.TextAlign = "MiddleLeft"
            $lbHRiskInvestS3.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS3.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS3.ReadOnly = $True
            $lbHRiskInvestS3.TabStop = $False
            $lbHRiskInvestS3.visible = $False

            $lbHRiskInvestS4 = New-Object Windows.Forms.Label
            $lbHRiskInvestS4.text = "Step 4: Resolve the IP to a name:"
            $lbHRiskInvestS4.ForeColor = "Black"
            $lbHRiskInvestS4.AutoSize = $false
            $lbHRiskInvestS4.width = 245
            $lbHRiskInvestS4.height = 20
            $lbHRiskInvestS4.location = New-Object Drawing.Point 5,245
            #$lbHRiskInvestS4.TextAlign = "Left"
            $lbHRiskInvestS4.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS4.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS4.ReadOnly = $True
            $lbHRiskInvestS4.TabStop = $False
            $lbHRiskInvestS4.visible = $False

            $lbHRiskInvestS5 = New-Object Windows.Forms.Label
            $lbHRiskInvestS5.text = "Step 5: Scan selected IP:"
            $lbHRiskInvestS5.ForeColor = "Black"
            $lbHRiskInvestS5.AutoSize = $false
            $lbHRiskInvestS5.width = 450
            $lbHRiskInvestS5.height = 20
            $lbHRiskInvestS5.location = New-Object Drawing.Point 280,5
            #$lbHRiskInvestS5.TextAlign = "Left"
            $lbHRiskInvestS5.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS5.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS5.ReadOnly = $True
            $lbHRiskInvestS5.TabStop = $False
            $lbHRiskInvestS5.visible = $False

            $lbHRiskInvestS6 = New-Object Windows.Forms.Label
            $lbHRiskInvestS6.text = "Step 6: Trace Route Results:"
            $lbHRiskInvestS6.ForeColor = "Black"
            $lbHRiskInvestS6.AutoSize = $false
            $lbHRiskInvestS6.width = 505
            $lbHRiskInvestS6.height = 20
            $lbHRiskInvestS6.location = New-Object Drawing.Point 280,140
            $lbHRiskInvestS6.TextAlign = "MiddleLeft"
            $lbHRiskInvestS6.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS6.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS6.ReadOnly = $True
            $lbHRiskInvestS6.Enabled = $True
            $lbHRiskInvestS6.TabStop = $False
            $lbHRiskInvestS6.visible = $False

            $lbHRiskInvestS7 = New-Object Windows.Forms.Label
            $lbHRiskInvestS7.text = "Step 7: IP Reputation:"
            $lbHRiskInvestS7.ForeColor = "Black"
            $lbHRiskInvestS7.AutoSize = $false
            $lbHRiskInvestS7.width = 505
            $lbHRiskInvestS7.height = 20
            $lbHRiskInvestS7.location = New-Object Drawing.Point 280,225
            $lbHRiskInvestS7.TextAlign = "MiddleLeft"
            $lbHRiskInvestS7.Font = New-Object Drawing.Font('Arial Bold',10)
            #$lbHRiskInvestS7.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbHRiskInvestS7.ReadOnly = $True
            $lbHRiskInvestS7.TabStop = $False
            $lbHRiskInvestS7.visible = $False

            $lstbxHRiskSrc = New-Object System.Windows.Forms.Listview
            $lstbxHRiskSrc.FullRowSelect = $True
            $lstbxHRiskSrc.Location = New-Object Drawing.Point 5,80
            $lstbxHRiskSrc.AutoSize = $False
            $lstbxHRiskSrc.size = New-Object Drawing.Point 260,21
            $lstbxHRiskSrc.Scrollable = $True
            $lstbxHRiskSrc.Height = 75
            $lstbxHRiskSrc.columns.add("Detected IP") | Out-Null
            $lstbxHRiskSrc.columns.add("Detected Offense") | Out-Null
            $lstbxHRiskSrc.add_columnclick({if($lstbxHRiskSrc.Sorting -eq "Descending") {$lstbxHRiskSrc.Sorting = "None"; Update_Controls(@())} else {$lstbxHRiskSrc.Sorting = "Descending";$lstbxHRiskSrc.sort()}})
            $lstbxHRiskSrc.view = "Details"
            $lstbxHRiskSrc.Enabled = $False
            $lstbxHRiskSrc.Visible = $False
            $lstbxHRiskSrc.add_Click({Step1_Click})

            $lstbxInvestS5 = New-Object System.Windows.Forms.Listview
            $lstbxInvestS5.FullRowSelect = $True
            $lstbxInvestS5.Location = New-Object Drawing.Point 280,25
            $lstbxInvestS5.AutoSize = $False
            $lstbxInvestS5.size = New-Object Drawing.Point 505,21
            $lstbxInvestS5.Scrollable = $True
            $lstbxInvestS5.Height = 115
            $lstbxInvestS5.columns.add("Port") | Out-Null
            $lstbxInvestS5.columns.add("State") | Out-Null
            $lstbxInvestS5.columns.add("Protocol") | Out-Null
            $lstbxInvestS5.columns.add("Description") | Out-Null
            $lstbxInvestS5.columns.add("Discovered Information") | Out-Null
            $lstbxInvestS5.add_columnclick({if($lstbxInvestS5.Sorting -eq "Descending") {$lstbxInvestS5.Sorting = "None"; Update_Controls(@())} else {$lstbxInvestS5.Sorting = "Descending";$lstbxInvestS5.sort()}})
            $lstbxInvestS5.view = "Details"
            $lstbxInvestS5.Enabled = $False
            $lstbxInvestS5.visible = $False
            #$lstbxInvestS5.add_Click({Step1_Click})

            $gbInvestChoices = New-Object system.Windows.Forms.Groupbox
            $gbInvestChoices.height = 57
            $gbInvestChoices.width = 260
            $gbInvestChoices.text = "Investigation Choices"
            $gbInvestChoices.font = New-Object Drawing.Font('Arial Bold',10)
            $gbInvestChoices.location = New-Object System.Drawing.Point(5,2)
            $gbInvestChoices.Visible = $True
            $gbInvestChoices.ForeColor = "White"

            $rbHRisk = New-Object system.Windows.Forms.RadioButton
            $rbHRisk.text = "High Risk Issues"
            $rbHRisk.AutoSize = $true
            $rbHRisk.width = 120
            $rbHRisk.height = 12
            $rbHRisk.location = New-Object System.Drawing.Point(5,17)
            $rbHRisk.Font = New-Object System.Drawing.Font('Arial Bold',9)
            $rbHRisk.Add_Click({RiskSelected_Click})

            $rbMRisk = New-Object system.Windows.Forms.RadioButton
            $rbMRisk.text = "Medium Risk Issues"
            $rbMRisk.AutoSize = $true
            $rbMRisk.width = 120
            $rbMRisk.height = 12
            $rbMRisk.location = New-Object System.Drawing.Point(125,17)
            $rbMRisk.Font = New-Object System.Drawing.Font('Arial Bold',9)
            $rbMRisk.Add_Click({RiskSelected_Click})

            $rbLRisk = New-Object system.Windows.Forms.RadioButton
            $rbLRisk.text = "Low Risk Issues"
            $rbLRisk.AutoSize = $true
            $rbLRisk.width = 120
            $rbLRisk.height = 12
            $rbLRisk.location = New-Object System.Drawing.Point(5,33)
            $rbLRisk.Font = New-Object System.Drawing.Font('Arial Bold',9)
            $rbLRisk.Add_Click({RiskSelected_Click})

            $rbOther = New-Object system.Windows.Forms.RadioButton
            $rbOther.text = "Other"
            $rbOther.AutoSize = $true
            $rbOther.width = 120
            $rbOther.height = 12
            $rbOther.location = New-Object System.Drawing.Point(125,33)
            $rbOther.Font = New-Object System.Drawing.Font('Arial Bold',9)
            $rbOther.Add_Click({RiskSelected_Click})

        # Licensing Tab
            $License_Panel = New-Object Windows.Forms.Panel
            $License_Panel.height = 130
            $License_Panel.width = 193
            $License_Panel.location = New-Object System.Drawing.Point(3,155)
            $License_Panel.BackColor = "lightgray"
            #$License_Panel.SendToBack()

            $tbLicOne = New-Object System.Windows.Forms.TextBox
            $tbLicOne.Text = ""
            #$tbLicOne.ForeColor = "white"
            #$tbLicOne.BackColor = "blue"
            $tbLicOne.Location = New-Object Drawing.Point 20,78
            $tbLicOne.AutoSize = $False
            $tbLicOne.size = New-Object Drawing.Point 42,23
            $tbLicOne.IsAccessible = $false
            $tbLicOne.Font = New-Object Drawing.Font('Arial Bold',10)
            $tbLicOne.TextAlign = 2
            #$tbLicOne.ReadOnly = $True
            #$tbLicOne.TabStop = $False
            #$tbLicOne.BringToFront()

            $tbLicTwo = New-Object System.Windows.Forms.TextBox
            $tbLicTwo.Text = ""
            #$tbLicTwo.ForeColor = "white"
            #$tbLicTwo.BackColor = "blue"
            $tbLicTwo.Location = New-Object Drawing.Point 73,78
            $tbLicTwo.AutoSize = $False
            $tbLicTwo.size = New-Object Drawing.Point 42,23
            $tbLicTwo.IsAccessible = $false
            $tbLicTwo.Font = New-Object Drawing.Font('Arial Bold',10)
            $tbLicTwo.TextAlign = 2
            #$tbLicTwo.ReadOnly = $True
            #$tbLicTwo.TabStop = $False
            #$tbLicTwo.BringToFront()

            $tbLicThree = New-Object System.Windows.Forms.TextBox
            $tbLicThree.Text = ""
            #$tbLicThree.ForeColor = "white"
            #$tbLicThree.BackColor = "blue"
            $tbLicThree.Location = New-Object Drawing.Point 126,78
            $tbLicThree.AutoSize = $False
            $tbLicThree.size = New-Object Drawing.Point 42,23
            $tbLicThree.IsAccessible = $false
            $tbLicThree.Font = New-Object Drawing.Font('Arial Bold',10)
            $tbLicThree.TextAlign = 2
            #$tbLicThree.ReadOnly = $True
            #$tbLicThree.TabStop = $False
            #$tbLicThree.BringToFront()

            $lbMACAddr = New-Object Windows.Forms.Label
            $lbMACAddr.text = "MAC Address"
            $lbMACAddr.ForeColor = "black"
            $lbMACAddr.AutoSize = $false
            $lbMACAddr.width = 188
            $lbMACAddr.height = 15
            $lbMACAddr.location = New-Object Drawing.Point 3,24
            $lbMACAddr.TextAlign = "MiddleCenter"
            $lbMACAddr.Font = New-Object Drawing.Font('Arial',10)
            #$lbMACAddr.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbMACAddr.ReadOnly = $True
            $lbMACAddr.TabStop = $False

            $lbLicenseInfo = New-Object Windows.Forms.Label
            $lbLicenseInfo.text = "License Information"
            $lbLicenseInfo.ForeColor = "black"
            $lbLicenseInfo.AutoSize = $false
            $lbLicenseInfo.width = 188
            $lbLicenseInfo.height = 15
            $lbLicenseInfo.location = New-Object Drawing.Point 3,5
            $lbLicenseInfo.TextAlign = "MiddleCenter"
            $lbLicenseInfo.Font = New-Object Drawing.Font('Arial',10)
            #$lbLicenseInfo.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbLicenseInfo.ReadOnly = $True
            $lbLicenseInfo.TabStop = $False

            $lbMAC = New-Object Windows.Forms.Label
            $lbMAC.text = ""
            $lbMAC.ForeColor = "black"
            $lbMAC.AutoSize = $false
            $lbMAC.width = 188
            $lbMAC.height = 15
            $lbMAC.location = New-Object Drawing.Point 3,39
            $lbMAC.TextAlign = "MiddleCenter"
            $lbMAC.Font = New-Object Drawing.Font('Arial',10)
            #$lbMAC.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbMAC.ReadOnly = $True
            $lbMAC.TabStop = $False

            $lbLicenseKey = New-Object Windows.Forms.Label
            $lbLicenseKey.text = "License Key"
            $lbLicenseKey.ForeColor = "black"
            $lbLicenseKey.AutoSize = $false
            $lbLicenseKey.width = 188
            $lbLicenseKey.height = 15
            $lbLicenseKey.location = New-Object Drawing.Point 3,59
            $lbLicenseKey.TextAlign = "MiddleCenter"
            $lbLicenseKey.Font = New-Object Drawing.Font('Arial',10)
            #$lbLicenseKey.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbLicenseKey.ReadOnly = $True
            $lbLicenseKey.TabStop = $False

            $lbLicKey = New-Object Windows.Forms.Label
            $lbLicKey.text = ""
            $lbLicKey.ForeColor = "black"
            $lbLicKey.AutoSize = $false
            $lbLicKey.width = 200
            $lbLicKey.height = 15
            $lbLicKey.location = New-Object Drawing.Point 3,90
            $lbLicKey.TextAlign = "MiddleCenter"
            $lbLicKey.Font = New-Object Drawing.Font('Arial',10)
            #$lbLicKey.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
            #$lbLicKey.ReadOnly = $True
            $lbLicKey.TabStop = $False

            $btnValidLic = New-Object Windows.Forms.Button
            $btnValidLic.Location = New-Object Drawing.Point 22,103
            $btnValidLic.size = New-Object Drawing.Point 144,24
            $btnValidLic.Text = "Validate License Key"
            $btnValidLic.BackColor = "Orange"
            $btnValidLic.ForeColor = "Black"
            $btnValidLic.Enabled = $False
            $btnValidLic.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',8)
            $btnValidLic.add_click({ValidLic_Click})
            $ttValidLic = New-Object Windows.Forms.ToolTip
            $ttValidLic.SetToolTip($btnValidLic, "Validate License Key")

            $tbLicenseTitle = New-Object System.Windows.Forms.TextBox
            $tbLicenseTitle.Text = "Windows Firewall Analyzer"
            $tbLicenseTitle.ForeColor = "Yellow"
            $tbLicenseTitle.BackColor = "DarkRed"
            $tbLicenseTitle.font = "Arial Bold, 11"
            $tbLicenseTitle.Location = New-Object Drawing.Point 3,5
            $tbLicenseTitle.AutoSize = $False
            $tbLicenseTitle.size = New-Object Drawing.Point 193,25
            $tbLicenseTitle.TextAlign = 2
            $tbLicenseTitle.ReadOnly = $True
            $tbLicenseTitle.TabStop = $False
            #$tbLicenseTitle.Enabled = $False

            $tbVersionInfo = New-Object System.Windows.Forms.TextBox
            $tbVersionInfo.Text = "Windows Firewall Analyzer`r`n"
            $tbVersionInfo.AppendText("Version: $global:FWMVersion`r`n")
            $tbVersionInfo.AppendText("Build Date: $global:BuildDate`r`n")
            $tbVersionInfo.AppendText("`r`nCopyright (C) 2016-2021 Tod Chapman`r`n")
            $tbVersionInfo.AppendText("All Rights Reserved.`r`n")
            $tbVersionInfo.ForeColor = "black"
            $tbVersionInfo.BackColor = "white"
            #$tbVersionInfo.font = "Arial Bold, 12"
            $tbVersionInfo.Location = New-Object Drawing.Point 3,30
            $tbVersionInfo.AutoSize = $False
            $tbVersionInfo.size = New-Object Drawing.Point 193,90
            $tbVersionInfo.Multiline = $True
            $tbVersionInfo.TextAlign = 2
            $tbVersionInfo.ReadOnly = $True
            $tbVersionInfo.TabStop = $False
            #$tbVersionInfo.Enabled = $False

            $tbLicense = New-Object System.Windows.Forms.TextBox
            $tbLicense.Text = "End-User License Agreement (EULA) of Windows Firewall Analyzer`r`n"
            $tbLicense.AppendText("`r`nThis End-User License Agreement (""EULA"") is a legal agreement between you and Tod Chapman.  This EULA agreement governs your acquisition and use of our Windows Firewall Monitor software (""Software"") directly from Tod Chapman or indirectly through a Tod Chapman authorized reseller or distributor (a ""Reseller""). Please read this EULA agreement carefully before completing the installation process and using the Windows Firewall Monitor software. It provides a license to use the Windows Firewall Monitor software and contains warranty information and liability disclaimers. If you register for a free trial of the Windows Firewall Monitor software, this EULA agreement will also govern that trial. By clicking ""accept"" or installing and/or using the Windows Firewall Monitor software, you are confirming your acceptance of the Software and agreeing to become bound by the terms of this EULA agreement. If you are entering into this EULA agreement on behalf of a company or other legal entity, you represent that you have the ")
            $tbLicense.AppendText("authority to bind such entity and its affiliates to these terms and conditions. If you do not have such authority or if you do not agree with the terms and conditions of this EULA agreement, do not install or use the Software, and you must not accept this EULA agreement. This EULA agreement shall apply only to the Software supplied by Tod Chapman herewith regardless of whether other software is referred to or described herein. The terms also apply to any Tod Chapman updates, supplements, Internet-based services, and support services for the Software, unless other terms accompany those items on delivery. If so, those terms apply.`r`n")
            $tbLicense.AppendText("`r`nLicense Grant`r`n")
            $tbLicense.AppendText("Tod Chapman hereby grants you a personal, non-transferable, non-exclusive licence to use the Windows Firewall Monitor software on your devices in accordance with the terms of this EULA agreement.  You are permitted to load the Windows Firewall Monitor software (for example a PC, laptop, mobile or tablet) under your control. You are responsible for ensuring your device meets the minimum requirements of the Windows Firewall Monitor software.`r`n")
            $tbLicense.AppendText("You are not permitted to:`r`n")
            $tbLicense.AppendText("  - Edit, alter, modify, adapt, translate or otherwise change the whole or any part of the Software nor permit the whole or any part of the Software to be combined with or become incorporated in any other software, nor decompile, disassemble or reverse engineer the Software or attempt to do any such things`r`n")
            $tbLicense.AppendText("  - Reproduce, copy, distribute, resell or otherwise use the Software for any commercial purpose`r`n")
            $tbLicense.AppendText("  - Allow any third party to use the Software on behalf of or for the benefit of any third party`r`n")
            $tbLicense.AppendText("  - Use the Software in any way which breaches any applicable local, national or international law`r`n")
            $tbLicense.AppendText("  - use the Software for any purpose that Tod Chapman considers is a breach of this EULA agreement.`r`n")
            $tbLicense.AppendText("`r`nIntellectual Property and Ownership`r`n")
            $tbLicense.AppendText("Tod Chapman shall at all times retain ownership of the Software as originally downloaded by you and all subsequent downloads of the Software by you. The Software (and the copyright, and other intellectual property rights of whatever nature in the Software, including any modifications made thereto) are and shall remain the property of Tod Chapman. Tod Chapman reserves the right to grant licences to use the Software to third parties.`r`n")
            $tbLicense.AppendText("`r`nTermination`r`n")
            $tbLicense.AppendText("This EULA agreement is effective from the date you first use the Software and shall continue until terminated. You may terminate it at any time upon written notice to Tod Chapman. It will also terminate immediately if you fail to comply with any term of this EULA agreement. Upon such termination, the licenses granted by this EULA agreement will immediately terminate and you agree to stop all access and use of the Software. The provisions that by their nature continue and survive will survive any termination of this EULA agreement.`r`n")
            $tbLicense.AppendText("`r`nGoverning Law`r`n")
            $tbLicense.AppendText("This EULA agreement, and any dispute arising out of or in connection with this EULA agreement, shall be governed by and construed in accordance with the laws of United States of America.")
            $tbLicense.ForeColor = "Black"
            $tbLicense.BackColor = "white"
            $tbLicense.font = "Arial, 10"
            $tbLicense.Location = New-Object Drawing.Point 200,5
            $tbLicense.AutoSize = $False
            $tbLicense.size = New-Object Drawing.Point 1095,280
            $tbLicense.Multiline = $True
            $tbLicense.AcceptsReturn = $True
            $tbLicense.ScrollBars = "Vertical"
            #$tbLicense.TextAlign = 2
            $tbLicense.ReadOnly = $True
            $tbLicense.TabStop = $False
            #$tbLicense.Enabled = $False
        # END of Licensing Tab


        # Help Tab

    # End of Tab Control

    # Form Controls
        $mainform.controls.AddRange(@($lstbxDstPort,$lstbxDstIP,$lstbxSrcIP,$lstbxAction,$lstbxProto,$FWStatus_Panel,$tbDstPrtSelected,$btnClearDstPrt,$tbDstIPSelected,$btnClearDstIP,$tbSrcIPSelected,$btnClearSrcIP,$tbActionSelected,$btnClearAction,$tbProtoSelected,$btnClearProto,$tbFWLog,$FWLog,$btnClearSearch,$btnAllTrafTo,$btnAllTrafFrom,$Options_Panel,$tabControl,$ProgramStatus_Panel))
        $FWStatus_Panel.Controls.AddRange(@($tbFWStatus,$lbProfile,$lbLogAllow,$lbLogDrop,$lbLogIgnored,$lbDefInbAction,$lbDefOutAction,$btnDomState,$btnPrivState,$btnPubState,$btnDLogAllow,$btnPrLogAllow,$btnPuLogAllow,$btnDLogDrop,$btnPrLogDrop,$btnPuLogDrop,$btnDLogIgnore,$btnPrLogIgnore,$btnPuLogIgnore,$btnDDefInb,$btnPrDefInb,$btnPuDefInb,$btnDDefOutb,$btnPrDefOutb,$btnPuDefOutb,$btnProfAll,$btnLogAllowAll,$btnLogDropAll,$btnLogIgnoredAll,$btnDefInbAll,$btnDefOutbAll,$lbDomProf,$lbPrivProf,$lbPubProf,$lbProfiles))
        #$ProgramStatus_Panel.Controls.AddRange(@($tbProgStatusTitle,$tbLicenseStatus,$tbAdminStatus,$tbInternetStatus,$tbLogFileStatus,$tbLoggingStatus,$tbHighStatus,$tbMedStatus,$tbLowStatus))
        $ProgramStatus_Panel.Controls.AddRange(@($tbProgStatusTitle,$tbLicenseStatus,$tbAdminStatus,$tbInternetStatus,$tbLogFileStatus,$tbLoggingStatus))
        $Options_Panel.controls.addrange(@($lbOptions,$cbIPv6,$cbPrevFile,$cbCurFile,$lbNumLines,$tbLastLines,$lbSelLog,$lbLogSize,$tbLogSize,$gbSystem))

        $gbSystem.controls.addrange(@($rbLocal, $rbRemote, $tbRemIP))

        $gbInvestChoices.Controls.AddRange(@($rbHRisk,$rbMRisk,$rbLRisk,$rbOther))

        # Tab Control
        #$tabControl.Controls.AddRange(@($LogTab,$NetConfigTab,$InvestigateTab,$LicensingTab,$HelpTab))
        $tabControl.Controls.AddRange(@($LogTab,$LicensingTab,$HelpTab))
            $LogTab.Controls.AddRange(@($lbLog,$tbAppLog,$lbStats,$tbAppStats))
<#            $NetConfigTab.Controls.AddRange(@($btnMSClient,$btnMSClient_Info,$btnMSServer,$btnMSServer_Info,$btnIPv4,$btnIPv4_Info,$btnQoS,$btnQoS_Info,$btnMultiplexor,$btnMultiplexor_Info,$btnLLDP,$btnLLDP_Info,$btnIPv6,$btnIPv6_Info,$btnLLTD,$btnLLTD_Info,$btnLLTDMapper,$btnLLTDMapper_Info,$tbNetDecision,$Network_Panel,$lstbxNetAdapt))
                $Network_Panel.Controls.AddRange(@($tbNetAll))
            $InvestigateTab.Controls.AddRange(@($gbInvestChoices,$lbHRiskInvestS1,$lstbxHRiskSrc,$lbHRiskInvestS2,$tbStep2LogSearch,$lbHRiskInvestS3,$tbStep3NetLoc,$lbHRiskInvestS4,$tbStep4DNS,$lbHRiskInvestS5,$lstbxInvestS5,$lbHRiskInvestS7,$tbStep7IPRep,$lbHRiskThreatDesc,$tbHRThreatDesc,$lbHRComplete,$tbHRInvResult,$lbHRiskInvestS6,$tbStep6TraceRt))
                $InvestigateTab.BackColor = "Gray"
#>
            $LicensingTab.Controls.addrange(@($tbLicense,$tbLicenseTitle,$tbVersionInfo,$License_Panel))
                $License_Panel.Controls.addrange(@($lbLicenseInfo,$lbMACAddr,$lbMAC,$tbLicOne,$tbLicTwo,$tbLicThree,$lbLicenseKey,$btnValidLic))
            #$AppConfigTab.Controls.AddRange(@($lbMonConfig))
            #$tabControl.Controls.Add($AlertTab)
            #$tabControl.Controls.Add($ProfileTab)
            #$tabControl.Controls.Add($RulebaseTab)
            #$tabControl.Controls.Add($AppConfigTab)
        # End of Tab Control

        $mainform.Add_Shown({
            #CLS
            $tbAppLog.Text = (get-date).ToString() + ": Program Started`r`n"
            $tbAppStats.Text = (get-date).ToString() + ": Program Started`r`n"
            $global:IPInfo += @(AdapterInfo)
            $lbMAC.text = $global:IPInfo[0].MAC_Address
            Build_LicenseKey
            $lbLicKey.text = ($global:LicenseKey[0]+$global:LicenseKey[1]).ToString() + " - " + ($global:LicenseKey[2]+$global:LicenseKey[3]).ToString() + " - " + ($global:LicenseKey[4]+$global:LicenseKey[5]).ToString()
            Disable_Controls

            if (Admin_Check -eq $True)
            {
                Internet_Check
                LogFile_Check
                $global:FWLogInfo = Get_FW_Logs
                $global:Live_Search = $global:FWLogInfo
                SearchJobs
                $tbDstPrtSelected.text = ""
                $tbDstIPSelected.text = ""
                $tbSrcIPSelected.text = ""
                $tbActionSelected.text = ""
                $tbProtoSelected.text = ""
                $tbDirSelected.text = ""
                #Port_Scan_Detect
                #Internet_IPs -IPType "Source"
                #Internet_IPs -IPType "Destination"
                #LowRisk_Check
                Update_Controls(@())
                ProfileState
                LogAllowState
                LogDropState
                LogIgnoreState
                DefInbAction
                DefOutbAction
                Enable_Controls
                $global:Initialize = $False
            }

        })

        $mainform.ShowDialog()
    }

# ******************************************
# *** END of Generate Main Form Function ***
# ******************************************

# ********************
# *** Main Program ***
# ********************

    GenerateMainForm

    [System.GC]::Collect()

# ***************************
# *** End of Main Program ***
# ***************************
