
CLS

$global:SvcName = @('AJRouter','ALG','bthserv','CertPropSvc','DiagTrack','DsmSvc','DPS','WdiServiceHost','WdiSystemHost','dmwappushservice','MapsBroker','HvHost','vmickvpexchange','vmicguestinterface','vmicshutdown','vmicheartbeat','vmicvmsession','vmicrdv','vmictimesync','vmicvss','SharedAccess','iphlpsvc','wlidsvc','MSiSCSI','NcaSvc','PhoneSvc','QWAVE','RmSvc','RpcLocator','SCardSvr','ScDeviceEnum','SCPolicySvc','SNMPTRAP','TapiSrv','TabletInputService','WalletService','Audiosrv','AudioEndpointBuilder','WbioSrvc','FrameServer','WerSvc','stisvc','icssvc')

[string]$SuccessColor = "Green"
[string]$FailedColor = "Red"

$global:OSType = "Server"
$global:OSName = "Server 2019"
$global:ValidOS = "False"
$global:SysInfo = ""

function getOSType
{
    $SearchCritType = "OS Configuration"
    $TempStringType = $global:SysInfo | findstr /B /C:$SearchCritType
    $OSTypeArray = $TempStringType.split(' ',4,[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
    $global:OSType = $OSTypeArray[3]

    $SearchCritName = "OS Name"
    $TempStringName = $global:SysInfo | findstr /B /C:$SearchCritName
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

Function VerifySettings
{
	$global:NetworkIssues = 0

    Write-Host "`nCurrent Computer Settings" -f Yellow
	Write-Host "=======================================================================================================" -f Cyan
	Write-Host "`n  Current Computer Name: $env:COMPUTERNAME"
	Write-Host "`n  Current Network Adapter Settings:" -f $SuccessColor
	Write-Host "  ====================================================================================================="
	
    $EthAdapters = Get-NetAdapter | Select Name,LinkSpeed,ifIndex,Status | Sort Name | Foreach-object {
        $EthAdapt = $_.Name

        if ($_.Status -eq "Up")
        {
            $InterIndex = $_.ifIndex
		    $LinkSpd = $_.LinkSpeed
		    $AdaptStatus = $_.Status
	    
		    Write-Host "`n    Auditing Current Settings for $EthAdapt..." -f Yellow
		    Write-Host "    ==================================================================================================="

            $CurrentIPAddressInfo = Get-NetIPAddress | Select InterfaceAlias, IPAddress, PrefixLength, AddressFamily | where {$_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -eq $EthAdapt}
            $RouteStatus = get-netroute | Select DestinationPrefix, NextHop, ifIndex | where {$_.IfIndex -eq $InterIndex -and $_.DestinationPrefix -eq "0.0.0.0/0"}

		    $DHCPStatus = Get-NetAdapter -Name $EthAdapt | Get-NetIPInterface -Addressfamily IPv4 | Select Dhcp, ConnectionState
		
		    $DNSServers = get-DnsClientServerAddress | Select ServerAddresses, InterfaceIndex, Addressfamily | where {$_.InterfaceIndex -eq $InterIndex -and $_.AddressFamily -eq 2}
        
            $LMHosts = get-wmiobject win32_networkadapterconfiguration | Select InterfaceIndex, WinsEnableLMHostsLookup | where { $_.InterfaceIndex -eq $InterIndex }
		    $NetBIOSSetting = get-wmiobject win32_networkadapterconfiguration | Select InterfaceIndex, tcpipnetbiosoptions | where { $_.InterfaceIndex -eq $InterIndex }
		
		    if ($NetBIOSSetting.tcpipnetbiosoptions -eq 2)
		    {
			    $NetBIOSSet = "Disabled"
	    	}
		    else
		    {
			    $NetBIOSSet = "Enabled"
		    }
		
            $TempIP = $CurrentIPAddressInfo.IPAddress
            $TempSubnet = $CurrentIPAddressInfo.PrefixLength
            $TempDGW = $RouteStatus.NextHop

            if ($DNSServers.ServerAddresses.count -gt 0)
            {
                $TempPriDNS = $DNSServers.ServerAddresses[0]
                $TempSecDNS = $DNSServers.ServerAddresses[1]
                $TempDNSServers = "$TempPriDNS, $TempSecDNS"
            }
            else
            {
                $TempDNSServers = ""
            }

            Write-Host "      Connection Status:  $AdaptStatus"
		    Write-Host "      IP Address:         $TempIP"
            Write-Host "      Subnet Mask:        $TempSubnet"
		    Write-Host "      Default Gateway:    $TempDGW"
            Write-Host "      DNS Server(s):      $TempDNSServers"

            $TempDHCP = $DHCPStatus.DHCP

            if ($DHCPStatus.DHCP -eq $True)
            {
                Write-Host "      DHCP:               $TempDHCP. Desired configuration is Disabled." -f $FailedColor
                $global:NetworkIssues = $global:NetworkIssues + 1
            }
            else
            {
                Write-Host "      DHCP:               $TempDHCP. Desired configuration is met." -f $SuccessColor
            }

            if ($NetBIOSSet -eq "Enabled")
            {
                Write-Host "      NetBIOS over TCPIP: $NetBIOSSet. Desired configuration is disabled." -f $FailedColor
                $global:NetworkIssues = $global:NetworkIssues + 1
            }
            else
            {
                Write-Host "      NetBIOS over TCPIP: $NetBIOSSet. Desired configuration is met." -f $SuccessColor
            }

            $TempLMHosts = $LMHosts.WinsEnableLMHostsLookup
            if ($LMHosts.WinsEnableLMHostsLookup -eq "Enabled")
            {
                Write-Host "      LMHosts Lookup:     $TempLMHosts. Desired configuration is disabled." -f $FailedColor
                $global:NetworkIssues = $global:NetworkIssues + 1
            }
            else
            {
                Write-Host "      LMHosts Lookup:     $TempLMHosts. Desired configuration is met." -f $SuccessColor
            }
		
		    $BindingStatus = get-netadapterbinding | Select InterfaceAlias, ComponentID, Enabled | where { $_.InterfaceAlias -eq $EthAdapt -and ($_.ComponentID -ne "ms_server" -And $_.ComponentID -ne "ms_msclient" -And $_.ComponentID -ne "ms_lltdio" -And $_.ComponentID -ne "ms_rspndr" -And $_.ComponentID -ne "ms_tcpip") -And $_.Enabled -ne "True" }
		    if (($BindingStatus.ComponentID -eq "ms_implat") -and ($BindingStatus.ComponentID -eq "ms_lldp") -and ($BindingStatus.ComponentID -eq "ms_tcpip6") -and ($BindingStatus.ComponentID -eq "ms_pacer"))
		    {
			    Write-Host "      Network Services:   Desired configuration is met." -f $SuccessColor
		    }
		    else
		    {
			    Write-Host "      Network Services:   Desired configuration is ms_implat, ms_lldp, ms_tcpip6, and ms_pacer disabled." -f $FailedColor
                $global:NetworkIssues = $global:NetworkIssues + 1
		    }
	    }
        else
        {
		    Write-Host "`n    $EthAdapt is disabled." -f Yellow
		    Write-Host "    ==================================================================================================="
        }
    }

	Write-Host "`n    Global DNS Settings..." -f Yellow
	Write-Host "    ==================================================================================================="

    $DNSSearchStatus = Get-DnsClientGlobalSetting
    $TempUseSuffix = $DNSSearchStatus.UseSuffixSearchList
	Write-Host "      Use DNS Suffix:     $TempUseSuffix"
    
    $TempSuffixSearch = $DNSSearchStatus.SuffixSearchList
    if ($DNSSearchStatus.SuffixSearchList.count -gt 0)
    {
        $TempSearchList = $DNSSearchStatus.SuffixSearchList[0]
    }
    else
    {
        $TempSearchList  = ""
    }

	Write-Host "      DNS Suffix List:    $TempSearchList"
	
	Write-Host "`n    Network Registry Settings..." -f Yellow
	Write-Host "    ==================================================================================================="

    $global:RegistryIssues = 0
	$SrcRouting = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' |Select DisableIPSourceRouting
    if ($SrcRouting.DisableIPSourceRouting -eq 2)
    {
        Write-Host "      (IPv4) Perform Router Discovery registry key set correctly to 2." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review IPv4 Disable IP Source Routing registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting"
		Write-Host "        Should exist, be a DWORD, and have a value of 2."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

    $PerfRtrDisc = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' |Select PerformRouterDiscovery
    if ($PerfRtrDisc.PerformRouterDiscovery -eq 0)
    {
        Write-Host "      (IPv4) Perform Router Discovery registry key set correctly to 0." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review IPv4 Perform Router Discovery registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery"
		Write-Host "        Desired configuration => Should exist, be a DWORD, and have a value of 0."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

    $TCPOpts = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' |Select Tcp1323Opts
    if ($TCPOpts.Tcp1323Opts -eq 0)
    {
        Write-Host "      (IPv4) Tcp1323Opts registry key set correctly to 0." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review IPv4 Tcp1323Opts registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\Tcp1323Opts"
		Write-Host "        Desired configuration => Should exist, be a DWORD, and have a value of 0."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

    $SrcRouting6 = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters' |Select DisableIPSourceRouting
    if ($SrcRouting6.DisableIPSourceRouting -eq 2)
    {
        Write-Host "      (IPv6) Perform Router Discovery registry key set correctly to 2." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review IPv6 Disable IP Source Routing registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting"
		Write-Host "        Desired configuration => Should exist, be a DWORD, and have a value of 2."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

    $PerfRtrDisc6 = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters' |Select PerformRouterDiscovery
    if ($PerfRtrDisc6.PerformRouterDiscovery -eq 0)
    {
        Write-Host "      (IPv6) Perform Router Discovery registry key set correctly to 0." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review IPv6 Perform Router Discovery registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\PerformRouterDiscovery"
		Write-Host "        Desired configuration => Should exist, be a DWORD, and have a value of 0."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

    $TCPOpts6 = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters' |Select Tcp1323Opts
    if ($TCPOpts6.Tcp1323Opts -eq 0)
    {
        Write-Host "      (IPv6) Tcp1323Opts registry key set correctly to 0." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review IPv6 Tcp1323Opts registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\Tcp1323Opts"
		Write-Host "        Desired configuration => Should exist, is a DWORD, and have a value of 0."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

    $UPnPMode = Get-ItemProperty -path 'HKLM:\Software\Microsoft\DirectPlayNATHelp\DPNHUPnP' |Select UPnPMode
    if ($UPnPMode.UPnPMode -eq 2)
    {
        Write-Host "      UPnPMode registry key set correctly to 2." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review UPnPMode registry key entry." -f $FailedColor
		Write-Host "        HKLM:\Software\Microsoft\DirectPlayNATHelp\DPNHUPnP\UPnPMode"
		Write-Host "        Desired configuration => Should exist, is a DWORD, and have a value of 2."
        $global:RegistryIssues = $global:RegistryIssues + 1
    }

	Write-Host "`n    Remote Desktop Registry Settings..." -f Yellow
	Write-Host "    ==================================================================================================="
    $global:RDPIssues = 0
    $DenyRDP = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' |Select fDenyTSConnections
    if ($DenyRDP.fDenyTSConnections -eq 0)
    {
        Write-Host "      Remote Desktop is enabled." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review Remote Desktop enabled registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections"
		Write-Host "        Desired configuration => Should exist and have a value of 0."
        $global:RDPIssues = $global:RDPIssues + 1
    }

    $MinEncrypt = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |Select MinEncryptionLevel
    if ($MinEncrypt.MinEncryptionLevel -eq 4)
    {
        Write-Host "      Minimum encryption registry key set correctly to 4." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review Minimum encryption registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel"
		Write-Host "        Desired configuration => Should exist and have a value of 4."
        $global:RDPIssues = $global:RDPIssues + 1
    }

    $RDP_Port = 5101
    $RDPPort = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |Select PortNumber
    if ($RDPPort.PortNumber -eq $RDP_Port)
    {
        Write-Host "      RDP port number registry key set correctly to $RDP_Port." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review Port Number registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber"
		Write-Host "        Desired configuration => Should exist and have a value of $RDP_Port."
        $global:RDPIssues = $global:RDPIssues + 1
    }

    $SecLayer = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |Select SecurityLayer
    if ($SecLayer.SecurityLayer -eq 2)
    {
        Write-Host "      Security layer registry key set correctly to 2." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review Security Layer registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer"
		Write-Host "        Desired configuration => Should exist and have a value of 2."
        $global:RDPIssues = $global:RDPIssues + 1
    }

    $UserAuth = Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |Select UserAuthentication
    if ($UserAuth.UserAuthentication -eq 1)
    {
        Write-Host "      User authentication registry key set correctly to 1." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review User Authentication registry key entry." -f $FailedColor
		Write-Host "        HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication"
		Write-Host "        Desired configuration => Should exist and have a value of 1."
        $global:RDPIssues = $global:RDPIssues + 1
    }

    if (@(Get-NetFirewallRule -PolicyStore PersistentStore | Select DisplayName, Enabled, Direction, Profile | where {$_.DisplayName -eq "NWE Custom Inbound RDP Access" -and $_.Enabled -eq "True"}).count -eq 0)
    {
        Write-host "      Creation of RDP Access Rule...Failed or Did not happen.  Please Review Rulebase to verify RDP is allowed inbound on the proper port, $RDP_Port." -f Cyan
        $global:RDPIssues = $global:RDPIssues + 1
    }
    else
    {
        write-host "      Created RDP Access Rule...Success." -f $SuccessColor
    }

    $FilterPolicy = Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' |Select LocalAccountTokenFilterPolicy
    if ($FilterPolicy.LocalAccountTokenFilterPolicy -eq 1)
    {
        Write-Host "      Local account token filter policy is configured properly." -f $SuccessColor
    }
    else
    {
        Write-Host "      Please review Local Account Filter registry key entry." -f $FailedColor
		Write-Host "        HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy"
		Write-Host "        Should exist and have a value of 1."
    }

	Write-Host "`n    Time Settings..." -f Yellow
	Write-Host "    ==================================================================================================="
	
	$TimeZone = Get-TimeZone | Select DisplayName
	$TempTimeZone = $TimeZone.DisplayName
	if (($TempTimeZone.ToUpper() -like "*MOUNTAIN*") -And ($TempTimeZone.ToUpper() -like "*CENTRAL*"))
	{
		Write-host "      Time Zone is not Mountain or Central." -f $FailedColor
	}
	else
	{
		Write-host "      Time Zone is $TempTimeZone." -f $SuccessColor
	}
	
	$Configuration = (W32tm /query /source).trim()
	Write-Host "      Time Server:  $Configuration"

	Write-Host "`n    Local Groups..." -f Yellow
	Write-Host "    ==================================================================================================="

	$Groups = @(Get-LocalGroup | Select Name)
    $Groups.Name

	Write-Host "`n    Local Users..." -f Yellow
	Write-Host "    ==================================================================================================="
    $global:LocalUserIssues = 0
	$LocalUsers = @(Get-LocalUser | Select Name, Enabled, SID)
    $LocalUsers | FT

	if (@(Get-LocalUser | Select Name, SID | where {$_.SID -like "S-1-5-*-500" -and $_.Name -ne "Administrator"}).count -eq 0)
	{
		Write-Host "      The administrator account was not renamed." -f $FailedColor
        $global:LocalUserIssues = $global:LocalUserIssues + 1
	}
	else
	{
		Write-Host "      The administrator account was renamed." -f $SuccessColor
	}

	if (@(Get-LocalUser | Select Name, Description, Enabled | where {$_.Name -eq "Administrator" -and $_.Description -like "Built-in account*" -and $_.Enabled -eq $False}).count -eq 0)
	{
		Write-Host "      The dummy administrator account was either not created or not configured correctly.  Please check the description of the account." -f $FailedColor
        $global:LocalUserIssues = $global:LocalUserIssues + 1
	}
	else
	{
		Write-Host "      The dummy administrator account was created and configured correctly." -f $SuccessColor
	}

	Write-Host "`n    Environmental Variables..." -f Yellow
	Write-Host "    ==================================================================================================="
    $global:EnvVarIssues = 0
    if ($env:PATHEXT -like ".COM;.EXE;.BAT;.CMD;.MSC*")
    {
        Write-Host "      Powershell: Auto Execution Extensions: Environmental variable is correctly set." -f $SuccessColor
    }
    else
    {
        Write-Host "      Auto Execution Extensions: Environmental variable is NOT correctly set." -f $FailedColor
        $global:EnvVarIssues = $global:EnvVarIssues + 1
    }
	
    write-host "`n=======================================================================================================`n" -f Cyan

    <#Write-Host "`nVerifying Applying Microsoft Security Baseline settings...`n" -f Yellow

    if ((test-path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd\') -eq $True)
	{
		$LAPSPolicy = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' | Select AdmPwdEnabled
		if ($LAPSPolicy.AdmPwdEnabled -eq 1)
		{
			Write-Host "  Microsoft Security Baseline was applied properly." -f $SuccessColor
		}
		else
		{
			Write-Host "  Microsoft Security Baseline was NOT applied properly." -f $FailedColor
		}
	}
	else
	{
		Write-Host "  Microsoft Security Baseline was NOT applied properly." -f $FailedColor
	}

    Write-Host "`nVerifying Applying Microsoft Security Baseline settings...Verified.`n" -f Yellow
	#>

    Write-Host "`nVerifying Domain Status..." -f Yellow
    [string]$DomainJoined = $global:SysInfo | findstr Domain
    if (($DomainJoined -notlike "*.com") -and ($DomainJoined -notlike "*.local"))
    {
        Write-host "  Domain was NOT joined." -f $SuccessColor
    }
    else
    {
        Write-host "  Domain was joined." -f $SuccessColor
    }
    Write-Host "Verifying Domain Status...Verified.`n" -f Yellow

    $global:PrintSpoolIssues = 0
    Write-Host "`nVerifying Print Spooler Status..." -f Yellow
    if (@(get-service | where {$_.Name -eq "Spooler" -and $_.Status -eq "Running"} | Select Name, Status).count -ne 0)
    {
        if ($Global:OSType -eq "Workstation")
        {
            Write-host "  $Global:OSType Print Spooler is running." -f Yellow
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }
        else
        {
            Write-host "  $Global:OSType Print Spooler is running." -f $FailedColor
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }

        if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        {
            if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall')
            {
                $PointPrint = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' | Select NoWarningNoElevationOnInstall

                if ($PointPrint.NoWarningNoElevationOnInstall -eq 0)
                {
                    Write-Host "  NoWarningNoElevationOnInstall registry key exits and set correctly to 0." -f $SuccessColor
                }
                else
                {
                    Write-Host "  Please review SNoWarningNoElevationOnInstall registry key entry." -f $FailedColor
		            Write-Host "    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall"
		            Write-Host "    Desired configuration => Should either not exist or exist and have a value of 0."
                    $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
                }
            }
            else
            {
                Write-Host "  NoWarningNoElevationOnInstall registry key does not exist." -f $SuccessColor
            }
        }
        else
        {
            Write-Host "  PointAndPrint registry key does not exist." -f $FailedColor
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }
    
        if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        {
            if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnUpdate')
            {
                $PointPrint = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' | Select NoWarningNoElevationOnUpdate

                if ($PointPrint.NoWarningNoElevationOnUpdate -eq 0)
                {
                    Write-Host "  NoWarningNoElevationOnUpdate registry key exits and set correctly to 0." -f $SuccessColor
                }
                else
                {
                    Write-Host "  Please review NoWarningNoElevationOnUpdate registry key entry." -f $FailedColor
		            Write-Host "    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnUpdate"
		            Write-Host "    Desired configuration => Should either not exist or exist and have a value of 0."
                    $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
                }
            }
            else
            {
                Write-Host "  NoWarningNoElevationOnUpdate registry key does not exist." -f $SuccessColor
            }
        }
        else
        {
            Write-Host "  PointAndPrint registry key does not exist." -f $FailedColor
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }
    
        if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        {
            if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings')
            {
                $PointPrint = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' | Select UpdatePromptSettings

                if ($PointPrint.UpdatePromptSettings -eq 0)
                {
                    Write-Host "  UpdatePromptSettings registry key exits and set correctly to 0." -f $SuccessColor
                }
                else
                {
                    Write-Host "  Please review UpdatePromptSettings registry key entry." -f $FailedColor
		            Write-Host "    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings"
		            Write-Host "    Desired configuration => Should either not exist or exist and have a value of 0."
                    $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
                }
            }
            else
            {
                Write-Host "  UpdatePromptSettings registry key does not exist." -f $SuccessColor
            }
        }
        else
        {
            Write-Host "  PointAndPrint registry key does not exist." -f $FailedColor
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }
    
        if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        {
            if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators')
            {
                $PointPrint = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' | Select RestrictDriverInstallationToAdministrators

                if ($PointPrint.RestrictDriverInstallationToAdministrators -ne 0)
                {
                    Write-Host "  RestrictDriverInstallationToAdministrators registry key exits and set correctly to anything but 0." -f $SuccessColor
                }
                else
                {
                    Write-Host "  Please review RestrictDriverInstallationToAdministrators registry key entry." -f $FailedColor
		            Write-Host "    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators"
		            Write-Host "    Desired configuration => Should either not exist or exist and have any value except 0."
                    $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
                }
            }
            else
            {
                Write-Host "  RestrictDriverInstallationToAdministrators registry key does not exist." -f $FailedColor
                $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
            }
        }
        else
        {
            Write-Host "  PointAndPrint registry key does not exist." -f $FailedColor
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }

    }
    else
    {
        if ($Global:OSType -eq "Workstation")
        {
            Write-host "  $Global:OSType Print Spooler is not running." -f Yellow
            $global:PrintSpoolIssues = $global:PrintSpoolIssues + 1
        }
        else
        {
            Write-host "  $Global:OSType Print Spooler is not running." -f $SuccessColor
        }
    }

    Write-Host "Verifying Print Spooler Status...Verified.`n" -f Yellow

}

Function Verify_Reg_Settings([PSObject] $IncomingReg)
{

    $NWEBLPolicies = import-csv "C:\Temp\Test.csv"

    $global:OSRegIssues = 0

    foreach ($Policy in $NWEBLPolicies) {
        $TempPath = $Policy.'RegPath'
        $TempKey = $Policy.'RegKey'
        $Found = $False
        Write-Host -nonewline "`r                                                                                                                       "
        Write-Host -nonewline "`r$TempPath\$TempKey"
        if ((test-path $TempPath) -eq $False)
        {
            Write-Host "`rMissing Registry Key: $TempPath\$TempKey => $TempKeyVal is missing from the system registry." -f $FailedColor
            $global:OSRegIssues = $global:OSRegIssues + 1
        }
        ForEach ($a in $IncomingReg){
            $a.Property | ForEach-Object {
                $RegSettingKey = $_
                $RegSettingValue = $a.GetValue($_)
                $RegSettingName = $a.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
                $RegKeyInfo = "$RegSettingName!$RegSettingKey"
                If ("$TempPath!$TempKey" -eq $RegKeyInfo)
                {
                    $TempKeyVal = $Policy.'KeyValue'
                    $LocalPolicySetting = Get-ItemProperty -path $RegSettingName | Select $RegSettingKey
                    $TempLiveVal = $LocalPolicySetting.$RegSettingKey
                    $Found = $True
                    if ($LocalPolicySetting.$RegSettingKey -ne $TempKeyVal)
                    {
                        Write-Host "`rIncorrect Setting: Current Value: $TempLiveVal Correct Value: $TempPath\$TempKey => $TempKeyVal." -f $FailedColor
                        $global:OSRegIssues = $global:OSRegIssues + 1
                    }
                    #else
                    #{
                    #    Write-Host "$TempPath\$TempKey => $TempKeyVal." -f $SuccessColor
                    #}
                    break
                }
            }
        }
    }
    if ($Found -ne $True)
    {
        Write-Host "`rMissing Setting: $TempPath\$TempKey => $TempKeyVal is missing from the system registry." -f $FailedColor
        $global:OSRegIssues = $global:OSRegIssues + 1
    }
}

Write-Host "`nGetting OS Information..." -f Yellow
$global:SysInfo = systeminfo
getOSType
Write-Host "Getting OS Information...Completed.`n" -f Yellow

VerifySettings

$CurrentDate1 = Get-Date -format "yyyyMMddHHmm"

$registryWin = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse
$registryWin += Get-ChildItem "HKLM:\Software\Policies" -Recurse
$registryWin += Get-Item "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$registryWin += Get-ChildItem "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations" -Recurse
$registryWin += Get-ChildItem "HKLM:\System\CurrentControlSet\Services\Tcpip" -Recurse
$registryWin += Get-ChildItem "HKLM:\System\CurrentControlSet\Services\Tcpip6" -Recurse

Write-Host "`nVerifying NWE LGPO (can take several minutes)..." -f Yellow

Verify_Reg_Settings $registryWin

Write-Host "Verifying NWE LGPO...Verified." -f Yellow

Write-Host "`nVerifying NWE Password Policies..." -f Yellow

Write-Host "`nLocal Account Policies"
Write-Host "============================================================================"
$global:AccntPolIssues = 0
$TempAcctPol = @(Net Accounts)
$TempAcctPol = $TempAcctPol.Split(':')
$AcctPol = $TempAcctPol.Trim()
$ForceLogoff = "Never"
$MinPWAge = 2
$MaxPWAge = 180
$MinPWLen = 14
$PWHistKept = 24
$AccntLockout = 3
$LockoutDur = 30
$LockoutWin = 30

if ($ForceLogoff -ne $AcctPol[1])
{
    write-host "Force user logoff how long after time expires is set incorrectly. It should be $ForceLogoff." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($MinPWAge -ne $AcctPol[3])
{
    write-host "The minimum password age is set incorrectly. It should be $MinPWAge." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($MaxPWAge -ne $AcctPol[5])
{
    write-host "The maximim password age is set incorrectly. It should be $MaxPWAge." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($MinPWLen -ne $AcctPol[7])
{
    write-host "The minimum password length is set incorrectly. It should be $MinPWLen." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($PWHistKept -ne $AcctPol[9])
{
    write-host "The length of password history maintained is set incorrectly. It should be $PWHistKept." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($AccntLockout -ne $AcctPol[11])
{
    write-host "The account lockout threshold is set incorrectly. It should be $AccntLockout." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($LockoutDur -ne $AcctPol[13])
{
    write-host "The account lockout duration is set incorrectly. It should be $LockoutDur." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}

if ($LockoutWin -ne $AcctPol[15])
{
    write-host "The account lockout observation window is set incorrectly. It should be $LockoutWin." -f $FailedColor
    $global:AccntPolIssues = $global:AccntPolIssues + 1
}


Write-Host "`nDomain Policies"
Write-Host "============================================================================"

    $Domain = Get-ADDomain | Select Forest

    ##Get the RootDSE
    $RootDSE = Get-ADRootDSE -Server $Domain.Forest

    ##Get the Account Lockout policy
    #Store specific attributes from the domain header
    $AccountPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property lockoutDuration,lockoutObservationWindow,lockoutThreshold -Server $Domain.Forest

    #Format the Account Lockout policy
    $AccountPolicy | Select @{n="PolicyType";e={"Account Lockout"}},`
                            DistinguishedName,`
                            @{n="lockoutDuration";e={"$($_.lockoutDuration / -600000000) minutes"}},`
                            @{n="lockoutObservationWindow";e={"$($_.lockoutObservationWindow / -600000000) minutes"}},`
                            lockoutThreshold | Format-List


    ##Get the Password policy
    #Store specific attributes from the domain header    
    $PasswordPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property minPwdAge,maxPwdAge,minPwdLength,pwdHistoryLength,pwdProperties -Server $Domain.Forest
    
    #Format the Password policy
    $PasswordPolicy | Select @{n="PolicyType";e={"Password"}},`
                             DistinguishedName,`
                             @{n="minPwdAge";e={"$($_.minPwdAge / -864000000000) days"}},`
                             @{n="maxPwdAge";e={"$($_.maxPwdAge / -864000000000) days"}},`
                             minPwdLength,`
                             pwdHistoryLength,`
                             @{n="pwdProperties";e={Switch ($_.pwdProperties) {
                                  0 {"Passwords can be simple and the administrator account cannot be locked out"} 
                                  1 {"Passwords must be complex and the administrator account cannot be locked out"} 
                                  8 {"Passwords can be simple, and the administrator account can be locked out"} 
                                  9 {"Passwords must be complex, and the administrator account can be locked out"} 
                                  Default {$_.pwdProperties}}}}

$curColor = $host.ui.RawUI.ForegroundColor
$host.ui.RawUI.ForegroundColor = "Yellow"
Write-Output "Verifying NWE Password Policies...Verified."

Write-Output "`nVerifying NWE Firewall Configuration..."
Write-Host "============================================================================"

$host.ui.RawUI.ForegroundColor = $curColor

$global:FirewallIssues = 0
$FirewallProfiles = @()
$Recommend = ""
$curColor = $host.ui.RawUI.ForegroundColor
Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, Enabled | Sort Profile, Enabled | foreach-object {
        $ProfileName = $_.Profile
        $Enabled_Status = $_.Enabled
        if ($Enabled_Status -eq $False)
        {
            $Audit_Find = "System is incorrectly configured.  "
            $Recommend = "The value should be True (enabled)."
        }
        else
        {
            $Audit_Find = "System is correctly configured."
        }

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Enabled = $Enabled_Status
            Audit_Finding = $Audit_Find
            Recommendation = $Recommend
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $FirewallProfiles += $PSObject

        if ($Recommend -ne "")
        {
            $host.ui.RawUI.ForegroundColor = "Red"
            $global:FirewallIssues = $global:FirewallIssues + 1
        }
    }
    $FirewallProfiles | FT

    $host.ui.RawUI.ForegroundColor = $curColor

    $FirewallInb = @()
    $Recommend = ""
    $curColor = $host.ui.RawUI.ForegroundColor
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, DefaultInboundAction | Sort Profile, DefaultInboundAction | foreach-object {
        $ProfileName = $_.Profile
        $Def_In_Action = $_.DefaultInboundAction
        if ($Def_In_Action -eq "Block")
        {
            $Audit_Find = "System is incorrectly configured."
            $Recommend = "The value should be Allow."
        }
        else
        {
            $Audit_Find = "System is correctly configured."
        }

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Default_Inbound_Action = $Def_In_Action
            Audit_Finding = $Audit_Find
            Recommendation = $Recommend
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $FirewallInb += $PSObject

        if ($Recommend -ne "")
        {
            $host.ui.RawUI.ForegroundColor = "Red"
            $global:FirewallIssues = $global:FirewallIssues + 1
        }
    }
    $FirewallInb | FT

    $host.ui.RawUI.ForegroundColor = $curColor

    $FirewallOut = @()
    $Recommend = ""
    $curColor = $host.ui.RawUI.ForegroundColor
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, DefaultOutboundAction | Sort Profile, DefaultOutboundAction | foreach-object {
        $ProfileName = $_.Profile
        $Def_Out_Action = $_.DefaultOutboundAction
        if ($Def_Out_Action -eq "Block")
        {
            $Audit_Find = "System is incorrectly configured."
            $Recommend = "The value should be Allow."
        }
        else
        {
            $Audit_Find = "System is correctly configured."
        }

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Default_Outbound_Action = $Def_In_Action
            Audit_Finding = $Audit_Find
            Recommendation = $Recommend
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $FirewallOut += $PSObject

        if ($Recommend -ne "")
        {
            $host.ui.RawUI.ForegroundColor = "Red"
            $global:FirewallIssues = $global:FirewallIssues + 1
        }
    }
    $FirewallOut | FT

    $host.ui.RawUI.ForegroundColor = $curColor

    $FirewallLogAllow = @()
    $Recommend = ""
    $curColor = $host.ui.RawUI.ForegroundColor
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, LogAllowed | Sort Profile, LogAllowed | foreach-object {
        $ProfileName = $_.Profile
        $Log_Allowed = $_.LogAllowed
        if ($Log_Allowed -eq $False)
        {
            $Audit_Find = "System is incorrectly configured."
            $Recommend = "The value should be True (enabled)."
        }
        else
        {
            $Audit_Find = "System is correctly configured."
        }

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Log_Allowed_Enabled = $Log_Allowed
            Audit_Finding = $Audit_Find
            Recommendation = $Recommend
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $FirewallLogAllow += $PSObject

        if ($Recommend -ne "")
        {
            $host.ui.RawUI.ForegroundColor = "Red"
            $global:FirewallIssues = $global:FirewallIssues + 1
        }
    }
    $FirewallLogAllow | FT

    $host.ui.RawUI.ForegroundColor = $curColor

    $FirewallLogBlock = @()
    $Recommend = ""
    $curColor = $host.ui.RawUI.ForegroundColor
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, LogBlocked | Sort Profile, LogBlocked | foreach-object {
        $ProfileName = $_.Profile
        $Log_Blocked = $_.LogBlocked
        if ($Log_Blocked -eq $False)
        {
            $Audit_Find = "System is incorrectly configured."
            $Recommend = "The value should be True (enabled)."
        }
        else
        {
            $Audit_Find = "System is correctly configured."
        }

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Log_Blocked_Enabled = $Log_Blocked
            Audit_Finding = $Audit_Find
            Recommendation = $Recommend
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $FirewallLogBlock += $PSObject

        if ($Recommend -ne "")
        {
            $host.ui.RawUI.ForegroundColor = "Red"
            $global:FirewallIssues = $global:FirewallIssues + 1
        }
    }
    $FirewallLogBlock | FT

    $host.ui.RawUI.ForegroundColor = $curColor

    $FirewallLogIgnore = @()
    $Recommend = ""
    $curColor = $host.ui.RawUI.ForegroundColor
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select Profile, LogIgnored | Sort Profile, LogIgnored | foreach-object {
        $ProfileName = $_.Profile
        $Log_Ignored = $_.LogIgnored
        if ($Log_Ignored -eq $False)
        {
            $Audit_Find = "System is incorrectly configured."
            $Recommend = "The value should be True (enabled)."
        }
        else
        {
            $Audit_Find = "System is correctly configured."
        }

        $TempVar = [ordered]@{
            Profile = $ProfileName
            Log_Ignored_Enabled = $Log_Ignored
            Audit_Finding = $Audit_Find
            Recommendation = $Recommend
        }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $FirewallLogIgnore += $PSObject

        if ($Recommend -ne "")
        {
            $host.ui.RawUI.ForegroundColor = "Red"
            $global:FirewallIssues = $global:FirewallIssues + 1
        }
    }
    $FirewallLogIgnore | FT

    $host.ui.RawUI.ForegroundColor = $curColor

Write-Output "`nChecking Services..."
Write-Host "============================================================================"
$global:ServiceIssues = 0
Foreach ($Srv in $global:SvcName )
{
    Write-Host -nonewline "`r                   "
    Write-Host -nonewline "`r$Srv"

    $ServiceAnalysis = get-service | Select ServiceName, DisplayName, StartType, Status, RequiredServices | where { $_.ServiceName -eq $Srv }

    $ServiceName = $ServiceAnalysis.DisplayName

    if ($ServiceAnalysis.StartType -ne "Disabled")
    {
        if ($ServiceAnalysis.Status -eq "Running")
        {
            Write-Host "`rThe service, $ServiceName, is not disabled and is running." -f Red
            $global:ServiceIssues = $global:ServiceIssues + 1
        }
        else
        {
            Write-Host "`rThe service, $ServiceName, is not disabled and is not running." -f Red
            $global:ServiceIssues = $global:ServiceIssues + 1
        }
    }
    else
    {
        if ($ServiceAnalysis.Status -eq "Running")
        {
            Write-Host "`rThe service, $ServiceName, is disabled and is running." -f Red
            $global:ServiceIssues = $global:ServiceIssues + 1
        }
        else
        {
            Write-Host "`rThe service, $ServiceName, is disabled and is not running." -f Green
        }
    }

}

Write-Host "`nReview Findings"
Write-Host "============================================================================"

Write-Host "  Network Configuration"
Write-Host "  =========================================================================="
if ($global:NetworkIssues -gt 0)
{
    Write-Host "    $global:NetworkIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Network Registry Settings"
Write-Host "  =========================================================================="
if ($global:RegistryIssues -gt 0)
{
    Write-Host "    $global:RegistryIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  RDP Settings"
Write-Host "  =========================================================================="
if ($global:RDPIssues -gt 0)
{
    Write-Host "    $global:RDPIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Local Users"
Write-Host "  =========================================================================="
if ($global:LocalUserIssues -gt 0)
{
    Write-Host "    $global:LocalUserIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Environmental Variables"
Write-Host "  =========================================================================="
if ($global:EnvVarIssues -gt 0)
{
    Write-Host "    $global:EnvVarIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Print Spooler Settings"
Write-Host "  =========================================================================="
if ($global:PrintSpoolIssues -gt 0)
{
    Write-Host "    $global:PrintSpoolIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  OS Registry Settings"
Write-Host "  =========================================================================="
if ($global:OSRegIssues -gt 0)
{
    Write-Host "    $global:OSRegIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Account and Password Policies"
Write-Host "  =========================================================================="
if ($global:AccntPolIssues -gt 0)
{
    Write-Host "    $global:AccntPolIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Firewall Configuration"
Write-Host "  =========================================================================="
if ($global:FirewallIssues -gt 0)
{
    Write-Host "    $global:FirewallIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

Write-Host "`n  Services"
Write-Host "  =========================================================================="
if ($global:ServiceIssues -gt 0)
{
    Write-Host "    $global:ServiceIssues issue(s) have been found.  Please review the appropriate section above." -f $FailedColor
}
else
{
    Write-Host "    No issues found." -f $SuccessColor
}

# SIG # Begin signature block
# MIITTgYJKoZIhvcNAQcCoIITPzCCEzsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUf1r8TqPHUKVx0GVmo6/sJXal
# UXOgghCxMIIHyjCCBbKgAwIBAgITeAAAAAmHzADLupVfHAACAAAACTANBgkqhkiG
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJU0x+MX
# SXWE6+MvPf2fhPcbJmI4MA0GCSqGSIb3DQEBAQUABIIBAMQG8AV73ZXcZ8XsxJzT
# mby1BdLKuG3OcOWeXF9rhFiuQ4cjZxz4j/X4s1l09aM2lz+EnRHoPYosv3GKBYYu
# pMVPIkCxXCySkuWrdvZny2VHCKDb2R1kyKBhcjTE8u5GUAhdixaspz5OYRpnoqMU
# xazuTYFpuPnkpd6jJTMw+A4z9BUO0anFHA38aI9QhUsAq2UZTt6O4c0wd5CxjpMd
# jy6hrsqy/m3Nj3Y+faLKvAjVO5Y4gKvzpYAwBu5CKWaLMzvxgyXq3ZBN4JTqTWSj
# QyoQfb4yKwBUIPsQCR5Udv3rc1kGKzIN5pXYaJUIUBYpKFHPzUI1df1S+5VMY8qB
# ZDs=
# SIG # End signature block
