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
    .PARAMETER S2File
        Save the output to a file
            FILE   - Save the output to a file
            NOFILE - Output to the screen (default)
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

$global:TCP_Ports = @('21','22','23','25','80','389','443','445','1433','3389','5101','5353','5355','5900','5938','5985','5986','8000','8010','9100','42981','50050')
$global:TCP_PortName = @('FTP','SSH','Telnet','SMTP','HTTP','LDAP','SSL (HTTPS)','SMB/CIFS','SQL','RDP','RDP','mDNS','LLMNR','VNC','TeamViewer','WinRM','WinRM','HTTP','HTTP','Print','RDP','CSTmSvr')
$global:UDP_Ports = @('53','67','88','123','137','161','389','5353','5355')
$global:UDP_PortName = @('DNS','DHCP','Kerberos','NTP','NetBIOS''SNMP','LDAP','mDNS','LLMNR')
$global:LinuxDistros = @('Android','Debian','GNU/Linux','Fedora','openSUSE','Red Hat','Slackware','SUSE','Ubuntu','Arch','CentOS','Gentoo','KNOPPIX','Mint','Mageia','Oracle','Scientific','Raspbian','Kali','ParrotOS','BackBox','BlackArch','CAINE','CensorNet','CLIP OS','Copperhead OS','Cyborg Hawk','DEFT','Security Onion','Sophos')

$global:ProgressPreference = 'SilentlyContinue'

# Program Versioning Information
$global:DiscIPVersion = "1.0.20220223"
$global:BuildDate = "02/23/2022"

function HTTP-Failure
{
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();
    Write-Host -BackgroundColor:Black -ForegroundColor:Red "Status: A system exception was caught."
    Write-Host -BackgroundColor:Black -ForegroundColor:Red $global:responsebody
    Write-Host -BackgroundColor:Black -ForegroundColor:Red "The request body has been saved to `$global:helpme"
    break
}

function Test-Port-Quick {
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

function Test-Port-UDP{  
<#    
.SYNOPSIS    
    Tests port on computer.  
     
.DESCRIPTION  
    Tests port on computer. 
      
.PARAMETER computer  
    Name of server to test the port connection on.
       
.PARAMETER port  
    Port to test 
        
.PARAMETER tcp  
    Use tcp port 
       
.PARAMETER udp  
    Use udp port  
      
.PARAMETER UDPTimeOut 
    Sets a timeout for UDP port query. (In milliseconds, Default is 1000)  
       
.PARAMETER TCPTimeOut 
    Sets a timeout for TCP port query. (In milliseconds, Default is 1000)
                  
.NOTES    
    Name: Test-Port.ps1  
    Author: Boe Prox  
    DateCreated: 18Aug2010   
    List of Ports: http://www.iana.org/assignments/port-numbers  
       
    To Do:  
        Add capability to run background jobs for each host to shorten the time to scan.         
.LINK    
    https://boeprox.wordpress.org 
      
.EXAMPLE    
    Test-Port -computer 'server' -port 80  
    Checks port 80 on server 'server' to see if it is listening  
     
.EXAMPLE    
    'server' | Test-Port -port 80  
    Checks port 80 on server 'server' to see if it is listening 
       
.EXAMPLE    
    Test-Port -computer @("server1","server2") -port 80  
    Checks port 80 on server1 and server2 to see if it is listening  
     
.EXAMPLE
    Test-Port -comp dc1 -port 17 -udp -UDPtimeout 10000
     
    Server   : dc1
    Port     : 17
    TypePort : UDP
    Open     : True
    Notes    : "My spelling is Wobbly.  It's good spelling but it Wobbles, and the letters
            get in the wrong places." A. A. Milne (1882-1958)
     
    Description
    -----------
    Queries port 17 (qotd) on the UDP port and returns whether port is open or not
        
.EXAMPLE    
    @("server1","server2") | Test-Port -port 80  
    Checks port 80 on server1 and server2 to see if it is listening  
       
.EXAMPLE    
    (Get-Content hosts.txt) | Test-Port -port 80  
    Checks port 80 on servers in host file to see if it is listening 
      
.EXAMPLE    
    Test-Port -computer (Get-Content hosts.txt) -port 80  
    Checks port 80 on servers in host file to see if it is listening 
         
.EXAMPLE    
    Test-Port -computer (Get-Content hosts.txt) -port @(1..59)  
    Checks a range of ports from 1-59 on all servers in the hosts.txt file      
             
#>  
[cmdletbinding(  
    DefaultParameterSetName = '',  
    ConfirmImpact = 'low'  
)]  
    Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [array]$computer,  
        [Parameter(  
            Position = 1,  
            Mandatory = $True,  
            ParameterSetName = '')]  
            [array]$port,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [int]$TCPtimeout=1000,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [int]$UDPtimeout=1000,             
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [switch]$TCP,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [switch]$UDP                                    
        )  
    Begin {  
        If (!$tcp -AND !$udp) {$tcp = $True}  
        #Typically you never do this, but in this case I felt it was for the benefit of the function  
        #as any errors will be noted in the output of the report          
        $ErrorActionPreference = "SilentlyContinue"  
        $report = @()  
    }  
    Process {     
        ForEach ($c in $computer) {  
            ForEach ($p in $port) {  
                If ($tcp) {    
                    #Create temporary holder   
                    $temp = "" | Select-Object Server, Port, TypePort, Open, Notes  
                    #Create object for connecting to port on computer  
                    $tcpobject = new-Object system.Net.Sockets.TcpClient  
                    #Connect to remote machine's port                
                    $connect = $tcpobject.BeginConnect($c,$p,$null,$null)  
                    #Configure a timeout before quitting  
                    $wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout,$false)  
                    #If timeout  
                    If(!$wait) {  
                        #Close connection  
                        $tcpobject.Close()  
                        Write-Verbose "Connection Timeout"  
                        #Build report  
                        $temp.Server = $c  
                        $temp.Port = $p  
                        $temp.TypePort = "TCP"  
                        $temp.Open = "False"  
                        $temp.Notes = "Connection to Port Timed Out"  
                    } Else {  
                        $error.Clear()  
                        $tcpobject.EndConnect($connect) | out-Null  
                        #If error  
                        If($error[0]){  
                            #Begin making error more readable in report  
                            [string]$string = ($error[0].exception).message  
                            $message = (($string.split(":")[1]).replace('"',"")).TrimStart()  
                            $failed = $true  
                        }  
                        #Close connection      
                        $tcpobject.Close()  
                        #If unable to query port to due failure  
                        If($failed){  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "TCP"  
                            $temp.Open = "False"  
                            $temp.Notes = "$message"  
                        } Else{  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "TCP"  
                            $temp.Open = "True"    
                            $temp.Notes = ""  
                        }  
                    }     
                    #Reset failed value  
                    $failed = $Null      
                    #Merge temp array with report              
                    $report += $temp  
                }      
                If ($udp) {  
                    #Create temporary holder   
                    $temp = "" | Select-Object Server, Port, TypePort, Open, Notes                                     
                    #Create object for connecting to port on computer  
                    $udpobject = new-Object system.Net.Sockets.Udpclient
                    #Set a timeout on receiving message 
                    $udpobject.client.ReceiveTimeout = $UDPTimeout 
                    #Connect to remote machine's port                
                    Write-Verbose "Making UDP connection to remote server" 
                    $udpobject.Connect("$c",$p) 
                    #Sends a message to the host to which you have connected. 
                    Write-Verbose "Sending message to remote host" 
                    $a = new-object system.text.asciiencoding 
                    $byte = $a.GetBytes("$(Get-Date)") 
                    [void]$udpobject.Send($byte,$byte.length) 
                    #IPEndPoint object will allow us to read datagrams sent from any source.  
                    Write-Verbose "Creating remote endpoint" 
                    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0) 
                    Try { 
                        #Blocks until a message returns on this socket from a remote host. 
                        Write-Verbose "Waiting for message return" 
                        $receivebytes = $udpobject.Receive([ref]$remoteendpoint) 
                        [string]$returndata = $a.GetString($receivebytes)
                        If ($returndata) {
                           Write-Verbose "Connection Successful"  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "UDP"  
                            $temp.Open = "True"  
                            $temp.Notes = $returndata   
                            $udpobject.close()   
                        }                       
                    } Catch { 
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") { 
                            #Close connection  
                            $udpobject.Close()  
                            #Make sure that the host is online and not a false positive that it is open 
                            If (Test-Connection -comp $c -count 1 -quiet) { 
                                Write-Verbose "Connection Open"  
                                #Build report  
                                $temp.Server = $c  
                                $temp.Port = $p  
                                $temp.TypePort = "UDP"  
                                $temp.Open = "True"  
                                $temp.Notes = "" 
                            } Else { 
                                <# 
                                It is possible that the host is not online or that the host is online,  
                                but ICMP is blocked by a firewall and this port is actually open. 
                                #> 
                                Write-Verbose "Host maybe unavailable"  
                                #Build report  
                                $temp.Server = $c  
                                $temp.Port = $p  
                                $temp.TypePort = "UDP"  
                                $temp.Open = "False"  
                                $temp.Notes = "Unable to verify if port is open or if host is unavailable."                                 
                            }                         
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) { 
                            #Close connection  
                            $udpobject.Close()  
                            Write-Verbose "Connection Timeout"  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "UDP"  
                            $temp.Open = "False"  
                            $temp.Notes = "Connection to Port Timed Out"                         
                        } Else {                      
                            $udpobject.close() 
                        } 
                    }     
                    #Merge temp array with report              
                    #$report += $temp
                    if ($temp.Open -eq "True")
                    {
                        Write-Host "Open" -ForegroundColor Green -Separator " ==> "
                    }
                    else
                    {
                        Write-Host "Closed" -ForegroundColor Red -Separator " ==> "
                    }
                }                                  
            }  
        }                  
    }  
    End {  
        #Generate Report  
        $report
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

$CurrentDate = Get-Date

if ($S2File -eq "FILE")
{
    $DirectoryToCreate = "\DiscoveryFiles\"

    if (!(Test-Path E:))
    {
        if (!(Test-Path D:))
        {
            if (-not (Test-Path -LiteralPath "C:$($DirectoryToCreate)"))
            {
                try
                {
                    New-Item -Path "C:$($DirectoryToCreate)" -ItemType Directory -ErrorAction Stop | Out-Null #-Force
                }
                catch
                {
                    Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
                }
                #"Successfully created directory '$DirectoryToCreate'."
                $FPath = "C:$($DirectoryToCreate)"
            }
            else
            {
                #"Directory already existed"
                $FPath = "C:$($DirectoryToCreate)"
            }
        }
        else
        {
            if (-not (Test-Path -LiteralPath "D:$($DirectoryToCreate)"))
            {
                try
                {
                    New-Item -Path "D:$($DirectoryToCreate)" -ItemType Directory -ErrorAction Stop | Out-Null #-Force
                }
                catch
                {
                    Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
                }
                #"Successfully created directory '$DirectoryToCreate'."
                $FPath = "D:$($DirectoryToCreate)"
            }
            else
            {
                #"Directory already existed"
                $FPath = "D:$($DirectoryToCreate)"
            }
        }
    }
    else
    {
        if (-not (Test-Path -LiteralPath "E:$($DirectoryToCreate)"))
        {
            try
            {
                New-Item -Path "E:$($DirectoryToCreate)" -ItemType Directory -ErrorAction Stop | Out-Null #-Force
            }
            catch
            {
                Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
            }
            #"Successfully created directory '$DirectoryToCreate'."
            $FPath = "E:$($DirectoryToCreate)"
        }
        else
        {
            #"Directory already existed"
            $FPath = "E:$($DirectoryToCreate)"
        }
    }

    $CurDate = $(Get-Date -Format "MM-dd-yy")
    $DevName = $IPAddress.replace(".","_")
    $PCFile = "$($DevName)_Disc_Results_$($CurDate).txt"
    $CurFName = "$($FPath)$($PCFile)"
}
write-host "********************************************************************************************"
write-host "** IP Discovery Tool                 version $global:DiscIPVersion    Build Date: $global:BuildDate       **"
write-host "**                                                                                        **"
write-host "** Arguments                                                                              **"
write-host "**   - IPAddress - IP address of the host to be scanned                                   **"
write-host "**   - DiscType  - Type of scan to run                                                    **"
write-host "**        FULL   - Perform SCAN, RISK, and DNS discoveries                                **"
write-host "**        SCAN   - Perform basic port scan of IP address (default)                        **"
write-host "**        RISK   - Analyze reputation websites for information on IP address              **"
write-host "**        DNS    - Perform ping, trace route, and DNS resolution of the IP address        **"
write-host "**   - TRDNS     - Include or do not include DNS resolution during trace route            **"
write-host "**        YES    - Include DNS resolution during trace route                              **"
write-host "**        NO     - Do not include DNS resolution during trace route (default)             **"
write-host "**   - S2File    - Save the output to a file                                              **"
write-host "**        FILE   - Save the output to a file                                              **"
write-host "**        NOFILE - Output to the screen (default)                                         **"
write-host "**                                                                                        **"
write-host "** Windows PowerShell (version 5.1)                                                       **"
write-host "**   - Works well for ping, trace route, DNS, and Risk                                    **"
write-host "**   - Issues with HTTP and HTTPS discovery (PowerShell 7x is better for this)            **"
write-host "**                                                                                        **"
write-host "** Windows PowerShell (version 7x)                                                        **"
write-host "**   - Works well for discovery of HTTP and HTTPS                                         **"
write-host "**   - Cannot perform Risk assessment                                                     **"
write-host "********************************************************************************************"
write-host "Discovery Start Date and Time: $CurrentDate"

if ($S2File -eq "FILE")
{
    write-output "********************************************************************************************" | out-file $CurFName
    write-output "** IP Discovery Tool                 version $global:DiscIPVersion    Build Date: $global:BuildDate       **" | out-file -append $CurFName
    write-output "**                                                                                        **" | out-file -append $CurFName
    write-output "** Arguments                                                                              **" | out-file -append $CurFName
    write-output "**   - IPAddress - IP address of the host to be scanned                                   **" | out-file -append $CurFName
    write-output "**   - DiscType  - Type of scan to run                                                    **" | out-file -append $CurFName
    write-output "**        FULL   - Perform SCAN, RISK, and DNS discoveries                                **" | out-file -append $CurFName
    write-output "**        SCAN   - Perform basic port scan of IP address (default)                        **" | out-file -append $CurFName
    write-output "**        RISK   - Analyze reputation websites for information on IP address              **" | out-file -append $CurFName
    write-output "**        DNS    - Perform ping, trace route, and DNS resolution of the IP address        **" | out-file -append $CurFName
    write-output "**   - TRDNS     - Include or do not include DNS resolution during trace route            **" | out-file -append $CurFName
    write-output "**        YES    - Include DNS resolution during trace route                              **" | out-file -append $CurFName
    write-output "**        NO     - Do not include DNS resolution during trace route (default)             **" | out-file -append $CurFName
    write-output "**   - S2File    - Save the output to a file                                              **" | out-file -append $CurFName
    write-output "**        FILE   - Save the output to a file                                              **" | out-file -append $CurFName
    write-output "**        NOFILE - Output to the screen (default)                                         **" | out-file -append $CurFName
    write-output "**                                                                                        **" | out-file -append $CurFName
    write-output "** Windows PowerShell (version 5.1)                                                       **" | out-file -append $CurFName
    write-output "**   - Works well for ping, trace route, DNS, and Risk                                    **" | out-file -append $CurFName
    write-output "**   - Issues with HTTP and HTTPS discovery (PowerShell 7x is better for this)            **" | out-file -append $CurFName
    write-output "**                                                                                        **" | out-file -append $CurFName
    write-output "** Windows PowerShell (version 7x)                                                        **" | out-file -append $CurFName
    write-output "**   - Works well for discovery of HTTP and HTTPS                                         **" | out-file -append $CurFName
    write-output "**   - Cannot perform Risk assessment                                                     **" | out-file -append $CurFName
    write-output "********************************************************************************************" | out-file -append $CurFName
    write-output "Discovery Start Date and Time: $CurrentDate"  | out-file -append $CurFName
}

$global:OverallTimer = [System.Diagnostics.Stopwatch]::StartNew()

#Resolve-DnsName $IPAddress

#(1..254) | % {$ip="10.0.40.$_"; Write-output "$IP  $(test-connection -computername "$ip" -quiet -count 1)  $( Resolve-DnsName $ip -ErrorAction Ignore |select -exp NameHost )  "}

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

$global:timer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "*************************************************************************************"
Write-Host -NoNewline "Pinging $IPAddress..."
$Pingable = test-connection -computername $IPAddress -quiet -count 1

if ($Pingable -eq $true)
{
    $output_string = [char]34 + "True" + [char]34 + ","

    $FinalTR = @()
    Write-Host "Successful." -ForegroundColor Green -Separator " ==> "

    if ($S2File -eq "FILE")
    {
        Write-Output "Pinging $IPAddress...Successful." | out-file -append $CurFName
    }

    if ($TRDNS.ToUpper() -eq "YES" -or $TRDNS.ToUpper() -eq "Y")
    {
        Write-Host "Performing Trace Route WITH DNS to $IPAddress..."
    
        if ($S2File -eq "FILE")
        {
            Write-Output "Performing Trace Route WITH DNS to $IPAddress..." | out-file -append $CurFName
        }
    }
    else
    {
        Write-Host "Performing Trace Route without DNS to $IPAddress..."

        if ($S2File -eq "FILE")
        {
            Write-Output "Performing Trace Route without DNS to $IPAddress..." | out-file -append $CurFName
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
            write-host "  ==> "$rec.IPAddress" <> "$rec.DNSName
            $temp_output_string = $temp_output_string + $rec.IPAddress + " <> " + $rec.DNSName + " "

            if ($S2File -eq "FILE")
            {
                Write-Output "  ==> "$rec.IPAddress" <> "$rec.DNSName | out-file -append $CurFName
            }
        }
        else
        {
            write-host "  ==> "$rec.IPAddress
            $temp_output_string = $temp_output_string + $rec.IPAddress + " "

            if ($S2File -eq "FILE")
            {
                Write-Output "  ==> "$rec.IPAddress | out-file -append $CurFName
            }
        }
    }
    $output_string = $output_string + [char]34 + $temp_output_string + [char]34 + ","
}
else
{
    Write-Host -nonewline "Failed." -ForegroundColor Red -Separator " ==> "
    $output_string = $output_string + [char]34 + "Failed" + [char]34 + ","
    if ($S2File -eq "FILE")
    {
        Write-Output "Pinging $IPAddress...Failed." | out-file -append $CurFName
    }
}

$global:timer.Stop()
$LoadTime = $global:timer.Elapsed
$ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
Write-Host " Ping Time:"$ElapsedTime

$global:timer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host -NoNewline "DNS Resolution for $IPAddress..."
$Resolvable = Resolve-DnsName $IPAddress -ErrorAction Ignore |Select-Object -exp NameHost

if ($Resolvable.Length -gt 0)
{
    Write-Host -nonewline "Successful ($Resolvable)." -ForegroundColor Green -Separator " ==> "
    $output_string = $output_string + [char]34 + $Resolvable + [char]34 + ","

    if ($S2File -eq "FILE")
    {
        Write-Output "DNS Resolution for $IPAddress...Successful." | out-file -append $CurFName
    }
}
else
{
    Write-Host -nonewline "Failed." -ForegroundColor Red -Separator " ==> "
    $output_string = $output_string + [char]34 + "Failed" + [char]34 + ","

    if ($S2File -eq "FILE")
    {
        Write-Output "DNS Resolution for $IPAddress...Failed." | out-file -append $CurFName
    }
}

$global:timer.Stop()
$LoadTime = $global:timer.Elapsed
$ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
Write-Host " DNS Time:"$ElapsedTime

$global:timer = [System.Diagnostics.Stopwatch]::StartNew()

$SplitIPAddress = $IPAddress.Split(".")

if ($SplitIPAddress[0] -ne 10)
{
    if ($SplitIPAddress[0] -ne 172)
    {
        if ($SplitIPAddress[0] -ne 192)
        {
            Write-Host "=============================== IP Info ===================================" -ForegroundColor Cyan
            Write-Host -NoNewline "Retrieveing IP Info from ipinfo.io..."
            $IPInfoURL = "https://ipinfo.io/" + $IPAddress + "/json?token=07ffbce68ef9cc"
            $IPInfoResults = Invoke-WebRequest -Uri $IPInfoURL
            Write-Host $IPInfoResults.Content
            Write-Host "Retrieveing IP Info from ipinfo.io...Completed"

            if ($S2File -eq "FILE")
            {
                Write-Output $IPInfoResults.Content | out-file -append $CurFName
            }

            $global:timer.Stop()
            $LoadTime = $global:timer.Elapsed
            $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
            Write-Host " IPInfo.io Query Time:"$ElapsedTime
        }
        else
        {
            if ($SplitIPAddress[1] -ne 168)
            {
                Write-Host "=============================== IP Info ===================================" -ForegroundColor Cyan
                Write-Host -NoNewline "Retrieveing IP Info from ipinfo.io..."
                $IPInfoURL = "https://ipinfo.io/" + $IPAddress + "/json?token=07ffbce68ef9cc"
                $IPInfoResults = Invoke-WebRequest -Uri $IPInfoURL
                Write-Host $IPInfoResults.Content
                Write-Host "Retrieveing IP Info from ipinfo.io...Completed"

                if ($S2File -eq "FILE")
                {
                    Write-Output $IPInfoResults.Content | out-file -append $CurFName
                }

                $global:timer.Stop()
                $LoadTime = $global:timer.Elapsed
                $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
                Write-Host " IPInfo.io Query Time:"$ElapsedTime
            }
        }
    }
    else
    {
        if ($SplitIPAddress[1] -lt 16 -Or $SplitIPAddress[1] -gt 32)
        {
            Write-Host "=============================== IP Info ===================================" -ForegroundColor Cyan
            Write-Host -NoNewline "Retrieveing IP Info from ipinfo.io..."
            $IPInfoURL = "https://ipinfo.io/" + $IPAddress + "/json?token=07ffbce68ef9cc"
            $IPInfoResults = Invoke-WebRequest -Uri $IPInfoURL
            Write-Host $IPInfoResults.Content
            Write-Host "Retrieveing IP Info from ipinfo.io...Completed"

            if ($S2File -eq "FILE")
            {
                Write-Output $IPInfoResults.Content | out-file -append $CurFName
            }

            $global:timer.Stop()
            $LoadTime = $global:timer.Elapsed
            $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
            Write-Host " IPInfo.io Query Time:"$ElapsedTime
        }
    }
}
#Write-host $output_string

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

if ($DiscType -eq "Full" -or $DiscType -eq "Scan")
{
    Write-Host "=============================== TCP Port Scanning ===================================" -ForegroundColor Cyan
    Write-Host "Scanning TCP ports (takes several minutes)..."
    $ListCount = 0
    $global:TCP_Ports.split(',') | Foreach-Object -Process {
                                                                $PrtNames = $global:TCP_PortName.split(',')
                                                                $CurPort = $PrtNames[$ListCount]
                                                                write-host -nonewline "  Scanning TCP port $_ $CurPort on $IPAddress..."
                                                                #Write-Progress -Activity "  Scanning TCP port $_ on $IPAddress..." -Status "Scanning"

                                                                $ListCount ++

                                                                $global:timer = [System.Diagnostics.Stopwatch]::StartNew()

                                                                #If (($a=Test-Connection $IpAddress -Port $_ -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true)
                                                                If (($a=Test-Port-Quick -ComputerName $IpAddress -Protocol 'TCP' -Port $_).Result -eq $true)
                                                                {
                                                                    Write-Host -NoNewLine "Open" -ForegroundColor Green -Separator " ==> "
                                                                    
                                                                    if ($S2File -eq "FILE")
                                                                    {
                                                                        Write-Output  "Scanning TCP port $_ $CurPort on $IPAddress...Open." | out-file -append $CurFName
                                                                    }

                                                                    Switch ($_)
                                                                    {
                                                                        "21" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
                                                                                $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -nonewline " Completed"

                                                                                if ($S2File -eq "FILE")
                                                                                {
                                                                                    Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                }
                                                                            }
                                                                        "22" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
                                                                                $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -nonewline " Completed"

                                                                                if ($S2File -eq "FILE")
                                                                                {
                                                                                    Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                }
                                                                                }
                                                                        "23" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
                                                                                $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -nonewline " Completed"

                                                                                if ($S2File -eq "FILE")
                                                                                {
                                                                                    Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                }
                                                                                }
                                                                        "25" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
                                                                                $PortFunction = TelnetDisc -PortNum $_ -IPAddr $IPAddress
                                                                                Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -nonewline " Completed"

                                                                                if ($S2File -eq "FILE")
                                                                                {
                                                                                    Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                }
                                                                                }
                                                                        "80" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
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
                                                                                    Write-host -nonewline " "$PortFunction -ForegroundColor Yellow

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    Write-host -nonewline " "$PortFunction":"$StatusDescription"`r`n" -ForegroundColor Yellow
                                                                                    Write-host ($RawContent -join "`n") -ForegroundColor Yellow

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort..." "$PortFunction":"$StatusDescription"`r`n"$RawContent Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }

                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -nonewline " Completed"

                                                                                if ($S2File -eq "FILE")
                                                                                {
                                                                                    Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                }
                                                                                }
                                                                        "443" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
                                                                                $PortFunction = Get-PublicKey -Uri "https://$IPAddress"
                                                                                Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -nonewline " Completed"

                                                                                if ($S2File -eq "FILE")
                                                                                {
                                                                                    Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                }
                                                                                }
                                                                        "445" {$ScanType = "URG"}
                                                                        "1433" {$ScanType = "URG"}
                                                                        "3389" {$ScanType = "RST"}
                                                                        "5985" {
                                                                                    Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
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
                                                                                    Write-host -nonewline " "$PortFunction -ForegroundColor Yellow
                                                                                    Write-Host -nonewline " Completed"

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }
                                                                        "8000" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
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
                                                                                    Write-host -nonewline " "$PortFunction -ForegroundColor Yellow

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    Write-host -nonewline " "$PortFunction":"$StatusDescription"`r`n" -ForegroundColor Yellow
                                                                                    Write-host ($RawContent -join "`n") -ForegroundColor Yellow

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }

                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -NoNewline " Completed"
                                                                                }
                                                                        "8010" {
                                                                                Write-Host -nonewline "`n    Interrogating TCP Port $_ $CurPort...`n"
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
                                                                                    Write-host -nonewline " "$PortFunction -ForegroundColor Yellow

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    Write-host -nonewline " "$PortFunction":"$StatusDescription"`r`n" -ForegroundColor Yellow
                                                                                    Write-host ($RawContent -join "`n") -ForegroundColor Yellow

                                                                                    if ($S2File -eq "FILE")
                                                                                    {
                                                                                        Write-Output  "    Interrogating TCP Port $_ $CurPort...$PortFunction Completed." | out-file -append $CurFName
                                                                                    }
                                                                                }

                                                                                $PortAnalysis = Port_Analysis -PortFunc $PortFunction
                                                                                Write-Host -NoNewline " Completed"
                                                                                }
                                                                        "50050" {
                                                                                    #wget -U "Internet Explorer" http://$IPAddress/vl6D
                                                                                    invoke-webrequest -Uri "http://$IPAddress/vl6D"
                                                                                }
                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    Write-Host -NoNewline "Closed" -Separator " ==> " -ForegroundColor Red

                                                                    if ($S2File -eq "FILE")
                                                                    {
                                                                        Write-Output  "Scanning TCP port $_ $CurPort on $IPAddress...Closed." | out-file -append $CurFName
                                                                    }
                                                                }
                                                                $global:timer.Stop()
                                                                $LoadTime = $global:timer.Elapsed
                                                                $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)
                                                                Write-Host " Scan Time:"$ElapsedTime
                                                            }
    Write-Host "Completed."

    if ($S2File -eq "FILE")
    {
        Write-Output  "Completed." | out-file -append $CurFName
    }


    Write-Host "=============================== UDP Port Scanning ===================================" -ForegroundColor Yellow
    Write-Host "Scanning UDP ports (takes several minutes)..."
    #$global:UDP_Ports.split(',') | Foreach-Object -Process {write-host -nonewline "  Scanning UDP port $_ on $IPAddress..."; Test-Port-UDP -comp $IPAddress -port $_ -udp -UDPtimeout 10000}
    $global:UDP_Ports.split(',') | Foreach-Object -Process {$global:timer = [System.Diagnostics.Stopwatch]::StartNew(); write-host -nonewline "  Scanning UDP port $_ on $IPAddress..."; if((Test-Port-Quick -ComputerName $IpAddress -Protocol 'UDP' -Port $_).Result -eq $False) { write-host -nonewline "Closed" -ForegroundColor Red} else { write-host -nonewline "Open" -ForegroundColor Green}; $global:timer.Stop(); $LoadTime = $global:timer.Elapsed; $ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks); Write-Host " Scan Time:"$ElapsedTime}
    Write-Host "Completed."
    Write-Host "*************************************************************************************"
}

if (($DiscType -eq "Full" -or $DiscType -eq "Risk"))
{
    if ($NetLoc -eq "Internet" -and $host.version.major -lt 7)
    {
        Write-Host "*************************************************************************************"
        Write-Host "Checking IP Reputation..."
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
                Write-host $RawData[2]
            }

            if ($line -like "*has been reported*")
            {
                $RawData = $TestData.InnerHTML[3].split('<').split('>')
                Write-host $RawData[0]$RawData[2]$RawData[4]$RawData[6]$RawData[8]$RawData[12]
            }
        }
        Write-Host "*************************************************************************************"
    }
    else
    {
        Write-Host "Risk data is not available using PowerShell 7.  Please run on PowerShell 5.1 (Windows PowerShell)." -f Red
    }
}
$global:OverallTimer.Stop()
$LoadOverallTime = $global:OverallTimer.Elapsed
$ElapsedOverallTime = "{0:HH:mm:ss}" -f ([datetime]$LoadOverallTime.Ticks)
Write-Host "*************************************************************************************"
Write-Host "Discovery Time:"$ElapsedOverallTime -f Green
Write-Host "*************************************************************************************"
$CurrentDate = Get-Date
Write-Host "*************************************************************************************"
write-host "Discovery Completion Date and Time: $CurrentDate"
Write-Host "*************************************************************************************"

if ($S2File -eq "FILE")
{
    Write-Output "*************************************************************************************" | out-file -append $CurFName
    Write-Output "Discovery Time:"$ElapsedOverallTime  | out-file -append $CurFName
    Write-Output "*************************************************************************************" | out-file -append $CurFName
    $CurrentDate = Get-Date
    Write-Output "*************************************************************************************" | out-file -append $CurFName
    write-Output "Discovery Completion Date and Time: $CurrentDate" | out-file -append $CurFName
    Write-Output "*************************************************************************************" | out-file -append $CurFName
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
