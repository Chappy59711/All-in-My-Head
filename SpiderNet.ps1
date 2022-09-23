    function IPType
    {        PARAM (
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
                $NetLoc = "Internet"
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

                                $NetLoc = IPType($Entry)
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

    Function NetSpider
    {
        PARAM (
                $FoundIPs
              )
        $FinalTR = @()
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
                #Write-Output "Trace Route to $DNS" | out-file -append $global:CurFName
                Write-Host "Trace Route to $DNS"
                $TraceRoute = @()
                $TraceRoute = test-netconnection -computername $DNS -TraceRoute -Hops 15 -warningaction SilentlyContinue

                foreach ($item in $TraceRoute.TraceRoute)
                {
                    $NetLoc = IPType($item)

                    $SplitTR = $DNS.split('.')
                    $TRNet = $SplitTR[0]+"."+$SplitTR[1]+"."+$SplitTR[2]+"."

                    if($item -ne '0.0.0.0')
                    {
                        $ResolveEachHop = Resolve-DnsName $Item -ErrorAction Ignore |Select-Object -exp NameHost
                        
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
                    #Write-Output "  > $item ==> $ResolveEachHop" | out-file -append $global:CurFName
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
        return $FinalTR
    }

    $FoundDNS = @()
    $FoundNetCon = @()
    $FoundDomains = @()
    $FoundArp = @()
    $FoundActPrts = @()
    $Found = @()
    $FinalList = @()
    $DiscoveryNets = @()

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

    #$FoundDNSCache| Group -property IPAddress | Sort Name

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

    

    $FinalList = $Found | where { $_.IPAddress.count -gt 0 } | Group -property IPAddress | Sort Name

    $FinalList

    $DiscNets = NetSpider($FinalList)
    $DiscoveryNets = $DiscNets | where { $_.IPNetwork.count -gt 0 } | Group -property IPNetwork

    $DiscoveryNets