	<#
	.SYNOPSIS
		This function sweeps a defined network space using ping and can perform DNS resolution.
	.DESCRIPTION
		Sweeps a network for live hosts and their names.
	.NOTES
		
	.PARAMETER IPSpace
		IP Space to sweep.
    .PARAMETER IPStart
        IP address to start the sweep with.
    .PARAMETER IPEnd
        IP address to end the sweep with.
	.PARAMETER SweepType
        Type of scan to run
            PING   - Ping Only
            DNS    - DNS Only
            FULL   - Both Ping and DNS (default)
    .PARAMETER S2File
        Save the output to a file
            FILE   - Save the output to a file
            NOFILE - Output to the screen (default)
	.EXAMPLE
		PS> Sweeper -IPSpace 199.99.21.
		
		This example sweeps the IP space using a SweepType of Full
        
        PS> Sweeper -IPSpace 199.99.21. -IPStart 25 -IPEnd 35

        This example sweeps 199.99.21.25 through 199.99.21.35 using a SweepType of FULL

        PS> Sweeper -IPSpace 199.99.21. -SweepType PING -S2File FILE

        This example sweeps the IP space using a SweepType of PING and writes results to a file
	#>

param ( 
        [Parameter(Mandatory=$true, Position=0)]
        [String]$IPSpace,
        [Parameter(Mandatory=$false, Position=1)]
        [Int]$IPStart = 1,
        [Parameter(Mandatory=$false, Position=2)]
        [Int]$IPEnd = 255,
        [Parameter(Mandatory=$false, Position=3)]
        [validateset('PING','DNS','FULL')]
        [String]$SweepType = 'FULL',
        [Parameter(Mandatory=$false, Position=4)]
        [validateset('FILE','NOFILE')]
        [String]$S2File = 'NOFILE'
      )

# Program Versioning Information
$global:SweepVersion = "1.0.20220323"
$global:BuildDate = "03/23/2022"

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

$global:CurFName = $FPath+$IPSpace.replace(".","-")+".txt"

# The overwrite of the line does not worki in ISE window.
# Run in a normal PowerShell window for output to work properly.

#Check inputs
if($IPSpace.Substring($IPSpace.length) -ne "." -and $IPSpace.Substring($IPSpace.length-1) -ne ".")
{
    $IPSpace = $IPSpace + "."
}

if($IPStart -gt 255)
{
    $IPStart = 254
}

if($IPStart -lt 1)
{
    $IPStart = 1
}

if($IPEnd -gt 255)
{
    $IPEnd = 255
}

if($IPEnd -lt 1)
{
    $IPEnd = 2
}

$global:timer = [System.Diagnostics.Stopwatch]::StartNew()

$CurrentDate = Get-Date
$Pingable = "False"

if ($S2File -eq "FILE")
{
    write-output "********************************************************************************************" | out-file -append $global:CurFName
    write-output "** IP Space Sweep Tool               version $global:SweepVersion    Build Date: $global:BuildDate       **" | out-file -append $global:CurFName
    write-output "**                                                                                        **" | out-file -append $global:CurFName
    write-output "** Arguments                                                                              **" | out-file -append $global:CurFName
    write-output "**   - IPSpace   - IP space to sweep                                                      **" | out-file -append $global:CurFName
    write-output "**   - IPStart   - IP address to start the sweep with                                     **" | out-file -append $global:CurFName
    write-output "**   - IPEnd     - IP address to end the sweep with                                       **" | out-file -append $global:CurFName
    write-output "**   - SweepType - Type of sweep to run                                                   **" | out-file -append $global:CurFName
    write-output "**        PING   - Perform ping on each IP in IP Space                                    **" | out-file -append $global:CurFName
    write-output "**        DNS    - Perform DNS resolution on each IP in IP Space                          **" | out-file -append $global:CurFName
    write-output "**        SCAN   - Perform a basic service scan on each IP in IP Space                    **" | out-file -append $global:CurFName
    write-output "**        FULL   - Perform PING, DNS, and scan sweep of each IP in IP Space (default)     **" | out-file -append $global:CurFName
    write-output "**   - S2File    - Save the output to a file                                              **" | out-file -append $global:CurFName
    write-output "**        FILE   - Save the output to a file                                              **" | out-file -append $global:CurFName
    write-output "**        NOFILE - Output to the screen (default)                                         **" | out-file -append $global:CurFName
    write-output "**                                                                                        **" | out-file -append $global:CurFName
    write-output "** For a full class C network, the FULL sweep can take up to 45 minutes.                  **" | out-file -append $global:CurFName
    write-output "** For a full class C network, the PING sweep can take up to 20 minutes.                  **" | out-file -append $global:CurFName
    write-output "** For a full class C network, the DNS sweep can take up to 20 minutes.                   **" | out-file -append $global:CurFName
    write-output "********************************************************************************************" | out-file -append $global:CurFName
    write-output "$SweepType Sweep Start Date and Time: $CurrentDate" | out-file -append $global:CurFName
    Write-output "********************************************************************************************" | out-file -append $global:CurFName
}

write-host "********************************************************************************************"
write-host "** IP Space Sweep Tool               version $global:SweepVersion    Build Date: $global:BuildDate       **"
write-host "**                                                                                        **"
write-host "** Arguments                                                                              **"
write-host "**   - IPSpace   - IP space to sweep                                                      **"
write-host "**   - IPStart   - IP address to start the sweep with                                     **"
write-host "**   - IPEnd     - IP address to end the sweep with                                       **"
write-host "**   - SweepType - Type of sweep to run                                                   **"
write-host "**        PING   - Perform ping on each IP in IP Space                                    **"
write-host "**        DNS    - Perform DNS resolution on each IP in IP Space                          **"
write-host "**        SCAN   - Perform a basic service scan on each IP in IP Space                    **"
write-host "**        FULL   - Perform PING, DNS, and scan sweep of each IP in IP Space (default)     **"
write-host "**   - S2File    - Save the output to a file                                              **"
write-host "**        FILE   - Save the output to a file                                              **"
write-host "**        NOFILE - Output to the screen (default)                                         **"
write-host "**                                                                                        **"
write-host "** For a full class C network, the FULL sweep can take up to 45 minutes.                  **"
write-host "** For a full class C network, the PING sweep can take up to 20 minutes.                  **"
write-host "** For a full class C network, the DNS sweep can take up to 20 minutes.                   **"
write-host "********************************************************************************************"
write-host "$SweepType Sweep Start Date and Time: $CurrentDate"
Write-Host "********************************************************************************************"

for($i = $IPStart; $I -le $IPEnd; $i++)
{
    $IPAddress = "$IPSpace$i"
    Write-Host -nonewline "`r                                                   "

    if($SweepType.ToUpper() -eq "PING" -Or $SweepType.ToUpper() -eq "FULL")
    {
        Write-Host -nonewline "`rAttempting Ping of $IPAddress..."

        $Pingable = test-connection -computername $IPAddress -quiet -count 1
    }

    Write-Host -nonewline "`r                                                   "

    if($SweepType.ToUpper() -eq "DNS" -Or $SweepType.ToUpper() -eq "FULL")
    {
        Write-Host -nonewline "`rAttempting to Resolve Name of $IPAddress..."

        $Resolvable = Resolve-DnsName $IPAddress -ErrorAction Ignore |Select-Object -exp NameHost
    }

    if($Pingable -eq "True" -And $Resolvable.Count -gt 0)
    {
        write-host "`r$IPaddress ($Resolvable) responds to Ping."
        $TempVar = [ordered]@{
                                IPAddress = $IPAddress
                                Name = $Resolvable
                                Ping = $Pingable
                                }
        $PSObject = new-object -TypeName PSObject -Property $TempVar
        $SweepResults += @($PSObject)
    }
    else
    {
        if($Pingable -eq "False" -And $Resolvable.Count -gt 0)
        {
            if($SweepType.ToUpper() -eq "DNS")
            {
                write-host "`r$IPaddress resolves to $Resolvable."
                $TempVar = [ordered]@{
                        IPAddress = $IPAddress
                        Name = $Resolvable
                        #Ping = $Pingable
                        }
                $PSObject = new-object -TypeName PSObject -Property $TempVar
                $SweepResults += @($PSObject)
            }
            else
            {
                write-host "`r$IPaddress ($Resolvable) does NOT respond to Ping."
                $TempVar = [ordered]@{
                        IPAddress = $IPAddress
                        Name = $Resolvable
                        Ping = $Pingable
                        }
                $PSObject = new-object -TypeName PSObject -Property $TempVar
                $SweepResults += @($PSObject)
            }
        }
        else
        {
            if($Pingable -eq "True" -And $Resolvable.Count -eq 0)
            {
                if($SweepType.ToUpper() -eq "PING")
                {
                    write-host "`r$IPaddress responds to Ping."
                    $TempVar = [ordered]@{
                            IPAddress = $IPAddress
                            #Name = $Resolvable
                            Ping = $Pingable
                            }
                    $PSObject = new-object -TypeName PSObject -Property $TempVar
                    $SweepResults += @($PSObject)
                }
                else
                {
                    write-host "`r$IPaddress (can not be resolved) responds to Ping."
                    $TempVar = [ordered]@{
                            IPAddress = $IPAddress
                            Name = $Resolvable
                            Ping = $Pingable
                            }
                    $PSObject = new-object -TypeName PSObject -Property $TempVar
                    $SweepResults += @($PSObject)
                }
            }
        }
    }
}

$FoundIPs = $SweepResults.count

if ($S2File -eq "FILE")
{
    Write-Output "********************************************************************************************"| out-file -append $global:CurFName
    Write-Output "FINAL RESULTS ($FoundIPs Live IPs found.)"| out-file -append $global:CurFName
    Write-Output "********************************************************************************************"| out-file -append $global:CurFName

    $SweepResults | Format-Table | out-file -append $global:CurFName
}

Write-Host -nonewline "`r                                                   "
Write-Host "`r********************************************************************************************"
Write-Host "FINAL RESULTS ($FoundIPs Live IPs found.)"
Write-Host "********************************************************************************************"

$SweepResults | Format-Table

$global:Timer.Stop()
$LoadTime = $global:Timer.Elapsed
$ElapsedTime = "{0:HH:mm:ss}" -f ([datetime]$LoadTime.Ticks)

if ($S2File -eq "FILE")
{
    Write-Output "********************************************************************************************" | out-file -append $global:CurFName
    Write-Output "$SweepType Sweep Time:"$ElapsedTime | out-file -append $global:CurFName
    Write-Output "********************************************************************************************" | out-file -append $global:CurFName
    $CurrentDate = Get-Date
    Write-Output "********************************************************************************************" | out-file -append $global:CurFName
    write-Output "$SweepType Sweep Completion Date and Time: $CurrentDate" | out-file -append $global:CurFName
    Write-Output "********************************************************************************************" | out-file -append $global:CurFName
}

Write-Host "********************************************************************************************"
Write-Host "$SweepType Sweep Time:"$ElapsedTime -f Green
Write-Host "********************************************************************************************"
$CurrentDate = Get-Date
Write-Host "********************************************************************************************"
write-host "$SweepType Sweep Completion Date and Time: $CurrentDate"
Write-Host "********************************************************************************************"
