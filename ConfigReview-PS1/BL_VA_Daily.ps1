$DirectoryToCreate = "\BLVA_Files_Do_Not_Delete_TC\"

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
$ScriptPath = "\\xxxxxxx\netlogon\"
# $FPath = "c:\"
# $FPath = "E:$($DirectoryToCreate)"
$DevName = $env:COMPUTERNAME
$PCFile = "$($DevName)_Baseline_VulnAssess_$($CurDate).txt"
# $PPFile = "\Documents\$($DevName)_Baseline-Previous_$($CurDate).txt"
$CurFName = "$($FPath)$($PCFile)"
# $PrevFName = "$($HDrive)$($HPath)$($PPFile)"
# if (Test-Path $CurFName)
# {
#     if (Test-Path $PrevFName)
#     {
#         Remove-Item $PrevFName
#     }
#     Rename-Item -Path $CurFName -NewName $PrevFName
# }
"**********************" | out-file $CurFName
"*** OS Information ***" | out-file -append $CurFName
"**********************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" | out-file -append $CurFName
" "| out-file -append $CurFName
"******************************" | out-file -append $CurFName
"*** Installed Applications ***" | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\'))
{
  $unistallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
  $unistallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
  @(
  if (Test-Path "HKLM:$unistallWow6432Path" ) { Get-ChildItem "HKLM:$unistallWow6432Path"}
  if (Test-Path "HKLM:$unistallPath" ) { Get-ChildItem "HKLM:$unistallPath" }
  if (Test-Path "HKCU:$unistallWow6432Path") { Get-ChildItem "HKCU:$unistallWow6432Path"}
  if (Test-Path "HKCU:$unistallPath" ) { Get-ChildItem "HKCU:$unistallPath" }
  ) |
  ForEach-Object { Get-ItemProperty $_.PSPath } |
  Where-Object {
    $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove)
  } |
  Sort-Object DisplayName | Select-Object DisplayName
}
else
{
  "You are running 32-bit Powershell on 64-bit system. Please run 64-bit Powershell instead." | Write-Host -ForegroundColor Red
}
$64bitApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove) }
$32bitApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ReleaseType -and !$_.ParentKeyName -and ($_.UninstallString -or $_.NoRemove) }
$AllApps = $64bitApps + $32bitApps
$AllApps | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | ft -AutoSize" " | out-file -append $CurFName
"*************************" | out-file -append $CurFName
"*** Installed Patches ***" | out-file -append $CurFName
"*************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
get-hotfix | Sort-Object Description, InstalledOn | out-file -append $CurFName
" " | out-file -append $CurFName
"*******************************" | out-file -append $CurFName
"*** Malicious Client Status ***" | out-file -append $CurFName
"*******************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
$exists = (get-service * | Where-Object {$_.DisplayName -like "*Traps*"})
if (-Not $exists)
{
    "Network Level Protection Only => No Client Installed" | out-file -append $CurFName
}
else
{
    get-service * | Where-Object {$_.DisplayName -like "*Traps*"} | out-file -append $CurFName
}
" " | out-file -append $CurFName
"**********************" | out-file -append $CurFName
"*** Logging Status ***" | out-file -append $CurFName
"**********************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
auditpol /get /Category:"Logon/Logoff" | out-file -append $CurFName
" " | out-file -append $CurFName
"*********************************" | out-file -append $CurFName
"*** Local Account Information ***" | out-file -append $CurFName
"*********************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
get-wmiobject -class win32_useraccount -Filter "LocalAccount='True'" | Select * | out-file -append $CurFName
" " | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"*** Local Account Settings ***" | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
$SecEditFN = "$($FPath)\seceditexport.cfg"
secedit /export /cfg $SecEditFN
type $SecEditFN | findstr /I /C:"PasswordComplex" | out-file -append $CurFName
net accounts | out-file -append $CurFName
if ($SecEditFN){Remove-Item $SecEditFN }
" " | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"***   Services Settings    ***" | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
get-wmiobject win32_service | Select Name, State, StartMode, DisplayName | Sort State, StartMode, Name | out-file -append $CurFName
" " | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"***   Firewall Settings    ***" | out-file -append $CurFName
"******************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
get-netfirewallprofile -PolicyStore ActiveStore -all | out-file -append $CurFName
get-netfirewallrule -PolicyStore ActiveStore -all | out-file -append $CurFName
" " | out-file -append $CurFName
"***************************" | out-file -append $CurFName
"***   Firewall Rules    ***" | out-file -append $CurFName
"***************************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
netsh advfirewall show allprofiles | out-file -append $CurFName
netsh advfirewall firewall show rule all verbose | out-file -append $CurFName
" " | out-file -append $CurFName
"********************" | out-file -append $CurFName
"*** Active Ports ***" | out-file -append $CurFName
"********************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
try {            
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpConnections() | Sort-Object -Property LocalEndPoint.Port, LocalEndPoint.Address
    foreach($Connection in $Connections) {            
        if($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
        $OutputObj = New-Object -TypeName PSobject            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $Connection.LocalEndPoint.Address
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalPort" -Value $Connection.LocalEndPoint.Port
        $OutputObj | Add-Member -MemberType NoteProperty -Name "RemoteAddress" -Value $Connection.RemoteEndPoint.Address
        $OutputObj | Add-Member -MemberType NoteProperty -Name "RemotePort" -Value $Connection.RemoteEndPoint.Port
        $OutputObj | Add-Member -MemberType NoteProperty -Name "State" -Value $Connection.State
        $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType
        $OutputObj | out-file -append $CurFName
    }            
            
} catch {            
    Write-Error "Failed to get active connections. $_" | out-file -append $CurFName
}
# netstat -anbo | out-file -append $CurFName
" " | out-file -append $CurFName
"***********************" | out-file -append $CurFName
"*** Listening Ports ***" | out-file -append $CurFName
"***********************" | out-file -append $CurFName
"Date and Time Retrieved: $(Get-Date)" | out-file -append $CurFName
try {            
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpListeners() | Sort-Object -Property Port, Address
    foreach($Connection in $Connections) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }
        $OutputObj = New-Object -TypeName PSobject
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
        $OutputObj | out-file -append $CurFName
    }            
            
} catch {            
    Write-Error "Failed to get listening connections. $_" | out-file -append $CurFName
}

$YestDate = (Get-Date).AddDays(-1).ToString("MM-dd-yy")
$PCFileYest = "$($DevName)_Baseline_VulnAssess_$($YestDate).txt"
$file1 = $CurFName
$file2 = "$($FPath)$($PCFileYest)"
$PCFile = "$($DevName)_Comparison_$($CurDate)_vs_$($YestDate).txt"
$outFile1 = "$($FPath)$($PCFile)"

# $outFile1 = "C:\Users\xxxxx\Documents\Baseline-Diff-File.txt"

Try{
    (Get-Content $file1) | where { $_.Trim(" `t") } | set-content $file1
    #(Get-Content $file2) | where { $_.Trim(" `t") } | set-content $file2
    
    $text1 = Get-Content $file1
    $newtext1 = New-Object System.Collections.ArrayList 
    for ($i=0;$i -lt $text1.count; $i ++) { $newtext1 += "$($i + 1): " + $text1[$i] }
    $newtext1 | set-content $file1

    #$text2 = Get-Content $file2
    #$newtext2 = New-Object System.Collections.ArrayList 
    #for ($i=0;$i -lt $text2.count; $i ++) { $newtext2 += "$($i + 1): " + $text2[$i] }
    #$newtext2 | set-content $file2
    
    $compareOne = Get-Content $file1
    $comparetwo = Get-Content $file2
} 
Catch{
    Write-Host "The path you entered is either invalid or the file does not exist. "    
}

Write-Host "Beginning comparison"
$Compare = 
Compare-Object $compareOne $comparetwo | Sort-Object InputObject | Where-Object { $_.InputObject -notlike "*Retrieved*" }

$compare | foreach  { 
      if ($_.sideindicator -eq '<=')
        {$_.sideindicator = $file1}

      if ($_.sideindicator -eq '=>')
        {$_.sideindicator = $file2}
     }
"Date and Time Compared: $(Get-Date)" | out-file $outFile1
 $Compare | 
   select @{l='Detected Difference';e={$_.InputObject}},@{l='File';e={$_.SideIndicator}} | format-list |
   Out-File -append $outFile1

  Write-Host "Complete!"
  
# SIG # Begin signature block
# MIITTgYJKoZIhvcNAQcCoIITPzCCEzsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUoBIh5pV+sEHIxy3Qyv3OhDSN
# oEagghCxMIIHyjCCBbKgAwIBAgITeAAAAAmHzADLupVfHAACAAAACTANBgkqhkiG
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPECM3x/
# SyKDw8frXkhXiK+Nc2tyMA0GCSqGSIb3DQEBAQUABIIBABq+reXQFZrqz/PaEE7n
# fzrDyHXEJse+uC3Gexc9FWQ0bPE2FvTEDRZbPmx0xZMQiQMvHQXYT6hgLplL9fXU
# yyyaSjwLLQTlM8Va9hDCulBY80i84Gp3RxbQE3qgOlgSq6FLDvFhNaiF014dllsM
# fCmPahwbqlRJUSwIgs1HLubuig3iYGoAoEDmLXdUAy0ZnT+cirRl0Vpmj+tchqov
# 9nvNWm3uBQEhhT1tk3G6lyK1gAuX0fxKrDbvJbJCflEzoGSRZAMcAA6wCzsdX9nT
# vzDavN4wh0xPTePcXerNCtbhCcLEFL4l5ROzDtYu003M+E9h4JamqRYiCN8eqaeq
# CTs=
# SIG # End signature block
