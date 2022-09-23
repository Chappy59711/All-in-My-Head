# .\FWTrafficAnalysis.ps1 -GB1 path -GB2 dst-port -GB3 action -GB4 src--ip-address -GB5 dst--ip-address -GB6 protocol
param(
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB1='',
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB2='',
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB3='',
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB4='',
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB5='',
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB6='',
    [Parameter(Mandatory=$False)] [ValidateSet('date','path','dst-port','action','src--ip-address','dst--ip-address','protocol')]
    $GB7='')

if ($GB1 -eq '' -and $GB2 -eq '' -and $GB3 -eq '' -and $GB4 -eq '' -and $GB5 -eq '' -and $GB6 -eq '' -and $GB7 -eq '')
{
    $GB1='date'
    $GB2='path'
    $GB3='dst-port'
    $GB4='action'
    $GB5='src--ip-address'
    $GB6='dst--ip-address'
    $GB7='protocol'
}
$ParamCount = 0

if ($GB1 -ne "")
{
    $ParamCount = $ParamCount + 1
}

if ($GB2 -ne "")
{
    $ParamCount = $ParamCount + 1
}

if ($GB3 -ne "")
{
    $ParamCount = $ParamCount + 1
}

if ($GB4 -ne "")
{
    $ParamCount = $ParamCount + 1
}

if ($GB5 -ne "")
{
    $ParamCount = $ParamCount + 1
}

if ($GB6 -ne "")
{
    $ParamCount = $ParamCount + 1
}

if ($GB7 -ne "")
{
    $ParamCount = $ParamCount + 1
}

$global:PrevLogFile = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log.old"
$global:CurLogFile = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

if ((Test-Path $global:PrevLogFile) -or (Test-Path $global:CurLogFile))
{
    Write-Host -nonewline "Reading firewall log..."
    if (!(Test-Path $global:PrevLogFile))
    {
        $LogInfo += import-csv $global:PrevLogFile -Header date,time,action,protocol,src--ip-address,dst--ip-address,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path -Delimiter " "
    }

    if (!(Test-Path $global:CurLogFile))
    {
        $LogInfo += import-csv $global:CurLogFile -Header date,time,action,protocol,src--ip-address,dst--ip-address,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path -Delimiter " "
    }
}
else
{
    Write-Host -nonewline "The firewall is not logging!"
    Break
}

$LogInfo += import-csv $global:CurLogFile -Header date,time,action,protocol,src--ip-address,dst--ip-address,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path -Delimiter " "

$LogInfo = $LogInfo | where {$_.date -notlike "#*" -and $_.date -notlike " *" -and $_.'dst--ip-address' -like "*.*.*.*"} | Select *
#write-host $LogInfo
Write-Host "Completed."

Write-Host -nonewline "Grouping data..."
Switch ($ParamCount)
{
    "1" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1 | Sort Name -Descending | Select Name, Count)}
    "2" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2 | Sort Name -Descending | Select Name, Count)}
    "3" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2, $GB3| Sort Name -Descending | Select Name, Count)}
    "4" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2, $GB3, $GB4 | Sort Name -Descending | Select Name, Count)}
    "5" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2, $GB3, $GB4, $GB5 | Sort Name -Descending | Select Name, Count)}
    "6" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2, $GB3, $GB4, $GB5, $GB6 | Sort Name -Descending | Select Name, Count)}
    "7" {$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2, $GB3, $GB4, $GB5, $GB6, $GB7 | Sort Name -Descending | Select Name, Count)}
}
#$Results = @($LogInfo | Select * | Group-Object -Property $GB1, $GB2, $GB3, $GB4, $GB5, $GB6, $GB7 | Sort Name -Descending | Select Name, Count)
Write-Host "Completed."

Write-Host "TRAFFIC ($GB1, $GB2, $GB3, $GB4, $GB5, $GB6, $GB7)"
Write-Host "===================================================================================================================================="

$Results | FT

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
