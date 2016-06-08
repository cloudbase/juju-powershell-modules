# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

function Invoke-DHCPRenew {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$NetAdapter
    )
    PROCESS {
        if($NetAdapter.CreationClassName -ne "MSFT_NetAdapter"){
            Throw ("Invalid object class: {0}" -f $NetAdapter.CreationClassName)
        }
        $ifIndex = $NetAdapter.ifIndex

        $interface = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $ifIndex}
        if($interface.IPEnabled -eq $false) {
            Throw "IP subsystem not enabled on this interface"
        } 
        if ($interface.DHCPEnabled -eq $false) {
            Throw "Interface not configured for DHCP"
        }
        $code = Invoke-CimMethod -CimInstance $interface -MethodName "RenewDHCPLease"
        return $code.ReturnValue
    }
}

function Invoke-DHCPRelease {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$NetAdapter
    )
    PROCESS {
        if($NetAdapter.CreationClassName -ne "MSFT_NetAdapter"){
            Throw ("Invalid object class: {0}" -f $NetAdapter.CreationClassName)
        }
        $ifIndex = $NetAdapter.ifIndex

        $interface = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $ifIndex}
        if($interface.IPEnabled -eq $false) {
            return 0
        } 
        if ($interface.DHCPEnabled -eq $false) {
            Throw "Interface not configured for DHCP"
        }
        $code = Invoke-CimMethod -CimInstance $interface -MethodName "ReleaseDHCPLease"
        return $code.ReturnValue
    }
}

function Get-IfaceWithSameNetwork {
    <#
    .SYNOPSIS
    Return the interface index of the network card directly connected to a network that
    can communicate with the given IP. For example, consider that we have
    one of the addresses configured on our system is 192.168.1.10/25.
    That means that its part of a subnet spanning from 192.168.1.0-192.168.1.127.
    This function will check that the given IP falls in that range and
    returns a boolean. This function is useful if you want to set another gateway
    for your system, and are unsure whether or not you can directly reach that
    address. 
    .PARAMETER IP
    IP address to check

    .EXAMPLE
    Get-IfaceWithSameNetwork -IP 192.168.1.2
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$IP
    )
    PROCESS {
        $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
        foreach($i in $configuredAddresses) {
            $decimalMask = ConvertTo-Mask $i.PrefixLength
            $ipNetwork = Get-NetworkAddress $IP $decimalMask
            $localNetwork = Get-NetworkAddress $i.IPv4Address $decimalMask
            if ($localNetwork -eq $ipNetwork) {
                return $i.ifIndex
            }
        }
    }
}

function Set-InterfaceDynamicDNSRegistration {
    <#
    .SYNOPSIS
    Enable or disable dynamic DNS on a particular interface.
    .PARAMETER FullDNSRegistrationEnabled
    If true, the IP addresses for this connection is registered in DNS under the computer's full DNS name. The full DNS
    name of the computer is displayed on the Network Identification tab of the system Control Panel. 
    .PARAMETER DomainDNSRegistrationEnabled
    If true, the IP addresses for this connection are registered under the domain name of this connection, in addition
    to being registered under the computer's full DNS name. The domain name of this connection is either set using the
    method SetDNSDomain or assigned by DHCP. The registered name is the host name of the computer with the domain name
    appended. This parameter has meaning only when FullDNSRegistrationEnabled is enabled. The default value is false. 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [int]$IfIndex,
        [Parameter(Mandatory=$false)]
        [bool]$FullDNSRegistrationEnabled=$true,
        [Parameter(Mandatory=$false)]
        [bool]$DomainDNSRegistrationEnabled=$false
    )
    PROCESS {
        if($IfIndex -eq $null) {
            Throw "No interface given"
        }
        $interface = Get-ManagementObject -Class Win32_NetworkAdapter -Filter ("InterfaceIndex='{0}'" -f $ifIndex)
        if(!$interface) {
            Throw "Could not find interface with index $ifIndex"
        }
        switch($interface.GetType().FullName){
            "System.Management.ManagementObject" {
                $config = $interface.GetRelated("Win32_NetworkAdapterConfiguration")
                $config.SetDynamicDNSRegistration($FullDNSRegistrationEnabled, $DomainDNSRegistrationEnabled)
            }
            "Microsoft.Management.Infrastructure.CimInstance" {
                $config = Get-CimAssociatedInstance -InputObject $interface -ResultClassName "Win32_NetworkAdapterConfiguration"
                $return = Invoke-CimMethod -InputObject $config `
                                           -MethodName SetDynamicDNSRegistration `
                                           -Arguments @{
                                                "FullDNSRegistrationEnabled" = $FullDNSRegistrationEnabled;
                                                "DomainDNSRegistrationEnabled" = $DomainDNSRegistrationEnabled;
                                            }
                if($return.ReturnValue) {
                    Throw ("Failed to set Dynamic DNS setting with error code: {0}" -f $return.ReturnValue)
                }
            }
            default {
                Throw ("Invalid service type {0}" -f $i.GetType().Name)
            }
        }
    }
}

function Get-BroadcastAddress {
    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        [Parameter(Mandatory=$true)]
        [string]$PrefixLength="24"
    )
    PROCESS {
        [UInt32]$ip = ConvertTo-DecimalIP $IPAddress
        [UInt32]$subnet = ConvertTo-DecimalIP $SubnetMask
        [UInt32]$broadcast = $ip -band $subnet 
        return ConvertTo-DottedDecimalIP ($broadcast -bor -bnot $subnet)
    }
}

function Get-NetIpFromNetwork {
    <#
    .SYNOPSIS
    Find a network interface that has an IPv4 address that belongs to a particular network.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Network
    )
    PROCESS {
        $details = $Network.Split("/")
        if($details.Count -ne 2) {
            Throw "Network must be in CIDR format"
        }
        try {
            $mask = [int]$details[1]
        } catch {
            Throw "Network must be in CIDR format"
        }
        $decimalMask = ConvertTo-Mask $mask

        $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
        foreach ($i in $configuredAddresses) {
            if ($i.PrefixLength -ne $mask){
                continue
            }
            $network = Get-NetworkAddress $i.IPv4Address $decimalMask
            if ($network -eq $details[0]){
                return $i
            }
        }
        Throw "Failed to find IP from specified network"
    }
}

Export-ModuleMember -Function * -Alias *
