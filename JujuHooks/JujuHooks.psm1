# Copyright 2014-2015 Cloudbase Solutions Srl
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

$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath

function Check-ContextComplete {
    <#
    .SYNOPSIS
     Check-ContextComplete loops through the provided context and returns either $true or $false. If any item
     in the context is empty, $null or $false, the context is incomplete and this will return $false.
    .PARAMETER Context
     This parameter holds the context to be checked. Contexts must be hashtables.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Alias("Ctx")]
        [Hashtable]$Context
    )
    PROCESS {
        if ($Context.Count -eq 0) {
            return $false
        }
        foreach ($i in $Context.GetEnumerator()) {
            if (!$i.Value) {
                return $false
            }
        }
        return $true
    }
}

function Get-JujuCharmDir {
    <#
    .SYNOPSIS
    Get-JujuCharmDir returns the location of the current running charm files. This is provided
    in the environment and can also be accessed by getting the value of $env:CHARM_DIR
    #>
    return ${env:CHARM_DIR}
}

function Has-JujuRelation {
    if (Get-JujuRelationType){
        return $true
    }
    return $false
}

function Get-JujuRelationType {
    <#
    .SYNOPSIS
    Get-JujuRelationType returns the name of the relation that triggered the currently running hook.
    The value of this can also be returned by expanding ${env:JUJU_RELATION}
    #>
    return ${env:JUJU_RELATION}
}

function Get-JujuRelationId {
    <#
    .SYNOPSIS
    Get-JujuRelationId returns the id of the relation that triggered the currently running hook.
    The value of this can also be returned by expanding ${env:JUJU_RELATION_ID}
    #>
    return ${env:JUJU_RELATION_ID}
}

function Get-JujuLocalUnit {
    <#
    .SYNOPSIS
    Get-JujuLocalUnit returns the name of the local unit.
    The value of this can also be returned by expanding ${env:JUJU_UNIT_NAME}
    #>
    return ${env:JUJU_UNIT_NAME}
}

function Get-JujuRemoteUnit {
    <#
    .SYNOPSIS
    Get-JujuRemoteUnit returns the name of the remote unit that triggered the hook run.
    The value of this can also be returned by expanding ${env:JUJU_REMOTE_UNIT}
    #>
    return ${env:JUJU_REMOTE_UNIT}
}

function Get-JujuServiceName {
    <#
    .SYNOPSIS
     Get-JujuServiceName returns the local service name for the current running iunit. The name
     is determined based on the rules currently used in juju-core for defining services on Windows.
    #>
    $localUnit = (Get-JujuLocalUnit).Split("/")[0]
    return ("jujud-{0}" -f $localUnit)
}

function Is-JujuMasterUnit {
    <#
    .SYNOPSIS
     This function is deprecated and should not be used. Please use Check-Leader instead
    #>
    [Obsolete("This cmdlet is obsolete. Please use Check-Leader instead.")]
    [CmdletBinding()]
    Param(
        [string]$PeerRelationName
    )
    return (Check-Leader)
}

function Execute-Command {
    <#
    .SYNOPSIS
     Execute-Command is a helper function that accepts a command as an array and returns the output of
     that command as a string. Any error returned by the command will make it throw an exception. This function
     should be used for launching native commands, not powershell commandlets.
    .PARAMETER Command
     Array containing the command and its arguments
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Cmd")]
        [array]$Command
    )
    PROCESS {
        $ret = & $Command[0] $Command[1..$Command.Length]
        if($LASTEXITCODE){
            Throw ("Failed to run: " + ($Command -Join " "))
        }
        if($ret -and $ret.Length -gt 0){
            return ($ret -as [string])
        }
        return $false
    }
}

function Get-JujuCharmConfig {
    <#
    .SYNOPSIS
     Get-JujuCharmConfig returns config values for the charm. By default it returns all config
     values as a hashtable.
    .PARAMETER Scope
     The config setting you want to extract. When this option is specified, Get-JujuCharmConfig will
     only return the value for the specified scope.
    #>
    [CmdletBinding()]
    Param(
        [string]$Scope=$null
    )
    PROCESS {
        $cmd = @("config-get.exe", "--format=json")
        if ($Scope -ne $null){
            $cmd += $Scope
        }

        return (Execute-Command -Cmd $cmd | ConvertFrom-Json)
    }
}

function Get-JujuRelation {
    <#
    .SYNOPSIS
     Get-JujuRelation returns relation information. If run as part of a relation change hook,
     parameters may be omitted, in which case the relation ID and unit are determined from the
     context supplied by juju.
    .PARAMETER Attribute
     Attribute you would like to get the value of. If omitted, all relation information is returned
     as a hashtable.
    .PARAMETER Unit
     The unit for which you want to get relation information. Each unit may set relation information.
     This will allow you to iterate through all units and fetch relation information for each unit. Useful
     when something changed in your environment and you want to sync all information from all units.
    .PARAMETER RelationId
     This is the relation ID parameter. This can be omitted if Get-JujuRelation is run as part of a relation
     change hook. The relation ID is inferred from the context. You can however use this function with any other
     relation ID as part of a relation change run.
    #>
    [CmdletBinding()]
    Param(
        [Alias("Attr")]
        [string]$Attribute=$null,
        [string]$Unit=$null,
        [Alias("Rid")]
        [string]$RelationId=$null
    )
    PROCESS {
        $cmd = @("relation-get.exe", "--format=json")
        if ($RelationId) {
            $cmd += "-r"
            $cmd += $RelationId
        }
        if ($Attribute) {
            $cmd += $Attribute
        } else {
            $cmd += '-'
        }
        if ($Unit) {
            $cmd += $Unit
        }
        return (Execute-Command -Cmd $cmd | ConvertFrom-Json)
    }
}

function Set-JujuRelation {
    <#
    .SYNOPSIS
     Set-JujuRelation sets information on a particular relation ID. When a charm joins a relationship,
     that relation is described by a relation ID. When a hook run is triggered as part of a relation change,
     the relation information is already part of the hook context.
     You can however set a value on other relations as well. This is useful to make other units aware of
     changes to the environment, to which they need to react immediately. For example, the current unit has
     just finished installing its service and is available for consumption. This unit can set a "ready" setting
     on a particular relation, to make all units in that relation aware of its status. As a result, all units in
     the target relation will start consuming this unit.
    .PARAMETER RelationId
     This parameter represents the relation ID on which we want to set values
    .PARAMETER Settings
     This parameter holds a hashtable of settings that will get set on the relation
    #>
    [CmdletBinding()]
    Param(
        [Alias("Relation_Id")]
        [string]$RelationId=$null,
        [Alias("Relation_Settings")]
        [Hashtable]$Settings=@{}
    )
    PROCESS {
        $cmd = @("relation-set.exe")
        if ($RelationId) {
            $cmd += "-r"
            $cmd += $RelationId
        }
        foreach ($i in $Settings.GetEnumerator()) {
           $cmd += $i.Name + "='" + $i.Value + "'"
        }
        Execute-Command $cmd
        return $true
    }
}

function Get-JujuRelationIds {
    <#
    .SYNOPSIS
     Get-JujuRelationIds fetches the relation ids for a particular interface. This function can be used in
     conjunction with Get-JujuRelation/Set-JujuRelation, to get or set information to/from a particular unit
     that is part of the relation returned by this function.
    .PARAMETER Relation
     This parameter represents the relation name we want to fetch the ids for 
    #>
    [CmdletBinding()]
    Param(
        [Alias("RelType")]
        [string]$Relation=$null
    )
    PROCESS {
        $cmd = @("relation-ids.exe", "--format=json")
        if ($Relation) {
            $relationType = $Relation
        }else{
            $relationType = Get-JujuRelationType
        }

        if ($relationType) {
            $cmd += $relationType
        }
        return (Execute-Command -Cmd $cmd | ConvertFrom-Json)
    }
}

function Get-JujuRelatedUnits {
    <#
    .SYNOPSIS
     Get-JujuRelatedUnits gets a list of units participating in a particular relation.
    .PARAMETER RelId
     The relation ID for which we want to fetch related units
    #>
    [CmdletBinding()]
    Param(
        [Alias("RelId")]
        [string]$RelationId=$null
    )
    PROCESS {
        $cmd = @("relation-list.exe", "--format=json")
        if ($RelId) {
            $relationId = $RelId
        } else {
            $relationId = Get-JujuRelationId
        }

        if ($relationId){
            $cmd += "-r" 
            $cmd += $relationId
        }
        return (Execute-Command -Cmd $cmd | ConvertFrom-Json)
    }
}

function Get-JujuRelationForUnit {
    <#
    .SYNOPSIS
     Get the json represenation of a unit's relation
    .PARAMETER Unit
     Unit name for which you want to get relation data. This parameter is optional, and will default
     to the remote unit that triggered the relation hook.
    .PARAMETER RelationId
     Relation on which we can find the remote unit.
    #>
    [CmdletBinding()]
    Param(
        [string]$Unit=$null,
        [Alias("Rid")]
        [string]$RelationId=$null
    )

    PROCESS {
        if ($Unit){
            $unitName = $Unit
        }else{
            $unitName = Get-JujuRemoteUnit
        }
        $relation = Get-JujuRelation -Unit $unitName -Rid $Rid
        foreach ($i in $relation.GetEnumerator()) {
            if ($i.Name.EndsWith("-list")) {
                $relation[$i.Name] = $relation[$i.Name].Split()
            }
        }
        return $relation
    }
}

function Get-JujuRelationForId {
    <#
    .SYNOPSIS
     Get relations of a specific relation ID
    .PARAMETER RelationId
     Relation ID on which we can find the remote units.
    #>
    [CmdletBinding()]
    Param(
        [Alias("RelId")]
        [string]$RelationId=$null
    )
    PROCESS {
        $relationData = @{}
        if (!$RelationId) {
            $RelationId = Get-JujuRelationIds
        }
        $relatedUnits = Get-JujuRelatedUnits -RelationId $RelationId
        foreach ($i in $relatedUnits) {
            $unitData = Get-JujuRelationForUnit -Unit $i -RelationId $RelationId
            $unitData['RelationId'] = $RelationId
            $relationData += $unitData
        }
        return $relationData
    }
}

function Get-JujuRelationsOfType {
    <#
    .SYNOPSIS
     Get relations of a specific type
    .PARAMETER Relation
     The name of the relation to get information for
    #>
    [CmdletBinding()]
    Param(
        [Alias("RelType")]
        [string]$Relation=$null
    )
    PROCESS {
        $relationData = @{}
        if (!$Relation) {
            $Relation = Get-JujuRelationType
        }
        $relationIds = Get-JujuRelationIds -Relation $Relation
        foreach ($i in $relationIds) {
            $relForId = Get-JujuRelationsForId $i
            foreach ($j in $relForId) {
                $j['RelationId'] = $i
                $relationData += $j
            }
        }
        return $relationData
    }
}

function Is-JujuRelationCreated {
    <#
    .SYNOPSIS
     Determine whether or not the relation has been made.
    .PARAMETER Relation
     Relation name to check
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Relation,
        [Obsolete("This parameter is obsolete. It is not required any more.")]
        [string]$Keys='private-address'
    )
    PROCESS {
        $ids = Get-JujuRelationIds -Relation $Relation
        if($ids){
            return $true
        }
        return $false
    }
}

function Get-JujuUnit {
    <#
    .SYNOPSIS
     returns information about the local unit. It accepts a single argument, which must
     be private-address or public-address. It is not affected by context.

     See:

     https://jujucharms.com/docs/stable/authors-hook-environment#unit-get

    .PARAMETER Attribute
     This parameter must be either private-address or public-address
    .NOTES
     On some providers both the private-address and public-address may be hostnames instead of IP addresses,
     so please take that into account when using this function. If you need the actual IP address instead of a
     hostname, you will have to validate the result, or use Get-JujuUnitPrivateIP as a helper function.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("private-address", "public-address")]
        [Alias("Attr")]
        [string]$Attribute
    )
    PROCESS {
        $cmd = @("unit-get.exe", "--format=json", $Attribute)
        return (Execute-Command $cmd | ConvertFrom-Json)
    }
}

function Check-IP {
    <#
    .SYNOPSIS
     Check if the parameter passed as a string, is a valid IPv4 address
    .PARAMETER IP
     the IP address to check
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$IP
    )
    PROCESS {
        return ($IP -as [ipaddress]) -as [bool]
    }
}

function Resolve-Address {
    <#
    .SYNOPSIS
     Resolve address to IP and return as string.
    .PARAMETER Address
     The address to resolve
    .NOTES
     This function only returns the first IP address found. It will not return all IP addresses.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Address
    )
    PROCESS {
        if((Check-IP $Address)){
            return $Address
        }
        $ip = ExecuteWith-Retry {
            $return = Execute-Command -Command @("ipconfig", "/flushdns")
            $ip = ([system.net.dns]::GetHostAddresses($Address))[0].ipaddresstostring
            return $ip 
        }
        if(!$ip){
            Throw ("Could not resolve address {0} to IP" -f $Address)
        }
        Write-JujuLog "Returning $ip" -LogLevel INFO
        return $ip
    }
}

function Get-JujuUnitPrivateIP {
    <#
    .SYNOPSIS
     A helper function to get the IPv4 representation (as string) of a units private-address
    #>
    [CmdletBinding()]
    PROCESS {
        $addr = Get-JujuUnit -Attribute "private-address"
        return (Resolve-Address -Address $addr)
    }
}

function Get-JujuRelationContext{
    <#
    .SYNOPSIS
     This function gets the context for a particular relation and returns a hashtable
     with the requested values. If any of the values requested via the -RequiredContext
     parameters is not set on the relation, an empty context is returned. This function
     takes an all-or-nothing approach.
    .PARAMETER Relation
     The relation for which to get the context
    .PARAMETER RequiredContext
     A hashtable consisting of the required parameters
    .EXAMPLE
     $context = {
        "private-address"=$null;
        "hostname"=$null;
        "username"=$null;
     }
     # Each key in the $context variable represents the name of the relation setting that
     # we expect to find on $Relation. If relation-get returns nothing for that named parameter
     # (private-address, hostname, username in our example), the resulting $ctx will be empty.
     # If all parameters have values, the context is complete, and $ctx will hold all 3 parameters
     # with associated value.
     $ctx = Get-JujuRelationContext -Relation example -RequiredContext $context
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Relation,
        [Parameter(Mandatory=$true)]
        [Hashtable]$RequiredContext
    )
    PROCESS {
        $relations = Get-JujuRelationIds -Relation $Relation
        foreach($rid in $relations){
            $related_units = Get-JujuRelatedUnits -RelationId $rid
            if (($related_units -ne $null) -and ($related_units.Count -gt 0)) {
                foreach ($unit in $related_units) {
                    $ctx = @{}
                    foreach ($key in $RequiredContext.Keys) {
                        $ctx[$key] = Get-JujuRelation -attr $RequiredContext[$key] `
                                     -rid $rid -unit $unit
                    }
                    $complete = Check-ContextComplete -Context $ctx
                    if ($complete) {
                        return $ctx
                    }
                }
            }
        }
        return @{}
    }
}

function Get-JujuRelationParams {
    <#
    .SYNOPSIS
     This function gets the context for a particular relation and returns a hashtable
     with the requested values.
    .PARAMETER Relation
     Relation name we need to querie
    .PARAMETER RequiredContext
     A hashtable of values that the relation must provide to be considered complete.
    .NOTES
     Do not use this function. It is Obsolete and also dangerous. It sets a field called "context"
     which is of type boolean. If a relation sets this field as a different type, it will be clobbered
     by this function.
    #>
    [Obsolete("This function is obsolete. Please use Get-JujuRelationContext")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("type")]
        [string]$Relation,
        [Parameter(Mandatory=$true)]
        [Alias("relationMap")]
        [Hashtable]$RequiredContext
    )
    PROCESS {
        $ctx = Get-JujuRelationContext -Relation $Relation -RequiredContext $RequiredContext
        if($ctx){
            $ctx["context"] = $true
        }else{
            $ctx = @{"context"=$false;}
        }
        return $ctx
    }
}

function Write-JujuLog {
    <#
    .SYNOPSIS
     Write-JujuLog writes a line in the Juju log with the given log level
    .PARAMETER LogLevel
     LogLevel represents the logging level of the message
    .PARAMETER Message
     Message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
        [string]$LogLevel="INFO"
    )
    PROCESS {
        $cmd = @("juju-log.exe")
        if($LogLevel -eq "DEBUG") {
            $cmd += "--debug"
        }
        $cmd += $Message
        $cmd += @("-l", $LogLevel.ToUpper())
        $return = Execute-Command -Command $cmd
    }
}

function Write-JujuDebug {
    <#
    .SYNOPSIS
     Helper function that writes a log message with DEBUG log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel DEBUG
    }
}

function Write-JujuTrace {
    <#
    .SYNOPSIS
     Helper function that writes a log message with TRACE log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel TRACE
    }
}

function Write-JujuInfo {
    <#
    .SYNOPSIS
     Helper function that writes a log message with INFO log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel INFO
    }
}

function Write-JujuWarning {
    <#
    .SYNOPSIS
     Helper function that writes a log message with WARNING log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel WARNING
    }
}

function Write-JujuCritical {
    <#
    .SYNOPSIS
     Helper function that writes a log message with CRITICAL log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel CRITICAL
    }
}

function Write-JujuErr {
    <#
    .SYNOPSIS
     Helper function that writes a log message with ERROR log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Msg -LogLevel ERROR
    }
}

function Write-JujuError {
    <#
    .SYNOPSIS
     Write an error level message to the juju log and optionally throw an exception using that same message.
    .PARAMETER Message
     Message to write to juju log
    .PARAMETER Fatal
     A boolean value that instructs the commandlet to throw an exception or not
    .NOTES
     Do not use this function. The recommended way of dealing with exceptions is to catch them in the hook itself.
     Write your charm modules to only throw exceptions on fatal errors. Use try{}catch{} in your hook to log the actual
     error.
    #>
    [Obsolete("This function is Obsolete. Please use Write-JujuErr")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Msg")]
        [string]$Message,
        [bool]$Fatal=$true
    )
    PROCESS {
        Write-JujuLog -Message $Msg -LogLevel ERROR
        if ($Fatal) {
            Throw $Msg
        }
    }
}

function ExitFrom-JujuHook {
    <#
    .SYNOPSIS
     Please do not use this function. It is only present for backwards compatibility. It should never be used
     in any charm code. Please use Execute-JujuReboot if you need to reboot the machine the charm is running on.
    .PARAMETER WithReboot
     When $true, it will run Execute-JujuReboot -Now, instead of exit 0.
    #>
    [Obsolete("This function is obsolete. Please use Execute-JujuReboot")]
    [CmdletBinding()]
    Param(
        [switch]$WithReboot
    )
    PROCESS {
        if ($WithReboot -eq $true) {
            Execute-JujuReboot -Now
        }
        exit 0
    }
}

function Execute-JujuReboot {
    <#
    .SYNOPSIS
     Request that the machine should reboot. This particular feature heavily used when installing windows
     features that require reboot. Juju has its own tool to signal all running units that a reboot is about
     to happen, and will wait for any currently running hook to finish before acquiring the execution lock
     and executing a reboot. It also waits for any running container to shutdown.
    .PARAMETER Now
     This parameter makes the Execute-JujuReboot commandlet to block until reboot is executed. It guarantees
     that if executed with the -Now parameter, your script will not continue after that point. You should take
     great care when using this option, as you might enter into a reboot loop.
     Omitting this option will schedule a reboot at the end of the currently running hook.
    .EXAMPLE

     # Check if feature is installed
     $isInstalled = Check-IfFeatureIsInstalled
     if(!$isInstalled){
        # Feature is not installed.
        # Its important to suppress any automatic reboot from any commandlet. Rebooting
        # a server while the hook is running will error out the hook.
        $result = Install-FeatureThatRequiresReboot -Reboot:$False

        # Some commandlets return a result that contains whether or not a reboot is required
        # before changes take effect
        if($result.RebootRequired){
            # Only reboot if we absolutely have to.
            Execute-JujuReboot -Now
        }
     }  
    #>
    Param(
        [switch]$Now
    )
    $cmd = @("juju-reboot.exe")

    if ($Now) {
        $cmd += "--now"
    }
    Execute-Command -Command $cmd
}

# TODO

# TODO(gabriel-samfira): Move this to separate module
function Get-MainNetadapter {
    <#
    .SYNOPSIS
    Returns the interface alias of the primary network adapter. The primary network adapter in this
    case is the NIC that has the IP address that juju is aware of, configured. So if the IP address
    returned by Get-JujuUnitPrivateIP is configured on a NIC, that NIC is the primary one.
    #>
    [CmdletBinding()]
    PROCESS {
        $unit_ip = unit_private_ip
        if (!$unit_ip) {
            Throw "Failed to get unit IP"
        }

        $iface = Get-NetIPAddress | Where-Object `
            { $_.IPAddress -match $unit_ip -and $_.AddressFamily -eq "IPv4" }
        if ($iface) {
            $ifaceAlias = $iface.InterfaceAlias
            if ($ifaceAlias) {
                return $ifaceAlias
            } else {
                Throw "Interface alias is null."
            }
        } else {
            Throw "Failed to find primary interface."
        }
    }
}

function Get-PrimaryAdapterDNSServers {
    <#
    .SYNOPSIS
    Returns the DNS servers configured for the primary network adapter. See Get-MainNetadapter
    for a definition of "primary network adapter"
    #>
    $netAdapter = Get-MainNetadapter
    $dnsServers = (Get-DnsClientServerAddress -InterfaceAlias $netAdapter `
                  -AddressFamily IPv4).ServerAddresses
    return $dnsServers
}

function Check-JujuPortRangeOpen{
    <#
    .SYNOPSIS
    Check if the given port or port range is open
    .PARAMETER Port
    The port or port range to check.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^(\d{1,5}-)?\d{1,5}/(tcp|udp)$')]
        [string]$Port,

    )
    PROCESS {
        $cmd = @("opened-ports.exe", "--format=json")
        $openedPorts = Execute-Command $cmd | ConvertFrom-Json

        if (!$openedPorts) {
            return $false
        }
        foreach ($i in $openedPorts) {
            if ($i -eq $Port) {
                return $true
            }
        }
        return $false
    }
}

function Is-JujuPortRangeOpen {
    <#
    .SYNOPSIS
    Obsolete. Please use Check-JujuPortRangeOpen
    #>
    [CmdletBinding()]
    [Obsolete("This function is obsolete. Please use Check-JujuPortRangeOpen")]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^(\d{1,5}-)?\d{1,5}/(tcp|udp)$')]
        [string]$port,

    )
    PROCESS {
        return (Check-JujuPortRangeOpen -Port $port)
    }
}

function Open-JujuPort {
    <#
    .SYNOPSIS
    Opens a port or a range of ports in the provider firewall.
    .PARAMETER Port
    TCP/UDP port or port range to open.
    .EXAMPLE
    # Open a TCP port range of 1024 to 2048

    Open-JujuPort -Port 1024-2048/TCP

    .EXAMPLE
    # Open single UDP port

    Open-JujuPort -Port 1024/UDP
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^(\d{1,5}-)?\d{1,5}/(tcp|udp)$')]
        [string]$Port,
        [Obsolete("This parameter is obsolete and will be removed in the future.")]
        [bool]$Fatal=$true
    )
    PROCESS {
        $isOpen = Check-JujuPortRangeOpen -Port $Port
        if ($isOpen){
            return $true
        }
        $cmd = @("open-port.exe", $port)
        try {
            Execute-Command -Cmd $cmd | Out-Null
        } catch {
            Write-JujuErr "Failed to open port $Port"
            if($Fatal){
                Throw
            }
        }
    }
}

function Close-JujuPort {
    <#
    .SYNOPSIS
    Closes a port or a range of ports in the provider firewall.
    .PARAMETER Port
    TCP/UDP port or port range to open.
    .EXAMPLE
    # Close the TCP port range 1024-2048

    Close-JujuPort -Port 1024-2048/TCP

    .EXAMPLE
    # Close single UDP port

    Close-JujuPort -Port 1024/UDP
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^(\d{1,5}-)?\d{1,5}/(tcp|udp)$')]
        [string]$Port
    )
    PROCESS {
        $isOpen = Check-JujuPortRangeOpen -Port $Port
        if ($isOpen) {
            Write-JujuInfo "Closing port $Port"
            $cmd = @("close-port.exe", $port)
            try {
                Execute-Command -Command $cmd | Out-Null
            } catch {
                Write-JujuErr "Failed to close port."
                Throw
            }
        }
    }
}

function Is-Leader {
    [CmdletBinding()]
    [Obsolete("This commandlet is obsolete. Please use Check-Leader instead")]
    PROCESS {
        return (Check-Leader)
    }
}

function Check-Leader {
    <#
    .SYNOPSIS
    Check if current unit is leader.
    #>
    [CmdletBinding()]
    PROCESS {
        $cmd = @("is-leader.exe", "--format=json")
        return (Execute-Command -Cmd $cmd | ConvertFrom-Json)
    }
}

function Set-LeaderData {
    <#
    .SYNOPSIS
    Sets the given parameters as leader data.
    .PARAMETER Settings
    A hashtable containing the parameters to set.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("params")]
        [Hashtable]$Settings
    )
    PROCESS {
        $cmd = @("leader-set.exe")

        foreach ($i in $params.GetEnumerator()) {
           $cmd += $i.Name + "=" + $i.Value
        }
        Execute-Command $cmd | Out-Null
        return $true
    }
}

function Get-LeaderData {
    <#
    .SYNOPSIS
    Get values set by leader.
    .PARAMETER Attribute
    The attribute we want to get from leader data. If not specified, all leader data is returned.
    #>
    [CmdletBinding()]
    Param(
        [Alias("Attr")]
        [string]$Attribute=$null
    )
    PROCESS {
        $cmd = @("leader-get.exe", "--format=json")
        if ($Attribute) {
            $cmd += $Attribute
        }
        return (Execute-Command -Cmd $cmd | ConvertFrom-Json)
    }
}

function Get-JujuVersion {
    <#
    .SYNOPSIS
    Gets the unit jujud version. This is useful if you plan to enable or disable features
    based on jujud version.
    #>
    [CmdletBinding()]
    PROCESS {
        $cmd = @("jujud.exe", "version")
        $return = Execute-Command -Command $cmd
        $binaryVersion = $return.Split("-")
        if($binaryVersion.Count -eq 3){
            $details = @{
                "version"=$binaryVersion[0];
                "series"=$binaryVersion[1];
                "arch"=$binaryVersion[2];
            }
        }elseif ($binaryVersion.Count -eq 4) {
            $subversion = $binaryVersion[1]
            Write-JujuWarning "Using beta version of juju ($subversion)"
            $details = @{
                "version"=$binaryVersion[0];
                "subversion"=$subversion;
                "series"=$binaryVersion[2];
                "arch"=$binaryVersion[3];
            }
        }else{
            Throw "Invalid jujud version"
        }
        return $details
    }
}

function Set-JujuStatus {
    <#
    .SYNOPSIS
    Set the status of a running unit, optionally allowing the charm author to also set
    a message along with the status. It is recommended that the charm set its status and
    a message when the charm transitions from one state to another.
    .PARAMETER Status
    One of the following statuses: maintenance, blocked, waiting, active
    .PARAMETER Message
    An optional message to set along with the status
    .PARAMETER StatusData
    This parameter is currently ignored. It is not yet exposed in any version of juju-core.
    Once it will be exposed, this commandlet will enable the StatusData parameter for versions
    of juju that enable this feature.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("maintenance", "blocked", "waiting", "active")]
        [string]$Status,
        [string]$Message,
        [hashtable]$StatusData,
    ) 
    BEGIN {
        # StatusData will be supported in future juju releases. At the time
        # of this writing, status-data was not yet exposed via status-set
        if($StatusData){
            Write-JujuWarning "The status-data feature is not yet exposed to hook tools."
            # TODO: Check juju version and set to $true when status-data gets exposed
            $Supported = $false
        }
    }
    PROCESS {
        $cmd = @("status-set.exe", $Status)
        if($Message){
            $cmd += $Message
        }
        if($StatusData -and $Supported){
            $js = ConvertTo-Json $StatusData
            $cmd += $js
        }
        if ((Get-JujuStatus) -ne $Status) {
            return Execute-Command -Cmd $cmd
        }
    }
}

function Get-JujuStatus {
    <#
    .SYNOPSIS
    Get unit status
    .PARAMETER Full
    return all data set in the status of a unit. Includes status, message, status-data
    #>
    [CmdletBinding()]
    Param(
        [switch]$Full=$false
    )
    PROCESS {
        $cmd = @("status-get.exe", "--include-data","--format=json")
        $result = Execute-Command -Cmd $cmd | ConvertFrom-Json

        if($Full){
            return $result
        }
        return $result["status"]
    }
}

function Get-JujuAction {
    <#
    .SYNOPSIS
    Returns the action parameters from within a particular action
    .PARAMETER Parameter
    The name of the parameter we want to fetch data for. If left empty, this commandlet returns
    all parameters defined in the action as a hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias("ActionParam")]
        [string]$Parameter
    )
    PROCESS {
        $cmd = @("action-get.exe", "--format=json")
        if($ActionParam){
            $cmd += $ActionParam
        }
        return (Execute-Command $cmd | ConvertFrom-Json)
    }
}

function Set-JujuAction {
    <#
    .SYNOPSIS
    This commandlet sets parameters for the current running action.
    .PARAMETER Settings
    A hashtable containing keys we want to set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("ActionParams")]
        [hashtable]$Settings
    )
    PROCESS {
        $cmd = @("action-set.exe")
        foreach($i in $Settings.GetEnumerator()){
            $cmd += ($i.key + "=" + $i.Value)
        }
        Execute-Command -Command $cmd | Out-Null
        return $true
    }
}

function Fail-JujuAction {
    <#
    .SYNOPSIS
    Fail the current running action.
    .PARAMETER Message
    Optional parameter to set a message for the failing action.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Message
    )
    PROCESS {
        $cmd = @("action-fail.exe")
        if ($Message) {
            $cmd += $Message
        }
        Execute-Command $cmd | Out-Null
        return $true
    }
}


#Python/Bash like function aliases
New-Alias -Name charm_dir -Value Get-JujuCharmDir
New-Alias -Name in_relation_hook -Value Has-JujuRelation
New-Alias -Name relation_type -Value Get-JujuRelationType
New-Alias -Name relation_id -Value Get-JujuRelationId
New-Alias -Name local_unit -Value Get-JujuLocalUnit
New-Alias -Name remote_unit -Value Get-JujuRemoteUnit
New-Alias -Name service_name -Value Get-JujuServiceName
New-Alias -Name is_master_unit -Value Is-JujuMasterUnit
New-Alias -Name charm_config -Value Get-JujuCharmConfig
New-Alias -Name relation_get -Value Get-JujuRelation
New-Alias -Name relation_set -Value Set-JujuRelation
New-Alias -Name relation_ids -Value Get-JujuRelationIds
New-Alias -Name related_units -Value Get-JujuRelatedUnits
New-Alias -Name relation_for_unit -Value Get-JujuRelationForUnit
New-Alias -Name relations_for_id -Value Get-JujuRelationsForId
New-Alias -Name relations_of_type -Value Get-JujuRelationsOfType
New-Alias -Name is_relation_made -Value Is-JujuRelationCreated
New-Alias -Name unit_get -Value Get-JujuUnit
New-Alias -Name unit_private_ip -Value Get-JujuUnitPrivateIP
