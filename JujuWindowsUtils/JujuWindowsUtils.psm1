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

$version = $PSVersionTable.PSVersion.Major
if ($version -lt 4){
    # Get-CimInstance is not supported on powershell versions earlier then 4
    New-Alias -Name Get-ManagementObject -Value Get-WmiObject
}else{
    New-Alias -Name Get-ManagementObject -Value Get-CimInstance
}

$CharmStateKey = "HKLM:\SOFTWARE\Juju-Charms"

function Get-IsNanoServer {
    <#
    .SYNOPSIS
    Return a boolean value of $true if we are running on a Nano server version.
    #>
    PROCESS {
        $k = "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels"
        if (!(Test-Path $k)){
            # We are most likely running on a workstation version
            return $false
        }
        $serverLevels = Get-ItemProperty $k
        return ($serverLevels.NanoServer -eq 1)
    }
}

function Start-ProcessRedirect {
    <#
    .SYNOPSIS
    A helper function that allows executing a process with more advanced process diagnostics. It returns a System.Diagnostics.Proces
    that gives you access to ExitCode, Stdout/StdErr.
    .PARAMETER Filename
    The executable to run
    .PARAMETER Arguments
    Arguments to pass to the executable
    .PARAMETER Domain
    Optionally, the process can be run as a domain user. This option allows you to specify the domain on which to run the command.
    .PARAMETER Username
    The username under which to run the command.
    .PARAMETER Password
    A SecureString encoded password.

    .EXAMPLE
    $p = Start-ProcessRedirect -Filename (Join-Path $PSHome powershell.exe) -Arguments @("-File", "C:\amazingPowershellScript.ps1")
    $p.ExitCode
    0
    $p.StandardOutput.ReadToEnd()
    whoami sais: desktop-dj170ar\JohnDoe
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Filename,
        [Parameter(Mandatory=$false)]
        [array]$Arguments,
        [Parameter(Mandatory=$false)]
        [array]$Domain,
        [Parameter(Mandatory=$false)]
        [array]$Username,
        [Parameter(Mandatory=$false)]
        [Alias("SecPassword")]
        [System.Security.SecureString]$Password
    )
    PROCESS {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $Filename
        if ($Domain -ne $null) {
            $pinfo.Username = $Username
            $pinfo.Password = $Password
            $pinfo.Domain = $Domain
        }
        $pinfo.CreateNoWindow = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.LoadUserProfile = $true
        if($Arguments){
            $pinfo.Arguments = $Arguments
        }
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $p.WaitForExit()
        return $p
    }
}

# New-Alias -Name Is-ComponentInstalled -Value Get-ComponentIsInstalled
function Get-ComponentIsInstalled {
    <#
    .SYNOPSIS
    This commandlet checks if a program is installed and returns a boolean value. Exact product names must be used, wildcards are not accepted.
    .PARAMETER Name
    The name of the product to check for

    .NOTES
    This commandlet is not supported on Nano server
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    BEGIN {
        if((Get-IsNanoServer)) {
            # TODO: Should we throw or just print a warning?
            # if the user expects this to work on nano, it may lead to
            # faulty code due to bad assumptions
            Throw "This commandlet is not supported on Nano server"
        }
    }
    PROCESS {
        $products = Get-ManagementObject -Class Win32_Product
        $component = $products | Where-Object { $_.Name -eq $Name}

        return ($component -ne $null)
    }
}

# New-Alias -Name Get-JujuUnitName -Value Convert-JujuUnitNameToNetbios
function Convert-JujuUnitNameToNetbios {
    <#
    .SYNOPSIS
    In some cases juju spawns instances with names such as juju-openstack-unit-active-directory-0, which exceeds the maximum 15
    characters allowed for netbios names. This commandlet returns a valid netbios name based on the charm name and unit number.
    It is still not guaranteed to yield unique names, especially if the charms you are deploying have similar names larger then 15
    characters, but it at least works some of the time.

    .NOTES
    If you have multiple charms with similar names larger then 15 characters, there is a chance that you will have multiple units
    with the same netbios name. In most situations, this is not a problem. If you want to join them to Active Directory however,
    it will become a problem. 
    #>
    PROCESS {
        $jujuUnitNameNumber = (Get-JujuLocalUnit).split('/')
        $jujuUnitName = ($jujuUnitNameNumber[0]).ToString()
        $jujuUnitNumber = ($jujuUnitNameNumber[1]).ToString()
        if (!$jujuUnitName -or !$jujuUnitNumber) {
            Throw "Failed to get unit name and number"
        }
        $maxUnitNameLength = 15 - ($jujuUnitName.Length + $jujuUnitNumber.Length)
        if ($maxUnitNameLength -lt 0) {
            $jujuUnitName = $jujuUnitName.substring(0, ($jujuUnitName.Length + $maxUnitNameLength))
        }
        $netbiosName = $jujuUnitName + $jujuUnitNumber
        return $netbiosName
    }
}

# New-Alias -Name Change-ServiceLogon -Value Set-ServiceLogon
function Set-ServiceLogon {
    <#
    .SYNOPSIS
    This function accepts a service or an array of services and sets the user under which the service should run.
    .PARAMETER Services
    An array of services to change startup user on. The values of the array can be a String, ManagementObject (returned by Get-WmiObject) or CimInstance (Returned by Get-CimInstance)
    .PARAMETER UserName
    The local or domain user to set as. Defaults to LocalSystem.
    .PARAMETER Password
    The password for the account.

    .NOTES
    The selected user account must have SeServiceLogonRight privilege.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [array]$Services,
        [Parameter(Mandatory=$true)]
        [string]$UserName="LocalSystem",
        [Parameter(Mandatory=$false)]
        [string]$Password=""
    )
    PROCESS {
        foreach ($i in $Services){
            switch($i.GetType().Name){
                "String" {
                    $svc = Get-ManagementObject -Class Win32_Service -Filter ("Name='{0}'" -f $i)
                    if(!$svc){
                        Throw ("Service named {0} could not be found" -f @($i))
                    }
                    Set-ServiceLogon -Services $svc -UserName $UserName -Password $Password
                }
                "ManagementObject" {
                    if ($i.CreationClassName -ne "Win32_Service"){
                        Throw ("Invalid management object {0}. Expected: {1}" -f @($i.CreationClassName, "Win32_Service"))
                    }
                    $i.Change($null,$null,$null,$null,$null,$null,$UserName,$Password)
                }
                "CimInstance" {
                    if ($i.CreationClassName -ne "Win32_Service"){
                        Throw ("Invalid management object {0}. Expected: {1}" -f @($i.CreationClassName, "Win32_Service"))
                    }
                    $ret = Invoke-CimMethod -CimInstance $i `
                                            -MethodName "Change" `
                                            -Arguments @{"StartName"=$UserName;"StartPassword"=$Password;}
                    if ($ret.ReturnValue){
                        Throw "Failed to set service credentials: $ret"
                    }
                }
                default {
                    Throw ("Invalid service type {0}" -f $i.GetType().Name)
                }
            }
        }
    }
}

# New-Alias -Name Is-ServiceAlive -Value Get-ServiceIsRunning
function Get-ServiceIsRunning {
    <#
    .SYNOPSIS
    Checks if a service is running and returns a boolean value.
    .PARAMETER ServiceName
    The service name to check
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    PROCESS {
        $service = Get-Service $ServiceName
        if ($service) {
            return ($service.Status -eq 'Running')
        } 
        return $false
    }
}

function Install-Msi {
    <#
    .SYNOPSIS
    Installs a MSI in unattended mode. If install fails an exception is thrown.
    .PARAMETER Installer
    Full path to the MSI installer
    .PARAMETER LogFilePath
    The path to the install log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("MsiFilePath")]
        [string]$Installer,
        [Parameter(Mandatory=$false)]
        [string]$LogFilePath
    )
    PROCESS {
        $args = @(
            "/i",
            $Installer,
            "/q"
            )

        if($LogFilePath){
            $parent = Split-Path $LogFilePath -Parent
            if(!(Test-Path $parent)){
                New-Item -ItemType Directory $parent
            }
            $args += @("/l*v", $LogFilePath)
        }

        if (!(Test-Path $Installer)){
            Throw "Could not find MSI installer at $Installer"
        }
        $p = Start-Process -FilePath "msiexec" -Wait -PassThru -ArgumentList $args
        if ($p.ExitCode -ne 0) {
            Throw "Failed to install MSI package."
        }
    }
}

function Install-WindowsFeatures {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [array]$Features
    )
    PROCESS {
        $rebootNeeded = $false
        foreach ($feature in $Features) {
            $state = ExecuteWith-Retry -Command {
                Install-WindowsFeature -Name $feature -ErrorAction Stop
            }
            if ($state.Success -eq $true) {
                if ($state.RestartNeeded -eq 'Yes') {
                    $rebootNeeded = $true
                }
            } else {
                throw "Install failed for feature $feature"
            }
        }

        if ($rebootNeeded -eq $true) {
            Invoke-JujuReboot -Now
        }
    }
}

# Get-CharmStateFullKeyPath

function Set-CharmState {
    <#
    .SYNOPSIS
    Sets persistent data the charm may need in the registry. This information is only relevant for the unit saving the data.
    .PARAMETER Namespace
    A prefix that gets added to the key
    .PARAMETER Key
    A key to identify the information by
    .PARAMETER Value
    The value we want to store. This must be a string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("CharmName")]
        [string]$Namespace,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [Alias("Val")]
        [string]$Value
    )
    PROCESS {
        $keyDirExists = Test-Path -Path $CharmStateKey
        if ($keyDirExists -eq $false) {
            $keyDir = Split-Path -Parent $CharmStateKey
            $keyName = Split-Path -Leaf $CharmStateKey
            New-Item -Path $keyDir -Name $keyName
        }

        $fullKey = ($CharmName + $Key)
        $property = New-ItemProperty -Path $CharmStateKey `
                                     -Name $fullKey `
                                     -Value $Val `
                                     -PropertyType String `
                                     -ErrorAction SilentlyContinue

        if ($property -eq $null) {
            Set-ItemProperty -Path $CharmStateKey -Name $fullKey -Value $Val
        }
    }
}

function Get-CharmState {
    <#
    .SYNOPSIS
    Gets persistent data stored by charm from registry. See Set-CharmState for more info.
    .PARAMETER Namespace
    A prefix that gets added to the key
    .PARAMETER Key
    A key to identify the information by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("CharmName")]
        [string]$Namespace,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )
    PROCESS {
        $fullKey = ($CharmName + $Key)
        $property = Get-ItemProperty -Path $CharmStateKey `
                                     -Name $fullKey `
                                     -ErrorAction SilentlyContinue

        if ($property) {
            $state = Select-Object -InputObject $property -ExpandProperty $fullKey
            return $state
        }
        return
    }
}

function Remove-CharmState {
    <#
    .SYNOPSIS
    Clears charm persistent data from registry
    .PARAMETER Namespace
    A prefix that gets added to the key
    .PARAMETER Key
    A key to identify the information by
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("CharmName")]
        [string]$Namespace,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )
    PROCESS {
        $keyPath = Get-CharmStateFullKeyPath
        $fullKey = ($CharmName + $Key)
        if (Get-CharmState $CharmName $Key) {
            Remove-ItemProperty -Path $keyPath -Name $fullKey
        }
    }
}

function Get-WindowsUser {
    <#
    .SYNOPSIS
    Returns a CimInstance or a ManagementObject containing the Win32_Account representation of the requested username.
    .PARAMETER Username
    User name to lookup.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )
    PROCESS {
        $u = Get-ManagementObject -Class "Win32_Account" `
                                      -Filter ("Name='{0}'" -f $Username)
        if (!$existentUser) {
            Throw "User not found: $Username"
        }

        return $u
    }
}

# New-Alias -Name Convert-SIDToFriendlyName -Value Get-AccountNameFromSID
function Get-AccountNameFromSID {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )
    PROCESS {
        $s = Get-ManagementObject -Class Win32_Account -Filter ("SID LIKE '{0}'" -f $SID)
        if(!$s){
            Throw "SID not found: $SID"
        }
        return $s.Name
    }
}

function Get-GroupNameFromSID {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )
    PROCESS {
        $s = Get-ManagementObject -Class Win32_Group -Filter ("SID LIKE '{0}'" -f $SID)
        if(!$s){
            Throw "SID not found: $SID"
        }
        return $s.Name
    }
}

function Get-AdministratorAccount {
    <#
    .SYNOPSIS
    Helper function to return the local Administrator account name. This works with internationalized versions of Windows.
    #>
    PROCESS {
        $SID = "S-1-5-21-%-500"
        return Get-AccountNameFromSID -SID $SID
    }
}

function Get-AdministratorsGroup {
    <#
    .SYNOPSIS
    Helper function to get the local Administrators group. This works with internationalized versions of Windows.
    #>
    PROCESS {
        $SID = "S-1-5-32-544"
        return Get-GroupNameFromSID -SID $SID
    }
}

function Check-Membership {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )

    $group = Get-CimInstance -ClassName Win32_Group  `
                -Filter "SID = '$GroupSID'"
    $ret = Get-CimAssociatedInstance -InputObject $group `
          -ResultClassName Win32_UserAccount | Where-Object `
                                               { $_.Name -eq $User }
    return $ret
}

function Create-LocalAdmin {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminUsername,
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminPassword
    )

    Add-WindowsUser $LocalAdminUsername $LocalAdminPassword

    $administratorsGroupSID = "S-1-5-32-544"
    $isLocalAdmin = Check-Membership $LocalAdminUsername $administratorsGroupSID
    $groupName = Convert-SIDToFriendlyName -SID $administratorsGroupSID
    if (!$isLocalAdmin) {
        Execute-ExternalCommand -Command {
            net.exe localgroup $groupName $LocalAdminUsername /add
        } -ErrorMessage "Failed to add user to local admins group."
    } else {
        Juju-Log "User is already in the administrators group."
    }
}

function Add-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )

    $existentUser = Get-WindowsUser $Username
    if ($existentUser -eq $null) {
        $computer = [ADSI]"WinNT://$env:computername"
        $user = $computer.Create("User", $Username)
        $user.SetPassword($Password)
        $user.SetInfo()
        $user.FullName = $Username
        $user.SetInfo()
        # UserFlags = Logon script | Normal user | No pass expiration
        $user.UserFlags = 1 + 512 + 65536
        $user.SetInfo()
    } else {
        Execute-ExternalCommand -Command {
            $computername = hostname.exe
            $user = [ADSI] "WinNT://$computerName/$Username,User"
            $user.SetPassword($Password)
        } -ErrorMessage "Failed to update user password."
    }
}

function Delete-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username '/DELETE'
    } -ErrorMessage "Failed to delete user."
}

function Open-Ports {
    Param($ports)

    $directions = @("Inbound", "Outbound")
    try {
        foreach ($protocol in $ports.Keys) {
            foreach ($port in $ports[$protocol]) {
                # due to bug https://bugs.launchpad.net/juju-core/+bug/1427770,
                # there is no way to get the ports opened by other units on
                # the same node, thus we can have collisions
                Open-JujuPort -Port "$port/$protocol" -Fatal $false
                foreach ($direction in $directions) {
                    $ruleName = "Allow $direction Port $port/$protocol"
                    if (!(Get-NetFirewallRule $ruleName `
                            -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName `
                            -Name $ruleName `
                            -Direction $direction -LocalPort $port `
                            -Protocol $protocol -Action Allow
                    }
                }
            }
        }
    } catch {
        Write-JujuError "Failed to open ports."
    }
}

Export-ModuleMember -Function *
