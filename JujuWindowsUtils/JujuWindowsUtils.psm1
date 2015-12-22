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
            }
        }
    }
}

function Is-ServiceAlive {
    param(
        [Parameter(Mandatory=$true)]
        [string]$serviceName)

    $service = Get-Service $serviceName
    if ($service -and $service.Status -eq 'Running') {
        Write-JujuLog "Service $serviceName is alive."
        return $true
    } else {
        Write-JujuLog "Service $serviceName is dead."
        return $false
    }
}

function Install-Msi {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MsiFilePath,
        [Parameter(Mandatory=$true)]
        [string]$LogFilePath
        )

    $args = @(
        "/i",
        $MsiFilePath,
        "/l*v",
        $LogFilePath
        )

    $p = Start-Process -FilePath "msiexec" -Wait -PassThru -ArgumentList $args
    if ($p.ExitCode -ne 0) {
        Write-JujuLog "Failed to install MSI package."
        Throw "Failed to install MSI package."
    } else {
        Write-JujuLog "Succesfully installed MSI package."
    }

}

function Get-IPv4Subnet {
    param(
        [Parameter(Mandatory=$true)]
        $IP,
        [Parameter(Mandatory=$true)]
        $Netmask
    )

    $class = 32
    $netmaskClassDelimiter = "255"
    $netmaskSplit = $Netmask -split "[.]"
    $ipSplit = $IP -split "[.]"
    for ($i = 0; $i -lt 4; $i++) {
        if ($netmaskSplit[$i] -ne $netmaskClassDelimiter) {
            $class -= 8
            $ipSplit[$i] = "0"
        }
    }

    $fullSubnet = ($ipSplit -join ".") + "/" + $class
    return $fullSubnet
}

function Install-WindowsFeatures {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Features
    )

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
        ExitFrom-JujuHook -WithReboot
    }
}

function Get-CharmStateFullKeyPath () {
    return ((Get-CharmStateKeyDir) + (Get-CharmStateKeyName))
}

function Get-CharmStateKeyDir () {
    return "HKLM:\SOFTWARE\"
}

function Get-CharmStateKeyName () {
    return "Juju-Charms"
}

function Set-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [string]$Val
    )

    $keyPath = Get-CharmStateFullKeyPath
    $keyDirExists = Test-Path -Path $keyPath
    if ($keyDirExists -eq $false) {
        $keyDir = Get-CharmStateKeyDir
        $keyName = Get-CharmStateKeyName
        New-Item -Path $keyDir -Name $keyName
    }

    $fullKey = ($CharmName + $Key)
    $property = New-ItemProperty -Path $keyPath `
                                 -Name $fullKey `
                                 -Value $Val `
                                 -PropertyType String `
                                 -ErrorAction SilentlyContinue

    if ($property -eq $null) {
        Set-ItemProperty -Path $keyPath -Name $fullKey -Value $Val
    }
}

function Get-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )

    $keyPath = Get-CharmStateFullKeyPath
    $fullKey = ($CharmName + $Key)
    $property = Get-ItemProperty -Path $keyPath `
                                 -Name $fullKey `
                                 -ErrorAction SilentlyContinue

    if ($property -ne $null) {
        $state = Select-Object -InputObject $property -ExpandProperty $fullKey
        return $state
    } else {
        return $null
    }
}

function Remove-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )

    $keyPath = Get-CharmStateFullKeyPath
    $fullKey = ($CharmName + $Key)
    if (Get-CharmState $CharmName $Key) {
        Remove-ItemProperty -Path $keyPath -Name $fullKey
    }
}

function Get-WindowsUser {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    $existentUser = Get-WmiObject -Class "Win32_Account" `
                                  -Filter "Name = '$Username'"
    if ($existentUser -eq $null) {
        Write-JujuLog "User not found."
    }

    return $existentUser
}


function Convert-SIDToFriendlyName {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $name = $objUser.Value
    $n = $name.Split("\")
    if ($n.length -gt 1){
        return $n[1]
    }
    return $n[0]
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
                # the same node, thus we can have colisions
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
