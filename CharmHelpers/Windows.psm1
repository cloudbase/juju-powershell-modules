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
$jujuModulePath = Join-Path $PSScriptRoot "juju.psm1"
Import-Module -Force -DisableNameChecking $jujuModulePath

function Start-ProcessRedirect {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Filename,
        [Parameter(Mandatory=$true)]
        [array]$Arguments,
        [Parameter(Mandatory=$false)]
        [array]$Domain,
        [Parameter(Mandatory=$false)]
        [array]$Username,
        [Parameter(Mandatory=$false)]
        $SecPassword
    )

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $Filename
    if ($Domain -ne $null) {
        $pinfo.Username = $Username
        $pinfo.Password = $secPassword
        $pinfo.Domain = $Domain
    }
    $pinfo.CreateNoWindow = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.LoadUserProfile = $true
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    Write-JujuLog "stdout: $stdout"
    Write-JujuLog "stderr: $stderr"

    return $p
}

function Is-ComponentInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $component = Get-WmiObject -Class Win32_Product | `
                     Where-Object { $_.Name -eq $Name}

    return ($component -ne $null)
}

function Get-JujuUnitName {
   $jujuUnitName = ${env:JUJU_UNIT_NAME}.split('/')
    if ($jujuUnitName[0].Length -ge 15) {
        $jujuName = $jujuUnitName[0].substring(0, 12)
    } else {
        $jujuName = $jujuUnitName[0]
    }
    $newHostname = $jujuName + $jujuUnitName[1]
    return $newHostname
}

function Rename-Hostname {
    $newHostname = Get-JujuUnitName
    if ($env:computername -ne $newHostname) {
        Rename-Computer -NewName $newHostname
        ExitFrom-JujuHook -WithReboot
    }
}

function Change-ServiceLogon {
    param(
        [Parameter(Mandatory=$true)]
        $Services,
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$false)]
        $Password
    )

    $Services | ForEach-Object { $_.Change($null,$null,$null,$null,$null,$null,$UserName,$Password) }
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
    return "HKLM:\SOFTWARE\Wow6432Node\"
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

function Create-LocalAdmin {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminUsername,
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminPassword
    )

    $existentUser = Get-WmiObject -Class Win32_Account `
                                  -Filter "Name = '$LocalAdminUsername'"
    if ($existentUser -eq $null) {
        $computer = [ADSI]"WinNT://$env:computername"
        $localAdmin = $computer.Create("User", $LocalAdminUsername)
        $localAdmin.SetPassword($LocalAdminPassword)
        $localAdmin.SetInfo()
        $LocalAdmin.FullName = $LocalAdminUsername
        $LocalAdmin.SetInfo()
        # UserFlags = Logon script | Normal user | No pass expiration
        $LocalAdmin.UserFlags = 1 + 512 + 65536
        $LocalAdmin.SetInfo()
    } else {
        Execute-ExternalCommand -Command {
            net.exe user $LocalAdminUsername $LocalAdminPassword
        } -ErrorMessage "Failed to create new user"
    }

    $localAdmins = Execute-ExternalCommand -Command {
        net.exe localgroup Administrators
    } -ErrorMessage "Failed to get local administrators"

    # Assign user to local admins groups if he isn't there
    $isLocalAdmin = ($localAdmins -match $LocalAdminUsername) -ne 0
    if ($isLocalAdmin -eq $false) {
        Execute-ExternalCommand -Command {
            net.exe localgroup Administrators $LocalAdminUsername /add
        } -ErrorMessage "Failed to add user to local admins group"
    }
}

function Add-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username $Password '/ADD'
    } -ErrorMessage "Failed to create new user"
}

function Delete-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username '/DELETE'
    } -ErrorMessage "Failed to create new user"
}

Export-ModuleMember -Function *
