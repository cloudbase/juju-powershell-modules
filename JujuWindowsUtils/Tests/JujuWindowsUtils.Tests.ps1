$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}

$savedEnv = [System.Environment]::GetEnvironmentVariables()

Import-Module JujuWindowsUtils

function Clear-Environment {
    $current = [System.Environment]::GetEnvironmentVariables()
    foreach($i in $savedEnv.GetEnumerator()) {
        [System.Environment]::SetEnvironmentVariable($i.Name, $i.Value, "Process")
    }
    $current = [System.Environment]::GetEnvironmentVariables()
    foreach ($i in $current.GetEnumerator()){
        if(!$savedEnv[$i.Name]){
            [System.Environment]::SetEnvironmentVariable($i.Name, $null, "Process")
        }
    }
}

Describe "Test Get-IsNanoServer" {
    Mock Get-ServerLevelKey -ModuleName JujuWindowsUtils { return "HKCU:\Software\Juju-Charms"}
    AfterEach {
        $CharmStateKey = "HKCU:\Software\Juju-Charms"
        if($CharmStateKey -and (Test-Path $CharmStateKey)) {
            Remove-Item $CharmStateKey -Recurse -Force
        }
    }
    Context "Running on a server build" {
        BeforeEach {
            $CharmStateKey = "HKCU:\Software\Juju-Charms"
            if($CharmStateKey -and (Test-Path $CharmStateKey)) {
                Remove-Item $CharmStateKey -Recurse -Force
            }
            $keyDir = Split-Path -Parent $CharmStateKey
            $keyName = Split-Path -Leaf $CharmStateKey
            New-Item -Path $keyDir -Name $keyName | Out-Null
        }
        It "Should return True" {
            New-ItemProperty -Path "HKCU:\Software\Juju-Charms" -Name NanoServer -Value 1 -PropertyType Dword
            Get-IsNanoServer | Should Be $true
        }
        It "Should return False" {
            New-ItemProperty -Path "HKCU:\Software\Juju-Charms" -Name NanoServer -Value 0 -PropertyType Dword
            Get-IsNanoServer | Should Be $false
        }
    }
    Context "Running on a desktop build" {
        It "Should be false" {
            Get-IsNanoServer | Should Be $false
        }
    }
}

Describe "Test Start-ProcessRedirect" {}

Describe "Test Get-ComponentIsInstalled" {}

Describe "Test Set-ServiceLogon" {}

Describe "Test Get-ServiceIsRunning" {}

Describe "Test Install-Msi" {}

Describe "Test Expand-ZipArchive" {}

Describe "Test Install-WindowsFeatures" {
    Mock Invoke-JujuReboot -ModuleName JujuWindowsUtils { }
    # This is missing on a desktop Windows workstation
    function Install-WindowsFeature { }

    Context "Windows features are enabled on Nano Server" {
        Mock Get-IsNanoServer -ModuleName JujuWindowsUtils { return $true }
        Mock Install-WindowsFeature -ModuleName JujuWindowsUtils { }
        Mock Enable-OptionalWindowsFeatures -ModuleName JujuWindowsUtils { }

        It "should enable Windows features on Nano Server" {
            $fakeFeatures = @('Feature_1', 'Feature_2')
            Install-WindowsFeatures -Features $fakeFeatures
            Assert-MockCalled Get-IsNanoServer -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Enable-OptionalWindowsFeatures -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Install-WindowsFeature -Exactly 0 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 0 -ModuleName JujuWindowsUtils
        }
    }

    Context "Windows features are installed" {
        Mock Get-IsNanoServer -ModuleName JujuWindowsUtils { return $false }
        Mock Enable-OptionalWindowsFeatures -ModuleName JujuWindowsUtils { }
        Mock Install-WindowsFeature -ModuleName JujuWindowsUtils {
            return @{
                'Success' = $true
                'RestartNeeded' = $true
            }
        }
        It "should install features and do a reboot" {
            $fakeFeatures = @('Feature_1', 'Feature_2')
            Install-WindowsFeatures -Features $fakeFeatures | Should BeNullOrEmpty
            Assert-MockCalled Get-IsNanoServer -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Enable-OptionalWindowsFeatures -Exactly 0 -ModuleName JujuWindowsUtils
            Assert-MockCalled Install-WindowsFeature -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 1 -ModuleName JujuWindowsUtils
        }
    }

    Context "Windows feature failed to install" {
        Mock Get-IsNanoServer -ModuleName JujuWindowsUtils { return $false }
        Mock Enable-OptionalWindowsFeatures -ModuleName JujuWindowsUtils { }
        Mock Install-WindowsFeature -ModuleName JujuWindowsUtils {
            return @{
                'Success' = $false
                'RestartNeeded' = $true
            }
        }
        It "should fail to install features" {
            $fakeFeatures = @('WindowsFeature_1')
            { Install-WindowsFeatures -Features $fakeFeatures } | Should Throw
            Assert-MockCalled Install-WindowsFeature -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Get-IsNanoServer -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Enable-OptionalWindowsFeatures -Exactly 0 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 0 -ModuleName JujuWindowsUtils
        }
    }
}

Describe "Test Enable-OptionalWindowsFeatures" {
    Mock Invoke-JujuReboot -ModuleName JujuWindowsUtils { }

    Context "Windows features are enabled" {
        Mock Get-WindowsOptionalFeature -ModuleName JujuWindowsUtils {
            return @{
                'State' = 'Disabled'
            }
        }
        Mock Enable-WindowsOptionalFeature -ModuleName JujuWindowsUtils {
            return @{
                'RestartNeeded' = $true
            }
        }

        It "should enable features and do a reboot" {
            $fakeFeatures = @('Feature_1', 'Feature_2')
            Enable-OptionalWindowsFeatures -Features $fakeFeatures | Should BeNullOrEmpty
            Assert-MockCalled Get-WindowsOptionalFeature -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Enable-WindowsOptionalFeature -Exactly 2 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 1 -ModuleName JujuWindowsUtils
        }
    }

    Context "Windows feature failed to enable" {
        Mock Get-WindowsOptionalFeature -ModuleName JujuWindowsUtils {
            return @{
                'State' = 'Disabled'
            }
        }
        Mock Enable-WindowsOptionalFeature -ModuleName JujuWindowsUtils { Throw }

        It "should fail to enable features" {
            $fakeFeatures = @('WindowsFeature_1')
            { Enable-OptionalWindowsFeatures -Features $fakeFeatures } | Should Throw
            Assert-MockCalled Get-WindowsOptionalFeature -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Enable-WindowsOptionalFeature -Exactly 1 -ModuleName JujuWindowsUtils
            Assert-MockCalled Invoke-JujuReboot -Exactly 0 -ModuleName JujuWindowsUtils
        }
    }
}

Describe "Test Get-AccountObjectByName" {}

Describe "Test Get-GroupObjectByName" {}

Describe "Test Get-AccountObjectBySID" {}

Describe "Test Get-GroupObjectBySID" {}

Describe "Test Get-AccountNameFromSID" {}

Describe "Test Get-GroupNameFromSID" {}

Describe "Test Get-AdministratorAccount" {}

Describe "Test Get-AdministratorsGroup" {}

Describe "Test Get-UserGroupMembership" {}

Describe "Test New-LocalAdmin" {}

Describe "Test Add-WindowsUser" {
    $fakeUser = "FakeUser"
    $fakePassword = "FakePassword"
    $fakeFullname = "Fake full name"
    $fakeDescription = "Fake description"
    Mock Invoke-JujuCommand -ModuleName JujuWindowsUtils { }

    Context "User already exist" {
        Mock Get-AccountObjectByName -ModuleName JujuWindowsUtils { return $true }

        It "should reset the password" {
            Add-WindowsUser -Username $fakeUser -Password $fakePassword | Should BeNullOrEmpty
            Assert-MockCalled Get-AccountObjectByName -ModuleName JujuWindowsUtils -Exactly 1
            Assert-MockCalled Invoke-JujuCommand -ModuleName JujuWindowsUtils -Exactly 1 -ParameterFilter {
                (Compare-Object $Command @("net.exe", "user", $fakeUser, $fakePassword)) -eq $null
            }
        }
    }

    Context "New user is created with both the optional parameters description and full name" {
        Mock Get-AccountObjectByName -ModuleName JujuWindowsUtils { return $false }

        It "should create a new user" {
            Add-WindowsUser -Username $fakeUser -Password $fakePassword -Fullname $fakeFullname -Description $fakeDescription | Should BeNullOrEmpty
            Assert-MockCalled Get-AccountObjectByName -ModuleName JujuWindowsUtils -Exactly 1
            Assert-MockCalled Invoke-JujuCommand -ModuleName JujuWindowsUtils -Exactly 1 -ParameterFilter {
                (Compare-Object $Command @("net.exe", "user", $fakeUser, $fakePassword,
                                           "/add", ("/fullname:{0}" -f @($fakeFullname)),
                                           ("/comment:{0}" -f @($fakeDescription)),
                                           "/expires:never", "/active:yes")) -eq $null
            }
        }
    }

    Context "New user is created with only the optional parameter description" {
        Mock Get-AccountObjectByName -ModuleName JujuWindowsUtils { return $false }

        It "should create a new user" {
            Add-WindowsUser -Username $fakeUser -Password $fakePassword -Description $fakeDescription | Should BeNullOrEmpty
            Assert-MockCalled Get-AccountObjectByName -ModuleName JujuWindowsUtils -Exactly 1
            Assert-MockCalled Invoke-JujuCommand -ModuleName JujuWindowsUtils -Exactly 1 -ParameterFilter {
                (Compare-Object $Command @("net.exe", "user", $fakeUser, $fakePassword,
                                           "/add", ("/comment:{0}" -f @($fakeDescription)),
                                           "/expires:never", "/active:yes")) -eq $null
            }
        }
    }

    Context "New user is created with only the optional parameter full name" {
        Mock Get-AccountObjectByName -ModuleName JujuWindowsUtils { return $false }

        It "should create a new user" {
            Add-WindowsUser -Username $fakeUser -Password $fakePassword -Fullname $fakeFullname | Should BeNullOrEmpty
            Assert-MockCalled Get-AccountObjectByName -ModuleName JujuWindowsUtils -Exactly 1
            Assert-MockCalled Invoke-JujuCommand -ModuleName JujuWindowsUtils -Exactly 1 -ParameterFilter {
                (Compare-Object $Command @("net.exe", "user", $fakeUser, $fakePassword,
                                           "/add", ("/fullname:{0}" -f @($fakeFullname)),
                                           "/expires:never", "/active:yes")) -eq $null
            }
        }
    }

    Context "New user is created without either the optional parameters full name or description" {
        Mock Get-AccountObjectByName -ModuleName JujuWindowsUtils { return $false }

        It "should create a new user" {
            Add-WindowsUser -Username $fakeUser -Password $fakePassword | Should BeNullOrEmpty
            Assert-MockCalled Get-AccountObjectByName -ModuleName JujuWindowsUtils -Exactly 1
            Assert-MockCalled Invoke-JujuCommand -ModuleName JujuWindowsUtils -Exactly 1 -ParameterFilter {
                (Compare-Object $Command @("net.exe", "user", $fakeUser, $fakePassword,
                                           "/add", "/expires:never", "/active:yes")) -eq $null
            }
        }
    }
}

Describe "Test Remove-WindowsUser" {}

Describe "Test Open-Ports" {}

Describe "Test Import-Certificate" {}

Describe "Test Grant-Privilege" {}