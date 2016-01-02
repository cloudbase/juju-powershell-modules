$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleHome = Split-Path -Parent $here
$moduleRoot = Split-Path -Parent $moduleHome
$bin = Join-Path $here "Bin"

$modulePath = ${env:PSModulePath}.Split(";")
if(!($moduleRoot -in $modulePath)){
    $env:PSModulePath += ";$moduleRoot"
}
$savedEnv = [System.Environment]::GetEnvironmentVariables()

Import-Module JujuHooks

Describe "Test Confirm-ContextComplete" {
    AfterEach {
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
    It "Should return False" {
        $ctx = @{
            "test" = $null;
            "test2" = "test";
        }
        Confirm-ContextComplete -Context $ctx | Should Be $false

        $ctx = @{
            "test" = $false;
            "test2" = "test";
        }
        Confirm-ContextComplete -Context $ctx | Should Be $false

        $ctx = @{}
        Confirm-ContextComplete -Context $ctx | Should Be $false
    }

    It "Should return True" {
        $ctx = @{
            "hello" = "world";
        }
        Confirm-ContextComplete -Context $ctx | Should Be $true
    }

    It "Should Throw an exception" {
        $ctx = "not a hashtable"
        { Confirm-ContextComplete -Context $ctx} | Should Throw
    }
}

Describe "Test hook environment functions" {
    AfterEach {
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
    It "Should return charm_dir" {
        $env:CHARM_DIR = "bogus"
        Get-JujuCharmDir | Should Be "bogus"
    }

    It "Should return relation name" {
        $env:JUJU_RELATION = "bogus"
        Get-JujuRelationType | Should be "bogus"
    }

    It "Confirm-JujuRelation should return True" {
        $env:JUJU_RELATION = "bogus"
        Confirm-JujuRelation | Should be $true
    }

    It "Confirm-JujuRelation should return False" {
        $env:JUJU_RELATION = ""
        Confirm-JujuRelation | Should be $false
    }

    It "Get-JujuRelationId should return relation ID" {
        $env:JUJU_RELATION_ID = "bogus:1"
        Get-JujuRelationId | Should Be "bogus:1"
    }

    It "Get-JujuLocalUnit should return unit name" {
        $env:JUJU_UNIT_NAME = "unit-1"
        Get-JujuLocalUnit | Should Be "unit-1"
    }

    It "Get-JujuRemoteUnit should return remote unit" {
        $env:JUJU_REMOTE_UNIT = "remote-1"
        Get-JujuRemoteUnit | Should Be "remote-1"
    }

    It "Get-JujuServiceName should get service name" {
        $env:JUJU_UNIT_NAME = "active-directory/0"
        Get-JujuServiceName | Should Be "jujud-active-directory-0"
    }
}

Describe "Test Get-JujuCharmConfig" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        $ret = @{
            "stringOption"="Hello";
            "intOption"=1;
        }
        if($Command.Length -gt 2) {
            $x = $Command[2]
            if($ret[$x]){
                return (ConvertTo-Json $ret[$x])
            }
            return ""
        }
        return (ConvertTo-Json $ret)
    }
    It "Should return a Hashtable" {
        (Get-JujuCharmConfig).GetType() | Should Be "Hashtable"
        (Get-JujuCharmConfig).stringOption | Should Be "Hello"
        (Get-JujuCharmConfig).intOption | Should Be 1
    }

    It "Should return a string" {
        Get-JujuCharmConfig -Scope "stringOption" | Should Be "Hello"
    }

    It "Should return an int" {
        Get-JujuCharmConfig -Scope "intOption" | Should Be 1
    }

    It "Should return empty" {
        Get-JujuCharmConfig -Scope "nonexisting" | Should BeNullOrEmpty
    }
}

Describe "Test Get-JujuRelation" {
    AfterEach {
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
    Context "Invoke Get-JujuRelation without params" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=json", "-")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }

        It "Should pass only - as attr" {
            $env:JUJU_REMOTE_UNIT = "bogus"
            $env:JUJU_RELATION_ID = "amqp:1"
            (Get-JujuRelation).GetType() | Should Be "Hashtable"
        }
        It "Should throw an exception" {
            { Get-JujuRelation }| Should Throw
        }
    }

    Context "Invoke Get-JujuRelation with Unit"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=json", "-", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }
        It "Should pass - and unit" {
            $env:JUJU_RELATION_ID = "amqp:1"
            Get-JujuRelation -Unit "bogus" | Should BeNullOrEmpty
        }
        It "Should throw an exception" {
            { Get-JujuRelation -Unit "bogus" }| Should Throw
        }
    }

    Context "Invoke Get-JujuRelation with Unit and relation ID"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=json", "-r", "amqp:1", "-", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }

        It "Should pass unit and relation id" {
            Get-JujuRelation -Unit "bogus" -RelationID "amqp:1" | Should BeNullOrEmpty
        }
    }

    Context "Invoke Get-JujuRelation with Unit, relation ID and attribute"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=json", "-r", "amqp:1", "name", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }

        It "Should pass unit, relation id and attribute" {
            Get-JujuRelation -Unit "bogus" -RelationID "amqp:1" -Attribute "name" | Should BeNullOrEmpty
        }
    }
}

Describe "Test Set-JujuRelation"{
    AfterEach {
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

    Context "Call Set-JujuRelation without RelationID" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-set.exe", "name='value'")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }

        It "Should pass name=value" {
            $env:JUJU_RELATION_ID = "amqp:1"
            $params = @{
                "name"="value";
            }
            Set-JujuRelation -Settings $params | Should Be $true
        }
        It "Should throw an exception" {
            $params = @{
                "name"="value";
            }
            { Set-JujuRelation -Settings $params }| Should Throw
        }
    }

    Context "Call Set-JujuRelation with RelationID" {
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-set.exe", "-r", "amqp:1", "name='value'")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }
        It "Should pass relationID" {
            $params = @{
                "name"="value";
            }
            Set-JujuRelation -Settings $params -RelationID "amqp:1" | Should Be $true
        }

        It "Should Throw an exception" {
            { Set-JujuRelation -RelationID "amqp:1" } | Should Throw
        }
    }

    Context "Call Set-JujuRelation with multiple settings"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-set.exe", "name='value'", "integer='111'")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
        }
        It "Should pass in multiple settings" {
            $params = @{
                "name"="value";
                "integer"=111;
            }
            $env:JUJU_RELATION_ID = "amqp:1"
            Set-JujuRelation -Settings $params | Should Be $true
        }
        It "Should throw an exception" {
            $params = @{
                "name"="value";
                "integer"=111;
            }
            { Set-JujuRelation -Settings $params } | Should Throw
        }
    }
}