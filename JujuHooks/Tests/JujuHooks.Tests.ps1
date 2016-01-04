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
            return '{"user": "guest"}'
        }

        It "Should pass only - as attr" {
            $env:JUJU_REMOTE_UNIT = "bogus"
            $env:JUJU_RELATION_ID = "amqp:1"
            (Get-JujuRelation).GetType() | Should Be "Hashtable"
            (Get-JujuRelation).user | Should Be "guest"
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
            { Get-JujuRelation -Unit "bogus" } | Should Throw
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
            return '{"test": "test", "hello": "world"}'
        }

        It "Should pass unit, relation id and attribute" {
            $r = Get-JujuRelation -Unit "bogus" -RelationID "amqp:1"
            $r.GetType() | Should Be "hashtable"
            $r["test"] | Should Be "test"
            $r["hello"] | Should Be "world"
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
            return '"test"'
        }

        It "Should pass unit, relation id and attribute" {
            Get-JujuRelation -Unit "bogus" -RelationID "amqp:1" -Attribute "name" | Should Be "test"
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
        It "Should throw an exception (Missing relation ID)" {
            $params = @{
                "name"="value";
            }
            { Set-JujuRelation -Settings $params } | Should Throw
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

        It "Should Throw an exception (Missing relation ID)" {
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
        It "Should throw an exception (Missing relation ID)" {
            $params = @{
                "name"="value";
                "integer"=111;
            }
            { Set-JujuRelation -Settings $params } | Should Throw
        }
    }
}

Describe "Test Get-JujuRelationIds" {
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
    Context "Call Get-JujuRelationIds without -Relation"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-ids.exe", "--format=json", "amqp")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '["amqp:1", "amqp:2"]'
        }
        It "Should throw an exception (Missing relation type)" {
            { Get-JujuRelationIds } | Should Throw
        }
        It "Should return relation ID" {
            $env:JUJU_RELATION = "amqp"
            Get-JujuRelationIds | Should Be @("amqp:1", "amqp:2")
            (Get-JujuRelationIds).GetType().BaseType.Name | Should Be "Array"
        }
    }
    Context "Call Get-JujuRelationIds with -Relation"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-ids.exe", "--format=json", "shared-db")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '"mysql:1"'
        }
        It "Should return relation ID" {
            Get-JujuRelationIds -Relation "shared-db" | Should Be "mysql:1"
        }
    }
}

Describe "Test Get-JujuRelatedUnits" {
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
    Context "Call Get-JujuRelatedUnits without -RelationID"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-list.exe", "--format=json", "-r", "amqp:1")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '["rabbitmq/0", "rabbitmq/1"]'
        }
        It "Should throw an exception (Missing relation ID)" {
            { Get-JujuRelatedUnits } | Should Throw
        }
        It "Should return related units" {
            $env:JUJU_RELATION_ID = "amqp:1"
            Get-JujuRelatedUnits | Should Be @("rabbitmq/0", "rabbitmq/1")
        }
    }
    Context "Get-JujuRelatedUnits with -Relation"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-list.exe", "--format=json", "-r","shared-db")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '"mysql:1"'
        }
        It "Should return related units" {
            Get-JujuRelatedUnits -RelationID "shared-db" | Should Be "mysql:1"
        }
    }
}

Describe "Test Get-JujuRelationForUnit" {
    Context "Call Get-JujuRelationForUnit"{
        Mock Invoke-JujuCommand -ModuleName JujuHooks {
            Param (
                [array]$Command
            )
            $expect = @("relation-get.exe", "--format=json", "-r", "amqp:1", "-", "bogus")
            if ((Compare-Object $Command $expect)) {
                Throw "Invalid parameters"
            }
            return '{"test": "test", "hello": "world", "test-list": "hello world"}'
        }

        It "Should pass unit and relation id. Return hashtable" {
            $r = Get-JujuRelationForUnit -Unit "bogus" -RelationId "amqp:1"
            $r.GetType() | Should Be "hashtable"
            $r["test"] | Should Be "test"
            $r["hello"] | Should Be "world"
            $r["test-list"] | Should Be @("hello", "world")
        }
    }
    
}

Describe "Test Get-JujuRelationForId" {
    Context "Call Get-JujuRelationForId"{
        Mock Get-JujuRelatedUnits -ModuleName JujuHooks {
            return @("rabbitmq/0", "rabbitmq/1")
        }
        Mock Get-JujuRelationForUnit -ModuleName JujuHooks {
            Param(
                [string]$Unit=$null,
                [Alias("Rid")]
                [string]$RelationId=$null
            )
            if ($RelationId -ne "amqp:1"){
                Throw "Invalid relationID. Expected amqp:1"
            }
            $ret = @{
                'rabbitmq/0'= @{"rabbit-0-test"="test-0"; "rabbit-0-hello"="rabbit-0-world";};
                'rabbitmq/1'= @{"rabbit-1-test"="test-1"; "rabbit-1-hello"="rabbit-1-world";};
            }
            return $ret[$Unit]
        }
        It "Should get array of relation data" {
            $r = Get-JujuRelationForId -RelationId "amqp:1"
            $r.GetType().BaseType.Name | Should Be "Array"
            $r.Count | Should Be 2
            $r[0]["rabbit-0-test"] | Should Be "test-0"
            $r[0]["rabbit-0-hello"] | Should Be "rabbit-0-world"
            $r[0]["__unit__"] | Should Be "rabbitmq/0"
            $r[1]["rabbit-1-test"] | Should Be "test-1"
            $r[1]["rabbit-1-hello"] | Should Be "rabbit-1-world"
            $r[1]["__unit__"] | Should Be "rabbitmq/1"
        }

        It "Should throw an exception (Missing relation ID)" {
            { Get-JujuRelationForId } | Should Throw
        }
    }
}

Describe "Test Get-JujuRelationsOfType" {
    Mock Get-JujuRelationIds -ModuleName JujuHooks {
        Param(
            [Alias("RelType")]
            [string]$Relation=$null
        )
        if($Relation -ne "amqp") {
            return $null
        }
        return @("amqp:1", "amqp:2")
    }
    Mock Get-JujuRelationForUnit -ModuleName JujuHooks {
        Param(
            [string]$Unit=$null,
            [Alias("Rid")]
            [string]$RelationId=$null
        )
        $data = @{
            "amqp:1"= @{
                'rabbitmq/0'= @{"rabbit-0-test"="test-0";};
                'rabbitmq/1'= @{"rabbit-1-test"="test-1";};
            };
            "amqp:2" = @{
                'keystone/0'=@{
                    "id"="root";
                };
            };
        }
        if(!$data[$RelationID]){
            Throw "Invalid relation ID"
        }
        $x = $data[$RelationId][$Unit]
        return $x
    }
    Mock Get-JujuRelatedUnits -ModuleName JujuHooks {
        Param(
            [Alias("RelId")]
            [string]$RelationId=$null
        )
        $data = @{
            "amqp:1"=@("rabbitmq/0", "rabbitmq/1");
            "amqp:2"=@("keystone/0")
        }
        return $data[$RelationId]
    }
    It "Should return an array of relation data" {
        $r = Get-JujuRelationsOfType -Relation "amqp"
        $r.GetType().BaseType.Name | Should Be "Array"
        $r.Count | Should Be 3
    }

    It "Should return empty" {
        $r = Get-JujuRelationsOfType -Relation "bogus"
        $r | Should BeNullOrEmpty
    }
}

Describe "Test Confirm-JujuRelationCreated" {
    Mock Get-JujuRelationIds -ModuleName JujuHooks {
        Param(
            [Alias("RelType")]
            [string]$Relation=$null
        )
        $relations = @{
            "amqp" = @("amqp:1", "amqp:2");
            "testing" = @();
        }
        return $relations[$Relation]
    }
    It "Should return True" {
        Confirm-JujuRelationCreated -Relation "amqp" | Should Be $true
    }

    It "Should return False" {
        Confirm-JujuRelationCreated -Relation "bogus" | Should Be $false
    }
    It "Should return False on non existing relation" {
        Confirm-JujuRelationCreated -Relation "bogus" | Should Be $false
    }
    It "Should return False on uninitialized relation" {
        Confirm-JujuRelationCreated -Relation "testing" | Should Be $false
    }
}

Describe "Test Get-JujuUnit" {
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        if(!($Command[-1] -in @("private-address", "public-address"))){
            Throw "only private-address and public-address are supported"
        }
        $expect = @("unit-get.exe", "--format=json")
        if ((Compare-Object $Command ($expect + $Command[-1]))) {
            Throw "Invalid parameters"
        }
        $addr = @{
            "private-address"='"192.168.1.1"';
            "public-address"='"192.168.1.2"';
        }
        return $addr[$Command[-1]]
    }
    It "Should throw an exception (invalid attribute)" {
        { Get-JujuUnit -Attribute "Bogus" } | Should Throw
    }

    It "Should return private-address" {
        Get-JujuUnit -Attribute "private-address" | Should Be "192.168.1.1"
    }

    It "Should return public-address" {
        Get-JujuUnit -Attribute "public-address" | Should Be "192.168.1.2"
    }
}

Describe "Test Confirm-IP" {
    It "Should return False for 'bla'" {
        Confirm-IP -IP "bla" | Should Be $false
    }
    It "Should return False for '192.168.1'" {
        Confirm-IP -IP "192.168.1" | Should Be $false
    }
    It "Should return True for '192.168.1.1'" {
        Confirm-IP -IP "192.168.1.1" | Should Be $true
    }
    It "Should return True for '::1'" {
        Confirm-IP -IP "::1" | Should Be $true
    }
}

Describe "Test Get-JujuUnitPrivateIP" {
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
    Mock Resolve-Address -ModuleName JujuHooks -Verifiable {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$Address
        )
        $data = @{
            "example.com"="192.168.1.1";
        }
        if(!$data[$Address]){
            Throw ("Could not resolve address {0} to IP" -f $Address)
        }
        return $data[$Address]
    }
    Mock Invoke-JujuCommand -ModuleName JujuHooks {
        Param (
            [array]$Command
        )
        if(!($Command[-1] -in @("private-address", "public-address"))){
            Throw "only private-address and public-address are supported"
        }
        $expect = @("unit-get.exe", "--format=json")
        if ((Compare-Object $Command ($expect + $Command[-1]))) {
            Throw "Invalid parameters"
        }
        if(!$env:privateIP){
            $pi = '"192.168.1.1"'
        }else {
            $pi = $env:privateIP
        }
        $addr = @{
            "private-address"=$pi;
            "public-address"='"192.168.1.2"';
        }
        return $addr[$Command[-1]]
    }
    It "Should return the private address (supply IP address)" {
        Get-JujuUnitPrivateIP | Should Be "192.168.1.1"
    }

    It "Should return the private address (supply hostname)" {
        $env:privateIP = '"example.com"'
        Get-JujuUnitPrivateIP | Should Be "192.168.1.1"
        Assert-VerifiableMocks
    }

    It "Should throw an exception" {
        $env:privateIP = '"example-bogus.com"'
        { Get-JujuUnitPrivateIP } | Should Throw
        Assert-VerifiableMocks
    }
}