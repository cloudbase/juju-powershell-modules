Import-Module JujuHooks
Import-Module powershell-yaml

$global:register = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
$global:hooks = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")

function ConvertTo-List {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object]$Bag
    )
    PROCESS {
        $lst = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
        if($bag -eq $null){
            return $lst
        }
        $t = $Bag.GetType()
        if(!([System.Collections.IList].IsAssignableFrom($t))) {
            $t.Add($Bag)
            return $t
        }
        return $Bag
    }
}

function Confirm-MethodIsInList {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ModuleName,
        [Parameter(Mandatory=$true)]
        [string]$MethodName
    )
    PROCESS {
        if(!$global:register[$ModuleName]){
            return $false
        }
        foreach($i in $global:register[$ModuleName]){
            if ($i["name"] -eq $MethodName) {
                return $true
            }
        }
        return $false
    }
}

function Register-ReactiveMethod {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$MethodName,
        [array]$ArgumentList=@(),
        [array]$When,
        [array]$WhenNot,
        [array]$Hooks,
        [switch]$OnlyOnce=$false
    )
    BEGIN {
        # hack to get module name where this method is invoked
        if(!$MyInvocation.PSCommandPath) {
            Throw "This method is meant to be used from inside a charm"
        }
        $here = Split-Path -Parent $MyInvocation.PSCommandPath
        $hasPsd = Get-ChildItem $here -Filter "*.psd1" -File
        if ($hasPsd){
            $modulePath = Join-Path $here $hasPsd[0]
        }else{
            $modulePath = $MyInvocation.PSCommandPath
        }
        $name = [System.IO.Path]::GetFileNameWithoutExtension($modulePath)
    }
    PROCESS {
        if ((Confirm-MethodIsInList -ModuleName $name -MethodName $MethodName)){
            return
        }

        $sig = [System.Collections.Generic.Dictionary[string,object]](New-Object "System.Collections.Generic.Dictionary[string,object]")
        $sig["name"] = $MethodName
        $sig["ModulePath"] = $modulePath
        $sig["ModuleName"] = $name
        $sig["when"] = $When
        $sig["WhenNot"] = $WhenNot
        $sig["OnlyOnce"] = $OnlyOnce
        $sig["hooks"] = $Hooks
        $sig["args"] = $ArgumentList
        if($Hooks) {
            $global:hooks.Add($sig)
        } else {
            $global:register.Add($sig)
        }
    }
}

function Get-RegisteredMethods {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ModuleName
    )
    PROCESS {
        if ($ModuleName) {
            return $global:register[$ModuleName]
        }
        return $global:register
    }
}

function Register-ReactiveModules {
    <#
    .SYNOPSIS
    This function looks in the standard locations for layers and interfaces and imports those modules using the module name
    as a prefix. This is done because powershell does not make use of namespaces for commandlets, and function names may clash.
    #>
    PROCESS {
        $charmDir = Get-JujuCharmDir
        if (!(Test-Path $charmDir)){
            return
        }
        $targets = @(
            (Join-Path $charmDir "reactive"),
            (Join-Path $charmDir "hooks\reactive"),
            (Join-Path $charmDir "hooks\relations")
        )
        foreach ($i in $targets){
            if(!(Test-Path $i)){
                continue
            }
            $items = Get-ChildItem $i
            foreach($j in $items) {
                if ($j.PSIsContainer){
                    $hasPsd = Get-ChildItem $j.FullName -Filter "*.psd1" -File
                    if ($hasPsd){
                        Import-Module $j.FullName
                    }
                } else {
                    if ($j.FullName.EndsWith(".psm1")) {
                        Import-Module $j.FullName
                    }
                }
            }
        }
    }
}

function Get-ReactiveState {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive.states",
        [Parameter(Mandatory=$false)]
        [object]$default=$null
    )
    PROCESS{
        $keyName = ("$Namespace.{0}" -f $State)
        $val = Get-CharmState -Key $keyName
        $obj = ConvertFrom-Yaml $val
        if(!$obj){
            return $default
        }
        return $obj
    }
}

function Set-ReactiveState {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive.states",
        [Parameter(Mandatory=$false)]
        [object]$Data
    )
    PROCESS {
        $keyName = ("$Namespace.{0}" -f $State)
        $val = ConvertTo-Yaml $data
        if($val.Length -gt 1MB){
            Throw ("Dataset too big for registry: {0} KB" -f ($val.Length * 1KB))
        }
        Set-CharmState -Key $keyName -Value $val
        Set-ReactiveStateWatch -State $State
    }
}

function Remove-ReactiveState {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive.states"
    )
    PROCESS {
        $keyName = ("$Namespace.{0}" -f $State)
        $val = Get-ReactiveState -Namespace $Namespace -State $State
        if($val) {
            Remove-CharmState -Key $keyName
            Set-CharmState -Namespace "reactive.dispatch" -State "removed_state" -Data $true
            Set-ReactiveStateWatch -State $State
        }
    }
}


function Get-ReactiveStateWatch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive"
    )
    PROCESS {
        $val = Get-ReactiveState -Namespace $Namespace -State "state_watch"
        if(!$val){
            $val = [System.Collections.Generic.Dictionary[string,object]](New-Object "System.Collections.Generic.Dictionary[string,object]")
            $val["iterations"] = 0
            $val["pending"] = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
            $val["changes"] = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
        }
        $val["pending"] = ConvertTo-List $val["pending"]
        $val["changes"] = ConvertTo-List $val["changes"]
        return $val
    }
}

function Reset-ReactiveStateWatch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive"
    )
    PROCESS {
        $keyName = "$Namespace.state_watch"
        Remove-CharmState -Key $keyName
    }
}

function Set-ReactiveStateWatch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive"
    )
    PROCESS{
        $keyName = "$Namespace.state_watch"
        $val = Get-ReactiveStateWatch -Namespace $Namespace
        $val["pending"].Add($State)
        if(!$val["changes"].Count) {
            $val.Remove("changes")
        }
        Set-ReactiveState -Namespace $Namespace -State "state_watch" -Data $val
    }
}

function Sync-ReactiveStateWatch {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Namespace="reactive"
    )
    PROCESS{
        $watched = Get-ReactiveStateWatch -Namespace $Namespace
        if($watched["pending"].Count) {
            $watched["changes"] = $watched["pending"]
            $watched.Remove("pending")
        }
        if(!$watched["changes"].Count){
            $watched.Remove("changes")
        }
        if(!$watched["pending"].Count){
            $watched.Remove("changes")
        }
        Set-ReactiveState -Namespace $Namespace -State $State -Data $watched
    }
}

function Set-ReactiveMethodInvoked {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$MethodName,
        [Parameter(Mandatory=$false)]
        [switch]$WasRun=$true
    )
    PROCESS {
        $keyName = ('reactive.invoked.{0}' -f $MethodName)
        $str = ConvertTo-Yaml $WasRun
        Set-CharmState -Key $keyName -Value $str
    }
}

function Confirm-CurrentHook {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Hooks
    )
    PROCESS {
        $hookName = $env:JUJU_HOOK_NAME
        if(!$hookName) {
            # Get the name of the hook witout its base path and extension 
            $hookName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
        }
        if($hookName -in $Hooks) {
            return $true
        }
        return $false
    }
}

function Confirm-MethodWasRun {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$MethodName
    )
    PROCESS {
        $keyName = ('reactive.invoked.{0}' -f $MethodName)
        $val = Get-CharmState -Key $keyName
        return (ConvertFrom-Yaml $val)
    }
}

function Confirm-WhenNot {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [array]$States
    )
    PROCESS {
        $currentStates = Get-ReactiveStateWatch
        foreach($i in $States) {
            if($i -in $currentStates["changes"]) {
                return $false
            }
        }
        return $true
    }
}

function Confirm-When {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [array]$States
    )
    PROCESS {
        $currentStates = Get-ReactiveStateWatch
        foreach($i in $States) {
            if(!($i in $currentStates)) {
                return $false
            }
        }
        return $true
    }
}


# @{
#     "module-name"=@{
#         "Path"="";
#         "registered-methods"=@(
#             @{
#                 "name"="test";
#                 "WhenNone"=$WhenNone;
#                 "when"="test";
#                 "hooks"="config-changed","install";
#                 "OnlyOnce"=$true;
#                 "args"=$ArgumentList;
#             }
#         )
#     )
# }

function Get-HookMethods {
    PROCESS {
        $methods = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
        foreach ($i in $global:hooks) {
            $shouldRun = Confirm-CurrentHook -Hooks $i["hooks"]
            if($shouldRun) {
                $methods.Add($j)
            }
        }
        return $methods
    }    
} 

function Invoke-Reactive {
    BEGIN {
        Reset-ReactiveStateWatch
    }
    PROCESS {
        Set-CharmState -Key 'reactive.dispatch.phase' -Value "hooks"
        $hookMethods = Get-HookMethods
        #TODO: implement the rest
        
    }
    END {
        Reset-ReactiveStateWatch
    }
}