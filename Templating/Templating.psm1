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
#

function Invoke-RenderTemplate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Collections.Generic.Dictionary[string, object]]$Context,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$TemplateData
    )
    PROCESS {
        $tpl = [DotLiquid.Template]::Parse($TemplateData)
        $hash = [DotLiquid.Hash]::FromDictionary($Context)
        return  $tpl.Render($hash)
    }
}

function Invoke-RenderTemplateFromFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Collections.Generic.Dictionary[string, object]]$Context,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Template
    )
    PROCESS {
        if(!(Test-Path $Template)) {
            Throw "Template $Template was not found"
        }
        $contents = [System.IO.File]::ReadAllText($Template)
        return Invoke-RenderTemplate -Context $Context -TemplateData $contents
    }
}

Export-ModuleMember -Function * -Alias *