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

param($DocumentPath=".\documentation.txt",
       $GenerateDocForEveryModule=$false)
$ErrorActionPreference = "Stop"

$charmHelpersModulePath = ".\CharmHelpers\CharmHelpers.psd1"
$fullCharmHelpersModulePath = Resolve-Path $charmHelpersModulePath
$modules = @("Carbon", "Juju", "Utils", "Windows")

function GenerateDoc {
    param($ModuleName,
        $ModulePath,
        $DocFilePath)

    Import-Module -Name $ModulePath -DisableNameChecking -Force
    $allModuleMethods = (Get-Module $ModuleName).ExportedCommands
    Set-Content -Value "Documentation for Powershell Module $ModuleName." `
                -Path $DocFilePath

    foreach ($method in $allModuleMethods.Keys) {
        (Get-Help -Name $method) | Out-File -Append -encoding ASCII `
                                            -FilePath $DocFilePath
    }
}

GenerateDoc "CharmHelpers" $charmHelpersModulePath $DocumentPath