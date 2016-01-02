# Copyright 2014 Cloudbase Solutions Srl
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

# The tests' execution can be performed also using a non-administrator account.
# In order to execute the tests, you need to set the Windows ExecutionPolicy to
# a less restrictive one:
# Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
#
# The tests are written using the Pester Powershell BDD framework. The Pester
# Powershell module can be downloaded from 
# https://github.com/pester/Pester/archive/master.zip
# When running the tests, the path for the unarchived Pester module should be
# given as a parameter. Example:
# ./run-tests.ps1 "C:\Pester-master"
# If the Pester module folder is already placed in one of the $env:PSModulePath
# folders, there is no need to provide the Pester module path.

param($PesterPath)
$ErrorActionPreference = "Stop"

function Log {
    param($message="")
    Write-Host $message
}

function TestIn-Path {
    param($path=".",
          $pesterFullPath=".\lib\Modules")

    $fullPath = Resolve-Path $path
    $initialPSModulePath = $env:PSModulePath
    $env:PSModulePath = $env:PSModulePath + ";$pesterFullPath"

    try {
        Log "Executing tests in the folder $fullPath"
        pushd $fullPath
        Invoke-Pester
    } catch {
        Log "Tests have failed."
        Log $_.Exception.ToString()
    } finally {
        popd
        $env:PSModulePath = $initialPSModulePath
    }
} 

$TestModule = "CharmHelpers"
$charmHelpersTestPath = ".\CharmHelpers\Tests"
$charmHelpersPath = ".\"
$charmHelpersFullPath = Resolve-Path $charmHelpersPath
$mainModuleTestPath = ".\Tests"

TestIn-Path $charmHelpersTestPath $PesterPath
