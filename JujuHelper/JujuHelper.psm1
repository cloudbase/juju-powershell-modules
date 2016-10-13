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

$version = $PSVersionTable.PSVersion.Major
if ($version -lt 4){
    # Get-CimInstance is not supported on powershell versions earlier then 4
    New-Alias -Name Get-ManagementObject -Value Get-WmiObject
}else{
    New-Alias -Name Get-ManagementObject -Value Get-CimInstance
}

function Invoke-JujuCommand {
    <#
    .SYNOPSIS
     Invoke-JujuCommand is a helper function that accepts a command as an array and returns the output of
     that command as a string. Any error returned by the command will make it throw an exception. This function
     should be used for launching native commands, not powershell commandlets (although that too is possible).
    .PARAMETER Command
     Array containing the command and its arguments
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Cmd")]
        [array]$Command
    )
    PROCESS {
        $cmdType = (Get-Command $Command[0]).CommandType
        if($cmdType -eq "Application") {
            # Some native applications write to stderr instead of stdout. If we redirect stderr
            # to stdout and have $ErrorActionPreference set to "stop", powershell will stop execution
            # even though no actual error has happened. Set ErrorActionPreference to SilentlyContinue
            # until after the native application finishes running. The $LASTEXITCODE variable will still
            # be set, and that is what we really care about here.
            $ErrorActionPreference = "SilentlyContinue"
            $ret = & $Command[0] $Command[1..$Command.Length] 2>&1
            $ErrorActionPreference = "Stop"
        } else {
            $ret = & $Command[0] $Command[1..$Command.Length]
        }

        if($cmdType -eq "Application" -and $LASTEXITCODE){
            Throw ("Failed to run: " + ($Command -Join " "))
        }
        if($ret -and $ret.Length -gt 0){
            return $ret
        }
        return $false
    }
}

function Test-FileIntegrity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [string]$File,
        [Parameter(Mandatory=$true)]
        [string]$ExpectedHash,
        [Parameter(Mandatory=$false)]
        [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160")]
        [string]$Algorithm="SHA1"
    )
    PROCESS {
        $hash = (Get-FileHash -Path $File -Algorithm $Algorithm).Hash
        if ($hash -ne $ExpectedHash) {
            throw ("File integrity check failed for {0}. Expected {1}, got {2}" -f @($File, $ExpectedHash, $hash))
        }
        return $true
    }
}

function Invoke-FastWebRequest {
    <#
    .SYNOPSIS
    Invoke-FastWebRequest downloads a file from the web via HTTP. This function will work on all modern windows versions,
    including Windows Server Nano. This function also allows file integrity checks using common hashing algorithms:

    "SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160"

    The hash of the file being downloaded should be specified in the Uri itself. See examples.
    .PARAMETER Uri
    The address from where to fetch the file
    .PARAMETER OutFile
    Destination file
    .PARAMETER SkipIntegrityCheck
    Skip file integrity check even if a valid hash is specified in the Uri.

    .EXAMPLE

    # Download file without file integrity check
    Invoke-FastWebRequest -Uri http://example.com/archive.zip -OutFile (Join-Path $env:TMP archive.zip)

    .EXAMPLE
    # Download file with file integrity check
    Invoke-FastWebRequest -Uri http://example.com/archive.zip#md5=43d89a2f6b8a8918ce3eb76227685276 `
                          -OutFile (Join-Path $env:TMP archive.zip)

    .EXAMPLE
    # Force skip file integrity check
    Invoke-FastWebRequest -Uri http://example.com/archive.zip#md5=43d89a2f6b8a8918ce3eb76227685276 `
                          -OutFile (Join-Path $env:TMP archive.zip) -SkipIntegrityCheck:$true
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
        [System.Uri]$Uri,
        [Parameter(Position=1)]
        [string]$OutFile,
        [switch]$SkipIntegrityCheck=$false
    )
    PROCESS
    {
        if(!([System.Management.Automation.PSTypeName]'System.Net.Http.HttpClient').Type)
        {
            $assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Net.Http")
        }

        if(!$OutFile) {
            $OutFile = $Uri.PathAndQuery.Substring($Uri.PathAndQuery.LastIndexOf("/") + 1)
            if(!$OutFile) {
                throw "The ""OutFile"" parameter needs to be specified"
            }
        }

        $fragment = $Uri.Fragment.Trim('#')
        if ($fragment) {
            $details = $fragment.Split("=")
            $algorithm = $details[0]
            $hash = $details[1]
        }

        if (!$SkipIntegrityCheck -and $fragment -and (Test-Path $OutFile)) {
            try {
                return (Test-FileIntegrity -File $OutFile -Algorithm $algorithm -ExpectedHash $hash)
            } catch {
                Remove-Item $OutFile
            }
        }

        $client = new-object System.Net.Http.HttpClient
        $task = $client.GetStreamAsync($Uri)
        $response = $task.Result
        if($task.IsFaulted) {
            $msg = "Request for URL '{0}' is faulted.`nTask status: {1}.`n" -f @($Uri, $task.Status)
            if($task.Exception) {
                $msg += "Exception details: {0}" -f @($task.Exception)
            }
            Throw $msg
        }
        $outStream = New-Object IO.FileStream $OutFile, Create, Write, None

        try {
            $totRead = 0
            $buffer = New-Object Byte[] 1MB
            while (($read = $response.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totRead += $read
                $outStream.Write($buffer, 0, $read);
            }
        }
        finally {
            $outStream.Close()
        }
        if(!$SkipIntegrityCheck -and $fragment) {
            Test-FileIntegrity -File $OutFile -Algorithm $algorithm -ExpectedHash $hash
        }
    }
}

function Get-RandomString {
    <#
    .SYNOPSIS
    Returns a random string of characters, with a minimum length of 6, suitable for passwords
    .PARAMETER Length
    length of the random string.
    .PARAMETER Weak
    Use a smaller set of characters
    #>
    [CmdletBinding()]
    Param(
        [int]$Length=16,
        [switch]$Weak=$false
    )
    PROCESS {
        if($Length -lt 6) {
            $Length = 6
        }
        if(!$Weak) {
            $characters = 33..122
        }else {
            $characters = (48..57) + (65..90) + (97..122)
        }

        $special = @(33, 35, 37, 38, 43, 45, 46)
        $numeric = 48..57
        $upper = 65..90
        $lower = 97..122

        $passwd = [System.Collections.Generic.List[object]](New-object "System.Collections.Generic.List[object]")
        for($i=0; $i -lt $Length; $i++){
            $c = get-random -input $characters
            $passwd.Add([char]$c)
        }

        $passwd.Add([char](get-random -input $numeric))
        $passwd.Add([char](get-random -input $special))
        $passwd.Add([char](get-random -input $upper))
        $passwd.Add([char](get-random -input $lower))

        $Random = New-Object Random
        return [string]::join("",($passwd|sort {$Random.Next()}))
    }
}

Export-ModuleMember -Function * -Alias *
