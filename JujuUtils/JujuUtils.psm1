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

function ConvertFile-ToBase64{
    <#
    .SYNOPSIS
    This powershell commandlet converts an entire file, byte by byte to base64 and returns the string.

    WARNING: Do not use this to convert large files, as it reads the entire contents of a file
    into memory. This function may be useful to transfer small amounts of data over a relation
    without having to worry about encoding or escaping, preserving at the same time any
    binary info/special
    characters.
    .PARAMETER File
    The path to the file you want to convert. It works for any type of file. Take great care not to
    try and convert large files.
    #>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true)]
        [string]$File
    )
    PROCESS {
        if(!(Test-Path $File)) {
            Throw "No such file: $File"
        }
        $ct = [System.IO.File]::ReadAllBytes($File)
        $b64 = [Convert]::ToBase64String($ct)
        return $b64
    }
}

function WriteFile-FromBase64 {
    <#
    .SYNOPSIS
    Helper function that converts base64 to bytes and then writes that stream to a file.
    .PARAMETER File
    Destination file to write to.
    .PARAMETER Content
    Base64 encoded string
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$File,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $bytes = [Convert]::FromBase64String($Content)
        [System.IO.File]::WriteAllBytes($File, $bytes)
    }
}

function ConvertTo-Base64 {
    <#
    .SYNOPSIS
    Convert string to its base64 representation
    .PARAMETER Content
    String to be converted to base64
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $x = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Content))
        return $x
    }
}

function ConvertFrom-Base64 {
    <#
    .SYNOPSIS
    Convert base64 back to string
    .PARAMETER Content
    Base64 encoded string
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $x = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($content))
        return $x
    }
}

function Encrypt-String {
    <#
    .SYNOPSIS
    This is just a helper function that converts a plain string to a secure string and returns the encrypted
    string representation.
    .PARAMETER Content
    The string you want to encrypt
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $ret = ConvertTo-SecureString -AsPlainText -Force $Content | ConvertFrom-SecureString
        return $ret
    }
}

function Decrypt-String {
    <#
    .SYNOPSIS
    Decrypt a securestring back to its plain text representation.
    .PARAMETER Content
    The encrypted content to decrypt.
    .NOTES
    This function is only meant to be used with encrypted strings, not binary.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Content
    )
    PROCESS {
        $c = ConvertTo-SecureString $Content
        $dec = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($c)
        $ret = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($dec)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($dec)
        return $ret
    }
}

function Execute-Process ($DestinationFile, $Arguments) {
    if (($Arguments.Count -eq 0) -or ($Arguments -eq $null)) {
        $p = Start-Process -FilePath $DestinationFile `
                           -PassThru `
                           -Wait
    } else {
        $p = Start-Process -FilePath $DestinationFile `
                           -ArgumentList $Arguments `
                           -PassThru `
                           -Wait
    }

    return $p
}

function Get-UserPath () {
    return [System.Environment]::GetEnvironmentVariable("PATH", "User")
}

function Get-SystemPath {
    return [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
}

function Write-PrivateProfileString ($Section, $Key, $Value, $Path) {
    return [PSCloudbase.Win32IniApi]::WritePrivateProfileString(
                                            $Section, $Key, $Value, $Path)
}

function Get-LastError () {
    return [PSCloudbase.Win32IniApi]::GetLastError()
}


# TESTABLE METHODS

function Compare-Objects ($first, $last) {
    (Compare-Object $first $last -SyncWindow 0).Length -eq 0
}

function Compare-ScriptBlocks {
    Param(
        [System.Management.Automation.ScriptBlock]$scrBlock1,
        [System.Management.Automation.ScriptBlock]$scrBlock2
    )

    $sb1 = $scrBlock1.ToString()
    $sb2 = $scrBlock2.ToString()

    return ($sb1.CompareTo($sb2) -eq 0)
}

function Add-FakeObjProperty ([ref]$obj, $name, $value) {
    Add-Member -InputObject $obj.value -MemberType NoteProperty `
        -Name $name -Value $value
}

function Add-FakeObjProperties ([ref]$obj, $fakeProperties, $value) {
    foreach ($prop in $fakeProperties) {
        Add-Member -InputObject $obj.value -MemberType NoteProperty `
            -Name $prop -Value $value
    }
}

function Add-FakeObjMethod ([ref]$obj, $name) {
    Add-Member -InputObject $obj.value -MemberType ScriptMethod `
        -Name $name -Value { return 0 }
}

function Add-FakeObjMethods ([ref]$obj, $fakeMethods) {
    foreach ($method in $fakeMethods) {
        Add-Member -InputObject $obj.value -MemberType ScriptMethod `
            -Name $method -Value { return 0 }
    }
}

function Compare-Arrays ($arr1, $arr2) {
    return (((Compare-Object $arr1 $arr2).InputObject).Length -eq 0)
}

function Compare-HashTables ($tab1, $tab2) {
    if ($tab1.Count -ne $tab2.Count) {
        return $false
    }
    foreach ($i in $tab1.Keys) {
        if (($tab2.ContainsKey($i) -eq $false) -or ($tab1[$i] -ne $tab2[$i])) {
            return $false
        }
    }
    return $true
}

function MergeLeft-Array {
    param(
        [Parameter(Mandatory=$true)]
        [HashTable]$first,
        [Parameter(Mandatory=$true)]
        [HashTable]$second
        )

    foreach ($key in $second.Keys) {
        $first[$key] = $second[$key]
    }

    return $first
}

function Update-IniEntry {
    param(
        $Path,
        $Name,
        $Value)

    $content = Get-Content -Path $Path
    $regex = "{{[\s]{0,}" + $Name + "[\s]{0,}}}"
    $newContent = $content -Replace $regex,$Value
    Set-Content -Path $Path -Value $newContent
}

function Execute-ExternalCommand {
    param(
        [ScriptBlock]$Command,
        [array]$ArgumentList=@(),
        [string]$ErrorMessage
    )

    $res = Invoke-Command -ScriptBlock $Command -ArgumentList $ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw $ErrorMessage
    }
    return $res
}

function Write-HookTracebackToLog {
    Param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$LogLevel="ERROR"
    )
    $name = $MyInvocation.PSCommandPath
    Write-JujuLog "Error while running $name" -LogLevel $LogLevel
    $info = Get-CallStack $ErrorRecord
    foreach ($i in $info){
        Write-JujuLog $i -LogLevel $LogLevel
    }
}

function Get-CallStack {
    Param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $message = $ErrorRecord.Exception.Message
    $position = $ErrorRecord.InvocationInfo.PositionMessage
    $trace = $ErrorRecord.ScriptStackTrace
    $info = @($message, $position, $trace)
    return $info
}

function ExecuteWith-Retry {
    param(
        [ScriptBlock]$Command,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [array]$ArgumentList=@()
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $Command `
                     -ArgumentList $ArgumentList
            $ErrorActionPreference = $currentErrorActionPreference
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -gt $MaxRetryCount) {
                $ErrorActionPreference = $currentErrorActionPreference
                throw
            } else {
                Write-HookTracebackToLog $_ -LogLevel WARNING
                Start-Sleep $RetryInterval
            }
        }
    }
}

function Unzip-File ($zipFile, $destination) {
    $shellApp = New-Object -ComObject Shell.Application
    $zipFileNs = $shellApp.NameSpace($zipFile)
    $destinationNs = $shellApp.NameSpace($destination)
    $destinationNs.CopyHere($zipFileNs.Items(), 0x4)
}

function Check-FileIntegrityWithSHA1 {
    param(
        [Parameter(Mandatory=$true)]
        [string]$File,
        [Parameter(Mandatory=$true)]
        [string]$ExpectedSHA1Hash
    )

    $hash = (Get-FileHash -Path $File -Algorithm "SHA1").Hash
    if ($hash -ne $ExpectedSHA1Hash) {
        $errMsg = "SHA1 hash not valid for file: $filename. " +
                  "Expected: $ExpectedSHA1Hash Current: $hash"
        throw $errMsg
    }
}

function Get-DependenciesDownloadLinks {
    [Parameter(Mandatory=$true)]
    param ($DownloadLinks)

    return $DownloadLinks.Split(";")
}

# the download information for a file resource can be sent as
# description|http://example.com/download.exe#sha1-hash
function Get-DownloadLinkMetadata {
    [Parameter(Mandatory=$true)]
    param ($DownloadLink)

    $metadata = @{
        "description" = "";
        "uri" = "";
        "sha1" = "";
        "file" = "";
    }

    $descriptionParts = $DownloadLink.Split("|")
    if ($descriptionParts.Count -eq 2) {
        $metadata["description"] = $descriptionParts[0]
        $uriParts = $descriptionParts[1]
    } else {
        $uriParts = $DownloadLink
    }

    $hashParts = $uriParts.Split("#")
    if ($hashParts.Count -eq 2) {
        $metadata["sha1"] = $hashParts[1]
        $metadata["uri"] = $hashParts[0]
    } else {
        $metadata["uri"] = $uriParts
    }

    $metadata["file"] = Split-Path $metadata["uri"] -Leaf

    return $metadata
}

function Download-File ($DownloadLink, $DestinationFile, $ExpectedSHA1Hash) {
    $webClient = New-Object System.Net.WebClient

    if ($DestinationFile -eq $null) {
        $fileName = $DownloadLink.Split('/')[-1]
        $DestinationFile = "$env:TEMP\" + $filename
    }

    ExecuteWith-Retry -Command {
        # test if DownloadLink a samba share path or a local path
        if (Test-Path $DownloadLink) {
            Copy-Item -Path $DownloadLink -Destination $DestinationFile `
                -Force -Recurse
        } else {
                #It will overwrite any existent file
                $webClient.DownloadFile($DownloadLink, $DestinationFile)
        }
    } -MaxRetryCount 5 -RetryInterval 30

    if($ExpectedSHA1Hash) {
        Check-FileIntegrityWithSHA1 $DestinationFile $ExpectedSHA1Hash
    }

    $fileExists = Test-Path $DestinationFile
    if ($fileExists){
        return $DestinationFile
    } else {
        throw "Failed to download file."
    }
}

function Remove-DuplicatePaths ($Path) {
    $arrayPath = $Path.Split(';')
    $arrayPath = $arrayPath | Select-Object -Unique
    $newPath = $arrayPath -join ';'

    return $newPath
}

function AddTo-UserPath ($Path) {
    $newPath = Remove-DuplicatePaths "$env:Path;$Path"

    Execute-ExternalCommand -Command {
        setx PATH $newPath
    } -ErrorMessage "Failed to set user path"

    Renew-PSSessionPath
}

function Renew-PSSessionPath () {
    $userPath = Get-UserPath
    $systemPath = Get-SystemPath

    $newPath = $env:Path
    if (($userPath -ne $null) -and ($systemPath -ne $null)) {
        $newPath += ";$userPath;$systemPath"
    } else {
        if ($userPath -eq $null) {
            $newPath += ";$systemPath"
        } else {
            $newPath += ";$userPath"
        }
    }

    $env:Path = Remove-DuplicatePaths $newPath
}

function Marshall-Object {
    Param(
        $obj
    )

    $encoded = $obj | ConvertTo-Json
    $b64 = ConvertTo-Base64 $encoded
    return $b64
}

function Unmarshall-Object {
    Param(
        $obj
    )
    $decode = ConvertFrom-Base64 $obj
    $ret = $decode | ConvertFrom-Json
    return $ret
}

function Set-IniFileValue {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,
        [parameter()]
        [string]$Section = "DEFAULT",
        [parameter(Mandatory=$true)]
        [string]$Value,
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    process
    {
        $Source = @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;

        namespace PSCloudbase
        {
            public sealed class Win32IniApi
            {
                [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
                public static extern uint GetPrivateProfileString(
                   string lpAppName,
                   string lpKeyName,
                   string lpDefault,
                   StringBuilder lpReturnedString,
                   uint nSize,
                   string lpFileName);

                [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool WritePrivateProfileString(
                   string lpAppName,
                   string lpKeyName,
                   StringBuilder lpString, // Don't use string, as Powershell replaces $null with an empty string
                   string lpFileName);

                [DllImport("Kernel32.dll")]
                public static extern uint GetLastError();
            }
        }
"@
        Add-Type -TypeDefinition $Source -Language CSharp
        $retVal = Write-PrivateProfileString $Section $Key $Value $Path
        $lastError = Get-LastError
        if (!$retVal -and $lastError) {
            throw ("Cannot set value in ini file: " + $lastError)
        }
    }
}

function Get-CmdStringFromHashtable {
    param(
        [Parameter(Mandatory=$true)]
        [Hashtable]$params
    )

    $args = ""
    foreach($i in $params.GetEnumerator()) {
        $args += $i.key + "=" + $i.value + " "
    }

    return $args
}

function Escape-QuoteInString {
    param(
        [string]$value
    )
    return "'" + $value.Replace("'", "''") + "'"
}

function Get-PSStringParamsFromHashtable {
    param(
        [Parameter(Mandatory=$true)]
        [Hashtable]$params
    )

    $args = ""
    foreach($i in $params.GetEnumerator()) {
        $args += ("-" + $i.key + " " + $i.value + " ")
    }

    return $args -join " "
}

Export-ModuleMember -Function *
