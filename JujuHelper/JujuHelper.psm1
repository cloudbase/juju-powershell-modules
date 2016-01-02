$ErrorActionPreference = "Stop"

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
        $ret = & $Command[0] $Command[1..$Command.Length] 2>&1

        if($cmdType -eq "Application" -and $LASTEXITCODE){
            Throw ("Failed to run: " + ($Command -Join " "))
        }
        if($ret -and $ret.Length -gt 0){
            return ($ret -as [string])
        }
        return $false
    }
}