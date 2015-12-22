function Write-JujuLog {
    <#
    .SYNOPSIS
     Write-JujuLog writes a line in the Juju log with the given log level
    .PARAMETER LogLevel
     LogLevel represents the logging level of the message
    .PARAMETER Message
     Message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
        [string]$LogLevel="INFO"
    )
    PROCESS {
        $cmd = @("juju-log.exe")
        if($LogLevel -eq "DEBUG") {
            $cmd += "--debug"
        }
        $cmd += $Message
        $cmd += @("-l", $LogLevel.ToUpper())
        $return = Invoke-JujuCommand -Command $cmd
    }
}

function Write-JujuDebug {
    <#
    .SYNOPSIS
     Helper function that writes a log message with DEBUG log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel DEBUG
    }
}

function Write-JujuTrace {
    <#
    .SYNOPSIS
     Helper function that writes a log message with TRACE log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel TRACE
    }
}

function Write-JujuInfo {
    <#
    .SYNOPSIS
     Helper function that writes a log message with INFO log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel INFO
    }
}

function Write-JujuWarning {
    <#
    .SYNOPSIS
     Helper function that writes a log message with WARNING log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel WARNING
    }
}

function Write-JujuCritical {
    <#
    .SYNOPSIS
     Helper function that writes a log message with CRITICAL log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Message -LogLevel CRITICAL
    }
}

function Write-JujuErr {
    <#
    .SYNOPSIS
     Helper function that writes a log message with ERROR log level.
    .PARAMETER Message
     The message that is to get written to the log
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    PROCESS {
        Write-JujuLog -Message $Msg -LogLevel ERROR
    }
}

function Write-JujuError {
    <#
    .SYNOPSIS
     Write an error level message to the juju log and optionally throw an exception using that same message.
    .PARAMETER Message
     Message to write to juju log
    .PARAMETER Fatal
     A boolean value that instructs the commandlet to throw an exception or not
    .NOTES
     Do not use this function. The recommended way of dealing with exceptions is to catch them in the hook itself.
     Write your charm modules to only throw exceptions on fatal errors. Use try{}catch{} in your hook to log the actual
     error.
    #>
    [Obsolete("This function is Obsolete. Please use Write-JujuErr")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Msg")]
        [string]$Message,
        [bool]$Fatal=$true
    )
    PROCESS {
        Write-JujuLog -Message $Msg -LogLevel ERROR
        if ($Fatal) {
            Throw $Msg
        }
    }
}