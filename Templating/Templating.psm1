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