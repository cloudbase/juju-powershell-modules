Param(
    [string]$docroot=$PWD.Path
)

$current = $PWD.Path
$ErrorActionPreference = "Stop"

function Start-Server {
	$job = Start-Job -InitializationScript $functions -ScriptBlock {
		$ErrorActionPreference = "Stop"
		function Start-WebServer {
			Param(
			 [string]$dir=$PWD.Path
			)
			#Throw $dir
			cd $dir
			Write-Host $dir
			#Write-Host "Starting web server"
			$Hso = New-Object Net.HttpListener
			$Hso.Prefixes.Add("http://127.0.0.1:8000/")
			$Hso.Start()
			while ($Hso.IsListening) {
				$HC = $Hso.GetContext()
				$HRes = $HC.Response
				$p = Join-Path $dir ($HC.Request).RawUrl
				$fileinfo = New-Object System.IO.FileInfo($p)
				if(!$fileinfo.Exists) {
					$HRes.Headers.Add("Status-Code", 404)
					$Buf = [Text.Encoding]::UTF8.GetBytes("File not found: $p")
					$HRes.ContentLength64 = $Buf.Length
					$HRes.OutputStream.Write($Buf,0,$Buf.Length)
					$HRes.Close()
					continue
				}
				switch($fileinfo.Extension) {
					".css" {
						   $HRes.Headers.Add("Content-Type","text/css")
					}
					".js" { $HRes.Headers.Add("Content-Type","application/javascript")}
					".html" { $HRes.Headers.Add("Content-Type","text/html") }
					"default" { $HRes.Headers.Add("Content-Type","text/plain") }
				}
				$Buf = [System.IO.File]::ReadAllBytes($p)
				$HRes.ContentLength64 = $Buf.Length
				$HRes.OutputStream.Write($Buf,0,$Buf.Length)
				$HRes.Close()
			}
			$Hso.Stop()
		}
		Start-WebServer -Dir $args[0]
	} -ArgumentList @($docroot)
	start http://127.0.0.1:8000/JujuHooks.html
	while($true) {
		if ([console]::KeyAvailable) {
			$key = [system.console]::readkey($true)
			if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")){
				"Terminating...This might take a while. Patience yound grasshopper."
				$job.StopJob())
				return
			}
		}else{
			Start-Sleep 1
		}
	}
}

[console]::TreatControlCAsInput = $true
Start-Server