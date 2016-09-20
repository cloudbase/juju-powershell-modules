[![Build status](https://ci.appveyor.com/api/projects/status/y0x1gm2n7y6ti2a9/branch/experimental?svg=true)](https://ci.appveyor.com/project/gabriel-samfira/juju-powershell-modules/branch/experimental)

#Juju PowerShell Modules


This repository contains common used logic for Windows Juju charms

## How to run tests

You will need pester on your system. It should already be installed on your system if you are running Windows 10. If it is not:

```powershell
Install-Package Pester
```

Running the actual tests (they must be run with administrative privileges):

```powershell
powershell.exe -NonInteractive {Invoke-Pester}
```

This will run all tests without polluting your current shell environment. The -NonInteractive flag will make sure that any test that checks for mandatory parameters will not block the tests if run in an interactive session. This is not needed if you run this in a CI.
