# mms-OS
Some extension to basic windows commands

PS C:\> Get-Command -Module mms-os

    CommandType     Name                                               ModuleName
    -----------     ----                                               ----------
    Function        Get-FolderSize                                     mms-os
    Function        Get-RAFarm                                         mms-os
    Function        Get-ServiceStatus                                  mms-os
    Function        Get-Uptime                                         mms-os
    Function        Test-Ping                                          mms-os
    Function        Update-MMSmodules                                  mms-os
    

For more help about the functions, read the function's help


#Installation Instruction:

I personally like psget, which can install modules directly from the github:

    PS C:\> iex ((new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1")) #install psget
    PS C:\> Install-Module -ModuleUrl https://github.com/hpmmatuska/mms-WindowsOS/archive/master.zip #download mms-os module


or you can download the zip and unpack folder mms-os to your modules folder:

    1. download zip
    2. c:\> $env:PSModulePath # unzip somewhere to this path
    3. c:\> import-module mms-os

