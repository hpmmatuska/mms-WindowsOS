# mms-OS
Some extension to basic windows commands

[ADMIN] PS4 Desktop:\> Get-Command -Module mms-os

CommandType     Name                                               ModuleName                                                -----------     ----                                               ----------                                                Function        Get-FolderSize                                     mms-os                                                    Function        Get-RAFarm                                         mms-os                                                    Function        Get-Uptime                                         mms-os                                                    Function        Test-Ping                                          mms-os                                                                                

#Installation Instruction:

I personally like psget, which can install modules directly from the github:

PS C:\> install psget: iex ((new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1"))
PS C:\> Install mms-WindowsOS: Install-Module -ModuleUrl https://github.com/hpmmatuska/mms-WindowsOS/archive/master.zip

or you can download the zip and unpack folder mms-os to your modules folder:

    1. download zip
    2. c:\> $env:PSModulePath # unzip somewhere to this path
    3. c:\> import-module mms-os


#Get-FolderSize

Utility simmilar to reskit tool diruse. Here is short example:

PS C:\> Get-FolderSize -path C:\RecoveryImage -ShowIn MB

    Path                            Size (MB)
    ----                            ---------
    C:\RecoveryImage                20 816,05 
    C:\RecoveryImage\Drivers        672,57   
    C:\RecoveryImage\OEMInformation 0,21     

    
#Get-RAFarm

will query the WMI for active connection on terminal gateway or RRAS server. Short Example:

PS C:\> Get-RemoteAccessFarmUsage server1,server2

    UserName                    Server   ConnectedFrom  RemoteAccessType ConnectedResource IdleTime ConnectionDuration RecievedKB SentKB
    --------                    ------   -------------  ---------------- ----------------- -------- ------------------ ---------- ------
    Domain\user1                server1  88.234.211.153 Vpn              10.10.91.194               04:12:14                 3110  20423
    Domain\user2                server2  120.210.33.201 RDP              10.10.90.121      00:00:00 03:37:20                 6162  16504
    Domain\user2                server2  120.210.33.201 Vpn              10.10.91.229               01:16:10                   88      5                     
 
# Get-Uptime

Nothing to add. It's do a query to bundle of computers to WMI and it's try to get uptime. Works parallel for input array.

  PS C:\> get-myuptime pc1,pc2,pc3
 
    ComputerName LastBootUpTime      Days Hours Minutes Seconds TotalDays
    ------------ --------------      ---- ----- ------- ------- ---------
    PC1          11.12.2014 0:27:07    49     8      35      39 49,36    
    PC2          27.12.2014 17:58:36   32    15       4      10 32,63    
    PC3          Not Accessible                                          
 
 
#Test-Ping

Uses the test-connection module. When single host is defined, it's do an endless ping; otherwise it's run test-connection as job. 
To the normal ping is added timestamp as well - with combination -ShowOnlyFailed I am using that for NW quality troubleshooting. 
The last option is to test a range of IP - usefull when you are looking a free IP on your NW (of course you have not to block echo on firewall).

