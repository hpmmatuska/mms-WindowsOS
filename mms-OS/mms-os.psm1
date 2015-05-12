Function Get-FolderSize {
    <#
    .Synopsis
    The function will return folder size and list of first level subfolders size.
    
    .Description
    The function is simmilar to reskit command "diruse" or unix tool "du". The output is sum value of file sizes 
    in specified folder and summary siza for each first level subfolder. The function is build up on top of 
    get-childitem function.

    .INPUTS
    -Path <[System.IO.FileInfo]string> -ShowIn [B,MB,GB]

    where paramter path:
        - is default parameter, not mandatory.
        - if present, function will run in the specified path (if exist)
        - when paramater is missing, current folder is set
        - an alias is "p"
    
    parameter ShowIn:
        B  - output of get-child item in bytes (as double)
        MB - output of get-child item in Mega Bytes (as double, rounded)
        GB - output of get-child item in Giga Bytes (as double, rounded)

    .OUTPUTS
    The default output is:
    [String]Path
    [Int]Size - when "ShowIn" param is missing, or
    [String]Size - formated Int output with expression "{0:N2}"
    
    .Example
    List of current folder size and subfolder sizes:

    PS C:\Temp> Get-FolderSize -ShowIn B

    Path                                                                   Size (B)
    ----                                                                   --------
    C:\Temp                                                                  935494
    C:\Temp\Microsoft Visual C++ 2010  x...                                       0
    C:\Temp\Microsoft Visual C++ 2010  x...                                       0
    C:\Temp\pulse                                                          20924852

    .Example
    List of current folder size and subfolder sizes formated in MB

    PS C:\Temp> mms-FolderSize -ShowIn MB |sort -Property size* -Descending

    Path                                                                  Size (MB)     
    ----                                                                    -------
    C:\Temp\pulse                                                             19,96  
    C:\Temp                                                                    0,89   
    C:\Temp\Microsoft Visual C++ 2010  x64 Redistributable Setup_10.0.40219     0,0   
    C:\Temp\Microsoft Visual C++ 2010  x86 Redistributable Setup_10.0.40219     0,0   

    .Example
    List of specified path subfolders size, formated in MB

    PS C:\> Get-FolderSize C:\RecoveryImage -ShowIn MB
    PS C:\> Get-FolderSize -p C:\RecoveryImage -ShowIn MB
    PS C:\> Get-FolderSize -path C:\RecoveryImage -ShowIn MB

    Path                            Size (MB)
    ----                            ---------
    C:\RecoveryImage                20 816,05 
    C:\RecoveryImage\Drivers           672,57   
    C:\RecoveryImage\OEMInformation      0,21     

    .Example
    The example of piped folder with manual expression and sorting

    PS C:\>$env:systemroot | Get-FolderSize | 
        sort size* -Descending |
        select -First 10|
        format-table Path, @{Name="Size (GB)";Expression={"{0:N2}" -f ($_.size / 1GB)}} -AutoSize

    Path                     Size (MB)
    ----                     ---------
    C:\WINDOWS\WinSxS        6,11     
    C:\WINDOWS\System32      3,52     
    C:\WINDOWS\SysWOW64      1,20     
    C:\WINDOWS\assembly      0,85     
    C:\WINDOWS\Microsoft.NET 0,67     
    C:\WINDOWS\Fonts         0,59     
    C:\WINDOWS\Globalization 0,20     
    C:\WINDOWS\IME           0,16     
    C:\WINDOWS\Panther       0,14     
    C:\WINDOWS\Speech        0,12     

    .Notes
    Last Updated: January 29, 2015
    Version     : 1.1

    .Link
    #>
 
    [cmdletbinding(DefaultParameterSetName = "Path")]
    Param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName, ParameterSetName="Path")]
        [Alias("p")]
        [String]$Path = $null,
        
        [parameter()]
        [ValidateSet('B','MB','GB')]
        [String]$ShowIn = 'MB'
    )

    if (!$path){$path = Get-Location}
    if (test-path $Path) {
        If ($ShowIn.ToUpper() -eq 'MB'){$divider = 1MB}
        elseIf ($ShowIn.ToUpper() -eq 'GB'){$divider = 1GB}
        else {$divider = 1}


        $size = [Math]::Round(((Get-ChildItem $path -ErrorAction SilentlyContinue | Measure-Object -Sum Length -ErrorAction SilentlyContinue).Sum / $divider),2)
        [PSCustomObject]@{
            Path = $Path
            "Size ($ShowIn)" = $size
        }
        
        get-childitem $path -ErrorAction SilentlyContinue | ?{$_.PSIsContainer} | %{
            $size = [Math]::Round(((Get-ChildItem $_ -ErrorAction SilentlyContinue | Measure-Object -Sum Length -ErrorAction SilentlyContinue).Sum / $divider),2)
            [PSCustomObject]@{
                Path = $_.fullName
                "Size ($ShowIn)" = $size
            } 
        }
    }  else {Write-Warning ('Path "'+$Path+'" Does not exist')} 

} #function get-foldersize 

Function Get-Uptime {
    <#
    .Synopsis
    Get computer uptime.
    .Description
    This command will query the Win32_OperatingSystem class using Get-CimInstance and write an uptime object to the pipeline.
    The function is calling workflow to parallely process all inputs to save some time.
    .Parameter Computername
    The name of the computer(s) to query. This parameter has an alias of CN. The Input can be piped.

    .Example
    PS C:\> get-myuptime pc1,pc2,pc3
 
    ComputerName LastBootUpTime      Days Hours Minutes Seconds TotalDays
    ------------ --------------      ---- ----- ------- ------- ---------
    PC1          11.12.2014 0:27:07    49     8      35      39 49,36    
    PC2          27.12.2014 17:58:36   32    15       4      10 32,63    
    PC3          Not Accessible                                          
 
    Formatted results for multiple computers. You can also pipe computer names into this command.

    .Notes
    Last Updated: May 06, 2015
    Version     : 1.1
  
    .Link
    #>
 
    [cmdletbinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [Alias("cn","name")]
        [String[]]$ComputerName,

        [System.Management.Automation.CredentialAttribute()]$credential

    )
    
    Workflow Get-HostUptime{ 
        Param(
            [String[]]$ComputerName, 
            [System.Management.Automation.CredentialAttribute()]$credential
        )
            Foreach -parallel ($computer in $computername){
                sequence{
                    #InlineScript {
                        Try {$wmi = gwmi Win32_OperatingSystem -PSComputerName $Computer -PSCredential $credential -ErrorAction Stop
                            $LBTime = [System.Management.ManagementDateTimeconverter]::ToDateTime($wmi.LastBootUpTime)
                            $uptime = [DateTime]::Now - $LBTime
                            $Obj = [PSCustomObject] @{
                                ComputerName = $Computer.ToUpper()
                                LastBootUpTime  = $LBTime
                                Days = $uptime.Days
                                Hours = $uptime.Hours
                                Minutes = $uptime.Minutes
                                Seconds = $uptime.Seconds
                                TotalDays = $uptime.totaldays
                            }
                        } #try
                        Catch {
                            $Obj = [PSCustomObject] @{
                                ComputerName = $Computer.ToUpper()
                                LastBootUpTime  = "Not Accessible"
                            }
                        } # catch
                        $Obj 
                    #} # InlineScript
                } # Sequence
            } # ForEach
    } #end workflow
    

    $CurrentPath = Get-Location # to achieve no problems when workflow is called from custom mapped PSDrive
    Set-Location $env:SystemRoot # cange location before workflow
    if ($Credential) {Get-HostUptime -ComputerName $ComputerName -Credential $credential | sort-object -Property LastBootUpTime -Descending | Select-Object ComputerName,LastBootUpTime,Days,Hours,Minutes,Seconds, @{Name="TotalDays";Expression={"{0:N2}" -f $_.TotalDays}} | ft -autosize }
    else {Get-HostUptime -ComputerName $ComputerName | sort-object -Property LastBootUpTime -Descending | Select-Object ComputerName,LastBootUpTime,Days,Hours,Minutes,Seconds, @{Name="TotalDays";Expression={"{0:N2}" -f $_.TotalDays}} | ft -autosize }
    Set-Location $CurrentPath #return location to original path


} #end function uptime

Function Test-Ping {
    <#
    .Synopsis
        Do a simple conncetion test (ping) to specified hosts.
    .Description
        The command will run "test-connection" again hosts defined in variable. If Single host is specified, 
        there will run continuos ping, otherwise one packet will be send to all hosts in paralel. The pipe input is supported.
    .Parameter ComputerName
        The destination name or IP addresses
        alias: name, cn
    .Parameter DelayInMilliseconds
        The delay between connection tests for single host. Default value is 1000.
        alias: d
    .Parameter BufferSize
        The size of the sent packet. Defualt size is 32b.
        alias: b
    .Parameter TimeToLive
        Specified maximum time to wait for answer. Default value is 80 ms.
        alias: ttl
    .Paramater ThrottleLimit
        The number of concurrent connection test. The default is 32 connections.
        alias: tl
    .Parameter Range
        Testing bundle of IPv4, where start address is the entered. The range param will increment start address by one.
        The input is expected only IPv4 address.
    .Switch ShowOnlyFailed
        When connection test runs again single IP, this option will display only missed answers.
    .Example
        PS C:\> test-ping server

        will perform connection test in a loop to entered name or IP
    .Example
        PS C:\> test-ping server, 10.1.1.1 -ThrottleLimit 8

        will perform single connection test to entered names or IPs in budle by 8 servers.
    .Example
        PS C:\> test-ping server -DelayInMillisecond 500 -BufferSize 16 -TimeToLive 40

        will perform endless connection test to entered names or IPs with specified parameters
    .Example
        PS C:\> test-ping 10.0.0.0 -Range 50

        will test 50 IP addresses for response, starting at 10.0.0.0 and ending with 10.0.0.50
    .Example
        PS C:\> test-ping server -DelayInMillisececonds 3000 -ShowOnlyFailed

        suitable for basic availability of the server with negative results only (of course with timestamp)
    .Notes
        Last Updated: May 06, 2015
        Version     : 1.1     
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [Alias("cn","name")][String[]]$ComputerName,
        [Alias("d")][int]$DelayInMilliseconds=1000,
        [Alias("b")][int]$BufferSize=32,
        [Alias("ttl")][int]$TimeToLive=80,
        [Alias("tl")][int]$ThrottleLimit=32,
        [int]$Range=0,
        [Switch]$ShowOnlyFailed
    )

    If ($ComputerName.Count -eq 1){
        if ($range -eq 0) {
            if (!$ShowOnlyFailed) {
                write-host ""
                write-warning "Endless ping is running, to break the cycle press CTRL+C"
                write-host ""
            }
            else {
            write-host ""
            write-warning "Endless ping is running with parameter to show only missed reply, to break the cycle press CTRL+C"
            write-host ""
            }
            do {
                try{
                    $ping = Test-Connection -Count 1 -BufferSize $BufferSize -TimeToLive $TimeToLive -ComputerName $ComputerName -ErrorAction stop
                        if(!$ShowOnlyFailed) {
                            write-host (`
                                (get-date).ToString() + `
                                "`tReply from: " + $ping.Address + `
                                " `t " + $ping.IPV4Address + `
                                " `t " + $ping.IPV6Address + `
                                " `tBuffer Size: " + $ping.ReplySize + `
                                " `tResponseTime (ms): " + $ping.ResponseTime)
                        }
                }
                catch {Write-Warning ((Get-Date).ToString()+"`t" + $_.Exception.Message)}
                Start-Sleep -m $DelayInMilliseconds
            } while ($true)
        } # if range = 0
        else {

          
            $pattern = "^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$" ##REGEX test for IP            if ($ComputerName -match $pattern){ #REGEX test for IP                $ipbase = ($computername.Split('.'))[0]+'.'+ ($computername.Split('.'))[1] +'.'+ ($computername.Split('.'))[2] + '.'
                ( ([int]($computername.Split('.')[3])) .. ([int](($computername.Split('.'))[3])+$range) ) | %{
                    if ($_ -le 255) {
                        $ping = Test-Connection -ComputerName ($ipbase + $_.ToString()) -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($ping -eq $true){write-host ($ipbase+ $_ + "`tresponding")}
                        else {write-warning ($ipbase + $_ + "`tnot responding")}
                    }
                    else {Write-Warning ($ipbase + $_ + "`tis not valid IP.")}
                }        
            } #REGEX test for IP            else {write-warning "$ip is not an valid IPv4 address. We are able to proceed only IPv4 with parameter 'Range'"}
        } # if range ne 0
    } # if one host
    else {
        if ($range -gt 0) {Write-Warning "for the more hosts is Range parameter ignored"}
        $job = Test-Connection -Count 1 -BufferSize $BufferSize -TimeToLive $TimeToLive -ThrottleLimit $ThrottleLimit -ComputerName $ComputerName -AsJob
        do {Start-Sleep -m 80} while ($job.JobStateInfo.State -eq "Running") 
        Receive-Job $job
    } # more hosts
} #end function ping

function Get-RAFarm {
    <#
    .Synopsis
    Get active remote connection thru RRAS and RDS Gateway for the specified servers.
    .Description
    This command will query the Win32_TSGatewayConnection class using RPC and root/Microsoft/Windows/RemoteAccess using WinRM 
    and write summary object to the pipeline.
    .Parameter Computername
    The name of the computer(s) to query. This parameter has an alias of CN. The Input can be piped.

    .Example
    PS C:\> Get-RemoteAccessFarmUsage server1,server2

    UserName                    Server   ConnectedFrom  RemoteAccessType ConnectedResource IdleTime ConnectionDuration RecievedKB SentKB
    --------                    ------   -------------  ---------------- ----------------- -------- ------------------ ---------- ------
    Domain\user1                server1  88.234.211.153 Vpn              10.10.91.194               04:12:14                 3110  20423
    Domain\user2                server2  120.210.33.201 RDP              10.10.90.121      00:00:00 03:37:20                 6162  16504
    Domain\user2                server2  120.210.33.201 Vpn              10.10.91.229               01:16:10                   88      5                     
 
    Formatted results for multiple computers. You can also pipe computer names into this command.

    .Notes
    Last Updated: February 05, 2015
    Version     : 1.1
    Changelog:
    v1.1  - Replaced [PSObject] with [PSCustomObject] to achieve $object column order
  
    .Link
    #>


    Param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [Alias("cn","name")]
        [String[]]$ComputerName 
    )

        Write-Verbose "Starting Script"
        foreach ($computer in $ComputerName){
            Try { #RDP
                Write-Verbose "Connecting over RPC to $computer"
                [object[]]$wmi_onPC = Get-WmiObject -class "Win32_TSGatewayConnection" -namespace "root\cimv2\TerminalServices" -ComputerName $computer 
            } # Try $wmi_OnPC RDP 
            Catch {write-warning "Cannot query RDP GW on the host: $computer"}
            if ($wmi_onPC){
                Write-Verbose "Building object from WMI received from $computer"
                foreach ($wmi in $wmi_onPC){
                    [PSCustomObject]@{
                        UserName = $wmi.UserName
                        Server = $wmi.PSComputerName
                        ConnectedFrom = $wmi.ClientAddress
                        RemoteAccessType = $wmi.ProtocolName
                        IdleTime = (New-TimeSpan -seconds ($wmi.IdleTime).Substring(0,14))
                        ConnectionDuration = (New-TimeSpan -seconds ($wmi.ConnectionDuration).Substring(0,14))
                        ConnectedResource = $wmi.ConnectedResource
                        RecievedKB = $wmi.NumberOfKilobytesReceived
                        SentKB = $wmi.NumberOfKilobytesSent
                    } #end $obj
                } # foreach $wmi
                Write-Verbose "Result builded from wmi from $computer"
            }#end IF $wmi for RDP
            else {Write-Verbose "There is no connected RDP GW client on $computer"}

            Try { #VPN
                Write-Verbose "Connecting over WMRemote to $computer"
                [object[]]$wmi_onPC = Get-RemoteAccessConnectionStatistics -ComputerName $computer
            } # Try $wmi_OnPC VPN 
            Catch {write-warning "Cannot query VPN on the host: $computer"}
            if (($wmi_onPC |measure).count -gt 0) {
                Write-Verbose "Building object from query results from $computer"
                foreach ($wmi in $wmi_onPC){
                    [PSCustomObject]@{
                        UserName = $wmi.UserName
                        Server = $computer
                        ConnectedFrom = $wmi.ClientExternalAddress
                        RemoteAccessType = $wmi.ConnectionType
                        IdleTime = ""#(New-TimeSpan -seconds ($wmi.IdleTime).Substring(0,14))
                        ConnectionDuration = (New-TimeSpan -seconds ($wmi.ConnectionDuration))
                        ConnectedResource = $wmi.ClientIPAddress
                        RecievedKB = ([Math]::Round($wmi.TotalBytesIn/1KB))
                        SentKB = ([Math]::Round($wmi.TotalBytesOut/1KB))
                    } #end $obj
                } # foreach $wmi
                Write-Verbose "Result builded from query from $computer"
            }# else IF $wmi count >1
            else {Write-Verbose "There is no connected VPN client on $computer"}
        }#foreach $computer
        Write-Verbose "Function ends."
} #end function RAFarm

function Get-ServiceStatus {

    <#
    .Synopsis
        List services, their startup type and current status.
    .Description
        This command will query the Win32_Service class using Get-WmiObject and return list of services.
    .Parameter 
        Computername - The name of the computer to query. This parameter has an alias of CN. The Input can be piped.
        Service      - query for service name, supports wildcards
        StartMode    - filter for service startup type
        State        - filter for service current state
        Do           - perform action for qeury results
        Credential   - define run as account
    .Input
        [String]        <Computername> #suport pipe
        [String[]]      <Service>      #support wildcard and hash table
        [String]        <StartMode>    #validation set: 'Auto','Manual','Disabled','*' 
        [String]        <State>        #validation set: 'NotRunning', 'Running', 'Stopped', 
                                                        'Other', '*', 'Paused', 'Stopping', 
                                                        'Starting', 'Resuming', 'Pausing'
        [string]        <do>           #validation set: 'Start','Stop','Restart'
        [PSCredentials] <Credential>   #hash: [string]name, [SecureString]password

    .Example
        List of all not running automatic services on remote machine

    
        PS C:\>Get-ServiceStatus -ComputerName Server1

        ExitCode Name             ProcessId StartMode State   Status
        -------- ----             --------- --------- -----   ------
               0 ShellHWDetection         0 Auto      Stopped OK    
               0 sppsvc                   0 Auto      Stopped OK    
               0 wuauserv                 0 Auto      Stopped OK    

    .Example
        List of not running windows update server service on untrusted machine

    
        PS C:\>Get-ServiceStatus -ComputerName Server1 -Service wuau* -StartMode Auto -State * -Credentials (get-credential)

        ExitCode Name             ProcessId StartMode State   Status
        -------- ----             --------- --------- -----   ------
               0 wuauserv                 0 Auto      Stopped OK    

    .Example
        Try to start all not runing automatic services

    
        PS C:\>Get-ServiceStatus -Do Start

 
    .Notes
    Last Updated: May 07, 2015
    Version     : 1.1
  
    .Link
    #>


    [cmdletbinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [Alias("cn","name")]
        [String]$ComputerName = $env:COMPUTERNAME,

        [System.Management.Automation.CredentialAttribute()]$credential,

        [parameter()]
        [String[]]$Service = '*',

        [parameter()]
        [ValidateSet('Auto','Manual','Disabled','*')]
        [String]$StartMode,

        [parameter()]
        [ValidateSet('NotRunning', 'Running', 'Stopped', 'Other', '*', 'Paused', 'Stopping', 'Starting', 'Resuming', 'Pausing')]
        [String]$State,

        [parameter()]
        [ValidateSet('Start','Stop','Restart')]
        [String]$do
    )

    function query-service {
        try{
            if ($credential) {
                if ($State -eq 'NotRunning') {Get-WmiObject Win32_Service -ComputerName $ComputerName -Credential $credential -ErrorAction stop| ? { $_.Name -like $Service -and $_.StartMode -like $StartMode -and $_.State -ne 'Running' }}
                else {Get-WmiObject Win32_Service -ComputerName $ComputerName -Credential $credential -ErrorAction stop| ? { $_.Name -like $Service -and $_.StartMode -like $StartMode -and $_.State -like $State }}
            }
            else {
                if ($State -eq 'NotRunning') {Get-WmiObject Win32_Service -ComputerName $ComputerName -ErrorAction stop| ? { $_.Name -like $Service -and $_.StartMode -like $StartMode -and $_.State -ne 'Running' }}
                else {Get-WmiObject Win32_Service -ComputerName $ComputerName -ErrorAction stop| ? { $_.Name -like $Service -and $_.StartMode -like $StartMode -and $_.State -like $State }}
            } 
        }#end try
        catch {Write-Warning $_.exception.Message}
    } #end query service function


    if ($Service -eq '*') {
        if (!$StartMode) {$StartMode = 'Auto'}
        if (!$State) {$state = 'NotRunning'}
    } else {
        if (!$StartMode) {$StartMode = '*'}
        if (!$State) {$state = '*'}
    }


    switch ($do) {
        start {query-service | Get-Service -ComputerName $ComputerName| Start-Service}
        stop {query-service | Get-Service -ComputerName $ComputerName| Stop-Service}
        restart {query-service | Get-Service -ComputerName $ComputerName| Restart-Service}
        default {query-service | ft -AutoSize}
    }
    

} # end Function ServiceStatus
