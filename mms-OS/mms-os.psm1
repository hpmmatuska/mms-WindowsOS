Function Get-FolderSize {
    <#
    .Synopsis
    The function will return folder size and list of first level subfolders with their size.
    
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
    [Int]Size - formated with function round to 2 decimal places
    [Int]Count - recursion for all subfolders
    [Int]Avg
    [Int]Min
    [Int]Max
    [Str]Unit

    
    .Example
    List of current folder size and subfolder sizes:

    PS C:\temp> Get-FolderSize -ShowIn B

    Path              Size Unit
    ----              ---- ----
    C:\temp              0 B   
    C:\temp\pulse 21726117 B

    .Example
    List of current folder size and subfolder sizes formated in MB

    PS C:\Program Files (x86)> Get-FolderSize -ShowIn MB | sort -Property Size -Descending |select -First 5

    Path                                                 Size Unit
    ----                                                 ---- ----
    C:\Program Files (x86)\Google                      698,19 MB  
    C:\Program Files (x86)\Common Files                310,61 MB  
    C:\Program Files (x86)\Adobe                       172,27 MB  
    C:\Program Files (x86)\Devolutions                  135,2 MB  
    C:\Program Files (x86)\Microsoft Analysis Services  98,15 MB  

    .Example
    List of specified path subfolders size, formated in MB with advanced view

    PS C:\> Get-FolderSize C:\RecoveryImage -ShowIn MB | ft * -AutoSize

    Path                            Count     Avg Min     Max    Size Unit
    ----                            -----     --- ---     ---    ---- ----
    C:\RecoveryImage                    2 1222,28   0 2444,56 2444,56 MB  
    C:\RecoveryImage\Drivers         1354    0,64   0   24,78  860,86 MB  
    C:\RecoveryImage\OEMInformation    11    0,02   0    0,17    0,21 MB  

    .Example
    The example of piped folder with manual expression and sorting

    PS C:\> $env:SystemRoot | Get-FolderSize | sort -Property Size -Descending |select -First 5 | ft * -AutoSize

    Path                Count   Avg Min    Max    Size Unit
    ----                -----   --- ---    ---    ---- ----
    C:\WINDOWS\WinSxS   60148  0,12   0 110,67 7071,48 MB  
    C:\WINDOWS\System32 18122  0,28   0 126,35 5064,22 MB  
    C:\WINDOWS\SysWOW64  5569  0,23   0  44,07 1294,78 MB  
    C:\WINDOWS\assembly  1008     1   0  31,16 1007,53 MB  
    C:\WINDOWS             38 22,06   0 827,95  838,17 MB  

    .Notes
    Last Updated: August 26, 2015
    Version     : 1.2

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

        ##Set up the default display set and create the member set object for use later on
        #Configure a default display set
        $defaultDisplaySet = 'Path','Size','Unit'

        #Create the default property display set
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultDisplaySet)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)


        $size = Get-ChildItem $path -ErrorAction SilentlyContinue |  Measure-Object -Sum Length -Average -Maximum -Minimum -ErrorAction SilentlyContinue
        $object = [PSCustomObject]@{
            "Path" = $Path
            "Count" = $size.Count
            "Avg" = [Math]::Round($size.Average/$divider,2)
            "Min" = [Math]::Round($size.Minimum/$divider,2)
            "Max" = [Math]::Round($size.Maximum/$divider,2)
            "Size" = [Math]::Round($size.sum/$divider,2)  
            "Unit" = $ShowIn
        }
        #Give this object a unique typename
        $object.PSObject.TypeNames.Insert(0,'Folder.Measure')
        $object | Add-Member MemberSet PSStandardMembers $PSStandardMembers
        #Show object that shows only what I specified by default
        $object
        
        get-childitem $path -ErrorAction SilentlyContinue | ?{$_.PSIsContainer} | %{
            $size = Get-ChildItem $_.FullName -Filter * -Recurse -ErrorAction SilentlyContinue |  Measure-Object -Sum Length -Average -Maximum -Minimum -ErrorAction SilentlyContinue
            $object = [PSCustomObject]@{
                "Path" = $_.FullName
                "Count" = $size.Count
                "Avg" = [Math]::Round($size.Average/$divider,2)
                "Min" = [Math]::Round($size.Minimum/$divider,2)
                "Max" = [Math]::Round($size.Maximum/$divider,2)
                "Size" = [Math]::Round($size.sum/$divider,2)  
                "Unit" = $ShowIn
            } 
            $object.PSObject.TypeNames.Insert(0,'Folder.Measure')
            $object | Add-Member MemberSet PSStandardMembers $PSStandardMembers
            #Show object that shows only what I specified by default
            $object
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

          
            $pattern = "^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$" ##REGEX test for IP
            if ($ComputerName -match $pattern){ #REGEX test for IP
                $ipbase = ($computername.Split('.'))[0]+'.'+ ($computername.Split('.'))[1] +'.'+ ($computername.Split('.'))[2] + '.'
                ( ([int]($computername.Split('.')[3])) .. ([int](($computername.Split('.'))[3])+$range) ) | %{
                    if ($_ -le 255) {
                        $ping = Test-Connection -ComputerName ($ipbase + $_.ToString()) -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($ping -eq $true){write-host ($ipbase+ $_ + "`tresponding")}
                        else {write-warning ($ipbase + $_ + "`tnot responding")}
                    }
                    else {Write-Warning ($ipbase + $_ + "`tis not valid IP.")}
                }        
            } #REGEX test for IP
            else {write-warning "$ip is not an valid IPv4 address. We are able to proceed only IPv4 with parameter 'Range'"}
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

Function Update-MMSmodules {
    $AvailableModules = get-module -listavailable
    if ( $AvailableModules.Name -notcontains 'PsGet') {(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex}
    if ( $AvailableModules.Name -notcontains 'mms-os') {Install-Module -ModuleUrl https://github.com/hpmmatuska/mms-WindowsOS/archive/master.zip} 
    else {Install-Module -ModuleUrl https://github.com/hpmmatuska/mms-WindowsOS/archive/master.zip -Update}
} # End of module update

Function Test-Port {

    <#
    .Synopsis
        Do a test for open ports against remote machine
    .Description
        Will create sample connection to remote machine on specified port (as classic telnet client)
    .Parameter Computername
        The name of the computer to query. The Input can be piped, it is default 1st parameter
    .Parameter Port
        The range of ports to query. It is default 2nd parameter
    .Parameter TCPTimeout
        Timeout for test connection. Default Value is 100 miliseconds
    .Parameter Async
        Default is synchron test for input port range. When you specify more than 400 ports, the Async parameter is
        set automatically.
    .Example
        PS C:\> test-port pc01 80
 
        Computername Port IsOpen Notes                              
        ------------ ---- ------ -----                              
        pc01         80  False Timeout occurred connecting to port
 
    
        Test PC01 if listen on port 80.

    .Example
        PS C:\> test-port pc01 | ?{$_.IsOpen}
 
        Computername Port IsOpen Notes                              
        ------------ ---- ------ -----                              
        pc01         135   True 
        pc01         139   True 
        pc01         445   True 
        pc01         5555  True 
 
    
        Test PC01 for all open ports.

    .Notes
        Last Updated: May 19, 2015
        Version     : 1.0
  
    .Link
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [Alias("cn","name")][String]$ComputerName,
        [Parameter(Position=1)]
        [int[]]$Port = (1..65535),
        [int]$TCPTimeout = 100, #in miliseconds
        [switch]$Async = $false
    )

    Begin {
        if ($port.count > 400){$async = $true}
        Function Test-PortSynchronly {Param($ComputerName, $Port)
                    $TCPClient  = New-Object  -TypeName   System.Net.Sockets.TCPClient
                    $AsyncResult  = $TCPClient.BeginConnect($Computername,$Port,$null,$null)
                    $Wait = $AsyncResult.AsyncWaitHandle.WaitOne($TCPtimeout) 
                    If ($Wait) {
                        Try {$Null  = $TCPClient.EndConnect($AsyncResult)} 
                        Catch {$Issue  = $_.Exception.Message} 
                        Finally {
                            [pscustomobject]@{
                                Computername = $Computername
                                Port =  $Item
                                IsOpen =  $TCPClient.Connected
                                Notes =  $Issue
                            }
                        }
                    } Else {
                        [pscustomobject]@{
                            Computername = $Computername
                            Port =  $Item
                            IsOpen =  $TCPClient.Connected
                            Notes =  'Timeout occurred connecting to port'
                        }    
                    }    
        }
        Workflow Test-PortAsynchronly {Param($ComputerName, [int[]]$Port)
                ForEach -parallel ($Item  in $Port)  {
                    InlineScript {
                        $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
                        $Task = $TCPClient.ConnectAsync($Using:Computername,$Using:Item)
                        Start-Sleep -Milliseconds $TCPTimeout
                        # while ($task.IsCompleted){Start-Sleep -Milliseconds 100}
                        [pscustomobject]@{
                            Computername = $Using:Computername
                            Port =  $using:Item
                            IsOpen =  $TCPClient.Connected #not working properly
                            #IsOpen = !$task.IsFaulted  #not working properly
                            Notes =  $Task.Exception.InnerException
                        }
                        $Issue = $Null
                        if ($task.IsCompleted -or $Task.IsCanceled -or $Task.IsFaulted) {$TCPClient.Dispose()}
                    }
                } # foreach port
        }
    }
    Process {
        Try {$null = test-connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue; $ping=$null}
        Catch {$ping = $_.Exception.Message}
        if (!$ping) {
            if (!$async) {        
                ForEach ($Item  in $Port)  {
                    #write-progress
                    Test-PortSynchronly -Computername $ComputerName -port $Item    
                } # foreach port
            } #sync test
            else {
                $CurrentPath = Get-Location # to achieve no problems when workflow is called from custom mapped PSDrive
                Set-Location $env:SystemRoot # cange location before workflow    
                Test-PortAsynchronly -ComputerName $ComputerName -Port $Port |
                    sort -Property Port |
                    ft ComputerName, Port, IsOpen, Notes -AutoSize 
                Set-Location $CurrentPath #return location to original path   
            } # async test
        } # if ping OK
        else {
            [pscustomobject]@{
                Computername = $Computername
                Port =  '*'
                IsOpen =  $TCPClient.Connected
                Notes =  $ping
            }    
        } # if no ping
    }
    End {}
} # End function test-port

function Get-AvailableUpdates { # functional for windows server 2016
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]] $Servers,
        [PSCredential] $Credential,
        [Switch] $Install,
        [Switch] $Restart
    )
    $servers | foreach-object {
        $session = New-CimSession `
            -ComputerName $_ `
            -Credential $credential
        $instance =  New-CimInstance `
            -Namespace root/Microsoft/Windows/WindowsUpdate `
            -ClassName MSFT_WUOperationsSession `
            -CimSession $session
        # Due to a bug in CIM on Nano Server (TP4 and TP5) an error is returned when
        # there are no available updates.
        # We use ErrorAction SilentlyContinue to ignore this (DON'T do this in a production script!!!!)
        $scanResults = @($Instance | Invoke-CimMethod `
            -MethodName ScanForUpdates `
            -Arguments @{SearchCriteria="IsInstalled=0";OnlineScan=$true} `
            -CimSession $session `
            -errorAction SilentlyContinue)
        if ($scanResults)
        {
            "$_ has $($scanResults.Count) updates to be installed:"
            if ($install)
            {
                $installResult = $Instance | Invoke-CimMethod `
                    -MethodName ApplyApplicableUpdates `
                    -CimSession $Session
                if ($installResult.ReturnValue -eq 0)
                {
                    'Updates were installed successfully:'
                    $scanResults.Updates
                    if ($Restart)
                    {
                        "Restarting $_"
                        Invoke-Command `
                            -ComputerName $_ `
                            -Credential $credential `
                            -ScriptBlock { Restart-Computer }
                    }
                    else
                    {
                        'You may need to reboot this server for update installation to complete.'
                    }
                }
                else
                {
                    'An error occurred installing updates:'
                    $installResult
                }
            }
            else
            {
                'Set -Install flag to install updates'
                $scanResults.Updates
            } # if
        }
        else
        {
            "$_ has no updates to be installed."
        } # if
        Remove-CimSession `
            -CimSession $session
    } # foreach-object
} # function Get-AvailableUpdates