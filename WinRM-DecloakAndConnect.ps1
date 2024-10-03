Param (    
    [Parameter(Mandatory = $true)]
    [int]$CloakPort,

    [Parameter(Mandatory = $true)]
    [int]$WinRMPort,

    [Parameter(Mandatory = $true)]
    [string]$SecretString,

    [Parameter(Mandatory = $false)]
    [string]$Computer = 'localhost',

    [Parameter(Mandatory = $false)]
    [PSCredential]$Creds,

    [Parameter(Mandatory = $false)]
    [string]$PSSessionConfName
)

$Script:Decloaked = $false

#Region Functions
Function Write-Log {
    param(
        [ValidateSet(0, 1, 2, 3, 4)]
        [int]$Level,

        [Parameter(Mandatory=$true)]
        [string]$Message            
    )
    $Message = $Message.Replace("`r",'').Replace("`n",' ')
    switch ($Level) {
        0 { $Status = 'Info'    ;$FGColor = 'White'   }
        1 { $Status = 'Success' ;$FGColor = 'Green'   }
        2 { $Status = 'Warning' ;$FGColor = 'Yellow'  }
        3 { $Status = 'Error'   ;$FGColor = 'Red'     }
        4 { $Status = 'Console' ;$FGColor = 'Gray'    }
        Default { $Status = ''  ;$FGColor = 'Black'   }
    }
    
    Write-Host "$((Get-Date).ToString()) " -ForegroundColor 'DarkGray' -NoNewline
    Write-Host "$Status" -ForegroundColor $FGColor -NoNewline

    if ($level -eq 4) {
        Write-Host ("`t " + $Message) -ForegroundColor 'Cyan'
    }
    else {
        Write-Host ("`t " + $Message) -ForegroundColor 'White'
    }
    
    if ($Level -eq 3) {
        $LogErrors += $Message
    }
}
Function Test-TCPPort {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Computer,

        [Parameter(Mandatory = $true)]
        [int]$Port    
    )
    $tcpClient = New-Object System.Net.Sockets.TcpClient    
    try {
        $tcpClient.BeginConnect($Computer, $Port, $null, $null) | Out-Null
        $wait = $tcpClient.Client.Poll(2000000, [System.Net.Sockets.SelectMode]::SelectWrite)        
        if ($wait) {
            Write-Log -Level 1 -Message "Test-TCPPort - '$WinRMPort' is open on computer '$Computer' (DE-CLOAKED)"
            $Script:Decloaked = $true
            
        } else {
            Write-Log -Level 0 -Message "Test-TCPPort - '$WinRMPort' is closed/filtered on computer '$Computer' (CLOAKED)"
            $Script:Decloaked = $false
        }
    } 
    catch {
        Write-Log -Level 3 -Message "Test-TCPPort - Unable to connet to '$WinRMPort' on computer '$Computer'. Error: $_"
        $Script:Decloaked = $false     
    }
    finally {     
        $tcpClient.Connected   
        $tcpClient.Close()
    }
}
Function Send-UDPPacket {
    param([int]$Port,$Computer,[string]$Message)    

    $IP = ([System.Net.Dns]::GetHostAddresses($Computer) | Where-Object {$_.AddressFamily -eq 'InterNetwork'})[0]
    $Address = [system.net.IPAddress]::Parse($IP) 

    # Create IP Endpoint 
    $End = New-Object System.Net.IPEndPoint $address, $port 

    # Create Socket 
    $Saddrf   = [System.Net.Sockets.AddressFamily]::InterNetwork 
    $Stype    = [System.Net.Sockets.SocketType]::Dgram 
    $Ptype    = [System.Net.Sockets.ProtocolType]::UDP 
    $Sock     = New-Object System.Net.Sockets.Socket $saddrf, $stype, $ptype 
    $Sock.TTL = 26 

    # Connect to socket 
    $sock.Connect($end) 

    # Create encoded buffer 
    $Enc     = [System.Text.Encoding]::ASCII     
    $Buffer  = $Enc.GetBytes($Message) 

    # Send the buffer 
    $Sent   = $Sock.Send($Buffer)
    Write-Log -Level 1 -Message "Send-UDPPacket - Secret string sendt to '$Computer' on UDP '$Port' ($Sent chars)"    
}
#Endregion Functions

$ComputerSystem = Get-WmiObject Win32_ComputerSystem
if ($ComputerSystem.PartOfDomain -eq $false) {
    Write-Log -Level 2 -Message "Computer is not domain joined. Make sure configuration allows for WORKGROUP PSRemoting!"
    #Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
}

if (!$Creds -and $ComputerSystem.PartOfDomain -eq $false) {
    Write-Log -Level 2 -Message "Credentials not supplied. This is mandatory in a workgroup environment (no SSO)"
    $Creds = (Get-Credential)
}

if ((Test-TCPPort -Computer $Computer -Port $WinRMPort) -eq $true) { }
else {    
    Send-UDPPacket -Port $CloakPort -Computer $Computer -Message $SecretString
    Start-Sleep -Seconds 2
    Test-TCPPort -Computer $Computer -Port $WinRMPort    
}

if ($Script:Decloaked -eq $true) {
    if (!$PSSessionConfName) {      
        Write-Log -Level 0 -Message "Attempting to Enter-PSSession on '$Computer' as user '$($Creds.UserName)' using TCP '$WinRMPort'"
        Enter-PSSession -Port $WinRMPort -ComputerName $Computer -Credential $Creds
    }
    else {
        Write-Log -Level 0 -Message "Attempting to Enter-PSSession on '$Computer' as user '$($Creds.UserName)' using TCP '$WinRMPort' and session config '$PSSessionConfName'"
        Enter-PSSession -Port $WinRMPort -ComputerName $Computer -Credential $Creds -ConfigurationName $PSSessionConfName
    }
}
else {
    Write-Log -Level 2 -Message "Unable to de-cloak. Will not attempt to PSRemote!"
}
