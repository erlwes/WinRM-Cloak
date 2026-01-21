Param (    
    [Parameter(Mandatory = $true)]
    [int]$CloakPort,

    [Parameter(Mandatory = $true)]
    [int]$WinRMPort,

    [Parameter(Mandatory = $false)]
    [string]$TOTP, #If TOTP is from authenticator.

    [Parameter(Mandatory = $false)]
    [string]$TOTPSecretKey, #User to calulated TOTP live from seed key/secret key (testing). This key needs to be 16,32 or 64 characters long and consit of uppercase A-Z and digits 2-7 (Base32).

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
            Write-Log -Level 1 -Message "Test-TCPPort - '$Port' is open on computer '$Computer' (DE-CLOAKED)"
            $Script:Decloaked = $true
            
        } else {
            Write-Log -Level 0 -Message "Test-TCPPort - '$Port' is closed/filtered on computer '$Computer' (CLOAKED)"
            $Script:Decloaked = $false
        }
    } 
    catch {
        Write-Log -Level 3 -Message "Test-TCPPort - Unable to connet to '$Port' on computer '$Computer'. Error: $_"
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
    Write-Log -Level 1 -Message "Send-UDPPacket - Secret key sent to '$Computer' on UDP '$Port' ($Sent chars)"    
}
function Convert-Base32ToBytes {
    param ([string]$base32)
    $base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $bytes = @()
    $base32 = $base32.ToUpper().Replace("=", "")
    $bitBuffer = 0
    $bitBufferLength = 0

    foreach ($char in $base32.ToCharArray()) {
        $bitBuffer = ($bitBuffer -shl 5) -bor ($base32Alphabet.IndexOf($char))
        $bitBufferLength += 5

        while ($bitBufferLength -ge 8) {
            $bitBufferLength -= 8
            $bytes += [byte](($bitBuffer -shr $bitBufferLength) -band 0xFF)
        }
    }

    return ,$bytes
}
function Get-OTP {
    param (
        [string]$secret,
        [int]$digits = 6, # 12 digits is ~4h cracktime, but will be throttled by 4 sec each try by service
        [int]$interval = 30  # 30 sec
    )

    # Convert secret to byte array
    $keyBytes = Convert-Base32ToBytes -base32 $secret

    # Calculate current time step (in days)
    $unixTimestamp = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $timeStep = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder([int64]($unixTimestamp / $interval)))

    # Generate HMAC-SHA1 hash
    $hmac = New-Object System.Security.Cryptography.HMACSHA1
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($timeStep)

    # Use the last nibble to choose the offset
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $otpBinary =
        (($hash[$offset] -band 0x7F) -shl 24) -bor
        (($hash[$offset + 1] -band 0xFF) -shl 16) -bor
        (($hash[$offset + 2] -band 0xFF) -shl 8) -bor
        ($hash[$offset + 3] -band 0xFF)

    # Generate OTP based on specified digit length
    $otp = $otpBinary % [math]::Pow(10, $digits)
    return $otp.ToString().PadLeft($digits, '0')
}
#Endregion Functions

$ComputerSystem = Get-WmiObject Win32_ComputerSystem
if ($ComputerSystem.PartOfDomain -eq $false) {
    Write-Log -Level 2 -Message "Computer is not domain joined. Make sure configuration allows for WORKGROUP PSRemoting!"
    Write-Log -Level 2 -Message "To add, run: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$Computer' -Concatenate -Force"
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
}

if (!$Creds -and $ComputerSystem.PartOfDomain -eq $false) {
    Write-Log -Level 2 -Message "Credentials not supplied. This is mandatory in a workgroup environment (no SSO)"
    $Creds = (Get-Credential)
}

if ((Test-TCPPort -Computer $Computer -Port $WinRMPort) -eq $true) { }
else {
    if (!$TOTP) {
        $TOTP = (Read-Host -Prompt 'Please enter OTP to de-cloak target')
    }
    elseif ($TOTPSecretKey) {
        $TOTP = Get-OTP -secret $TOTPSecretKey
    }
    else {
        Write-Log -Level 2 -Message "Target cloaked, and no TOTP or secret key is provided. Not able to continue."
        Break
    }
    Send-UDPPacket -Port $CloakPort -Computer $Computer -Message $TOTP
    Write-Log -Level 2 -Message "Waiting 5 sec to allow target to start WinRM-service."
    Start-Sleep -Seconds 5
    Test-TCPPort -Computer $Computer -Port $WinRMPort    
}
$SessionOption = New-PSSessionOption -OperationTimeout 60000
if ($Script:Decloaked -eq $true) {
    if (!$PSSessionConfName) {      
        Write-Log -Level 0 -Message "Attempting to Enter-PSSession on '$Computer' as user '$($Creds.UserName)' using TCP '$WinRMPort'"        
        Enter-PSSession -Port $WinRMPort -ComputerName $Computer -Credential $Creds -SessionOption $SessionOption
    }
    else {
        Write-Log -Level 0 -Message "Attempting to Enter-PSSession on '$Computer' as user '$($Creds.UserName)' using TCP '$WinRMPort' and session config '$PSSessionConfName'"
        Enter-PSSession -Port $WinRMPort -ComputerName $Computer -Credential $Creds -ConfigurationName $PSSessionConfName -SessionOption $SessionOption
    }
}
else {
    Write-Log -Level 2 -Message "Unable to de-cloak. Will not attempt to PSRemote!"
}
