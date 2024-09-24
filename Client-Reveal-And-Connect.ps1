# UDP CLIENT

#If Workgroup:
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord

Function Send-UDPPacket {
    param([int]$port,[system.net.IPAddress]$ip,[string]$Message)    
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
    Write-Host "$Sent characters sent to: $IP ($Message)"        
}


# After open, connect:
# $cred = (Get-Credential WinDev2407Eval\user)
# Enter-PSSession -ComputerName WinDev2407Eval -Port 30952 -ConfigurationName MyCustomSessionConf -Credential $cred
