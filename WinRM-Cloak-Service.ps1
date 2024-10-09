# ---To-do---
#   1. HANDLE CRASH, SERVICE STOP AND OS SHUTDOWNS
#       - Seems possible by using the .ini file, we can run this script with a shutdown-parameter on system halt, serviuce stop, crash etc.
#       - This is important, so that the service failure will ensure that WinRM and firewall is not left running etc
#       - The listener will however close when the process dies, so that part is good. $udpclient.Close() is not nessasary

# ---Ideas---
#   1. Mutating portnumbers?
#       - Lets say this was implemented for RDP and exposed to the internet. Shodan and other scanners would map open ports while service is de-cloaked.
#       If the portnumber was changing, this would be confusing, and the info from scanners would not be invalid.
#       One example of doing this would be using port (3000 + weeknumber). This would be know to both client and server, and the port would be predictable.
#       This would require seting the WinRM-listener port within the service, and updating it when needed. Would require som extra CPU-cycles per loop to check if weeknumber or any other known shared value has changed.

Param(
    [int]$Port,
    [string]$TOTPSecretKey, #Should ofc not have a default value, but for now...
    [string]$WinRMListenerTransport = 'HTTP',
    [int]$ServiceRunningTime = 600,
    [bool]$Debug = $false
)

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
function Get-TOTP {
    param (
        [string]$secret,
        [int]$digits = 6, # 12 digits is ~4h cracktime, but will be throttled by 4 sec each try inside loop.
        [int]$interval = 30  # 24 hours in seconds. Dont want service to re-calculate the current code per loop-cycle
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

Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 100 -Message "Service starting" -EntryType Information

if ($Debug) {
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: Port = $Port" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: TOTPSecretKey = $TOTPSecretKey" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: WinRMListenerTransport = $WinRMListenerTransport" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: ServiceRunningTime = $ServiceRunningTime" -EntryType Information
}

#Disable Firewall-rule for WinRM
$FirewallRule = "WinRM - $WinRMListenerTransport custom port"
try {
    Set-NetFirewallRule -DisplayName $FirewallRule -Enabled 2 -ErrorAction Stop
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 302 -Message "Firewall: Rule '$FirewallRule' disabled" -EntryType Information
    try{
        Stop-Service WinRM -ErrorAction Stop
        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 402 -Message "WinRM-service: Stopped" -EntryType Information
    }
    catch {
        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 404 -Message "WinRM-service: Failed to stop: $($_.Exception.Message)" -EntryType Error
    }
}
catch {
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 302 -Message "Firewall: Failed to disable rule '$FirewallRule': $($_.Exception.Message)" -EntryType Error
}

$endpoint  = new-object System.Net.IPEndPoint( [IPAddress]::Any, $Port)
$udpclient = new-object System.Net.Sockets.UdpClient $Port
$udpclient.Client.SendBufferSize = 0
$udpclient.Client.ReceiveBufferSize = 1

[System.Threading.Thread]::Sleep(5000)

while ($true) {

    # Sleep is for both performance and brute force throttling
    [System.Threading.Thread]::Sleep(4000)

    if ($udpclient.Available) {
        $content = $udpclient.Receive([ref]$endpoint)
        if ($content) {

            $TOTP = Get-TOTP -Secret $TOTPSecretKey
            $String = [Text.Encoding]::ASCII.GetString($content)

            if ($Debug) {
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Content: Expecting One-time password: '$TOTP'" -EntryType Information
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Content: Recieved '$String'" -EntryType Information
            }

            if ($String -eq $TOTP) {

                
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 201 -Message "UDP-listener: De-cloaking. Correct string recieved ($($endpoint.Address.IPAddressToString))" -EntryType Information
                $udpclient.Client.ReceiveBufferSize = 0 # Don't queue up content while de-cloaked
                
                try {
                    Set-NetFirewallRule -DisplayName $FirewallRule -Enabled 1 -ErrorAction Stop
                    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 301 -Message "Firewall: Rule '$FirewallRule' enabled" -EntryType Information
                    try {
                        Start-Service WinRM -ErrorAction Stop
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 401 -Message "WinRM-service: Started" -EntryType Information
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 100 -Message "Waiting $ServiceRunningTime sec" -EntryType Information
                        Start-Sleep -Seconds $ServiceRunningTime
                        try {
                            Set-NetFirewallRule -DisplayName $FirewallRule -Enabled 2 -ErrorAction Stop
                            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 302 -Message "Firewall: Rule '$FirewallRule' disabled" -EntryType Information                                         
                            try {
                                Stop-Service WinRM -Force -ErrorAction Stop
                                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 402 -Message "WinRM-service: Stopped" -EntryType Information                                
                                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 202 -Message "UDP-listener: Cloaked" -EntryType Information
                            }
                            catch {
                                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 404 -Message "WinRM-service: Failed to stop: $($_.Exception.Message)" -EntryType Error
                            }
                        }
                        catch {
                            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 302 -Message "Firewall: Failed to disable rule '$FirewallRule': $($_.Exception.Message)" -EntryType Error
                        }
                    }
                    catch {
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 404 -Message "WinRM-service: Failed to start: $($_.Exception.Message)" -EntryType Error
                    }
                }
                catch {
                    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 304 -Message "Firewall: Failed to enable rule '$FirewallRule': $($_.Exception.Message)" -EntryType Error
                }

                [System.GC]::Collect() # Run garbage collection on the PowerShell.exe process
                $udpclient.Client.ReceiveBufferSize = 1 # Start buffering content again                
            }
            else {
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 2002 -Message "UDP-listener: packet sent/port scanned ($($endpoint.Address.IPAddressToString))" -EntryType Warning
            }
        }
    }
}
