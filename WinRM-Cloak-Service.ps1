Param(
    [int]$Port,
    [string]$TOTPSecretKey,
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
        [int]$digits = 6,
        [int]$interval = 30
    )
    
    # Convert secret to byte array
    $keyBytes = Convert-Base32ToBytes -base32 $secret
   
    $unixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $currentStep = [int64]($unixTime / $interval)
    $results = @()

    foreach ($stepOffset in -1..0) {
        $step = $currentStep + $stepOffset
        $stepBytes = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($step))

        $hmac = New-Object System.Security.Cryptography.HMACSHA1
        $hmac.Key = $keyBytes
        $hash = $hmac.ComputeHash($stepBytes)

        $offset = $hash[-1] -band 0x0F
        $binary =
            (($hash[$offset] -band 0x7F) -shl 24) -bor
            (($hash[$offset + 1] -band 0xFF) -shl 16) -bor
            (($hash[$offset + 2] -band 0xFF) -shl 8) -bor
            ($hash[$offset + 3] -band 0xFF)

        $otp = $binary % [math]::Pow(10, $digits)
        $results += $otp.ToString().PadLeft($digits, '0')
    }
    return $results
}

Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 100 -Message "Service starting" -EntryType Information

if ($Debug) {
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: Port = $Port" -EntryType Information   
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: WinRMListenerTransport = $WinRMListenerTransport" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: ServiceRunningTime = $ServiceRunningTime" -EntryType Information    
   #Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Parameters: TOTPSecretKey = $TOTPSecretKey" -EntryType Information
    # If you uncomment this, be aware that users with remote eventlog reader will be able to see the TOTP secret key, and that the secret could possibly be forwarded into SIEM, syslog and such.
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
[int]$i = 0
while ($true) {

    # Sleep is for both performance and throttle/limiting
    # The Start-Sleep cmdlet uses more CPU and gets logged in PowerShell-Operational eventlog for each loop cycle, therefore this method is prefered.
    [System.Threading.Thread]::Sleep(4000)

    if ($udpclient.Available) {
        $content = $udpclient.Receive([ref]$endpoint)

        # Received any data?
        if ($content) {

            $TOTP = Get-TOTP -Secret $TOTPSecretKey
            $String = [Text.Encoding]::ASCII.GetString($content)

            if ($Debug) {
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Content: Expecting One-time password: '$TOTP'" -EntryType Information
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "Content: Recieved '$String'" -EntryType Information
            }

            # Does the content match a valid TOTP (current or previous)?
            if ($String -eq $TOTP[0] -or $String -eq $TOTP[1]) {

                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 201 -Message "UDP-listener: De-cloaking. Valid OTP recieved from $($endpoint.Address.IPAddressToString)" -EntryType Information
                
                # Stop buffering data on listener
                $udpclient.Client.ReceiveBufferSize = 0
                
                try {
                    # Add connecting IP to allowed source in WinRM-firewall rule and enable it
                    Set-NetFirewallRule -DisplayName $FirewallRule -Enabled 1 -RemoteAddress $($endpoint.Address.IPAddressToString) -ErrorAction Stop
                    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 301 -Message "Firewall: Rule '$FirewallRule' enabled" -EntryType Information

                    try {
                        # Start the WinRM service
                        Start-Service WinRM -ErrorAction Stop
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 401 -Message "WinRM-service: Started" -EntryType Information
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 100 -Message "Waiting $ServiceRunningTime sec" -EntryType Information

                        # Wait for however long the service should be up after de-cloaked (ServiceRunningTime-parameter)
                        Start-Sleep -Seconds $ServiceRunningTime

                        try {
                            # Disable the firewall-rule
                            # Remote IPs is not reset, this is by design. It will be overwritten on next connection. In case WinRM fails to stop, it is bettered to be filtered on RemoteAddress vs. any.
                            Set-NetFirewallRule -DisplayName $FirewallRule -Enabled 2 -ErrorAction Stop 
                            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 302 -Message "Firewall: Rule '$FirewallRule' disabled" -EntryType Information                                         
                            
                            try {
                                # Stop the WinRM service again
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

                # Run garbage collection on the PowerShell.exe process to keep low memory footprint.
                [System.GC]::Collect()

                # Start buffering data on listener again
                $udpclient.Client.ReceiveBufferSize = 1
            }
            else {
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 2002 -Message "UDP-listener: packet sent/port scanned ($($endpoint.Address.IPAddressToString))" -EntryType Warning
            }
        }
    }

    # For every 10th loop, stop the WinRM-service if its running
    # This is in case the WinRM service is started manually by user. For the service to keep track on this, without spending to much CPU, we check every ~40 seconds
    if ([int]$i -ge 10) {
        if (!((Get-Service WinRM).Status -eq 'Stopped')) {
            try {
                Stop-Service WinRM -Force -ErrorAction Stop
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 402 -Message "WinRM-service: Stopped" -EntryType Information
            }
            catch {
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 404 -Message "WinRM-service: Failed to stop: $($_.Exception.Message)" -EntryType Error
            }
        }        
        if ($Debug) {
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 50 -Message "WinRM-service: Alive ($i)" -EntryType Information
        }
        [int]$i = 0
    }
    [int]$i ++
}
