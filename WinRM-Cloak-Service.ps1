Param(
    [int]$Port,
    [string]$TOTPSecretKey,
    [string]$WinRMListenerTransport = 'HTTP',
    [int]$SessionDurationInSeconds = 1800,
    [int]$MaxClients = 3,
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
        [string]$Secret,
        [int]$Digits = 6,
        [int]$Interval = 30
    )

    $KeyBytes = Convert-Base32ToBytes -base32 $Secret

    $UnixTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $CurrentStep = [int64]($UnixTime / $Interval)
    $Results = @()

    foreach ($StepOffset in -1..0) {
        $Step = $CurrentStep + $StepOffset
        $stepBytes = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($Step))

        $HMAC = New-Object System.Security.Cryptography.HMACSHA1
        $HMAC.Key = $KeyBytes
        $Hash = $HMAC.ComputeHash($stepBytes)

        $Offset = $Hash[-1] -band 0x0F
        $Binary =
            (($Hash[$Offset] -band 0x7F) -shl 24) -bor
            (($Hash[$Offset + 1] -band 0xFF) -shl 16) -bor
            (($Hash[$Offset + 2] -band 0xFF) -shl 8) -bor
            ($Hash[$Offset + 3] -band 0xFF)

        $OTP = $Binary % [math]::Pow(10, $Digits)
        $Results += $OTP.ToString().PadLeft($Digits, '0')
    }
    return $Results
}

function Sync-WinRMAccess {
    param(
        [hashtable]$Clients,
        [string]$FirewallRule,
        [bool]$Debug
    )

    # Cache last-seen state per rule (persists across loop iterations in the same script/module runspace)
    if (-not $script:WinRMAccessState) { $script:WinRMAccessState = @{} }

    $Now = Get-Date

    # Prune expired clients
    foreach ($ip in @($Clients.Keys)) {
        if ($Clients[$ip] -le $Now) {
            $Clients.Remove($IP) | Out-Null
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 400 -Message "Client Sync: Client '$IP' expired" -EntryType Information
        }
    }

    # ---- CHANGE DETECTION (added/expired/expiry-updated) ----
    # Build a stable fingerprint of current clients+expiry
    $CurrentState = (
        $Clients.GetEnumerator() |
            Sort-Object Name |
            ForEach-Object {
                # Use UTC ticks for stable formatting
                "{0}={1}" -f $_.Key, ([datetime]$_.Value).ToUniversalTime().Ticks
            }
    ) -join ';'

    $PreviousState = $script:WinRMAccessState[$FirewallRule]
    $Changed = ($CurrentState -ne $PreviousState)

    if (-not $Changed) {
        # No new client and no expiry/removal -> do nothing this iteration
        return ($Clients.Count -gt 0)
    }

    # Update cache now that we know it changed, for next loop
    $script:WinRMAccessState[$FirewallRule] = $CurrentState

    if ($Clients.Count -gt 0) {
        $IPList = [string[]]$Clients.Keys

        # Ensure firewall rule is enabled and set to allowed IP list
        try {
            Set-NetFirewallRule -DisplayName $FirewallRule -Enabled True -RemoteAddress $IPList -ErrorAction Stop
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 200 -Message "Firewall: Rule '$FirewallRule' updated/enabled (allowed: $($IPList -join ','))" -EntryType Information
        }
        catch {
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 201 -Message "Firewall: Failed to set rule '$FirewallRule'(allowed: $($IPList -join ',')): $($_.Exception.Message)" -EntryType Error
        }

        # Ensure WinRM is running (only when changes occurred)
        if ((Get-Service WinRM).Status -ne 'Running') {
            Start-Service WinRM -ErrorAction Stop
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 500 -Message "WinRM-service: Started (active clients)" -EntryType Information
        }

        if ($Debug) {
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message ("Client Sync: Active clients: " + ($ipList -join ', ')) -EntryType Information
        }

        return $true
    }
    else {
        # No active clients -> close down firewall rule + WinRM service
        try {
            Set-NetFirewallRule -DisplayName $FirewallRule -Enabled False -ErrorAction Stop
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 210 -Message "Firewall: Rule '$FirewallRule' disabled" -EntryType Information
        }
        catch {
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 211 -Message "Firewall: Failed to disable rule '$FirewallRule': $($_.Exception.Message)" -EntryType Error
        }

        Stop-WinRM -Context 'no active clients'
        return $false
    }
}

function Stop-WinRM {
    Param([string]$Context)
    if ((Get-Service WinRM).Status -ne 'Stopped') {
        try {
            Stop-Service WinRM -Force -ErrorAction Stop
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 510 -Message "WinRM-service: Stopped ($Context)" -EntryType Information
        }
        catch {
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 511 -Message "WinRM-service: Failed to stop ($Context): $($_.Exception.Message)" -EntryType Error
        }
    }
}

Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 100 -Message "Service starting" -EntryType Information

if ($Debug) {
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Parameters: Port = $Port" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Parameters: WinRMListenerTransport = $WinRMListenerTransport" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Parameters: ServiceRunningTime = $SessionDurationInSeconds" -EntryType Information
    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Parameters: MaxClients = $MaxClients" -EntryType Information
}

# Disable Firewall-rule for WinRM and stop WinRM at start
$FirewallRule = "WinRM - $WinRMListenerTransport custom port"
Stop-WinRM -Context 'startup'

# UDP listener
$Endpoint  = New-Object System.Net.IPEndPoint([IPAddress]::Any, $Port)
$UdpClient = New-Object System.Net.Sockets.UdpClient $Port
$UdpClient.Client.SendBufferSize = 0
$UdpClient.Client.ReceiveBufferSize = 1

# Track allowed IPs and their expiry times
$Clients = @{}
$WinRMOpen = $false

# Allow some time for listener to get sorted
[System.Threading.Thread]::Sleep(5000)
[int]$i = 0

# Start of main loop
while ($true) {

    # Throttle this loop, to limit CPU. Balance between low resource usage and responsiveness.
    [System.Threading.Thread]::Sleep(3000)

    # Periodic sync for each loop. Control access for existing clients. Expire and remove, or add (ip in firewall rules)
    $WinRMOpen = Sync-WinRMAccess -Clients $Clients -FirewallRule $FirewallRule -Debug $Debug

    # Is listener still ready?
    if ($UdpClient.Available) {
        $Data = $UdpClient.Receive([ref]$Endpoint)

        # Did it receive any data since last loop?
        if ($Data) {

            # Get client IP
            $IP = $Endpoint.Address.IPAddressToString
            $String = [Text.Encoding]::ASCII.GetString($data)
            [int]$IsInt = $string

            # Empty payload/portscan?
            if ($String -match '>\?\?\?') {
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 312 -Message "Listener: Client '$IP' sendt an empty packet. Typical NMAP." -EntryType Warning
            }

            # Is the received data a integer? (then go on)
            elseif ($IsInt -is [int]) {

                # Calculate the corrent valid TOTPs
                $TOTP = Get-TOTP -Secret $TOTPSecretKey

                # Output valid OTP and revieved OTP to eventlog, if -debug parameter is used.
                if ($Debug) {
                    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Content: Expecting One-time password: '$($TOTP -join ',')'" -EntryType Information
                    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Content: Recieved '$String' from $IP" -EntryType Information
                }

                # Check if revieved TOTP is valid (current or previous)
                if ([int]$IsInt -eq $TOTP[0] -or [int]$IsInt -eq $TOTP[1]) {

                    # Calculate expiry time for this connection
                    $Now = Get-Date
                    $Expiry = $Now.AddSeconds($SessionDurationInSeconds)

                    # Verify that max number of clients is not reached.
                    if (-not $Clients.ContainsKey($IP) -and $Clients.Count -ge $MaxClients) {
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 301 -Message "Listener: Client '$ip' sendt valid OTP, but MaxClients ($MaxClients) is reached. Denied." -EntryType Warning
                    }
                    else {
                        # Add the client to clients list (IP + expiry time)
                        $Clients[$IP] = $Expiry
                        Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 300 -Message "Listener: Client '$ip' sendt valid OTP. Access expires $expiry" -EntryType Information

                        # Sync access, so that new client is added to firewall rule immediatly (without waiting for next loop)
                        $WinRMOpen = Sync-WinRMAccess -Clients $Clients -FirewallRule $FirewallRule -Debug $Debug
                    }
                }
                else {
                    Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 310 -Message "Listener: Client '$ip' sendt invalid TOTP" -EntryType Warning
                }
            }
            else {
                # Recieve data is NaN. Do not process at all.
                Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 311 -Message "Listener: Client '$ip' sendt a packet with NaN-content" -EntryType Warning
            }
        }
    }

    # For every 20th loop, stop the WinRM-service if its running AND we have no active clients + trigger garbage collection
    if ([int]$i -ge 20) {

        # Re-sync first to prune expired
        $WinRMOpen = Sync-WinRMAccess -Clients $Clients -FirewallRule $FirewallRule -Debug $Debug

        # Stop service if no connections. In case it was manually started
        if (-not $WinRMOpen) {
            Stop-WinRM -Context 'sanity check if manually started'
        }

        if ($Debug) {
            Write-EventLog -LogName 'WinRM-Cloak' -Source "WinRM-Cloak" -EventID 800 -Message "Maint: Alive. loop number $i reached; ActiveClients=$($Clients.Count)" -EntryType Information
        }

        # Garbabge collection to keep memory usage low
        [System.GC]::Collect()

        # Reset the loop counter
        [int]$i = 0
    }

    [int]$i++
}
