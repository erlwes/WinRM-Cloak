<#
  .SYNOPSIS
    A script for installing, removing and monitor the WinRM-cloak service.

  .DESCRIPTION
    The script installs a service that will make the WinRM-service avaliable, only after a valid TOTP is received.

        1. Takes controll over WinRM-service
            * Stops WinRM-service and change startup type to manual
            * Removes default WinRM firewall-rules, and creates one custom-rule to control PowerShell remote access
        2. Deploys a UDP-listener
            * Listener wait for a valid TOTP to be received
            * Listener is designed to be invisible. It has no responsebuffer, and should not send any data in return
        3. Open WinRM for IPs sending correct TOTP
            * When a valid OTP is received, the sender IP is added to WinRM-firewall rule, and the WinRM-service is started for configured amout of time, and the listener stops processing incomming data
            * When time is up (1800 sec default), the firewall rule is disabled and the WinRM-service is shut down
    
    In short: you have to do a secret knock on door A, for door B to be uncloaked/revealed (port-knocking)
#>

#Requires -RunAsAdministrator

Param (
    [Parameter(Mandatory = $false, ParameterSetName = 'Install')]
    [int]$CloakPort,

    [Parameter(Mandatory = $false, ParameterSetName = 'Remove')]
    [switch]$Remove,

    [Parameter(Mandatory = $false, ParameterSetName = 'Monitor')]
    [switch]$Monitor
)

# [FUNCTIONS]
function Write-Log {
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
function New-Base32SecretKey {
    param (
        [int]$length = 32
    )    
    $base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $seedKey = ""   
    for ($i = 0; $i -lt $length; $i++) {
        $randomIndex = Get-Random -Minimum 0 -Maximum $base32Alphabet.Length
        $randomChar = $base32Alphabet[$randomIndex]
        $seedKey += $randomChar
    }
    return $seedKey
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
function Get-NSSM {
    $nssmVersion = 'nssm-2.24-103-gdee49fc'

    # Download NSSM
    While (!(Test-Path .\$nssmVersion.zip)) {	    
	    try {
            Invoke-WebRequest "https://nssm.cc/ci/$($nssmVersion).zip" -Outfile "$PSScriptRoot\$nssmVersion.zip" -ErrorAction Stop
            Write-Log -Level 1 -Message "Invoke-WebRequest - Downloaded NSSM (Non-Sucking Service Manager)"
        }
        catch {
            # Unreliable NGIX-server, so we might have to try several times.
        }
	    Start-Sleep -Seconds 2
    }

    # Verify SHA1-hash
    $SHA1 = '0722c8a775deb4a1460d1750088916f4f5951773' #https://nssm.cc/builds
    $SHA1DownloadedFile = (Get-FileHash "$PSScriptRoot\$nssmVersion.zip" -Algorithm SHA1).Hash
    if ($SHA1 -eq $SHA1DownloadedFile) {        
        Write-Log -Level 1 -Message "Get-FileHash - File-hash for download is correct"
    }
    else {
        Write-Log -Level 2 -Message "Get-FileHash - File-hash does not match!"
        Break
    }

    # Extract archive
    try {
        Expand-Archive "$PSScriptRoot\$nssmVersion.zip" -ErrorAction Stop
        Write-Log -Level 1 -Message "Expand-Archive - Archive extracted to '$PSScriptRoot\$nssmVersion.zip'"
    }
    catch {
        Write-Log -Level 3 -Message "Expand-Archive - Failed to extract archive to '$PSScriptRoot\$nssmVersion.zip'. Error: $($_.Exception.Message)"
        Break
    }

    # Get required x86 NSSM-files from Archive
    Write-Log -Level 1 -Message "Copy-Item - Copy the required files from extracted folder-structure"
    Copy-Item .\$nssmVersion\$nssmVersion\win32\nssm.* $PSScriptRoot -Force

    # Delete archive and extracted folder structure
    Write-Log -Level 1 -Message "Remove-Item - Delete extracted folder and items archive ('$PSScriptRoot\$nssmVersion')"
    Remove-Item "$PSScriptRoot\$nssmVersion" -Recurse
    
    Write-Log -Level 1 -Message "Remove-Item - Delete downloaded archive ('$PSScriptRoot\$nssmVersion.zip')"
    Remove-Item "$PSScriptRoot\$nssmVersion.zip" -Force    
}

switch ($PSCmdlet.ParameterSetName) {
    'Remove'  {
        '';Write-Host "[REMOVING SERVICE]" -ForegroundColor Cyan        
        $ExistingService = Get-Service WinRM-Cloak -ErrorAction SilentlyContinue
        if ($ExistingService) {
            Write-Log -Level 0 -Message "Get-Service - Service 'WinRM-Cloak' exists"
            
            # Stop the service
            try {
                Stop-Service WinRM-Cloak -Force -ErrorAction Stop
                Write-Log -Level 1 -Message "Stop-Service - Service 'WinRM-Cloak' stopped"
            }
            catch {
                Write-Log -Level 3 -Message "Stop-Service - Failed to stop service 'WinRM-Cloak'. Error: $($_.Exception.Message)"
                Break
            }
            
            # Remove the service
            .\nssm.exe remove WinRM-Cloak confirm | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Level 1 -Message "Remove-Service - Service removed (Exitcode: $LASTEXITCODE)"
            }
            else {
                Write-Log -Level 3 -Message "Remove-Service - Failed to remove service (Exitcode: $LASTEXITCODE)"
                Break
            }
        }
        else {
            Write-Log -Level 2 -Message "Get-Service - Service 'WinRM-Cloak' does not exist and can therefore not be removed."
        }

        '';Write-Host "[REMOVING EVENTLOG]" -ForegroundColor Cyan
        try {
            $Eventlog = Get-EventLog -LogName WinRM-Cloak -ErrorAction Stop
            try {
                Remove-EventLog -LogName 'WinRM-Cloak' -ErrorAction Stop
                Write-Log -Level 1 -Message "Remove-EventLog - Eventlog deleted"
            }
            catch {
                Write-Log -Level 3 -Message "Remove-EventLog - Failed to delete eventlog. Error: $($_.Exception.Message)"
            }
        }
        catch {
            Write-Log -Level 2 -Message "Get-EventLog - Eventlog 'WinRM-Cloak' does not exist and can therefore not be removed."
        }
        
        '';Write-Host "[REMOVING FIREWALL RULES]" -ForegroundColor Cyan
        $Rules = Get-NetFirewallRule | Where-Object {$_.DisplayName -match "WinRM - Cloak listener service"}
        if ($Rules) {
            Write-Log -Level 0 -Message "Get-NetFirewallRule - $($Rules.count) rules found"
            ForEach ($Rule in $rules) { 
                try {
                    $Rule | Remove-NetFirewallRule -Confirm:$false
                    Write-Log -Level 1 -Message "Remove-NetFirewallRule - Rule '$($Rule.DisplayName)' removed"
                }
                catch {
                    Write-Log -Level 2 -Message "Remove-NetFirewallRule - Failed to remove rule '$($Rule.DisplayName)'. Error: $($_.Exception.Message)"
                }

            }
        }
        else {
            Write-Log -Level 0 -Message "Get-NetFirewallRule - No rules found"
        }
    }
    'Monitor' {
        Function Invoke-WinRMMonitor {
            while ($true) {
                Clear-Host
                Clear-Variable Port -ErrorAction SilentlyContinue    
                $Port = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTP\').Port
                '';Write-Host "[SERVICES]" -ForegroundColor Cyan
                if((Get-Service WinRM).Status -eq 'Stopped') {
                    Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                    Write-Host "WinRM is stopped (TCP $Port)" -ForegroundColor Yellow
                }
                elseif((Get-Service WinRM).Status -eq 'Running') {
                    $Connections = Get-PSSession -ComputerName localhost -Port $Port -ErrorAction SilentlyContinue
                    if ($Connections) {
                        Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                        Write-Host "WinRM is running (TCP $Port), and connected [$($Connections.count)]" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                        Write-Host "WinRM is running (TCP $Port)" -ForegroundColor Green
                    }
                    Clear-Variable Connections
                }

                Clear-Variable CloakService -ErrorAction SilentlyContinue
                $CloakService = Get-CimInstance Win32_Service -Filter "Name = 'WinRM-Cloak'"

                if($CloakService.State -eq 'Stopped') {
                    Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                    Write-Host "WinRM-Cloak is stopped ($Port)" -ForegroundColor Yellow
                }
                elseif($CloakService.State -eq 'Running') {

                    Clear-Variable ServiceChildProcess, UDPEndpoint, TOTPs -ErrorAction SilentlyContinue
                    $ServiceChildProcess = Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -eq $CloakService.ProcessId}
                    $UDPEndpoint = Get-NetUDPEndpoint -OwningProcess $ServiceChildProcess.ProcessId
                    $TOTPs = Get-TOTP -secret $seedkey

                    Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                    Write-Host "WinRM-Cloak is running on UDP port $($UDPEndpoint.LocalPort) (OTP-current: $($TOTPs[1]) OTP-prev: $($TOTPs[0]))" -ForegroundColor Green
                }

                '';Write-Host "[LAST 10 EVENTS]" -ForegroundColor Cyan
                Get-EventLog -LogName WinRM-Cloak -Newest 10
                Start-Sleep -s 2
            }
        }

        #Seed key from .ini
        $regex = [regex]::new('\b[A-Z2-7]{32}\b', [System.Text.RegularExpressions.RegexOptions]::None)
        $serviceConfig = .\nssm.exe get WinRM-Cloak AppParameters
        $seedMatches = $regex.Matches($serviceConfig)
        $seedkey = $seedMatches.value
        
        Invoke-WinRMMonitor;Break
    }
    'Install' {
        #Region Prereq
        '';Write-Host "[CHECKING PREREQUISITES]" -ForegroundColor Cyan
        if (Test-Path "$PSScriptRoot\nssm.exe") {
            Write-Log -Level 1 -Message "NSSM - Non-Sucking Service Manager found"
        }
        else {
            Write-Log -Level 2 -Message "NSSM - Non-Sucking Service Manager not found. Will download"
            Get-NSSM
        }
        if (!(Test-Path "$PSScriptRoot\nssm.exe")) {
            Break
        }
        #Endregion Prereq

        #Region AleadyInstalled?
        $ServiceExists = Get-Service WinRM-Cloak -ErrorAction SilentlyContinue
        if ($ServiceExists) {
            Write-Log -Level 2 -Message "WinRM Cloak - The service already exitst. Please run script again with -Remove first"
            Break
        }
        #Endregion AleadyInstalled?

        #Region DefaultPortInUse?
        $Port = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTP\').Port
        #Endregion DefaultPortInUse?


        #Region EventViewer
        New-EventLog -Source 'WinRM-Cloak' -LogName 'WinRM-Cloak'
        #Endregion EventViewer

        #Region WinRM
        '';Write-Host "[INSTALLING SERVICE]" -ForegroundColor Cyan
        # [WINRM - SET SERVICE STARTUP TO MANUAL]
        try {
            if ((Get-Service WinRM).StartType -ne 'Manual') {
                Set-Service WinRM -StartupType Manual -ErrorAction Stop    
                Write-Log -Level 1 -Message "WinRM - Set service startuptype to 'Manual'"
            }
            else {
                Write-Log -Level 0 -Message "WinRM - Service startuptype already set to 'Manual'"
            }
        }
        catch {
            Write-Log -Level 3 -Message "WinRM - Failed to set service startuptype to 'Manual'. Error: $($_.Exception.Message)"
        }

        # [WINRM - START SERVICE]
        try {
            if ((Get-Service WinRM).Status -ne 'Running') {
                Start-Service WinRM -ErrorAction Stop
                Write-Log -Level 1 -Message 'WinRM - Service started'
            }
        }
        catch {
            Write-Log -Level 3 -Message "WinRM - Failed to start service. Error: $($_.Exception.Message)"
            Break
        }

        # [WINRM - GET LISTENER]
        try {
            $Listeners = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate
            Write-Log -Level 1 -Message "WinRM - Got listener (Transport: $($Listeners.Transport))"
        }
        catch {
            Write-Log -Level 3 -Message "WinRM - Failed to get listener. Error: $($_.Exception.Message)"
        }

        # [WINRM - STOP SERVICE]
        try {
            if ((Get-Service WinRM).Status -eq 'Running') {
                Stop-Service WinRM -Force -ErrorAction Stop
                Write-Log -Level 1 -Message 'WinRM - Service stopped'
            }
        }
        catch {
            Write-Log -Level 3 -Message "WinRM - Failed to stop service. Error: $($_.Exception.Message)"
        }
        #Endregion WinRM

        #Region Firewall
        # OPEN UDP LISTERNER/DOORKEEPER PORT
        $FirewallParam2 = @{
            DisplayName = 'WinRM - Cloak listener service'
            Description = "Allow Windows to listen on UDP port $CloakPort"
            Direction = 'Inbound'
            LocalPort = $CloakPort
            Protocol = 'UDP'
            Action = 'Allow'
            Profile = 'Private', 'Domain'
            Program = 'Any' #PowerShell.exe for manually testing WinRM-Cloak-Service.ps1, and SYSTEM/Srvstart.exe for service. Could limit further.
        }
        try {
            New-NetFirewallRule @FirewallParam2 -ErrorAction Stop -Confirm:$false | Out-Null
            Write-Log -Level 1 -Message "FIREWALL - New rule '$($FirewallParam2.DisplayName)' created (UDP $CloakPort inbound)"
        }
        catch {
            Write-Log -Level 3 -Message "FIREWALL - Failed to create new rule '$($FirewallParam2.DisplayName)'. Error: $($_.Exception.Message)"
        }
        #Endregion Firewall

        #Region Cloak service
        # [WinRM-Cloak - CREATE SERVICE FOR UDP LISTENER]
        if (Test-Path -Path "$PSScriptRoot\WinRM-Cloak-Service.ini") {
            Remove-Item "$PSScriptRoot\WinRM-Cloak-Service.ini" -Force -Confirm:$false
        }

        # [WinRM-Cloak - Generate TOTP secret key/seed key]
        $TOTPSecretKey = New-Base32SecretKey
        Write-Log -Level 4 -Message "WinRM CLOAK - ####################################################################"
        Write-Log -Level 4 -Message "WinRM CLOAK - Secret key/seed key generated: '$TOTPSecretKey'"
        Write-Log -Level 4 -Message "WinRM CLOAK - This is needed to generate TOTP on client-side"
        Write-Log -Level 4 -Message "WinRM CLOAK - ####################################################################"

        # [WinRM-Cloak - Create the service]
        $Binary = (Get-Command Powershell).Source
        $Arguments = "-ExecutionPolicy Bypass -NonInteractive -NoProfile -File $PSScriptRoot\WinRM-Cloak-Service.ps1 $CloakPort $TOTPSecretKey $($Listeners.Transport)"
        .\nssm.exe install WinRM-Cloak "$Binary" "$Arguments" | Out-Null        
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Level 1 -Message "WinRM CLOAK - Service created (Exitcode: $LASTEXITCODE)"
        }
        elseif ($LASTEXITCODE -eq 5) {
            Write-Log -Level 2 -Message "WinRM CLOAK - Service already exists (Exitcode: $LASTEXITCODE)"
        }
        else {
            Write-Log -Level 3 -Message "WinRM CLOAK - Failed to create service (Exitcode: $LASTEXITCODE)"
        }

        # [WinRM-Cloak - Start the service]
        try {
            if ((Get-Service WinRM-Cloak).Status -ne 'Running') {
                Start-Service WinRM-Cloak -ErrorAction Stop
                Write-Log -Level 1 -Message 'WinRM CLOAK - Service started'
            }
        }
        catch {
            Write-Log -Level 3 -Message "WinRM CLOAK - Failed to start service. Error: $($_.Exception.Message)"
            Break
        }
        #Endregion Cloak service
    }
}
''
