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
            * When time is up (600 sec default), the firewall rule is disabled, the WinRM-service is stopped, and the listener starts listening again
    
    In short: you have to do a secret knock on door A, for door B to be uncloaked/revealed
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
switch ($PSCmdlet.ParameterSetName) {
    'Remove'  {        
        Write-Host "[REMOVING SERVICE]" -ForegroundColor Cyan
        if (Get-Service WinRM-Cloak -ErrorAction SilentlyContinue) {
            Write-Log -Level 0 -Message "Get-Service - Service 'WinRM-Cloak' exists"
            try {
                Stop-Service WinRM-Cloak -Force -ErrorAction Stop
                Write-Log -Level 1 -Message "Stop-Service - Service 'WinRM-Cloak' stopped"
            }
            catch {
                Write-Log -Level 3 -Message "Stop-Service - Failed to stop service 'WinRM-Cloak'. Error: $($_.Exception.Message)"
                Break
            }
            
            SC.EXE DELETE WinRM-Cloak | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Level 1 -Message "WinRM CLOAK - Service deleted (Exitcode: $LASTEXITCODE)"
            }
            else {
                Write-Log -Level 3 -Message "WinRM CLOAK - Failed to delete service (Exitcode: $LASTEXITCODE)"
                Break
            }
        }
        else {
            Write-Log -Level 2 -Message "Get-Service - Service 'WinRM-Cloak' does not exist and can therefore not be removed."
        }        
        try {
            Get-EventLog -LogName WinRM-Cloak -ErrorAction Stop
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
                    if (Get-PSSession -ComputerName localhost -Port $Port -ErrorAction SilentlyContinue) {
                        Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                        Write-Host "WinRM is running (TCP $Port), and connected" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "$((Get-Date).ToString()) " -ForegroundColor DarkGray -NoNewline
                        Write-Host "WinRM is running (TCP $Port)" -ForegroundColor Green                        
                    }        
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
        $seedMatches = $regex.Matches((Get-Content $PSScriptRoot\WinRM-Cloak-Service.ini))
        $seedkey = $seedMatches.value
        
        Invoke-WinRMMonitor;Break
    }
    'Install' {
        #Region EventViewer
        New-EventLog -Source 'WinRM-Cloak' -LogName 'WinRM-Cloak'
        #Endregion EventViewer

        #Region WinRM
        Write-Host "[INSTALLING SERVICE]" -ForegroundColor Cyan
        # [WINRM - SET SERVICE STARTUP TO MANUAL]
        try {
            if ((Get-Service WinRM).StartType -ne 'Manual') {
                Set-Service WinRM -StartupType Manual -ErrorAction Stop    
                Write-Log -Level 1 -Message "WINRM - Set service startuptype to 'Manual'"
            }
            else {
                Write-Log -Level 0 -Message "WINRM - Service startuptype already set to 'Manual'"
            }
        }
        catch {
            Write-Log -Level 3 -Message "WINRM - Failed to set service startuptype to 'Manual'. Error: $($_.Exception.Message)"
        }

        # [WINRM - START SERVICE]
        try {
            if ((Get-Service WinRM).Status -ne 'Running') {
                Start-Service WinRM -ErrorAction Stop
                Write-Log -Level 1 -Message 'WINRM - Service started'
            }
        }
        catch {
            Write-Log -Level 3 -Message "WINRM - Failed to start service. Error: $($_.Exception.Message)"
            Break
        }

        # [WINRM - GET LISTENER]
        try {
            $Listeners = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate
            Write-Log -Level 1 -Message "WINRM - Got listener (Transport: $($Listeners.Transport))"
        }
        catch {
            Write-Log -Level 3 -Message "WINRM - Failed to get listener. Error: $($_.Exception.Message)"
        }

        # [WINRM - STOP SERVICE]
        try {
            if ((Get-Service WinRM).Status -eq 'Running') {
                Stop-Service WinRM -Force -ErrorAction Stop
                Write-Log -Level 1 -Message 'WINRM - Service stopped'
            }
        }
        catch {
            Write-Log -Level 3 -Message "WINRM - Failed to stop service. Error: $($_.Exception.Message)"
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
        Write-Log -Level 2 -Message "WinRM CLOAK - Secret key/seed key generated: '$TOTPSecretKey'. This is needed to generate TOTP on client-side"

        # [WinRM-Cloak - Generate service .ini-file]
        try {
            $ServiceConfig = @()
            $ServiceConfig += "[WinRM-Cloak]`n"
            $ServiceConfig += "startup=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NoProfile -File $PSScriptRoot\WinRM-Cloak-Service.ps1 $CloakPort $TOTPSecretKey $($Listeners.Transport)`n"
            $ServiceConfig += "shutdown_method=kill"
            $ServiceConfig | Out-File "$PSScriptRoot\WinRM-Cloak-Service.ini" -Force -Encoding ASCII -NoNewline -ErrorAction Stop
            Write-Log -Level 1 -Message "WinRM CLOAK - Created service config-file ('$PSScriptRoot\WinRM-Cloak-Service.ini')"
            # If you edit the .ini file manually, make sure it is saved as ANSI after changes. The service will not start if UTF8.
        }
        catch {
            Write-Log -Level 3 -Message "WinRM CLOAK - Failed to create service config-file ('$PSScriptRoot\WinRM-Cloak-Service.ini'). Error: $($_.Exception.Message)"
        }

        # [WinRM-Cloak - Create the service]
        SC.EXE CREATE WinRM-Cloak Displayname= "WinRM-Cloak" binpath= "$PSScriptRoot\srvstart.exe WinRM-Cloak -c $PSScriptRoot\WinRM-Cloak-Service.ini" start=auto | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Level 1 -Message "WinRM CLOAK - Service created (Exitcode: $LASTEXITCODE)"
        }
        elseif ($LASTEXITCODE -eq 1073) {
            Write-Log -Level 2 -Message "WinRM CLOAK - Service 'WinRM-Cloak' already exist (Exitcode: $LASTEXITCODE)"
        }
        elseif ($LASTEXITCODE -eq 1072) {
            Write-Log -Level 3 -Message "WinRM CLOAK - Service 'WinRM-Cloak' is marked for deletion (Exitcode: $LASTEXITCODE)"
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
