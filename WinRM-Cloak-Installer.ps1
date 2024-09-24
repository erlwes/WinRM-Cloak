<#
  .SYNOPSIS
    A script for hardening WinRM/PowerShell Remoting on a workstation or domain joined Windows-machine.

  .DESCRIPTION
    The script will harden WinRM by doing the following:

    1. Change the default port on the WinRM-service, and set startup to manual
        - This will make the job harder for an attacker. Attackers will not always take time to scan all ports, especially not the dynamic/high ranges.        

    2. Disable default session configurations
        - When default sc is disabled/not avaliable, the client will have to specify the correct configuration name when doing PS-remoting.

    3. Create a custom session configuration
        - Unless an attacker finds correct config name in eventlog, transcripts, history, ps-readline or elsewhere, they would have to guess/bruteforce it.
        - ! This session configuration in this scrips is not limited and has all capabilities !

    3. Deploy a gatekeeper/cloak that will start WinRM-service only when a secret string is sent to listener
        - Deploys a PowerShell UDP-listener as a service
        - This service will listen for data on a specified UDP port (no reply back to sender)
        - If correct string is received -> Start WinRM-service, Sleep for x amount of seconds and stop WinRM-service again
        - This means that you have to do a secret knock on door A, for door B to open

    Thoughts/general considerations
    1. When selecting a port. Avoid commons ports. One way of doing this would be to pick a port
       that is not on nmap top port list (nmap --top-ports 20000 localhost -v -oG -).
    2. The PowerShell session configuration created by this script is not limited (all capabilities).
    3. Consider limiting this session config by setting language mode, limiting capabilities with JEA and using a virtual account.
    4. In domain environments, try to use FQDN/hostname when PS-remoting. If you dont, NTLM will be used instead of kerberos. Authentication Negotiate = NTLM.
    5. Avvoid default/common username for administrative accounts, and enforce strong passwords
    6. Where ever you decide to drop the service script on disk, make sure that ...
        A) Folder/file-ACL does not allow the script to be edited by non-administrators (service hijacking). Running as system by default.
        B) Folder/file-ACL does not allow the script to be read by non-administrators, Secret string is hardcoded in listener script for now.

        
    .EXAMPLE    
#>
Param (    
    [Parameter(Mandatory = $false)]
    [int]$WinRMPort,

    [Parameter(Mandatory = $false)]
    [int]$CloakPort,

    [Parameter(Mandatory = $false)]
    [string]$PSSessionConfName,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveWinRMCloakService,

    [Parameter(Mandatory = $false)]
    [switch]$MonitorWinRMService
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

if ($RemoveWinRMCloakService) {
    sc.exe DELETE WinRM-Cloak
    Break
}
if ($MonitorWinRMService) {
    Function Get-WinRM {
        Clear-Variable Port -ErrorAction SilentlyContinue    
        $Port = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTP\').Port
        while ($true) {
            if((Get-Service WinRM).Status -eq 'Stopped') {
                Write-Host "WinRM is stopped ($Port)" -f yellow
            }
            elseif((Get-Service WinRM).Status -eq 'Running') {
                if (Get-PSSession -ComputerName localhost -Port $Port -ErrorAction SilentlyContinue) {
                    Write-Host "WinRM is running ($Port), and connected" -f Cyan
                }
                else {
                    Write-Host "WinRM is running ($Port)" -f Green
                }        
            }
            Start-Sleep -s 2
        }
    }
    Get-WinRM;Break
}

#Region Tests
if (!$WinRMPort -or !$CloakPort -or !$PSSessionConfName) {
    Write-Host 'Please specify all required parameters (WinRMPort, CloakPort, PSSessionConfName)' -ForegroundColor Yellow
    Break
}

# [NET CONNECTION PROFILE - WARN IF ACTIVE PROFILE IS PUBLIC]
if ((Get-NetConnectionProfile).NetworkCategory -eq 'Public') {    
    Write-Log -Level 2 -Message "NET CONNECTION PROFILE - Active profile is 'Public'"
    Write-Log -Level 2 -Message "NET CONNECTION PROFILE - Change profile to Private or Domain, or add public profile to allow rule for WinRM (Set-NetConnectionProfile -NetworkCategory [Domain|Private])"
    Break
}
else {
    Write-Log -Level 1 -Message "NET CONNECTION PROFILE - Active profile is '$((Get-NetConnectionProfile).NetworkCategory)'"
}
#Endregion Tests


#Region WinRM
# [PS-REMOTING - ENABLE]
try {
    Enable-PSRemoting -Force -ErrorAction Stop | Out-Null
    Write-Log -Level 1 -Message "PS-REMOTING - Enabled PS-Remoting"
}
catch {
    Write-Log -Level 3 -Message "PS-REMOTING - Failed to enabled PS-Remoting. Error: $($_.Exception.Message)"
    Break
}

# [PS-SESSION-CONFIGURATION - DISABLE DEFAULTS]
try {
    Get-PSSessionConfiguration -Name microsoft.* | Where-Object {$_.Enabled -eq $true} | ForEach-Object {
        Disable-PSSessionConfiguration -Name $_.Name -Force -Confirm:$false -ErrorAction Stop
        Write-Log -Level 1 -Message "PS-SESSION-CONFIGURATION - Disabled '$($_.Name)'"
    }
}
catch {
    Write-Log -Level 3 -Message "PS-SESSION-CONFIGURATION - Failed to disable. Error:'$($_.Exception.Message)'"
}

# [PS-SESSION-CONFIGURATION - CREATE CUSTOM]
try {
    # This profile has all capabilities. Consider limiting with JEA!

    #Before creating new session-config, check if it already exists.

    New-PSSessionConfigurationFile -Path "$PSScriptRoot\Defaults-session-config.pssc" -Author Admin -ErrorAction Stop
    Register-PSSessionConfiguration -Name $PSSessionConfName -Path "$PSScriptRoot\Defaults-session-config.pssc" -NoServiceRestart -Force -ErrorAction Stop | Out-Null
    Write-Log -Level 1 -Message "PS-SESSION-CONFIGURATION - '$PSSessionConfName' created"
}
catch {
    Write-Log -Level 3 -Message "PS-SESSION-CONFIGURATION - Failed to create '$PSSessionConfName'. Error: $($_.Exception.Message)"
}

# [WINRM - CHANGE DEFAULT PORT]
$Command = "winrm set winrm/config/listener?Address=*+Transport=HTTP '@{Port=`"$WinRMPort`"}'"
Invoke-Expression $Command | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Log -Level 1 -Message "WINRM - Default port for WinRM changed to '$WinRMPort'"
}
else {
    Write-Log -Level 3 -Message "WINRM - Failed to set WinRM por to '$WinRMPort'. Exitcode: $LASTEXITCODE"
}

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
# [FIREWALL - OPEN TCP CUSTOM WINRM PORT]
$FirewallParam1 = @{
    DisplayName = 'WinRM - Custom port'
    Description = "Allow incomming traffic on TCP port $WinRMPort"
    Direction = 'Inbound'
    LocalPort = $WinRMPort
    Protocol = 'TCP'
    Action = 'Allow'
    Profile = 'Private', 'Domain'
    Program = 'System'
}
try {
    New-NetFirewallRule @FirewallParam1 -ErrorAction Stop -Confirm:$false | Out-Null
    Write-Log -Level 1 -Message "FIREWALL - New rule '$($FirewallParam1.DisplayName)' created (TCP $WinRMPort inbound)"
}
catch {
    Write-Log -Level 3 -Message "FIREWALL - Failed to create new rule '$($FirewallParam1.DisplayName)'. Error: $($_.Exception.Message)"
}

# [FIREWALL - OPEN UDP LISTERNER/DOORKEEPER PORT]
$FirewallParam2 = @{
    DisplayName = 'WinRM - Doorkeeper service'
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

# [FIREWALL - DISABLE DEFAULT RULE THAT ALLOW TCP 5985]
Get-NetFirewallRule | Where-Object {$_.Name -match 'WINRM-HTTP-in-TCP' -and $_.Enabled -eq $true} | ForEach-Object {
    try {
        Disable-NetFirewallRule -Name $_.Name -ErrorAction Stop
        Write-Log -Level 1 -Message "FIREWALL - Disabled default rule '$($_.DisplayName)' ($($_.Profile))"
    }
    catch {
        Write-Log -Level 3 -Message "FIREWALL - Failed to disable default rule '$($_.DisplayName)' ($($_.Profile)). Error: $($_.Exception.Message)"
    }
} 
#Endregion Firewall


#Region Cloak service
# [WinRM-Cloak - CREATE SERVICE FOR UDP LISTENER]
if (Test-Path -Path "$PSScriptRoot\WinRM-Cloak-Service.ini") {
    Remove-Item "$PSScriptRoot\WinRM-Cloak-Service.ini" -Force -Confirm:$false
}
try {
    $ServiceConfig = @()
    $ServiceConfig += "[WinRM-Cloak]`n"
    $ServiceConfig += "startup=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NoProfile -File $PSScriptRoot\WinRM-Cloak-Service.ps1 $CloakPort`n"
    $ServiceConfig += "shutdown_method=kill"
    $ServiceConfig | Out-File "$PSScriptRoot\WinRM-Cloak-Service.ini" -Force -Encoding ASCII -NoNewline -ErrorAction Stop
    Write-Log -Level 1 -Message "WinRM CLOAK - Created service config-file ('$PSScriptRoot\WinRM-Cloak-Service.ini')"
}
catch {
    Write-Log -Level 3 -Message "WinRM CLOAK - Failed to create service config-file ('$PSScriptRoot\WinRM-Cloak-Service.ini'). Error: $($_.Exception.Message)"
}


SC.EXE CREATE WinRM-Cloak Displayname= "WinRM-Cloak" binpath= "$PSScriptRoot\srvstart.exe WinRM-Cloak -c $PSScriptRoot\WinRM-Cloak-Service.ini" start=auto | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Log -Level 1 -Message "WinRM CLOAK - Service created (Exitcode: $LASTEXITCODE)"
}
else {
    Write-Log -Level 3 -Message "WinRM CLOAK - Failed to create service (Exitcode: $LASTEXITCODE)"
}
#Exitcode 1073 = 'Den angitte tjenesten eksisterer allerede.' Handle as warning

#Endregion Cloak service