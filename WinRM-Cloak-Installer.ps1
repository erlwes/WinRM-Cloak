<#
  .SYNOPSIS
    A script for cloaking PowerShell remoting (WinRM-service), by hiding the service when not explicitly unlocked/started by sending a secret string to a listener.

  .DESCRIPTION
    The script install a gatekeeper/cloak-service that will start WinRM-service only when a secret string is sent to listener
        - Deploys a PowerShell UDP-listener as a service
        - This service will listen for data on a specified UDP port (no reply back to sender)
        - If correct string is received -> Start WinRM-service, Sleep for x amount of seconds and stop WinRM-service again
        - This means that you have to do a secret knock on door A, for door B to open

    Thoughts/general considerations
    1. When selecting a port. Avoid commons ports. One way of doing this would be to pick a port
       that is not on nmap top port list (nmap --top-ports 20000 localhost -v -oG -).
    2. Where ever you decide to drop the service script on disk, make sure that ...
        A) Folder/file-ACL does not allow the script to be edited by non-administrators (service hijacking). Running as system by default.
        B) Folder/file-ACL does not allow the script to be read by non-administrators, Secret string is hardcoded in listener script for now.
#>
Param (
    [Parameter(Mandatory = $false)]
    [int]$CloakPort,

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
if (!$CloakPort) {
    Write-Host 'Please specify all required parameters (CloakPort)' -ForegroundColor Yellow
    Break
}

#Region WinRM
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
# OPEN UDP LISTERNER/DOORKEEPER PORT
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
    # If you edit the .ini file manually, make sure it is saved as ANSI after changes. The service will not start if UTF8.
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
