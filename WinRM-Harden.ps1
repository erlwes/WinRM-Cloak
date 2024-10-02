<#
  .SYNOPSIS
    A script for hardening WinRM/PowerShell-remoting on a workstation or domain joined Windows-machine.

  .DESCRIPTION
    The script will harden WinRM by doing the following:

    1. Change the default port on the WinRM-service.
        - This will make the job harder for an attacker. Attackers will not always take time to scan all ports, especially not the dynamic/high ranges.        

    2. Disable default session configurations
        - When default sc is disabled/not avaliable, the client will have to specify the correct configuration name when doing PS-remoting.

    3. Create a custom session configuration
        - Unless an attacker finds correct config name in eventlog, transcripts, history, ps-readline or elsewhere, they would have to guess/bruteforce it.
        - ! This session configuration in this scrips is not limited and has all capabilities !

    Thoughts/general considerations
    1. When selecting a port. Avoid commons ports. One way of doing this would be to pick a port
       that is not on nmap top port list (nmap --top-ports 20000 localhost -v -oG -).
    2. The PowerShell session configuration created by this script is not limited (all capabilities).
    3. Consider limiting this session config by setting language mode, limiting capabilities with JEA and using a virtual account.
    4. In domain environments, try to use FQDN/hostname when PS-remoting. If you dont, NTLM will be used instead of kerberos. Authentication Negotiate = NTLM.
    5. Avvoid default/common username for administrative accounts, and enforce strong passwords
#>
Param (    
    [Parameter(Mandatory = $false)]
    [int]$WinRMPort,

    [Parameter(Mandatory = $false)]
    [string]$PSSessionConfName,

    [Parameter(Mandatory = $false)]
    [switch]$Harden
)

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

#Region Tests
# [DOMAIN OR WORKGROUP]
'';Write-Log -Level 4 -Message 'COMPUTER'
$ComputerSystem = Get-WmiObject Win32_ComputerSystem
if ($ComputerSystem.PartOfDomain -eq $false) {
    $DesiredFWProfile = 'Private'
    Write-Log -Level 0 -Message "This computer is not domain joined"
    Write-Log -Level 2 -Message "This computer need to be added to trustedhosts in WinRM-config on client, since it is part of a WORKGROUP!"
}
else {
    $DesiredFWProfile = 'Domain'
}

# [NET CONNECTION PROFILE - WARN IF ACTIVE PROFILE IS PUBLIC]
'';Write-Log -Level 4 -Message 'FIREWALL PROFILE'
$CurrentFirewallProfile = (Get-NetConnectionProfile).NetworkCategory
if ($CurrentFirewallProfile -eq 'Public') {
    Write-Log -Level 2 -Message "$CurrentFirewallProfile firewall-profile is active"
    Write-Log -Level 2 -Message "Please change profile to $DesiredFWProfile"
    
    ''
    Clear-Variable FixIt -ErrorAction SilentlyContinue
    $FixIt = Read-Host "Run 'Set-NetConnectionProfile -NetworkCategory $DesiredFWProfile'? (Y/N)"
    switch ($FixIt) {
        Y {            
            try {
                Set-NetConnectionProfile -NetworkCategory $DesiredFWProfile -ErrorAction Stop
                Write-Log -Level 1 -Message "Set-NetConnectionProfile - Profile changed to '$DesiredFWProfile'"
            }
            catch {
                Write-Log -Level 3 -Message "Set-NetConnectionProfile - Failed to change profile to '$DesiredFWProfile'. Error: $($_.Exception.Message)"
            }
        }
        N {
            Write-Log -Level 2 -Message 'Script aborted (N)';Exit
        }
        default { Write-Host 'Script aborted (invalid choice)';Exit}
    }
    ''
}
else {
    Write-Log -Level 0 -Message "$CurrentFirewallProfile firewall-profile is active"
}

# [WINRM SERVICE - VERIFY THAT IT IS RUNNING]
'';Write-Log -Level 4 -Message 'WINRM SERVICE STATUS'
if ((Get-Service WinRM).Status -eq 'Running') {
    Write-Log -Level 0 -Message "WinRM-service is running"
}
else {
    Write-Log -Level 2 -Message "WinRM-service is not running"
    Write-Log -Level 2 -Message "Please start before running this script (Start-Service WinRM)"

    ''
    Clear-Variable FixIt -ErrorAction SilentlyContinue
    $FixIt = Read-Host "Run 'Start-Service WinRM'? (Y/N)"
    switch ($FixIt) {
        Y {            
            try {
                Start-Service WinRM -ErrorAction Stop
                Write-Log -Level 1 -Message "Start-Service - Started"
            }
            catch {
                Write-Log -Level 3 -Message "Start-Service - Failed. Error: $($_.Exception.Message)"
            }
        }
        N {
            Write-Log -Level 2 -Message 'Script aborted (N)';Exit
        }
        default { Write-Host 'Script aborted (invalid choice)';Exit}
    }
    ''

}

# [WINRM PORT - GET LISTENERS]
'';Write-Log -Level 4 -Message 'WINRM HTTP LISTENER'
Clear-Variable Port -ErrorAction SilentlyContinue
$Listeners = Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate

if ($Listeners) {
    $HTTPPort = ($Listeners | Where-Object {$_.Transport -eq 'HTTP'}).Port
    $HTTPSPort = ($Listeners | Where-Object {$_.Transport -eq 'HTTPS'}).Port
    if ($HTTPPort) {
        Clear-Variable HTTPPortType -ErrorAction SilentlyContinue
        if ($HTTPPort -eq 5985) {
            $HTTPPortType = 'default'
        }
        else {
            $HTTPPortType = 'custom'
        }
        Write-Log -Level 0 -Message "HTTP-port is $HTTPPort ($HTTPPortType)"
        if ($ComputerSystem.PartOfDomain -eq $false) {
            Write-Log -Level 2 -Message "Kerberos-auth can not be used in a workgroup environment. WinRM should be HTTPS, if not, NTLM-auth will be sent in cleartext over the network!"
        }
        else {
            Write-Log -Level 2 -Message "Use hostname/FQDN when remoting to this server. When using IP, NTLM-auth is used, and sent in cleartext over the network!"
        }
    }
    else {
        Write-Log -Level 0 -Message "HTTP is not in use"
    }

    '';Write-Log -Level 4 -Message 'WINRM HTTPS LISTENER'
    if ($HTTPSPort) {
        Clear-Variable HTTPSPortType -ErrorAction SilentlyContinue
        if ($HTTPPort -eq 5986) {
            $HTTPSPortType = 'default'
        }
        else {
            $HTTPSPortType = 'custom'
        }
        Write-Log -Level 0 -Message "HTTPS-port is $HTTPPort ($HTTPSPortType)"    
    }
    else {
        Write-Log -Level 0 -Message "HTTPS is not in use"
        if ($ComputerSystem.PartOfDomain -eq $false) {
            Write-Log -Level 2 -Message "HTTPS should be used, since this computer is in a WORKGROUP. Basic- and negotiate/NTLM authentication will be sent cleartext over the network when not using HTTPS!"
        }
    }

    '';Write-Log -Level 4 -Message 'WINRM CHOSEN LISTENER'
    if     (!$HTTPPort -and $HTTPSPort)     { $ListenerToConfigure = $Listeners | Where-Object {$_.Transport -eq 'HTTPS'} }
    elseif ($HTTPPort -and !$HTTPSPort)     { $ListenerToConfigure = $Listeners | Where-Object {$_.Transport -eq 'HTTP'}  }
    elseif (!$HTTPPort -and !$HTTPSPort)    { Write-Log -Level 2 -Message "No active listener. Can not continue. Please enable PSRemoting (Enable-PSRemoting -Force)";Break }
    elseif ($HTTPPort -and $HTTPSPort)      { Write-Log -Level 2 -Message "Two active listeners. Should not be possible? Breaking";Break }
    Write-Log -Level 0 -Message "$($ListenerToConfigure.Transport) listener will be configured/used"
}
else {
    Write-Log -Level 2 -Message 'WinRM is not accepting connections.'
    Write-Log -Level 2 -Message 'Make sure PowerShell-remoting is enabled (Enable-PSRemoting -Force)'

    ''
    Clear-Variable FixIt -ErrorAction SilentlyContinue
    $FixIt = Read-Host "Run 'Enable-PSRemoting -Force'? (Y/N)"
    switch ($FixIt) {
        Y {            
            try {
                Enable-PSRemoting -Force -ErrorAction Stop
                Write-Log -Level 1 -Message "Enable-PSRemoting - Enabled"
            }
            catch {
                Write-Log -Level 3 -Message "Enable-PSRemoting - Failed. Error: $($_.Exception.Message)"
            }
        }
        N {
            Write-Log -Level 2 -Message 'Script aborted (N)';Exit
        }
        default { Write-Host 'Script aborted (invalid choice)';Exit}
    }
    ''
    
}

# [WINRM PORT - GET CURRENT SESSION CONFIGURATIONS]
'';Write-Log -Level 4 -Message "SESSION CONFIGS (PowerShell $($Host.Version.Major).$($Host.Version.Minor))"
Clear-Variable CurrentSessionConfigs, EnabledSessionConfigs, DisabledSessionConfigs -ErrorAction SilentlyContinue
$CurrentSessionConfigs = Get-PSSessionConfiguration | Where-Object {$_.PSVersion -match "^$($Host.Version.Major)\."}
$EnabledSessionConfigs = $CurrentSessionConfigs | Where-Object {$_.Enabled -eq $true}
$DisabledSessionConfigs = $CurrentSessionConfigs | Where-Object {$_.Enabled -eq $false}
if ($EnabledSessionConfigs) {
    Write-Log -Level 0 -Message "Enabled PSSessionConfigs: $($EnabledSessionConfigs.Count) ($(($EnabledSessionConfigs | Select-Object -ExpandProperty Name) -join ', '))"
}
else {
    Write-Log -Level 0 -Message "Enabled PSSessionConfigs: 0"
}
if ($DisabledSessionConfigs) {
    Write-Log -Level 0 -Message "Disabled PSSessionConfigs: $($DisabledSessionConfigs.Count) ($(($DisabledSessionConfigs | Select-Object -ExpandProperty Name) -join ', '))"    
}
else {
    Write-Log -Level 0 -Message "Disabled PSSessionConfigs: 0"
}
''
#Endregion Tests


#Region ParameterLogic
if (!$Harden -or !$WinRMPort -or !$PSSessionConfName) {
    '';Write-Log -Level 2 -Message "TO MAKE CHANGES, USE '-Harden' parameter together with '-WinRMPort' -and '-PSSessionConfName'";''
    Break
}
#Endregion ParameterLogic


#Region WinRM
# [PS-SESSION-CONFIGURATION - DISABLE DEFAULTS]
Clear-Variable ServiceRestartWanted -ErrorAction SilentlyContinue
$ServiceRestartWanted = $false
try {
    if ($Host.Version.Major -eq 7) {
        $DefaultSessionConfigs =  $CurrentSessionConfigs | Where-Object {$_.Name -match 'PowerShell7*' -and $_.Enabled -eq $true}
    }
    elseif ($Host.Version.Major -eq 5) {
        $DefaultSessionConfigs =  $CurrentSessionConfigs | Where-Object {$_.Name -match 'microsoft.*' -and $_.Enabled -eq $true}
    }
    $DefaultSessionConfigs | ForEach-Object {
        Disable-PSSessionConfiguration -Name $_.Name -Force -Confirm:$false -ErrorAction Stop
        Write-Log -Level 1 -Message "Disable-PSSessionConfiguration - Disabled '$($_.Name)'"
        $ServiceRestartWanted = $true
    }
}
catch {
    Write-Log -Level 3 -Message "Disable-PSSessionConfiguration - Failed to disable. Error:'$($_.Exception.Message)'"
}

# [PS-SESSION-CONFIGURATION - CREATE CUSTOM]
Clear-Variable Exist -ErrorAction SilentlyContinue    
$Exist = $CurrentSessionConfigs | Where-Object {$_.Name -eq $PSSessionConfName}
if ($Exist -and $Exist.Enabled -eq $true) {
    Write-Log -Level 0 -Message "Get-PSSessionConfiguration - '$PSSessionConfName' already exist, and is enabled"
}
elseif ($Exist -and $Exist.Enabled -eq $false) {
    Write-Log -Level 2 -Message "Get-PSSessionConfiguration - '$PSSessionConfName' already exist, but is disabled"        
    try {
        Enable-PSSessionConfiguration -Name $PSSessionConfName -Confirm:$false -ErrorAction Stop
        Write-Log -Level 1 -Message "Enable-PSSessionConfiguration - '$PSSessionConfName' was enabled"
        $ServiceRestartWanted = $true
    }
    catch {
        Write-Log -Level 3 -Message "Enable-PSSessionConfiguration - Failed to enable '$PSSessionConfName'. Error: $($_.Exception.Message)"
    }
}
else {
    Write-Log -Level 0 -Message "Get-PSSessionConfiguration - '$PSSessionConfName' does not exist. Will try to create session-config '$PSScriptRoot\Defaults-session-config.pssc'."
    try {
        New-PSSessionConfigurationFile -Path "$PSScriptRoot\Defaults-session-config.pssc" -Author Admin -ErrorAction Stop
        Write-Log -Level 1 -Message "New-PSSessionConfigurationFile - '$PSSessionConfName' configuration file was created"
    }
    catch {
        Write-Log -Level 3 -Message "New-PSSessionConfigurationFile - '$PSSessionConfName' failed to create configuration file. Error: $($_.Exception.Message)"
    }
    try {
        Register-PSSessionConfiguration -Name $PSSessionConfName -Path "$PSScriptRoot\Defaults-session-config.pssc" -NoServiceRestart -Force -ErrorAction Stop | Out-Null
        Write-Log -Level 1 -Message "Register-PSSessionConfiguration - '$PSSessionConfName' was registered"
        $ServiceRestartWanted = $true
    }
    catch {
        Write-Log -Level 3 -Message "Register-PSSessionConfiguration - Failed to register '$PSSessionConfName'. Error: $($_.Exception.Message)"
    }
}   

# [WINRM - CHANGE DEFAULT PORT]
if ($WinRMPort -ne $ListenerToConfigure.Port) {
    try {
        Set-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Address=$ListenerToConfigure.Address;Transport=$ListenerToConfigure.Transport} -ValueSet @{Port="$WinRMPort"} -ErrorAction Stop | Out-Null
        Write-Log -Level 1 -Message "Set-WSManInstance - $($ListenerToConfigure.Transport)-port for WinRM changed to '$WinRMPort'"
        $ServiceRestartWanted = $true
    }
    catch {
        Write-Log -Level 3 -Message "Set-WSManInstance - Failed to set $($ListenerToConfigure.Transport)-port to '$WinRMPort'. Error: $($_.Exception.Message)"
    }
}
else {
    Write-Log -Level 0 -Message "Get-WSManInstance - $($ListenerToConfigure.Transport)-port for WinRM is already set to '$($ListenerToConfigure.Port)'"
}

# [WINRM - RESTART SERVICE]
if ($ServiceRestartWanted) {
    try {
        Restart-Service WinRM -Force -ErrorAction Stop
        Write-Log -Level 1 -Message "Restart-Service - WinRM was restarted"
    }
    catch {
        Write-Log -Level 3 -Message "Restart-Service - Failed to restart WinRM $($_.Exception.Message)"
    }
}
#Endregion WinRM


#Region Firewall
# [FIREWALL - OPEN TCP CUSTOM WINRM PORT]
Clear-Variable FirewallRuleDisplayName -ErrorAction SilentlyContinue
$FirewallRuleDisplayName = "WinRM - $($ListenerToConfigure.Transport) custom port"
$FirewallRule = Get-NetFirewallRule -DisplayName $FirewallRuleDisplayName -ErrorAction SilentlyContinue
if ($FirewallRule) {
    Write-Log -Level 0 -Message "Get-NetFirewallRule - Rule '$FirewallRuleDisplayName' already exist"
    $FirewallRulePortFilter = $FirewallRule | Get-NetFirewallPortFilter

    if ($FirewallRulePortFilter.LocalPort -eq $WinRMPort) {
        Write-Log -Level 0 -Message "Get-NetFirewallPortFilter - Rule '$FirewallRuleDisplayName' has correct portfilter ($($FirewallRulePortFilter.LocalPort))"
    }
    else {
        Write-Log -Level 2 -Message "Get-NetFirewallPortFilter - Rule '$FirewallRuleDisplayName' has incorrect portfilter (current:$($FirewallRulePortFilter.LocalPort) / desired:$WinRMPort)"
        try {
            Set-NetFirewallRule -DisplayName $FirewallRuleDisplayName -LocalPort $WinRMPort -ErrorAction Stop
            Write-Log -Level 1 -Message "Set-NetFirewallRule - Rule '$FirewallRuleDisplayName' portfilter updated to allow TCP $WinRMPort"
        }
        catch {
            Write-Log -Level 3 -Message "Set-NetFirewallRule - Failed to update portfilter on rule '$FirewallRuleDisplayName' to allow TCP $WinRMPort. Error: $($_.Exception.Message)"
        }
    }
}
else {
    $FirewallParam = @{
        DisplayName = $FirewallRuleDisplayName
        Description = "Allow incomming traffic on TCP port $WinRMPort"
        Direction = 'Inbound'
        LocalPort = $WinRMPort
        Protocol = 'TCP'
        Action = 'Allow'
        Profile = 'Private', 'Domain'
        Program = 'System'
    }
    try {
        New-NetFirewallRule @FirewallParam -ErrorAction Stop -Confirm:$false | Out-Null
        Write-Log -Level 1 -Message "New-NetFirewallRule - New rule '$($FirewallParam.DisplayName)' created (TCP $WinRMPort inbound)"
    }
    catch {
        Write-Log -Level 3 -Message "New-NetFirewallRule - Failed to create new rule '$($FirewallParam.DisplayName)'. Error: $($_.Exception.Message)"
    }
}

# [FIREWALL - DISABLE DEFAULT RULE]
Clear-Variable EnabledDefaultRules -ErrorAction SilentlyContinue
$EnabledDefaultRules = Get-NetFirewallRule | Where-Object {$_.Name -match "WINRM-$($ListenerToConfigure.Transport)-in-TCP" -and $_.Enabled -eq $true}
if ($EnabledDefaultRules) {
    $EnabledDefaultRules | ForEach-Object {
        try {
            Disable-NetFirewallRule -Name $_.Name -ErrorAction Stop
            Write-Log -Level 1 -Message "Disable-NetFirewallRule - Disabled default rule '$($_.DisplayName)' ($($_.Profile))"
        }
        catch {
            Write-Log -Level 3 -Message "Disable-NetFirewallRule - Failed to disable default rule '$($_.DisplayName)' ($($_.Profile)). Error: $($_.Exception.Message)"
        }
    }
}
else {
    Write-Log -Level 0 -Message "Get-NetFirewallRule - Default firewall rules for WinRM $($ListenerToConfigure.Transport) is already disabled or deleted"
}
#Endregion Firewall