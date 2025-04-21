# WinRM-Cloak
Hardening and cloaking of PowerShell-remoting. In short making the WinRM-service avoid detection of nmap/port-scans, add 2FA protection using OTP and a few other security by obscurity changes to the service.

## Video demo

https://github.com/user-attachments/assets/e9a98058-e1a6-46f8-8fc7-5b00ee3f0750


### This is the idea:
1. The default port on WinRM-service is changed, so that it is no longer listening on 5985/5986
2. The default PSSession configurations are removed, so that one will have to specify correct name for existing session config in order to connect
3. The WinRM service is not running by default
4. A listener on UDP port 10000 is waiting for the correct TOTP code, if received, then starts WinRM-service for 10 minutes

### The attacker would have to
1. Figure out that a listener is active on UDP 10000 (nmap will not detect. No resposebuffer on listener/no reply is returned)
2. Figure out the correct seed/key in order to generate the correct OTP that is accepted by the listener, which in turn opens WinRM on TCP 3000 (non-default port)
3. Guess the correct PSSession configuration name (defaults are removed). I dont think one can enumerate the session configs remote?
4. Have a username and a password for the remote server, and connect to it

### The POC does not cover
1. JIT for the session-config
2. Use of WinRM over HTTPS or SSH (now possible)

### Combine with
1. New non-default ports that are not part of nmap top 10000 ports, or in the high/dynamic range :) (nmap --top-ports 10000 localhost -v -oG -)
2. Strict firewall rules, so that other remoting and attack vectors are unavaliable (eg. RDP, SMB etc.)
3. Logging of attempts vs. default WinRM-ports
4. Non-default username for pivileged accounts with remoting enabled (eg. not username "Administrator" or "Admin")

### Example setup and testing
```PowerShell
# SERVER - Harden WinRM and install Cloak-service
$WinRMPort = 3000
$CloakPort = 10000
$PSSessionConfigName = 'MySessionConfig'
.\WinRM-Harden.ps1 -WinRMPort $WinRMPort -PSSessionConfName $PSSessionConfigName -Harden
.\WinRM-Cloak.ps1 -CloakPort $CloakPort #Take note of secret key/seed key for TOTP from console, or get from "WinRM-Cloak-Service.ini" after install.

# CLIENT - De-cloak and connect
$WinRMPort = 3000
$CloakPort = 10000
$PSSessionConfigName = 'MySessionConfig'
$Computer = '10.10.10.100'
$Creds = (Get-Credential 'WinDev2407Eval\Test')

$Parameters = @{
    CloakPort = $CloakPort
    WinRMPort = $WinRMPort
    Computer = $Computer
    Creds = $Creds
    PSSessionConfName = $PSSessionConfigName
}

.\WinRM-DecloakAndConnect.ps1 @Parameters #Make sure the seed key is entered into an authenticator, so that you have your OTP ready (or send the key itself using TOTPSecreyKey-parameter)
```

### Dependencies
[srvstart](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip): srvstart.exe, srvstart.dll and logger.dll from this [zip](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip).
