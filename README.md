# WinRM-Cloak
Hardening and cloaking of remote access via. PowerShell-remoting.

Download and view this video-demo of the setup:
https://github.com/user-attachments/assets/e9a98058-e1a6-46f8-8fc7-5b00ee3f0750



### This is the idea:
1. The default port on WinRM-server is changed, so that it is no longer listening on 5985/5986
2. The default PSSession configurations are removed, so that one will have to specify correct name for exising session config in order to connect
3. The WinRM service is not running by default
4. A listener on UDP port 10000 is waiting for the correct TOTP code, if received, then starts WinRM-service for 10 minutes. This listener gives 0 response, and nmap will not detect it.

### The attacker would have to
1. Figure out that a listener is active on UDP 10.000 (nmap detects nothing. No resposebuffer on listener, and no reply is sendt back)
2. Figure out the correct seed-string in order to generate the correct OTP that is accepted by the listener, wich in turn opens WinRM on TCP 3000.
3. Guess the correct PSSession configuration name (defaults are removed). I dont think one can ennumerate the session configs remote?
4. Have a username and a passord for the remote server, and connect to it

### The POC does not cover
1. JIT for the session-config
2. Use of WinRM over HTTPS or SSH (now possible)


Notes for testing:
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

.\WinRM-DecloakAndConnect.ps1 @Parameters #Make sure the seed key is entered into an autenticator, so that you have your OTP ready (or send the key itself using TOTPSecreyKey-parameter)
```

**Dependencies**
[srvstart](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip): srvstart.exe, srvstart.dll and logger.dll from this [zip](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip).

# To-do
**WinRM-Harden (hardening script)**
1. Look into HTTPS setup with certificates. Offer to set up with selfsigned. Important in workgroups/non-domain environment ❗

**WinRM-Cloak (service installer)**
1. Verify that it is listening to expected port after starting (method is already in place inside monitor function)
2. Make optional parameter so specify service install folder (some comments on folder ACL?)
3. Check dependencies (check that binary dependencies are store beside script, or in c:\windows, if not download and unzip?)
4. Could use parameter sets instead of manual script logic for parameter combos


**WinRM-Cloak-Service (UDP listener/service)**
1. Implement actions on service crash, stop or OS-shutdown! ⚠️
