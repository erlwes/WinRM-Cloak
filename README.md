# WinRM-Cloak

Notes for testing:
```PowerShell
# SERVER - Harden WinRM and install Cloak-service
$WinRMPort = 3000
$CloakPort = 10000
$PSSessionConfigName = 'MySessionConfig'
$Computer = '10.90.90.31'
$Creds = (Get-Credential 'WinDev2407Eval\Test')

.\WinRM-Harden.ps1 -WinRMPort 3000 -PSSessionConfName $PSSessionConfigName -Harden
.\WinRM-Cloak.ps1 -CloakPort 10000 #Take note of secret key/seed key for TOTP from console, or get from "WinRM-Cloak-Service.ini" after install.

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

**WinRM-DecloakAndConnect (client/connect)**
1. ...

