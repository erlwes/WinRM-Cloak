# WinRM-Cloak

Notes for testing:
```PowerShell
.\WinRM-Harden.ps1 -WinRMPort 10000 -PSSessionConfName MySessionConfig -Harden
.\WinRM-Cloak.ps1 -CloakPort 3000
Start-Service WinRM-Cloak
$Creds = (Get-Credential -Credential "$(Hostname)\Temp")
.\WinRM-DecloakAndConnect.ps1 -CloakPort 3000 -WinRMPort 10000 -SecretString 'Knock knock! Secret sauce' -Computer Localhost -PSSessionConfName MySessionConfig -Creds $Creds
# $PSSessionOption
```

**Dependencies**
[srvstart](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip): srvstart.exe, srvstart.dll and logger.dll from this [zip](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip).

# To-do
**WinRM-Harden (hardening script)**
1. Look into HTTPS setup with certificates. Offer to set up with selfsigned. Important in workgroups/non-domain environment

**WinRM-Cloak (service installer)**
1. Attempt to start service if successfully created
3. Verify that it is listening to expected port after starting (method is already in place inside monitor function)
4. Make optional parameter so specify service install folder (some comments on folder ACL?)
5. Check dependencies (check that binary dependencies are store beside script, or in c:\windows, if not download and unzip?)
6. Could use parameter sets instead of manual script logic for parameter combos
7. Need to parameterise the secret string on service install

**WinRM-Cloak-Service (UDP listener/service)**
1. Try to make sure that the service in not suspicable to script injection attacks
2. Check if performance of listening loop can be improved
3. Parameterize open-for-duration (10m/600s for now)
4. Parameterize secret string. Check if non-admins can read service start parameters? yes? no? A bit too late if already on server, so might not be a big deal.

**WinRM-DecloakAndConnect (client/connect)**
Needs more work, but seems to work ok for now..

