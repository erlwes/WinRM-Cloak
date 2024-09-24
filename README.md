# WinRM-Cloak

Work in progress...

## TO-DO

**General**
1. Separate harden WinRM script and install WinRM-cloaker to separate scripts. The cloak is a bit niche, and some of the actions are separte. If not installing service, one woult not set winrm startup to manual etc.

**Installer**
1. Check if session config already exist
2. Handle SC CREATE if service already exist (Exitcode 1073)
3. Offer to start service after create?
4. Check if listener is active after starting?
5. Could to an install path parameter. This way one could ensure that non-admins will not be able to access/modify service files (prevent service hijack or read of secret string)
6. Could check that binary dependencies are store beside script, or in c:\windows, if not download and unzip? (srvstart.exe)
7. Could use parameter sets instead of manual script logic for parameter combos

**WinRM-Cloak service**
1. Try to make sure that the service in not suspicable to script injection attacks
2. Check if performance of listening loop can be improved
3. Could add logging to disk for successfull "unlocks", and start, stop service etc. Or log all connecting IPs, but only correct strings?
4. Parameterize open-for-duration (10m/600s for now)
5. Parameterize secret string. Check if non-admins can read service start parameters? yes? no? A bit too late if already on server, so might not be a big deal.

**Client**
1. Create a client function that both de-cloaks AND connect using Enter-PSSession in one. Ideally loading the secret string from password manager. Hmmm still visible in transcripts? Dual edged blade. Test this.


## Dependencies:
[srvstart](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip): srvstart.exe, srvstart.dll and logger.dll from this [zip](https://github.com/rozanski/srvstart/blob/master/srvstart/srvstart_run.v110.zip).
