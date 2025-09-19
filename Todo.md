# To-do

### WinRM-Harden
* Maybe: Consider to make script fix HTTPS setup or SSH

### Service functionality
* Mutation -> Tested. Works. Make optional.
  * Using same seed as OTP, but set to 1 hour rotation (3600 sec) and 2 digits. Now both server and client know the same 2 digit 10..99. So I can use baseport + mutationport to determine current port. Loop inside service will check this every 40 sec and update to new listenerport if changed.
  * Other ideas: Could be checking the temperature in a specific place, then adding or subracting from base-port on temperature value. Let external API do the rounding og decimals. Could use date or time.. could do alot of things, but some require internet connection -> avoid.

### Service security
* Make sure service path has no spaces, and/or is not unquoted
```PowerShell
sc.exe create MyService binPath= "`"C:\Program Files\srvstart\srvstart.exe`" MyService"
```
* Make sure that correct ACL is set on service folder/location
  * .ini contains seed key and point to the script that should run and the .ps1 can be modified for code execution as fit

### WSMan ennumeration
If the attacker has uncloaked WSMAN, found the correct port, and have username and password - the PSSessionConfigurationName could be ennumerated like so:
```PowerShell
Connect-WSMan 10.100.100.10 -Port 3000 -Credential (Get-Credentials)
Get-ChildItem WSMan:\10.100.100.10\Plugin\
```

We can not set AllowRemoteAccess to false, as this affects PowerShell remoting too (unless using ssh).
What we can do is changing the ACL on the remote system, so that only admins can ennumerate:
```PowerShell
Set-Item WSMan:\localhost\Service\RootSDDL "O:NSG:BAD:P(A;;GA;;;BA)"
```
Will not help if credentials has admin-rights.


### Service core behaviour
* Implement actions on service crash, stop or OS-shutdown! ⚠️
* Consider converting to NSSM for service creation?

### Service logging
* Some logging, like expected OTP value (debug only), and initiall seed-key (never) should not be logged to eventviwer -> Almost there ➗ (OTP still exposed. Moved to monitor, but noe removed from eventlogs)
* If a user has remote eventlog viwer rights, or all logs (including custom logs) are gathered in a SIEM, this info is not protected.
* Solution? Make a debug parameter for expected vs. received OTP, not log by default -> Seems I had already thought of this ✅

### Service installer
* Verify that it is listening to expected port after starting (method is already in place inside monitor function)
* Make optional parameter so specify service install folder (some comments on folder ACL?)
* Check dependencies (check that binary dependencies are store beside script, or in c:\windows, if not download and unzip?)
* Could use parameter sets instead of manual script logic for parameter combos

### Stability
* Make the secvice run for weeks. Check its memory and CPU consumption and verifi that it still works
  * Typically the service uses < 1% CPU and ~15MB of RAM (srvstart.exe + PowerShell.exe). Verify over time.
