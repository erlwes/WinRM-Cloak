# To-do

### WinRM-Harden
* Bug: When checking if port is already in use, I have hard-coded the port number to 139 or something in line 323. Fix so that it checks the correct port and not a static one.
* Maybe: Consider to make script fix HTTPS setup or SSH

### Service functionality
* When un-cloaking, before starting the service, update the firewall-rule for WinRM, and specify source IP, so that only the IP that provided correct OTP is allowed in firewall-rule.
  * I did initialy want to disable the firewall rule after a short time, but this terminated the WinRM-session (same happens with RDP over TCP regardless of NLA). I was sure that existing sessions was kept alive, but nay
  * To avoid open ports avaliable for 600 sec (or whatever time configured), filtering by IP is the second best option (that I can think of)
* Idea
  * Instead of using static TCP-port on WinRM-service, the port could be mutating/changed before each start. Something known to both client and server, for example 3000 + current day of month, or something else known to both server and client

### Service security
* Make sure service path has no spaces, and/or is not unquoted
```PowerShell
sc.exe create MyService binPath= "`"C:\Program Files\srvstart\srvstart.exe`" MyService"
```
* Make sure that correct ACL is set on service folder/location
  * .ini contains seed key and point to the script that should run and the .ps1 can be modified for code execution as fit

### Service core behaviour
* Implement actions on service crash, stop or OS-shutdown! ⚠️
* Consider converting to NSSM for service creation?

### Service installer
* Verify that it is listening to expected port after starting (method is already in place inside monitor function)
* Make optional parameter so specify service install folder (some comments on folder ACL?)
* Check dependencies (check that binary dependencies are store beside script, or in c:\windows, if not download and unzip?)
* Could use parameter sets instead of manual script logic for parameter combos

### Stability
* Make the secvice run for weeks. Check its memory and CPU consumption and verifi that it still works
  * Typically the service uses < 1% CPU and ~15MB of RAM (srvstart.exe + PowerShell.exe). Verify over time.
