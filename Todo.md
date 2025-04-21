### To-do
1. WinRM-Harden -> when checking if port is already in use, I have hard-coded the port number to 139 or something in line 323. Fix so that it checks the correct port and not a static one.
2. When un-cloaking, before starting the service, update the firewall-rule for WinRM, and specify source IP, so that only the IP that provided correct OTP is allowed in firewall-rule.
  - I did initialy want to disable the firewall rule after a short time, but this terminated the WinRM-session (same happens with RDP over TCP regardless of NLA). I was sure that existing sessions was kept alive, but nay
  - To avoid open ports avaliable for 600 sec (or whatever time configured), filtering by IP is the second best option (that I can think of) 

### Ideas
**WinRM-Harden (hardening script)**
1. Change to WinRM over HTTPS. Offer to set up with self signed. Important in workgroups/non-domain environment to avoid NTLM❗
OR
2. Use SSH. 

**WinRM-Cloak (service installer)**
1. Verify that it is listening to expected port after starting (method is already in place inside monitor function)
2. Make optional parameter so specify service install folder (some comments on folder ACL?)
3. Check dependencies (check that binary dependencies are store beside script, or in c:\windows, if not download and unzip?)
4. Could use parameter sets instead of manual script logic for parameter combos

**WinRM-Cloak-Service (UDP listener/service)**
1. Implement actions on service crash, stop or OS-shutdown! ⚠️
2. Consider converting to NSSM for service creation?
3. Instead of using static TCP-port on WinRM-service, the port could be mutating/changed before each start. Something known to both client and server, for example 3000 + current day of month, or something else known to both server and client
