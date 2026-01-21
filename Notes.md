# Notes

### Use an authenticator
* Add the seed/secret into a authenticator like microsoft authenticator, google authenticator or any other that support TOTP.

### Service security
* Make sure service path has no spaces, and/or is not unquoted. Default path "C:\Widows\WinRM-Cloak" is ok (no spaces).
* Limit read and write access to the service folder. Modify access can edit the service, read access can get TOTP seed and other info

### Notes on preventing remote ennumeration of PSSessionConfiguration-names
To harden the setup further, one can prevent remote ennumeration of PSSessionConfiruration names. The permissions below, prevent users (admins too) from ennumerating the config names via. `Connect-WSMan`, by changing ACL on RootSDDL.
*Be warned*, this change probably have strange side-effects, but for me it has worked ok 🤷‍♂️

*Backup*
```PwSh
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service').RootSDDL | Out-File "$Env:windir\WinRM-Cloak\WSMAN-RootSDDL.bak"
```

*Deny access*
```PwSh
# Dont allow reads from remote-interactive sessions: 'O:NSG:BAD:P(A;;GR;;;IU)(A;;GX;;;IU)(A;;GX;;;BA)(A;;GX;;;RM)'
Set-Item WSMan:\localhost\Service\RootSDDL 'O:NSG:BAD:P(A;;GR;;;IU)(A;;GX;;;IU)(A;;GX;;;BA)(A;;GX;;;RM)'
Restart-Service WinRM
```

*Reset to default*
```PwSh
# Default: O:NSG:BAD:P(A;;GA;;;BA)(A;;GR;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" /v RootSDDL /t REG_SZ /d "$(Get-Content "$Env:windir\WinRM-Cloak\WSMAN-RootSDDL.bak")" /f
Restart-Service WinRM
```

### Service permissionlevel
By default NSSM runs as "Local System", idealy we set it to "Network Service", or som other less privileges mode. Virtual service. Something.
I originaly ran it with the "Network Service"-principal, and that worked well untill I wanted service to controll Windows firewall for granular access (specific IPs)


### Service architecture
I noticed that x64 version of NSSM and PowerShell used 140% more RAM (~85MB) vs. their x86 process eqvivalents (~35MB).
I went with 32-bit. Also ok for compatability, I guess. Security-wise, x86 processes have less ASLR entrophy compared to x64.


### Stealth/nmap testing

*UDP SCAN VS. CLOAK SERVICE PORT*
```PwSh
# Never responds, because responsebuffer is always 0. Does not show up.
nmap -sU -p 43650-43660 192.168.10.20
```

*TCP SCAN VS. CUSTOM WINRM PORT*
```PwSh
# Responds when de-cloaked, but only to the IPs that have provided the correct OTP, and therefore is allowed access because IP is added to firewall rule.
nmap -Pn -p 30830-30840 192.168.10.20
```
