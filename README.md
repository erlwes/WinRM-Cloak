# WinRM-Cloak
Hardening and cloaking of PowerShell-remoting. In short making the WinRM-service avoid detection of nmap/port-scans, add 2FA protection using OTP and a few other security by obscurity changes to the service.

I was inspired to create this service after learning a lot about PowerShell-remoting from the great [Yossi Sassi (1nTh35h3ll)](https://github.com/YossiSassi) on his 4-day "PowerShell for Security Professionals"-course @ HackCon #19. The course made an impression on we, and changed my mindset on how I approch defensive IT-security.

The usecase I had in mind, was protecting a jumpstation/paw/entry point. Not running this service "everywhere".

## Video demo (of old version)

https://github.com/user-attachments/assets/e9a98058-e1a6-46f8-8fc7-5b00ee3f0750

No video of new version. Yet.

### This is the idea:
1. The default port on WinRM-service is changed, so that it is no longer listening on 5985/5986
2. The default PSSession configurations are removed, so that one will have to specify correct name for existing session config in order to connect
3. The WinRM service is not running
4. A listener on UDP port 10000 (configurable) is waiting for the correct TOTP code, if received, the WinRM-service is started, and the specific client is given access by adding its IP to the Windows firewall-rule
5. Client access expires after 30 minutes (default)
6. When no connections active, the WinRM service is shut down
7. The listener has no response buffer, and gives zero reply (as if packet is dropped and connection times out). This makes it undetactable by nmap/port-scanning.

### The attacker would have to
1. Figure out that a listener is active on UDP 10000 (nmap will not detect. No resposebuffer on listener/no reply is returned)
2. Figure out the correct seed/key in order to generate the correct OTP that is accepted by the listener, which in turn opens WinRM on TCP 3000 (non-default port)
3. Guess the correct PSSession configuration name (defaults are removed), or know how to ennumerate these when having username, password and correct port.
4. Have a username and a password for the remote server, and connect to it

### Combine with
1. JIT on the PSSession configuration for limiting
2. HTTPS or SSH as bearer
3. New non-default ports that are not part of nmap top 10000 ports, or in the high/dynamic range :) (nmap --top-ports 10000 localhost -v -oG -)
4. Strict firewall rules, so that other remoting and attack vectors are unavaliable (eg. RDP, SMB etc.)
5. Logging of attempts vs. default WinRM-ports
6. Non-default username for pivileged accounts with remoting enabled (eg. not username "Administrator" or "Admin")
7. Scriptblock logging/transcripts

## Example setup and testing

### 1. Download required files
Download NSSM service manager, this repos, create a folder for the service, extract nessasary files from archive
```Pwsh
$need = @(
    'https://github.com/erlwes/WinRM-Cloak/archive/refs/heads/main.zip;WinRM-Cloak-main.zip'
    'https://nssm.cc/ci/nssm-2.24-103-gdee49fc.zip;nssm-2.24-103-gdee49fc.zip'
)

$installDir = "$env:windir\WinRM-Cloak"
New-Item $installDir -ItemType Directory -Force | Out-Null

Foreach ($thing in $need) {
    ''
    $url = ($thing -split ';')[0]
    $zip = ($thing -split ';')[1]
    $foldername = $zip -replace '.zip$'

    Write-Host $foldername -ForegroundColor Magenta
    While (!(Test-Path $installDir\$zip)) {
	    try {
            Invoke-WebRequest "$url" -Outfile "$installDir\$zip" -ErrorAction Stop
            Write-Host "Invoke-WebRequest - Downloaded '$url'"
        }
        catch {
            # NSSM has unreliable NGIX-server, so we might have to try several times.
        }
	    Start-Sleep -Seconds 2
    }

    # Unblock downloaded file
    Unblock-File -Path "$installDir\$zip" -Confirm:$false
    Write-Host "Unblock-File - '$installDir\$zip'"

    # Extract archive
    try {
        Expand-Archive -Path "$installDir\$zip" -DestinationPath $installDir -ErrorAction Stop -Force
        Write-Host "Expand-Archive - Archive '$zip' extracted to '$installDir\$foldername'"
    }
    catch {
        Write-Host "Expand-Archive - Failed to extract archive '$zip' to '$installDir\$foldername'. Error: $($_.Exception.Message)" -ForegroundColor Red
        Break
    }

    # Copy needed files from extracted folders to install dir
    if ($zip -match 'nssm') {
        # Get required x86 NSSM-files from Archive
        Write-Host "Copy-Item - Copy the required files from extracted folder-structure"
        Copy-Item  -Path "$installDir\$foldername\win32\nssm.*" -Destination "$installDir" -Force
    }
    elseif ($zip -match 'winrm-cloak') {
        Write-Host "Copy-Item - Copy the required files from extracted folder-structure"
        Copy-Item -Path "$installDir\$foldername\*.ps1" -Destination "$installDir" -Force
    }

    # Delete archive and extracted folder structure
    Write-Host "Remove-Item - Delete extracted folder and items archive ('$installDir\$foldername')"
    Remove-Item "$installDir\$foldername" -Recurse -Force
    
    Write-Host "Remove-Item - Delete downloaded archive ('$installDir\$zip')"
    Remove-Item "$installDir\$zip" -Force
    ''
    Set-Location $env:windir\WinRM-Cloak
}
```

### 2. Install service on a server
```PowerShell
Set-Location $env:windir\WinRM-Cloak
$WinRMPort = 30834
$CloakPort = 43654
$PSSessionConfigName = 'Rick'
.\WinRM-Harden.ps1 -WinRMPort $WinRMPort -PSSessionConfName $PSSessionConfigName -Harden
.\WinRM-Cloak-Manager.ps1 -CloakPort $CloakPort
```

### 3. Test from a client
```PwSh
$WinRMPort = 30834
$CloakPort = 43654
$PSSessionConfigName = 'Rick'
$Computer = 'ew-srv02'
$Creds = (Get-Credential "$Computer\Adminispagetti")

$Parameters = @{
    CloakPort = $CloakPort
    WinRMPort = $WinRMPort
    Computer = $Computer
    Creds = $Creds
    PSSessionConfName = $PSSessionConfigName
}

.\WinRM-DecloakAndConnect.ps1 @Parameters
```

### 4. Monitor service on server
Passive monitoring by checking eventlogs, services and netstat.
```PwSh
cd $env:windir\WinRM-Cloak
.\WinRM-Cloak-Manager.ps1 -Monitor
```

### 4. Remove cloak-service and hardening on server
Passive monitoring by checking eventlogs, services and netstat.
```PwSh
cd $env:windir\WinRM-Cloak
.\WinRM-Cloak-Manager.ps1 -Remove
.\WinRM-Harden.ps1 -Reset
```
