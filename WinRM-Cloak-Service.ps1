# TO-DO

# Vulnerabilities: Suspicable to script injection attacks? Seemingly no, but look deeper
#   - https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection?view=powershell-7.4
#   - For safe measure, dont handle non-correct strings at all, just ignore (no out console or log)

# Secret string: Will the secret be trapped in transcriptions, PS-readline, history or PowerShell operational logs? Most likely.
#   - Load the secret string from a password manager, secure string etc, so that it will not be stored cleartext on disk or PStranscription location (could be network share).
#   - Find another way to store the string so that, non-admin users can not read it. Could set ACL on the script itself, or store secure string as service user? hmmm.

# Performance: Look into the performance of this loop.
#   - I'm sure there are ways to make this listener more light weight. Not a priority atm.

Param(
    $Port
    #$ServiceRunningTime (Parameterize time to stay open/keep WinRM running.)
    #$SecureString (Parameterize the secure string? Can non admins read service start parameters? check.)
)
$endpoint  = new-object System.Net.IPEndPoint( [IPAddress]::Any, $Port)
$udpclient = new-object System.Net.Sockets.UdpClient $Port
$udpclient.Client.SendBufferSize = 0
$udpclient.Client.ReceiveBufferSize = 1

while ($true) {
    Start-Sleep -Seconds 0.5
    if ($udpclient.Available) {        
        $content = $udpclient.Receive([ref]$endpoint)
        if ($content) {            
            $String = [Text.Encoding]::ASCII.GetString($content)
            if ($String -ceq 'Knock knock! Secret sauce') {
                $udpclient.Client.ReceiveBufferSize = 0
                
                # Uncomment for interactive testing, to see when correct string is sent to UDP-listener
                #Write-Host "$($endpoint.Address.IPAddressToString):$($endpoint.Port) - De-cloaked! ($String)" -ForegroundColor Magenta
                
                Start-Service WinRM
                Start-Sleep -Seconds 600
                Stop-Service WinRM -Force
                $udpclient.Client.ReceiveBufferSize = 1                
            }
            # Uncomment for interactive testing, to see any string recieved by UDP-listener
            #else {                
            #   Write-Host "$($endpoint.Address.IPAddressToString):$($endpoint.Port) - $String"
            #}
        }        
    }
}
$udpclient.Close()