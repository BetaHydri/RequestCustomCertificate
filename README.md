# RequestCustomCertificate

## This script requests custom certificates for a list of servers and exports them as PFX files.

- This script requests custom certificates based on a .inf request template for a list of servers and exports them as PFX files.<br>
- If the request must be approved by the CA admin, the RequestIDs will be stored in the array and the requestID will be saved in the output directory.<br>

### .PARAMETER InfFilePath
    Specifies the path to the INF file that contains the certificate template information.

### .PARAMETER servernames
    Specifies an array of server names for which the certificate is requested.

### .PARAMETER CAName
    Specifies the name of the certification authority (CA) that issues the certificate.

### .PARAMETER OutputDir
    Specifies the path to the output directory where the certificate request files and PFX files are saved.

### .PARAMETER RemoveTempFiles
    Specifies whether to remove the temporary files created during the certificate request process.

> 📘INFO
> 
> New functions + helpers:
> - <b>New-CustomCertificateRequest</b> - Returns requestIDs when certificate requests returns state <b>pending</b>, or imports .cer with private key files when certificate request was in state <b>issued</b>.
> - <b>Export-CertificateAsPFXByProperty</b> - Exports the certificates as PFX file by protecting the .pfx using the password.
> - <b>Search-Output</b> - Searches for a specified string in an array or string input and returns all matches that contain the search string. 
   
### Sample usage:
```
## MAIN Program
$certs = @()
# Define the FQDNs of all Servers that will be in the certificate request to the CAName
$servers = "Test07.contoso.com", "Test08.contoso.com", "Test09.contoso.com"

# Request the certificates and store the RequestIDs or Thumbprints in an array
# If request must be approved by CA admin, the RequestIDs will be stored in the array and the requestID will be saved in the output folder
$requestIDs = New-CustomCertificateRequest -InfFilePath .\CertTemplate.inf -servernames $servers -CAName 'AO-PKI.contoso.com\contoso-AO-PKI-CA' -OutputDir '.\' -RemoveTempFiles

if ($requestIDs -eq $false) {
    Write-Error "Error while requesting certificates"
    return $false
}
else {
    Write-Output "Exporting certificates as PFX files..."

    # Export the certificates as PFX files after searching for the Thumbprints in requestIDs output.
    foreach ($server in $servers) {
        $certs += Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "RDP_$($server)" }
    }
    if ($certs.Count -ne 0) {
        $password = Read-SecureString -Prompt "Enter password for PFX file"  
        foreach ($cert in $certs) {
            $cert | Export-CertificateAsPFXByProperty -Property 'Thumbprint' -Value $cert.Thumbprint -ExportPath ".\$($cert.DnsNameList.Unicode).pfx" -Password $password
        }
    }
    else {
        Write-Error "No Thumbprints found in var requestIDs"
        $requestIDs
        return $false
    }
}
```
