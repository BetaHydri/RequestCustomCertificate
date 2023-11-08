# RequestCustomCertificate

## This script requests custom certificates for a list of servers and exports them as PFX files.

- This script requests custom certificates based on a .inf request template for a list of servers and exports them as PFX files.<br>
- If the request must be approved by the CA admin, the RequestIDs will be stored in the array and the requestID will be saved in the output folder.<br>

### .PARAMETER InfFilePath
    Specifies the path to the INF file that contains the certificate template information.

### .PARAMETER servernames
    Specifies an array of server names for which the certificate is requested.

## .PARAMETER CAName
    Specifies the name of the certification authority (CA) that issues the certificate.

### .PARAMETER OutputDir
    Specifies the path to the output directory where the certificate request files and PFX files are saved.

### .PARAMETER RemoveTempFiles
    Specifies whether to remove the temporary files created during the certificate request process.

> 📘INFO
> 
> Includes functions:
> - <b>New-CustomCertificateRequest</b> - Returns requestIDs when certificate requests returns state <b>pending</b>, or imports .cer with private key files when certificate request was in state <b>issued</b>.
> - <b>Export-CertificateAsPFXByProperty</b> - Exports the certificates as PFX file by protecting the .pfx using the password. 
   
### Sample usage:
```
# Define empty Array to store the Thumbprints of the certificates to export
$MyThumbprints = @()

# Define the FQDNs of all Servers that will be in the certificate request to the CAName
$servers = "Test07.contoso.com", "Test08.contoso.com", "Test09.contoso.com"

# Request the certificates and store the RequestIDs or Thumbprints in an array
# If request must be approved by CA admin, the RequestIDs will be stored in the array and the requestID will be saved in the output folder
$requestIDs = New-CustomCertificateRequest -InfFilePath .\CertTemplate.inf -servernames $servers -CAName 'AO-PKI.contoso.com\contoso-AO-PKI-CA' -OutputDir '.\' -RemoveTempFiles

# Export the certificates as PFX files after searching for the Thumbprints in requestIDs output.
[string[]]$MyThumbprints = Search-Output -InputContent $requestIDs -SearchString 'Thumbprint:'
if ($MyThumbprints.Count -ne 0) {
    $password = Read-SecureString -Prompt "Enter password for PFX file"  
    foreach ($thumbprint in $MyThumbprints) {
        $thumbprint = $($thumbprint.Substring(14))
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }
        $cert | Export-CertificateAsPFXByProperty -Property Thumbprint -Value $thumbprint -ExportPath ".\$($cert.DnsNameList.Unicode).pfx" -Password $password
    }
}
else {
    Write-Error "No Thumbprints found in var requestIDs"
    $requestIDs
    return $false
}
```
