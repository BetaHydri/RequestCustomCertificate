#region functions

<#
.SYNOPSIS
Updates the content of all .inf files in a specified folder by replacing the host name with a list of server names.

.PARAMETER FolderPath
The path to the folder containing the .inf files.

.PARAMETER servernames
An array of server names to replace the host name with.

.EXAMPLE
Update-InfFiles -FolderPath "C:\InfFiles" -servernames "Server1", "Server2"

This example updates the content of all .inf files in the "C:\InfFiles" folder by replacing the host name with "Server1" and "Server2".
#>
function Update-InfFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderPath,
        [Parameter(Mandatory = $true)]
        [array]$servernames
    )
    
    $infFiles = Get-ChildItem -Path $FolderPath -Filter *.inf
    
    foreach ($file in $infFiles) {
        $content = Get-Content -Path $file.FullName -Raw
        foreach ($server in $servernames) {
            $content = $content -replace $Host, $server
        }
    
        Write-Output $content
    }
}

<#
    .SYNOPSIS
    Exports a certificate with a specific property value as a PFX file.
    
    .DESCRIPTION
    This function exports a certificate with a specific property value as a PFX file to the specified export path. The property and value are used to filter the certificates in the LocalMachine\My store.
    
    .PARAMETER Property
    The name of the certificate property to filter on.
    
    .PARAMETER Value
    The value of the certificate property to filter on.
    
    .PARAMETER ExportPath
    The path where the exported PFX file will be saved.
    
    .PARAMETER Password
    The password to protect the exported PFX file.
    
    .EXAMPLE
    Export-CertificateAsPFXByProperty -Property "Subject" -Value "CN=www.contoso.com" -ExportPath "C:\certs\www.contoso.com.pfx" -Password $securePassword
    
    Exports the certificate with Subject equal to "CN=www.contoso.com" as a PFX file to "C:\certs\www.contoso.com.pfx" with the specified password.
    
    .NOTES
    Author: Jan Tiedemann
    Date: 06/11/2023
#>
function Export-CertificateAsPFXByProperty {
    [CmdletBinding()]
    param(
        [string]$Property,
        [string]$Value,
        [string]$ExportPath,
        [securestring]$Password
    )
    
    $certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.$($Property) -eq $Value }
    if ($certs.Count -eq 0) {
        Write-Error "No certificate found with $Property equal to $Value"
        return $false
    }
    
    $cert = $certs[0]
    try {
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password)
        [System.IO.File]::WriteAllBytes($ExportPath, $certBytes)
        return $true
    }
    catch {
        Write-Error "Not allowed to export found certificate with $Property equal to $Value"
        return $false
    }
}

<#
    .SYNOPSIS
        Reads a secure string from the user input.
    .DESCRIPTION
        Prompts the user to enter a secure string and returns the entered value as a secure string.
    .PARAMETER Prompt
        The message to display to the user when prompting for input.
    .EXAMPLE
        $secureString = Read-SecureString -Prompt "Enter your password"
#>
function Read-SecureString {
    [CmdletBinding()] 
    param(
        [string]$Prompt
    )
    
    $secureString = Read-Host -Prompt $Prompt -AsSecureString
    return $secureString
}

<#
    .SYNOPSIS
        Creates a custom certificate request and submits it to a certificate authority.
    .DESCRIPTION
        This function creates a custom certificate request based on an .inf file and submits it to a certificate authority.
    .PARAMETER InfFilePath
        The file path of the .inf template with the certificate definition.
    .PARAMETER servernames
        The server DNS name that will be in the certificate.
    .PARAMETER CAName
        The name of the certificate authority.
    .PARAMETER OutputDir
        The output directory for the generated files.
    .PARAMETER RemoveTempFiles
        Specifies whether to remove temporary files after the request is submitted.
    .OUTPUTS
        System.Management.Automation.PSObject
    .EXAMPLE
        New-CustomCertificateRequest -InfFilePath "C:\certificates\mycert.inf" -servernames "myserver1", "myserver2" -CAName "MyCA" -OutputDir "C:\certificates" -RemoveTempFiles
#>
Function New-CustomCertificateRequest {
    [OutputType('System.Management.Automation.PSObject')]
    [CmdletBinding(DefaultParameterSetName = 'InfFilePath')]
    param(
            
        [Parameter(Mandatory = $true,
            ParameterSetName = 'InfFilePath',
            HelpMessage = "Enter the file path of the .inf template with the certificate definition")]
        [string]$InfFilePath,
    
        [Parameter(Mandatory = $true,
            ParameterSetName = 'InfFilePath',
            HelpMessage = "Enter the server DNS name that will be in the certificate")]
        [array]$servernames,
            
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$CAName,
    
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$OutputDir,
            
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false)]
        [switch]$RemoveTempFiles
    )
    $newInffiles = @()
    $newRegFiles = @()  
    $newCerFiles = @() 
    
    # remove last backslash from path
    $OutputDir = Remove-lastbackslash -Path $OutputDir
    $t = Get-ChildItem -Path $InfFilePath
    [string]$InfFolderPath = $t.Directory.FullName
        
    if ($PSCmdlet.ParameterSetName -eq 'InfFilePath') {
        $infFiles = Get-ChildItem -Path $InfFolderPath -Filter $t.Name
        foreach ($file in $infFiles) {
            $content = Get-Content -Path $file.FullName
            foreach ($server in $servernames) {
                $line = $null
                foreach ($line in $content) {
                    if ($line -like "*SERVER_FQDN = HOSTFQDN*") {
                        $line = $line -replace $line, "SERVER_FQDN = $server"
                        Out-File -InputObject $line -FilePath "$OutputDir\$server.inf" -Encoding ascii -Append
                    }
                    else {
                        Out-File -InputObject $line -FilePath "$OutputDir\$server.inf" -Encoding ascii -Append
                    }
                }   
                $newInffiles += "$OutputDir\$server.inf"
            }
        }
    }
    # create a new custom request file from an .inf file
    foreach ($infFile in $newInffiles) {
        $fqdn = get-fqdn -InputString $infFile
        $fqdn = $fqdn.Substring(0, $fqdn.Length - 4)
        $reqout = certreq -new -f -q "$($infFile)" "$($OutputDir)\$($fqdn).reg"
        if ($reqout -like "*The entry already exists*") {
            Write-Error "The entry already exists"
            return $false
        }
        else {
            $newRegFiles += "$OutputDir\$fqdn.reg"           
        }
    }
    $MyArray = @()    
    # submit a request to the certificate authority
    foreach ($regFile in $newRegFiles) {
        $fqdn = get-fqdn -InputString $regFile
        $fqdn = $fqdn.Substring(0, $fqdn.Length - 4)    
        $reqout = certreq -submit -f -q -config "$($CAName)" $regFile "$OutputDir\$fqdn.cer"
    
        # parse via regex the certificate RequestId from the output of certreg -new
        [regex]$parseout = '^(?<property>\w+):\s*(?<value>\d+)'
        foreach ($line in $reqout) {
            if ($line -match $parseout) {
                $Matches.Remove(0)         
                $MyArray += [PSCustomObject]$Matches
            }
        }
        if ($reqout -like "*pending:*") {
            $fileName = "RequestID_" + $fqdn + "_$(Get-Date -Format 'dd-MM-yyyy_HH-mm-ss').log" 
            Out-File -InputObject "$($MyArray.Property) = $($MyArray.Value)" -FilePath "$OutputDir\$fileName"
        }
        elseif ($reqout -like "*Issued*") {
            $newCerFiles = Get-ChildItem -Path $OutputDir -Filter *.cer
            foreach ($cerFile in $newCerFiles) {
                # accept and install PFX certificate into machine or user certificate store
                CertReq -machine -q -f -Accept $cerFile 
            }
        }
    }
    if ($RemoveTempFiles) {
        $removeFiles = Get-ChildItem -Path $($OutputDir + '*') -Include *.inf, *.reg, *.rsp -Exclude CertTemplate.inf
        foreach ($file in $removeFiles) {
            Remove-Item -Path $file.FullName -Force
        }
    }
    return $MyArray 
}

<#
    .SYNOPSIS
        Searches for a specified string in an array or string input and returns all lines that contain the string.
    .PARAMETER InputContent
        The input content to search. Must be a string or an array.
    .PARAMETER SearchString
        The string to search for in the input content.
    .EXAMPLE
        $output = Search-Output -InputContent $content -SearchString "error"
        Returns all lines in $content that contain the string "error".
#>
function Search-Output {
    [CmdletBinding()]
    param(
        $InputContent,
        [string]$SearchString
    )
    $mylines = @()
    if ($InputContent.GetType().IsArray) {
        $outputLines = $InputContent
    }
    elseif ($InputContent.GetType().Name -eq "String") {
        $outputLines = $InputContent -split "`r`n"
    }
    else {
        Write-Error "InputContent must be a string or an array"
        return $null
    }
    try {
        foreach ($line in $outputLines) {
            if ($line.Contains($SearchString)) {
                $mylines += $line
            }
        }
    }
    catch {
        #Write-Error "Error while searching for $SearchString in $InputContent"
    }
    return $mylines
}

<#
    .SYNOPSIS
        Gets the fully qualified domain name (FQDN) from a given input string.
    .DESCRIPTION
        This function uses a regular expression to extract the FQDN from a given input string.
    .PARAMETER InputString
        The input string from which to extract the FQDN.
    .EXAMPLE
        Get-FQDN "https://www.example.com/path/to/resource"
        Returns: "www.example.com"
#>
function Get-FQDN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )
    
    $regex = [regex]"((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))$"
    $match = $regex.Match($InputString.Trim())
    
    if ($match.Success) {
        return $match.Value
    }
    
    return $null
}

<#
    .SYNOPSIS
    Removes the last backslash character from a string.
    
    .DESCRIPTION
    This function removes the last backslash character from a string, if it exists.
    
    .PARAMETER Path
    The string to remove the last backslash character from.
    
    .EXAMPLE
    Remove-LastBackslash "C:\Users\johndoe\Documents\"
    Returns: "C:\Users\johndoe\Documents"
    
    .EXAMPLE
    Remove-LastBackslash "C:\Users\johndoe\Documents"
    Returns: "C:\Users\johndoe\Documents"
    
    .NOTES
    Author: Jan Tiedemann
    Date: 06/11/2023
#>
function Remove-LastBackslash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    if ($Path.EndsWith("\")) {
        return $Path.Substring(0, $Path.Length - 1)
    }
    
    return $Path
}

#endregion functions

#region Main

<#
.SYNOPSIS
    This script requests custom certificates for a list of servers and exports them as PFX files.
.DESCRIPTION
    This script requests custom certificates for a list of servers and exports them as PFX files.
    The script defines an empty array to store the Thumbprints of the certificates to export.
    It also defines the FQDNs of all servers that will be in the certificate request to the CAName.
    The certificates are requested and stored in an array.
    If the request must be approved by the CA admin, the RequestIDs will be stored in the array and the requestID will be saved in the output folder.
    The certificates are exported as PFX files after searching for the Thumbprints in requestIDs output.
.PARAMETER InfFilePath
    Specifies the path to the INF file that contains the certificate template information.
.PARAMETER servernames
    Specifies an array of server names for which the certificate is requested.
.PARAMETER CAName
    Specifies the name of the certification authority (CA) that issues the certificate.
.PARAMETER OutputDir
    Specifies the path to the output directory where the certificate request files and PFX files are saved.
.PARAMETER RemoveTempFiles
    Specifies whether to remove the temporary files created during the certificate request process.
.EXAMPLE
    .\RequestCustomCertificate.ps1 -InfFilePath .\CertTemplate.inf -servernames "Test07.contoso.com", "Test08.contoso.com", "Test09.contoso.com" -CAName 'AO-PKI.contoso.com\contoso-AO-PKI-CA' -OutputDir '.\' -RemoveTempFiles
#>

# Set error handling
$ErrorActionPreference = "Stop"
trap {
    Write-Warning "Script failed: $_"
    throw $_
}

# Set script variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$InfFilePath = "$($ScriptPath)\CertTemplate.inf"
$OutputPath = "$($ScriptPath)\"

# Define an empty array to store the Thumbprints of the certificates to export
$certs = @()

# Define the FQDNs of all Servers that will be in the certificate request to the CAName
$servers = "Test07.contoso.com", "Test08.contoso.com", "Test09.contoso.com"

# Request the certificates and store the RequestIDs or Thumbprints in an array
# If request must be approved by CA admin, the RequestIDs will be stored in the array and the requestID will be saved in the output folder
$requestIDs = New-CustomCertificateRequest -InfFilePath $InfFilePath -servernames $servers -CAName 'AO-PKI.contoso.com\contoso-AO-PKI-CA' -OutputDir $OutputPath -RemoveTempFiles

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
            $cert | Export-CertificateAsPFXByProperty -Property 'Thumbprint' -Value $cert.Thumbprint -ExportPath "$OutputPath$($cert.DnsNameList.Unicode).pfx" -Password $password
        }
    }
    else {
        Write-Error "No Thumbprints found in var requestIDs"
        $requestIDs
        return $false
    }
}

#endregion Main