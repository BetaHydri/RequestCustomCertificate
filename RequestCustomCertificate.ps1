function Update-InfFiles {
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

function Export-CertificateAsPFXByProperty {
    param(
        [string]$Property,
        [string]$Value,
        [string]$ExportPath,
        [securestring]$Password
    )

    $certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.$Property -eq $Value }
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

function Read-SecureString {
    param(
        [string]$Prompt
    )

    $secureString = Read-Host -Prompt $Prompt -AsSecureString
    return $secureString
}

Function New-CustomCertificateRequest {
    [OutputType('System.Management.Automation.PSObject')]
    [CmdletBinding(DefaultParameterSetName = 'InfAsFile')]
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
        $fqdn = $fqdn.Substring(0, $infFile.Length - 7)
        certreq -new "$infFile" "$OutputDir\$fqdn.reg"
        $newRegFiles += "$OutputDir\$fqdn.reg"
    }
    $MyArray = @()    
    # submit a request to the certificate authority
    foreach ($regFile in $newRegFiles) {
        $reqoutput = $null
        $fqdn = get-fqdn -InputString $regFile
        $fqdn = $fqdn.Substring(0, $regFile.Length - 7)    
        $reqoutput = certreq -submit -config "$($CAName)" $regFile "$OutputDir\$fqdn.cer"

        # parse via regex the certificate RequestId from the output of certreg -new
        [regex]$parseout = '^(?<property>\w+):\s*(?<value>\d+)'
        foreach ($line in $reqoutput) {
            if ($line -match $parseout) {
                $Matches.Remove(0)         
                $MyArray += [PSCustomObject]$Matches
            }
        }
        if ($reqoutput -like "*pending:*") {
            $fileName = "RequestID_" + $fqdn + "_$(Get-Date -Format 'dd-MM-yyyy_HH-mm-ss').log" 
            Out-File -InputObject "$($MyArray.Property) = $($MyArray.Value)" -FilePath "$OutputDir\$fileName"
        }
        elseif ($reqoutput -like "*Issued*") {
            $newCerFiles = Get-ChildItem -Path $OutputDir -Filter *.cer
            foreach ($cerFile in $newCerFiles) {
                # accept and install PFX certificate into machine or user certificate store
                CertReq -machine -Accept $cerFile 
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

function Search-Output {
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

function Get-FQDN {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )

    $regex = [regex]"\b((\w+\.)+\w+)\b"
    $match = $regex.Match($InputString)

    if ($match.Success) {
        return $match.Value
    }

    return $null
}

function Remove-LastBackslash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.EndsWith("\")) {
        return $Path.Substring(0, $Path.Length - 1)
    }

    return $Path
}


## MAIN Program

# Define empty Array to Store the Thumbprints of the certificates to export
$MyThumbprints = @()
# Define the path where the .inf template are located with the certificate definition
$servers = "Test07.contoso.com", "Test08.contoso.com", "Test09.contoso.com"

# Request the certificates and store the RequestIDs or Thumbprints in an array
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






