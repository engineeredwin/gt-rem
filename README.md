param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $VEDServer,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $certParentDN,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $certCommonName,

    [Parameter(Mandatory=$true)]
    [string] $certCADN,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $keyStorePath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $keyStorePassword,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $targetServer,

    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential] $credential
)

# Create a keystore and generate a private key
$keyStoreType = "JKS"
$keyPairAlgorithm = "RSA"
$privateKeyAlgorithm = "RSA"
$keySize = 2048

$keyStore = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Store" -ArgumentList "My", "LocalMachine"
$keyStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

$certificateRequest = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Certificate2"

try {
    $keyParams = New-Object -TypeName "System.Security.Cryptography.CspParameters"
    $keyParams.KeyContainerName = [System.Guid]::NewGuid().ToString()
    $keyParams.KeyNumber = [System.Security.Cryptography.KeyNumber]::Exportable
    $keyParams.ProviderType = 1

    $rsa = New-Object -TypeName "System.Security.Cryptography.RSACryptoServiceProvider" -ArgumentList $keySize, $keyParams

    $certificateRequest.PrivateKey = $rsa

    # Generate a CSR
    $subjectName = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X500DistinguishedName" -ArgumentList "CN=$certCommonName"
    $certificateRequest.Subject = $subjectName
    $certificateRequest.SignatureAlgorithm = [System.Security.Cryptography.X509Certificates.X509SignatureAlgorithm]::Sha256
    $certificateRequest.NotBefore = [System.DateTime]::Now.AddDays(-1)
    $certificateRequest.NotAfter = [System.DateTime]::Now.AddYears(1)

    $csr = $certificateRequest.CreateSigningRequest()

    # Save the private key and CSR to the keystore
    $keyStorePath = Resolve-Path $keyStorePath
    $keyStoreFilePath = Join-Path -Path $keyStorePath -ChildPath "private_key.jks"

    $password = ConvertTo-SecureString -String $keyStorePassword -AsPlainText -Force
    $keyStoreObject = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Store" -ArgumentList "My", "CurrentUser"
    $keyStoreObject.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    $certEntry = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Certificate2" -ArgumentList $certificateRequest.RawData
    $keyStoreObject.Add($certEntry)

    $keyStoreObject.Close()

    $keyStoreInfo = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509KeyStorageFlags"
    $keyStoreInfo = $keyStoreInfo -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    $keyStoreInfo = $keyStoreInfo -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

    $certificateRequest.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password) | Set-Content -Path $keyStoreFilePath -Encoding Byte

    # Send the CSR to Venafi and retrieve the certificate
    Connect-VEDService -server $VEDServer -credential $credential
    $service = Get-VEDService

    $csrBase64 = [System.Convert]::ToBase64String($csr)
    $certDN = "{0},{1}" -f $certCommonName, $certParentDN

    try {
        $certificate = Create-VEDCertificate -service $service -CADN $certCADN -CSR $csrBase64 -DN $certDN -targetServer $targetServer
        $certificatePath = Join-Path -Path $keyStorePath -ChildPath "certificate.p7b"
        $certificate | Export-VEDCertificate -Path $certificatePath

        $certificateData = Get-Content -Path $certificatePath -Raw
        $certificateObject = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Certificate2" -ArgumentList $certificateData

        $keyStoreObject = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Store" -ArgumentList "My", "CurrentUser"
        $keyStoreObject.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $keyStoreObject.Add($certificateObject)
        $keyStoreObject.Close()

        Write-Host "Certificate DN: $certDN"
    }
    catch {
        Write-Host -ForegroundColor Red "ERROR: Failed to create certificate. Message: $($_)"
    }
    finally {
        Disconnect-VEDService -service $service
    }
}
finally {
    $keyStore.Close()
}





# JKS keystore details
$keyStorePath = "keystore.jks"
$keyStorePassword = "KEYSTORE_PASSWORD"

# Target server
$targetServer = "TARGET_SERVER"

# Generate keystore
$keytoolPath = "keytool.exe"
$keytoolArgs = "-genkeypair -alias $targetServer -keyalg RSA -keysize 2048 -keystore $keyStorePath -storepass $keyStorePassword -dname ""CN=$targetServer"""
$keytoolCommand = "$keytoolPath $keytoolArgs"
Invoke-Expression -Command $keytoolCommand

# Generate CSR
$certCSRFile = "$CertPath$targetServer.csr"
$keytoolArgs = "-certreq -alias $targetServer -keystore $keyStorePath -storepass $keyStorePassword -file $certCSRFile"
$keytoolCommand = "$keytoolPath $keytoolArgs"
Invoke-Expression -Command $keytoolCommand

switch ($requestType) {
    "create" {
        request-cert -VEDServer $VEDServer -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -CertCSRFile $certCSRFile -cre $cre
        $signedCert = download-cert -VEDServer $VEDServer -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -credential $cre
        $signedCert.certData | Out-File -FilePath "$CertPath$targetServer.cer"
        if ($apply_cert) {
            apply-cert -filePath "$CertPath$targetServer.cer"
        }
        break
    }
    "renew" {
        renew-cert -VEDServer $VEDServer -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -CertCSRFile $certCSRFile -credential $credential
        $signedCert = download-cert -VEDServer $VEDServer -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -credential $credential
        $signedCert.certData | Out-File -FilePath "$CertPath$targetServer.cer"
        if ($apply_cert) {
            apply-cert -filePath "$CertPath$targetServer.cer"
        }
        break
    }
}






