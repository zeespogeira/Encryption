

$savePath = "$env:USERPROFILE\Documents\MyRSAKeypair"

Write-Host "Creating a 2048-bit RSA Keypair"
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048

# Make a directory for the keys
Write-Host "Creating directory $savePath for storing keys"
New-Item $savePath -ItemType directory | Out-Null

Write-Host "Saving private and public keys as private-key.xml and public-key.xml"

#Private Key
$rsa.toXmlString($true) | Out-File $savePath\private-key.xml

#Public Key
$rsa.ToXmlString($false) | Out-File $savePath\public-key.xml
