$PasswordFilePath = "C:\Users\Admin\Documents\Powershell\Password Manager\PasswordManager.txt"

function Protect-Password {
    param(
        # The plaintext password to be encrypted
        [System.Security.SecureString]$Password,
        # The encryption key used for AES encryption
        [byte[]]$Key,
        # The initialization vector used for AES encryption
        [byte[]]$IV 
    )

    # Instantiate a new AES object
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.KeySize = 256  # Set the key size to 256 bits
    $aes.BlockSize = 128  # Set the block size to 128 bits
    $aes.Key = $Key
    $aes.IV = $IV

    # Create an encryptor
    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)

    # Memory Stream Setup
    $memoryStream = New-Object System.IO.MemoryStream

    # Create a Crypto Stream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $encryptor, "Write")

    # Convert Password to Bytes
    $bytes = [System.Text.Encoding]::Unicode.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)))

    # Encryption
    $cryptoStream.Write($bytes, 0, $bytes.Length)
    $cryptoStream.FlushFinalBlock()

    # Convert the encrypted data to Base64 string
    $encryptedPassword = [Convert]::ToBase64String($memoryStream.ToArray())

    # Closing Streams
    $memoryStream.Close()
    $cryptoStream.Close()

    return $encryptedPassword
} 

function Get-Protect-Password {
    param(
        # The encrypted password as a byte array
        [byte[]]$EncryptedPassword,
        # The encryption key used for AES decryption
        [byte[]]$Key,
        # The initialization vector used for AES decryption
        [byte[]]$IV 
    )
    
    # Instantiate a new AES object
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.KeySize = 256  # Set the key size to 256 bits
    $aes.BlockSize = 128  # Set the block size to 128 bits
    $aes.Key = $Key
    $aes.IV = $IV

    # Create a decryptor
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)

    # Memory Stream Setup
    $memoryStream = New-Object System.IO.MemoryStream($EncryptedPassword)

    # Create a Crypto Stream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, "Read")

    # Read the decrypted bytes
    $reader = New-Object System.IO.StreamReader($cryptoStream)
    $decryptedPassword = $reader.ReadToEnd()

    # Close streams
    $reader.Close()
    $memoryStream.Close()
    $cryptoStream.Close()

    return $decryptedPassword
}

function New-RandomPassword {
    param(
        [int]$Length,
        [bool]$IncludeUppercase,
        [bool]$IncludeLowercase,
        [bool]$IncludeDigits,
        [bool]$IncludeSpecialCharacters
    )

    $uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWYZ"
    $lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
    $digitalChars = "0123456789"
    $specialChars = "!@#$%^&*()-_+=[]{}|;:,.<>?/`~"

    $charSet = ""

    if ($IncludeUppercase) {
        $charSet += $uppercaseChars
    }
    if ($IncludeLowercase) {
        $charSet += $lowercaseChars
    }
    if ($IncludeDigits) {
        $charSet += $digitalChars
    }
    if ($IncludeSpecialCharacters) {
        $charSet += $specialChars
    }

    $random = New-Object System.Security.RNGCryptoServiceProvider
    $randomBytes = New-Object byte[] $Length
    $random.GetBytes($randomBytes)

    $randomPassword = ""

    for ($i = 0; $i -lt $Length; $i++) {
        $randomPassword += $charSet[$randomBytes[$i] % $charSet.Length]
    }

    return $randomPassword
}

function Add-Password {
    param (
        [string]$Service,
        [System.Security.SecureString]$Password,
        [byte[]]$Key,
        [byte[]]$IV
    )
    
    $key = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $random.GetBytes($key)

    $iv = New-Object byte[] 16
    $random.GetBytes($iv)

    $encryptedPassword = Protect-Password -Password $Password -Key $Key -IV $IV
    "$Service|$encryptedPassword" | Out-File -File $PasswordFilePath -Append
}

function Get-Password {
    param (
        [string]$Service,
        [byte[]]$Key,
        [byte[]]$IV
    )

    $passwords = Get-Content -Path $PasswordFilePath

    foreach ($line in $passwords){
        $split = $line.Split('|')
        $serviceName = $split[0]
        $encryptedPassword = [System.Convert]::FromBase64String($split[1])

        if ($serviceName -eq $Service){
            $decryptedPassword = Get-Protect-Password -EncryptedPassword $encryptedPassword -Key $Key -IV $IV
            return $decryptedPassword
        }
    }

    return "Password not found for service: $Service"    
}


# Prompt user for action
$action = Read-Host "Select action: 1. Add Password 2. Get Password"

switch ($action) {
    "1" {
        $service = Read-Host "Enter service name"
        $password = Read-Host "Enter password" -AsSecureString
        $key = [System.Text.Encoding]::UTF8.GetBytes("YourEncryptionKey") # Replace with your own encryption key
        $iv = [System.Text.Encoding]::UTF8.GetBytes("YourEncryptionIV")  # Replace with your own encryption IV
        Add-Password -Service $service -Password $password -Key $key -IV $iv
    }
    "2" {
        $service = Read-Host "Enter service name"
        $key = [System.Text.Encoding]::UTF8.GetBytes("YourEncryptionKey") # Replace with your own encryption key
        $iv = [System.Text.Encoding]::UTF8.GetBytes("YourEncryptionIV")  # Replace with your own encryption IV
        $retrievedPassword = Get-Password -Service $service -Key $key -IV $iv
        Write-Output $retrievedPassword
    }
    default {
        Write-Output "Invalid selection"
    }
}