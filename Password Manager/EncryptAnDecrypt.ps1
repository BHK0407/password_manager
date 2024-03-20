$PasswordFilePath = "C:\Users\Admin\Documents\Powershell\Password Manager\PasswordManager.txt"

function Encrypt-Password {
    param(
        # The plaintext pasword to be encrypted
        [string]$Password,
        # They encryption key used for AES encryption
        [byte[]]$Key,
        # The initialization vector used for AES encryption
        [byte[]]$IV 
    )
    # Instantieates a new object
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $Key
    $aes.IV = $IV

    # Create an encryptor
    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)

    # Memory Stream Setup
    # Create a new memory stream to hold the encrypted data
    $memoryStream = New-Object System.IO.MemoryStream
    # Create a new crypto stream, using the memory stream and encryptor, for writing encrypted data
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $encryptor, "Write")

    # Convert Password to Bytes

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Password)

    # Encryption
    $cryptoStream.Write($bytes, 0, $bytes.Length)
    $cryptoStream.FlushFinalBlock()

    $encryptedPassword = [Convert]::ToBase64String($memoryStream.ToArray())

    # Closing Streams
    $memoryStream.Close()
    $cryptoStream.Close()

    return $encryptedPassword
} 


function Decrypt-Password {
    param(
        # The encrypted password to be decrypted
        [string]$EncryptedPassword,
        # The encryption key used for AES decryption
        [byte[]]$Key,
        # The initialization vector used for AES decryption
        [byte[]]$IV 
    )
    # Instantieates a new object
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $Key
    $aes.IV = $IV

    # Create an decryptor
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)

    # Convert Base64-encoded encrypted password to byte array
    $encryptedBytes = [Convert]::ToBase64String($EncryptedPassword)

    # Memory Stream Setup
    # Create a new memory stream to hold the encrypted data
    $memoryStream = New-Object System.IO.MemoryStream($encryptedBytes, 0, $encryptedBytes.Length)
    # Create a new crypto stream, using the memory stream and encryptor, for writing encrypted data
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, "Read")

    # Convert decrypted bytes to plaintext password

    $reader = New-Object System.IO.StreamReader($cryptoStream)

    $decryptedPassword = $reader.ReadToEnd()
    
    # Close streams
    $reader.Close()
    $memoryStream.Close()
    $cryptoStream.Close()

    return $decryptedPassword
} 

