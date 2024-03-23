# PowerShell Password Manager

## Overview
This PowerShell script serves as a simple password manager that allows you to securely store and retrieve passwords for various services using AES encryption.

## Features
- **Add Password:** Add a new password for a service securely encrypted using AES.
- **Get Password:** Retrieve a password for a service and decrypt it.

## Prerequisites
- PowerShell 7

## Setup
1. Clone or download the script to your local machine.
2. Open the script in a text editor and customize the encryption key and IV:

    ```powershell
    $key = [System.Text.Encoding]::UTF8.GetBytes("YourEncryptionKey")
    $iv = [System.Text.Encoding]::UTF8.GetBytes("YourEncryptionIV")
    ```
    Replace "YourEncryptionKey" and "YourEncryptionIV" with your desired encryption key and initialization vector.
4. Save the script.

## Usage
1. Open PowerShell.
2. Navigate to the directory where the script is saved.
3. Run the script using the following command:
    ```powershell
    .\PasswordManager.ps1
    ```
4. Select the action you want to perform:
    - **Add Password:** Enter the service name and password when prompted.
    - **Get Password:** Enter the service name for which you want to retrieve the password.

## Security Considerations
- **Encryption:** Passwords are encrypted using AES encryption with a user-defined encryption key and initialization vector.
- **SecureString:** Passwords are stored and passed as SecureString objects to enhance security.

## License
This project is licensed under the MIT License.
