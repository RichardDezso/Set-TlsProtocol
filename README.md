# Set-TlsProtocol
A PowerShell script to manage SSL/TLS protocol settings on Windows by modifying SCHANNEL registry keys.  
It supports enabling or disabling protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2), with options to back up and restore configurations and generate reports.  

## Features
- Enable or disable specific SSL/TLS protocols
- Apply a secure baseline (`-Secure`)
- Backup and restore registry settings
- Report current protocol states
- Optional .NET strong crypto defaults
- Supports `-WhatIf` and `-Confirm` for safety

## Requirements
- Windows Server or Windows 10/11  
- Run as **Administrator**  
- Reboot required for changes to take effect  

## Usage
```powershell
# Secure baseline (disable SSL 2.0/3.0, TLS 1.0/1.1; enable TLS 1.2)
.\Set-TlsProtocols.ps1 -Secure -Backup

# Disable TLS 1.0 and 1.1, enable TLS 1.2 only on Server side
.\Set-TlsProtocols.ps1 -Disable "TLS 1.0","TLS 1.1" -Enable "TLS 1.2" -Scope Server -Backup
