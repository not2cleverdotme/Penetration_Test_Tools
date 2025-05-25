# Enhanced Recon Tool v2.2

A comprehensive PowerShell-based system reconnaissance and security assessment tool designed for system administrators and security professionals.

## Features

### 1. System Information Gathering
- Detailed OS information
- Hardware specifications
- System configuration
- Installation and boot time details
- Disk information and storage metrics

### 2. Network Configuration Analysis
- Network adapter details
- IP configuration
- DNS settings
- ARP table
- Routing information
- Network shares
- Interface statistics (Extended mode)
- DHCP lease information (Extended mode)

### 3. Active Directory Assessment
- Domain and forest information
- Domain controller details
- Privileged group enumeration
- Password policy analysis
- Trust relationships (Extended mode)
- GPO information (Extended mode)
- Service account enumeration (Extended mode)

### 4. ADCS (Active Directory Certificate Services) Security
- Enterprise CA information
- Certificate template analysis
- ESC vulnerability checks (ESC1-8)
- Detailed vulnerability reporting
- Mitigation suggestions

### 5. MITM (Man-in-the-Middle) Security Assessment
- NTLM Security Analysis:
  - NTLM traffic restrictions
  - Minimum client/server security levels
  - LM compatibility level checks
- Kerberos Security:
  - Supported encryption types
  - Configuration settings
  - Security parameters
- SMB Security:
  - Client and server signing requirements
  - Signing enforcement status
  - Security configuration
- LDAP Security:
  - LDAP signing requirements
  - Channel binding status
  - Server integrity settings
- Authentication Protections:
  - Extended Protection for Authentication (EPA)
  - WDigest credential storage settings
  - Memory protection features
- Name Resolution Security:
  - LLMNR status and configuration
  - NBT-NS settings and vulnerabilities
- Automated Vulnerability Detection:
  - Identifies common MITM attack vectors
  - Provides detailed vulnerability explanations
  - Includes specific mitigation recommendations

### 6. General Security Assessment
- Windows Update status
- Security services status
- Windows Defender configuration
- Share permissions
- Firewall rules
- Startup programs (Extended mode)
- System integrity checks (Extended mode)
- BitLocker status (Extended mode)

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrative privileges
- Required PowerShell modules:
  - ActiveDirectory (for AD-related functions)
  - PSPKI (for ADCS checks)
  - NetAdapter
  - NetTCPIP
  - Storage
  - SecurityCenter
  - BitLocker (for extended checks)

## Installation

1. Clone the repository:
\`\`\`powershell
git clone https://github.com/not2clever/enhanced-recon.git
\`\`\`

2. Ensure you have the required PowerShell modules:
\`\`\`powershell
# For AD module
Install-WindowsFeature RSAT-AD-PowerShell

# For PSPKI module
Install-Module -Name PSPKI -Force
\`\`\`

## Usage

### Basic Syntax
\`\`\`powershell
.\Recon.ps1 [-SkipAD] [-Extended] [-OutputDir <path>]
\`\`\`

### Parameters

- \`-SkipAD\`: Skip Active Directory enumeration
- \`-Extended\`: Enable extended information gathering
- \`-OutputDir\`: Specify custom output directory (default: script directory)

### Examples

1. Basic scan with default settings:
\`\`\`powershell
.\Recon.ps1
\`\`\`

2. Extended scan with all checks:
\`\`\`powershell
.\Recon.ps1 -Extended
\`\`\`

3. System-only scan (skip AD):
\`\`\`powershell
.\Recon.ps1 -SkipAD
\`\`\`

4. Custom output location:
\`\`\`powershell
.\Recon.ps1 -OutputDir "C:\Audit\Results"
\`\`\`

## Output

The script generates two files in the specified output directory:
- \`Recon_Results_[timestamp].txt\`: Main results and findings
- \`Recon_Errors_[timestamp].txt\`: Error logs and warnings

### MITM Findings Format
The MITM security assessment results include:
- Detailed status of each protocol
- Current security settings
- Identified vulnerabilities (highlighted in red)
- Specific mitigation recommendations
- Risk levels for each finding

## Security Considerations

- The script requires administrative privileges
- Performs read-only operations
- Logs all activities
- Does not modify system settings
- Does not store sensitive information
- Safe to run in production environments

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

not2clever

## Version History

- 2.2: Current release
  - Enhanced ADCS vulnerability checks
  - Added comprehensive MITM security assessment
  - Improved error handling
  - Added extended mode features
  - Optimized performance
  - Added detailed logging

## Acknowledgments

- PowerShell community
- Active Directory Security researchers
- ADCS vulnerability researchers
- MITM security researchers

## Support

For issues, questions, or contributions, please:
1. Check existing issues on GitHub
2. Create a new issue with detailed information
3. Follow the contribution guidelines

## Disclaimer

This tool is for legitimate system administration and security assessment purposes only. Users must ensure they have appropriate authorization before running this tool in any environment. 