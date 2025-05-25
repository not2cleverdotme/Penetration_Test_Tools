<#
.SYNOPSIS
    This script performs comprehensive network and Active Directory reconnaissance for penetration testing purposes.

.DESCRIPTION
    Gathers information about the local network configuration, neighboring devices, routing information,
    connection profiles, open ports, and Active Directory domain details, including domain controllers,
    trusts, organizational units, and group memberships.

.PARAMETER NetworkRange
    The network range to scan for active hosts.

.PARAMETER SkipAD
    Skips Active Directory enumeration.

.PARAMETER Extended
    Enables extended mode for more detailed information.

.PARAMETER OutputDir
    Specifies the output directory for saving results.

.EXAMPLE
    .\ReconnaissanceScript.ps1 -NetworkRange "192.168.1.0/24"

.NOTES
    Author: not2clever
    Date: 2025-05-24
    Version: 2.2
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$SkipAD,
    [Parameter(Mandatory = $false)]
    [switch]$Extended,
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = $PSScriptRoot
)

# Create output directory if it doesn't exist (this will only be used if custom path is provided)
if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Generate output file names with timestamp in script's directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$outputFile = Join-Path $OutputDir "$($scriptName)_Results_$timestamp.txt"
$errorLogFile = Join-Path $OutputDir "$($scriptName)_Errors_$timestamp.txt"

# Function to write both to console and file
function Write-OutputAndLog {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$Message,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White
    )
    
    # Write to console with color
    if ($Message) {
        Write-Host $Message -ForegroundColor $ForegroundColor
        # Write to file (without color codes)
        $Message | Out-File -FilePath $outputFile -Append -Encoding utf8
    }
}

# Function to format and log table output
function Write-TableOutput {
    param(
        [Parameter(ValueFromPipeline=$true)]
        $InputObject,
        [string]$Title
    )
    
    process {
        if ($Title) {
            Write-OutputAndLog "`n=== $Title ==="
        }
        
        if ($InputObject) {
            $formattedOutput = $InputObject | Format-Table -AutoSize | Out-String -Width 4096
            if (-not [string]::IsNullOrWhiteSpace($formattedOutput)) {
                Write-OutputAndLog $formattedOutput.Trim()
            }
        }
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info' { Write-OutputAndLog -Message $logMessage -ForegroundColor Green }
        'Warning' { Write-OutputAndLog -Message $logMessage -ForegroundColor Yellow }
        'Error' { 
            Write-OutputAndLog -Message $logMessage -ForegroundColor Red
            $logMessage | Out-File -FilePath $errorLogFile -Append -Encoding utf8
        }
    }
}

# Script version and banner
$ScriptVersion = "2.2"
$Banner = @"
+================================================+
  Enhanced Recon Tool v$ScriptVersion by not2clever          
+================================================+

Scan started at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Results will be saved to: $outputFile
"@

Write-OutputAndLog $Banner

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemInfo {
    Write-Log "Gathering detailed system information..."
    try {
        Write-OutputAndLog "`n=== System Information ==="
        
        # Get basic system information without ComputerInfo cmdlet
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $cs = Get-WmiObject -Class Win32_ComputerSystem
        $proc = Get-WmiObject -Class Win32_Processor
        $mem = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        
        # Create ordered dictionary with system information
        $systemInfo = [ordered]@{
            'Computer Name' = $env:COMPUTERNAME
            'Operating System' = $os.Caption
            'OS Version' = $os.Version
            'OS Build' = $os.BuildNumber
            'OS Architecture' = $os.OSArchitecture
            'System Manufacturer' = $cs.Manufacturer
            'System Model' = $cs.Model
            'Processor' = $proc.Name
            'Total Memory' = "{0:N2} GB" -f ($mem.Sum/1GB)
            'Domain/Workgroup' = if ($cs.PartOfDomain) { $cs.Domain } else { "Workgroup: $($cs.Workgroup)" }
            'Install Date' = $os.ConvertToDateTime($os.InstallDate)
            'Last Boot Time' = $os.ConvertToDateTime($os.LastBootUpTime)
            'System Drive' = $env:SystemDrive
            'System Directory' = $env:SystemRoot
        }

        # Get network adapters
        $nics = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        foreach ($nic in $nics) {
            $systemInfo["Network Adapter ($($nic.Description))"] = $nic.IPAddress[0]
            if ($nic.DefaultIPGateway) {
                $systemInfo["Gateway ($($nic.Description))"] = $nic.DefaultIPGateway[0]
            }
        }

        # Get disk information
        $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
        foreach ($disk in $disks) {
            $freeSpaceGB = [math]::Round($disk.FreeSpace/1GB, 2)
            $totalSpaceGB = [math]::Round($disk.Size/1GB, 2)
            $systemInfo["Disk $($disk.DeviceID)"] = "Total: $totalSpaceGB GB, Free: $freeSpaceGB GB"
        }

        # Display system information
        foreach ($item in $systemInfo.GetEnumerator()) {
            if ($null -ne $item.Value) {
                Write-OutputAndLog "$($item.Key): $($item.Value)"
            }
            else {
                Write-OutputAndLog "$($item.Key): Not Available"
            }
        }

        # Additional security information
        Write-OutputAndLog "`n=== Security Information ==="
        
        # Check Windows Defender status
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                Write-OutputAndLog "Windows Defender Status:"
                Write-OutputAndLog "- Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
                Write-OutputAndLog "- Antivirus Enabled: $($defenderStatus.AntivirusEnabled)"
                Write-OutputAndLog "- Antispyware Enabled: $($defenderStatus.AntispywareEnabled)"
            }
        }
        catch {
            Write-OutputAndLog "Windows Defender Status: Unable to retrieve"
        }

        # Check firewall status
        try {
            $firewallStatus = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            if ($firewallStatus) {
                Write-OutputAndLog "`nFirewall Status:"
                $firewallStatus | ForEach-Object {
                    Write-OutputAndLog "- $($_.Name): $($_.Enabled)"
                }
            }
        }
        catch {
            Write-OutputAndLog "Firewall Status: Unable to retrieve"
        }

        # Check Windows Update status
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $pendingUpdates = $updateSearcher.Search("IsInstalled=0")
            Write-OutputAndLog "`nWindows Updates:"
            Write-OutputAndLog "- Pending Updates: $($pendingUpdates.Updates.Count)"
        }
        catch {
            Write-OutputAndLog "Windows Update Status: Unable to retrieve"
        }

        return $systemInfo
    }
    catch {
        Write-Log "Error gathering system information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-NetworkInfo {
    Write-Log "Collecting network information..."
    try {
        # Network Adapters
        Write-OutputAndLog "`n=== Network Adapters ==="
        $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
            $dnsServers = ($ipConfig.DNSServer | Where-Object AddressFamily -eq 2).ServerAddresses
            
            Write-OutputAndLog "Adapter: $($adapter.Name)"
            Write-OutputAndLog "MAC Address: $($adapter.MacAddress)"
            Write-OutputAndLog "IP Address(es):"
            $ipConfig.IPv4Address | ForEach-Object { Write-OutputAndLog "  $_" }
            Write-OutputAndLog "DNS Servers:"
            $dnsServers | ForEach-Object { Write-OutputAndLog "  $_" }
            
            if ($adapter.AdminStatus -eq 'Up' -and $ipConfig.IPv4DefaultGateway) {
                Write-OutputAndLog "Default Gateway: $($ipConfig.IPv4DefaultGateway.NextHop)"
            }
            Write-OutputAndLog ""
        }

        # ARP Table
        Get-NetNeighbor | Where-Object State -eq 'Reachable' | 
            Write-TableOutput -Title "ARP Table"

        # Routing Table
        Get-NetRoute -Protocol NetMgmt | 
            Write-TableOutput -Title "Routing Table"

        # Network Discovery
        Write-OutputAndLog "`n=== Active Network Hosts ==="
        Write-OutputAndLog "Starting network discovery..."

        $subnet = $NetworkRange -replace '/24$', ''
        $baseIP = $subnet -replace '\.\d+$', ''
        $results = @()
        $total = 254
        $progress = 0
        $foundHosts = 0

        Write-OutputAndLog "Scanning network range: $NetworkRange"
        Write-OutputAndLog "Starting scan at: $(Get-Date -Format 'HH:mm:ss')`n"

        1..254 | ForEach-Object {
            $progress++
            $percentComplete = [math]::Round(($progress / $total) * 100)
            
            # Update main progress bar
            Write-Progress -Activity "Network Discovery" `
                -Status "Scanning $baseIP.$_ ($percentComplete% complete)" `
                -PercentComplete $percentComplete `
                -CurrentOperation "Found $foundHosts hosts so far"
            
            $ip = "$baseIP.$_"
            if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
                $foundHosts++
                try {
                    $hostEntry = Resolve-DnsName -Name $ip -ErrorAction SilentlyContinue
                    $hostname = if ($hostEntry.NameHost) { $hostEntry.NameHost } else { "N/A" }
                    $results += [PSCustomObject]@{
                        'IP Address' = $ip
                        'Hostname' = $hostname
                        'Status' = 'Online'
                        'TimeFound' = Get-Date
                    }
                    
                    # Write immediate feedback for found hosts
                    Write-OutputAndLog "Found host: $ip $(if($hostname -ne 'N/A'){"($hostname)"})" -ForegroundColor Green
                }
                catch {
                    $results += [PSCustomObject]@{
                        'IP Address' = $ip
                        'Hostname' = "N/A"
                        'Status' = 'Online'
                        'TimeFound' = Get-Date
                    }
                    Write-OutputAndLog "Found host: $ip" -ForegroundColor Green
                }
            }
        }

        # Complete the progress bar
        Write-Progress -Activity "Network Discovery" -Status "Complete" -Completed

        # Display network discovery results
        Write-OutputAndLog "`n=== Network Host Discovery Results ==="
        if ($results.Count -gt 0) {
            $results | 
                Sort-Object { ($_.{'IP Address'} -split '\.' | ForEach-Object { [int]$_ }) } |
                ForEach-Object {
                    Write-OutputAndLog ("`nIP: $($_.'IP Address')")
                    Write-OutputAndLog ("Hostname: $($_.'Hostname')")
                    Write-OutputAndLog ("Status: $($_.'Status')")
                    Write-OutputAndLog ("Found at: $($_.TimeFound.ToString('HH:mm:ss'))")
                    Write-OutputAndLog "-------------------"
                }
            
            # Summary with timing information
            Write-OutputAndLog "`nNetwork Discovery Summary:"
            Write-OutputAndLog "Total hosts discovered: $($results.Count)"
            Write-OutputAndLog "Hosts with DNS names: $(($results | Where-Object { $_.Hostname -ne 'N/A' }).Count)"
            
            # Calculate scan duration
            if ($results.Count -gt 0) {
                $scanStart = ($results | Select-Object -ExpandProperty TimeFound | Sort-Object | Select-Object -First 1)
                $scanEnd = ($results | Select-Object -ExpandProperty TimeFound | Sort-Object | Select-Object -Last 1)
                $duration = $scanEnd - $scanStart
                Write-OutputAndLog "Scan Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes"
                Write-OutputAndLog "Average discovery rate: $([math]::Round($results.Count / $duration.TotalMinutes, 2)) hosts/minute"
            }
        }
        else {
            Write-OutputAndLog "No active hosts found in network range $NetworkRange" -ForegroundColor Yellow
        }

        # Network Shares
        Get-SmbShare | Write-TableOutput -Title "Network Shares"

        if ($Extended) {
            # Network Profiles
            Get-NetConnectionProfile | Write-TableOutput -Title "Network Profiles"

            # Interface Statistics
            Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
                $stats = $_ | Get-NetAdapterStatistics
                [PSCustomObject]@{
                    'Adapter' = $_.Name
                    'ReceivedBytes' = [math]::Round($stats.ReceivedBytes/1MB, 2).ToString() + " MB"
                    'SentBytes' = [math]::Round($stats.SentBytes/1MB, 2).ToString() + " MB"
                    'TotalErrors' = $stats.ReceivedErrors + $stats.OutboundErrors
                }
            } | Write-TableOutput -Title "Interface Statistics"

            # DHCP Leases
            Get-DhcpServerv4Lease -ErrorAction SilentlyContinue | 
                Write-TableOutput -Title "DHCP Leases"
        }
    }
    catch {
        Write-Log "Error collecting network information: $($_.Exception.Message)" -Level Error
    }
}

function Get-EnhancedADInfo {
    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Active Directory module not available. Skipping AD enumeration." -Level Warning
        return
    }
    
    Write-Log "Gathering enhanced Active Directory information..."
    try {
        # Get Domain Info
        $domain = Get-ADDomain
        $forest = Get-ADForest
        
        # Get Domain Controllers with detailed info
        $dcs = Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, 
            OperatingSystemVersion, Site, IsGlobalCatalog, IsReadOnly
        
        # Get Privileged Groups and Members
        $privilegedGroups = @(
            "Enterprise Admins", "Domain Admins", "Schema Admins", 
            "Administrators", "Account Operators", "Backup Operators",
            "Print Operators", "Server Operators", "DNS Admins"
        )
        
        $groupMembers = @{}
        foreach ($group in $privilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive | 
                    Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
                $groupMembers[$group] = $members
            }
            catch {
                Write-Log "Could not enumerate group $group : $_" -Level Warning
            }
        }
        
        # Get Password Policy
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
        
        # Output findings
        Write-Host "`n=== Domain Information ==="
        $domain | Format-List Name, Forest, DomainMode, PDCEmulator, RIDMaster
        
        Write-Host "`n=== Forest Information ==="
        $forest | Format-List Name, ForestMode, RootDomain, SchemaMaster
        
        Write-Host "`n=== Domain Controllers ==="
        $dcs | Format-Table -AutoSize
        
        Write-Host "`n=== Privileged Groups ==="
        foreach ($group in $groupMembers.Keys) {
            Write-Host "`nGroup: $group"
            $groupMembers[$group] | Format-Table -AutoSize
        }
        
        Write-Host "`n=== Password Policy ==="
        $passwordPolicy | Format-List ComplexityEnabled, LockoutDuration, LockoutThreshold,
            MinPasswordLength, PasswordHistoryCount
            
        if ($Extended) {
            # Additional AD enumeration for extended mode
            Write-Host "`n=== Trust Relationships ==="
            Get-ADTrust -Filter * | Format-Table Name, Direction, TrustType
            
            Write-Host "`n=== GPO Information ==="
            Get-GPO -All | Format-Table DisplayName, GpoStatus, CreationTime, ModificationTime
            
            Write-Host "`n=== Service Accounts ==="
            Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
                Format-Table Name, ServicePrincipalName
        }
    }
    catch {
        Write-Log "Error during AD enumeration: $_" -Level Error
    }
}

function Test-MITMVulnerabilities {
    Write-Log "Checking for MITM vulnerabilities and protocol security..."
    try {
        Write-OutputAndLog "`n=== MITM and Protocol Security Analysis ==="

        # Check NTLM Settings
        Write-OutputAndLog "`nNTLM Security Settings:"
        $ntlmSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue
        
        # Check NTLM restrictions
        $ntlmRestrictions = @{
            "RestrictSendingNTLMTraffic" = $ntlmSettings.RestrictSendingNTLMTraffic
            "NTLMMinClientSec" = $ntlmSettings.NTLMMinClientSec
            "NTLMMinServerSec" = $ntlmSettings.NTLMMinServerSec
        }
        
        foreach ($setting in $ntlmRestrictions.GetEnumerator()) {
            Write-OutputAndLog "- $($setting.Key): $($setting.Value)"
        }

        # Check LM Compatibility Level
        $lmCompatLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        Write-OutputAndLog "- LM Compatibility Level: $($lmCompatLevel.LmCompatibilityLevel)"
        
        # Check if SMB Signing is enabled
        Write-OutputAndLog "`nSMB Security Settings:"
        $smbClient = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ErrorAction SilentlyContinue
        $smbServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
        
        Write-OutputAndLog "- SMB Client Signing Required: $($smbClient.RequireSecuritySignature)"
        Write-OutputAndLog "- SMB Server Signing Required: $($smbServer.RequireSecuritySignature)"
        Write-OutputAndLog "- SMB Client Signing Enabled: $($smbClient.EnableSecuritySignature)"
        Write-OutputAndLog "- SMB Server Signing Enabled: $($smbServer.EnableSecuritySignature)"

        # Check Kerberos Settings
        Write-OutputAndLog "`nKerberos Security Settings:"
        $kerberosSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ErrorAction SilentlyContinue
        
        if ($kerberosSettings) {
            Write-OutputAndLog "- Supported Encryption Types: $($kerberosSettings.SupportedEncryptionTypes)"
        }
        
        # Check for LDAP Signing and Channel Binding
        Write-OutputAndLog "`nLDAP Security Settings:"
        $ldapSettings = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
        $ldapEnforcement = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
        
        Write-OutputAndLog "- LDAP Signing Requirements: $($ldapSettings.LDAPServerIntegrity)"
        Write-OutputAndLog "- LDAP Channel Binding: $($ldapEnforcement.LdapEnforceChannelBinding)"

        # Check for EPA (Extended Protection for Authentication)
        Write-OutputAndLog "`nExtended Protection for Authentication (EPA):"
        $epaSettings = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -like "*ExtendedProtection*" }
        
        if ($epaSettings) {
            foreach ($setting in $epaSettings) {
                Write-OutputAndLog "- $($setting.PSChildName): Enabled"
            }
        } else {
            Write-OutputAndLog "- EPA settings not found (potentially vulnerable)"
        }

        # Check for WDigest Authentication
        Write-OutputAndLog "`nWDigest Authentication Settings:"
        $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
        Write-OutputAndLog "- WDigest UseLogonCredential: $($wdigest.UseLogonCredential)"
        
        # Check for LLMNR and NBT-NS
        Write-OutputAndLog "`nName Resolution Security:"
        $llmnr = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
        $nbtns = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue
        
        Write-OutputAndLog "- LLMNR Enabled: $(if($llmnr.EnableMulticast -eq 0){'No'}else{'Yes (vulnerable)'})"
        Write-OutputAndLog "- NBT-NS Enabled: $(if($nbtns.NodeType -eq 2){'No'}else{'Yes (potentially vulnerable)'})"

        # Vulnerability Summary
        Write-OutputAndLog "`nPotential MITM Vulnerabilities:"
        $vulnerabilities = @()

        if ($ntlmSettings.RestrictSendingNTLMTraffic -ne 2) {
            $vulnerabilities += "- NTLM traffic not fully restricted"
        }
        if ($lmCompatLevel.LmCompatibilityLevel -lt 5) {
            $vulnerabilities += "- LM Compatibility Level below recommended value (should be 5)"
        }
        if ($smbClient.RequireSecuritySignature -ne 1 -or $smbServer.RequireSecuritySignature -ne 1) {
            $vulnerabilities += "- SMB Signing not required on all endpoints"
        }
        if ($wdigest.UseLogonCredential -eq 1) {
            $vulnerabilities += "- WDigest storing credentials in memory (vulnerable to mimikatz)"
        }
        if ($llmnr.EnableMulticast -ne 0) {
            $vulnerabilities += "- LLMNR enabled (vulnerable to MITM attacks)"
        }
        if ($nbtns.NodeType -ne 2) {
            $vulnerabilities += "- NBT-NS enabled (vulnerable to MITM attacks)"
        }

        if ($vulnerabilities.Count -gt 0) {
            Write-OutputAndLog "`nDetected Vulnerabilities:" -ForegroundColor Red
            $vulnerabilities | ForEach-Object { Write-OutputAndLog $_ -ForegroundColor Red }
            
            Write-OutputAndLog "`nRecommended Mitigations:"
            Write-OutputAndLog "1. Disable LLMNR and NBT-NS"
            Write-OutputAndLog "2. Enable SMB Signing requirements"
            Write-OutputAndLog "3. Set LM Compatibility Level to 5"
            Write-OutputAndLog "4. Disable WDigest credential storage"
            Write-OutputAndLog "5. Implement EPA for sensitive services"
            Write-OutputAndLog "6. Enable LDAP Channel Binding and Signing"
        } else {
            Write-OutputAndLog "`nNo immediate MITM vulnerabilities detected." -ForegroundColor Green
        }
    }
    catch {
        Write-Log "Error during MITM vulnerability check: $($_.Exception.Message)" -Level Error
    }
}

function Get-VulnerabilityCheck {
    Write-Log "Performing basic vulnerability checks..."
    try {
        # Check Windows Update status using PowerShell method
        Write-Host "`n=== Windows Update Status ==="
        try {
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            $UpdateSearcher.Online = $false  # Offline search to prevent hanging
            $pendingUpdates = $UpdateSearcher.Search("IsInstalled=0")
            Write-Host "Pending Updates: $($pendingUpdates.Updates.Count)"
        }
        catch {
            Write-Host "Windows Update status check failed. Requires different permissions or not available."
        }

        # Check running services (focusing on security-relevant services)
        Write-Host "`n=== Security Services Status ==="
        $securityServices = @(
            "VSS", # Volume Shadow Copy
            "WinDefend", # Windows Defender
            "Sense", # Windows Defender Advanced Threat Protection Service
            "WdNisSvc", # Windows Defender Network Inspection
            "SecurityHealthService", # Windows Security Health Service
            "wscsvc", # Security Center
            "MpsSvc", # Windows Firewall
            "EventLog", # Windows Event Log
            "Schedule" # Task Scheduler
        )
        
        foreach ($service in $securityServices) {
            try {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    Write-Host "$($svc.DisplayName): $($svc.Status)"
                }
            }
            catch {
                # Silently continue if service not found
            }
        }

        # Check Windows Defender Status
        Write-Host "`n=== Windows Defender Status ==="
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                Write-Host "Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
                Write-Host "Antivirus Signature: $($defenderStatus.AntivirusSignatureVersion)"
                Write-Host "Last Scan Time: $($defenderStatus.LastFullScanTime)"
            }
        }
        catch {
            Write-Host "Windows Defender status check failed. May require different permissions."
        }

        # Check shared folders and permissions
        Write-Host "`n=== Network Shares ==="
        Get-SmbShare | ForEach-Object {
            Write-Host "`nShare: $($_.Name)"
            Write-Host "Path: $($_.Path)"
            try {
                Get-SmbShareAccess -Name $_.Name | Format-Table AccountName, AccessRight, AccessControlType -AutoSize
            }
            catch {
                Write-Host "Unable to retrieve share permissions."
            }
        }

        # Check firewall status
        Write-Host "`n=== Firewall Status ==="
        $firewallProfiles = Get-NetFirewallProfile
        $firewallProfiles | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize

        if ($Extended) {
            # Check startup programs
            Write-Host "`n=== Startup Programs ==="
            Get-CimInstance Win32_StartupCommand | 
                Select-Object Name, Command, Location, User | 
                Format-Table -AutoSize

            # Check scheduled tasks (security relevant)
            Write-Host "`n=== Important Scheduled Tasks ==="
            Get-ScheduledTask | Where-Object {
                $_.TaskPath -like "*Microsoft*Windows*" -and
                ($_.State -eq 'Ready' -or $_.State -eq 'Running')
            } | Select-Object TaskName, State, LastRunTime |
                Format-Table -AutoSize

            # Check system integrity
            Write-Host "`n=== System Integrity Check ==="
            $sfc = Start-Process -FilePath "sfc.exe" -ArgumentList "/verifyonly" -WindowStyle Hidden -PassThru -Wait
            Write-Host "System File Checker Exit Code: $($sfc.ExitCode)"

            # Check BitLocker Status
            Write-Host "`n=== BitLocker Status ==="
            Get-BitLockerVolume -ErrorAction SilentlyContinue | 
                Format-Table MountPoint, VolumeStatus, EncryptionPercentage -AutoSize
        }

        # Add MITM vulnerability checks
        Test-MITMVulnerabilities

        # Continue with other checks...
    }
    catch {
        Write-Log "Error during vulnerability checks: $($_.Exception.Message)" -Level Error
    }
}

function Test-ADCSVulnerabilities {
    Write-Log "Checking for ADCS vulnerabilities..."
    try {
        # Check if ADCS PowerShell module is available
        if (!(Get-Module -ListAvailable -Name PSPKI)) {
            Write-Log "PSPKI module not found. Some ADCS checks may be limited." -Level Warning
        }

        Write-OutputAndLog "`n=== ADCS Enterprise CA Information ==="
        try {
            $certutilOutput = certutil -dump
            $cas = $certutilOutput | Select-String "CA Name" -Context 0,1
            foreach ($ca in $cas) {
                Write-OutputAndLog "`nCA Details:"
                Write-OutputAndLog $ca.Context.PreContext
                Write-OutputAndLog $ca.Line
                Write-OutputAndLog $ca.Context.PostContext
            }
        }
        catch {
            Write-OutputAndLog "Unable to enumerate Enterprise CAs"
        }

        # Get all certificate templates
        Write-OutputAndLog "`n=== Certificate Template Analysis ==="
        
        # Search for certificate templates in AD
        $searchBase = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $adsi = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$searchBase"
        
        $templates = $adsi.Children | ForEach-Object {
            $props = $_.Properties
            
            # Check for vulnerable settings
            $flags = $props["msPKI-Enrollment-Flag"][0]
            $eku = $props["pKIExtendedKeyUsage"]
            $attributes = $props["msPKI-Certificate-Name-Flag"][0]
            $authenticationEnabled = $false
            $enrolleeSuppliesSubject = $false
            $noSecurityExtension = $false
            $enrollmentAgentTemplate = $false
            $vulnerableESCs = @()
            
            # Check for ESC1 conditions
            if ($attributes -band 0x00001) {
                $enrolleeSuppliesSubject = $true
            }
            
            # Check for client authentication
            if ($eku -contains "1.3.6.1.5.5.7.3.2") {
                $authenticationEnabled = $true
            }

            # Check if template requires no security extension
            if (-not ($flags -band 0x00000100)) {
                $noSecurityExtension = $true
            }

            # Check for ESC3 (Enrollment Agent Templates)
            if ($eku -contains "1.3.6.1.4.1.311.20.2.1") {
                $enrollmentAgentTemplate = $true
            }

            # Determine which ESCs apply
            if ($enrolleeSuppliesSubject -and $authenticationEnabled) {
                $vulnerableESCs += "ESC1 (Template Misconfiguration)"
            }
            if ($enrollmentAgentTemplate) {
                $vulnerableESCs += "ESC3 (Enrollment Agent)"
            }
            if ($noSecurityExtension -and $authenticationEnabled) {
                $vulnerableESCs += "ESC4 (No Security Extension)"
            }
            if ($eku.Count -eq 0 -and $authenticationEnabled) {
                $vulnerableESCs += "ESC7 (Unrestricted EKU)"
            }

            [PSCustomObject]@{
                'Template Name' = $props["displayName"][0]
                'Schema Version' = $props["msPKI-Template-Schema-Version"][0]
                'ESC Vulnerabilities' = if ($vulnerableESCs.Count -gt 0) { $vulnerableESCs -join ", " } else { "None" }
                'Enrollment Flags' = "0x{0:X}" -f $flags
                'Extended Key Usage' = if ($eku.Count -gt 0) { $eku -join ", " } else { "None" }
                'Client Auth' = $authenticationEnabled
                'Enrollee Supplies Subject' = $enrolleeSuppliesSubject
                'No Security Extension' = $noSecurityExtension
                'Enrollment Agent' = $enrollmentAgentTemplate
            }
        }

        # Display vulnerable templates with their specific ESC vulnerabilities
        Write-OutputAndLog "`n=== Vulnerable Certificate Templates Summary ==="
        $vulnerableTemplates = $templates | Where-Object { $_.'ESC Vulnerabilities' -ne "None" }
        if ($vulnerableTemplates) {
            $vulnerableTemplates | ForEach-Object {
                Write-OutputAndLog "`nTemplate: $($_.'Template Name')" -ForegroundColor Red
                Write-OutputAndLog "Vulnerabilities: $($_.'ESC Vulnerabilities')" -ForegroundColor Red
                Write-OutputAndLog "Settings that make it vulnerable:"
                if ($_.'Client Auth') { Write-OutputAndLog "- Client Authentication enabled" }
                if ($_.'Enrollee Supplies Subject') { Write-OutputAndLog "- Enrollee can supply subject" }
                if ($_.'No Security Extension') { Write-OutputAndLog "- No security extension required" }
                if ($_.'Enrollment Agent') { Write-OutputAndLog "- Enrollment Agent capabilities" }
                Write-OutputAndLog "Extended Key Usage: $($_.'Extended Key Usage')"
            }
        }
        else {
            Write-OutputAndLog "No vulnerable templates found." -ForegroundColor Green
        }

        # Check for ESC2 (Vulnerable Certificate Authority)
        Write-OutputAndLog "`n=== ESC2 Vulnerability Check ==="
        try {
            $caConfig = certutil -getreg policy\EditFlags
            if ($caConfig -match "EDITF_ATTRIBUTESUBJECTALTNAME2") {
                Write-OutputAndLog "WARNING: CA is configured to allow SAN attribute in requests (vulnerable to ESC2)" -ForegroundColor Red
                Write-OutputAndLog "This makes the CA vulnerable to ESC2 (SAN Modification) attacks"
            }
            else {
                Write-OutputAndLog "CA is not configured to allow SAN attribute in requests." -ForegroundColor Green
            }
        }
        catch {
            Write-OutputAndLog "Unable to check CA configuration for ESC2 vulnerability."
        }

        # Check for ESC8 (NTLM Relay to ADCS HTTP Endpoints)
        Write-OutputAndLog "`n=== ESC8 Vulnerability Check ==="
        try {
            $adcsWebEnrollment = Get-WebApplication -Name "certsrv" -ErrorAction SilentlyContinue
            if ($adcsWebEnrollment) {
                Write-OutputAndLog "WARNING: Web Enrollment is enabled - potentially vulnerable to ESC8 (NTLM Relay)" -ForegroundColor Yellow
                Write-OutputAndLog "Web Enrollment URL: $($adcsWebEnrollment.Path)"
                Write-OutputAndLog "Mitigation: Enable EPA (Extended Protection for Authentication) and HTTPS"
            }
            else {
                Write-OutputAndLog "Web Enrollment not found - likely not vulnerable to ESC8." -ForegroundColor Green
            }
        }
        catch {
            Write-OutputAndLog "Unable to check Web Enrollment status."
        }

    }
    catch {
        Write-Log "Error during ADCS vulnerability check: $($_.Exception.Message)" -Level Error
    }
}

# Main execution
Clear-Host
Write-OutputAndLog $Banner

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin) {
    Write-Log "Running without administrative privileges. Some features will be limited." -Level Warning
    Write-OutputAndLog @"

Limited functionality mode:
- Basic system information only
- Network adapter information (limited)
- Basic security checks
- No Active Directory checks
- No ADCS vulnerability checks
- Limited registry checks

For full functionality, run as Administrator.
"@ -ForegroundColor Yellow
}

# Execute reconnaissance modules
Write-OutputAndLog "`n=== Starting Reconnaissance ==="

# 1. System Information (works without admin)
$systemInfo = Get-SystemInfo

# 2. Basic Network Information (partial functionality without admin)
Write-OutputAndLog "`n=== Network Configuration ==="
try {
    # Get all network adapters (works without admin)
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    foreach ($adapter in $adapters) {
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
        $dnsServers = ($ipConfig.DNSServer | Where-Object AddressFamily -eq 2).ServerAddresses
        
        Write-OutputAndLog "`nAdapter: $($adapter.Name)"
        Write-OutputAndLog "MAC Address: $($adapter.MacAddress)"
        Write-OutputAndLog "IP Address(es):"
        $ipConfig.IPv4Address | ForEach-Object { Write-OutputAndLog "  $_" }
        Write-OutputAndLog "DNS Servers:"
        $dnsServers | ForEach-Object { Write-OutputAndLog "  $_" }
        
        if ($adapter.AdminStatus -eq 'Up' -and $ipConfig.IPv4DefaultGateway) {
            Write-OutputAndLog "Default Gateway: $($ipConfig.IPv4DefaultGateway.NextHop)"
        }
    }

    # Only run these if we have admin rights
    if ($isAdmin) {
        # Get ARP table
        Get-NetNeighbor | Where-Object State -eq 'Reachable' | 
            Write-TableOutput -Title "ARP Table"

        # Get routing table
        Get-NetRoute -Protocol NetMgmt | 
            Write-TableOutput -Title "Routing Table"

        # Get Network Shares
        Get-SmbShare | Write-TableOutput -Title "Network Shares"

        if ($Extended) {
            # Get Network Connection Profiles
            Get-NetConnectionProfile | Write-TableOutput -Title "Network Profiles"

            # Get Network Interface Statistics
            Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
                $stats = $_ | Get-NetAdapterStatistics
                [PSCustomObject]@{
                    'Adapter' = $_.Name
                    'ReceivedBytes' = [math]::Round($stats.ReceivedBytes/1MB, 2).ToString() + " MB"
                    'SentBytes' = [math]::Round($stats.SentBytes/1MB, 2).ToString() + " MB"
                    'TotalErrors' = $stats.ReceivedErrors + $stats.OutboundErrors
                }
            } | Write-TableOutput -Title "Interface Statistics"
        }
    }
}
catch {
    Write-Log "Error collecting network configuration: $($_.Exception.Message)" -Level Error
}

# 3. Active Directory Information (requires admin and modules)
if (!$SkipAD -and $isAdmin) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Get-EnhancedADInfo
    } else {
        Write-Log "ActiveDirectory module not available. To enable AD checks, install RSAT tools." -Level Warning
    }
    
    if (Get-Module -ListAvailable -Name PSPKI) {
        Test-ADCSVulnerabilities
    } else {
        Write-Log "PSPKI module not available. To enable ADCS checks, install PSPKI module." -Level Warning
    }
}

# 4. Basic Security Assessment (partial functionality without admin)
Get-VulnerabilityCheck

# Add summary at the end
$endTime = Get-Date
Write-OutputAndLog "`n=== Scan Summary ===" -ForegroundColor Green
Write-OutputAndLog "Scan completed at: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-OutputAndLog "Results saved to: $outputFile"
if (Test-Path $errorLogFile) {
    Write-OutputAndLog "Errors logged to: $errorLogFile" -ForegroundColor Yellow
}

Write-Log "Reconnaissance completed. Results have been saved to: $outputFile" -Level Info

