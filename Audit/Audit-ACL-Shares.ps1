<#
.SYNOPSIS
Comprehensive ACL Audit Script for file shares.

.DESCRIPTION
This script discovers all SMB shares, administrative shares, DFS namespaces, and
federated/trusted domain shares on a server. It extracts detailed ACL information
for each share, analyzes Active Directory group memberships, and exports results
to CSV files with a summary report.

.NOTES
File Name      : Audit-ACL-Shares.ps1
Author         : Infrastructure Audit Toolkit
Prerequisite   : PowerShell 5.1 or later
                 Administrator privileges
Required Modules: ActiveDirectory

.EXAMPLE
.\Audit\Audit-ACL-Shares.ps1

.OUTPUTS
Creates the following files in a timestamped subfolder under the user's Downloads directory:
- Share_ACL_Report.csv          : Summary of all discovered shares
- Detailed_ACL_Report.csv       : Detailed ACL entries per share
- ACL_Audit_Log.txt             : Execution log
- Audit_Summary.md              : Markdown summary report
#>

# Check for administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrator privileges required. Please run as Administrator."
    exit 1
}

# Check and install required modules
$requiredModules = @("ActiveDirectory")
foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Host "Module $module is not installed. Installing..." -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force
        Write-Host "Module $module installed." -ForegroundColor Green
    }
}

# Configuration
$basePath = [System.IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), 'Downloads')
$OutputPath = Join-Path -Path $basePath -ChildPath "ACL_Audit_$(Get-Date -Format 'MM-dd-yyyy_HHmmss')"
$LogPath = "$OutputPath\ACL_Audit_Log.txt"
$CsvOutput = "$OutputPath\Share_ACL_Report.csv"
$DetailedCsvOutput = "$OutputPath\Detailed_ACL_Report.csv"

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry
}

# Function to get all SMB shares
function Get-AllSMBShares {
    Write-Log "Discovering SMB shares..."
    $excludedShares = @("ADMIN$", "IPC$", "C$", "PRINT$")
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object {
            $_.ShareType -eq "FileSystemDirectory" -and
            $_.Name -notin $excludedShares
        }
        if ($null -eq $shares) {
            Write-Log "No SMB shares found or result is null." "WARN"
            return @()
        }
        Write-Log "Found $($shares.Count) SMB shares"
        return $shares
    }
    catch {
        Write-Log "Error getting SMB shares: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

# Function to get hidden/administrative shares
function Get-AdministrativeShares {
    Write-Log "Discovering administrative shares..."
    try {
        $adminShares = Get-SmbShare -ErrorAction Stop | Where-Object { 
            $_.Name -match '\$$' -and 
            $_.ShareType -eq "FileSystemDirectory"
        }
        Write-Log "Found $($adminShares.Count) administrative shares"
        return $adminShares
    }
    catch {
        Write-Log "Error getting administrative shares: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

# Function to discover DFS namespaces and targets
function Get-DFSNamespaces {
    Write-Log "Discovering DFS namespaces..."
    try {
        $dfsNamespaces = @()
        
        # Get DFS namespaces
        $namespaces = Get-DfsnRoot -ErrorAction SilentlyContinue
        if ($namespaces) {
            foreach ($namespace in $namespaces) {
                Write-Log "Processing DFS namespace: $($namespace.Path)"
                $folders = Get-DfsnFolder -Path "$($namespace.Path)\*" -ErrorAction SilentlyContinue
                foreach ($folder in $folders) {
                    $targets = Get-DfsnFolderTarget -Path $folder.Path -ErrorAction SilentlyContinue
                    foreach ($target in $targets) {
                        $dfsNamespaces += [PSCustomObject]@{
                            Name = $folder.Name
                            Path = $folder.Path
                            TargetPath = $target.TargetPath
                            NamespacePath = $namespace.Path
                            State = $target.State
                        }
                    }
                }
            }
        }
        
        Write-Log "Found $($dfsNamespaces.Count) DFS folder targets"
        return $dfsNamespaces
    }
    catch {
        Write-Log "Error discovering DFS namespaces: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

# Function to get federated/domain suffix shares
function Get-FederatedShares {
    Write-Log "Discovering federated/domain suffix shares..."
    try {
        $federatedShares = @()
        
        # Get trusted domains
        $trustedDomains = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
        if ($trustedDomains) {
            foreach ($trust in $trustedDomains) {
                Write-Log "Checking trusted domain: $($trust.Name)"
                
                # Try to discover shares in trusted domains (requires appropriate permissions)
                try {
                    $domainShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
                        $_.Path -match "\\$($trust.Name)\\"
                    }
                    $federatedShares += $domainShares
                }
                catch {
                    Write-Log "Could not access shares in trusted domain $($trust.Name): $($_.Exception.Message)" "WARN"
                }
            }
        }
        
        Write-Log "Found $($federatedShares.Count) federated shares"
        return $federatedShares
    }
    catch {
        Write-Log "Error discovering federated shares: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

# Function to get detailed ACL information
function Get-DetailedACL {
    param([string]$Path)
    
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $accessRules = @()
        
        foreach ($rule in $acl.Access) {
            # Resolve identity to get detailed information
            $identity = $rule.IdentityReference
            $identityType = "Unknown"
            $domain = ""
            $displayName = ""
            
            try {
                if ($identity.Value -match "^(.+)\\(.+)$") {
                    $domain = $matches[1]
                    $accountName = $matches[2]
                    
                    # Try to get AD object details
                    try {
                        $adObject = Get-ADObject -Filter { SamAccountName -eq $accountName } -Properties objectClass, displayName -ErrorAction SilentlyContinue
                        if ($adObject) {
                            $identityType = $adObject.objectClass
                            $displayName = $adObject.displayName
                        }
                    }
                    catch {
                        # Fallback for local accounts or when AD module not available
                        $identityType = "Local/Unknown"
                    }
                }
                elseif ($identity.Value -match "^(.+)\\(.+)$") {
                    # Handle well-known SIDs
                    $identityType = "WellKnown"
                }
            }
            catch {
                $identityType = "Unknown"
            }
            
            $accessRules += [PSCustomObject]@{
                IdentityReference = $rule.IdentityReference.Value
                IdentityType = $identityType
                Domain = $domain
                DisplayName = $displayName
                AccessControlType = $rule.AccessControlType
                FileSystemRights = $rule.FileSystemRights
                IsInherited = $rule.IsInherited
                InheritanceFlags = $rule.InheritanceFlags
                PropagationFlags = $rule.PropagationFlags
            }
        }
        
        return @{
            Owner = $acl.Owner.Value
            AccessRules = $accessRules
            Sddl = $acl.Sddl
        }
    }
    catch {
        Write-Log "Error getting ACL for $Path`: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Function to analyze group membership
function Get-GroupMembershipAnalysis {
    param([string]$GroupName)
    
    try {
        $group = Get-ADGroup -Identity $GroupName -Properties Members -ErrorAction SilentlyContinue
        if ($group) {
            $memberCount = ($group.Members | Measure-Object).Count
            $directMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue
            
            $memberDetails = @()
            foreach ($member in $directMembers) {
                $memberDetails += [PSCustomObject]@{
                    Name = $member.Name
                    SamAccountName = $member.SamAccountName
                    ObjectClass = $member.ObjectClass
                    Enabled = if ($member.ObjectClass -eq "user") { (Get-ADUser -Identity $member.DistinguishedName -Properties Enabled -ErrorAction SilentlyContinue).Enabled } else { $null }
                }
            }
            
            return @{
                MemberCount = $memberCount
                DirectMembers = $memberDetails
            }
        }
    }
    catch {
        Write-Log "Error analyzing group membership for $GroupName`: $($_.Exception.Message)" "WARN"
    }
    
    return $null
}

# Main audit function
function Start-ACLAudit {
    Write-Log "Starting comprehensive ACL audit..."
    Write-Log "Output directory: $OutputPath"
    
    # Initialize results arrays
    $allShares = @()
    $detailedACLs = @()
    
    # Get all types of shares
    $smbShares = Get-AllSMBShares
    $adminShares = Get-AdministrativeShares
    $dfsShares = Get-DFSNamespaces
    $federatedShares = Get-FederatedShares
    
    # Process SMB shares
    foreach ($share in $smbShares) {
        Write-Log "Processing SMB share: $($share.Name)"
        
        $shareInfo = [PSCustomObject]@{
            ShareName = $share.Name
            SharePath = $share.Path
            ShareType = "SMB"
            Description = $share.Description
            ShareTypeValue = $share.ShareType
            CurrentUsers = $share.CurrentUsers
            Availability = $share.Availability
            AuditDate = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
        }
        
        $allShares += $shareInfo
        
        # Get detailed ACL
        if (Test-Path $share.Path) {
            $aclInfo = Get-DetailedACL -Path $share.Path
            if ($aclInfo) {
                foreach ($rule in $aclInfo.AccessRules) {
                    $detailedACLs += [PSCustomObject]@{
                        ShareName = $share.Name
                        SharePath = $share.Path
                        ShareType = "SMB"
                        IdentityReference = $rule.IdentityReference
                        IdentityType = $rule.IdentityType
                        Domain = $rule.Domain
                        DisplayName = $rule.DisplayName
                        AccessControlType = $rule.AccessControlType
                        FileSystemRights = $rule.FileSystemRights
                        IsInherited = $rule.IsInherited
                        InheritanceFlags = $rule.InheritanceFlags
                        PropagationFlags = $rule.PropagationFlags
                        Owner = $aclInfo.Owner
                        AuditDate = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
                    }
                    
                    # Analyze group membership for groups
                    if ($rule.IdentityType -eq "group") {
                        $groupAnalysis = Get-GroupMembershipAnalysis -GroupName $rule.IdentityReference
                        if ($groupAnalysis) {
                            Write-Log "Group $($rule.IdentityReference) has $($groupAnalysis.MemberCount) members"
                        }
                    }
                }
            }
        }
    }
    
    # Process administrative shares
    foreach ($share in $adminShares) {
        Write-Log "Processing administrative share: $($share.Name)"
        
        $shareInfo = [PSCustomObject]@{
            ShareName = $share.Name
            SharePath = $share.Path
            ShareType = "Administrative"
            Description = $share.Description
            ShareTypeValue = $share.ShareType
            CurrentUsers = $share.CurrentUsers
            Availability = $share.Availability
            AuditDate = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
        }
        
        $allShares += $shareInfo
        
        # Get detailed ACL for administrative shares (if accessible)
        if (Test-Path $share.Path) {
            $aclInfo = Get-DetailedACL -Path $share.Path
            if ($aclInfo) {
                foreach ($rule in $aclInfo.AccessRules) {
                    $detailedACLs += [PSCustomObject]@{
                        ShareName = $share.Name
                        SharePath = $share.Path
                        ShareType = "Administrative"
                        IdentityReference = $rule.IdentityReference
                        IdentityType = $rule.IdentityType
                        Domain = $rule.Domain
                        DisplayName = $rule.DisplayName
                        AccessControlType = $rule.AccessControlType
                        FileSystemRights = $rule.FileSystemRights
                        IsInherited = $rule.IsInherited
                        InheritanceFlags = $rule.InheritanceFlags
                        PropagationFlags = $rule.PropagationFlags
                        Owner = $aclInfo.Owner
                        AuditDate = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
                    }
                }
            }
        }
    }
    
    # Process DFS shares
    foreach ($dfsShare in $dfsShares) {
        Write-Log "Processing DFS share: $($dfsShare.Name)"
        
        $shareInfo = [PSCustomObject]@{
            ShareName = $dfsShare.Name
            SharePath = $dfsShare.TargetPath
            ShareType = "DFS"
            Description = "DFS Namespace: $($dfsShare.NamespacePath)"
            ShareTypeValue = "DFS"
            CurrentUsers = $null
            Availability = $dfsShare.State
            AuditDate = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
        }
        
        $allShares += $shareInfo
        
        # Get detailed ACL for DFS targets
        if (Test-Path $dfsShare.TargetPath) {
            $aclInfo = Get-DetailedACL -Path $dfsShare.TargetPath
            if ($aclInfo) {
                foreach ($rule in $aclInfo.AccessRules) {
                    $detailedACLs += [PSCustomObject]@{
                        ShareName = $dfsShare.Name
                        SharePath = $dfsShare.TargetPath
                        ShareType = "DFS"
                        IdentityReference = $rule.IdentityReference
                        IdentityType = $rule.IdentityType
                        Domain = $rule.Domain
                        DisplayName = $rule.DisplayName
                        AccessControlType = $rule.AccessControlType
                        FileSystemRights = $rule.FileSystemRights
                        IsInherited = $rule.IsInherited
                        InheritanceFlags = $rule.InheritanceFlags
                        PropagationFlags = $rule.PropagationFlags
                        Owner = $aclInfo.Owner
                        AuditDate = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
                    }
                }
            }
        }
    }
    
    # Export results
    Write-Log "Exporting results to CSV files..."
    
    $allShares | Export-Csv -Path $CsvOutput -NoTypeInformation -ErrorAction Stop
    $detailedACLs | Export-Csv -Path $DetailedCsvOutput -NoTypeInformation -ErrorAction Stop
    
    Write-Log "Share summary exported to: $CsvOutput"
    Write-Log "Detailed ACL report exported to: $DetailedCsvOutput"
    Write-Log "Audit completed successfully!"
    Write-Log "Total shares discovered: $($allShares.Count)"
    Write-Log "Total ACL entries processed: $($detailedACLs.Count)"
    
    # Generate summary report
    $summaryReport = @"
# ACL Audit Summary Report
Generated: $(Get-Date -Format 'MM-dd-yyyy HH:mm:ss')

## Share Discovery Summary
- Total SMB Shares: $($smbShares.Count)
- Administrative Shares: $($adminShares.Count)
- DFS Namespace Targets: $($dfsShares.Count)
- Federated Shares: $($federatedShares.Count)

## ACL Analysis Summary
- Total ACL Entries Processed: $($detailedACLs.Count)
- Unique Identities: $($detailedACLs | Select-Object -ExpandProperty IdentityReference | Sort-Object -Unique | Measure-Object).Count
- Groups Found: $($detailedACLs | Where-Object { $_.IdentityType -eq "group" } | Select-Object -ExpandProperty IdentityReference | Sort-Object -Unique | Measure-Object).Count

## Files Generated
- Share Summary: $CsvOutput
- Detailed ACL Report: $DetailedCsvOutput
- Log File: $LogPath

"@
    
    $summaryReport | Out-File -FilePath "$OutputPath\Audit_Summary.md" -Encoding UTF8
    Write-Log "Summary report generated: $OutputPath\Audit_Summary.md"
}

# Execute the audit
try {
    Start-ACLAudit
}
catch {
    Write-Log "Fatal error during audit: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
}

Write-Host "Audit completed. Check $OutputPath for results." -ForegroundColor Green