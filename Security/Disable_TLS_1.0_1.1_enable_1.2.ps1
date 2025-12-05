#  TLS Configuration Script
# Check for administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrator privileges required. Please run as Administrator."
    exit 1
}

# Verify temp directory exists and create log file
$tempPath = "C:\temp"
if (-not (Test-Path $tempPath)) {
    try {
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        Write-Host "Created temp directory: $tempPath"
    } catch {
        Write-Error "Failed to create temp directory: $($_.Exception.Message)"
        exit 1
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFile = Join-Path $tempPath "TLS_Configuration_$timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    Write-Host $logEntry
}

function Backup-RegistrySettings {
    try {
        Write-Log "Creating registry backup..." "INFO"
        $backupFile = Join-Path $tempPath "TLS_Configuration_Backup_$timestamp.reg"
        
        # Export SCHANNEL protocols registry key
        $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
        if (Test-Path $schannelPath) {
            reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" $backupFile /y | Out-Null
            Write-Log "Registry backup created: $backupFile" "SUCCESS"
        } else {
            Write-Log "SCHANNEL Protocols registry key not found - creating empty backup" "WARNING"
            "Windows Registry Editor Version 5.00" | Out-File -FilePath $backupFile -Encoding UTF8
        }
        
        # Also backup .NET Framework settings
        $netBackupFile = Join-Path $tempPath "NET_Framework_Backup_$timestamp.reg"
        $netPath = "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319"
        if (Test-Path $netPath) {
            reg export "HKLM\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" $netBackupFile /y | Out-Null
            Write-Log ".NET Framework backup created: $netBackupFile" "SUCCESS"
        }
        
        # Backup 32-bit .NET Framework settings on 64-bit systems
        $netWowPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319"
        if (Test-Path $netWowPath) {
            $netWowBackupFile = Join-Path $tempPath "NET_Framework_Wow6432_Backup_$timestamp.reg"
            reg export "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319" $netWowBackupFile /y | Out-Null
            Write-Log ".NET Framework x86 backup created: $netWowBackupFile" "SUCCESS"
        }
        
    } catch {
        Write-Log "Failed to create registry backup: $($_.Exception.Message)" "ERROR"
        # Continue with script execution even if backup fails
    }
}

Write-Log "Starting TLS configuration script" "INFO"

# Create registry backup before making changes
Backup-RegistrySettings

# Disable TLS 1.0
try {
    Write-Log "Disabling TLS 1.0..." "INFO"
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value 1 -Type DWord -Force
    Write-Log "Successfully disabled TLS 1.0" "SUCCESS"
} catch {
    Write-Log "Failed to disable TLS 1.0: $($_.Exception.Message)" "ERROR"
}

# Disable TLS 1.1
try {
    Write-Log "Disabling TLS 1.1..." "INFO"
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value 1 -Type DWord -Force
    Write-Log "Successfully disabled TLS 1.1" "SUCCESS"
} catch {
    Write-Log "Failed to disable TLS 1.1: $($_.Exception.Message)" "ERROR"
}

# Explicitly enable TLS 1.2
try {
    Write-Log "Enabling TLS 1.2..." "INFO"
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value 0 -Type DWord -Force
    Write-Log "Successfully enabled TLS 1.2" "SUCCESS"
} catch {
    Write-Log "Failed to enable TLS 1.2: $($_.Exception.Message)" "ERROR"
}

# Enable .NET strong crypto (critical for Outlook, LOB apps)
try {
    Write-Log "Enabling .NET strong crypto..." "INFO"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force
    Write-Log "Successfully enabled .NET strong crypto" "SUCCESS"
} catch {
    Write-Log "Failed to enable .NET strong crypto: $($_.Exception.Message)" "ERROR"
}

Write-Log "TLS configuration script completed" "INFO"
Write-Host "`nLog file created at: $logFile" -ForegroundColor Green
Write-Host "`nA system restart is required for changes to take effect." -ForegroundColor Yellow