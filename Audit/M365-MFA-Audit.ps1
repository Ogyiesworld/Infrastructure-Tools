# M365-MFA-Audit.ps1
# Microsoft 365 MFA Status Audit Script
# This script checks the MFA status of all users in a Microsoft 365 tenant

# Make sure the required modules are installed
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Reports"
)

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Warning "Module $module is not installed. Please install it using: Install-Module $module -Scope CurrentUser"
    }
}

# Helper function to interpret authentication methods
function Get-AuthenticationMethodDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$AuthMethods
    )
    
    # Initialize result object with all possible auth methods
    $result = [PSCustomObject]@{
        HasMfaMethod = $false
        HasPhoneAuth = $false
        HasAppAuth = $false
        HasFido2 = $false
        HasWindowsHello = $false
        HasEmail = $false
        HasSoftwareOath = $false
        HasPassword = $false
        HasTemporaryAccessPass = $false
        MethodTypes = @()
        MethodDetails = @{}
    }
    
    if ($null -eq $AuthMethods -or $AuthMethods.Count -eq 0) {
        return $result
    }
    
    # Define method types with their friendly names and corresponding property flags
    $microsoftAuthenticator = @{ Name = "Microsoft Authenticator"; Flag = "HasAppAuth" }
    $phoneAuth = @{ Name = "Phone"; Flag = "HasPhoneAuth" }
    $fido2 = @{ Name = "FIDO2 Security Key"; Flag = "HasFido2" }
    $windowsHello = @{ Name = "Windows Hello"; Flag = "HasWindowsHello" }
    $email = @{ Name = "Email"; Flag = "HasEmail" }
    $password = @{ Name = "Password"; Flag = "HasPassword" }
    $softwareOath = @{ Name = "Authenticator App"; Flag = "HasSoftwareOath" }
    $temporaryAccessPass = @{ Name = "Temporary Access Pass"; Flag = "HasTemporaryAccessPass" }
    
    # Create the mapping hashtable
    $methodTypeMap = @{}
    $methodTypeMap["#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"] = $microsoftAuthenticator
    $methodTypeMap["#microsoft.graph.phoneAuthenticationMethod"] = $phoneAuth
    $methodTypeMap["#microsoft.graph.fido2AuthenticationMethod"] = $fido2
    $methodTypeMap["#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"] = $windowsHello
    $methodTypeMap["#microsoft.graph.emailAuthenticationMethod"] = $email
    $methodTypeMap["#microsoft.graph.passwordAuthenticationMethod"] = $password
    $methodTypeMap["#microsoft.graph.softwareOathAuthenticationMethod"] = $softwareOath
    $methodTypeMap["#microsoft.graph.temporaryAccessPassAuthenticationMethod"] = $temporaryAccessPass
    
    # Check authentication methods
    foreach ($method in $AuthMethods) {
        # Get the method type if available
        if ($method.AdditionalProperties -and $method.AdditionalProperties.ContainsKey("@odata.type")) {
            $methodType = $method.AdditionalProperties["@odata.type"]
            
            # Add to method types list and set appropriate flags
            if ($methodTypeMap.ContainsKey($methodType)) {
                $methodInfo = $methodTypeMap[$methodType]
                $friendlyName = $methodInfo.Name
                $flagName = $methodInfo.Flag
                
                # Add to method types list
                $result.MethodTypes += $friendlyName
                $result.MethodDetails[$friendlyName] = $true
                
                # Set the corresponding flag to true
                $result.$flagName = $true
                
                # Any method except password and temporary access pass qualifies as MFA
                if ($flagName -ne "HasPassword" -and $flagName -ne "HasTemporaryAccessPass") {
                    $result.HasMfaMethod = $true
                }
            }
            else {
                # Handle unknown types
                $friendlyName = $methodType.Replace("#microsoft.graph.", "").Replace("AuthenticationMethod", "")
                $result.MethodTypes += $friendlyName
                $result.MethodDetails[$friendlyName] = $true
                
                # Unknown methods are considered MFA for safety
                $result.HasMfaMethod = $true
            }
            
            # We've already set the flags in the previous section, so we don't need this switch block anymore
        }
    }
    
    return $result
}

# Create output directory if it doesn't exist
$outputPath = [System.IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), 'Downloads')
if (!(Test-Path -Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
    Write-Host "Created output directory: $outputPath" -ForegroundColor Green
}

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow

# First disconnect any existing connections
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

# Connect with the required scopes
Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All", "AuditLog.Read.All"
Write-Host "Connected to Microsoft Graph" -ForegroundColor Green

# Get all users
Write-Host "Getting all users..." -ForegroundColor Yellow
$users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled
Write-Host "Found $($users.Count) users" -ForegroundColor Green

# Get all available successful sign-in logs (retention period varies by license: 30 days free, 30+ days Premium)
Write-Host "Getting all available successful sign-in logs..." -ForegroundColor Yellow
Write-Host "  Note: Retention is typically 30 days (Free/Basic) or up to 30 days (Premium P1/P2)" -ForegroundColor Gray
try {
    # Query successful sign-ins only (errorCode 0 = success) - no date filter to get all available history
    $signInLogs = Get-MgAuditLogSignIn -Filter "status/errorCode eq 0" -All
    Write-Host "Found $($signInLogs.Count) successful sign-in events in retention period" -ForegroundColor Green
    
    # Group sign-ins by user and type for faster lookup
    Write-Host "Processing sign-in data..." -ForegroundColor Yellow
    $signInsByUser = @{}
    foreach ($log in $signInLogs) {
        $userId = $log.UserId
        if (-not $signInsByUser.ContainsKey($userId)) {
            $signInsByUser[$userId] = @{
                Interactive = @()
                NonInteractive = @()
            }
        }
        
        # isInteractive property determines type
        if ($log.IsInteractive) {
            $signInsByUser[$userId].Interactive += $log.CreatedDateTime
        } else {
            $signInsByUser[$userId].NonInteractive += $log.CreatedDateTime
        }
    }
    Write-Host "Processed sign-in data for $($signInsByUser.Count) users" -ForegroundColor Green
}
catch {
    Write-Warning "Could not retrieve sign-in logs. Continuing without sign-in data. Error: $_"
    $signInsByUser = @{}
}

# Initialize results array
$results = @()

# Loop through each user and check their MFA status
Write-Host "Checking MFA status for users..." -ForegroundColor Yellow

# Add a parameter to enable verbose debug output
$VerboseDebug = $false  # Set to $true to see detailed debug information for each user

# Process all users
$processedCount = 0

foreach ($user in $users) {
    $processedCount++
    
    # Show progress every 10 users
    if ($processedCount % 10 -eq 0) {
        Write-Host "Processed $processedCount of $($users.Count) users..." -ForegroundColor Yellow
    }
    
    # Only show detailed user info if in verbose mode or for the first few users
    $showUserDetails = $VerboseDebug -or $processedCount -le 3
    
    if ($showUserDetails) {
        Write-Host "Processing user: $($user.DisplayName)" -ForegroundColor Cyan
    }
    
    try {
        # Get authentication methods for the user
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
        
        if ($showUserDetails) {
            Write-Host "  Found $($authMethods.Count) authentication methods" -ForegroundColor Yellow
            
            # Debug: Show raw authentication method types if in verbose mode
            if ($VerboseDebug) {
                Write-Host "  Raw authentication method data:" -ForegroundColor Magenta
                foreach ($method in $authMethods) {
                    if ($method.AdditionalProperties -and $method.AdditionalProperties.ContainsKey("@odata.type")) {
                        $methodType = $method.AdditionalProperties["@odata.type"]
                        Write-Host "    - $methodType" -ForegroundColor Magenta
                        
                        # Show all additional properties for debugging
                        Write-Host "      Properties:" -ForegroundColor Gray
                        foreach ($key in $method.AdditionalProperties.Keys) {
                            Write-Host "        $key = $($method.AdditionalProperties[$key])" -ForegroundColor Gray
                        }
                    }
                    else {
                        Write-Host "    - Unknown method type (no @odata.type)" -ForegroundColor Red
                    }
                }
            }
        }
        
        # Get authentication method details
        $authDetails = Get-AuthenticationMethodDetails -AuthMethods $authMethods
        
        # Debug: Show processed authentication details if in verbose mode
        if ($showUserDetails) {
            Write-Host "  Processed authentication details:" -ForegroundColor Cyan
            Write-Host "    MFA Enabled: $($authDetails.HasMfaMethod)" -ForegroundColor $(if ($authDetails.HasMfaMethod) { "Green" } else { "Red" })
            
            if ($VerboseDebug) {
                Write-Host "    Microsoft Authenticator: $($authDetails.HasAppAuth)" -ForegroundColor $(if ($authDetails.HasAppAuth) { "Green" } else { "Gray" })
                Write-Host "    Phone Auth: $($authDetails.HasPhoneAuth)" -ForegroundColor $(if ($authDetails.HasPhoneAuth) { "Green" } else { "Gray" })
                Write-Host "    FIDO2: $($authDetails.HasFido2)" -ForegroundColor $(if ($authDetails.HasFido2) { "Green" } else { "Gray" })
                Write-Host "    Method Types: $($authDetails.MethodTypes -join ", ")" -ForegroundColor Cyan
            }
        }
        
        # Get SUCCESSFUL sign-in activity from audit logs (errorCode 0 only)
        $lastSuccessfulInteractiveSignIn = $null
        $lastSuccessfulNonInteractiveSignIn = $null
        $daysSinceLastSuccessfulSignIn = $null
        
        if ($signInsByUser.ContainsKey($user.Id)) {
            $userSignIns = $signInsByUser[$user.Id]
            
            # Get most recent successful interactive sign-in
            if ($userSignIns.Interactive.Count -gt 0) {
                $lastSuccessfulInteractiveSignIn = ($userSignIns.Interactive | Sort-Object -Descending | Select-Object -First 1)
            }
            
            # Get most recent successful non-interactive sign-in
            if ($userSignIns.NonInteractive.Count -gt 0) {
                $lastSuccessfulNonInteractiveSignIn = ($userSignIns.NonInteractive | Sort-Object -Descending | Select-Object -First 1)
            }
            
            # Calculate days since last successful sign-in (use the most recent successful one)
            $mostRecentSuccessfulSignIn = @($lastSuccessfulInteractiveSignIn, $lastSuccessfulNonInteractiveSignIn) | Where-Object { $_ -ne $null } | Sort-Object -Descending | Select-Object -First 1
            if ($mostRecentSuccessfulSignIn) {
                $daysSinceLastSuccessfulSignIn = [math]::Round((New-TimeSpan -Start $mostRecentSuccessfulSignIn -End (Get-Date)).TotalDays, 0)
            }
        }
        
        # Create result object with detailed auth methods
        $resultObj = [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            MFAEnabled = $authDetails.HasMfaMethod
            AuthMethodCount = $authMethods.Count
            AccountEnabled = $user.AccountEnabled
            LastSuccessfulInteractiveSignIn = $lastSuccessfulInteractiveSignIn
            LastSuccessfulNonInteractiveSignIn = $lastSuccessfulNonInteractiveSignIn
            DaysSinceLastSuccessfulSignIn = $daysSinceLastSuccessfulSignIn
            MicrosoftAuthenticator = $authDetails.HasAppAuth
            PhoneAuth = $authDetails.HasPhoneAuth
            FIDO2SecurityKey = $authDetails.HasFido2
            WindowsHello = $authDetails.HasWindowsHello
            Email = $authDetails.HasEmail
            AuthenticatorApp = $authDetails.HasSoftwareOath
            Password = $authDetails.HasPassword
            TemporaryAccessPass = $authDetails.HasTemporaryAccessPass
            AuthMethods = ($authDetails.MethodTypes -join ", ")
        }
        
        $results += $resultObj
        
        # Display results for this user
        Write-Host "  MFA Enabled: $($authDetails.HasMfaMethod)" -ForegroundColor $(if ($authDetails.HasMfaMethod) { "Green" } else { "Red" })
    }
    catch {
        Write-Warning "Error processing user $($user.UserPrincipalName): $_"
    }
}

# Output results to console
Write-Host "\nSample Results:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Output to CSV
$csvPath = Join-Path -Path $outputPath -ChildPath "$(Get-Date -Format 'yyyy-MM-dd')_MFA_Results.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Results exported to: $csvPath" -ForegroundColor Green

# Disconnect from Microsoft Graph
Disconnect-MgGraph
Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Green
