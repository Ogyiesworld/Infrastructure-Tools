<#
.SYNOPSIS
Disables all self-service subscriptions in Microsoft 365.

.DESCRIPTION
This script disables all self-service purchase capabilities for Microsoft 365 products.
It checks for and installs the required MSCommerce module if not present, connects to
Microsoft 365, and then disables self-service purchasing for all available products.
Results are exported to a CSV file with the current date in the filename.

.NOTES
File Name      : disabled-self-service-subscriptions.ps1
Author         : IT Administration
Prerequisite   : PowerShell 5.1 or later
                 MSCommerce module
                 Microsoft 365 admin credentials
Required Modules: MSCommerce

.EXAMPLE
.\disabled-self-service-subscriptions.ps1

.OUTPUTS
Creates a CSV file in the user's Downloads folder with the naming format: MM-dd-yyyy-disabled-self-service-subscriptions.csv

.LINK
https://docs.microsoft.com/en-us/microsoft-365/commerce/subscriptions/allowselfservicepurchase-powershell
#>

# Check if required module is installed
if (Get-Module -ListAvailable -Name MSCommerce) {
    Write-Host "Module is installed."
} else {
    install-module MSCommerce -Scope CurrentUser
    Write-Host "Module installed."
}
# Import the MSCommerce module
import-module MSCommerce

# Create output directory if it doesn't exist
$outputPath = [System.IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), 'Downloads')
if (!(Test-Path -Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
    Write-Host "Created output directory: $outputPath" -ForegroundColor Green
}

# Connect to Microsoft 365 commerce service
Connect-MSCommerce

# List all products that currently have self-service purchasing enabled
Get-MSCommerceProductPolicies -PolicyId AllowSelfServicePurchase | Where-Object { $_.PolicyValue -eq "Enabled" }

# Get all products and gather their IDs in an array to be used to disable self-service purchasing
$products = Get-MSCommerceProductPolicies -PolicyId AllowSelfServicePurchase

# Disable self-service purchasing for each product
foreach ($product in $products) {
    Update-MSCommerceProductPolicy -PolicyId AllowSelfServicePurchase -ProductId $product.ProductId -Value "Disabled" -ErrorAction SilentlyContinue | Out-Null
}

# List all products that now have self-service purchasing disabled
Get-MSCommerceProductPolicies -PolicyId AllowSelfServicePurchase | Where-Object { $_.PolicyValue -eq "Disabled" }

# Export the results to a CSV file in Downloads folder with the current date in the filename
$csvPath = Join-Path -Path $outputPath -ChildPath "$(Get-Date -Format 'MM-dd-yyyy')-disabled-self-service-subscriptions.csv"
Get-MSCommerceProductPolicies -PolicyId AllowSelfServicePurchase | Where-Object { $_.PolicyValue -eq "Disabled" } | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Results exported to: $csvPath" -ForegroundColor Green
