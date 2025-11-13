# Infrastructure Audit Toolkit

A collection of PowerShell scripts for auditing and managing Microsoft 365 infrastructure.

## Scripts

### Audit/
- **M365-MFA-Audit.ps1** - Audits MFA status for all users in a Microsoft 365 tenant

### Disable/
- **disabled-self-service-subscriptions.ps1** - Disables self-service purchasing for Microsoft 365 products

## Prerequisites

- PowerShell 5.1 or later
- Microsoft 365 admin credentials
- Required PowerShell modules (installed automatically by scripts):
  - Microsoft.Graph modules (Authentication, Users, Identity.SignIns, Reports)
  - MSCommerce

## Usage

Run scripts directly from PowerShell:

```powershell
.\Audit\M365-MFA-Audit.ps1
.\Disable\disabled-self-service-subscriptions.ps1
```

Results are exported to CSV files in your Downloads folder.

## License

MIT License - See [LICENSE](LICENSE) for details.
