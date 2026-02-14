# Infrastructure Toolkit

A collection of PowerShell scripts for auditing, securing, and managing Windows and Microsoft 365 infrastructure.

## Scripts

### Audit/
- **Audit-ACL-Shares.ps1** - Discovers all SMB, administrative, DFS, and federated shares on a server and exports detailed ACL reports
- **M365-MFA-Audit.ps1** - Audits MFA status and sign-in activity for all users in a Microsoft 365 tenant

### Disable/
- **disabled-self-service-subscriptions.ps1** - Disables self-service purchasing for Microsoft 365 products

### Security/
- **Disable_TLS_1.0_1.1_enable_1.2.ps1** - Hardens TLS configuration by disabling TLS 1.0/1.1 and enabling TLS 1.2 with .NET strong cryptography

## Prerequisites

- PowerShell 5.1 or later
- Administrator privileges (required by ACL audit and TLS scripts; you will be prompted)
- Microsoft 365 admin credentials (required by MFA audit and self-service scripts)
- Required PowerShell modules (installed automatically by scripts if missing):
  - Microsoft.Graph modules (Authentication, Users, Identity.SignIns, Reports)
  - MSCommerce
  - ActiveDirectory

## Usage

Run scripts directly from PowerShell:

```powershell
.\Audit\Audit-ACL-Shares.ps1
.\Audit\M365-MFA-Audit.ps1
.\Disable\disabled-self-service-subscriptions.ps1
.\Security\Disable_TLS_1.0_1.1_enable_1.2.ps1
```

All output is exported to the user's Downloads folder. Each script includes a full PowerShell help block — run `Get-Help .\<script>` for details.

## License

MIT License - See [LICENSE](LICENSE) for details.
