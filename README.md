# Azure Let's Encrypt Certificate Manager

Automatically obtain Let's Encrypt SSL certificates and upload them to Azure Key Vault using Python.

[中文文档 / Chinese Documentation](README_CN.md)

## Features

- Automatically obtain Let's Encrypt certificates using DNS-01 challenge
- Support for wildcard certificates (*.domain.com)
- Automatic Azure DNS TXT record management
- Automatic certificate upload to Azure Key Vault
- Local certificate backup (organized by year-month)
- **Smart certificate renewal**: Automatically check certificate expiry time, only renew when needed
- Generate PFX files with password protection

## Requirements

- Python 3.7+
- Azure subscription
- Azure DNS zone
- Azure Key Vault
- Azure Service Principal (App Registration)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

1. Copy the example configuration file:
```bash
cp config.example.json config.json
```

2. Edit `config.json` with your actual configuration:
   - ACME email and domains
   - Azure Key Vault information
   - Azure DNS configuration
   - Azure authentication information

## Azure Permissions

Ensure your Azure Service Principal has the following permissions:

1. **DNS Zone Contributor** - For managing DNS records
2. **Key Vault Certificate Officer** - For uploading certificates

## Usage

### Basic Usage
```bash
python cert_manager.py
```

### Command Line Arguments
```bash
# Force certificate renewal (ignore expiry check)
python cert_manager.py --force

# Set renewal to start 15 days before expiry
python cert_manager.py --days 15

# Combined usage
python cert_manager.py --force --days 15
```

### Generate PFX Files
```bash
# Generate PFX files with password protection
python create_pfx.py

# Verify PFX file integrity
python verify_pfx.py
```

## Configuration Reference

### ACME Configuration
- `email`: Let's Encrypt account email
- `domains`: List of domains to request certificates for
- `directory_url`: ACME server address

### Azure Configuration
- `key_vault_url`: Key Vault URL
- `tenant_id`: Azure tenant ID
- `client_id`: Application ID
- `client_secret`: Application secret
- `certificate_name`: Certificate name in Key Vault

### DNS Configuration
- `provider`: DNS provider (currently supports azure)
- `subscription_id`: Azure subscription ID
- `resource_group`: Resource group containing DNS zone
- `zone_name`: DNS zone name

## Automation

### Windows Scheduled Task
```cmd
# Check daily, only renew when needed
schtasks /create /tn "SSL Certificate Update" /tr "python E:\path\to\cert_manager.py" /sc daily
```

### Linux Cron
```bash
# Check daily at 2 AM
0 2 * * * cd /path/to/cert_update && python cert_manager.py
```

## Notes

- Ensure DNS zone is properly configured
- Service Principal needs appropriate permissions
- Certificates are valid for 90 days, default renewal 30 days before expiry
- Configuration file contains sensitive information, do not commit to version control
- Program automatically checks certificate status, only renews when necessary
- PFX files are generated with password "1234" by default

## License

MIT License