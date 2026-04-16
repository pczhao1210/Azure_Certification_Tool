# Azure Functions Certificate Renewal

This folder contains a standalone Azure Functions implementation for renewing a Let's Encrypt certificate and importing it into Azure Key Vault.

## What It Does

- Runs as a Timer Trigger once per day at 02:00 UTC
- Checks whether the target Key Vault certificate is near expiry
- Uses DNS-01 validation in Azure DNS
- Imports the renewed certificate into Azure Key Vault
- Uses Managed Identity in Azure through DefaultAzureCredential

## Files

- `function_app.py`: Azure Functions timer entry point
- `cert_renewal.py`: Standalone renewal implementation
- `host.json`: Functions host configuration
- `requirements.txt`: Python dependencies
- `local.settings.json.example`: Local Azure Functions host settings template
- `settings.json`: The single configuration file used both for infrastructure deployment and runtime settings
- `azuredeploy.json`: ARM template invoked internally by `deploy.sh`
- `azuredeploy.parameters.example.json`: ARM parameter reference example
- `deploy.sh`: Unified deployment script for infrastructure, code, and configuration

## Required Azure Permissions

The Function App identity needs:

- `DNS Zone Contributor` on the Azure DNS zone resource group
- `Key Vault Certificates Officer` or equivalent certificate import permission on the Key Vault

## Required Configuration

The Function now reads configuration directly from `settings.json`. It no longer uses environment variables and no longer falls back to `local.settings.json` for business settings:

- `ACME_EMAIL`
- `ACME_DOMAINS`
- `AZURE_KEY_VAULT_URL`
- `AZURE_CERTIFICATE_NAME`
- `DNS_SUBSCRIPTION_ID`
- `DNS_RESOURCE_GROUP`
- `DNS_ZONE_NAME`

To avoid entering the same values twice, `settings.json` is also the input source for infrastructure deployment. Common infrastructure keys include:

- `AZURE_LOCATION`
- `AZURE_RESOURCE_GROUP`
- `AZURE_FUNCTION_APP_NAME`
- `AZURE_FUNCTION_PLAN_NAME`
- `AZURE_STORAGE_MODE`
- `AZURE_STORAGE_ACCOUNT_NAME`
- `AZURE_LOG_ANALYTICS_MODE`
- `AZURE_LOG_ANALYTICS_NAME`
- `AZURE_APP_INSIGHTS_MODE`
- `AZURE_APPLICATION_INSIGHTS_NAME`

Optional settings:

- `AZURE_STORAGE_SUBSCRIPTION_ID`
- `AZURE_STORAGE_RESOURCE_GROUP`
- `AZURE_STORAGE_ACCOUNT_RESOURCE_ID`
- `AZURE_DEPLOYMENT_CONTAINER_NAME`
- `AZURE_LOG_ANALYTICS_SUBSCRIPTION_ID`
- `AZURE_LOG_ANALYTICS_RESOURCE_GROUP`
- `AZURE_LOG_ANALYTICS_RESOURCE_ID`
- `AZURE_APPLICATION_INSIGHTS_SUBSCRIPTION_ID`
- `AZURE_APPLICATION_INSIGHTS_RESOURCE_GROUP`
- `AZURE_APPLICATION_INSIGHTS_RESOURCE_ID`
- `AZURE_APPLICATION_INSIGHTS_CONNECTION_STRING`
- `AZURE_MAXIMUM_INSTANCE_COUNT`
- `AZURE_INSTANCE_MEMORY_MB`
- `AZURE_ZONE_REDUNDANT`
- `DNS_ZONE_RESOURCE_ID`
- `DNS_ROLE_ASSIGNMENT_ENABLED`
- `KEY_VAULT_SUBSCRIPTION_ID`
- `KEY_VAULT_RESOURCE_GROUP`
- `KEY_VAULT_RESOURCE_ID`
- `KEY_VAULT_ROLE_ASSIGNMENT_ENABLED`
- `DNS_CHALLENGE_ZONE_NAME`
- `DNS_CHALLENGE_RESOURCE_GROUP`
- `RENEWAL_DAYS_BEFORE_EXPIRY`
- `SAVE_LOCAL_CERTS`
- `CERT_OUTPUT_DIR`
- `PFX_PASSWORD`
- `ACME_VALIDATION_TIMEOUT`
- `DNS_PROPAGATION_TIMEOUT`
- `DNS_PROPAGATION_INTERVAL`
- `DNS_PROPAGATION_STABLE_SECONDS`
- `PUBLIC_DNS_SERVERS`

## Local Run

1. If you want to start the Azure Functions host locally, copy `local.settings.json.example` to `local.settings.json`
2. Prepare and edit `settings.json`
3. Install dependencies from `requirements.txt`
4. Run Azure Functions Core Tools from this folder

## Deployment Notes

- Use a Linux Python Function App
- Prefer Managed Identity in Azure
- Timer schedule is defined in `function_app.py`
- Current schedule: daily at 02:00 UTC

## Deploy Script

`deploy.sh` now handles the full deployment workflow:

1. If `settings.json` does not exist, generate a default template and stop
2. Create or update the Azure resource group from `settings.json`
3. Invoke `azuredeploy.json` to create or update the Function App, Storage, Application Insights, Log Analytics, and role assignments
4. Package and upload the Functions code together with `settings.json`

### Prerequisites

1. Azure CLI 2.60.0 or later
2. `zip` installed locally
3. Logged in with `az login`

### Example

```bash
chmod +x deploy.sh
./deploy.sh
```

On first run, the script generates a default `settings.json` such as:

```json
{
	"AZURE_LOCATION": "japaneast",
	"AZURE_RESOURCE_GROUP": "your-functions-rg",
	"AZURE_FUNCTION_APP_NAME": "your-cert-renewal-func",
	"AZURE_FUNCTION_PLAN_NAME": "your-cert-renewal-func-plan",
	"AZURE_STORAGE_MODE": "new",
	"AZURE_STORAGE_ACCOUNT_NAME": "yourfuncstorageacct",
	"ACME_EMAIL": "your-email@example.com",
	"ACME_DOMAINS": "example.com,*.example.com",
	"AZURE_KEY_VAULT_URL": "https://your-keyvault.vault.azure.net/",
	"AZURE_CERTIFICATE_NAME": "your-ssl-certificate",
	"DNS_SUBSCRIPTION_ID": "your-subscription-id",
	"DNS_RESOURCE_GROUP": "your-dns-resource-group",
	"DNS_ZONE_NAME": "example.com"
}
```

Edit that file manually, then rerun `deploy.sh`. The script first deploys or updates the Azure resources and then uploads the code package together with `settings.json`, which the Function reads directly at runtime.

### Actual Deployment Flow

1. Run `deploy.sh` once to generate a default `settings.json`
2. Edit `settings.json` and fill in both infrastructure and business settings
3. Run `deploy.sh` again
4. The script creates or updates the resource group, deploys Azure resources, and uploads code plus configuration

### Optional Role Assignment

The ARM deployment invoked by `deploy.sh` now assigns required runtime roles by default:

- `DNS Zone Contributor` on the effective managed DNS zone scope
- `Key Vault Certificates Officer` on the target Key Vault scope

Use these optional environment variables only when the default scope discovery needs to be overridden:

- `DNS_ZONE_RESOURCE_ID`: used for `DNS Zone Contributor`
- `DNS_ROLE_ASSIGNMENT_ENABLED`: set to `false` to skip DNS role assignment
- `KEY_VAULT_SUBSCRIPTION_ID`: use when the vault is in another subscription
- `KEY_VAULT_RESOURCE_GROUP`: use when the vault is in another resource group
- `KEY_VAULT_RESOURCE_ID`: used for `Key Vault Certificates Officer`
- `KEY_VAULT_ROLE_ASSIGNMENT_ENABLED`: set to `false` to skip Key Vault role assignment

## Permission Notes

- DNS permissions are sufficient for this function because it only reads and updates TXT records through `DnsManagementClient`.
- Key Vault permissions are sufficient for this function because it only reads certificate metadata and imports a certificate version through `CertificateClient`.
- The Key Vault role assignment assumes the vault uses Azure RBAC. If the vault still uses the legacy access policy model, you must add an access policy separately.