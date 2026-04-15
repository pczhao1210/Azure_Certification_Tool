# Azure Functions Certificate Renewal

This folder contains a standalone Azure Functions implementation for renewing a Let's Encrypt certificate and importing it into Azure Key Vault.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpczhao1210%2FAzure_Certification_Tool%2Fmain%2FFunctions%2Fazuredeploy.json)

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
- `local.settings.json.example`: Local development settings template
- `azuredeploy.json`: ARM template for provisioning Azure resources
- `azuredeploy.parameters.example.json`: ARM parameter example
- `deploy.sh`: ARM deployment and code publish helper

## Required Azure Permissions

The Function App identity needs:

- `DNS Zone Contributor` on the Azure DNS zone resource group
- `Key Vault Certificates Officer` or equivalent certificate import permission on the Key Vault

## Required App Settings

Configure these in the Function App settings:

- `ACME_EMAIL`
- `ACME_DOMAINS`
- `AZURE_KEY_VAULT_URL`
- `AZURE_CERTIFICATE_NAME`
- `DNS_SUBSCRIPTION_ID`
- `DNS_RESOURCE_GROUP`
- `DNS_ZONE_NAME`

Optional settings:

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

1. Copy `local.settings.json.example` to `local.settings.json`
2. Fill in the values
3. Install dependencies from `requirements.txt`
4. Run Azure Functions Core Tools from this folder

## Deployment Notes

- Use a Linux Python Function App
- Prefer Managed Identity in Azure
- Timer schedule is defined in `function_app.py`
- Current schedule: daily at 02:00 UTC

## Deploy To Azure

The button above provisions the Azure resources from this ARM template:

- Template URL: `https://raw.githubusercontent.com/pczhao1210/Azure_Certification_Tool/main/Functions/azuredeploy.json`

The ARM deployment creates:

- Flex Consumption Function App (`FC1`)
- Storage account used by Azure Functions
- Deployment blob container
- Log Analytics workspace
- Application Insights instance
- System-assigned managed identity
- Automatic role assignment for the managed DNS zone used by challenges
- Automatic role assignment for the target Key Vault certificate import scope

After the portal deployment finishes, publish the function code with:

```bash
./deploy.sh --skip-infra --resource-group your-functions-rg --app-name your-cert-renewal-func
```

## ARM Parameters

See `azuredeploy.parameters.example.json` for a full example. The main parameters are:

- `location`
- `functionPlanName`
- `functionAppName`
- `storageAccountName`
- `logAnalyticsName`
- `applicationInsightsName`
- `acmeEmail`
- `acmeDomains`
- `azureKeyVaultUrl`
- `azureCertificateName`
- `dnsSubscriptionId`
- `dnsResourceGroup`
- `dnsZoneName`
- `dnsChallengeZoneName` and `dnsChallengeResourceGroup` when using a delegated challenge zone
- `keyVaultResourceGroup` when the Key Vault is not in the same resource group as the Function App deployment
- `keyVaultSubscriptionId` when the Key Vault is in another subscription
- `dnsZoneResourceId` and `keyVaultResourceId` only when you need to override the computed scopes

## Deploy Script

Use `deploy.sh` from this folder in either of these modes:

1. Provision infrastructure with ARM and then publish code
2. Publish code only to an already provisioned Function App

### Prerequisites

1. Azure CLI 2.60.0 or later
2. `zip` installed locally
3. Logged in with `az login`
4. Environment variables prepared for the certificate renewal settings when you want the script to also run the ARM deployment

### Required Environment Variables

- `ACME_EMAIL`
- `ACME_DOMAINS`
- `AZURE_KEY_VAULT_URL`
- `AZURE_CERTIFICATE_NAME`
- `DNS_RESOURCE_GROUP`
- `DNS_ZONE_NAME`

### Optional Environment Variables

- `DNS_SUBSCRIPTION_ID`
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
- `DNS_ZONE_RESOURCE_ID`
- `KEY_VAULT_RESOURCE_ID`

### Example

```bash
chmod +x deploy.sh

export ACME_EMAIL="your-email@example.com"
export ACME_DOMAINS="example.com,*.example.com"
export AZURE_KEY_VAULT_URL="https://your-keyvault.vault.azure.net/"
export AZURE_CERTIFICATE_NAME="your-ssl-certificate"
export DNS_RESOURCE_GROUP="your-dns-resource-group"
export DNS_ZONE_NAME="example.com"

./deploy.sh \
	--resource-group your-functions-rg \
	--location japaneast \
	--app-name your-cert-renewal-func \
	--storage-account yourfuncstorage123
```

Code-only publish after a portal-based ARM deployment:

```bash
./deploy.sh --skip-infra --resource-group your-functions-rg --app-name your-cert-renewal-func
```

### Optional Role Assignment

The ARM deployment now assigns required runtime roles by default:

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