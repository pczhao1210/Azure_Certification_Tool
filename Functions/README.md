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
- Storage account used by Azure Functions, either newly created or existing
- Deployment blob container in the selected storage account
- Log Analytics workspace, either newly created or existing
- Application Insights instance, either newly created or existing
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
- `storageMode`: `new` or `existing`
- `storageAccountName`
- `storageSubscriptionId`, `storageResourceGroup`, `storageAccountResourceId` for existing storage
- `deploymentContainerName` to override the default deployment container name
- `logAnalyticsMode`: `new` or `existing`
- `logAnalyticsName`
- `logAnalyticsSubscriptionId`, `logAnalyticsResourceGroup`, `logAnalyticsResourceId` for an existing workspace
- `appInsightsMode`: `new` or `existing`
- `applicationInsightsName`
- `applicationInsightsSubscriptionId`, `applicationInsightsResourceGroup`, `applicationInsightsResourceId` for an existing Application Insights resource
- `applicationInsightsConnectionString` if you prefer to reuse an existing Application Insights resource without an ARM resource reference
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

Notes for existing resources:

- Existing Log Analytics is only used when `appInsightsMode` is `new` and `logAnalyticsMode` is `existing`.
- If the existing storage account is in another resource group or subscription, the template reuses the deployment container name but does not create that blob container for you. Create it first, then pass the same `deploymentContainerName`.

### Minimal Portal Example For `existing` Mode

If you click the Deploy to Azure button and want to reuse an existing storage account and an existing Application Insights resource, these are the minimum fields to fill in the portal form:

```text
location = japaneast
functionPlanName = cert-renewal-fc-plan
functionAppName = cert-renewal-func-app

storageMode = existing
storageAccountName = sharedfuncstorage
storageResourceGroup = shared-platform-rg
storageAccountResourceId = /subscriptions/<sub>/resourceGroups/shared-platform-rg/providers/Microsoft.Storage/storageAccounts/sharedfuncstorage
deploymentContainerName = app-package-cert-renewal

appInsightsMode = existing
applicationInsightsName = shared-ai
applicationInsightsResourceId = /subscriptions/<sub>/resourceGroups/monitoring-rg/providers/Microsoft.Insights/components/shared-ai
applicationInsightsConnectionString =

logAnalyticsMode = existing
logAnalyticsName = shared-logs
logAnalyticsResourceId =

acmeEmail = your-email@example.com
acmeDomains = example.com,*.example.com
azureKeyVaultUrl = https://your-keyvault.vault.azure.net/
azureCertificateName = your-ssl-certificate
dnsSubscriptionId = <dns-subscription-id>
dnsResourceGroup = your-dns-resource-group
dnsZoneName = example.com
```

Portal notes:

- When `appInsightsMode=existing`, the template only needs the existing Application Insights resource. `logAnalyticsMode` can stay `existing`, but its resource ID is not required in that case.
- If the existing storage account is outside the deployment resource group or subscription, `deploymentContainerName` must already exist in that storage account.
- Leave optional override fields empty unless you really need cross-scope override behavior.

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

- `STORAGE_MODE`
- `STORAGE_SUBSCRIPTION_ID`
- `STORAGE_RESOURCE_GROUP`
- `STORAGE_ACCOUNT_RESOURCE_ID`
- `DEPLOYMENT_CONTAINER_NAME`
- `LOG_ANALYTICS_MODE`
- `LOG_ANALYTICS_SUBSCRIPTION_ID`
- `LOG_ANALYTICS_RESOURCE_GROUP`
- `LOG_ANALYTICS_RESOURCE_ID`
- `APPINSIGHTS_MODE`
- `APPLICATION_INSIGHTS_SUBSCRIPTION_ID`
- `APPLICATION_INSIGHTS_RESOURCE_GROUP`
- `APPLICATION_INSIGHTS_RESOURCE_ID`
- `APPLICATION_INSIGHTS_CONNECTION_STRING`
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

Example using existing storage and monitoring resources:

```bash
export STORAGE_MODE="existing"
export STORAGE_RESOURCE_GROUP="shared-platform-rg"
export STORAGE_ACCOUNT_RESOURCE_ID="/subscriptions/<sub>/resourceGroups/shared-platform-rg/providers/Microsoft.Storage/storageAccounts/sharedfuncstorage"
export LOG_ANALYTICS_MODE="existing"
export LOG_ANALYTICS_RESOURCE_ID="/subscriptions/<sub>/resourceGroups/monitoring-rg/providers/Microsoft.OperationalInsights/workspaces/shared-logs"
export APPINSIGHTS_MODE="existing"
export APPLICATION_INSIGHTS_RESOURCE_ID="/subscriptions/<sub>/resourceGroups/monitoring-rg/providers/Microsoft.Insights/components/shared-ai"
export DEPLOYMENT_CONTAINER_NAME="app-package-cert-renewal"

./deploy.sh \
  --resource-group your-functions-rg \
  --location japaneast \
  --app-name your-cert-renewal-func \
  --storage-account sharedfuncstorage
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