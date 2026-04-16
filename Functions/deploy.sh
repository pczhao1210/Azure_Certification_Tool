#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_PATH="${SCRIPT_DIR}/functionapp.zip"
SETTINGS_PATH="${SCRIPT_DIR}/settings.json"
ARM_TEMPLATE_PATH="${SCRIPT_DIR}/azuredeploy.json"
TMP_PARAMETERS_FILE=""

cleanup() {
  if [[ -n "$TMP_PARAMETERS_FILE" && -f "$TMP_PARAMETERS_FILE" ]]; then
    rm -f "$TMP_PARAMETERS_FILE"
  fi
}

trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage:
  ./deploy.sh

This script creates or updates the Azure resources defined by azuredeploy.json,
then packages and uploads the Functions code together with settings.json.

If settings.json does not exist in this folder, the script creates a default template for you to edit manually.
EOF
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
fi

command -v az >/dev/null || { echo "Azure CLI is required" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

if [[ ! -f "$SETTINGS_PATH" ]]; then
  cat > "$SETTINGS_PATH" <<'EOF'
{
  "AZURE_LOCATION": "japaneast",
  "AZURE_RESOURCE_GROUP": "your-functions-rg",
  "AZURE_FUNCTION_APP_NAME": "your-cert-renewal-func",
  "AZURE_FUNCTION_PLAN_NAME": "your-cert-renewal-func-plan",
  "AZURE_STORAGE_MODE": "new",
  "AZURE_STORAGE_ACCOUNT_NAME": "yourfuncstorageacct",
  "AZURE_STORAGE_SUBSCRIPTION_ID": "",
  "AZURE_STORAGE_RESOURCE_GROUP": "",
  "AZURE_STORAGE_ACCOUNT_RESOURCE_ID": "",
  "AZURE_DEPLOYMENT_CONTAINER_NAME": "",
  "AZURE_LOG_ANALYTICS_MODE": "new",
  "AZURE_LOG_ANALYTICS_NAME": "your-cert-renewal-func-logs",
  "AZURE_LOG_ANALYTICS_SUBSCRIPTION_ID": "",
  "AZURE_LOG_ANALYTICS_RESOURCE_GROUP": "",
  "AZURE_LOG_ANALYTICS_RESOURCE_ID": "",
  "AZURE_APP_INSIGHTS_MODE": "new",
  "AZURE_APPLICATION_INSIGHTS_NAME": "your-cert-renewal-func-ai",
  "AZURE_APPLICATION_INSIGHTS_SUBSCRIPTION_ID": "",
  "AZURE_APPLICATION_INSIGHTS_RESOURCE_GROUP": "",
  "AZURE_APPLICATION_INSIGHTS_RESOURCE_ID": "",
  "AZURE_APPLICATION_INSIGHTS_CONNECTION_STRING": "",
  "AZURE_MAXIMUM_INSTANCE_COUNT": "40",
  "AZURE_INSTANCE_MEMORY_MB": "2048",
  "AZURE_ZONE_REDUNDANT": "false",
  "DNS_ZONE_RESOURCE_ID": "",
  "DNS_ROLE_ASSIGNMENT_ENABLED": "true",
  "KEY_VAULT_SUBSCRIPTION_ID": "",
  "KEY_VAULT_RESOURCE_GROUP": "",
  "KEY_VAULT_RESOURCE_ID": "",
  "KEY_VAULT_ROLE_ASSIGNMENT_ENABLED": "true",
  "ACME_EMAIL": "your-email@example.com",
  "ACME_DOMAINS": "example.com,*.example.com",
  "ACME_DIRECTORY_URL": "https://acme-v02.api.letsencrypt.org/directory",
  "AZURE_KEY_VAULT_URL": "https://your-keyvault.vault.azure.net/",
  "AZURE_CERTIFICATE_NAME": "your-ssl-certificate",
  "DNS_SUBSCRIPTION_ID": "your-subscription-id",
  "DNS_RESOURCE_GROUP": "your-dns-resource-group",
  "DNS_ZONE_NAME": "example.com",
  "DNS_CHALLENGE_ZONE_NAME": "",
  "DNS_CHALLENGE_RESOURCE_GROUP": "",
  "RENEWAL_DAYS_BEFORE_EXPIRY": "30",
  "SAVE_LOCAL_CERTS": "false",
  "CERT_OUTPUT_DIR": "/tmp/certificates",
  "PFX_PASSWORD": "",
  "ACME_VALIDATION_TIMEOUT": "900",
  "DNS_PROPAGATION_TIMEOUT": "900",
  "DNS_PROPAGATION_INTERVAL": "15",
  "DNS_PROPAGATION_STABLE_SECONDS": "90",
  "PUBLIC_DNS_SERVERS": "8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
}
EOF
  echo "Created default settings template: $SETTINGS_PATH"
  echo "Edit that file first, then rerun deploy.sh to deploy infrastructure and upload code."
  exit 1
fi

TMP_PARAMETERS_FILE="$(mktemp)"

eval "$(python3 - "$SETTINGS_PATH" "$TMP_PARAMETERS_FILE" <<'PY'
import json
import shlex
import sys

settings_path = sys.argv[1]
parameters_path = sys.argv[2]

with open(settings_path, "r", encoding="utf-8") as file_handle:
    settings = json.load(file_handle)

if not isinstance(settings, dict):
    raise SystemExit("settings.json must contain a JSON object")

def get_str(key, default=None, required=False):
    value = settings.get(key, default)
    if value is None:
        if required:
            raise SystemExit(f"Missing required setting: {key}")
        return ""
    value = str(value).strip()
    if required and not value:
        raise SystemExit(f"Missing required setting: {key}")
    return value

def get_bool(key, default):
    value = settings.get(key)
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}

def get_int(key, default):
    value = settings.get(key)
    if value is None or str(value).strip() == "":
        return default
    return int(str(value).strip())

resource_group = get_str("AZURE_RESOURCE_GROUP", required=True)
location = get_str("AZURE_LOCATION", required=True)
function_app_name = get_str("AZURE_FUNCTION_APP_NAME", required=True)
function_plan_name = get_str("AZURE_FUNCTION_PLAN_NAME", f"{function_app_name}-plan")
storage_mode = get_str("AZURE_STORAGE_MODE", "new")
log_analytics_mode = get_str("AZURE_LOG_ANALYTICS_MODE", "new")
app_insights_mode = get_str("AZURE_APP_INSIGHTS_MODE", "new")

allowed_modes = {"new", "existing"}
for key, value in {
    "AZURE_STORAGE_MODE": storage_mode,
    "AZURE_LOG_ANALYTICS_MODE": log_analytics_mode,
    "AZURE_APP_INSIGHTS_MODE": app_insights_mode,
}.items():
    if value not in allowed_modes:
        raise SystemExit(f"{key} must be one of: new, existing")

instance_memory_mb = get_int("AZURE_INSTANCE_MEMORY_MB", 2048)
if instance_memory_mb not in {512, 2048, 4096}:
    raise SystemExit("AZURE_INSTANCE_MEMORY_MB must be one of: 512, 2048, 4096")

parameters = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "location": {"value": location},
        "functionPlanName": {"value": function_plan_name},
        "functionAppName": {"value": function_app_name},
        "storageMode": {"value": storage_mode},
        "storageAccountName": {"value": get_str("AZURE_STORAGE_ACCOUNT_NAME", required=True)},
        "storageSubscriptionId": {"value": get_str("AZURE_STORAGE_SUBSCRIPTION_ID", "")},
        "storageResourceGroup": {"value": get_str("AZURE_STORAGE_RESOURCE_GROUP", "")},
        "storageAccountResourceId": {"value": get_str("AZURE_STORAGE_ACCOUNT_RESOURCE_ID", "")},
        "deploymentContainerName": {"value": get_str("AZURE_DEPLOYMENT_CONTAINER_NAME", "")},
        "logAnalyticsMode": {"value": log_analytics_mode},
        "logAnalyticsName": {"value": get_str("AZURE_LOG_ANALYTICS_NAME", f"{function_app_name}-logs")},
        "logAnalyticsSubscriptionId": {"value": get_str("AZURE_LOG_ANALYTICS_SUBSCRIPTION_ID", "")},
        "logAnalyticsResourceGroup": {"value": get_str("AZURE_LOG_ANALYTICS_RESOURCE_GROUP", "")},
        "logAnalyticsResourceId": {"value": get_str("AZURE_LOG_ANALYTICS_RESOURCE_ID", "")},
        "appInsightsMode": {"value": app_insights_mode},
        "applicationInsightsName": {"value": get_str("AZURE_APPLICATION_INSIGHTS_NAME", f"{function_app_name}-ai")},
        "applicationInsightsSubscriptionId": {"value": get_str("AZURE_APPLICATION_INSIGHTS_SUBSCRIPTION_ID", "")},
        "applicationInsightsResourceGroup": {"value": get_str("AZURE_APPLICATION_INSIGHTS_RESOURCE_GROUP", "")},
        "applicationInsightsResourceId": {"value": get_str("AZURE_APPLICATION_INSIGHTS_RESOURCE_ID", "")},
        "applicationInsightsConnectionString": {"value": get_str("AZURE_APPLICATION_INSIGHTS_CONNECTION_STRING", "")},
        "azureKeyVaultUrl": {"value": get_str("AZURE_KEY_VAULT_URL", required=True)},
        "dnsSubscriptionId": {"value": get_str("DNS_SUBSCRIPTION_ID", required=True)},
        "dnsResourceGroup": {"value": get_str("DNS_RESOURCE_GROUP", required=True)},
        "dnsZoneName": {"value": get_str("DNS_ZONE_NAME", required=True)},
        "dnsChallengeZoneName": {"value": get_str("DNS_CHALLENGE_ZONE_NAME", "")},
        "dnsChallengeResourceGroup": {"value": get_str("DNS_CHALLENGE_RESOURCE_GROUP", "")},
        "maximumInstanceCount": {"value": get_int("AZURE_MAXIMUM_INSTANCE_COUNT", 40)},
        "instanceMemoryMB": {"value": instance_memory_mb},
        "zoneRedundant": {"value": get_bool("AZURE_ZONE_REDUNDANT", False)},
        "dnsZoneResourceId": {"value": get_str("DNS_ZONE_RESOURCE_ID", "")},
        "dnsRoleAssignmentEnabled": {"value": get_bool("DNS_ROLE_ASSIGNMENT_ENABLED", True)},
        "keyVaultSubscriptionId": {"value": get_str("KEY_VAULT_SUBSCRIPTION_ID", "")},
        "keyVaultResourceGroup": {"value": get_str("KEY_VAULT_RESOURCE_GROUP", "")},
        "keyVaultResourceId": {"value": get_str("KEY_VAULT_RESOURCE_ID", "")},
        "keyVaultRoleAssignmentEnabled": {"value": get_bool("KEY_VAULT_ROLE_ASSIGNMENT_ENABLED", True)},
    },
}

with open(parameters_path, "w", encoding="utf-8") as file_handle:
    json.dump(parameters, file_handle, indent=2)
    file_handle.write("\n")

for key, value in {
    "RESOURCE_GROUP": resource_group,
    "APP_NAME": function_app_name,
    "LOCATION": location,
    "FUNCTION_PLAN_NAME": function_plan_name,
}.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

echo "Ensuring resource group exists..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" >/dev/null

echo "Deploying Azure resources..."
az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "${APP_NAME}-infra" \
  --template-file "$ARM_TEMPLATE_PATH" \
  --parameters @"$TMP_PARAMETERS_FILE" >/dev/null

echo "Packaging Functions project..."
rm -f "$PACKAGE_PATH"
pushd "$SCRIPT_DIR" >/dev/null
zip -rq "$PACKAGE_PATH" . \
  -x "functionapp.zip" \
     "azuredeploy.parameters.example.json" \
     "azuredeploy.json" \
     "local.settings.json" \
     "local.settings.json.example" \
     "deploy.sh" \
     "README.md" \
     "README_CN.md" \
     "__pycache__/*" \
     "*.pyc" \
     ".venv/*"
popd >/dev/null

echo "Deploying code package..."
az functionapp deployment source config-zip \
  --resource-group "$RESOURCE_GROUP" \
  --name "$APP_NAME" \
  --src "$PACKAGE_PATH" >/dev/null

PRINCIPAL_ID="$(az functionapp identity show --resource-group "$RESOURCE_GROUP" --name "$APP_NAME" --query principalId -o tsv)"

echo
echo "Deployment complete."
echo "Function App: $APP_NAME"
echo "Function Plan: $FUNCTION_PLAN_NAME"
echo "Resource Group: $RESOURCE_GROUP"
echo "Managed Identity Principal ID: $PRINCIPAL_ID"
echo "Uploaded settings file: $SETTINGS_PATH"