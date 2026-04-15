#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_PATH="${SCRIPT_DIR}/functionapp.zip"
TEMPLATE_FILE="${SCRIPT_DIR}/azuredeploy.json"
RESOURCE_GROUP=""
LOCATION=""
APP_NAME=""
STORAGE_ACCOUNT=""
PLAN_NAME=""
LOG_ANALYTICS_NAME=""
APPLICATION_INSIGHTS_NAME=""
PYTHON_VERSION="3.12"
SKIP_INFRA="false"

usage() {
  cat <<'EOF'
Usage:
  ./deploy.sh --resource-group <rg> --app-name <name> [--skip-infra]
  ./deploy.sh --resource-group <rg> --location <region> --app-name <name> --storage-account <storage>

When provisioning infrastructure, this script uses the local ARM template and then publishes the code package.

Required environment variables for ARM provisioning:
  ACME_EMAIL
  ACME_DOMAINS
  AZURE_KEY_VAULT_URL
  AZURE_CERTIFICATE_NAME
  DNS_RESOURCE_GROUP
  DNS_ZONE_NAME

Optional environment variables:
  DNS_SUBSCRIPTION_ID
  DNS_CHALLENGE_ZONE_NAME
  DNS_CHALLENGE_RESOURCE_GROUP
  DNS_ROLE_ASSIGNMENT_ENABLED
  RENEWAL_DAYS_BEFORE_EXPIRY
  SAVE_LOCAL_CERTS
  CERT_OUTPUT_DIR
  PFX_PASSWORD
  ACME_VALIDATION_TIMEOUT
  DNS_PROPAGATION_TIMEOUT
  DNS_PROPAGATION_INTERVAL
  DNS_PROPAGATION_STABLE_SECONDS
  PUBLIC_DNS_SERVERS
  DNS_ZONE_RESOURCE_ID
  KEY_VAULT_SUBSCRIPTION_ID
  KEY_VAULT_RESOURCE_GROUP
  KEY_VAULT_RESOURCE_ID
  KEY_VAULT_ROLE_ASSIGNMENT_ENABLED
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-group)
      RESOURCE_GROUP="$2"
      shift 2
      ;;
    --location)
      LOCATION="$2"
      shift 2
      ;;
    --app-name)
      APP_NAME="$2"
      shift 2
      ;;
    --storage-account)
      STORAGE_ACCOUNT="$2"
      shift 2
      ;;
    --plan-name)
      PLAN_NAME="$2"
      shift 2
      ;;
    --log-analytics-name)
      LOG_ANALYTICS_NAME="$2"
      shift 2
      ;;
    --app-insights-name)
      APPLICATION_INSIGHTS_NAME="$2"
      shift 2
      ;;
    --python-version)
      PYTHON_VERSION="$2"
      shift 2
      ;;
    --skip-infra)
      SKIP_INFRA="true"
      shift
      ;;
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
done

if [[ -z "$RESOURCE_GROUP" || -z "$APP_NAME" ]]; then
  usage
  exit 1
fi

command -v az >/dev/null || { echo "Azure CLI is required" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is required" >&2; exit 1; }

if [[ "$SKIP_INFRA" != "true" ]]; then
  if [[ -z "$LOCATION" || -z "$STORAGE_ACCOUNT" ]]; then
    usage
    exit 1
  fi

  required_settings=(
    ACME_EMAIL
    ACME_DOMAINS
    AZURE_KEY_VAULT_URL
    AZURE_CERTIFICATE_NAME
    DNS_RESOURCE_GROUP
    DNS_ZONE_NAME
  )

  for setting_name in "${required_settings[@]}"; do
    if [[ -z "${!setting_name:-}" ]]; then
      echo "Missing required environment variable: ${setting_name}" >&2
      exit 1
    fi
  done

  if [[ ! -f "$TEMPLATE_FILE" ]]; then
    echo "ARM template not found: $TEMPLATE_FILE" >&2
    exit 1
  fi
fi

SUBSCRIPTION_ID="${DNS_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"
PLAN_NAME="${PLAN_NAME:-${APP_NAME}-plan}"
LOG_ANALYTICS_NAME="${LOG_ANALYTICS_NAME:-${APP_NAME}-logs}"
APPLICATION_INSIGHTS_NAME="${APPLICATION_INSIGHTS_NAME:-${APP_NAME}-ai}"

if [[ "$SKIP_INFRA" != "true" ]]; then
  echo "Creating or updating resource group..."
  az group create --name "$RESOURCE_GROUP" --location "$LOCATION" >/dev/null

  echo "Deploying ARM template..."
  az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$TEMPLATE_FILE" \
    --parameters \
      location="$LOCATION" \
      functionPlanName="$PLAN_NAME" \
      functionAppName="$APP_NAME" \
      functionAppRuntime="python" \
      functionAppRuntimeVersion="$PYTHON_VERSION" \
      storageAccountName="$STORAGE_ACCOUNT" \
      logAnalyticsName="$LOG_ANALYTICS_NAME" \
      applicationInsightsName="$APPLICATION_INSIGHTS_NAME" \
      acmeEmail="$ACME_EMAIL" \
      acmeDomains="$ACME_DOMAINS" \
      acmeDirectoryUrl="${ACME_DIRECTORY_URL:-https://acme-v02.api.letsencrypt.org/directory}" \
      azureKeyVaultUrl="$AZURE_KEY_VAULT_URL" \
      azureCertificateName="$AZURE_CERTIFICATE_NAME" \
      dnsSubscriptionId="$SUBSCRIPTION_ID" \
      dnsResourceGroup="$DNS_RESOURCE_GROUP" \
      dnsZoneName="$DNS_ZONE_NAME" \
      dnsChallengeZoneName="${DNS_CHALLENGE_ZONE_NAME:-}" \
      dnsChallengeResourceGroup="${DNS_CHALLENGE_RESOURCE_GROUP:-}" \
      renewalDaysBeforeExpiry="${RENEWAL_DAYS_BEFORE_EXPIRY:-30}" \
      saveLocalCerts="${SAVE_LOCAL_CERTS:-false}" \
      certOutputDir="${CERT_OUTPUT_DIR:-/tmp/certificates}" \
      pfxPassword="${PFX_PASSWORD:-}" \
      acmeValidationTimeout="${ACME_VALIDATION_TIMEOUT:-900}" \
      dnsPropagationTimeout="${DNS_PROPAGATION_TIMEOUT:-900}" \
      dnsPropagationInterval="${DNS_PROPAGATION_INTERVAL:-15}" \
      dnsPropagationStableSeconds="${DNS_PROPAGATION_STABLE_SECONDS:-90}" \
      publicDnsServers="${PUBLIC_DNS_SERVERS:-8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222}" \
      dnsZoneResourceId="${DNS_ZONE_RESOURCE_ID:-}" \
      dnsRoleAssignmentEnabled="${DNS_ROLE_ASSIGNMENT_ENABLED:-true}" \
      keyVaultSubscriptionId="${KEY_VAULT_SUBSCRIPTION_ID:-}" \
      keyVaultResourceGroup="${KEY_VAULT_RESOURCE_GROUP:-}" \
      keyVaultResourceId="${KEY_VAULT_RESOURCE_ID:-}" \
      keyVaultRoleAssignmentEnabled="${KEY_VAULT_ROLE_ASSIGNMENT_ENABLED:-true}" >/dev/null
fi

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
echo "Resource Group: $RESOURCE_GROUP"
echo "Managed Identity Principal ID: $PRINCIPAL_ID"