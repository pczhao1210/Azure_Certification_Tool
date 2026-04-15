#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_PATH="${SCRIPT_DIR}/functionapp.zip"
SETTINGS_TEMPLATE_PATH="${SCRIPT_DIR}/settings.json"
RESOURCE_GROUP=""
APP_NAME=""

usage() {
  cat <<'EOF'
Usage:
  ./deploy.sh --resource-group <rg> --app-name <name>

This script only packages and uploads the Functions code.
If settings.json does not exist in this folder, the script creates a default template for you to edit manually.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-group)
      RESOURCE_GROUP="$2"
      shift 2
      ;;
    --app-name)
      APP_NAME="$2"
      shift 2
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

if [[ ! -f "$SETTINGS_TEMPLATE_PATH" ]]; then
  cat > "$SETTINGS_TEMPLATE_PATH" <<'EOF'
{
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
  echo "Created default settings template: $SETTINGS_TEMPLATE_PATH"
  echo "Edit that file first, then rerun deploy.sh to upload code and settings.json."
  exit 1
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
echo "Uploaded settings file: $SETTINGS_TEMPLATE_PATH"