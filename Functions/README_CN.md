# Azure Functions 证书续期

这个目录包含一个独立的 Azure Functions 实现，用于定时续签 Let's Encrypt 证书并导入 Azure Key Vault。

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpczhao1210%2FAzure_Certification_Tool%2Fmain%2FFunctions%2Fazuredeploy.json)

## 功能说明

- 通过 Timer Trigger 每天 UTC 02:00 运行一次
- 检查 Key Vault 中的目标证书是否即将过期
- 使用 Azure DNS 完成 DNS-01 验证
- 将更新后的证书导入 Azure Key Vault
- 在 Azure 上通过 DefaultAzureCredential 优先使用 Managed Identity

## 文件说明

- `function_app.py`：Azure Functions 定时触发入口
- `cert_renewal.py`：独立的证书续期逻辑
- `host.json`：Functions 主机配置
- `requirements.txt`：Python 依赖
- `local.settings.json.example`：本地调试配置模板
- `azuredeploy.json`：Azure 资源 ARM 模板
- `azuredeploy.parameters.example.json`：ARM 参数示例
- `deploy.sh`：ARM 资源部署和代码发布脚本

## 所需 Azure 权限

Function App 身份至少需要：

- Azure DNS 区域所在资源组上的 `DNS Zone Contributor`
- Key Vault 上的 `Key Vault Certificates Officer` 或等效证书导入权限

## 必需应用设置

在 Function App 的应用设置中至少配置：

- `ACME_EMAIL`
- `ACME_DOMAINS`
- `AZURE_KEY_VAULT_URL`
- `AZURE_CERTIFICATE_NAME`
- `DNS_SUBSCRIPTION_ID`
- `DNS_RESOURCE_GROUP`
- `DNS_ZONE_NAME`

## 本地运行

1. 将 `local.settings.json.example` 复制为 `local.settings.json`
2. 填入配置项
3. 安装 `requirements.txt` 中的依赖
4. 在本目录运行 Azure Functions Core Tools

## 部署说明

- 使用 Linux Python Function App
- Azure 上优先使用 Managed Identity
- 定时计划定义在 `function_app.py`
- 当前调度为每天 UTC 02:00

## Deploy to Azure

上方按钮现在会直接打开 Azure Portal，并使用这个 ARM 模板创建资源：

- 模板地址：`https://raw.githubusercontent.com/pczhao1210/Azure_Certification_Tool/main/Functions/azuredeploy.json`

ARM 部署会创建：

- Flex Consumption Function App（`FC1`）
- Azure Functions 运行所需的 Storage Account
- 用于代码部署的 Blob 容器
- Log Analytics Workspace
- Application Insights
- System-assigned Managed Identity
- 自动为 challenge 使用的 DNS 区域授予角色
- 自动为目标 Key Vault 授予证书导入角色

如果你是通过 Portal 按钮先完成资源创建，之后用下面命令发布 Functions 代码：

```bash
./deploy.sh --skip-infra --resource-group your-functions-rg --app-name your-cert-renewal-func
```

## ARM 参数

完整示例见 `azuredeploy.parameters.example.json`。主要参数包括：

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
- `dnsChallengeZoneName` 和 `dnsChallengeResourceGroup`：使用独立 challenge zone 时填写
- `keyVaultResourceGroup`：当 Key Vault 不在当前部署资源组时填写
- `keyVaultSubscriptionId`：当 Key Vault 位于其他订阅时填写
- `dnsZoneResourceId` 和 `keyVaultResourceId`：只有在你想手工覆盖自动计算范围时才需要填写

## 部署脚本

本目录下的 `deploy.sh` 支持两种模式：

1. 先用 ARM 创建资源，再自动发布代码
2. 仅向已创建的 Function App 发布代码

### 前置要求

1. Azure CLI 2.60.0 或更高版本
2. 本地已安装 `zip`
3. 已通过 `az login` 登录 Azure
4. 如果要由脚本同时执行 ARM 部署，需要提前准备证书续期所需环境变量

### 必需环境变量

- `ACME_EMAIL`
- `ACME_DOMAINS`
- `AZURE_KEY_VAULT_URL`
- `AZURE_CERTIFICATE_NAME`
- `DNS_RESOURCE_GROUP`
- `DNS_ZONE_NAME`

### 可选环境变量

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

### 示例

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

如果资源已经通过 Portal 按钮部署完成，只发布代码即可：

```bash
./deploy.sh --skip-infra --resource-group your-functions-rg --app-name your-cert-renewal-func
```

### 可选角色赋权

ARM 部署现在默认会自动授予运行所需角色：

- 在实际管理的 DNS Zone 范围上授予 `DNS Zone Contributor`
- 在目标 Key Vault 范围上授予 `Key Vault Certificates Officer`

只有在默认范围计算不满足你的环境时，才需要这些可选环境变量：

- `DNS_ZONE_RESOURCE_ID`：用于授予 `DNS Zone Contributor`
- `DNS_ROLE_ASSIGNMENT_ENABLED`：设为 `false` 时跳过 DNS 角色分配
- `KEY_VAULT_SUBSCRIPTION_ID`：Key Vault 位于其他订阅时使用
- `KEY_VAULT_RESOURCE_GROUP`：Key Vault 位于其他资源组时使用
- `KEY_VAULT_RESOURCE_ID`：用于授予 `Key Vault Certificates Officer`
- `KEY_VAULT_ROLE_ASSIGNMENT_ENABLED`：设为 `false` 时跳过 Key Vault 角色分配

## 权限说明

- DNS 权限已经覆盖当前函数实际使用的能力，因为代码只会通过 `DnsManagementClient` 读取和更新 TXT 记录。
- Key Vault 权限已经覆盖当前函数实际使用的能力，因为代码只会通过 `CertificateClient` 读取证书元数据并导入证书版本。
- Key Vault 角色分配的前提是该 Vault 使用 Azure RBAC 权限模型。如果你的 Vault 仍然使用旧的 Access Policy 模型，还需要额外添加访问策略。