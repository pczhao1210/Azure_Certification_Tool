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
- `local.settings.json.example`：本地 Azure Functions 主机配置模板
- `settings.json`：Functions 唯一使用的业务配置文件，由 `deploy.sh` 自动生成模板
- `azuredeploy.json`：Azure 资源 ARM 模板
- `azuredeploy.parameters.example.json`：ARM 参数示例
- `deploy.sh`：Functions 代码上传脚本

## 所需 Azure 权限

Function App 身份至少需要：

- Azure DNS 区域所在资源组上的 `DNS Zone Contributor`
- Key Vault 上的 `Key Vault Certificates Officer` 或等效证书导入权限

## 必需配置

Function 现在直接从 `settings.json` 读取配置，不再依赖环境变量，也不再从 `local.settings.json` 读取业务配置：

- `ACME_EMAIL`
- `ACME_DOMAINS`
- `AZURE_KEY_VAULT_URL`
- `AZURE_CERTIFICATE_NAME`
- `DNS_SUBSCRIPTION_ID`
- `DNS_RESOURCE_GROUP`
- `DNS_ZONE_NAME`

## 本地运行

1. 如果要在本地启动 Azure Functions host，将 `local.settings.json.example` 复制为 `local.settings.json`
2. 准备并填写 `settings.json`
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
- Azure Functions 运行所需的 Storage Account，可新建也可复用现有资源
- 所选 Storage Account 中用于代码部署的 Blob 容器
- Log Analytics Workspace，可新建也可复用现有资源
- Application Insights，可新建也可复用现有资源
- System-assigned Managed Identity
- 自动为 challenge 使用的 DNS 区域授予角色
- 自动为目标 Key Vault 授予证书导入角色

如果你是通过 Portal 按钮先完成资源创建，之后运行下面命令上传 Functions 代码：

```bash
./deploy.sh --resource-group your-functions-rg --app-name your-cert-renewal-func
```

如果当前目录没有 `settings.json`，脚本会先生成一个默认模板并立即退出。你需要先手工改好这个文件，再重新执行上传。

上传成功后，Function 运行时直接读取包内的 `settings.json`。如果你后续想修改配置，可以在 Azure Portal 的文件编辑界面里直接修改这个文件；但要注意，下次重新执行 `deploy.sh` 时，线上文件会被本地上传包覆盖。

## ARM 参数

完整示例见 `azuredeploy.parameters.example.json`。主要参数包括：

- `location`
- `functionPlanName`
- `functionAppName`
- `storageMode`：`new` 或 `existing`
- `storageAccountName`
- `storageSubscriptionId`、`storageResourceGroup`、`storageAccountResourceId`：复用现有 Storage 时使用
- `deploymentContainerName`：覆盖默认 deployment 容器名
- `logAnalyticsMode`：`new` 或 `existing`
- `logAnalyticsName`
- `logAnalyticsSubscriptionId`、`logAnalyticsResourceGroup`、`logAnalyticsResourceId`：复用现有 Workspace 时使用
- `appInsightsMode`：`new` 或 `existing`
- `applicationInsightsName`
- `applicationInsightsSubscriptionId`、`applicationInsightsResourceGroup`、`applicationInsightsResourceId`：复用现有 Application Insights 时使用
- `applicationInsightsConnectionString`：如果不想通过 ARM 资源引用现有 AI，可直接传连接串
- `azureKeyVaultUrl`
- `dnsSubscriptionId`
- `dnsResourceGroup`
- `dnsZoneName`
- `dnsChallengeZoneName` 和 `dnsChallengeResourceGroup`：使用独立 challenge zone 时填写
- `keyVaultResourceGroup`：当 Key Vault 不在当前部署资源组时填写
- `keyVaultSubscriptionId`：当 Key Vault 位于其他订阅时填写
- `dnsZoneResourceId` 和 `keyVaultResourceId`：只有在你想手工覆盖自动计算范围时才需要填写

复用现有资源时的说明：

- 只有在 `appInsightsMode` 为 `new` 且 `logAnalyticsMode` 为 `existing` 时，才会使用现有 Log Analytics Workspace。
- 如果现有 Storage Account 位于其他资源组或其他订阅，模板会复用你指定的 deployment container 名称，但不会替你创建这个 blob container。需要先手工创建，再传同一个 `deploymentContainerName`。

### Portal 中 `existing` 模式最小填写示例

如果你点的是 Deploy to Azure 按钮，并且想复用现有 Storage Account 和现有 Application Insights，Portal 里最少可以按下面这样填：

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

azureKeyVaultUrl = https://your-keyvault.vault.azure.net/
dnsSubscriptionId = <dns-subscription-id>
dnsResourceGroup = your-dns-resource-group
dnsZoneName = example.com
```

Portal 填写说明：

- 当 `appInsightsMode=existing` 时，模板真正需要的是现有的 Application Insights 资源；这时 `logAnalyticsMode` 可以保留为 `existing`，但通常不需要再填 `logAnalyticsResourceId`。
- 如果现有 Storage Account 不在当前部署资源组或订阅内，`deploymentContainerName` 对应的 blob container 必须提前存在。
- 其他 override 类型参数没有特殊需求时保持为空即可。

## 部署脚本

本目录下的 `deploy.sh` 只做两件事：

1. 如果当前目录没有 `settings.json`，先生成默认模板并退出
2. 在 `settings.json` 已存在时，打包并上传 Functions 代码和该配置文件

### 前置要求

1. Azure CLI 2.60.0 或更高版本
2. 本地已安装 `zip`
3. 已通过 `az login` 登录 Azure

### 示例

```bash
chmod +x deploy.sh
./deploy.sh \
  --resource-group your-functions-rg \
  --app-name your-cert-renewal-func
```

脚本第一次运行时会生成一个默认的 `settings.json`，例如：

```json
{
  "ACME_EMAIL": "your-email@example.com",
  "ACME_DOMAINS": "example.com,*.example.com",
  "AZURE_KEY_VAULT_URL": "https://your-keyvault.vault.azure.net/",
  "AZURE_CERTIFICATE_NAME": "your-ssl-certificate",
  "DNS_SUBSCRIPTION_ID": "your-subscription-id",
  "DNS_RESOURCE_GROUP": "your-dns-resource-group",
  "DNS_ZONE_NAME": "example.com"
}
```

你需要手工修改这个文件，然后重新运行 `deploy.sh`。脚本会把 `settings.json` 一起上传，Function 运行时直接读取它。

### Portal 部署后的实际流程

1. 先点击 Deploy to Azure，只部署 infra 和授权资源
2. 第一次运行 `deploy.sh`，生成默认 `settings.json`
3. 手工修改 `settings.json`
4. 再次运行 `deploy.sh`，上传代码和 `settings.json`

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