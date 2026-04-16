# Azure Functions 证书续期

这个目录包含一个独立的 Azure Functions 实现，用于定时续签 Let's Encrypt 证书并导入 Azure Key Vault。

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
- `settings.json`：唯一配置文件，既用于基础设施部署，也用于运行时业务配置
- `azuredeploy.json`：由 `deploy.sh` 在后台调用的 Azure 资源 ARM 模板
- `azuredeploy.parameters.example.json`：ARM 参数参考示例
- `deploy.sh`：一体化部署脚本，负责资源部署、代码上传和配置文件上传

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

为了避免基础设施参数和业务参数重复填写，`settings.json` 同时也是部署脚本的输入来源。常用基础设施键包括：

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

复用现有资源时，还可以在同一文件里填写这些可选键：

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

## 部署脚本

本目录下的 `deploy.sh` 现在负责完整部署流程：

1. 如果当前目录没有 `settings.json`，先生成默认模板并退出
2. 根据 `settings.json` 创建或更新 Azure 资源组
3. 调用 `azuredeploy.json` 创建或更新 Function App、Storage、Application Insights、Log Analytics 和角色分配
4. 打包并上传 Functions 代码和 `settings.json`

### 前置要求

1. Azure CLI 2.60.0 或更高版本
2. 本地已安装 `zip`
3. 已通过 `az login` 登录 Azure

### 示例

```bash
chmod +x deploy.sh
./deploy.sh
```

脚本第一次运行时会生成一个默认的 `settings.json`，例如：

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

你需要手工修改这个文件，然后重新运行 `deploy.sh`。脚本会先部署或更新 Azure 资源，再把 `settings.json` 一起上传，Function 运行时直接读取它。

### 实际部署流程

1. 第一次运行 `deploy.sh`，生成默认 `settings.json`
2. 手工修改 `settings.json`，把基础设施参数和业务参数一次填完
3. 再次运行 `deploy.sh`
4. 脚本自动创建或更新资源组、部署 Azure 资源、上传代码和配置文件

### 可选角色赋权

`deploy.sh` 在后台调用 ARM 模板，默认会自动授予运行所需角色：

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