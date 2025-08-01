# Azure Let's Encrypt Certificate Manager

自动获取Let's Encrypt SSL证书并上传到Azure Key Vault的Python工具。

## 功能特性

- 使用DNS-01挑战自动获取Let's Encrypt证书
- 支持通配符证书（*.domain.com）
- 自动管理Azure DNS TXT记录
- 证书自动上传到Azure Key Vault
- 本地证书备份（按年月分类）
- **智能证书更新**：自动检查证书过期时间，仅在需要时更新

## 环境要求

- Python 3.7+
- Azure订阅
- Azure DNS区域
- Azure Key Vault
- Azure Service Principal（应用程序注册）

## 安装依赖

```bash
pip install -r requirements.txt
```

## 配置

1. 复制配置示例文件：
```bash
cp config.example.json config.json
```

2. 编辑 `config.json`，填入你的实际配置：
   - ACME邮箱和域名
   - Azure Key Vault信息
   - Azure DNS配置
   - Azure身份认证信息

## Azure权限配置

确保你的Azure Service Principal具有以下权限：

1. **DNS Zone Contributor** - 用于管理DNS记录
2. **Key Vault Certificate Officer** - 用于上传证书

## 使用方法

### 基本使用
```bash
python cert_manager.py
```

### 命令行参数
```bash
# 强制更新证书（忽略过期检查）
python cert_manager.py --force

# 设置证书过期前15天开始更新
python cert_manager.py --days 15

# 组合使用
python cert_manager.py --force --days 15
```

## 配置说明

### ACME配置
- `email`: Let's Encrypt账户邮箱
- `domains`: 要申请证书的域名列表
- `directory_url`: ACME服务器地址

### Azure配置
- `key_vault_url`: Key Vault URL
- `tenant_id`: Azure租户ID
- `client_id`: 应用程序ID
- `client_secret`: 应用程序密钥
- `certificate_name`: 证书在Key Vault中的名称

### DNS配置
- `provider`: DNS提供商（目前支持azure）
- `subscription_id`: Azure订阅ID
- `resource_group`: DNS区域所在资源组
- `zone_name`: DNS区域名称

## 自动化部署

### Windows 定时任务
```cmd
# 每天检查一次，仅在需要时更新
schtasks /create /tn "SSL Certificate Update" /tr "python E:\path\to\cert_manager.py" /sc daily
```

### Linux Cron
```bash
# 每天凌晨2点检查
0 2 * * * cd /path/to/cert_update && python cert_manager.py
```

## 注意事项

- 确保DNS区域已正确配置
- Service Principal需要适当的权限
- 证书有效期为90天，默认在过期前30天自动更新
- 配置文件包含敏感信息，请勿提交到版本控制
- 程序会自动检查证书状态，仅在必要时才会更新

## 许可证

MIT License